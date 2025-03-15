/**
 * @fileoverview Authentication Controller
 * Handles all authentication-related operations including registration, login, 
 * password management, token management, session handling, and 2FA.
 */

const rateLimit = require('express-rate-limit');

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const { promisify } = require('util');
const { v4: uuidv4 } = require('uuid');

/**
 * Rate limiter for authentication attempts
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per window
  message: 'Too many authentication attempts from this IP, please try again after 15 minutes',
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * Rate limiter for account operations (password reset, email verification, etc.)
 */
const accountLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // limit each IP to 3 requests per window
  message: 'Too many account operation attempts from this IP, please try again after an hour',
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * Rate limiter for 2FA operations
 */
const twoFactorLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 10, // limit each IP to 10 requests per window
  message: 'Too many 2FA attempts from this IP, please try again after 5 minutes',
  standardHeaders: true,
  legacyHeaders: false,
});

const User = require('../models/user.model');
const Session = require('../models/session.model'); 
const TokenBlacklist = require('../models/token-blacklist.model');
const config = require('../config');
const { 
  ApiError, 
  AuthenticationError, 
  ValidationError, 
  PermissionError, 
  RateLimitError,
  SessionError,
  ServerError
} = require('../utils/appError');
const asyncWrapper = require('../utils/asyncWrapper');
const EmailService = require('../services/email.service');
const LogService = require('../services/log.service');
const redisClient = require('../services/redis.service');

/**
 * @class AuthController
 * @description Controller for handling all authentication related operations
 */
class AuthController {
  /**
   * @method register
   * @description Register a new user account
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @returns {Object} JSON response with user data and token
   */
  static register = asyncWrapper(async (req, res) => {
    const { 
      firstName, 
      lastName, 
      email, 
      password, 
      passwordConfirm, 
      phoneNumber,
      role = 'user',
      acceptTerms
    } = req.body;

    // Check if user accepted terms and conditions
    if (!acceptTerms) {
      throw ValidationError.invalidInput('You must accept the terms and conditions to register', 'acceptTerms');
    }

    // Check if passwords match
    if (password !== passwordConfirm) {
      throw ValidationError.invalidInput('Passwords do not match', 'passwordConfirm');
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      throw AuthenticationError.userExists('Email is already registered', 'email');
    }

    // Generate email verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const verificationTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Create new user
    const newUser = await User.create({
      firstName,
      lastName,
      email: email.toLowerCase(),
      password, // Model handles hashing
      phoneNumber,
      role,
      verificationToken,
      verificationTokenExpires,
      isEmailVerified: false,
      tokenVersion: 0,
      lastLogin: null,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date()
    });

    // Send verification email
    try {
      const verificationUrl = `${config.clientUrl}/verify-email?token=${verificationToken}`;
      
      await EmailService.sendVerificationEmail({
        to: newUser.email,
        firstName: newUser.firstName,
        verificationUrl
      });
    } catch (error) {
      // Log email error but don't stop registration process
      LogService.error('Failed to send verification email', {
        error: error.message,
        userId: newUser._id
      });
    }

    // Generate JWT tokens
    const { accessToken, refreshToken } = this._generateTokens(newUser);

    // Record user activity
    LogService.info('User registered', {
      userId: newUser._id,
      email: newUser.email,
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });

    // Set refresh token in HTTP-only cookie
    this._setRefreshTokenCookie(res, refreshToken);

    // Return response without sensitive data
    const userWithoutSensitiveData = newUser.toJSON();
    delete userWithoutSensitiveData.password;
    delete userWithoutSensitiveData.verificationToken;

    res.status(201).json({
      success: true,
      data: {
        user: userWithoutSensitiveData,
        accessToken,
        expiresIn: config.jwt.accessExpiresIn
      },
      message: 'Registration successful. Please verify your email address.'
    });
  });

  /**
   * @method login
   * @description Log in a user with email and password
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @returns {Object} JSON response with user data and token
   */
  static login = asyncWrapper(async (req, res) => {
    const { email, password, rememberMe = false } = req.body;

    // Check if email and password are provided
    if (!email || !password) {
      throw ValidationError.invalidInput('Please provide email and password', 'credentials');
    }

    // Find user by email with password field
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password +loginAttempts +lockUntil +is2FAEnabled +twoFactorSecret');

    // Check if user exists and password is correct
    if (!user || !(await user.comparePassword(password))) {
      // Increment login attempts
      if (user) {
        user.loginAttempts += 1;
        
        // Lock account after 5 failed attempts
        if (user.loginAttempts >= 5) {
          user.lockUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
          LogService.warn('Account locked due to multiple failed login attempts', {
            userId: user._id,
            email: user.email,
            ip: req.ip
          });
        }
        
        await user.save();
      }
      
      throw AuthenticationError.invalidCredentials('Invalid email or password');
    }

    // Check if account is locked
    if (user.lockUntil && user.lockUntil > Date.now()) {
      const minutesLeft = Math.ceil((user.lockUntil - Date.now()) / (60 * 1000));
      throw AuthenticationError.accountLocked(`Account locked. Try again in ${minutesLeft} minutes`);
    }

    // Check if email is verified
    if (!user.isEmailVerified) {
      throw AuthenticationError.unverifiedEmail('Please verify your email address before logging in');
    }

    // Check if account is active
    if (!user.isActive) {
      throw AuthenticationError.accountDisabled('Your account has been disabled. Please contact support');
    }

    // Reset login attempts on successful login
    user.loginAttempts = 0;
    user.lockUntil = null;
    user.lastLogin = new Date();
    await user.save();

    // Create session
    const session = await Session.create({
      userId: user._id,
      userAgent: req.headers['user-agent'],
      ip: req.ip,
      expiresAt: rememberMe 
        ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days
        : new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
    });

    // Check if 2FA is enabled
    if (user.is2FAEnabled) {
      // Create temporary token for 2FA verification
      const tempToken = jwt.sign(
        { id: user._id, sessionId: session._id, require2FA: true },
        config.jwt.secret,
        { expiresIn: '5m' }
      );

      return res.status(200).json({
        success: true,
        data: {
          require2FA: true,
          tempToken
        },
        message: 'Two-factor authentication required'
      });
    }

    // Generate tokens
    const { accessToken, refreshToken } = this._generateTokens(user, session._id);

    // Set refresh token cookie
    this._setRefreshTokenCookie(res, refreshToken, rememberMe);

    // Log login activity
    LogService.info('User logged in', {
      userId: user._id,
      email: user.email,
      ip: req.ip,
      sessionId: session._id,
      userAgent: req.headers['user-agent']
    });

    // Return user data and token
    const userWithoutSensitiveData = user.toJSON();
    delete userWithoutSensitiveData.password;
    delete userWithoutSensitiveData.loginAttempts;
    delete userWithoutSensitiveData.lockUntil;
    delete userWithoutSensitiveData.twoFactorSecret;

    res.status(200).json({
      success: true,
      data: {
        user: userWithoutSensitiveData,
        accessToken,
        expiresIn: config.jwt.accessExpiresIn,
        sessionId: session._id
      },
      message: 'Login successful'
    });
  });

  /**
   * @method verifyTwoFactor
   * @description Verify 2FA code and complete login
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @returns {Object} JSON response with user data and token
   */
  static verifyTwoFactor = asyncWrapper(async (req, res) => {
    const { code, tempToken } = req.body;

    if (!code || !tempToken) {
      throw ValidationError.invalidInput('Verification code and token are required');
    }

    // Verify temp token
    let decoded;
    try {
      decoded = jwt.verify(tempToken, config.jwt.secret);
    } catch (error) {
      throw AuthenticationError.invalidToken('Invalid or expired token. Please login again');
    }

    // Check if token has 2FA requirement
    if (!decoded.require2FA) {
      throw AuthenticationError.invalidToken('Invalid token type');
    }

    // Find user
    const user = await User.findById(decoded.id).select('+twoFactorSecret');
    if (!user) {
      throw AuthenticationError.userNotFound('User not found');
    }

    // Find session
    const session = await Session.findById(decoded.sessionId);
    if (!session) {
      throw SessionError.invalidSession('Session not found');
    }

    // Verify code
    const isValid = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: code,
      window: 1 // Allow 30 seconds window
    });

    if (!isValid) {
      LogService.warn('Invalid 2FA attempt', {
        userId: user._id,
        ip: req.ip,
        sessionId: session._id
      });
      throw AuthenticationError.invalid2FACode('Invalid verification code');
    }

    // Generate tokens
    const { accessToken, refreshToken } = this._generateTokens(user, session._id);

    // Set refresh token cookie
    this._setRefreshTokenCookie(res, refreshToken, session.expiresAt > Date.now() + 24 * 60 * 60 * 1000);

    // Update session
    session.lastActiveAt = new Date();
    await session.save();

    // Log successful 2FA
    LogService.info('User completed 2FA verification', {
      userId: user._id,
      ip: req.ip,
      sessionId: session._id
    });

    // Return user data and token
    const userWithoutSensitiveData = user.toJSON();
    delete userWithoutSensitiveData.password;
    delete userWithoutSensitiveData.twoFactorSecret;

    res.status(200).json({
      success: true,
      data: {
        user: userWithoutSensitiveData,
        accessToken,
        expiresIn: config.jwt.accessExpiresIn,
        sessionId: session._id
      },
      message: 'Two-factor authentication successful'
    });
  });

  /**
   * @method setupTwoFactor
   * @description Set up 2FA for a user
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @returns {Object} JSON response with 2FA setup data
   */
  static setupTwoFactor = asyncWrapper(async (req, res) => {
    // Get user from authenticated request
    const user = req.user;

    // Generate new secret
    const secret = speakeasy.generateSecret({
      length: 20,
      name: `ImmigrationApp:${user.email}`
    });

    // Generate QR code
    const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);

    // Save secret temporarily in Redis with 10-minute expiry
    const setupKey = `2fa_setup:${user._id}`;
    await redisClient.setex(setupKey, 600, secret.base32);

    // Log 2FA setup attempt
    LogService.info('User initiated 2FA setup', {
      userId: user._id,
      ip: req.ip
    });

    res.status(200).json({
      success: true,
      data: {
        qrCode: qrCodeUrl,
        secret: secret.base32, // Only shown once during setup
        setupKey
      },
      message: 'Two-factor authentication setup initiated'
    });
  });

  /**
   * @method confirmTwoFactor
   * @description Confirm and enable 2FA for a user
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @returns {Object} JSON response with confirmation result
   */
  static confirmTwoFactor = asyncWrapper(async (req, res) => {
    const { code, setupKey } = req.body;
    const user = req.user;

    if (!code || !setupKey) {
      throw ValidationError.invalidInput('Verification code and setup key are required');
    }

    // Get secret from Redis
    const secret = await redisClient.get(setupKey);
    if (!secret) {
      throw ValidationError.invalidInput('Setup session expired or invalid. Please restart the 2FA setup process');
    }

    // Verify code
    const isValid = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token: code,
      window: 1
    });

    if (!isValid) {
      throw ValidationError.invalidInput('Invalid verification code');
    }

    // Enable 2FA for user
    await User.findByIdAndUpdate(user._id, {
      is2FAEnabled: true,
      twoFactorSecret: secret,
      updatedAt: new Date()
    });

    // Delete setup key from Redis
    await redisClient.del(setupKey);

    // Generate backup codes
    const backupCodes = [];
    for (let i = 0; i < 10; i++) {
      backupCodes.push(crypto.randomBytes(4).toString('hex'));
    }

    // Hash and store backup codes
    const hashedBackupCodes = await Promise.all(
      backupCodes.map(async (code) => {
        const salt = await bcrypt.genSalt(10);
        return await bcrypt.hash(code, salt);
      })
    );

    await User.findByIdAndUpdate(user._id, {
      backupCodes: hashedBackupCodes
    });

    // Log 2FA setup completion
    LogService.info('User enabled 2FA', {
      userId: user._id,
      ip: req.ip
    });

    res.status(200).json({
      success: true,
      data: {
        backupCodes
      },
      message: 'Two-factor authentication enabled successfully. Please save your backup codes.'
    });
  });

  /**
   * @method logout
   * @description Log out a user by invalidating their session and clearing cookies
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @returns {Object} JSON response with logout status
   */
  static logout = asyncWrapper(async (req, res) => {
    const { sessionId } = req.body;
    const user = req.user;

    try {
      // If specific session ID is provided, only invalidate that session
      if (sessionId) {
        await Session.findOneAndUpdate(
          { _id: sessionId, userId: user._id },
          { isActive: false, endedAt: new Date() }
        );

        LogService.info('Session logged out', {
          userId: user._id,
          sessionId,
          ip: req.ip
        });
      } else {
        // Otherwise, invalidate all sessions for this user
        await Session.updateMany(
          { userId: user._id, isActive: true },
          { isActive: false, endedAt: new Date() }
        );

        LogService.info('All sessions logged out', {
          userId: user._id,
          ip: req.ip
        });
      }

      // Blacklist the current refresh token if it exists
      const refreshToken = req.cookies.refreshToken;
      if (refreshToken) {
        try {
          const decoded = jwt.verify(refreshToken, config.jwt.refreshSecret);
          
          // Add token to blacklist with expiry matching token expiry
          await TokenBlacklist.create({
            token: refreshToken,
            userId: user._id,
            expiresAt: new Date(decoded.exp * 1000)
          });
        } catch (error) {
          // If token verification fails, we can safely ignore
          LogService.debug('Failed to blacklist refresh token', {
            error: error.message
          });
        }
      }

      // Clear refresh token cookie
      this._clearRefreshTokenCookie(res);

      return res.status(200).json({
        success: true,
        message: 'Logged out successfully'
      });
    } catch (error) {
      LogService.error('Logout failed', {
        userId: user._id,
        error: error.message,
        ip: req.ip
      });

      // Still clear cookies on client side even if server operations fail
      this._clearRefreshTokenCookie(res);
      
      return res.status(200).json({
        success: true,
        message: 'Logged out successfully'
      });
    }
  });

  /**
   * @method refreshToken
   * @description Refresh the access token using a valid refresh token
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @returns {Object} JSON response with new access token
   */
  static refreshToken = asyncWrapper(async (req, res) => {
    const { refreshToken } = req.cookies;

    if (!refreshToken) {
      throw AuthenticationError.missingToken('Refresh token is required');
    }

    // Check if token is blacklisted
    const isBlacklisted = await TokenBlacklist.findOne({ token: refreshToken });
    if (isBlacklisted) {
      this._clearRefreshTokenCookie(res);
      throw AuthenticationError.invalidToken('Invalid refresh token');
    }

    try {
      // Verify refresh token
      const decoded = jwt.verify(refreshToken, config.jwt.refreshSecret);

      // Find user and session
      const user = await User.findById(decoded.id);
      if (!user) {
        throw AuthenticationError.userNotFound('User not found');
      }

      // Verify token version matches
      if (decoded.tokenVersion !== user.tokenVersion) {
        throw AuthenticationError.invalidToken('Token has been revoked');
      }

      // Find active session if sessionId is in token
      let session = null;
      if (decoded.sessionId) {
        session = await Session.findOne({
          _id: decoded.sessionId,
          userId: user._id,
          isActive: true
        });

        if (!session) {
          throw SessionError.invalidSession('Session not found or inactive');
        }

        // Update session last active time
        session.lastActiveAt = new Date();
        await session.save();
      }

      // Generate new access token, but keep the same refresh token
      const { accessToken } = this._generateTokens(user, session?._id, false);

      // Log refresh activity
      LogService.info('Token refreshed', {
        userId: user._id,
        ip: req.ip,
        sessionId: session?._id
      });

      return res.status(200).json({
        success: true,
        data: {
          accessToken,
          expiresIn: config.jwt.accessExpiresIn
        },
        message: 'Token refreshed successfully'
      });
    } catch (error) {
      // Clear refresh token cookie if invalid
      this._clearRefreshTokenCookie(res);

      if (error instanceof ApiError) {
        throw error;
      }

      // JWT verification errors
      if (error.name === 'TokenExpiredError') {
        throw AuthenticationError.expiredToken('Refresh token has expired');
      }
      
      throw AuthenticationError.invalidToken('Invalid refresh token');
    }
  });

  /**
   * @method forgotPassword
   * @description Send a password reset email to the user
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @returns {Object} JSON response with password reset status
   */
  static forgotPassword = asyncWrapper(async (req, res) => {
    const { email } = req.body;

    if (!email) {
      throw ValidationError.invalidInput('Email is required');
    }

    // Find user by email
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      // For security reasons, don't reveal if email exists or not
      return res.status(200).json({
        success: true,
        message: 'If your email is registered, you will receive a password reset link'
      });
    }

    // Check for frequent reset requests
    const resetKey = `password_reset:${user._id}`;
    const resetCount = await redisClient.get(resetKey);
    if (resetCount && parseInt(resetCount, 10) >= 3) {
      throw RateLimitError.tooManyRequests('Too many password reset requests. Please try again later.');
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    // Hash token before storing in database for security
    const hashedToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');

    // Save hashed token to user
    user.passwordResetToken = hashedToken;
    user.passwordResetExpires = resetTokenExpires;
    await user.save({ validateBeforeSave: false });

    // Increment reset request count in Redis
    await redisClient.incr(resetKey);
    await redisClient.expire(resetKey, 60 * 60); // 1 hour expiry

    // Generate reset URL
    const resetUrl = `${config.clientUrl}/reset-password?token=${resetToken}`;

    try {
      // Send password reset email
      await EmailService.sendPasswordResetEmail({
        to: user.email,
        firstName: user.firstName,
        resetUrl,
        expiresIn: '1 hour'
      });

      // Log password reset request
      LogService.info('Password reset requested', {
        userId: user._id,
        email: user.email,
        ip: req.ip
      });

      return res.status(200).json({
        success: true,
        message: 'If your email is registered, you will receive a password reset link'
      });
    } catch (error) {
      // Reset token fields in database if email fails
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save({ validateBeforeSave: false });

      LogService.error('Failed to send password reset email', {
        userId: user._id,
        email: user.email,
        error: error.message,
        ip: req.ip
      });

      throw ServerError.emailFailed('Failed to send password reset email. Please try again later.');
    }
  });

  /**
   * @method resetPassword
   * @description Reset a user's password using a valid reset token
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @returns {Object} JSON response with password reset status
   */
  static resetPassword = asyncWrapper(async (req, res) => {
    const { token, password, passwordConfirm } = req.body;

    if (!token || !password || !passwordConfirm) {
      throw ValidationError.invalidInput('Token and new password are required');
    }

    if (password !== passwordConfirm) {
      throw ValidationError.invalidInput('Passwords do not match', 'passwordConfirm');
    }

    // Hash the token provided by the user
    const hashedToken = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');

    // Find user with valid token
    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      throw AuthenticationError.invalidToken('Invalid or expired password reset token');
    }

    // Update password and clear reset token fields
    user.password = password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    
    // Increment token version to invalidate all existing tokens
    user.tokenVersion = (user.tokenVersion || 0) + 1;
    
    await user.save();

    // Invalidate all active sessions
    await Session.updateMany(
      { userId: user._id, isActive: true },
      { isActive: false, endedAt: new Date() }
    );

    // Log password reset
    LogService.info('Password reset successful', {
      userId: user._id,
      email: user.email,
      ip: req.ip
    });

    return res.status(200).json({
      success: true,
      message: 'Password has been reset successfully. You can now log in with your new password.'
    });
  });

  /**
   * @method verifyEmail
   * @description Verify a user's email using a verification token
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @returns {Object} JSON response with email verification status
   */
  static verifyEmail = asyncWrapper(async (req, res) => {
    const { token } = req.body;
    if (!token) {
      throw ValidationError.invalidInput('Verification token is required');
    }

    // Find user with matching verification token
    const user = await User.findOne({
      verificationToken: token,
      verificationTokenExpires: { $gt: Date.now() }
    });

    if (!user) {
      throw AuthenticationError.invalidToken('Invalid verification token or token has expired');
    }

    // Update user to verified status
    user.isEmailVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpires = undefined;
    user.updatedAt = new Date();
    await user.save();

    // Log verification success
    LogService.info('Email verified successfully', {
      userId: user._id,
      email: user.email,
      ip: req.ip
    });

    return res.status(200).json({
      success: true,
      message: 'Email verified successfully. You can now log in.'
    });
  });

  /**
   * @method resendVerification
   * @description Resend email verification token to user
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @returns {Object} JSON response with verification status
   */
  static resendVerification = asyncWrapper(async (req, res) => {
    const { email } = req.body;

    if (!email) {
      throw ValidationError.invalidInput('Email is required');
    }

    // Find user by email
    const user = await User.findOne({ email: email.toLowerCase() });
    
    // For security reasons, don't reveal if email exists or not
    if (!user) {
      return res.status(200).json({
        success: true,
        message: 'If your email is registered, a verification email has been sent.'
      });
    }

    // Check if user is already verified
    if (user.isEmailVerified) {
      return res.status(200).json({
        success: true,
        message: 'Your email is already verified. You can log in.'
      });
    }

    // Check for frequent verification requests
    const verificationKey = `email_verification:${user._id}`;
    const verificationCount = await redisClient.get(verificationKey);
    if (verificationCount && parseInt(verificationCount, 10) >= 3) {
      throw RateLimitError.tooManyRequests('Too many verification requests. Please try again later.');
    }

    // Generate new verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const verificationTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Save new token to user
    user.verificationToken = verificationToken;
    user.verificationTokenExpires = verificationTokenExpires;
    await user.save({ validateBeforeSave: false });

    // Increment verification request count in Redis
    await redisClient.incr(verificationKey);
    await redisClient.expire(verificationKey, 60 * 60); // 1 hour expiry

    // Generate verification URL
    const verificationUrl = `${config.clientUrl}/verify-email?token=${verificationToken}`;

    try {
      // Send verification email
      await EmailService.sendVerificationEmail({
        to: user.email,
        firstName: user.firstName,
        verificationUrl
      });

      // Log verification request
      LogService.info('Verification email resent', {
        userId: user._id,
        email: user.email,
        ip: req.ip
      });

      return res.status(200).json({
        success: true,
        message: 'If your email is registered, a verification email has been sent.'
      });
    } catch (error) {
      // If email fails, log error
      LogService.error('Failed to send verification email', {
        userId: user._id,
        email: user.email,
        error: error.message,
        ip: req.ip
      });

      throw ServerError.emailFailed('Failed to send verification email. Please try again later.');
    }
  });

  /**
   * @method _generateTokens
   * @description Generate access and refresh tokens for a user
   * @param {Object} user - The user object
   * @param {String} sessionId - Optional session ID to include in tokens
   * @param {Boolean} genRefreshToken - Whether to generate a new refresh token
   * @returns {Object} Object containing accessToken and refreshToken
   * @private
   */
  static _generateTokens(user, sessionId = null, genRefreshToken = true) {
    // Generate access token with user data and expiry
    const accessToken = jwt.sign(
      { 
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        sessionId,
        tokenVersion: user.tokenVersion || 0
      },
      config.jwt.secret,
      { expiresIn: config.jwt.accessExpiresIn }
    );

    // Only generate refresh token if required
    let refreshToken = null;
    if (genRefreshToken) {
      refreshToken = jwt.sign(
        { 
          id: user._id,
          sessionId,
          tokenVersion: user.tokenVersion || 0
        },
        config.jwt.refreshSecret,
        { expiresIn: config.jwt.refreshExpiresIn }
      );
    }

    return { accessToken, refreshToken };
  }

  /**
   * @method _setRefreshTokenCookie
   * @description Set refresh token as HTTP-only cookie
   * @param {Object} res - Express response object
   * @param {String} refreshToken - The refresh token to set
   * @param {Boolean} rememberMe - Whether to set extended expiry
   * @private
   */
  static _setRefreshTokenCookie(res, refreshToken, rememberMe = false) {
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/api/auth',
      maxAge: rememberMe 
        ? 30 * 24 * 60 * 60 * 1000 // 30 days
        : 24 * 60 * 60 * 1000 // 24 hours
    };

    res.cookie('refreshToken', refreshToken, cookieOptions);
  }

  /**
   * @method _clearRefreshTokenCookie
   * @description Clear refresh token cookie
   * @param {Object} res - Express response object
   * @private
   */
  static _clearRefreshTokenCookie(res) {
    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/api/auth'
    });
  }
}

// Export the controller
module.exports = AuthController;
};
/**
 * Register a new user with email verification
 * @route POST /api/auth/register
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @returns {Object} Response with registration status
 * @throws {ApiError} If validation fails or user creation fails
 */
exports.register = asyncWrapper(async (req, res) => {
  const { email, password, firstName, lastName, phoneNumber, role } = req.body;

  // Check if user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    throw new ApiError('Email already in use', 400);
  }

  // Create verification token
  const verificationToken = crypto.randomBytes(32).toString('hex');
  const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

  // Create user with verification token - enforce client role for public registration
  const user = await User.create({
    email,
    password,
    firstName,
    lastName,
    phoneNumber,
    role: role === 'client' ? 'client' : 'client', // Force client role for security
    emailVerificationToken: verificationToken,
    emailVerificationExpires: verificationExpires,
    tokenVersion: 0,
    loginAttempts: 0,
    lastLoginAttempt: null
  });

  // Generate verification URL
  const verificationUrl = `${config.frontendUrl}/verify-email?token=${verificationToken}`;

  try {
    // Send verification email
    await emailService.sendTemplateEmail({
      to: email,
      subject: 'Please verify your email address',
      template: 'verify-email',
      data: {
        name: firstName,
        verificationUrl,
        expiresIn: '24 hours',
        supportEmail: config.supportEmail
      }
    });

    logger.info(`New user registered: ${email}`);

    res.status(201).json({
      success: true,
      message: 'Registration successful. Please check your email to verify your account.'
    });
  } catch (error) {
    // If email fails, we should cleanup the created user to maintain consistency
    await User.findByIdAndDelete(user._id);
    logger.error(`Failed to send verification email to ${email}: ${error.message}`);
    throw new ApiError('Registration failed: Could not send verification email', 500);
  }
});

/**
 * Register staff member (admin, attorney, paralegal) - Admin only
 * @route POST /api/auth/register-staff
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @returns {Object} Response with registration status
 * @throws {ApiError} If validation fails or user creation fails
 */
exports.registerStaff = asyncWrapper(async (req, res) => {
  const { email, password, firstName, lastName, phoneNumber, role } = req.body;

  // Check if user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    throw new ApiError('Email already in use', 400);
  }

  // Create verification token
  const verificationToken = crypto.randomBytes(32).toString('hex');
  const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

  // Validate role is one of the allowed staff roles
  const allowedRoles = ['admin', 'attorney', 'paralegal'];
  const staffRole = allowedRoles.includes(role) ? role : 'paralegal'; // Default to paralegal

  // Create staff user with verification token
  const user = await User.create({
    email,
    password,
    firstName,
    lastName,
    phoneNumber,
    role: staffRole,
    emailVerificationToken: verificationToken,
    emailVerificationExpires: verificationExpires,
    tokenVersion: 0,
    loginAttempts: 0,
    lastLoginAttempt: null
  });

  // Generate verification URL
  const verificationUrl = `${config.frontendUrl}/verify-email?token=${verificationToken}`;

  try {
    // Send verification email
    await emailService.sendTemplateEmail({
      to: email,
      subject: 'Staff Account Created - Please verify your email',
      template: 'verify-email',
      data: {
        name: firstName,
        verificationUrl,
        expiresIn: '24 hours',
        supportEmail: config.supportEmail
      }
    });

    logger.info(`New staff member registered (${staffRole}): ${email}`);

    res.status(201).json({
      success: true,
      message: 'Staff registration successful. Please check the email to verify the account.'
    });
  } catch (error) {
    // If email fails, we should cleanup the created user to maintain consistency
    await User.findByIdAndDelete(user._id);
    logger.error(`Failed to send verification email to staff ${email}: ${error.message}`);
    throw new ApiError('Staff registration failed: Could not send verification email', 500);
  }
});
/**
 * Verify user

/**
 * Login user and generate JWT and refresh token
 */
exports.login = asyncWrapper(async (req, res) => {
  const { email, password } = req.body;

  // Validate email and password
  if (!email || !password) {
    throw new ApiError('Please provide email and password', 400);
  }

  // Check if user exists
  const user = await User.findOne({ email }).select('+password');
  if (!user) {
    throw new ApiError('Invalid credentials', 401);
  }

  // Check if password is correct
  const isPasswordCorrect = await user.comparePassword(password);
  if (!isPasswordCorrect) {
    throw new ApiError('Invalid credentials', 401);
  }

  // Check if email is verified
  if (!user.isEmailVerified) {
    throw new ApiError('Please verify your email before logging in', 401);
  }

  // Check if 2FA is enabled and verify if provided
  if (user.isTwoFactorEnabled) {
    const { twoFactorCode } = req.body;
    
    if (!twoFactorCode) {
      return res.status(200).json({
        success: true,
        requires2FA: true,
        message: 'Two-factor authentication code required'
      });
    }

    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: twoFactorCode,
      window: 1 // Allow 1 period before and after the current time
    });

    if (!verified) {
      throw new ApiError('Invalid two-factor authentication code', 401);
    }
  }

  // Generate tokens
  const { accessToken, refreshToken } = generateTokens(user);

  // Save refresh token to user
  user.refreshToken = refreshToken;
  await user.save({ validateBeforeSave: false });

  // Set refresh token as HTTP-only cookie
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: config.jwt.refreshExpiresInMs
  });

  // Remove password from response
  user.password = undefined;

  logger.info(`User logged in: ${user.email}`);

  res.status(200).json({
    success: true,
    accessToken,
    user: {
      id: user._id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
      isTwoFactorEnabled: user.isTwoFactorEnabled
    }
  });
});

/**
 * Logout user by clearing tokens
 */
exports.logout = asyncWrapper(async (req, res) => {
  const { refreshToken } = req.cookies;

  if (refreshToken) {
    const user = await User.findOne({ refreshToken });
    if (user) {
      user.refreshToken = undefined;
      await user.save({ validateBeforeSave: false });
    }
  }

  // Clear refresh token cookie
  res.clearCookie('refreshToken');

  logger.info('User logged out');

  res.status(200).json({
    success: true,
    message: 'Logged out successfully'
  });
});

/**
 * Request password reset
 */
exports.forgotPassword = asyncWrapper(async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });
  if (!user) {
    // Don't reveal that email doesn't exist for security
    return res.status(200).json({
      success: true,
      message: 'If a user with that email exists, a password reset link has been sent'
    });
  }

  // Create reset token
  const resetToken = crypto.randomBytes(32).toString('hex');
  const resetExpires = new Date(Date.now() + 1 * 60 * 60 * 1000); // 1 hour

  user.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
  user.passwordResetExpires = resetExpires;
  await user.save({ validateBeforeSave: false });

  // Generate reset URL
  const resetUrl = `${config.frontendUrl}/reset-password?token=${resetToken}`;

  try {
    // Send password reset email
    await emailService.sendTemplateEmail({
      to: email,
      subject: 'Your password reset request',
      template: 'reset-password',
      data: {
        name: user.firstName,
        resetUrl,
        expiresIn: '1 hour',
        supportEmail: config.supportEmail
      }
    });

    logger.info(`Password reset email sent to: ${email}`);

    res.status(200).json({
      success: true,
      message: 'If a user with that email exists, a password reset link has been sent'
    });
  } catch (error) {
    // If email fails, reset tokens in DB
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });

    logger.error(`Failed to send password reset email to ${email}: ${error.message}`);
    throw new ApiError('Failed to send password reset email', 500);
  }
});

/**
 * Reset password with token
 */
exports.resetPassword = asyncWrapper(async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  // Hash token to compare with stored hash
  const hashedToken = crypto
    .createHash('sha256')
    .update(token)
    .digest('hex');

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() }
  });

  if (!user) {
    throw new ApiError('Invalid or expired reset token', 400);
  }

  // Set new password and clear reset fields
  user.password = password;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();

  // Invalidate all existing sessions
  user.refreshToken = undefined;
  await user.save({ validateBeforeSave: false });

  logger.info(`Password reset successful for user: ${user.email}`);

  res.status(200).json({
    success: true,
    message: 'Password reset successful. You can now log in with your new password.'
  });
});

/**
 * Change password for logged-in user
 */
exports.changePassword = asyncWrapper(async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.user.id;

  const user = await User.findById(userId).select('+password');
  if (!user) {
    throw new ApiError('User not found', 404);
  }

  // Check if current password is correct
  const isPasswordCorrect = await user.comparePassword(currentPassword);
  if (!isPasswordCorrect) {
    throw new ApiError('Current password is incorrect', 401);
  }

  // Update password
  user.password = newPassword;
  await user.save();

  // Invalidate all existing sessions except current one
  user.refreshToken = undefined;
  await user.save({ validateBeforeSave: false });

  logger.info(`Password changed for user: ${user.email}`);

  res.status(200).json({
    success: true,
    message: 'Password changed successfully'
  });
});

/**
 * Refresh JWT token using refresh token
 */
exports.refreshToken = asyncWrapper(async (req, res) => {
  const { refreshToken } = req.cookies;

  if (!refreshToken) {
    throw new ApiError('Refresh token not provided', 401);
  }

  try {
    // Verify refresh token
    const decoded = jwt.verify(refreshToken, config.jwt.refreshSecret);

    // Find user with matching refresh token
    const user = await User.findOne({
      _id: decoded.id,
      refreshToken
    });

    if (!user) {
      throw new ApiError('Invalid refresh token', 401);
    }

    // Generate new tokens
    const newTokens = generateTokens(user);

    // Update refresh token in database
    user.refreshToken = newTokens.refreshToken;
    await user.save({ validateBeforeSave: false });

    // Set new refresh token as HTTP-only cookie
    res.cookie('refreshToken', newTokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: config.jwt.refreshExpiresInMs
    });

    logger.info(`Token refreshed for user: ${user.email}`);

    res.status(200).json({
      success: true,
      accessToken: newTokens.accessToken
    });
  } catch (error) {
    // Clear invalid refresh token
    res.clearCookie('refreshToken');
    throw new ApiError('Invalid or expired refresh token', 401);
  }
});

/**
 * Setup two-factor authentication
 */
exports.setupTwoFactor = asyncWrapper(async (req, res) => {
  const userId = req.user.id;

  const user = await User.findById(userId);
  if (!user) {
    throw new ApiError('User not found', 404);
  }

  // Generate new TOTP secret
  const secret = speakeasy.generateSecret({
    length: 20,
    name: `ImmigrationApp:${user.email}`
  });

  // Save secret to user
  user.twoFactorSecret = secret.base32;
  user.twoFactorTempSecret = secret.base32;
  await user.save({ validateBeforeSave: false });

  // Generate QR code
  const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);

  logger.info(`2FA setup initiated for user: ${user.email}`);

  res.status(200).json({
    success: true,
    secret: secret.base32,
    qrCode: qrCodeUrl
  });
});

/**
 * Verify and enable two-factor authentication
 */
exports.verifyTwoFactor = asyncWrapper(async (req, res) => {
  const { twoFactorCode } = req.body;
  const userId = req.user.id;

  const user = await User.findById(userId);
  if (!user) {
    throw new ApiError('User not found', 404);
  }

  if

const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const User = require('../models/user.model');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');
const { sendEmail } = require('../services/email.service');

// Helper function to create and send JWT token
const createSendToken = (user, statusCode, res) => {
  const token = jwt.sign(
    { id: user._id, role: user.role },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_EXPIRES_IN,
    }
  );

  // Remove password from output
  user.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user,
    },
  });
};

/**
 * @desc    Register a new user
 * @route   POST /api/auth/register
 * @access  Public
 */
exports.register = catchAsync(async (req, res, next) => {
  const { name, email, password, role } = req.body;

  // Check if email already exists
  const userExists = await User.findOne({ email });
  if (userExists) {
    return next(new AppError('Email already registered', 400));
  }

  // Create user with restricted role assignment (clients only for public registration)
  const user = await User.create({
    name,
    email,
    password,
    role: role === 'client' ? 'client' : 'client', // Force client role for security
  });

  createSendToken(user, 201, res);
});

/**
 * @desc    Register an admin, attorney, or paralegal (protected)
 * @route   POST /api/auth/register-staff
 * @access  Private/Admin
 */
exports.registerStaff = catchAsync(async (req, res, next) => {
  const { name, email, password, role } = req.body;

  // Check if email already exists
  const userExists = await User.findOne({ email });
  if (userExists) {
    return next(new AppError('Email already registered', 400));
  }

  // Create staff user with specified role
  const user = await User.create({
    name,
    email,
    password,
    role: ['admin', 'attorney', 'paralegal'].includes(role) ? role : 'paralegal',
  });

  createSendToken(user, 201, res);
});

/**
 * @desc    Login user
 * @route   POST /api/auth/login
 * @access  Public
 */
exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  // Check if email and password exist
  if (!email || !password) {
    return next(new AppError('Please provide email and password', 400));
  }

  // Check if user exists and password is correct
  const user = await User.findOne({ email }).select('+password');
  if (!user || !(await user.matchPassword(password))) {
    return next(new AppError('Invalid email or password', 401));
  }

  createSendToken(user, 200, res);
});

/**
 * @desc    Logout user / clear cookie
 * @route   GET /api/auth/logout
 * @access  Private
 */
exports.logout = catchAsync(async (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'Logged out successfully',
  });
});

/**
 * @desc    Get current user profile
 * @route   GET /api/auth/me
 * @access  Private
 */
exports.getMe = catchAsync(async (req, res, next) => {
  // User is already available in req.user due to protect middleware
  const user = await User.findById(req.user.id);

  res.status(200).json({
    status: 'success',
    data: {
      user,
    },
  });
});

/**
 * @desc    Update user profile
 * @route   PATCH /api/auth/updateme
 * @access  Private
 */
exports.updateMe = catchAsync(async (req, res, next) => {
  // Check if user is trying to update password
  if (req.body.password) {
    return next(new AppError('This route is not for password updates. Please use /updatepassword', 400));
  }

  // Filter out unwanted fields that shouldn't be updated
  const filteredBody = filterObj(req.body, 'name', 'email', 'phone', 'address');

  // Update user
  const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredBody, {
    new: true,
    runValidators: true,
  });

  res.status(200).json({
    status: 'success',
    data: {
      user: updatedUser,
    },
  });
});

/**
 * @desc    Update password
 * @route   PATCH /api/auth/updatepassword
 * @access  Private
 */
exports.updatePassword = catchAsync(async (req, res, next) => {
  const { currentPassword, newPassword } = req.body;

  // Get user from collection
  const user = await User.findById(req.user.id).select('+password');

  // Check if posted current password is correct
  if (!(await user.matchPassword(currentPassword))) {
    return next(new AppError('Your current password is incorrect', 401));
  }

  // Update password
  user.password = newPassword;
  await user.save();

  // Log user in with new password
  createSendToken(user, 200, res);
});

/**
 * @desc    Forgot password - send reset token
 * @route   POST /api/auth/forgotpassword
 * @access  Public
 */
exports.forgotPassword = catchAsync(async (req, res, next) => {
  // Get user by email
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return next(new AppError('There is no user with that email address', 404));
  }

  // Generate random reset token
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  // Send token to user's email
  const resetURL = `${req.protocol}://${req.get('host')}/api/auth/resetpassword/${resetToken}`;
  const message = `Forgot your password? Submit a PATCH request with your new password to: ${resetURL}.\nIf you didn't forget your password, please ignore this email.`;

  try {
    await sendEmail({
      email: user.email,
      subject: 'Your password reset token (valid for 10 minutes)',
      message,
    });

    res.status(200).json({
      status: 'success',
      message: 'Token sent to email',
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });

    return next(new AppError('There was an error sending the email. Try again later!', 500));
  }
});

/**
 * @desc    Reset password using token
 * @route   PATCH /api/auth/resetpassword/:token
 * @access  Public
 */
exports.resetPassword = catchAsync(async (req, res, next) => {
  // Get user based on token
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });

  // If token has not expired and there is a user, set new password
  if (!user) {
    return next(new AppError('Token is invalid or has expired', 400));
  }

  user.password = req.body.password;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();

  // Log the user in
  createSendToken(user, 200, res);
});

// Helper function to filter allowed fields
const filterObj = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach((el) => {
    if (allowedFields.includes(el)) newObj[el] = obj[el];
  });
  return newObj;
};

