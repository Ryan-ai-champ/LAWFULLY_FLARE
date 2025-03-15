const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const asyncWrapper = require('../utils/asyncWrapper');
const ApiError = require('../utils/apiError');
const User = require('../models/user.model');
const emailService = require('../services/email.service');
const config = require('../config/config');
const logger = require('../utils/logger');

/**
 * Generate and return access and refresh tokens
 * @param {Object} user - User document from database
 * @returns {Object} - Object containing tokens
 */
const generateTokens = (user) => {
  const accessToken = jwt.sign(
    { 
      id: user._id, 
      email: user.email,
      role: user.role
    },
    config.jwt.accessSecret,
    { expiresIn: config.jwt.accessExpiresIn }
  );

  const refreshToken = jwt.sign(
    { id: user._id },
    config.jwt.refreshSecret,
    { expiresIn: config.jwt.refreshExpiresIn }
  );

  return { accessToken, refreshToken };
};

/**
 * Register a new user with email verification
 */
exports.register = asyncWrapper(async (req, res) => {
  const { email, password, firstName, lastName, phoneNumber } = req.body;

  // Check if user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    throw new ApiError('Email already in use', 400);
  }

  // Create verification token
  const verificationToken = crypto.randomBytes(32).toString('hex');
  const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

  // Create user with verification token
  const user = await User.create({
    email,
    password,
    firstName,
    lastName,
    phoneNumber,
    emailVerificationToken: verificationToken,
    emailVerificationExpires: verificationExpires,
  });

  // Generate verification URL
  const verificationUrl = `${config.frontendUrl}/verify-email?token=${verificationToken}`;

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
});

/**
 * Verify user email with token
 */
exports.verifyEmail = asyncWrapper(async (req, res) => {
  const { token } = req.params;

  const user = await User.findOne({
    emailVerificationToken: token,
    emailVerificationExpires: { $gt: Date.now() }
  });

  if (!user) {
    throw new ApiError('Invalid or expired verification token', 400);
  }

  // Update user status
  user.isEmailVerified = true;
  user.emailVerificationToken = undefined;
  user.emailVerificationExpires = undefined;
  await user.save();

  logger.info(`Email verified for user: ${user.email}`);

  res.status(200).json({
    success: true,
    message: 'Email verification successful. You can now log in.'
  });
});

/**
 * Resend email verification token
 */
exports.resendVerificationEmail = asyncWrapper(async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });
  if (!user) {
    throw new ApiError('User not found', 404);
  }

  if (user.isEmailVerified) {
    throw new ApiError('Email already verified', 400);
  }

  // Create new verification token
  const verificationToken = crypto.randomBytes(32).toString('hex');
  const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

  user.emailVerificationToken = verificationToken;
  user.emailVerificationExpires = verificationExpires;
  await user.save();

  // Generate verification URL
  const verificationUrl = `${config.frontendUrl}/verify-email?token=${verificationToken}`;

  // Send verification email
  await emailService.sendTemplateEmail({
    to: email,
    subject: 'Please verify your email address',
    template: 'verify-email',
    data: {
      name: user.firstName,
      verificationUrl,
      expiresIn: '24 hours',
      supportEmail: config.supportEmail
    }
  });

  logger.info(`Verification email resent to: ${email}`);

  res.status(200).json({
    success: true,
    message: 'Verification email resent successfully'
  });
});

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

