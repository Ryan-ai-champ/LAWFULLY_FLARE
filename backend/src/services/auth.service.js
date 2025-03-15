const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/user.model');
const { ApiError } = require('../utils/error.utils');
const logger = require('../utils/logger.utils');

/**
 * Auth Service
 * Handles all authentication-related operations
 * @module AuthService
 */
class AuthService {
  constructor() {
    this.secretKey = process.env.JWT_SECRET || 'immigration-app-secret-key';
    this.tokenExpiry = process.env.JWT_EXPIRY || '1d';
    this.refreshTokenExpiry = process.env.REFRESH_TOKEN_EXPIRY || '7d';
    // Store active sessions - in production, use Redis or database
    this.activeSessions = new Map();
  }

  /**
   * Generate JWT token
   * @param {Object} payload - Data to encode in the token
   * @param {String} expiry - Token expiration time
   * @returns {String} JWT token
   */
  generateToken(payload, expiry = this.tokenExpiry) {
    try {
      return jwt.sign(payload, this.secretKey, { expiresIn: expiry });
    } catch (error) {
      logger.error(`Token generation failed: ${error.message}`);
      throw new ApiError(500, 'Failed to generate authentication token');
    }
  }

  /**
   * Verify JWT token
   * @param {String} token - JWT token to verify
   * @returns {Object} Decoded token payload
   */
  verifyToken(token) {
    try {
      return jwt.verify(token, this.secretKey);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new ApiError(401, 'Token has expired');
      }
      if (error.name === 'JsonWebTokenError') {
        throw new ApiError(401, 'Invalid token');
      }
      logger.error(`Token verification failed: ${error.message}`);
      throw new ApiError(500, 'Failed to verify token');
    }
  }

  /**
   * Hash password
   * @param {String} password - Plain text password
   * @returns {String} Hashed password
   */
  async hashPassword(password) {
    try {
      const salt = await bcrypt.genSalt(10);
      return await bcrypt.hash(password, salt);
    } catch (error) {
      logger.error(`Password hashing failed: ${error.message}`);
      throw new ApiError(500, 'Failed to hash password');
    }
  }

  /**
   * Compare password with hash
   * @param {String} password - Plain text password
   * @param {String} hash - Hashed password
   * @returns {Boolean} True if password matches hash
   */
  async comparePassword(password, hash) {
    try {
      return await bcrypt.compare(password, hash);
    } catch (error) {
      logger.error(`Password comparison failed: ${error.message}`);
      throw new ApiError(500, 'Failed to verify password');
    }
  }

  /**
   * Authenticate user
   * @param {String} email - User email
   * @param {String} password - User password
   * @returns {Object} User data and tokens
   */
  async authenticateUser(email, password) {
    try {
      // Find user by email
      const user = await User.findOne({ email });
      if (!user) {
        throw new ApiError(401, 'Invalid email or password');
      }

      // Verify password
      const isPasswordValid = await this.comparePassword(password, user.password);
      if (!isPasswordValid) {
        throw new ApiError(401, 'Invalid email or password');
      }

      // Check if account is active
      if (!user.active) {
        throw new ApiError(403, 'Account is deactivated');
      }

      // Generate tokens
      const payload = { 
        userId: user._id, 
        email: user.email, 
        role: user.role 
      };
      
      const accessToken = this.generateToken(payload);
      const refreshToken = this.generateToken(payload, this.refreshTokenExpiry);

      // Store session
      this.createSession(user._id.toString(), refreshToken);

      return {
        user: {
          _id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          role: user.role
        },
        tokens: {
          accessToken,
          refreshToken
        }
      };
    } catch (error) {
      // Re-throw ApiError instances
      if (error instanceof ApiError) {
        throw error;
      }
      logger.error(`Authentication failed: ${error.message}`);
      throw new ApiError(500, 'Authentication failed');
    }
  }

  /**
   * Register new user
   * @param {Object} userData - User data
   * @returns {Object} Created user
   */
  async registerUser(userData) {
    try {
      // Check if user already exists
      const existingUser = await User.findOne({ email: userData.email });
      if (existingUser) {
        throw new ApiError(409, 'Email is already in use');
      }

      // Hash password
      const hashedPassword = await this.hashPassword(userData.password);

      // Create new user
      const user = new User({
        ...userData,
        password: hashedPassword,
        role: userData.role || 'user',
        active: true,
        createdAt: new Date()
      });

      await user.save();

      return {
        _id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role
      };
    } catch (error) {
      // Re-throw ApiError instances
      if (error instanceof ApiError) {
        throw error;
      }
      logger.error(`User registration failed: ${error.message}`);
      throw new ApiError(500, 'Failed to register user');
    }
  }

  /**
   * Refresh access token
   * @param {String} refreshToken - Refresh token
   * @returns {Object} New access token and refresh token
   */
  async refreshToken(refreshToken) {
    try {
      // Verify refresh token
      const decoded = this.verifyToken(refreshToken);
      
      // Check if token is in active sessions
      const isSessionActive = this.getSessionByToken(refreshToken);
      
      if (!isSessionActive) {
        throw new ApiError(401, 'Invalid refresh token');
      }

      // Generate new tokens
      const payload = { 
        userId: decoded.userId, 
        email: decoded.email, 
        role: decoded.role 
      };
      
      const newAccessToken = this.generateToken(payload);
      const newRefreshToken = this.generateToken(payload, this.refreshTokenExpiry);

      // Update session
      this.updateSession(decoded.userId, refreshToken, newRefreshToken);

      return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken
      };
    } catch (error) {
      // Re-throw ApiError instances
      if (error instanceof ApiError) {
        throw error;
      }
      logger.error(`Token refresh failed: ${error.message}`);
      throw new ApiError(500, 'Failed to refresh token');
    }
  }

  /**
   * Create new session
   * @param {String} userId - User ID
   * @param {String} token - Refresh token
   */
  createSession(userId, token) {
    // For each user, store an array of active refresh tokens (for multiple devices)
    if (!this.activeSessions.has(userId)) {
      this.activeSessions.set(userId, []);
    }
    
    this.activeSessions.get(userId).push(token);
    
    // In production, store this in Redis or database
    logger.info(`Session created for user ${userId}`);
  }

  /**
   * Get session by token
   * @param {String} token - Refresh token
   * @returns {Boolean} True if session exists
   */
  getSessionByToken(token) {
    // Check all users' sessions for the token
    for (const [userId, tokens] of this.activeSessions.entries()) {
      if (tokens.includes(token)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Update session
   * @param {String} userId - User ID
   * @param {String} oldToken - Old refresh token
   * @param {String} newToken - New refresh token
   */
  updateSession(userId, oldToken, newToken) {
    if (this.activeSessions.has(userId)) {
      const tokens = this.activeSessions.get(userId);
      const index = tokens.indexOf(oldToken);
      
      if (index !== -1) {
        tokens[index] = newToken;
        this.activeSessions.set(userId, tokens);
        logger.info(`Session updated for user ${userId}`);
      }
    }
  }

  /**
   * Invalidate session (logout)
   * @param {String} userId - User ID
   * @param {String} token - Refresh token to invalidate
   * @returns {Boolean} True if successful
   */
  invalidateSession(userId, token) {
    try {
      if (this.activeSessions.has(userId)) {
        const tokens = this.activeSessions.get(userId);
        const index = tokens.indexOf(token);
        
        if (index !== -1) {
          tokens.splice(index, 1);
          this.activeSessions.set(userId, tokens);
          logger.info(`Session invalidated for user ${userId}`);
          return true;
        }
      }
      return false;
    } catch (error) {
      logger.error(`Session invalidation failed: ${error.message}`);
      return false;
    }
  }

  /**
   * Check if user has required permissions
   * @param {String} userRole - User role
   * @param {Array} allowedRoles - Array of allowed roles
   * @returns {Boolean} True if user has permission
   */
  checkPermission(userRole, allowedRoles) {
    return allowedRoles.includes(userRole);
  }

  /**
   * Get permission middleware
   * @param {Array} allowedRoles - Array of allowed roles
   * @returns {Function} Express middleware
   */
  permitRoles(allowedRoles) {
    return (req, res, next) => {
      if (!req.user) {
        return res.status(401).json({ 
          success: false, 
          message: 'Authentication required' 
        });
      }

      if (this.checkPermission(req.user.role, allowedRoles)) {
        return next();
      }

      return res.status(403).json({ 
        success: false, 
        message: 'You do not have permission to access this resource' 
      });
    };
  }
}

// Create singleton instance
const authService = new AuthService();
Object.freeze(authService);

module.exports = authService;

