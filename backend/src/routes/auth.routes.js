const express = require('express');
const router = express.Router();
const authController = require('../controllers/auth.controller');
const { 
  authenticate, 
  checkRole, 
  verify2FA, 
  validateSession, 
  checkApiKey 
} = require('../middleware/auth.middleware');
const { validateRequest } = require('../middleware/validate.middleware');
const { 
  authLimiter, 
  passwordResetLimiter, 
  apiLimiter,
  adminLimiter,
  userLimiter 
} = require('../middleware/rateLimit.middleware');
const validators = require('../validators/auth.validators');
const { securityHeaders } = require('../middleware/security.middleware');
const { logRequest } = require('../middleware/logging.middleware');

/**
 * @fileoverview Authentication Routes
 * This file contains all routes related to authentication, user management, 
 * and access control. Routes are organized by access level and feature.
 */

// Apply common middleware to all routes
router.use(securityHeaders);
router.use(logRequest);

/**
 * ========================================
 * PUBLIC ROUTES (NO AUTHENTICATION REQUIRED)
 * ========================================
 */

/**
 * @route POST /api/auth/register
 * @desc Register a new user and send email verification
 * @access Public
 * @middleware 
 *   - Rate limiting to prevent abuse
 *   - Input validation for user data
 *   - Security headers
 */
router.post(
  '/register',
  authLimiter,
  validateRequest(validators.register),
  authController.register
);

/**
 * @route POST /api/auth/login
 * @desc Authenticate user and get tokens
 * @access Public
 * @middleware 
 *   - Rate limiting to prevent brute force
 *   - Input validation for credentials
 *   - IP tracking for suspicious activity
 */
router.post(
  '/login',
  authLimiter,
  validateRequest(validators.login),
  authController.login
);
/**
 * @route POST /api/auth/login/2fa
 * @desc Complete login with 2FA verification
 * @access Public (but requires first authentication step)
 * @middleware 
 *   - Rate limiting to prevent brute force
 *   - Input validation for 2FA token
 */
router.post(
  '/login/2fa',
  authLimiter,
  validateRequest(validators.verify2FA),
  authController.verify2FAAndLogin
);

/**
 * @route POST /api/auth/refresh
 * @desc Refresh access token using refresh token
 * @access Public (requires valid refresh token)
 * @middleware 
 *   - Rate limiting to prevent abuse
 *   - Cookie verification
 */
router.post(
  '/refresh',
  authLimiter,
  authController.refreshToken
);

/**
 * @route POST /api/auth/password/forgot
 * @desc Request password reset email
 * @access Public
 * @middleware 
 *   - Rate limiting to prevent abuse
 *   - Input validation for email
 */
router.post(
  '/password/forgot',
  passwordResetLimiter,
  validateRequest(validators.forgotPassword),
  authController.forgotPassword
);

/**
 * @route POST /api/auth/password/reset/:token
 * @desc Reset password using reset token
 * @access Public (requires valid reset token)
 * @middleware 
 *   - Rate limiting to prevent abuse
 *   - Input validation for password
 */
router.post(
  '/password/reset/:token',
  passwordResetLimiter,
  validateRequest(validators.resetPassword),
  authController.resetPassword
);

/**
 * @route GET /api/auth/verify-email/:token
 * @desc Verify user email with token
 * @access Public (requires valid email token)
 */
router.get(
  '/verify-email/:token',
  authController.verifyEmail
);

/**
 * ========================================
 * PROTECTED ROUTES (AUTHENTICATION REQUIRED)
 * ========================================
 */

/**
 * @route POST /api/auth/logout
 * @desc Logout user and invalidate tokens
 * @access Protected
 * @middleware 
 *   - Authentication token verification
 *   - Session validation
 */
router.post(
  '/logout',
  authenticate,
  validateSession,
  authController.logout
);

/**
 * ========================================
 * USER PROFILE ROUTES
 * ========================================
 */

/**
 * @route GET /api/auth/profile
 * @desc Get current user profile
 * @access Protected
 * @middleware 
 *   - Authentication token verification
 *   - Session validation
 */
router.get(
  '/profile',
  authenticate,
  validateSession,
  userLimiter,
  authController.getProfile
);

/**
 * @route PUT /api/auth/profile
 * @desc Update user profile
 * @access Protected
 * @middleware 
 *   - Authentication token verification
 *   - Session validation
 *   - Input validation for profile data
 */
router.put(
  '/profile',
  authenticate,
  validateSession,
  userLimiter,
  validateRequest(validators.updateProfile),
  authController.updateProfile
);

/**
 * @route PUT /api/auth/password/change
 * @desc Change user password
 * @access Protected
 * @middleware 
 *   - Authentication token verification
 *   - Session validation
 *   - Input validation for password
 */
router.put(
  '/password/change',
  authenticate,
  validateSession,
  passwordResetLimiter,
  validateRequest(validators.changePassword),
  authController.changePassword
);

/**
 * ========================================
 * 2FA MANAGEMENT ROUTES
 * ========================================
 */

/**
 * @route POST /api/auth/2fa/setup
 * @desc Initialize 2FA setup and return QR code
 * @access Protected
 * @middleware 
 *   - Authentication token verification
 *   - Session validation
 */
router.post(
  '/2fa/setup',
  authenticate,
  validateSession,
  userLimiter,
  authController.setup2FA
);

/**
 * @route POST /api/auth/2fa/enable
 * @desc Verify and enable 2FA
 * @access Protected
 * @middleware 
 *   - Authentication token verification
 *   - Session validation
 *   - Input validation for 2FA token
 */
router.post(
  '/2fa/enable',
  authenticate,
  validateSession,
  userLimiter,
  validateRequest(validators.verify2FA),
  authController.enable2FA
);

/**
 * @route POST /api/auth/2fa/disable
 * @desc Disable 2FA
 * @access Protected
 * @middleware 
 *   - Authentication token verification
 *   - Session validation
 *   - 2FA verification
 *   - Input validation for 2FA token
 */
router.post(
  '/2fa/disable',
  authenticate,
  validateSession,
  verify2FA,
  validateRequest(validators.verify2FA),
  authController.disable2FA
);

/**
 * @route GET /api/auth/2fa/backup-codes
 * @desc Generate new backup codes for 2FA
 * @access Protected
 * @middleware 
 *   - Authentication token verification
 *   - Session validation
 *   - 2FA verification
 */
router.get(
  '/2fa/backup-codes',
  authenticate,
  validateSession,
  verify2FA,
  userLimiter,
  authController.generateBackupCodes
);

/**
 * ========================================
 * SESSION MANAGEMENT ROUTES
 * ========================================
 */

/**
 * @route GET /api/auth/sessions
 * @desc Get all active sessions for current user
 * @access Protected
 * @middleware 
 *   - Authentication token verification
 *   - Session validation
 */
router.get(
  '/sessions',
  authenticate,
  validateSession,
  userLimiter,
  authController.getSessions
);

/**
 * @route DELETE /api/auth/sessions/:sessionId
 * @desc Terminate a specific session
 * @access Protected
 * @middleware 
 *   - Authentication token verification
 *   - Session validation
 */
router.delete(
  '/sessions/:sessionId',
  authenticate,
  validateSession,
  userLimiter,
  authController.terminateSession
);

/**
 * @route DELETE /api/auth/sessions
 * @desc Terminate all sessions except current
 * @access Protected
 * @middleware 
 *   - Authentication token verification
 *   - Session validation
 */
router.delete(
  '/sessions',
  authenticate,
  validateSession,
  userLimiter,
  authController.terminateAllSessions
);

/**
 * ========================================
 * API ACCESS MANAGEMENT ROUTES
 * ========================================
 */

/**
 * @route POST /api/auth/api-keys
 * @desc Generate a new API key
 * @access Protected
 * @middleware 
 *   - Authentication token verification
 *   - Session validation
 *   - 2FA verification for sensitive operation
 *   - Input validation for API key details
 */
router.post(
  '/api-keys',
  authenticate,
  validateSession,
  verify2FA,
  apiLimiter,
  validateRequest(validators.createApiKey),
  authController.createApiKey
);

/**
 * @route GET /api/auth/api-keys
 * @desc Get all API keys for current user
 * @access Protected
 * @middleware 
 *   - Authentication token verification
 *   - Session validation
 */
router.get(
  '/api-keys',
  authenticate,
  validateSession,
  apiLimiter,
  authController.getApiKeys
);

/**
 * @route DELETE /api/auth/api-keys/:keyId
 * @desc Revoke a specific API key
 * @access Protected
 * @middleware 
 *   - Authentication token verification
 *   - Session validation
 */
router.delete(
  '/api-keys/:keyId',
  authenticate,
  validateSession,
  apiLimiter,
  authController.revokeApiKey
);

/**
 * ========================================
 * ADMIN ROUTES (ADMIN ROLE REQUIRED)
 * ========================================
 */

/**
 * @route GET /api/auth/users
 * @desc Get list of all users (with pagination, filtering)
 * @access Admin only
 * @middleware 
 *   - Authentication token verification
 *   - Session validation
 *   - Admin role check
 *   - Rate limiting for admin actions
 */
router.get(
  '/users',
  authenticate,
  validateSession,
  checkRole('admin'),
  adminLimiter,
  authController.getUsers
);

/**
 * @route GET /api/auth/users/:userId
 * @desc Get specific user details
 * @access Admin only
 * @middleware 
 *   - Authentication token verification
 *   - Session validation
 *   - Admin role check
 */
router.get(
  '/users/:userId',
  authenticate,
  validateSession,
  checkRole('admin'),
  adminLimiter,
  authController.getUserById
);

/**
 * @route PUT /api/auth/users/:userId
 * @desc Update user details (admin operation)
 * @access Admin only
 * @middleware 
 *   - Authentication token verification
 *   - Session validation
 *   - Admin role check
 *   - Input validation for user data
 */
router.put(
  '/users/:userId',
  authenticate,
  validateSession,
  checkRole('admin'),
  adminLimiter,
  validateRequest(validators.updateUser),
  authController.updateUser
);

/**
 * @route POST /api/auth/staff/register
 * @desc Register a new staff member (admin operation)
 * @access Admin only
 * @middleware 
 *   - Authentication token verification
 *   - Session validation
 *   - Admin role check
 *   - Input validation for user data
 */
router.post(
  '/staff/register',
  authenticate,
  validateSession,
  checkRole('admin'),
  adminLimiter,
  validateRequest(validators.registerStaff),
  authController.registerStaff
);

/**
 * @route PUT /api/auth/users/:userId/status
 * @desc Change user status (activate/deactivate)
 * @access Admin only
 * @middleware 
 *   - Authentication token verification
 *   - Session validation
 *   - Admin role check
 *   - Input validation for status change
 */
router.put(
  '/users/:userId/status',
  authenticate,
  validateSession,
  checkRole('admin'),
  adminLimiter,
  validateRequest(validators.changeUserStatus),
  authController.changeUserStatus
);

/**
 * @route PUT /api/auth/users/:userId/role
 * @desc Change user role
 * @access Admin only
 * @middleware 
 *   - Authentication token verification
 *   - Session validation
 *   - Admin role check
 *   - Input validation for role change
 */
router.put(
  '/users/:userId/role',
  authenticate,
  validateSession,
  checkRole('admin'),
  adminLimiter,
  validateRequest(validators.changeUserRole),
  authController.changeUserRole
);

/**
 * @route DELETE /api/auth/users/:userId
 * @desc Delete user (admin operation)
 * @access Admin only
 * @middleware 
 *   - Authentication token verification
 *   - Session validation
 *   - Admin role check
 *   - 2FA verification for sensitive operation
 */
router.delete(
  '/users/:userId',
  authenticate,
  validateSession,
  checkRole('admin'),
  verify2FA,
  adminLimiter,
  authController.deleteUser
);

/**
