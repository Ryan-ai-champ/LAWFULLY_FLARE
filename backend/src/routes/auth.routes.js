const express = require('express');
const router = express.Router();
const authController = require('../controllers/auth.controller');
const { authenticate } = require('../middleware/auth.middleware');
const { validateRequest } = require('../middleware/validate.middleware');
const { authLimiter, passwordResetLimiter } = require('../middleware/rateLimit.middleware');
const validators = require('../validators/auth.validators');

/**
 * @route POST /api/auth/register
 * @desc Register a new user and send email verification
 * @access Public
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
 */
router.post(
  '/login',
  authLimiter,
  validateRequest(validators.login),
  authController.login
);

/**
 * @route POST /api/auth/logout
 * @desc Logout user and invalidate tokens
 * @access Private
 */
router.post(
  '/logout',
  authenticate,
  authController.logout
);

/**
 * @route POST /api/auth/refresh-token
 * @desc Refresh access token using refresh token
 * @access Public
 */
router.post(
  '/refresh-token',
  authLimiter,
  validateRequest(validators.refreshToken),
  authController.refreshToken
);

/**
 * @route POST /api/auth/forgot-password
 * @desc Send password reset email
 * @access Public
 */
router.post(
  '/forgot-password',
  passwordResetLimiter,
  validateRequest(validators.forgotPassword),
  authController.forgotPassword
);

/**
 * @route POST /api/auth/reset-password/:token
 * @desc Reset password using token
 * @access Public
 */
router.post(
  '/reset-password/:token',
  passwordResetLimiter,
  validateRequest(validators.resetPassword),
  authController.resetPassword
);

/**
 * @route PUT /api/auth/change-password
 * @desc Change password (when user is logged in)
 * @access Private
 */
router.put(
  '/change-password',
  authenticate,
  validateRequest(validators.changePassword),
  authController.changePassword
);

/**
 * @route GET /api/auth/verify-email/:token
 * @desc Verify user email with token
 * @access Public
 */
router.get(
  '/verify-email/:token',
  authController.verifyEmail
);

/**
 * @route POST /api/auth/resend-verification
 * @desc Resend email verification link
 * @access Public
 */
router.post(
  '/resend-verification',
  authLimiter,
  validateRequest(validators.resendVerification),
  authController.resendVerification
);

/**
 * @route GET /api/auth/profile
 * @desc Get user profile
 * @access Private
 */
router.get(
  '/profile',
  authenticate,
  authController.getProfile
);

/**
 * @route PUT /api/auth/profile
 * @desc Update user profile
 * @access Private
 */
router.put(
  '/profile',
  authenticate,
  validateRequest(validators.updateProfile),
  authController.updateProfile
);

/**
 * @route DELETE /api/auth/profile
 * @desc Delete user account
 * @access Private
 */
router.delete(
  '/profile',
  authenticate,
  validateRequest(validators.deleteAccount),
  authController.deleteAccount
);

/**
 * @route POST /api/auth/setup-2fa
 * @desc Setup two-factor authentication
 * @access Private
 */
router.post(
  '/setup-2fa',
  authenticate,
  authController.setup2FA
);

/**
 * @route POST /api/auth/verify-2fa
 * @desc Verify two-factor authentication
 * @access Private
 */
router.post(
  '/verify-2fa',
  authenticate,
  validateRequest(validators.verify2FA),
  authController.verify2FA
);

/**
 * @route POST /api/auth/disable-2fa
 * @desc Disable two-factor authentication
 * @access Private
 */
router.post(
  '/disable-2fa',
  authenticate,
  validateRequest(validators.disable2FA),
  authController.disable2FA
);

/**
 * @route GET /api/auth/sessions
 * @desc Get all active sessions
 * @access Private
 */
router.get(
  '/sessions',
  authenticate,
  authController.getSessions
);

/**
 * @route DELETE /api/auth/sessions/:sessionId
 * @desc Terminate a specific session
 * @access Private
 */
router.delete(
  '/sessions/:sessionId',
  authenticate,
  validateRequest(validators.terminateSession),
  authController.terminateSession
);

/**
 * @route DELETE /api/auth/sessions
 * @desc Terminate all sessions except current
 * @access Private
 */
router.delete(
  '/sessions',
  authenticate,
  authController.terminateAllSessions
);

module.exports = router;

const express = require('express');
const { body } = require('express-validator');
const authController = require('../controllers/auth.controller');
const { verifyToken } = require('../middleware/auth.middleware');

const router = express.Router();

// Log auth controller functions
console.log('Login Function:', authController.login);
console.log('Register Function:', authController.register);

/**
 * @route POST /api/auth/register
 * @desc Register a new user
 * @access Public
 */
router.post(
  '/register',
  [
    body('email').isEmail().withMessage('Please provide a valid email'),
    body('password')
      .isLength({ min: 8 })
      .withMessage('Password must be at least 8 characters long')
      .matches(/\d/)
      .withMessage('Password must contain a number')
      .matches(/[A-Z]/)
      .withMessage('Password must contain an uppercase letter'),
    body('firstName').notEmpty().withMessage('First name is required'),
    body('lastName').notEmpty().withMessage('Last name is required'),
    body('role').optional().isIn(['client', 'attorney', 'paralegal', 'admin'])
      .withMessage('Invalid role specified')
  ],
  authController.register
);

/**
 * @route POST /api/auth/login
 * @desc Login user and return JWT token
 * @access Public
 */
router.post(
  '/login',
  [
    body('email').isEmail().withMessage('Please provide a valid email'),
    body('password').notEmpty().withMessage('Password is required')
  ],
  authController.login
);

/**
 * @route POST /api/auth/logout
 * @desc Logout user / clear cookie if using cookie auth
 * @access Private
 */
router.post('/logout', verifyToken, authController.logout);

/**
 * @route GET /api/auth/profile
 * @desc Get user profile
 * @access Private
 */
router.get('/profile', verifyToken, authController.getProfile);

/**
 * @route PUT /api/auth/profile
 * @desc Update user profile
 * @access Private
 */
router.put(
  '/profile',
  verifyToken,
  [
    body('email').optional().isEmail().withMessage('Please provide a valid email'),
    body('firstName').optional().notEmpty().withMessage('First name cannot be empty'),
    body('lastName').optional().notEmpty().withMessage('Last name cannot be empty'),
    body('phone').optional().isMobilePhone().withMessage('Please provide a valid phone number')
  ],
  authController.updateProfile
);

/**
 * @route POST /api/auth/forgot-password
 * @desc Request password reset email
 * @access Public
 */
router.post(
  '/forgot-password',
  [
    body('email').isEmail().withMessage('Please provide a valid email')
  ],
  authController.forgotPassword
);

/**
 * @route POST /api/auth/reset-password/:token
 * @desc Reset password with token
 * @access Public
 */
router.post(
  '/reset-password/:token',
  [
    body('password')
      .isLength({ min: 8 })
      .withMessage('Password must be at least 8 characters long')
      .matches(/\d/)
      .withMessage('Password must contain a number')
      .matches(/[A-Z]/)
      .withMessage('Password must contain an uppercase letter'),
    body('confirmPassword').custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Password confirmation does not match password');
      }
      return true;
    })
  ],
  authController.resetPassword
);

/**
 * @route POST /api/auth/change-password
 * @desc Change password when logged in
 * @access Private
 */
router.post(
  '/change-password',
  verifyToken,
  [
    body('currentPassword').notEmpty().withMessage('Current password is required'),
    body('newPassword')
      .isLength({ min: 8 })
      .withMessage('Password must be at least 8 characters long')
      .matches(/\d/)
      .withMessage('Password must contain a number')
      .matches(/[A-Z]/)
      .withMessage('Password must contain an uppercase letter'),
    body('confirmPassword').custom((value, { req }) => {
      if (value !== req.body.newPassword) {
        throw new Error('Password confirmation does not match password');
      }
      return true;
    })
  ],
  authController.changePassword
);

/**
 * @route GET /api/auth/verify-email/:token
 * @desc Verify user email with token
 * @access Public
 */
router.get('/verify-email/:token', authController.verifyEmail);

/**
 * @route POST /api/auth/refresh-token
 * @desc Refresh JWT token
 * @access Public
 */
router.post('/refresh-token', authController.refreshToken);

module.exports = router;

