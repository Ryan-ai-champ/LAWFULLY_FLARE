const express = require('express');
const router = express.Router();
const userController = require('../controllers/user.controller');
const authMiddleware = require('../middleware/auth.middleware');
const validateMiddleware = require('../middleware/validate.middleware');
const rateLimitMiddleware = require('../middleware/rateLimit.middleware');
const uploadMiddleware = require('../middleware/upload.middleware');

// Input validation schemas
const {
  createUserSchema,
  updateUserSchema,
  updateProfileSchema,
  changePasswordSchema,
  updateRoleSchema,
  updateStatusSchema,
  searchUsersSchema
} = require('../validations/user.validation');

/**
 * @route   POST /api/users
 * @desc    Create a new user (Admin only)
 * @access  Private/Admin
 */
router.post(
  '/',
  authMiddleware.verifyToken,
  authMiddleware.isAdmin,
  validateMiddleware(createUserSchema),
  rateLimitMiddleware.adminRoutes,
  userController.createUser
);

/**
 * @route   GET /api/users
 * @desc    Get all users with pagination and filtering
 * @access  Private/Admin
 */
router.get(
  '/',
  authMiddleware.verifyToken,
  authMiddleware.isAdmin,
  validateMiddleware(searchUsersSchema, 'query'),
  rateLimitMiddleware.adminRoutes,
  userController.getUsers
);

/**
 * @route   GET /api/users/:id
 * @desc    Get user by ID
 * @access  Private (Admin or own profile)
 */
router.get(
  '/:id',
  authMiddleware.verifyToken,
  authMiddleware.isAdminOrSameUser,
  userController.getUserById
);

/**
 * @route   PUT /api/users/:id
 * @desc    Update user by ID (Admin only)
 * @access  Private/Admin
 */
router.put(
  '/:id',
  authMiddleware.verifyToken,
  authMiddleware.isAdmin,
  validateMiddleware(updateUserSchema),
  userController.updateUser
);

/**
 * @route   DELETE /api/users/:id
 * @desc    Delete user by ID (Admin only)
 * @access  Private/Admin
 */
router.delete(
  '/:id',
  authMiddleware.verifyToken,
  authMiddleware.isAdmin,
  rateLimitMiddleware.adminRoutes,
  userController.deleteUser
);

/**
 * @route   PUT /api/users/:id/profile
 * @desc    Update user profile (Admin or own profile)
 * @access  Private
 */
router.put(
  '/:id/profile',
  authMiddleware.verifyToken,
  authMiddleware.isAdminOrSameUser,
  validateMiddleware(updateProfileSchema),
  userController.updateProfile
);

/**
 * @route   POST /api/users/:id/profile-image
 * @desc    Upload/update profile image
 * @access  Private (Admin or own profile)
 */
router.post(
  '/:id/profile-image',
  authMiddleware.verifyToken,
  authMiddleware.isAdminOrSameUser,
  uploadMiddleware.single('profileImage'),
  userController.uploadProfileImage
);

/**
 * @route   PUT /api/users/:id/password
 * @desc    Change user password (Admin or own profile)
 * @access  Private
 */
router.put(
  '/:id/password',
  authMiddleware.verifyToken,
  authMiddleware.isAdminOrSameUser,
  validateMiddleware(changePasswordSchema),
  rateLimitMiddleware.sensitiveRoutes,
  userController.changePassword
);

/**
 * @route   PUT /api/users/:id/role
 * @desc    Update user role (Admin only)
 * @access  Private/Admin
 */
router.put(
  '/:id/role',
  authMiddleware.verifyToken,
  authMiddleware.isAdmin,
  validateMiddleware(updateRoleSchema),
  rateLimitMiddleware.adminRoutes,
  userController.updateRole
);

/**
 * @route   PUT /api/users/:id/status
 * @desc    Update user account status (Admin only)
 * @access  Private/Admin
 */
router.put(
  '/:id/status',
  authMiddleware.verifyToken,
  authMiddleware.isAdmin,
  validateMiddleware(updateStatusSchema),
  rateLimitMiddleware.adminRoutes,
  userController.updateStatus
);

/**
 * @route   GET /api/users/search
 * @desc    Search users based on criteria
 * @access  Private/Admin
 */
router.get(
  '/search',
  authMiddleware.verifyToken,
  authMiddleware.isAdmin,
  validateMiddleware(searchUsersSchema, 'query'),
  userController.searchUsers
);

/**
 * @route   GET /api/users/roles
 * @desc    Get all available roles
 * @access  Private/Admin
 */
router.get(
  '/roles',
  authMiddleware.verifyToken,
  authMiddleware.isAdmin,
  userController.getRoles
);

/**
 * @route   GET /api/users/stats
 * @desc    Get user statistics
 * @access  Private/Admin
 */
router.get(
  '/stats',
  authMiddleware.verifyToken,
  authMiddleware.isAdmin,
  userController.getUserStats
);

/**
 * @route   POST /api/users/bulk-create
 * @desc    Bulk create users (Admin only)
 * @access  Private/Admin
 */
router.post(
  '/bulk-create',
  authMiddleware.verifyToken,
  authMiddleware.isAdmin,
  validateMiddleware(createUserSchema, 'array'),
  rateLimitMiddleware.adminRoutes,
  userController.bulkCreateUsers
);

/**
 * @route   GET /api/users/:id/activity
 * @desc    Get user activity logs
 * @access  Private (Admin or own profile)
 */
router.get(
  '/:id/activity',
  authMiddleware.verifyToken,
  authMiddleware.isAdminOrSameUser,
  userController.getUserActivity
);

/**
 * @route   PUT /api/users/:id/preferences
 * @desc    Update user preferences
 * @access  Private (Admin or own profile)
 */
router.put(
  '/:id/preferences',
  authMiddleware.verifyToken,
  authMiddleware.isAdminOrSameUser,
  userController.updatePreferences
);

module.exports = router;

