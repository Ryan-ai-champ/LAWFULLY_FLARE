/**
 * Authentication validation middleware
 * Contains validation chains for all authentication-related operations
 * @module validators/auth
 */

const { body, param, query, validationResult } = require('express-validator');
const { ApiError } = require('../utils/appError');
const UserModel = require('../models/user.model');

/**
 * Custom validation middleware that throws a structured API error
 * @function validateRequest
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @throws {ApiError} Throws if validation fails
 */
const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const errorMessages = errors.array().map(error => error.msg);
    throw new ApiError(400, 'Validation error', errorMessages);
  }
  next();
};

/**
 * Custom email validator that checks if email is already registered
 * @function isEmailAvailable
 * @param {string} email - Email to check
 * @param {Object} meta - Validation meta information
 * @returns {Promise<boolean>} Returns true if email is available
 * @throws {Error} Throws if email is already taken
 */
const isEmailAvailable = async (email, { req }) => {
  const user = await UserModel.findOne({ email: email.toLowerCase() });
  if (user) {
    throw new Error('Email is already registered');
  }
  return true;
};

/**
 * Custom username validator that checks if username is already taken
 * @function isUsernameAvailable
 * @param {string} username - Username to check
 * @param {Object} meta - Validation meta information
 * @returns {Promise<boolean>} Returns true if username is available
 * @throws {Error} Throws if username is already taken
 */
const isUsernameAvailable = async (username, { req }) => {
  const user = await UserModel.findOne({ username: username.toLowerCase() });
  if (user) {
    throw new Error('Username is already taken');
  }
  return true;
};

/**
 * Custom validator to check if passwords match
 * @function passwordsMatch
 * @param {string} confirmPassword - Password confirmation
 * @param {Object} meta - Validation meta information
 * @returns {boolean} Returns true if passwords match
 * @throws {Error} Throws if passwords don't match
 */
const passwordsMatch = (confirmPassword, { req }) => {
  if (confirmPassword !== req.body.password) {
    throw new Error('Passwords do not match');
  }
  return true;
};

/**
 * Custom validator to check if current password is correct
 * @function isCurrentPasswordCorrect
 * @param {string} currentPassword - Current password
 * @param {Object} meta - Validation meta information
 * @returns {Promise<boolean>} Returns true if current password is correct
 * @throws {Error} Throws if current password is incorrect
 */
const isCurrentPasswordCorrect = async (currentPassword, { req }) => {
  const user = await UserModel.findById(req.user.id).select('+password');
  if (!user || !(await user.comparePassword(currentPassword))) {
    throw new Error('Current password is incorrect');
  }
  return true;
};

/**
 * Custom validator to check if API key exists
 * @function doesApiKeyExist
 * @param {string} id - API key ID
 * @param {Object} meta - Validation meta information
 * @returns {Promise<boolean>} Returns true if API key exists
 * @throws {Error} Throws if API key doesn't exist
 */
const doesApiKeyExist = async (id, { req }) => {
  const user = await UserModel.findById(req.user.id);
  if (!user || !user.apiKeys.find(key => key._id.toString() === id)) {
    throw new Error('API key not found');
  }
  return true;
};

/**
 * Custom validator to check if session exists
 * @function doesSessionExist
 * @param {string} id - Session ID
 * @param {Object} meta - Validation meta information
 * @returns {Promise<boolean>} Returns true if session exists
 * @throws {Error} Throws if session doesn't exist
 */
const doesSessionExist = async (id, { req }) => {
  const user = await UserModel.findById(req.user.id);
  if (!user || !user.sessions.find(session => session._id.toString() === id)) {
    throw new Error('Session not found');
  }
  return true;
};

/**
 * Custom validator to check if user exists
 * @function doesUserExist
 * @param {string} id - User ID
 * @param {Object} meta - Validation meta information
 * @returns {Promise<boolean>} Returns true if user exists
 * @throws {Error} Throws if user doesn't exist
 */
const doesUserExist = async (id, { req }) => {
  const user = await UserModel.findById(id);
  if (!user) {
    throw new Error('User not found');
  }
  return true;
};

/**
 * Password strength validator (min 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special)
 * @function isStrongPassword
 * @param {string} password - Password to check
 * @returns {boolean} Returns true if password is strong
 * @throws {Error} Throws if password is not strong enough
 */
const isStrongPassword = (password) => {
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  if (!passwordRegex.test(password)) {
    throw new Error('Password must be at least 8 characters and include uppercase, lowercase, number and special character');
  }
  return true;
};

/**
 * Phone number format validator
 * @function isValidPhoneNumber
 * @param {string} phone - Phone number to check
 * @returns {boolean} Returns true if phone number is valid
 * @throws {Error} Throws if phone number is invalid
 */
const isValidPhoneNumber = (phone) => {
  const phoneRegex = /^\+?[1-9]\d{1,14}$/; // E.164 format
  if (!phoneRegex.test(phone)) {
    throw new Error('Please provide a valid phone number');
  }
  return true;
};

// Export validation chains

/**
 * Public registration validation chain
 * @type {Array<ValidationChain>}
 */
exports.registerValidation = [
  body('firstName')
    .trim()
    .notEmpty().withMessage('First name is required')
    .isLength({ min: 2, max: 50 }).withMessage('First name must be between 2 and 50 characters'),
  
  body('lastName')
    .trim()
    .notEmpty().withMessage('Last name is required')
    .isLength({ min: 2, max: 50 }).withMessage('Last name must be between 2 and 50 characters'),
  
  body('email')
    .trim()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Please provide a valid email')
    .normalizeEmail()
    .custom(isEmailAvailable),
  
  body('username')
    .trim()
    .notEmpty().withMessage('Username is required')
    .isLength({ min: 3, max: 20 }).withMessage('Username must be between 3 and 20 characters')
    .isAlphanumeric().withMessage('Username can only contain letters and numbers')
    .custom(isUsernameAvailable),
  
  body('password')
    .notEmpty().withMessage('Password is required')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .custom(isStrongPassword),
  
  body('confirmPassword')
    .notEmpty().withMessage('Password confirmation is required')
    .custom(passwordsMatch),
  
  body('phone')
    .optional()
    .custom(isValidPhoneNumber),
    
  validateRequest
];

/**
 * Staff registration validation chain (admin only)
 * @type {Array<ValidationChain>}
 */
exports.registerStaffValidation = [
  body('firstName')
    .trim()
    .notEmpty().withMessage('First name is required')
    .isLength({ min: 2, max: 50 }).withMessage('First name must be between 2 and 50 characters'),
  
  body('lastName')
    .trim()
    .notEmpty().withMessage('Last name is required')
    .isLength({ min: 2, max: 50 }).withMessage('Last name must be between 2 and 50 characters'),
  
  body('email')
    .trim()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Please provide a valid email')
    .normalizeEmail()
    .custom(isEmailAvailable),
  
  body('username')
    .trim()
    .notEmpty().withMessage('Username is required')
    .isLength({ min: 3, max: 20 }).withMessage('Username must be between 3 and 20 characters')
    .isAlphanumeric().withMessage('Username can only contain letters and numbers')
    .custom(isUsernameAvailable),
  
  body('role')
    .notEmpty().withMessage('Role is required')
    .isIn(['admin', 'staff', 'manager']).withMessage('Invalid role specified'),
    
  body('permissions')
    .optional()
    .isArray().withMessage('Permissions must be an array'),
    
  body('password')
    .notEmpty().withMessage('Password is required')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .custom(isStrongPassword),
  
  body('phone')
    .optional()
    .custom(isValidPhoneNumber),
    
  validateRequest
];

/**
 * Login validation chain
 * @type {Array<ValidationChain>}
 */
exports.loginValidation = [
  body('identifier')
    .trim()
    .notEmpty().withMessage('Email or username is required'),
  
  body('password')
    .notEmpty().withMessage('Password is required'),
    
  validateRequest
];

/**
 * Two-factor authentication setup validation
 * @type {Array<ValidationChain>}
 */
exports.setupTwoFactorValidation = [
  body('password')
    .notEmpty().withMessage('Password is required'),
  
  validateRequest
];

/**
 * Two-factor authentication verification validation
 * @type {Array<ValidationChain>}
 */
exports.verifyTwoFactorValidation = [
  body('token')
    .trim()
    .notEmpty().withMessage('Verification token is required')
    .isLength({ min: 6, max: 6 }).withMessage('Verification token must be 6 digits')
    .isNumeric().withMessage('Verification token must contain only numbers'),
  
  validateRequest
];

/**
 * Forgot password validation chain
 * @type {Array<ValidationChain>}
 */
exports.forgotPasswordValidation = [
  body('email')
    .trim()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Please provide a valid email')
    .normalizeEmail(),
    
  validateRequest
];

/**
 * Reset password validation chain
 * @type {Array<ValidationChain>}
 */
exports.resetPasswordValidation = [
  body('token')
    .trim()
    .notEmpty().withMessage('Reset token is required'),
  
  body('password')
    .notEmpty().withMessage('Password is required')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .custom(isStrongPassword),
  
  body('confirmPassword')
    .notEmpty().withMessage('Password confirmation is required')
    .custom(passwordsMatch),
    
  validateRequest
];

/**
 * Change password validation chain
 * @type {Array<ValidationChain>}
 */
exports.changePasswordValidation = [
  body('currentPassword')
    .notEmpty().withMessage('Current password is required')
    .custom(isCurrentPasswordCorrect),
  
  body('newPassword')
    .notEmpty().withMessage('New password is required')
    .isLength({ min: 8 }).withMessage('New password must be at least 8 characters')
    .custom(isStrongPassword)
    .custom((value, { req }) => {
      if (value === req.body.currentPassword) {
        throw new Error('New password must be different from current password');
      }
      return true;
    }),
  
  body('confirmPassword')
    .notEmpty().withMessage('Password confirmation is required')
    .custom((value, { req }) => {
      if (value !== req.body.newPassword) {
        throw new Error('Passwords do not match');
      }
      return true;
    }),
    
  validateRequest
];

/**
 * Update profile validation chain
 * @type {Array<ValidationChain>}
 */
exports.updateProfileValidation = [
  body('firstName')
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 }).withMessage('First name must be between 2 and 50 characters'),
  
  body('lastName')
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 }).withMessage('Last name must be between 2 and 50 characters'),
  
  body('username')
    .optional()
    .trim()
    .isLength({ min: 3, max: 20 }).withMessage('Username must be between 3 and 20 characters')
    .isAlphanumeric().withMessage('Username can only contain letters and numbers')
    .custom((value, { req }) => {
      if (value.toLowerCase() !== req.user.username.toLowerCase()) {
        return isUsernameAvailable(value, { req });
      }
      return true;
    }),
  
  body('phone')
    .optional()
    .custom(isValidPhoneNumber),
  
  body('address')
    .optional()
    .isObject().withMessage('Address must be an object'),
  
  body('address.street')
    .optional()
    .trim()
    .isLength({ min: 3, max: 100 }).withMessage('Street must be between 3 and 100 characters'),
  
  body('address.city')
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 }).withMessage('City must be between 2 and 50 characters'),
  
  body('address.state')
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 }).withMessage('State must be between 2 and 50 characters'),
  
  body('address.zipCode')
    .optional()
    .trim()
    .isLength({ min: 5, max: 10 }).withMessage('Zip code must be between 5 and 10 characters'),
  
  body('address.country')
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 }).withMessage('Country must be between 2 and 50 characters'),
    
  validateRequest
];

/**
 * Create API key validation chain
 * @type {Array<ValidationChain>}
 */
exports.createApiKeyValidation = [
  body('name')
    .trim()
    .notEmpty().withMessage('API key name is required')
    .isLength({ min: 3, max: 50 }).withMessage('API key name must be between 3 and 50 characters'),
    
  body('expiration')
    .optional()
    .isISO8601().withMessage('Expiration date must be a valid ISO 8601 date')
    .custom((value) => {
      const expirationDate = new Date(value);
      const now = new Date();
      if (expirationDate <= now) {
        throw new Error('Expiration date must be in the future');
      }
      return true;
    }),
    
  body('scopes')
    .optional()
    .isArray().withMessage('Scopes must be an array')
    .custom((value) => {
      const validScopes = ['read', 'write', 'delete'];
      const invalidScopes = value.filter(scope => !validScopes.includes(scope));
      if (invalidScopes.length > 0) {
        throw new Error(`Invalid scopes: ${invalidScopes.join(', ')}`);
      }
      return true;
    }),
    
  validateRequest
];

/**
 * Update API key validation chain
 * @type {Array<ValidationChain>}
 */
exports.updateApiKeyValidation = [
  param('id')
    .trim()
    .notEmpty().withMessage('API key ID is required')
    .isMongoId().withMessage('Invalid API key ID format')
    .custom(doesApiKeyExist),
    
  body('name')
    .optional()
    .trim()
    .isLength({ min: 3, max: 50 }).withMessage('API key name must be between 3 and 50 characters'),
    
  body('expiration')
    .optional()
    .isISO8601().withMessage('Expiration date must be a valid ISO 8601 date')
    .custom((value) => {
      const expirationDate = new Date(value);
      const now = new Date();
      if (expirationDate <= now) {
        throw new Error('Expiration date must be in the future');
      }
      return true;
    }),
    
  body('scopes')
    .optional()
    .isArray().withMessage('Scopes must be an array')
    .custom((value) => {
      const validScopes = ['read', 'write', 'delete'];
      const invalidScopes = value.filter(scope => !validScopes.includes(scope));
      if (invalidScopes.length > 0) {
        throw new Error(`Invalid scopes: ${invalidScopes.join(', ')}`);
      }
      return true;
    }),
    
  validateRequest
];

/**
 * Revoke API key validation chain
 * @type {Array<ValidationChain>}
 */
exports.revokeApiKeyValidation = [
  param('id')
    .trim()
    .notEmpty().withMessage('API key ID is required')
    .isMongoId().withMessage('Invalid API key ID format')
    .custom(doesApiKeyExist),
    
  validateRequest
];

/**
 * Admin user management validation chain
 * @type {Array<ValidationChain>}
 */
exports.adminUserManagementValidation = [
  param('id')
    .trim()
    .notEmpty().withMessage('User ID is required')
    .isMongoId().withMessage('Invalid user ID format')
    .custom(doesUserExist),
    
  body('firstName')
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 }).withMessage('First name must be between 2 and 50 characters'),
    
  body('lastName')
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 }).withMessage('Last name must be between 2 and 50 characters'),
    
  body('email')
    .optional()
    .trim()
    .isEmail().withMessage('Please provide a valid email')
    .normalizeEmail()
    .custom(async (email, { req }) => {
      const user = await UserModel.findOne({ 
        email: email.toLowerCase(),
        _id: { $ne: req.params.id }
      });
      if (user) {
        throw new Error('Email is already registered');
      }
      return true;
    }),
    
  body('username')
    .optional()
    .trim()
    .isLength({ min: 3, max: 20 }).withMessage('Username must be between 3 and 20 characters')
    .isAlphanumeric().withMessage('Username can only contain letters and numbers')
    .custom(async (username, { req }) => {
      const user = await UserModel.findOne({ 
        username: username.toLowerCase(),
        _id: { $ne: req.params.id }
      });
      if (user) {
        throw new Error('Username is already taken');
      }
      return true;
    }),
    
  body('phone')
    .optional()
    .custom(isValidPhoneNumber),
    
  body('permissions')
    .optional()
    .isArray().withMessage('Permissions must be an array')
    .custom((value) => {
      const validPermissions = [
        'manage_users', 'manage_cases', 'manage_documents', 
        'view_reports', 'manage_settings', 'manage_billing'
      ];
      
      const invalidPermissions = value.filter(perm => !validPermissions.includes(perm));
      if (invalidPermissions.length > 0) {
        throw new Error(`Invalid permissions: ${invalidPermissions.join(', ')}`);
      }
      return true;
    }),
    
  validateRequest
];

/**
 * Change user status validation chain (admin only)
 * @type {Array<ValidationChain>}
 */
exports.changeUserStatusValidation = [
  param('id')
    .trim()
    .notEmpty().withMessage('User ID is required')
    .isMongoId().withMessage('Invalid user ID format')
    .custom(doesUserExist),
    
  body('status')
    .trim()
    .notEmpty().withMessage('Status is required')
    .isIn(['active', 'inactive', 'suspended', 'pending']).withMessage('Invalid status specified'),
    
  body('reason')
    .optional()
    .trim()
    .isLength({ min: 5, max: 200 }).withMessage('Reason must be between 5 and 200 characters'),
    
  validateRequest
];

/**
 * Change user role validation chain (admin only)
 * @type {Array<ValidationChain>}
 */
exports.changeUserRoleValidation = [
  param('id')
    .trim()
    .notEmpty().withMessage('User ID is required')
    .isMongoId().withMessage('Invalid user ID format')
    .custom(doesUserExist),
    
  body('role')
    .trim()
    .notEmpty().withMessage('Role is required')
    .isIn(['admin', 'staff', 'manager', 'client']).withMessage('Invalid role specified'),
    
  body('permissions')
    .optional()
    .isArray().withMessage('Permissions must be an array')
    .custom((value, { req }) => {
      // If role is admin, certain permissions are always granted
      if (req.body.role === 'admin') {
        return true;
      }
      
      const validPermissions = [
        'manage_users', 'manage_cases', 'manage_documents', 
        'view_reports', 'manage_settings', 'manage_billing'
      ];
      
      const invalidPermissions = value.filter(perm => !validPermissions.includes(perm));
      if (invalidPermissions.length > 0) {
        throw new Error(`Invalid permissions: ${invalidPermissions.join(', ')}`);
      }
      return true;
    }),
    
  body('reason')
    .optional()
    .trim()
    .isLength({ min: 5, max: 200 }).withMessage('Reason must be between 5 and 200 characters'),
    
  validateRequest
];

/**
 * Session management validation chain
 * @type {Array<ValidationChain>}
 */
exports.manageSessionValidation = [
  param('id')
    .trim()
    .notEmpty().withMessage('Session ID is required')
    .isMongoId().withMessage('Invalid session ID format')
    .custom(doesSessionExist),
    
  validateRequest
];

/**
 * Bulk session management validation chain
 * @type {Array<ValidationChain>}
 */
exports.bulkSessionManagementValidation = [
  body('sessionIds')
    .isArray().withMessage('Session IDs must be an array')
    .notEmpty().withMessage('At least one session ID is required')
    .custom(async (sessionIds, { req }) => {
      const user = await UserModel.findById(req.user.id);
      if (!user) {
        throw new Error('User not found');
      }
      
      const invalidSessions = sessionIds.filter(id => 
        !user.sessions.some(session => session._id.toString() === id)
      );
      
      if (invalidSessions.length > 0) {
        throw new Error(`Invalid session IDs: ${invalidSessions.join(', ')}`);
      }
      
      return true;
    }),
    
  body('action')
    .trim()
    .notEmpty().withMessage('Action is required')
    .isIn(['revoke', 'extend']).withMessage('Invalid action specified'),
    
  body('duration')
    .optional()
    .isInt({ min: 1, max: 30 }).withMessage('Duration must be between 1 and 30 days')
    .custom((value, { req }) => {
      if (req.body.action === 'extend' && !value) {
        throw new Error('Duration is required for extend action');
      }
      return true;
    }),
    
  validateRequest
];

/**
 * Admin user search validation chain
 * @type {Array<ValidationChain>}
 */
exports.adminUserSearchValidation = [
  query('search')
    .optional()
    .trim()
    .isLength({ min: 2 }).withMessage('Search term must be at least 2 characters'),
    
  query('status')
    .optional()
    .trim()
    .isIn(['active', 'inactive', 'suspended', 'pending', 'all']).withMessage('Invalid status specified'),
    
  query('role')
    .optional()
    .trim()
    .isIn(['admin', 'staff', 'manager', 'client', 'all']).withMessage('Invalid role specified'),
    
  query('sort')
    .optional()
    .trim()
    .isIn(['name', 'email', 'role', 'status', 'createdAt', 'lastLogin']).withMessage('Invalid sort field'),
    
  query('order')
    .optional()
    .trim()
    .isIn(['asc', 'desc']).withMessage('Invalid sort order'),
    
  query('page')
    .optional()
    .isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    
  query('limit')
    .optional()
    .isInt({ min: 5, max: 100 }).withMessage('Limit must be between 5 and 100'),
    
  validateRequest
];

/**
 * Force password reset validation chain (admin only)
 * @type {Array<ValidationChain>}
 */
exports.forcePasswordResetValidation = [
  param('id')
    .trim()
    .notEmpty().withMessage('User ID is required')
    .isMongoId().withMessage('Invalid user ID format')
    .custom(doesUserExist),
    
  body('reason')
    .optional()
    .trim()
    .isLength({ min: 5, max: 200 }).withMessage('Reason must be between 5 and 200 characters'),
    
  validateRequest
];

/**
 * Enable/Disable 2FA for a user validation chain (admin only)
 * @type {Array<ValidationChain>}
 */
exports.adminToggle2FAValidation = [
  param('id')
    .trim()
    .notEmpty().withMessage('User ID is required')
    .isMongoId().withMessage('Invalid user ID format')
    .custom(doesUserExist),
    
  body('action')
    .trim()
