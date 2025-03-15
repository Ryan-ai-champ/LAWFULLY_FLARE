const AppError = require('../utils/appError');

/**
 * Middleware to restrict access to routes based on user roles
 * @param {...String} roles - The roles allowed to access the route
 * @returns {Function} Express middleware function
 */
const restrictTo = (...roles) => {
  return (req, res, next) => {
    // req.user should be set by the auth middleware that runs before this
    if (!req.user) {
      return next(new AppError('You are not logged in. Please log in to get access.', 401));
    }

    // Check if user's role is allowed
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError('You do not have permission to perform this action', 403)
      );
    }

    next();
  };
};

/**
 * Middleware to verify that the user has all of the specified roles
 * @param {...String} roles - The roles that the user must have
 * @returns {Function} Express middleware function
 */
const requireAllRoles = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new AppError('You are not logged in. Please log in to get access.', 401));
    }

    // For this to work, req.user.roles must be an array
    if (!req.user.roles || !Array.isArray(req.user.roles)) {
      return next(
        new AppError('User roles are not properly defined', 500)
      );
    }

    // Check if user has all required roles
    const hasAllRoles = roles.every(role => req.user.roles.includes(role));
    if (!hasAllRoles) {
      return next(
        new AppError('You need additional permissions to perform this action', 403)
      );
    }

    next();
  };
};

/**
 * Middleware to verify user owns a resource or is an admin
 * @param {String} resourceField - The field name on the request that contains the resource owner ID
 * @returns {Function} Express middleware function
 */
const isOwnerOrAdmin = (resourceField) => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new AppError('You are not logged in. Please log in to get access.', 401));
    }

    // Allow admins to access any resource
    if (req.user.role === 'admin') {
      return next();
    }

    // Check if the resource belongs to the user
    const resourceOwnerId = req[resourceField];
    if (!resourceOwnerId || resourceOwnerId.toString() !== req.user.id.toString()) {
      return next(
        new AppError('You do not have permission to access this resource', 403)
      );
    }

    next();
  };
};

/**
 * Middleware to check permissions based on a permission string
 * @param {String} permission - The permission string to check (e.g. 'case:read')
 * @returns {Function} Express middleware function
 */
const hasPermission = (permission) => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new AppError('You are not logged in. Please log in to get access.', 401));
    }

    // For this to work, req.user.permissions must be an array
    if (!req.user.permissions || !Array.isArray(req.user.permissions)) {
      return next(
        new AppError('User permissions are not properly defined', 500)
      );
    }

    if (!req.user.permissions.includes(permission)) {
      return next(
        new AppError(`You do not have the '${permission}' permission required to perform this action`, 403)
      );
    }

    next();
  };
};

module.exports = {
  restrictTo,
  requireAllRoles,
  isOwnerOrAdmin,
  hasPermission
};

