/**
 * @fileoverview Centralized error handling utility for the application
 * Provides a set of custom error classes with proper inheritance and formatting
 * for consistent error handling across the application.
 * 
 * @module utils/appError
 * @requires winston
 */

const { createLogger, format, transports } = require('winston');

/**
 * Error codes for the application, organized by category
 * @enum {Object}
 */
const ERROR_CODES = {
  AUTHENTICATION: {
    INVALID_CREDENTIALS: 'AUTH_001',
    TOKEN_EXPIRED: 'AUTH_002',
    TOKEN_INVALID: 'AUTH_003',
    TOKEN_MISSING: 'AUTH_004',
    USER_NOT_FOUND: 'AUTH_005',
    ACCOUNT_LOCKED: 'AUTH_006',
    INVALID_2FA: 'AUTH_007',
    SESSION_EXPIRED: 'AUTH_008',
    EMAIL_NOT_VERIFIED: 'AUTH_009',
    PASSWORD_RESET_EXPIRED: 'AUTH_010',
    REFRESH_TOKEN_INVALID: 'AUTH_011',
    MULTIPLE_DEVICES: 'AUTH_012',
    INVALID_ACTIVATION: 'AUTH_013'
  },
  VALIDATION: {
    INVALID_INPUT: 'VAL_001',
    MISSING_FIELD: 'VAL_002',
    INVALID_FORMAT: 'VAL_003',
    DUPLICATE_ENTRY: 'VAL_004',
    INVALID_STATE: 'VAL_005',
    REFERENCE_ERROR: 'VAL_006',
    DATA_INTEGRITY: 'VAL_007',
    SCHEMA_VALIDATION: 'VAL_008'
  },
  PERMISSION: {
    UNAUTHORIZED: 'PERM_001',
    FORBIDDEN: 'PERM_002',
    INSUFFICIENT_ROLE: 'PERM_003',
    RESOURCE_ACCESS_DENIED: 'PERM_004',
    ACTION_NOT_ALLOWED: 'PERM_005',
    ROUTE_PROTECTED: 'PERM_006',
    ADMIN_REQUIRED: 'PERM_007',
    CLIENT_ACCESS_DENIED: 'PERM_008'
  },
  RATE_LIMIT: {
    TOO_MANY_REQUESTS: 'RATE_001',
    IP_BLOCKED: 'RATE_002',
    ACCOUNT_THROTTLED: 'RATE_003',
    API_LIMIT_EXCEEDED: 'RATE_004',
    CONCURRENT_LIMIT: 'RATE_005'
  },
  SESSION: {
    INVALID_SESSION: 'SESS_001',
    SESSION_TIMEOUT: 'SESS_002',
    CONCURRENT_LOGIN: 'SESS_003',
    SESSION_REVOKED: 'SESS_004',
    DEVICE_NOT_RECOGNIZED: 'SESS_005'
  },
  SERVER: {
    INTERNAL_ERROR: 'SRV_001',
    SERVICE_UNAVAILABLE: 'SRV_002',
    DATABASE_ERROR: 'SRV_003',
    NETWORK_ERROR: 'SRV_004',
    THIRD_PARTY_ERROR: 'SRV_005',
    UNHANDLED_EXCEPTION: 'SRV_006',
    TIMEOUT: 'SRV_007'
  }
};

/**
 * HTTP status codes mapped to their meanings
 * @enum {Object}
 */
const HTTP_STATUS = {
  OK: 200,
  CREATED: 201,
  NO_CONTENT: 204,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  METHOD_NOT_ALLOWED: 405,
  CONFLICT: 409,
  UNPROCESSABLE_ENTITY: 422,
  TOO_MANY_REQUESTS: 429,
  INTERNAL_SERVER_ERROR: 500,
  SERVICE_UNAVAILABLE: 503
};

/**
 * Configure Winston logger for error logging
 */
const logger = createLogger({
  level: 'error',
  format: format.combine(
    format.timestamp({
      format: 'YYYY-MM-DD HH:mm:ss'
    }),
    format.errors({ stack: true }),
    format.splat(),
    format.json()
  ),
  defaultMeta: { service: 'immigration-case-mgmt' },
  transports: [
    new transports.File({ filename: 'error.log', level: 'error' }),
    new transports.Console({
      format: format.combine(
        format.colorize(),
        format.printf(({ timestamp, level, message, stack, ...rest }) => {
          return `${timestamp} ${level}: ${message} ${Object.keys(rest).length ? JSON.stringify(rest, null, 2) : ''} ${stack || ''}`;
        })
      )
    })
  ]
});

/**
 * Base API Error class that extends Error
 * @class ApiError
 * @extends Error
 */
class ApiError extends Error {
  /**
   * Creates an instance of ApiError.
   * @param {string} message - Error message
   * @param {number} statusCode - HTTP status code
   * @param {string} errorCode - Application-specific error code
   * @param {Object} [metadata={}] - Additional error metadata
   * @param {boolean} [isOperational=true] - If true, error is operational and expected
   * @memberof ApiError
   */
  constructor(message, statusCode, errorCode, metadata = {}, isOperational = true) {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.errorCode = errorCode;
    this.metadata = metadata;
    this.isOperational = isOperational;
    this.timestamp = new Date().toISOString();

    // Capture stack trace, excluding constructor call from it
    Error.captureStackTrace(this, this.constructor);
    
    // Log the error
    this.logError();
  }

  /**
   * Logs the error using Winston logger
   * @memberof ApiError
   */
  logError() {
    const logObject = {
      errorCode: this.errorCode,
      statusCode: this.statusCode,
      message: this.message,
      stack: this.stack,
      metadata: this.metadata,
      isOperational: this.isOperational
    };

    if (this.isOperational) {
      logger.warn(this.message, logObject);
    } else {
      logger.error(this.message, logObject);
    }
  }

  /**
   * Formats the error response for API consumption
   * @returns {Object} Formatted error response
   * @memberof ApiError
   */
  toJSON() {
    return {
      error: {
        code: this.errorCode,
        message: this.message,
        ...(process.env.NODE_ENV === 'development' && { stack: this.stack }),
        ...(Object.keys(this.metadata).length > 0 && { details: this.metadata }),
        timestamp: this.timestamp
      }
    };
  }
}

/**
 * Authentication Error class for auth-related errors
 * @class AuthenticationError
 * @extends ApiError
 */
class AuthenticationError extends ApiError {
  /**
   * Creates an instance of AuthenticationError.
   * @param {string} message - Error message
   * @param {string} errorCode - Application-specific error code
   * @param {Object} [metadata={}] - Additional error metadata
   * @memberof AuthenticationError
   */
  constructor(message, errorCode = ERROR_CODES.AUTHENTICATION.INVALID_CREDENTIALS, metadata = {}) {
    super(message, HTTP_STATUS.UNAUTHORIZED, errorCode, metadata, true);
  }

  /**
   * Creates an invalid credentials error
   * @param {string} [message='Invalid username or password'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {AuthenticationError} Authentication error instance
   * @static
   * @memberof AuthenticationError
   */
  static invalidCredentials(message = 'Invalid username or password', metadata = {}) {
    return new AuthenticationError(message, ERROR_CODES.AUTHENTICATION.INVALID_CREDENTIALS, metadata);
  }

  /**
   * Creates a token expired error
   * @param {string} [message='Your session has expired, please log in again'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {AuthenticationError} Authentication error instance
   * @static
   * @memberof AuthenticationError
   */
  static tokenExpired(message = 'Your session has expired, please log in again', metadata = {}) {
    return new AuthenticationError(message, ERROR_CODES.AUTHENTICATION.TOKEN_EXPIRED, metadata);
  }

  /**
   * Creates an invalid token error
   * @param {string} [message='Invalid authentication token'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {AuthenticationError} Authentication error instance
   * @static
   * @memberof AuthenticationError
   */
  static invalidToken(message = 'Invalid authentication token', metadata = {}) {
    return new AuthenticationError(message, ERROR_CODES.AUTHENTICATION.TOKEN_INVALID, metadata);
  }

  /**
   * Creates a missing token error
   * @param {string} [message='Authentication token is required'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {AuthenticationError} Authentication error instance
   * @static
   * @memberof AuthenticationError
   */
  static missingToken(message = 'Authentication token is required', metadata = {}) {
    return new AuthenticationError(message, ERROR_CODES.AUTHENTICATION.TOKEN_MISSING, metadata);
  }

  /**
   * Creates a user not found error
   * @param {string} [message='User not found'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {AuthenticationError} Authentication error instance
   * @static
   * @memberof AuthenticationError
   */
  static userNotFound(message = 'User not found', metadata = {}) {
    return new AuthenticationError(message, ERROR_CODES.AUTHENTICATION.USER_NOT_FOUND, metadata);
  }

  /**
   * Creates an account locked error
   * @param {string} [message='Account has been locked due to too many failed attempts'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {AuthenticationError} Authentication error instance
   * @static
   * @memberof AuthenticationError
   */
  static accountLocked(message = 'Account has been locked due to too many failed attempts', metadata = {}) {
    return new AuthenticationError(message, ERROR_CODES.AUTHENTICATION.ACCOUNT_LOCKED, metadata);
  }

  /**
   * Creates an invalid 2FA code error
   * @param {string} [message='Invalid two-factor authentication code'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {AuthenticationError} Authentication error instance
   * @static
   * @memberof AuthenticationError
   */
  static invalid2FA(message = 'Invalid two-factor authentication code', metadata = {}) {
    return new AuthenticationError(message, ERROR_CODES.AUTHENTICATION.INVALID_2FA, metadata);
  }

  /**
   * Creates an email not verified error
   * @param {string} [message='Email address has not been verified'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {AuthenticationError} Authentication error instance
   * @static
   * @memberof AuthenticationError
   */
  static emailNotVerified(message = 'Email address has not been verified', metadata = {}) {
    return new AuthenticationError(message, ERROR_CODES.AUTHENTICATION.EMAIL_NOT_VERIFIED, metadata);
  }

  /**
   * Creates a password reset token expired error
   * @param {string} [message='Password reset link has expired'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {AuthenticationError} Authentication error instance
   * @static
   * @memberof AuthenticationError
   */
  static passwordResetExpired(message = 'Password reset link has expired', metadata = {}) {
    return new AuthenticationError(message, ERROR_CODES.AUTHENTICATION.PASSWORD_RESET_EXPIRED, metadata);
  }

  /**
   * Creates an invalid refresh token error
   * @param {string} [message='Invalid refresh token'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {AuthenticationError} Authentication error instance
   * @static
   * @memberof AuthenticationError
   */
  static invalidRefreshToken(message = 'Invalid refresh token', metadata = {}) {
    return new AuthenticationError(message, ERROR_CODES.AUTHENTICATION.REFRESH_TOKEN_INVALID, metadata);
  }
}

/**
 * Validation Error class for input validation errors
 * @class ValidationError
 * @extends ApiError
 */
class ValidationError extends ApiError {
  /**
   * Creates an instance of ValidationError.
   * @param {string} message - Error message
   * @param {string} errorCode - Application-specific error code
   * @param {Object} [metadata={}] - Additional error metadata
   * @memberof ValidationError
   */
  constructor(message, errorCode = ERROR_CODES.VALIDATION.INVALID_INPUT, metadata = {}) {
    super(message, HTTP_STATUS.UNPROCESSABLE_ENTITY, errorCode, metadata, true);
  }

  /**
   * Creates an invalid input error
   * @param {string} [message='Invalid input data'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {ValidationError} Validation error instance
   * @static
   * @memberof ValidationError
   */
  static invalidInput(message = 'Invalid input data', metadata = {}) {
    return new ValidationError(message, ERROR_CODES.VALIDATION.INVALID_INPUT, metadata);
  }

  /**
   * Creates a missing field error
   * @param {string} [message='Required field is missing'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {ValidationError} Validation error instance
   * @static
   * @memberof ValidationError
   */
  static missingField(message = 'Required field is missing', metadata = {}) {
    return new ValidationError(message, ERROR_CODES.VALIDATION.MISSING_FIELD, metadata);
  }

  /**
   * Creates an invalid format error
   * @param {string} [message='Input format is invalid'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {ValidationError} Validation error instance
   * @static
   * @memberof ValidationError
   */
  static invalidFormat(message = 'Input format is invalid', metadata = {}) {
    return new ValidationError(message, ERROR_CODES.VALIDATION.INVALID_FORMAT, metadata);
  }

  /**
   * Creates a duplicate entry error
   * @param {string} [message='Entry already exists'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {ValidationError} Validation error instance
   * @static
   * @memberof ValidationError
   */
  static duplicateEntry(message = 'Entry already exists', metadata = {}) {
    return new ValidationError(message, ERROR_CODES.VALIDATION.DUPLICATE_ENTRY, metadata);
  }

  /**
   * Creates an invalid state error
   * @param {string} [message='Operation invalid in current state'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {ValidationError} Validation error instance
   * @static
   * @memberof ValidationError
   */
  static invalidState(message = 'Operation invalid in current state', metadata = {}) {
    return new ValidationError(message, ERROR_CODES.VALIDATION.INVALID_STATE, metadata);
  }

  /**
   * Creates a reference error
   * @param {string} [message='Referenced entity does not exist'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {ValidationError} Validation error instance
   * @static
   * @memberof ValidationError
   */
  static referenceError(message = 'Referenced entity does not exist', metadata = {}) {
    return new ValidationError(message, ERROR_CODES.VALIDATION.REFERENCE_ERROR, metadata);
  }

  /**
   * Creates a data integrity error
   * @param {string} [message='Data integrity constraint violated'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {ValidationError} Validation error instance
   * @static
   * @memberof ValidationError
   */
  static dataIntegrity(message = 'Data integrity constraint violated', metadata = {}) {
    return new ValidationError(message, ERROR_CODES.VALIDATION.DATA_INTEGRITY, metadata);
  }

  /**
   * Creates a schema validation error
   * @param {string} [message='Schema validation failed'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {ValidationError} Validation error instance
   * @static
   * @memberof ValidationError
   */
  static schemaValidation(message = 'Schema validation failed', metadata = {}) {
    return new ValidationError(message, ERROR_CODES.VALIDATION.SCHEMA_VALIDATION, metadata);
  }
}

/**
 * Permission Error class for access control errors
 * @class PermissionError
 * @extends ApiError
 */
class PermissionError extends ApiError {
  /**
   * Creates an instance of PermissionError.
   * @param {string} message - Error message
   * @param {string} errorCode - Application-specific error code
   * @param {Object} [metadata={}] - Additional error metadata
   * @memberof PermissionError
   */
  constructor(message, errorCode = ERROR_CODES.PERMISSION.FORBIDDEN, metadata = {}) {
    super(message, HTTP_STATUS.FORBIDDEN, errorCode, metadata, true);
  }

  /**
   * Creates an unauthorized error
   * @param {string} [message='Authentication required'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {PermissionError} Permission error instance
   * @static
   * @memberof PermissionError
   */
  static unauthorized(message = 'Authentication required', metadata = {}) {
    return new PermissionError(message, ERROR_CODES.PERMISSION.UNAUTHORIZED, { 
      statusCode: HTTP_STATUS.UNAUTHORIZED,
      ...metadata 
    });
  }

  /**
   * Creates a forbidden error
   * @param {string} [message='You do not have permission to perform this action'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {PermissionError} Permission error instance
   * @static
   * @memberof PermissionError
   */
  static forbidden(message = 'You do not have permission to perform this action', metadata = {}) {
    return new PermissionError(message, ERROR_CODES.PERMISSION.FORBIDDEN, metadata);
  }

  /**
   * Creates an insufficient role error
   * @param {string} [message='Your role does not have sufficient permissions'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {PermissionError} Permission error instance
   * @static
   * @memberof PermissionError
   */
  static insufficientRole(message = 'Your role does not have sufficient permissions', metadata = {}) {
    return new PermissionError(message, ERROR_CODES.PERMISSION.INSUFFICIENT_ROLE, metadata);
  }

  /**
   * Creates a resource access denied error
   * @param {string} [message='Access to this resource is denied'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {PermissionError} Permission error instance
   * @static
   * @memberof PermissionError
   */
  static resourceAccessDenied(message = 'Access to this resource is denied', metadata = {}) {
    return new PermissionError(message, ERROR_CODES.PERMISSION.RESOURCE_ACCESS_DENIED, metadata);
  }

  /**
   * Creates an action not allowed error
   * @param {string} [message='This action is not allowed'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {PermissionError} Permission error instance
   * @static
   * @memberof PermissionError
   */
  static actionNotAllowed(message = 'This action is not allowed', metadata = {}) {
    return new PermissionError(message, ERROR_CODES.PERMISSION.ACTION_NOT_ALLOWED, metadata);
  }

  /**
   * Creates a route protected error
   * @param {string} [message='This route is protected'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {PermissionError} Permission error instance
   * @static
   * @memberof PermissionError
   */
  static routeProtected(message = 'This route is protected', metadata = {}) {
    return new PermissionError(message, ERROR_CODES.PERMISSION.ROUTE_PROTECTED, metadata);
  }

  /**
   * Creates an admin required error
   * @param {string} [message='Administrator privileges required'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {PermissionError} Permission error instance
   * @static
   * @memberof PermissionError
   */
  static adminRequired(message = 'Administrator privileges required', metadata = {}) {
    return new PermissionError(message, ERROR_CODES.PERMISSION.ADMIN_REQUIRED, metadata);
  }

  /**
   * Creates a client access denied error
   * @param {string} [message='Access denied for this client'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {PermissionError} Permission error instance
   * @static
   * @memberof PermissionError
   */
  static clientAccessDenied(message = 'Access denied for this client', metadata = {}) {
    return new PermissionError(message, ERROR_CODES.PERMISSION.CLIENT_ACCESS_DENIED, metadata);
  }
}

/**
 * Rate Limit Error class for rate limiting errors
 * @class RateLimitError
 * @extends ApiError
 */
class RateLimitError extends ApiError {
  /**
   * Creates an instance of RateLimitError.
   * @param {string} message - Error message
   * @param {string} errorCode - Application-specific error code
   * @param {Object} [metadata={}] - Additional error metadata
   * @memberof RateLimitError
   */
  constructor(message, errorCode = ERROR_CODES.RATE_LIMIT.TOO_MANY_REQUESTS, metadata = {}) {
    super(message, HTTP_STATUS.TOO_MANY_REQUESTS, errorCode, metadata, true);
  }

  /**
   * Creates a too many requests error
   * @param {string} [message='Too many requests, please try again later'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {RateLimitError} Rate limit error instance
   * @static
   * @memberof RateLimitError
   */
  static tooManyRequests(message = 'Too many requests, please try again later', metadata = {}) {
    return new RateLimitError(message, ERROR_CODES.RATE_LIMIT.TOO_MANY_REQUESTS, metadata);
  }

  /**
   * Creates an IP blocked error
   * @param {string} [message='Your IP address has been temporarily blocked'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {RateLimitError} Rate limit error instance
   * @static
   * @memberof RateLimitError
   */
  static ipBlocked(message = 'Your IP address has been temporarily blocked', metadata = {}) {
    return new RateLimitError(message, ERROR_CODES.RATE_LIMIT.IP_BLOCKED, metadata);
  }

  /**
   * Creates an account throttled error
   * @param {string} [message='Your account has been temporarily throttled'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {RateLimitError} Rate limit error instance
   * @static
   * @memberof RateLimitError
   */
  static accountThrottled(message = 'Your account has been temporarily throttled', metadata = {}) {
    return new RateLimitError(message, ERROR_CODES.RATE_LIMIT.ACCOUNT_THROTTLED, metadata);
  }

  /**
   * Creates an API limit exceeded error
   * @param {string} [message='API rate limit exceeded'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {RateLimitError} Rate limit error instance
   * @static
   * @memberof RateLimitError
   */
  static apiLimitExceeded(message = 'API rate limit exceeded', metadata = {}) {
    return new RateLimitError(message, ERROR_CODES.RATE_LIMIT.API_LIMIT_EXCEEDED, metadata);
  }

  /**
   * Creates a concurrent limit error
   * @param {string} [message='Maximum concurrent requests exceeded'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {RateLimitError} Rate limit error instance
   * @static
   * @memberof RateLimitError
   */
  static concurrentLimit(message = 'Maximum concurrent requests exceeded', metadata = {}) {
    return new RateLimitError(message, ERROR_CODES.RATE_LIMIT.CONCURRENT_LIMIT, metadata);
  }
}

/**
 * Session Error class for session management errors
 * @class SessionError
 * @extends ApiError
 */
class SessionError extends ApiError {
  /**
   * Creates an instance of SessionError.
   * @param {string} message - Error message
   * @param {string} errorCode - Application-specific error code
   * @param {Object} [metadata={}] - Additional error metadata
   * @memberof SessionError
   */
  constructor(message, errorCode = ERROR_CODES.SESSION.INVALID_SESSION, metadata = {}) {
    super(message, HTTP_STATUS.UNAUTHORIZED, errorCode, metadata, true);
  }

  /**
   * Creates an invalid session error
   * @param {string} [message='Invalid or expired session'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {SessionError} Session error instance
   * @static
   * @memberof SessionError
   */
  static invalidSession(message = 'Invalid or expired session', metadata = {}) {
    return new SessionError(message, ERROR_CODES.SESSION.INVALID_SESSION, metadata);
  }

  /**
   * Creates a session timeout error
   * @param {string} [message='Session has timed out due to inactivity'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {SessionError} Session error instance
   * @static
   * @memberof SessionError
   */
  static sessionTimeout(message = 'Session has timed out due to inactivity', metadata = {}) {
    return new SessionError(message, ERROR_CODES.SESSION.SESSION_TIMEOUT, metadata);
  }

  /**
   * Creates a concurrent login error
   * @param {string} [message='Account logged in from another device'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {SessionError} Session error instance
   * @static
   * @memberof SessionError
   */
  static concurrentLogin(message = 'Account logged in from another device', metadata = {}) {
    return new SessionError(message, ERROR_CODES.SESSION.CONCURRENT_LOGIN, metadata);
  }

  /**
   * Creates a session revoked error
   * @param {string} [message='Session has been revoked'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {SessionError} Session error instance
   * @static
   * @memberof SessionError
   */
  static sessionRevoked(message = 'Session has been revoked', metadata = {}) {
    return new SessionError(message, ERROR_CODES.SESSION.SESSION_REVOKED, metadata);
  }

  /**
   * Creates a device not recognized error
   * @param {string} [message='Login attempt from unrecognized device'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {SessionError} Session error instance
   * @static
   * @memberof SessionError
   */
  static deviceNotRecognized(message = 'Login attempt from unrecognized device', metadata = {}) {
    return new SessionError(message, ERROR_CODES.SESSION.DEVICE_NOT_RECOGNIZED, metadata);
  }
}
/**
 * Server Error class for internal server errors
 * @class ServerError
 * @extends ApiError
 */
class ServerError extends ApiError {
  /**
   * Creates an instance of ServerError.
   * @param {string} message - Error message
   * @param {string} errorCode - Application-specific error code
   * @param {Object} [metadata={}] - Additional error metadata
   * @param {boolean} [isOperational=false] - If true, error is operational and expected
   * @memberof ServerError
   */
  constructor(message, errorCode = ERROR_CODES.SERVER.INTERNAL_ERROR, metadata = {}, isOperational = false) {
    super(message, HTTP_STATUS.INTERNAL_SERVER_ERROR, errorCode, metadata, isOperational);
  }

  /**
   * Creates an internal error
   * @param {string} [message='Internal server error'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {ServerError} Server error instance
   * @static
   * @memberof ServerError
   */
  static internalError(message = 'Internal server error', metadata = {}) {
    return new ServerError(message, ERROR_CODES.SERVER.INTERNAL_ERROR, metadata);
  }

  /**
   * Creates a service unavailable error
   * @param {string} [message='Service temporarily unavailable'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {ServerError} Server error instance
   * @static
   * @memberof ServerError
   */
  static serviceUnavailable(message = 'Service temporarily unavailable', metadata = {}) {
    return new ServerError(
      message, 
      ERROR_CODES.SERVER.SERVICE_UNAVAILABLE, 
      metadata, 
      true
    );
  }

  /**
   * Creates a database error
   * @param {string} [message='Database operation failed'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {ServerError} Server error instance
   * @static
   * @memberof ServerError
   */
  static databaseError(message = 'Database operation failed', metadata = {}) {
    return new ServerError(message, ERROR_CODES.SERVER.DATABASE_ERROR, metadata);
  }

  /**
   * Creates a network error
   * @param {string} [message='Network operation failed'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {ServerError} Server error instance
   * @static
   * @memberof ServerError
   */
  static networkError(message = 'Network operation failed', metadata = {}) {
    return new ServerError(message, ERROR_CODES.SERVER.NETWORK_ERROR, metadata, true);
  }

  /**
   * Creates a third party error
   * @param {string} [message='Third party service error'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {ServerError} Server error instance
   * @static
   * @memberof ServerError
   */
  static thirdPartyError(message = 'Third party service error', metadata = {}) {
    return new ServerError(message, ERROR_CODES.SERVER.THIRD_PARTY_ERROR, metadata, true);
  }

  /**
   * Creates an unhandled exception error
   * @param {string} [message='Unhandled exception occurred'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {ServerError} Server error instance
   * @static
   * @memberof ServerError
   */
  static unhandledException(message = 'Unhandled exception occurred', metadata = {}) {
    return new ServerError(message, ERROR_CODES.SERVER.UNHANDLED_EXCEPTION, metadata);
  }

  /**
   * Creates a timeout error
   * @param {string} [message='Operation timed out'] - Error message
   * @param {Object} [metadata={}] - Additional error metadata
   * @returns {ServerError} Server error instance
   * @static
   * @memberof ServerError
   */
  static timeout(message = 'Operation timed out', metadata = {}) {
    return new ServerError(message, ERROR_CODES.SERVER.TIMEOUT, metadata, true);
  }
}

// Export all error classes, utility constants and the logger
module.exports = {
  // Error Classes
  ApiError,
  AuthenticationError,
  ValidationError,
  PermissionError,
  RateLimitError,
  SessionError,
  ServerError,
  
  // Constants
  ERROR_CODES,
  HTTP_STATUS,
  
  // Loggers
  logger
};
