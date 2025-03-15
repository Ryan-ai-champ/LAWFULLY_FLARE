/**
 * ApiError class for standardized API error responses
 * Extends the basic Error class with additional properties
 * needed for consistent API error handling
 */
class ApiError extends Error {
  /**
   * Create a new ApiError
   * @param {string} message - Error message
   * @param {number} statusCode - HTTP status code
   * @param {Array} errors - Validation errors array
   * @param {string} stack - Error stack trace
   */
  constructor(message, statusCode = 500, errors = [], stack = '') {
    super(message);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;
    this.errors = errors;

    if (stack) {
      this.stack = stack;
    } else {
      Error.captureStackTrace(this, this.constructor);
    }
  }

  /**
   * Create a BadRequest error (400)
   * @param {string} message - Error message
   * @param {Array} errors - Validation errors
   * @returns {ApiError} - BadRequest error
   */
  static badRequest(message = 'Bad request', errors = []) {
    return new ApiError(message, 400, errors);
  }

  /**
   * Create an Unauthorized error (401)
   * @param {string} message - Error message
   * @returns {ApiError} - Unauthorized error
   */
  static unauthorized(message = 'Unauthorized') {
    return new ApiError(message, 401);
  }

  /**
   * Create a Forbidden error (403)
   * @param {string} message - Error message
   * @returns {ApiError} - Forbidden error
   */
  static forbidden(message = 'Forbidden') {
    return new ApiError(message, 403);
  }

  /**
   * Create a NotFound error (404)
   * @param {string} message - Error message
   * @returns {ApiError} - NotFound error
   */
  static notFound(message = 'Resource not found') {
    return new ApiError(message, 404);
  }

  /**
   * Create a Conflict error (409)
   * @param {string} message - Error message
   * @returns {ApiError} - Conflict error
   */
  static conflict(message = 'Conflict') {
    return new ApiError(message, 409);
  }

  /**
   * Create a Validation error (422)
   * @param {string} message - Error message
   * @param {Array} errors - Validation errors
   * @returns {ApiError} - Validation error
   */
  static validation(message = 'Validation error', errors = []) {
    return new ApiError(message, 422, errors);
  }

  /**
   * Create an Internal Server error (500)
   * @param {string} message - Error message
   * @returns {ApiError} - Internal Server error
   */
  static internal(message = 'Internal server error') {
    return new ApiError(message, 500);
  }

  /**
   * Convert any error to ApiError
   * @param {Error} err - Error to convert
   * @returns {ApiError} - Converted ApiError
   */
  static from(err) {
    // If it's already an ApiError, return it
    if (err instanceof ApiError) {
      return err;
    }
    
    // Determine status code based on error name or code
    let statusCode = 500;
    let errors = [];
    
    if (err.name === 'ValidationError') {
      statusCode = 422;
      errors = Object.values(err.errors || {}).map(e => e.message);
    } else if (err.name === 'CastError') {
      statusCode = 400;
    } else if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
      statusCode = 401;
    } else if (err.code === 11000) {
      statusCode = 409;
    }
    
    return new ApiError(
      err.message || 'Something went wrong',
      statusCode,
      errors,
      err.stack
    );
  }
}

module.exports = ApiError;

