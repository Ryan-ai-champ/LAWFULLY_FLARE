const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const { ValidationError } = require('joi');
const { logger } = require('../utils/logger');
const ApiError = require('../utils/apiError');
const config = require('../config/config');

/**
 * Error handling for MongoDB errors
 * @param {Error} err - The error object
 * @returns {ApiError} - Formatted API error
 */
const handleMongoDBError = (err) => {
  let errors = {};
  let message = 'Database operation failed';
  let statusCode = 500;

  // Handle MongoDB duplicate key error
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    errors[field] = `${field} already exists`;
    message = 'Duplicate field value entered';
    statusCode = 400;
  }

  // Handle MongoDB validation errors
  if (err.name === 'ValidationError') {
    Object.keys(err.errors).forEach((field) => {
      errors[field] = err.errors[field].message;
    });
    message = 'Invalid input data';
    statusCode = 400;
  }

  // Handle MongoDB CastError (invalid ObjectId)
  if (err.name === 'CastError') {
    errors[err.path] = `Invalid ${err.path}: ${err.value}`;
    message = 'Resource not found';
    statusCode = 404;
  }

  return new ApiError(message, statusCode, errors);
};

/**
 * Error handling for JWT errors
 * @param {Error} err - The error object
 * @returns {ApiError} - Formatted API error
 */
const handleJWTError = (err) => {
  let message = 'Authentication error';
  let statusCode = 401;
  let errors = {};

  switch (err.name) {
    case 'JsonWebTokenError':
      message = 'Invalid token. Please log in again.';
      break;
    case 'TokenExpiredError':
      message = 'Your token has expired. Please log in again.';
      break;
    default:
      message = 'Authorization failed. Please log in again.';
  }

  return new ApiError(message, statusCode, errors);
};

/**
 * Error handling for Joi validation errors
 * @param {ValidationError} err - The Joi validation error
 * @returns {ApiError} - Formatted API error
 */
const handleJoiValidationError = (err) => {
  const errors = {};
  err.details.forEach((detail) => {
    errors[detail.context.key] = detail.message.replace(/['"]/g, '');
  });

  return new ApiError('Validation error', 400, errors);
};

/**
 * Development error response formatter
 * Includes detailed error information and stack trace
 */
const sendDevError = (err, req, res) => {
  // Log error for debugging
  logger.error(`${err.name || 'Error'}: ${err.message}`, {
    stack: err.stack,
    requestId: req.id,
    path: req.originalUrl,
    method: req.method,
    body: req.body,
    query: req.query,
    params: req.params,
    user: req.user ? req.user.id : 'unauthenticated',
  });

  return res.status(err.statusCode || 500).json({
    success: false,
    error: {
      message: err.message,
      stack: err.stack,
      errors: err.errors,
    },
    requestId: req.id,
  });
};

/**
 * Production error response formatter
 * Excludes sensitive information like stack traces
 */
const sendProdError = (err, req, res) => {
  // Log error but don't expose details to client
  logger.error(`${err.name || 'Error'}: ${err.message}`, {
    stack: err.stack,
    requestId: req.id,
    path: req.originalUrl,
    statusCode: err.statusCode || 500,
  });

  // If operational error, send details
  if (err.isOperational) {
    return res.status(err.statusCode).json({
      success: false,
      error: {
        message: err.message,
        errors: err.errors,
      },
      requestId: req.id,
    });
  }

  // For programming or unknown errors, send generic message
  return res.status(500).json({
    success: false,
    error: {
      message: 'Something went wrong',
    },
    requestId: req.id,
  });
};

/**
 * Map specific HTTP status codes to customized error messages
 * @param {number} statusCode - HTTP status code
 * @returns {string} - Custom error message for status code
 */
const getStatusCodeMessage = (statusCode) => {
  const statusMessages = {
    400: 'Bad request. Please check your inputs.',
    401: 'Authentication required. Please log in.',
    403: 'Access forbidden. You don\'t have permission to access this resource.',
    404: 'Resource not found.',
    405: 'Method not allowed for this endpoint.',
    408: 'Request timeout. Please try again.',
    409: 'Conflict with current state of the resource.',
    413: 'Request entity too large.',
    422: 'Unprocessable entity. Validation failed.',
    429: 'Too many requests. Please try again later.',
    500: 'Internal server error. We\'re working on fixing this issue.',
    503: 'Service unavailable. Please try again later.',
  };

  return statusMessages[statusCode] || 'An error occurred.';
};

/**
 * Global error handling middleware
 * Catches all unhandled errors in the application
 */
module.exports = (err, req, res, next) => {
  // Default to 500 internal server error if statusCode not set
  err.statusCode = err.statusCode || 500;
  
  // Set a default error message if none exists
  err.message = err.message || getStatusCodeMessage(err.statusCode);
  
  // Convert different error types to ApiError format
  if (err instanceof mongoose.Error) {
    err = handleMongoDBError(err);
  } else if (err.name && err.name.includes('JsonWebToken') || err.name === 'TokenExpiredError') {
    err = handleJWTError(err);
  } else if (err instanceof ValidationError) {
    err = handleJoiValidationError(err);
  } else if (!err.isOperational) {
    // For unknown errors, create a proper ApiError
    const message = config.nodeEnv === 'production' 
      ? 'Something went wrong' 
      : err.message;
    err = new ApiError(message, err.statusCode, {});
    err.stack = err.stack;
  }

  // Different error handling for development and production
  if (config.nodeEnv === 'development') {
    sendDevError(err, req, res);
  } else {
    sendProdError(err, req, res);
  }
};

const AppError = require('../utils/appError');

/**
 * Handle errors from async/await functions
 */
const handleAsyncErrors = (err, req, res, next) => {
  if (!err.statusCode) err.statusCode = 500;
  next(err);
};

/**
 * Handle MongoDB duplicate key errors
 */
const handleDuplicateKeyError = (err) => {
  const field = Object.keys(err.keyValue)[0];
  const value = err.keyValue[field];
  const message = `Duplicate field value: ${value}. Please use another value for ${field}.`;
  return new AppError(message, 400);
};

/**
 * Handle MongoDB validation errors
 */
const handleValidationError = (err) => {
  const errors = Object.values(err.errors).map((el) => el.message);
  const message = `Invalid input data. ${errors.join('. ')}`;
  return new AppError(message, 400);
};

/**
 * Handle JWT errors
 */
const handleJWTError = () => new AppError('Invalid token. Please log in again.', 401);

/**
 * Handle JWT expired error
 */
const handleJWTExpiredError = () => new AppError('Your token has expired. Please log in again.', 401);

/**
 * Send error response in development environment
 */
const sendErrorDev = (err, res) => {
  res.status(err.statusCode).json({
    status: err.status,
    error: err,
    message: err.message,
    stack: err.stack
  });
};

/**
 * Send error response in production environment
 */
const sendErrorProd = (err, res) => {
  // Operational, trusted error: send message to client
  if (err.isOperational) {
    res.status(err.statusCode).json({
      status: err.status,
      message: err.message
    });
  } else {
    // Programming or other unknown error: don't leak error details
    console.error('ERROR 💥', err);
    res.status(500).json({
      status: 'error',
      message: 'Something went wrong'
    });
  }
};

/**
 * Main error handling middleware
 */
const errorHandler = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  if (process.env.NODE_ENV === 'development') {
    sendErrorDev(err, res);
  } else if (process.env.NODE_ENV === 'production') {
    let error = { ...err };
    error.message = err.message;

    if (error.code === 11000) error = handleDuplicateKeyError(error);
    if (error.name === 'ValidationError') error = handleValidationError(error);
    if (error.name === 'JsonWebTokenError') error = handleJWTError();
    if (error.name === 'TokenExpiredError') error = handleJWTExpiredError();

    sendErrorProd(error, res);
  }
};

/**
 * Handle 404 errors for routes that don't exist
 */
const notFound = (req, res, next) => {
  const error = new AppError(`Can't find ${req.originalUrl} on this server!`, 404);
  next(error);
};

module.exports = {
  handleAsyncErrors,
  errorHandler,
  notFound
};

