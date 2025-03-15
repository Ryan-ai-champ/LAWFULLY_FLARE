const { logger } = require('../utils/logger');
const ApiError = require('../utils/ApiError');
const config = require('../config/config');

/**
 * Error handler middleware
 * Handles all errors thrown in the application and formats appropriate responses
 */
const errorHandler = (err, req, res, next) => {
  let error = { ...err };
  error.message = err.message;
  
  // Log error
  logger.error(`${err.name}: ${err.message}`, { 
    url: req.originalUrl,
    method: req.method,
    body: req.body,
    stack: err.stack,
    error: err
  });

  // Mongoose bad ObjectId
  if (err.name === 'CastError') {
    const message = 'Resource not found';
    error = new ApiError(message, 404);
  }

  // Mongoose duplicate key
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    const message = `Duplicate value entered for ${field} field`;
    error = new ApiError(message, 400);
  }

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const message = Object.values(err.errors).map(val => val.message);
    error = new ApiError(message, 400);
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    const message = 'Invalid token. Please log in again.';
    error = new ApiError(message, 401);
  }

  if (err.name === 'TokenExpiredError') {
    const message = 'Your token has expired! Please log in again.';
    error = new ApiError(message, 401);
  }

  // Multer file upload errors
  if (err.code === 'LIMIT_FILE_SIZE') {
    const message = 'File size is too large. Maximum file size is 2MB.';
    error = new ApiError(message, 400);
  }

  if (err.code === 'LIMIT_UNEXPECTED_FILE') {
    const message = 'Invalid file type. Only images and PDFs are allowed.';
    error = new ApiError(message, 400);
  }

  // Final response to client
  const statusCode = error.statusCode || 500;
  const response = {
    success: false,
    error: {
      message: error.message || 'Server Error',
      statusCode,
    },
  };

  // Add stack trace in development environment
  if (config.env === 'development') {
    response.error.stack = err.stack;
    response.error.detailedError = err;
  }

  res.status(statusCode).json(response);
};

module.exports = errorHandler;

