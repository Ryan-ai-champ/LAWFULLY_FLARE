const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const Redis = require('ioredis');
const { ApiError } = require('../utils/apiError');
const config = require('../config/config');
const logger = require('../utils/logger');

// Initialize Redis client if Redis is configured
let redisClient;
if (config.redis.enabled) {
  redisClient = new Redis({
    host: config.redis.host,
    port: config.redis.port,
    password: config.redis.password,
    username: config.redis.username,
    enableOfflineQueue: false,
  });

  redisClient.on('error', (err) => {
    logger.error(`Redis error: ${err.message}`);
  });
}

/**
 * Factory function to create rate limiters with different configurations
 * @param {Object} options - Rate limiter options
 * @returns {Function} Express middleware
 */
const createRateLimiter = (options) => {
  const defaultOptions = {
    windowMs: 15 * 60 * 1000, // 15 minutes by default
    max: 100, // Limit each IP to 100 requests per windowMs
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    message: {
      status: 'error',
      message: 'Too many requests, please try again later.',
    },
    handler: (req, res, next, options) => {
      next(new ApiError(options.message.message, 429));
    },
  };

  // If Redis is configured, use Redis store
  if (config.redis.enabled && redisClient) {
    defaultOptions.store = new RedisStore({
      sendCommand: (...args) => redisClient.call(...args),
      prefix: 'ratelimit:',
    });
  }

  return rateLimit({ ...defaultOptions, ...options });
};

/**
 * General API rate limiter - applies to most routes
 * More permissive than specific endpoint limiters
 */
const generalLimiter = createRateLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: 60, // 60 requests per minute
  message: {
    status: 'error',
    message: 'Too many requests from this IP, please try again after a minute.',
  },
  keyGenerator: (req) => {
    // Use IP address as the key
    return req.ip;
  },
});

/**
 * Authentication endpoints rate limiter
 * More restrictive to prevent brute force attacks
 */
const authLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 requests per 15 minutes
  message: {
    status: 'error',
    message: 'Too many authentication attempts, please try again after 15 minutes.',
  },
  keyGenerator: (req) => {
    // Use IP address as the key
    return req.ip;
  },
});

/**
 * Dynamic rate limiter based on user authentication status
 * More permissive for authenticated users, more restrictive for guests
 */
const dynamicLimiter = (req, res, next) => {
  const isAuthenticated = req.user !== undefined;
  
  const options = isAuthenticated
    ? {
        windowMs: 60 * 1000, // 1 minute
        max: 100, // 100 requests per minute for authenticated users
        message: {
          status: 'error',
          message: 'Too many requests, please try again after a minute.',
        },
        keyGenerator: (req) => {
          // Use user ID as the key for authenticated users
          return `user:${req.user.id}`;
        },
      }
    : {
        windowMs: 60 * 1000, // 1 minute
        max: 30, // 30 requests per minute for guests
        message: {
          status: 'error',
          message: 'Too many requests from this IP, please try again after a minute.',
        },
        keyGenerator: (req) => {
          // Use IP address as the key for guests
          return `ip:${req.ip}`;
        },
      };

  return createRateLimiter(options)(req, res, next);
};

/**
 * Role-based rate limiter
 * Different limits based on user role
 */
const roleLimiter = (req, res, next) => {
  // Default to guest if no user or no role
  const role = req.user?.role || 'guest';
  
  const roleLimits = {
    admin: 300,       // 300 requests per minute for admins
    attorney: 200,    // 200 requests per minute for attorneys
    paralegal: 150,   // 150 requests per minute for paralegals
    client: 100,      // 100 requests per minute for clients
    guest: 30,        // 30 requests per minute for guests
  };

  const max = roleLimits[role] || roleLimits.guest;
  
  const options = {
    windowMs: 60 * 1000, // 1 minute
    max,
    message: {
      status: 'error',
      message: 'Rate limit exceeded for your role type. Please try again later.',
    },
    keyGenerator: (req) => {
      // Use role and user ID/IP as the key
      const id = req.user?.id || req.ip;
      return `role:${role}:${id}`;
    },
  };

  return createRateLimiter(options)(req, res, next);
};

/**
 * IP-based rate limiter
 * Useful for tracking and limiting by IP address regardless of authentication
 */
const ipLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 1000, // 1000 requests per hour
  message: {
    status: 'error',
    message: 'Too many requests from this IP, please try again after an hour.',
  },
  keyGenerator: (req) => {
    // Use IP address as the key
    return req.ip;
  },
});

module.exports = {
  generalLimiter,
  authLimiter,
  dynamicLimiter,
  roleLimiter,
  ipLimiter,
  createRateLimiter, // Export factory function for custom limiters
};

