const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const xss = require('xss-clean');
const cors = require('cors');
const hpp = require('hpp');
const csrf = require('csurf');
const ipFilter = require('express-ip-filter');
const { check, validationResult } = require('express-validator');
const cookieParser = require('cookie-parser');
const mongoSanitize = require('express-mongo-sanitize');
const logger = require('../utils/logger');
const AppError = require('../utils/appError');
const config = require('../config');

/**
 * @module SecurityMiddleware
 * @description Provides comprehensive security middleware for Express applications
 */

/**
 * @function setSecurityHeaders
 * @description Sets secure HTTP headers using Helmet
 * @returns {Function} Express middleware
 */
exports.setSecurityHeaders = () => {
  return helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'self'"],
        fontSrc: ["'self'", 'https:', 'data:'],
        frameAncestors: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        objectSrc: ["'none'"],
        scriptSrc: ["'self'"],
        scriptSrcAttr: ["'none'"],
        styleSrc: ["'self'", 'https:', "'unsafe-inline'"],
        upgradeInsecureRequests: [],
      },
    },
    crossOriginEmbedderPolicy: { policy: 'require-corp' },
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    dnsPrefetchControl: { allow: false },
    expectCt: {
      maxAge: 86400,
      enforce: true,
    },
    frameguard: { action: 'deny' },
    hsts: {
      maxAge: 15552000,
      includeSubDomains: true,
      preload: true,
    },
    ieNoOpen: true,
    noSniff: true,
    originAgentCluster: true,
    permittedCrossDomainPolicies: { permittedPolicies: 'none' },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    xssFilter: true,
  });
};

/**
 * @function setCsrfProtection
 * @description Protects against Cross-Site Request Forgery
 * @returns {Function} Express middleware
 */
exports.setCsrfProtection = () => {
  return [
    cookieParser(),
    csrf({ 
      cookie: {
        key: '_csrf',
        path: '/',
        httpOnly: true,
        secure: config.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 3600 // 1 hour
      } 
    }),
    (req, res, next) => {
      res.locals.csrfToken = req.csrfToken();
      next();
    },
    (err, req, res, next) => {
      if (err.code === 'EBADCSRFTOKEN') {
        logger.security({
          message: 'CSRF attack detected',
          ip: req.ip,
          path: req.originalUrl,
          method: req.method,
          headers: req.headers,
        });
        return next(new AppError('Invalid CSRF token. Request denied.', 403));
      }
      next(err);
    }
  ];
};

/**
 * @function setRateLimiter
 * @description Rate limits requests based on specified tier
 * @param {String} tier - Rate limiting tier (standard, auth, api)
 * @returns {Function} Express middleware
 */
exports.setRateLimiter = (tier = 'standard') => {
  const tiers = {
    standard: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // limit each IP to 100 requests per windowMs
      message: 'Too many requests from this IP, please try again after 15 minutes',
    },
    auth: {
      windowMs: 60 * 60 * 1000, // 1 hour
      max: 10, // limit each IP to 10 login attempts per hour
      message: 'Too many login attempts from this IP, please try again after an hour',
    },
    api: {
      windowMs: 5 * 60 * 1000, // 5 minutes
      max: 50, // limit each IP to 50 API requests per 5 minutes
      message: 'API rate limit exceeded. Please try again later.',
    },
    sensitive: {
      windowMs: 24 * 60 * 60 * 1000, // 24 hours
      max: 5, // limit each IP to 5 requests per day
      message: 'Too many requests for sensitive operations, please try again later',
    }
  };

  const limiter = rateLimit({
    windowMs: tiers[tier].windowMs,
    max: tiers[tier].max,
    message: tiers[tier].message,
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    skipSuccessfulRequests: false,
    handler: (req, res, next, options) => {
      logger.security({
        message: `Rate limit exceeded (${tier} tier)`,
        ip: req.ip,
        path: req.originalUrl,
        method: req.method,
        headers: req.headers,
      });
      return res.status(429).json({
        status: 'error',
        message: options.message
      });
    },
    skip: (req) => {
      // Skip rate limiting for trusted IPs if configured
      return config.TRUSTED_IPS && config.TRUSTED_IPS.includes(req.ip);
    },
    keyGenerator: (req) => {
      // Use API key as rate limit key for authenticated requests
      if (req.headers['x-api-key']) {
        return req.headers['x-api-key'];
      }
      // Otherwise use IP address
      return req.ip;
    }
  });

  return limiter;
};

/**
 * @function setIpFilter
 * @description Filters requests based on IP address
 * @returns {Function} Express middleware
 */
exports.setIpFilter = () => {
  const options = {
    forbidden: config.BLOCKED_IPS || [],
    filter: 'forbid',
    trustProxy: true,
    log: false,
    strict: true,
  };

  return [
    ipFilter(options),
    (err, req, res, next) => {
      if (err instanceof ipFilter.IpDeniedError) {
        logger.security({
          message: 'IP blocked',
          ip: req.ip,
          path: req.originalUrl,
          method: req.method,
          headers: req.headers,
        });
        return next(new AppError('Access denied from this IP address.', 403));
      }
      next(err);
    }
  ];
};

/**
 * @function sanitizeRequests
 * @description Sanitizes request data to prevent injection attacks
 * @returns {Function} Express middleware
 */
exports.sanitizeRequests = () => {
  return [
    xss(), // Sanitize request body, query, and params against XSS attacks
    mongoSanitize({ // Sanitize request against NoSQL query injection
      allowDots: true,
      replaceWith: '_'
    }),
    hpp({ // Prevent HTTP Parameter Pollution
      whitelist: [
        'id', 'name', 'email', 'role', 'status', 'sort', 'limit', 'page', 
        'fields', 'caseId', 'clientId', 'startDate', 'endDate'
      ]
    })
  ];
};

/**
 * @function limitRequestSize
 * @description Limits the size of request payloads
 * @returns {Function} Express middleware
 */
exports.limitRequestSize = () => {
  return (req, res, next) => {
    const contentLength = parseInt(req.headers['content-length'] || '0', 10);
    const maxSize = 1024 * 1024; // 1MB

    if (contentLength > maxSize) {
      logger.security({
        message: 'Request body too large',
        size: contentLength,
        ip: req.ip,
        path: req.originalUrl,
        method: req.method,
        headers: req.headers,
      });
      return next(new AppError('Request body too large. Maximum size is 1MB.', 413));
    }
    next();
  };
};

/**
 * @function detectSuspiciousActivity
 * @description Detects and logs suspicious activity patterns
 * @returns {Function} Express middleware
 */
exports.detectSuspiciousActivity = () => {
  return (req, res, next) => {
    // Check for suspicious query parameters
    const suspiciousParams = ['../','..\\', '..%252F', '%00', 'script', 'eval(', '<script', 'document.cookie'];
    const queryString = req.originalUrl;
    
    const hasSuspiciousParams = suspiciousParams.some(param => queryString.includes(param));
    
    // Check for suspicious headers
    const suspiciousUserAgent = req.headers['user-agent'] && 
      (req.headers['user-agent'].includes('sqlmap') || 
       req.headers['user-agent'].includes('nmap') ||
       req.headers['user-agent'].includes('burp') ||
       req.headers['user-agent'].includes('nikto'));
    
    // Check for suspicious referer
    const suspiciousReferer = req.headers['referer'] && 
      suspiciousParams.some(param => req.headers['referer'].includes(param));
    
    if (hasSuspiciousParams || suspiciousUserAgent || suspiciousReferer) {
      logger.security({
        message: 'Suspicious activity detected',
        ip: req.ip,
        path: req.originalUrl,
        method: req.method,
        headers: req.headers,
        queryParams: req.query,
        reason: {
          suspiciousParams: hasSuspiciousParams,
          suspiciousUserAgent: suspiciousUserAgent,
          suspiciousReferer: suspiciousReferer
        }
      });
      
      // Increment suspicious activity counter in cache/db for this IP
      // For more advanced implementations, this could trigger additional security measures
      
      // We still allow the request to proceed, but with heightened monitoring
    }
    
    next();
  };
};

/**
 * @function validateApiKey
 * @description Validates API key for external service access
 * @returns {Function} Express middleware
 */
exports.validateApiKey = () => {
  return (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    
    if (!apiKey) {
      return next(new AppError('API key is required', 401));
    }
    
    // In production, you'd validate against a database of API keys
    // This is a simplified example
    if (!config.API_KEYS.includes(apiKey)) {
      logger.security({
        message: 'Invalid API key attempt',
        ip: req.ip,
        path: req.originalUrl,
        method: req.method,
        headers: req.headers,
        apiKey: apiKey
      });
      return next(new AppError('Invalid API key', 401));
    }
    
    // Set API key information in request for subsequent middleware
    req.apiKeyInfo = {
      key: apiKey,
      // In a real implementation, you would look up:
      // owner: 'API key owner',
      // permissions: ['permission1', 'permission2'],
      // rateLimit: 1000,
      // expiresAt: new Date()
    };
    
    next();
  };
};

/**
 * @function validateSession
 * @description Validates user session and checks for session fixation
 * @returns {Function} Express middleware
 */
exports.validateSession = () => {
  return (req, res, next) => {
    // Check if session exists
    if (!req.session) {
      return next(new AppError('Session not found', 401));
    }
    
    // Check for session expiration
    if (req.session.expiresAt && new Date() > new Date(req.session.expiresAt)) {
      logger.security({
        message: 'Expired session attempt',
        ip: req.ip,
        userId: req.session.userId,
        sessionId: req.sessionID,
        path: req.originalUrl,
        method: req.method
      });
      
      req.session.destroy();
      return next(new AppError('Session has expired. Please log in again.', 401));
    }
    
    // Check for session fixation attacks
    if (req.session.userAgent && req.session.userAgent !== req.headers['user-agent']) {
      logger.security({
        message: 'Possible session fixation attempt',
        ip: req.ip,
        userId: req.session.userId,
        sessionId: req.sessionID,
        originalUserAgent: req.session.userAgent,
        currentUserAgent: req.headers['user-agent'],
        path: req.originalUrl,
        method: req.method
      });
      
      req.session.destroy();
      return next(new AppError('Session mismatch. Please log in again.', 401));
    }
    
    // Check for IP mismatch (optional, configurable)
    if (config.SESSION_IP_VALIDATION && req.session.ip && req.session.ip !== req.ip) {
      logger.security({
        message: 'Session IP mismatch',
        originalIp: req.session.ip,
        currentIp: req.ip,
        userId: req.session.userId,
        sessionId: req.sessionID,
        path: req.originalUrl,
        method: req.method
      });
      
      // In strict mode, terminate the session
      if (config.STRICT_SESSION_SECURITY) {
        req.session.destroy();
        return next(new AppError('Session IP mismatch. Please log in again.', 401));
      }
      
      // Otherwise, just update the session IP (for users with dynamic IPs)
      req.session.ip = req.ip;
    }
    
    // Update session last activity time
    req.session.lastActivity = new Date();
    
    next();
  };
};

/**
 * @function setCorsOptions
 * @description Sets CORS policy for cross-origin requests
 * @returns {Function} Express middleware
 */
exports.setCorsOptions = () => {
  const corsOptions = {
    origin: config.CORS_ORIGINS || '*',
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-API-Key', 'X-CSRF-Token'],
    exposedHeaders: ['Content-Disposition'],
    credentials: true,
    maxAge: 86400 // 24 hours
  };
  
  return cors(corsOptions);
};

/**
 * @function securityErrorHandler
 * @description Centralized error handler for security middleware
 * @returns {Function} Express error middleware
 */
exports.securityErrorHandler = () => {
  return (err, req, res, next) => {
    // Log all security-related errors
    logger.security({
      message: 'Security error encountered',
      error: err.message,
      stack: config.NODE_ENV === 'development' ? err.stack : undefined,
      ip: req.ip,
      path: req.originalUrl,
      method: req.method,
      headers: req.headers,
      statusCode: err.statusCode || 500
    });

    // Handle specific security error types
    if (err.name === 'ValidationError') {
      return res.status(400).json({
        status: 'error',
        message: 'Input validation failed',
        errors: err.errors || [err.message]
      });
    }

    if (err.name === 'UnauthorizedError' || err.name === 'JsonWebTokenError') {
      return res.status(401).json({
        status: 'error',
        message: 'Authentication failed. Please log in again.'
      });
    }
    
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        status: 'error',
        message: 'Your session has expired. Please log in again.'
      });
    }

    if (err.statusCode === 403) {
      return res.status(403).json({
        status: 'error',
        message: err.message || 'Access forbidden'
      });
    }

    if (err.statusCode === 429) {
      return res.status(429).json({
        status: 'error',
        message: err.message || 'Too many requests. Please try again later.'
      });
    }

    // Default handler for other security errors
    const statusCode = err.statusCode || 500;
    const message = statusCode === 500 
      ? 'Internal server error' 
      : err.message || 'Security policy violation';

    res.status(statusCode).json({
      status: 'error',
      message
    });
  };
};

/**
 * @function validateRequest
 * @description Validates request data against specified schema
 * @param {Object} schema - Validation schema object
 * @returns {Function} Express middleware
 */
exports.validateRequest = (schema) => {
  return (req, res, next) => {
    if (!schema) return next();

    const validationFields = ['body', 'query', 'params'];
    const validationErrors = [];

    validationFields.forEach(field => {
      if (schema[field]) {
        const { error } = schema[field].validate(req[field], { abortEarly: false });
        if (error) {
          error.details.forEach(detail => {
            validationErrors.push({
              field: `${field}.${detail.path.join('.')}`,
              message: detail.message,
              value: detail.context.value
            });
          });
        }
      }
    });

    if (validationErrors.length > 0) {
      logger.security({
        message: 'Request validation failed',
        ip: req.ip,
        path: req.originalUrl,
        method: req.method,
        errors: validationErrors,
        body: config.NODE_ENV === 'development' ? req.body : undefined
      });

      return next(new AppError('Request validation failed', 400, validationErrors));
    }

    next();
  };
};

/**
 * @function preventClickjacking
 * @description Sets X-Frame-Options header to prevent clickjacking attacks
 * @returns {Function} Express middleware
 */
exports.preventClickjacking = () => {
  return (req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    next();
  };
};

/**
 * @function strictTransportSecurity
 * @description Sets Strict-Transport-Security header for HTTPS enforcement
 * @returns {Function} Express middleware
 */
exports.strictTransportSecurity = () => {
  const maxAge = 31536000; // 1 year in seconds
  return (req, res, next) => {
    res.setHeader('Strict-Transport-Security', `max-age=${maxAge}; includeSubDomains; preload`);
    next();
  };
};

/**
 * @function secureJsonHandling
 * @description Prevents JSON hijacking by prefixing all JSON responses
 * @returns {Function} Express middleware
 */
exports.secureJsonHandling = () => {
  return (req, res, next) => {
    const originalJson = res.json;
    res.json = function(obj) {
      if (req.headers['content-type'] === 'application/json' && 
          req.method === 'GET' && 
          config.NODE_ENV === 'production') {
        // Prefix pure array responses to prevent JSON hijacking
        if (Array.isArray(obj)) {
          return originalJson.call(this, { data: obj });
        }
      }
      return originalJson.call(this, obj);
    };
    next();
  };
};

/**
 * @function detectBruteForce
 * @description Detects potential brute force attacks
 * @returns {Function} Express middleware
 */
exports.detectBruteForce = () => {
  // In a real application, this would use Redis or another caching mechanism
  const failedAttempts = {};
  const threshold = 5; // Number of failures before flagging
  const windowMs = 10 * 60 * 1000; // 10 minutes
  
  return (req, res, next) => {
    // Only apply to auth endpoints
    if (!req.originalUrl.includes('/auth/')) {
      return next();
    }
    
    const ip = req.ip;
    const now = Date.now();
    
    // Clean up old entries
    if (failedAttempts[ip] && now - failedAttempts[ip].firstAttempt > windowMs) {
      delete failedAttempts[ip];
    }
    
    // Initialize counter for new IPs
    if (!failedAttempts[ip]) {
      failedAttempts[ip] = {
        count: 0,
        firstAttempt: now
      };
    }
    
    // Check for threshold
    if (failedAttempts[ip].count >= threshold) {
      logger.security({
        message: 'Potential brute force attack detected',
        ip: ip,
        attemptCount: failedAttempts[ip].count,
        timeWindow: `${windowMs/60000} minutes`,
        path: req.originalUrl,
        method: req.method
      });
      
      // We could block here, but we'll just log and continue
      // Actual blocking is handled by the rate limiter
    }
    
    // Store original send function
    const originalSend = res.send;
    
    // Override send method to track failed login attempts
    res.send = function(body) {
      // Parse response body if it's a string
      let parsedBody;
      if (typeof body === 'string') {
        try {
          parsedBody = JSON.parse(body);
        } catch (e) {
          parsedBody = {};
        }
      } else {
        parsedBody = body;
      }
      
      // If this is an error response for an auth endpoint
      if (this.statusCode >= 400 && req.originalUrl.includes('/auth/')) {
        failedAttempts[ip].count++;
      }
      
      // Call original send
      return originalSend.call(this, body);
    };
    
    next();
  };
};

/**
 * @function applySecurityMiddleware
 * @description Applies all security middleware to an Express app
 * @param {Object} app - Express app
 * @returns {void}
 */
exports.applySecurityMiddleware = (app) => {
  // Apply all security middleware in appropriate order
  app.use(this.setSecurityHeaders());
  app.use(this.setCorsOptions());
  app.use(this.limitRequestSize());
  app.use(this.sanitizeRequests());
  app.use(this.detectSuspiciousActivity());
  app.use(this.detectBruteForce());
  app.use(this.preventClickjacking());
  app.use(this.secureJsonHandling());
  
  // Apply environment-specific security
  if (config.NODE_ENV === 'production') {
    app.use(this.strictTransportSecurity());
    app.use(this.setIpFilter());
  }
  
  // Apply CSRF protection for non-API routes
  // This must be after cookie-parser and session middleware
  app.use((req, res, next) => {
    if (!req.path.startsWith('/api/')) {
      return this.setCsrfProtection()(req, res, next);
    }
    next();
  });
  
  // Error handlers should be registered last
  app.use(this.securityErrorHandler());
};
