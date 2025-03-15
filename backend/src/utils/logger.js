const winston = require('winston');
require('winston-daily-rotate-file');
const { format } = winston;
const path = require('path');
const config = require('../config/config');

// Define log directory
const logDir = path.join(process.cwd(), 'logs');

// Define custom log formats
const customFormats = {
  console: format.combine(
    format.colorize(),
    format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    format.printf(({ timestamp, level, message, ...meta }) => {
      const metaString = Object.keys(meta).length ? `\n${JSON.stringify(meta, null, 2)}` : '';
      return `[${timestamp}] ${level}: ${message}${metaString}`;
    })
  ),
  file: format.combine(
    format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    format.json()
  )
};

// Configure log levels based on environment
const logLevel = config.env === 'development' ? 'debug' : 'info';

// Create file transport for daily rotated logs
const fileRotateTransport = new winston.transports.DailyRotateFile({
  filename: path.join(logDir, 'application-%DATE%.log'),
  datePattern: 'YYYY-MM-DD',
  maxSize: '20m',
  maxFiles: '14d',
  format: customFormats.file,
  level: logLevel
});

// Create error log file transport for daily rotated logs (errors only)
const errorFileRotateTransport = new winston.transports.DailyRotateFile({
  filename: path.join(logDir, 'error-%DATE%.log'),
  datePattern: 'YYYY-MM-DD',
  maxSize: '20m',
  maxFiles: '14d',
  format: customFormats.file,
  level: 'error'
});

// Create console transport
const consoleTransport = new winston.transports.Console({
  format: customFormats.console,
  level: logLevel
});

// Initialize logger with transports
const logger = winston.createLogger({
  level: logLevel,
  defaultMeta: { service: 'immigration-app' },
  transports: [
    consoleTransport,
    fileRotateTransport,
    errorFileRotateTransport
  ],
  exitOnError: false
});

// Add events to handle transport errors
fileRotateTransport.on('error', (error) => {
  console.error('Error with file rotation transport:', error);
});

errorFileRotateTransport.on('error', (error) => {
  console.error('Error with error file rotation transport:', error);
});

// Create request logging middleware
const requestLogger = (req, res, next) => {
  const startTime = Date.now();
  
  // Log request details
  logger.debug(`Incoming request: ${req.method} ${req.originalUrl}`, {
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    headers: req.headers
  });

  // Log body if not a GET request and not a file upload
  if (req.method !== 'GET' && !req.originalUrl.includes('/upload') && !req.headers['content-type']?.includes('multipart/form-data')) {
    logger.debug('Request body:', { body: req.body });
  }
  
  // Log response when completed
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    const logLevel = res.statusCode >= 400 ? 'warn' : 'info';
    
    logger[logLevel](`Response: ${res.statusCode} ${res.statusMessage} [${duration}ms]`, {
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      duration: `${duration}ms`
    });
  });
  
  next();
};

// Wrap console methods to use logger
const wrapConsole = () => {
  const originalConsoleLog = console.log;
  const originalConsoleInfo = console.info;
  const originalConsoleWarn = console.warn;
  const originalConsoleError = console.error;
  
  console.log = (...args) => {
    logger.debug(...args);
    originalConsoleLog(...args);
  };
  
  console.info = (...args) => {
    logger.info(...args);
    originalConsoleInfo(...args);
  };
  
  console.warn = (...args) => {
    logger.warn(...args);
    originalConsoleWarn(...args);
  };
  
  console.error = (...args) => {
    logger.error(...args);
    originalConsoleError(...args);
  };
};

// Execute in non-test environment
if (process.env.NODE_ENV !== 'test') {
  wrapConsole();
}

// Create streaming interface for Morgan (if used)
logger.stream = {
  write: (message) => {
    logger.info(message.trim());
  }
};

module.exports = {
  logger,
  requestLogger
};

