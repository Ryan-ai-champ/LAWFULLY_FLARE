const dotenv = require('dotenv');
const path = require('path');
const Joi = require('joi');
const fs = require('fs');

// Load environment variables from .env file
dotenv.config({ path: path.join(__dirname, '../../.env') });

// Define validation schema for environment variables
const envVarsSchema = Joi.object()
  .keys({
    NODE_ENV: Joi.string().valid('production', 'development', 'test').default('development'),
    PORT: Joi.number().default(5000),
    MONGODB_URI: Joi.string().required().description('MongoDB connection string'),
    JWT_SECRET: Joi.string().required().description('JWT secret key'),
    JWT_ACCESS_EXPIRATION_MINUTES: Joi.number().default(30).description('Minutes after which access tokens expire'),
    JWT_REFRESH_EXPIRATION_DAYS: Joi.number().default(30).description('Days after which refresh tokens expire'),
    JWT_RESET_PASSWORD_EXPIRATION_MINUTES: Joi.number().default(10).description('Minutes after which reset password token expires'),
    JWT_VERIFY_EMAIL_EXPIRATION_MINUTES: Joi.number().default(10).description('Minutes after which verify email token expires'),
    SMTP_HOST: Joi.string().description('SMTP server host'),
    SMTP_PORT: Joi.number().description('SMTP server port'),
    SMTP_USERNAME: Joi.string().description('SMTP username'),
    SMTP_PASSWORD: Joi.string().description('SMTP password'),
    EMAIL_FROM: Joi.string().description('Email sender address'),
    UPLOAD_LIMIT: Joi.number().default(5).description('File upload size limit in MB'),
    UPLOAD_ALLOWED_TYPES: Joi.string().default('image/jpeg,image/png,application/pdf,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document'),
    API_RATE_LIMIT: Joi.number().default(100).description('API rate limit per IP'),
    API_RATE_LIMIT_WINDOW_MS: Joi.number().default(15 * 60 * 1000).description('API rate limit window in milliseconds'),
    LOG_LEVEL: Joi.string().valid('error', 'warn', 'info', 'debug').default('info'),
    LOG_FILE: Joi.string().default('logs/app.log'),
    CLIENT_URL: Joi.string().required().description('Client URL for CORS and email links'),
  })
  .unknown();

// Validate environment variables against the schema
const { value: envVars, error } = envVarsSchema.prefs({ errors: { label: 'key' } }).validate(process.env);

if (error) {
  throw new Error(`Config validation error: ${error.message}`);
}

// Create configuration object
const config = {
  env: envVars.NODE_ENV,
  port: envVars.PORT,
  
  // Database configuration
  mongoose: {
    url: envVars.MONGODB_URI,
    options: {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    },
  },
  
  // JWT configuration
  jwt: {
    secret: envVars.JWT_SECRET,
    accessExpirationMinutes: envVars.JWT_ACCESS_EXPIRATION_MINUTES,
    refreshExpirationDays: envVars.JWT_REFRESH_EXPIRATION_DAYS,
    resetPasswordExpirationMinutes: envVars.JWT_RESET_PASSWORD_EXPIRATION_MINUTES,
    verifyEmailExpirationMinutes: envVars.JWT_VERIFY_EMAIL_EXPIRATION_MINUTES,
  },
  
  // Email configuration
  email: {
    smtp: {
      host: envVars.SMTP_HOST,
      port: envVars.SMTP_PORT,
      auth: {
        user: envVars.SMTP_USERNAME,
        pass: envVars.SMTP_PASSWORD,
      },
    },
    from: envVars.EMAIL_FROM || 'no-reply@immigration-app.com',
    templates: {
      welcome: {
        subject: 'Welcome to Immigration Application',
        text: fs.readFileSync(path.join(__dirname, '../templates/welcome.txt'), 'utf8'),
        html: fs.readFileSync(path.join(__dirname, '../templates/welcome.html'), 'utf8'),
      },
      resetPassword: {
        subject: 'Reset your password',
        text: fs.readFileSync(path.join(__dirname, '../templates/reset-password.txt'), 'utf8'),
        html: fs.readFileSync(path.join(__dirname, '../templates/reset-password.html'), 'utf8'),
      },
      verifyEmail: {
        subject: 'Email Verification',
        text: fs.readFileSync(path.join(__dirname, '../templates/verify-email.txt'), 'utf8'),
        html: fs.readFileSync(path.join(__dirname, '../templates/verify-email.html'), 'utf8'),
      },
      caseStatusUpdate: {
        subject: 'Case Status Update',
        text: fs.readFileSync(path.join(__dirname, '../templates/case-status-update.txt'), 'utf8'),
        html: fs.readFileSync(path.join(__dirname, '../templates/case-status-update.html'), 'utf8'),
      },
    },
  },
  
  // File upload configuration
  fileUpload: {
    limits: {
      fileSize: envVars.UPLOAD_LIMIT * 1024 * 1024, // in bytes
    },
    allowedTypes: envVars.UPLOAD_ALLOWED_TYPES.split(','),
    storage: {
      destination: path.join(__dirname, '../../uploads/'),
      tempDir: path.join(__dirname, '../../uploads/temp/'),
    },
  },
  
  // API rate limiting
  rateLimit: {
    windowMs: envVars.API_RATE_LIMIT_WINDOW_MS,
    max: envVars.API_RATE_LIMIT,
    message: 'Too many requests from this IP, please try again later.',
  },
  
  // Logging configuration
  logging: {
    level: envVars.LOG_LEVEL,
    file: envVars.LOG_FILE,
    console: true,
  },
  
  // Client URL for CORS and email links
  clientUrl: envVars.CLIENT_URL,
  
  // Document verification settings
  documentVerification: {
    expiryDays: 30,
    requiredDocuments: [
      'passport',
      'birthCertificate',
      'proofOfResidence',
      'financialDocuments',
      'photoId',
    ],
  },
};

// Ensure upload directories exist
try {
  if (!fs.existsSync(config.fileUpload.storage.destination)) {
    fs.mkdirSync(config.fileUpload.storage.destination, { recursive: true });
  }
  if (!fs.existsSync(config.fileUpload.storage.tempDir)) {
    fs.mkdirSync(config.fileUpload.storage.tempDir, { recursive: true });
  }
} catch (err) {
  console.error('Error creating upload directories:', err);
}

// Ensure log directory exists
try {
  const logDir = path.dirname(config.logging.file);
  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
  }
} catch (err) {
  console.error('Error creating log directory:', err);
}

module.exports = config;

