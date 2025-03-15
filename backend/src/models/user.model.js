const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
/**
 * User Model Schema
 * @typedef {Object} UserSchema
 * @property {String} firstName - User's first name
 * @property {String} lastName - User's last name
 * @property {String} email - User's email address (unique)
 * @property {String} password - Hashed password (not returned in queries)
 * @property {String} role - User role (admin, attorney, paralegal, client)
 * @property {Object} tokenVersion - Token version for JWT invalidation and rotation
 * @property {Array} activeSessions - List of active user sessions
 * @property {Object} twoFactorAuth - 2FA settings and verification
 * @property {Object} loginAttempts - Tracking for failed login attempts
 * @property {Object} permissions - Custom role-based permissions
 * @property {Object} accountStatus - Various account status flags
 * @property {Object} verificationData - Email verification information
 * @property {Object} passwordReset - Password reset information
 * @property {Array} activeCases - Related immigration cases
 * @property {Date} createdAt - Account creation timestamp
 * @property {Date} updatedAt - Last update timestamp
 */
const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: [true, 'First name is required'],
    trim: true
  },
  lastName: {
    type: String,
    required: [true, 'Last name is required'],
    trim: true
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please provide a valid email']
  },
  /**
   * Password field with enhanced validation requirements
   * - At least 8 characters
   * - Contains at least one uppercase letter
   * - Contains at least one lowercase letter
   * - Contains at least one number
   * - Contains at least one special character
   * @type {String}
   */
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters'],
    validate: {
      validator: function(v) {
        // Password must have at least one uppercase, one lowercase, one number, and one special character
        return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/.test(v);
      },
      message: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
    },
    select: false // Don't return password in queries by default
  },
  /**
   * User role defining access level and permissions
   * @type {String}
   */
  role: {
    type: String,
    enum: ['admin', 'attorney', 'paralegal', 'client'],
    default: 'client'
  },
  
  /**
   * Token version for invalidating JWTs and preventing replay attacks
   * Incremented whenever password changes or user performs logout on all devices
   * @type {Object}
   */
  tokenVersion: {
    accessVersion: {
      type: Number,
      default: 0
    },
    refreshVersion: {
      type: Number,
      default: 0
    },
    lastRotated: {
      type: Date,
      default: Date.now
    }
  },
  
  /**
   * Tracks all active sessions across devices
   * Allows for targeted session revocation
   * @type {Array}
   */
  activeSessions: [{
    deviceId: String,
    userAgent: String,
    ipAddress: String,
    lastActivity: {
      type: Date,
      default: Date.now
    },
    issuedAt: {
      type: Date,
      default: Date.now
    },
    expiresAt: Date,
    location: {
      city: String,
      country: String,
      coordinates: {
        latitude: Number,
        longitude: Number
      }
    }
  }],
  
  /**
   * Login attempt tracking for security monitoring
   * Used for account lockout after multiple failed attempts
   * @type {Object}
   */
  loginAttempts: {
    count: {
      type: Number,
      default: 0
    },
    lastAttempt: Date,
    lockUntil: Date
  },
  
  /**
   * Custom permissions beyond role-based access
   * Allows for granular control of user abilities
   * @type {Object}
   */
  permissions: {
    custom: [{
      name: String,
      granted: {
        type: Boolean,
        default: false
      },
      grantedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
      },
      grantedAt: Date
    }],
    overrides: [{
      name: String,
      value: Boolean,
      reason: String,
      appliedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
      },
      appliedAt: {
        type: Date,
        default: Date.now
      }
    }]
  },
  phone: {
    type: String,
    trim: true
  },
  address: {
    street: String,
    city: String,
    state: String,
    zipCode: String,
    country: String
  },
  dateOfBirth: {
    type: Date
  },
  languages: [{
    type: String,
    enum: ['English', 'Spanish', 'Chinese', 'Hindi', 'Arabic', 'French', 'Russian', 'Portuguese', 'Other']
  }],
  profileImage: {
    type: String, // URL to image stored in S3
  },
  barNumber: {
    type: String, // For attorneys
    sparse: true
  },
  specializations: [{
    type: String,
    enum: ['Family-Based Immigration', 'Employment-Based Immigration', 'Asylum', 'Deportation Defense', 'Citizenship', 'Non-Immigrant Visas', 'Other']
  }],
  subscribedPlan: {
    type: String,
    enum: ['free', 'basic', 'premium', 'enterprise'],
    default: 'free'
  },
  paymentInfo: {
    customerId: String, // Stripe customer ID
    subscriptionId: String, // Stripe subscription ID
    subscriptionStatus: String
  },
  notifications: {
    email: {
      type: Boolean,
      default: true
    },
    sms: {
      type: Boolean,
      default: false
    },
    push: {
      type: Boolean,
      default: true
    }
  },
  /**
   * Account status flags for controlling access and features
   * @type {Object}
   */
  accountStatus: {
    isActive: {
      type: Boolean,
      default: true
    },
    isSuspended: {
      type: Boolean,
      default: false
    },
    suspensionReason: String,
    suspendedAt: Date,
    suspendedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    isLocked: {
      type: Boolean,
      default: false
    },
    lockReason: String,
    deactivatedAt: Date,
    lastStatusChange: {
      status: String,
      changedAt: {
        type: Date,
        default: Date.now
      },
      changedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
      },
      reason: String
    }
  },
  
  /**
   * Email verification data
   * @type {Object}
   */
  verificationData: {
    emailVerified: {
      type: Boolean,
      default: false
    },
    verifiedAt: Date,
    verificationToken: String,
    verificationTokenExpire: Date,
    verificationAttempts: {
      type: Number,
      default: 0
    },
    lastVerificationAttempt: Date
  },
  
  /**
   * Password reset information
   * @type {Object}
   */
  passwordReset: {
    resetToken: String,
    resetTokenExpire: Date,
    resetRequested: Date,
    resetRequestIP: String,
    resetCount: {
      type: Number,
      default: 0
    },
    lastReset: Date,
    previousPasswords: [{
      hash: String,
      changedAt: Date
    }]
  },
  /**
   * Two-factor authentication configuration
   * @type {Object}
   */
  twoFactorAuth: {
    enabled: {
      type: Boolean,
      default: false
    },
    secret: {
      type: String,
      select: false // Don't return secret in queries by default
    },
    method: {
      type: String,
      enum: ['app', 'email', 'sms'],
      default: 'app'
    },
    backupCodes: [{
      code: {
        type: String,
        select: false // Don't return codes in queries by default
      },
      used: {
        type: Boolean,
        default: false
      },
      usedAt: Date
    }],
    lastVerified: Date,
    verificationAttempts: {
      count: {
        type: Number,
        default: 0
      },
      lastAttempt: Date,
      lockUntil: Date
    },
    tempSecret: {
      secret: String,
      createdAt: Date,
      expiresAt: Date
    }
  },
  /**
   * Refresh token data
   * @type {Object}
   */
  refreshToken: {
    token: {
      type: String,
      select: false // Don't return token in queries by default
    },
    expires: Date,
    family: String, // For tracking token chains for proper rotation
    issuedIp: String
  },
  
  /**
   * Login history tracking
   * @type {Object}
   */
  loginHistory: {
    lastSuccessfulLogin: {
      date: Date,
      ipAddress: String,
      userAgent: String,
      location: {
        city: String,
        country: String
      }
    },
    lastFailedLogin: {
      date: Date,
      ipAddress: String,
      userAgent: String,
      reason: String
    },
    loginCount: {
      type: Number,
      default: 0
    },
    recentLogins: [{
      date: Date,
      ipAddress: String,
      userAgent: String,
      success: Boolean,
      tokenIssued: Boolean
    }]
  },
  activeCases: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'ImmigrationCase'
  }],
  /**
   * API access configuration
   * @type {Object}
   */
  apiAccess: {
    enabled: {
      type: Boolean,
      default: false
    },
    apiKey: {
      type: String,
      select: false // Don't return API key in queries by default
    },
    lastKeyReset: Date,
    allowedIPs: [String],
    rateLimits: {
      requestsPerMinute: {
        type: Number,
        default: 60
      },
      burstLimit: {
        type: Number,
        default: 10
      }
    },
    accessLog: [{
      timestamp: Date,
      endpoint: String,
      ipAddress: String,
      success: Boolean,
      responseTime: Number
    }]
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Middleware to encrypt password before saving
userSchema.pre('save', async function(next) {
  // Only hash the password if it has been modified (or is new)
  if (!this.isModified('password')) return next();
  
  try {
    // Generate salt
    const salt = await bcrypt.genSalt(10);
    // Hash the password with the salt
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to check if password matches
userSchema.methods.matchPassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Method to generate JWT token
userSchema.methods.generateAuthToken = function() {
  return jwt.sign(
    { 
      id: this._id, 
      role: this.role,
      email: this.email,
      emailVerified: this.emailVerified
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRE }
  );
};

/**
 * Generates a JWT access token with the token version
 * @param {Object} options - Token generation options
 * @param {Number} options.expiresIn - Token expiration time in seconds
 * @returns {String} JWT token
 */
userSchema.methods.generateAccessToken = function(options = {}) {
  // Increment access token version on explicit rotation
  if (options.rotate) {
    this.tokenVersion.accessVersion += 1;
    this.tokenVersion.lastRotated = new Date();
  }
  
  return jwt.sign(
    { 
      id: this._id, 
      role: this.role,
      email: this.email,
      emailVerified: this.verificationData.emailVerified,
      tokenVersion: this.tokenVersion.accessVersion,
      requires2FA: this.twoFactorAuth.enabled && !options.twoFactorVerified,
    },
    process.env.JWT_SECRET,
    { expiresIn: options.expiresIn || process.env.JWT_EXPIRE || '15m' }
  );
};

/**
 * Generates a refresh token with security features
 * @param {Object} reqInfo - Request information for audit
 * @param {String} reqInfo.ipAddress - IP address of the requester
 * @param {String} reqInfo.userAgent - User agent of the requester
 * @param {Boolean} rotateFamily - Whether to rotate the token family (for suspicious activity)
 * @returns {String} Refresh token
 */
userSchema.methods.generateRefreshToken = function(reqInfo = {}, rotateFamily = false) {
  // Generate a random token
  const refreshToken = crypto.randomBytes(40).toString('hex');
  
  // Set expiration (7 days)
  const expiresIn = Date.now() + 7 * 24 * 60 * 60 * 1000;
  
  // Create or rotate token family
  const tokenFamily = rotateFamily ? 
    crypto.randomBytes(10).toString('hex') : 
    (this.refreshToken?.family || crypto.randomBytes(10).toString('hex'));
  
  // Increment refresh token version on family rotation
  if (rotateFamily) {
    this.tokenVersion.refreshVersion += 1;
    this.tokenVersion.lastRotated = new Date();
  }
  
  // Save to user document
  this.refreshToken = {
    token: refreshToken,
    expires: new Date(expiresIn),

// Method to generate password reset token
userSchema.methods.generatePasswordResetToken = function() {
  // Generate token
  const resetToken = crypto.randomBytes(20).toString('hex');
  
  // Hash token and set to resetPasswordToken field
  this.resetPasswordToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
  
  // Set token expiration time (10 minutes)
  this.resetPasswordExpire = Date.now() + 10 * 60 * 1000;
  
  return resetToken;
};

// Method to generate email verification token
userSchema.methods.generateVerificationToken = function() {
  // Generate token
  const verificationToken = crypto.randomBytes(20).toString('hex');
  
  // Hash token and set to verificationToken field
  this.verificationToken = crypto
    .createHash('sha256')
    .update(verificationToken)
    .digest('hex');
  
  // Set token expiration time (24 hours)
  this.verificationTokenExpire = Date.now() + 24 * 60 * 60 * 1000;
  
  return verificationToken;
};

// Check if user has specific permissions
userSchema.methods.hasPermission = function(permission) {
  const rolePermissions = {
    'client': ['view_own_cases', 'submit_documents', 'update_profile'],
    'paralegal': ['view_own_cases', 'view_assigned_cases', 'submit_documents', 'update_profile', 'add_notes'],
    'attorney': ['view_own_cases', 'view_assigned_cases', 'view_all_cases', 'submit_documents', 'update_profile', 'add_notes', 'manage_cases'],
    'admin': ['view_own_cases', 'view_assigned_cases', 'view_all_cases', 'submit_documents', 'update_profile', 'add_notes', 'manage_cases', 'manage_users', 'manage_settings']
  };
  
  return rolePermissions[this.role]?.includes(permission) || false;
};

let User;
if (mongoose.models.User) {
  User = mongoose.model('User');
} else {
  User = mongoose.model('User', userSchema);
}

module.exports = User;

