const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
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
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters'],
    select: false // Don't return password in queries by default
  },
  role: {
    type: String,
    enum: ['admin', 'attorney', 'paralegal', 'client'],
    default: 'client'
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
  resetPasswordToken: String,
  resetPasswordExpire: Date,
  emailVerified: {
    type: Boolean,
    default: false
  },
  verificationToken: String,
  verificationTokenExpire: Date,
  twoFactorAuth: {
    enabled: {
      type: Boolean,
      default: false
    },
    secret: String
  },
  refreshToken: {
    token: String,
    expires: Date
  },
  lastLogin: Date,
  activeCases: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'ImmigrationCase'
  }],
  isActive: {
    type: Boolean,
    default: true
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

// Method to generate refresh token
userSchema.methods.generateRefreshToken = function() {
  // Generate a random token
  const refreshToken = crypto.randomBytes(40).toString('hex');
  
  // Set expiration (7 days)
  const expiresIn = Date.now() + 7 * 24 * 60 * 60 * 1000;
  
  // Save to user document
  this.refreshToken = {
    token: refreshToken,
    expires: new Date(expiresIn)
  };
  
  return refreshToken;
};

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

