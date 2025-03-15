const Joi = require('joi');
const { ApiError } = require('../utils/ApiError');

// Common validation schemas
const objectId = Joi.string().pattern(/^[0-9a-fA-F]{24}$/);
const password = Joi.string().min(8).max(30)
  .pattern(/[a-zA-Z]/).pattern(/[0-9]/).pattern(/[^a-zA-Z0-9]/)
  .message('Password must be 8-30 characters, include letters, numbers, and special characters');
const email = Joi.string().email();
const name = Joi.string().min(2).max(50);
const phone = Joi.string().pattern(/^\+?[0-9]{10,15}$/).message('Invalid phone number format');

// Auth route validation schemas
const authSchemas = {
  register: Joi.object({
    firstName: name.required(),
    lastName: name.required(),
    email: email.required(),
    password: password.required(),
    confirmPassword: Joi.string().valid(Joi.ref('password')).required()
      .messages({ 'any.only': 'Passwords do not match' }),
    phone: phone.optional(),
    role: Joi.string().valid('client', 'lawyer', 'admin').default('client'),
  }),

  login: Joi.object({
    email: email.required(),
    password: Joi.string().required(),
    rememberMe: Joi.boolean().default(false),
  }),

  forgotPassword: Joi.object({
    email: email.required(),
  }),

  resetPassword: Joi.object({
    token: Joi.string().required(),
    password: password.required(),
    confirmPassword: Joi.string().valid(Joi.ref('password')).required()
      .messages({ 'any.only': 'Passwords do not match' }),
  }),

  verifyEmail: Joi.object({
    token: Joi.string().required(),
  }),

  refreshToken: Joi.object({
    refreshToken: Joi.string().required(),
  }),
};

// User route validation schemas
const userSchemas = {
  updateProfile: Joi.object({
    firstName: name.optional(),
    lastName: name.optional(),
    email: email.optional(),
    phone: phone.optional(),
    address: Joi.object({
      street: Joi.string().max(100).optional(),
      city: Joi.string().max(50).optional(),
      state: Joi.string().length(2).optional(),
      zipCode: Joi.string().pattern(/^\d{5}(-\d{4})?$/).optional(),
      country: Joi.string().max(50).optional(),
    }).optional(),
    dateOfBirth: Joi.date().max('now').optional(),
    language: Joi.string().valid('en', 'es', 'fr', 'zh').default('en').optional(),
    notifications: Joi.object({
      email: Joi.boolean().default(true).optional(),
      sms: Joi.boolean().default(false).optional(),
      push: Joi.boolean().default(true).optional(),
    }).optional(),
  }),

  changePassword: Joi.object({
    currentPassword: Joi.string().required(),
    newPassword: password.required(),
    confirmPassword: Joi.string().valid(Joi.ref('newPassword')).required()
      .messages({ 'any.only': 'Passwords do not match' }),
  }),

  createUser: Joi.object({
    firstName: name.required(),
    lastName: name.required(),
    email: email.required(),
    password: password.required(),
    phone: phone.optional(),
    role: Joi.string().valid('client', 'lawyer', 'admin').required(),
    status: Joi.string().valid('active', 'inactive', 'pending').default('pending').optional(),
  }),

  updateUser: Joi.object({
    firstName: name.optional(),
    lastName: name.optional(),
    email: email.optional(),
    phone: phone.optional(),
    role: Joi.string().valid('client', 'lawyer', 'admin').optional(),
    status: Joi.string().valid('active', 'inactive', 'pending').optional(),
  }),
};

// Case route validation schemas
const caseSchemas = {
  createCase: Joi.object({
    title: Joi.string().min(5).max(100).required(),
    caseType: Joi.string().valid(
      'asylum', 'family-based', 'employment-based', 'naturalization', 
      'removal-defense', 'visa-application', 'other'
    ).required(),
    description: Joi.string().max(1000).optional(),
    clientId: objectId.optional(),
    assignedLawyer: objectId.optional(),
    priority: Joi.string().valid('low', 'medium', 'high', 'urgent').default('medium').optional(),
    dueDate: Joi.date().min('now').optional(),
    uscisNumber: Joi.string().pattern(/^[A-Z]{3}[0-9]{10}$/).optional()
      .messages({ 'string.pattern.base': 'USCIS number must be in format ABC1234567890' }),
  }),

  updateCase: Joi.object({
    title: Joi.string().min(5).max(100).optional(),
    caseType: Joi.string().valid(
      'asylum', 'family-based', 'employment-based', 'naturalization', 
      'removal-defense', 'visa-application', 'other'
    ).optional(),
    description: Joi.string().max(1000).optional(),
    status: Joi.string().valid(
      'open', 'in-progress', 'pending-review', 
      'pending-client', 'pending-uscis', 'closed', 'archived'
    ).optional(),
    assignedLawyer: objectId.optional(),
    priority: Joi.string().valid('low', 'medium', 'high', 'urgent').optional(),
    dueDate: Joi.date().min('now').optional(),
    uscisNumber: Joi.string().pattern(/^[A-Z]{3}[0-9]{10}$/).optional()
      .messages({ 'string.pattern.base': 'USCIS number must be in format ABC1234567890' }),
  }),

  addComment: Joi.object({
    content: Joi.string().min(1).max(1000).required(),
    isInternal: Joi.boolean().default(false).optional(),
  }),

  updateStatus: Joi.object({
    status: Joi.string().valid(
      'open', 'in-progress', 'pending-review', 
      'pending-client', 'pending-uscis', 'closed', 'archived'
    ).required(),
    notes: Joi.string().max(500).optional(),
  }),
};

// Document route validation schemas
const documentSchemas = {
  uploadDocument: Joi.object({
    title: Joi.string().min(3).max(100).required(),
    description: Joi.string().max(500).optional(),
    caseId: objectId.required(),
    documentType: Joi.string().valid(
      'identification', 'application', 'evidence', 'form', 
      'legal', 'communication', 'personal', 'other'
    ).required(),
    isConfidential: Joi.boolean().default(false).optional(),
    expirationDate: Joi.date().min('now').optional(),
  }),

  updateDocument: Joi.object({
    title: Joi.string().min(3).max(100).optional(),
    description: Joi.string().max(500).optional(),
    documentType: Joi.string().valid(
      'identification', 'application', 'evidence', 'form', 
      'legal', 'communication', 'personal', 'other'
    ).optional(),
    isConfidential: Joi.boolean().optional(),
    status: Joi.string().valid(
      'pending', 'approved', 'rejected', 'requires-update'
    ).optional(),
    expirationDate: Joi.date().min('now').optional(),
  }),
  
  shareDocument: Joi.object({
    userIds: Joi.array().items(objectId).min(1).required(),
    expirationDate: Joi.date().min('now').optional(),
    permission: Joi.string().valid('view', 'comment', 'edit').default('view').required(),
    message: Joi.string().max(500).optional(),
  }),
};

// Param validation schemas
const paramSchemas = {
  userId: Joi.object({
    userId: objectId.required(),
  }),
  
  caseId: Joi.object({
    caseId: objectId.required(),
  }),
  
  documentId: Joi.object({
    documentId: objectId.required(),
  }),
  
  commentId: Joi.object({
    commentId: objectId.required(),
  }),
  
  token: Joi.object({
    token: Joi.string().required(),
  }),
};

// Query validation schemas
const querySchemas = {
  pagination: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(10),
    sortBy: Joi.string().optional(),
    order: Joi.string().valid('asc', 'desc').default('desc'),
  }),
  
  caseFilter: Joi.object({
    status: Joi.string().valid(
      'all', 'open', 'in-progress', 'pending-review', 
      'pending-client', 'pending-uscis', 'closed', 'archived'
    ).default('all'),
    priority: Joi.string().valid('all', 'low', 'medium', 'high', 'urgent').default('all'),
    caseType: Joi.string().optional(),
    assignedLawyer: Joi.string().optional(),
    client: Joi.string().optional(),
    search: Joi.string().optional(),
    dateFrom: Joi.date().optional(),
    dateTo: Joi.date().min(Joi.ref('dateFrom')).optional(),
  }).unknown(true),
  
  documentFilter: Joi.object({
    status: Joi.string().valid(
      'all', 'pending', 'approved', 'rejected', 'requires-update'
    ).default('all'),
    documentType: Joi.string().optional(),
    search: Joi.string().optional(),
    dateFrom: Joi.date().optional(),
    dateTo: Joi.date().min(Joi.ref('dateFrom')).optional(),
  }).unknown(true),
  
  userFilter: Joi.object({
    role: Joi.string().valid('all', 'client', 'lawyer', 'admin').default('all'),
    status: Joi.string().valid('all', 'active', 'inactive', 'pending').default('all'),
    search: Joi.string().optional(),
  }).unknown(true),
};

// Custom validation rules
const customValidation = {
  atLeastOne: (schema, fields) => {
    return schema.custom((object, helpers) => {
      const presentFields = fields.filter(field => object[field] !== undefined);
      if (presentFields.length === 0) {
        return helpers.error('object.atLeastOne', { fields });
      }
      return object;
    }, 'At least one field must be provided');
  },
  
  conditionalRequire: (schema, field, condition) => {
    return schema.custom((object, helpers) => {
      if (condition(object) && !object[field]) {
        return helpers.error('any.required', { field });
      }
      return object;
    }, `Field ${field} is required based on other fields`);
  },
  
  xor: (schema, fields) => {
    return schema.custom((object, helpers) => {
      const presentFields = fields.filter(field => object[field] !== undefined);
      if (presentFields.length !== 1) {
        return helpers.error('object.xor', { fields });
      }
      return object;
    }, 'Exactly one field must be provided');
  },
};

// Validation middleware factory
const validate = (schema, property = 'body') => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req[property], {
      abortEarly: false,
      stripUnknown: true,
      errors: {
        wrap: {
          label: false,
        },
      },
    });

    if (error) {
      const errorMessage = error.details.map(detail => detail.message).join(', ');
      return next(new ApiError(400, errorMessage));
    }

    // Replace the request object with the validated value
    req[property] = value;
    return next();
  };
};

module.exports = {
  validate,
  authSchemas,
  userSchemas,
  caseSchemas,
  documentSchemas,
  paramSchemas,
  querySchemas,
  customValidation,
};

