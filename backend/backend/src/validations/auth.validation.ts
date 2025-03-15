import Joi from 'joi';

export const registerSchema = Joi.object({
  firstName: Joi.string().required().min(2).max(50),
  lastName: Joi.string().required().min(2).max(50),
  email: Joi.string().email().required(),
  password: Joi.string()
    .required()
    .min(8)
    .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])'))
    .message('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
  role: Joi.string().valid('admin', 'lawyer', 'staff', 'client').required(),
  phone: Joi.string().pattern(/^\+?[\d\s-]+$/).optional(),
  address: Joi.object({
    street: Joi.string().optional(),
    city: Joi.string().optional(),
    state: Joi.string().optional(),
    zipCode: Joi.string().optional(),
    country: Joi.string().optional(),
  }).optional(),
});

export const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});

