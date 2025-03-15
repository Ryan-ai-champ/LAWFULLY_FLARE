import Joi from 'joi';

export const createCaseSchema = Joi.object({
  client: Joi.string().required(),
  assignedLawyer: Joi.string().required(),
  caseType: Joi.string().required(),
  status: Joi.string().valid('new', 'in-progress', 'pending', 'completed', 'cancelled'),
  priority: Joi.string().valid('low', 'medium', 'high'),
  description: Joi.string().required(),
  documents: Joi.array().items(
    Joi.object({
      name: Joi.string().required(),
      type: Joi.string().required(),
      url: Joi.string().required(),
      uploadedBy: Joi.string().required(),
      uploadedAt: Joi.date().default(Date.now),
    })
  ),
  notes: Joi.array().items(
    Joi.object({
      content: Joi.string().required(),
      createdBy: Joi.string().required(),
      createdAt: Joi.date().default(Date.now),
    })
  ),
  deadlines: Joi.array().items(
    Joi.object({
      title: Joi.string().required(),
      date: Joi.date().required(),
      description: Joi.string(),
      completed: Joi.boolean().default(false),
    })
  ),
});

export const updateCaseSchema = Joi.object({
  status: Joi.string().valid('new', 'in-progress', 'pending', 'completed', 'cancelled'),
  priority: Joi.string().valid('low', 'medium', 'high'),
  description: Joi.string(),
  documents: Joi.array().items(
    Joi.object({
      name: Joi.string().required(),
      type: Joi.string().required(),
      url: Joi.string().required(),
      uploadedBy: Joi.string().required(),
      uploadedAt: Joi.date().default(Date.now),
    })
  ),
  notes: Joi.array().items(
    Joi.object({
      content: Joi.string().required(),
      createdBy: Joi.string().required(),
      createdAt: Joi.date().default(Date.now),
    })
  ),
  deadlines: Joi.array().items(
    Joi.object({
      title: Joi.string().required(),
      date: Joi.date().required(),
      description: Joi.string(),
      completed: Joi.boolean(),
    })
  ),
}).min(1);

