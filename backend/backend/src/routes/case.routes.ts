import express from 'express';
import {
  getCases,
  getCase,
  createCase,
  updateCase,
  deleteCase,
} from '../controllers/case.controller';
import { protect, authorize } from '../middleware/auth.middleware';
import { validate } from '../middleware/validate.middleware';
import { createCaseSchema, updateCaseSchema } from '../validations/case.validation';

const router = express.Router();

router.use(protect); // All case routes require authentication

router
  .route('/')
  .get(getCases)
  .post(
    authorize('admin', 'lawyer', 'staff'),
    validate(createCaseSchema),
    createCase
  );

router
  .route('/:id')
  .get(getCase)
  .put(
    authorize('admin', 'lawyer', 'staff'),
    validate(updateCaseSchema),
    updateCase
  )
  .delete(authorize('admin'), deleteCase);

export default router;

