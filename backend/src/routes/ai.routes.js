const express = require('express');
const router = express.Router();
const { authMiddleware, roleMiddleware } = require('../middleware/auth.middleware');
const { validate } = require('../middleware/validate.middleware');
const rateLimitMiddleware = require('../middleware/rateLimit.middleware');
const aiController = require('../controllers/ai.controller');
const aiValidation = require('../validations/ai.validation');

// Apply rate limiting to all AI routes
router.use(rateLimitMiddleware({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 25, // limit each IP to 25 requests per windowMs
  message: 'Too many AI requests, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
}));

/**
 * @route   POST /api/ai/document-analysis
 * @desc    Analyze legal documents and extract key information
 * @access  Private
 */
router.post(
  '/document-analysis',
  authMiddleware,
  validate(aiValidation.documentAnalysis),
  aiController.analyzeDocument
);

/**
 * @route   POST /api/ai/case-recommendations
 * @desc    Get recommendations for an immigration case
 * @access  Private
 */
router.post(
  '/case-recommendations',
  authMiddleware,
  validate(aiValidation.caseRecommendations),
  aiController.getCaseRecommendations
);

/**
 * @route   POST /api/ai/generate-response
 * @desc    Generate automated responses for client communications
 * @access  Private
 */
router.post(
  '/generate-response',
  authMiddleware,
  validate(aiValidation.generateResponse),
  aiController.generateResponse
);

/**
 * @route   POST /api/ai/legal-research
 * @desc    Research legal precedents and information
 * @access  Private
 */
router.post(
  '/legal-research',
  authMiddleware,
  validate(aiValidation.legalResearch),
  aiController.conductLegalResearch
);

/**
 * @route   POST /api/ai/form-completion
 * @desc    AI-assisted form completion for immigration forms
 * @access  Private
 */
router.post(
  '/form-completion',
  authMiddleware,
  validate(aiValidation.formCompletion),
  aiController.completeForm
);

/**
 * @route   GET /api/ai/usage
 * @desc    Get AI feature usage statistics for the current user
 * @access  Private
 */
router.get(
  '/usage',
  authMiddleware,
  aiController.getUsageStats
);

/**
 * @route   GET /api/ai/models
 * @desc    Get available AI models and their capabilities
 * @access  Private
 */
router.get(
  '/models',
  authMiddleware,
  aiController.getAvailableModels
);

/**
 * @route   POST /api/ai/feedback
 * @desc    Submit feedback on AI-generated content
 * @access  Private
 */
router.post(
  '/feedback',
  authMiddleware,
  validate(aiValidation.feedback),
  aiController.submitFeedback
);

module.exports = router;

