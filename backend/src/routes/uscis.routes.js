const express = require('express');
const router = express.Router();
const { auth } = require('../middleware/auth.middleware');
const { validate } = require('../middleware/validate.middleware');
const { rateLimiter, apiLimiter } = require('../middleware/rateLimit.middleware');
const cacheMiddleware = require('../middleware/cache.middleware');
const uscisController = require('../controllers/uscis.controller');

/**
 * @route   GET /api/uscis/case/:receiptNumber
 * @desc    Check status of a USCIS case
 * @access  Private
 */
router.get(
  '/case/:receiptNumber',
  auth('user'),
  validate('uscis.caseStatus'),
  cacheMiddleware(300), // Cache for 5 minutes
  rateLimiter({ windowMs: 60 * 1000, max: 5 }), // 5 requests per minute
  uscisController.checkCaseStatus
);

/**
 * @route   GET /api/uscis/cases
 * @desc    Get all user's tracked cases
 * @access  Private
 */
router.get(
  '/cases',
  auth('user'),
  uscisController.getUserCases
);

/**
 * @route   POST /api/uscis/case/track
 * @desc    Add a case to track
 * @access  Private
 */
router.post(
  '/case/track',
  auth('user'),
  validate('uscis.trackCase'),
  uscisController.trackCase
);

/**
 * @route   DELETE /api/uscis/case/:receiptNumber
 * @desc    Stop tracking a case
 * @access  Private
 */
router.delete(
  '/case/:receiptNumber',
  auth('user'),
  validate('uscis.receiptNumber'),
  uscisController.stopTrackingCase
);

/**
 * @route   POST /api/uscis/forms/submit
 * @desc    Submit a form to USCIS
 * @access  Private
 */
router.post(
  '/forms/submit',
  auth('user'),
  validate('uscis.formSubmission'),
  apiLimiter,
  uscisController.submitForm
);

/**
 * @route   GET /api/uscis/forms/:formNumber
 * @desc    Get a specific USCIS form
 * @access  Private
 */
router.get(
  '/forms/:formNumber',
  auth('user'),
  validate('uscis.formNumber'),
  cacheMiddleware(60 * 60), // Cache for 1 hour
  uscisController.getForm
);

/**
 * @route   GET /api/uscis/forms
 * @desc    Get all available USCIS forms
 * @access  Private
 */
router.get(
  '/forms',
  auth('user'),
  cacheMiddleware(60 * 60 * 24), // Cache for 1 day
  uscisController.getAllForms
);

/**
 * @route   POST /api/uscis/webhook
 * @desc    Webhook for USCIS updates
 * @access  Public (secured by webhook secret)
 */
router.post(
  '/webhook',
  validate('uscis.webhook'),
  uscisController.handleWebhook
);

/**
 * @route   POST /api/uscis/verify/document
 * @desc    Verify a USCIS document
 * @access  Private
 */
router.post(
  '/verify/document',
  auth('user'),
  validate('uscis.documentVerification'),
  rateLimiter({ windowMs: 60 * 60 * 1000, max: 10 }), // 10 requests per hour
  uscisController.verifyDocument
);

/**
 * @route   GET /api/uscis/application/:applicationId/status
 * @desc    Get detailed application status
 * @access  Private
 */
router.get(
  '/application/:applicationId/status',
  auth('user'),
  validate('uscis.applicationId'),
  cacheMiddleware(300), // Cache for 5 minutes
  uscisController.getApplicationStatus
);

/**
 * @route   GET /api/uscis/updates/:receiptNumber
 * @desc    Get historical updates for a case
 * @access  Private
 */
router.get(
  '/updates/:receiptNumber',
  auth('user'),
  validate('uscis.receiptNumber'),
  uscisController.getCaseUpdates
);

/**
 * @route   POST /api/uscis/notifications/subscribe
 * @desc    Subscribe to notifications for a case
 * @access  Private
 */
router.post(
  '/notifications/subscribe',
  auth('user'),
  validate('uscis.notificationSubscription'),
  uscisController.subscribeToNotifications
);

/**
 * @route   DELETE /api/uscis/notifications/unsubscribe/:receiptNumber
 * @desc    Unsubscribe from notifications for a case
 * @access  Private
 */
router.delete(
  '/notifications/unsubscribe/:receiptNumber',
  auth('user'),
  validate('uscis.receiptNumber'),
  uscisController.unsubscribeFromNotifications
);

module.exports = router;

