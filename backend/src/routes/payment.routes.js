const express = require('express');
const router = express.Router();
const { authenticate } = require('../middleware/auth.middleware');
const { validateRequest } = require('../middleware/validate.middleware');
const { paymentController } = require('../controllers/payment.controller');
const { rateLimit } = require('../middleware/rateLimit.middleware');
const { checkRole } = require('../middleware/auth.middleware');

/**
 * @route   GET /api/payment/plans
 * @desc    Get all subscription plans
 * @access  Public
 */
router.get('/plans', rateLimit('standard'), paymentController.getSubscriptionPlans);

/**
 * @route   GET /api/payment/plan/:id
 * @desc    Get a subscription plan by ID
 * @access  Public
 */
router.get('/plan/:id', rateLimit('standard'), validateRequest('params', 'planId'), paymentController.getSubscriptionPlan);

/**
 * @route   POST /api/payment/create-subscription
 * @desc    Create a new subscription
 * @access  Private
 */
router.post(
  '/create-subscription',
  authenticate,
  rateLimit('payment'),
  validateRequest('body', 'createSubscription'),
  paymentController.createSubscription
);

/**
 * @route   POST /api/payment/cancel-subscription
 * @desc    Cancel an existing subscription
 * @access  Private
 */
router.post(
  '/cancel-subscription',
  authenticate,
  rateLimit('payment'),
  validateRequest('body', 'subscriptionId'),
  paymentController.cancelSubscription
);

/**
 * @route   PUT /api/payment/update-subscription
 * @desc    Update subscription (change plan, payment method, etc.)
 * @access  Private
 */
router.put(
  '/update-subscription',
  authenticate,
  rateLimit('payment'),
  validateRequest('body', 'updateSubscription'),
  paymentController.updateSubscription
);

/**
 * @route   POST /api/payment/create-payment-intent
 * @desc    Create a payment intent (for one-time payments)
 * @access  Private
 */
router.post(
  '/create-payment-intent',
  authenticate,
  rateLimit('payment'),
  validateRequest('body', 'createPaymentIntent'),
  paymentController.createPaymentIntent
);

/**
 * @route   POST /api/payment/methods
 * @desc    Add a new payment method
 * @access  Private
 */
router.post(
  '/methods',
  authenticate,
  rateLimit('payment'),
  validateRequest('body', 'addPaymentMethod'),
  paymentController.addPaymentMethod
);

/**
 * @route   GET /api/payment/methods
 * @desc    Get all payment methods for a user
 * @access  Private
 */
router.get('/methods', authenticate, rateLimit('standard'), paymentController.getPaymentMethods);

/**
 * @route   DELETE /api/payment/methods/:id
 * @desc    Delete a payment method
 * @access  Private
 */
router.delete(
  '/methods/:id',
  authenticate,
  rateLimit('standard'),
  validateRequest('params', 'paymentMethodId'),
  paymentController.deletePaymentMethod
);

/**
 * @route   GET /api/payment/invoices
 * @desc    Get all invoices for a user
 * @access  Private
 */
router.get('/invoices', authenticate, rateLimit('standard'), paymentController.getInvoices);

/**
 * @route   GET /api/payment/invoices/:id
 * @desc    Get an invoice by ID
 * @access  Private
 */
router.get(
  '/invoices/:id',
  authenticate,
  rateLimit('standard'),
  validateRequest('params', 'invoiceId'),
  paymentController.getInvoice
);

/**
 * @route   GET /api/payment/history
 * @desc    Get payment history for a user
 * @access  Private
 */
router.get('/history', authenticate, rateLimit('standard'), paymentController.getPaymentHistory);

/**
 * @route   POST /api/payment/webhooks
 * @desc    Handle Stripe webhook events
 * @access  Public (but secured by Stripe signature)
 */
router.post('/webhooks', express.raw({ type: 'application/json' }), paymentController.handleWebhook);

/**
 * Admin Routes
 */

/**
 * @route   POST /api/payment/plans
 * @desc    Create a new subscription plan
 * @access  Admin
 */
router.post(
  '/plans',
  authenticate,
  checkRole(['admin']),
  validateRequest('body', 'createPlan'),
  paymentController.createSubscriptionPlan
);

/**
 * @route   PUT /api/payment/plans/:id
 * @desc    Update a subscription plan
 * @access  Admin
 */
router.put(
  '/plans/:id',
  authenticate,
  checkRole(['admin']),
  validateRequest('body', 'updatePlan'),
  validateRequest('params', 'planId'),
  paymentController.updateSubscriptionPlan
);

/**
 * @route   DELETE /api/payment/plans/:id
 * @desc    Delete a subscription plan
 * @access  Admin
 */
router.delete(
  '/plans/:id',
  authenticate,
  checkRole(['admin']),
  validateRequest('params', 'planId'),
  paymentController.deleteSubscriptionPlan
);

/**
 * @route   GET /api/payment/admin/invoices
 * @desc    Get all invoices (admin view)
 * @access  Admin
 */
router.get('/admin/invoices', authenticate, checkRole(['admin']), paymentController.getAllInvoices);

/**
 * @route   GET /api/payment/admin/subscriptions
 * @desc    Get all subscriptions (admin view)
 * @access  Admin
 */
router.get('/admin/subscriptions', authenticate, checkRole(['admin']), paymentController.getAllSubscriptions);

module.exports = router;

