const express = require('express');
const router = express.Router();
const { authMiddleware } = require('../middleware/auth.middleware');
const { validate } = require('../middleware/validate.middleware');
const { rateLimiter } = require('../middleware/rateLimit.middleware');
const notificationController = require('../controllers/notification.controller');
const notificationValidation = require('../validations/notification.validation');

/**
 * @route   GET /api/notifications
 * @desc    Get all notifications for the current user
 * @access  Private
 */
router.get(
  '/',
  authMiddleware,
  rateLimiter.standard,
  notificationController.getUserNotifications
);

/**
 * @route   GET /api/notifications/unread
 * @desc    Get unread notifications for the current user
 * @access  Private
 */
router.get(
  '/unread',
  authMiddleware,
  rateLimiter.standard,
  notificationController.getUnreadNotifications
);

/**
 * @route   GET /api/notifications/:id
 * @desc    Get a specific notification by ID
 * @access  Private
 */
router.get(
  '/:id',
  authMiddleware,
  validate(notificationValidation.getNotification),
  rateLimiter.standard,
  notificationController.getNotificationById
);

/**
 * @route   POST /api/notifications/preferences
 * @desc    Update notification preferences
 * @access  Private
 */
router.post(
  '/preferences',
  authMiddleware,
  validate(notificationValidation.updatePreferences),
  rateLimiter.standard,
  notificationController.updateNotificationPreferences
);

/**
 * @route   GET /api/notifications/preferences
 * @desc    Get notification preferences
 * @access  Private
 */
router.get(
  '/preferences',
  authMiddleware,
  rateLimiter.standard,
  notificationController.getNotificationPreferences
);

/**
 * @route   POST /api/notifications/:id/read
 * @desc    Mark a notification as read
 * @access  Private
 */
router.post(
  '/:id/read',
  authMiddleware,
  validate(notificationValidation.markNotification),
  rateLimiter.standard,
  notificationController.markNotificationAsRead
);

/**
 * @route   POST /api/notifications/read-all
 * @desc    Mark all notifications as read
 * @access  Private
 */
router.post(
  '/read-all',
  authMiddleware,
  rateLimiter.standard,
  notificationController.markAllNotificationsAsRead
);

/**
 * @route   DELETE /api/notifications/:id
 * @desc    Delete a notification
 * @access  Private
 */
router.delete(
  '/:id',
  authMiddleware,
  validate(notificationValidation.deleteNotification),
  rateLimiter.standard,
  notificationController.deleteNotification
);

/**
 * @route   DELETE /api/notifications
 * @desc    Delete all notifications (or batch delete)
 * @access  Private
 */
router.delete(
  '/',
  authMiddleware,
  validate(notificationValidation.batchDeleteNotifications),
  rateLimiter.standard,
  notificationController.deleteNotifications
);

/**
 * @route   POST /api/notifications/subscribe
 * @desc    Subscribe to real-time notifications
 * @access  Private
 */
router.post(
  '/subscribe',
  authMiddleware,
  validate(notificationValidation.subscribeNotifications),
  rateLimiter.standard,
  notificationController.subscribeToNotifications
);

/**
 * @route   POST /api/notifications/unsubscribe
 * @desc    Unsubscribe from real-time notifications
 * @access  Private
 */
router.post(
  '/unsubscribe',
  authMiddleware,
  validate(notificationValidation.unsubscribeNotifications),
  rateLimiter.standard,
  notificationController.unsubscribeFromNotifications
);

/**
 * @route   POST /api/notifications/email-settings
 * @desc    Update email notification settings
 * @access  Private
 */
router.post(
  '/email-settings',
  authMiddleware,
  validate(notificationValidation.updateEmailSettings),
  rateLimiter.standard,
  notificationController.updateEmailNotificationSettings
);

/**
 * @route   GET /api/notifications/email-settings
 * @desc    Get email notification settings
 * @access  Private
 */
router.get(
  '/email-settings',
  authMiddleware,
  rateLimiter.standard,
  notificationController.getEmailNotificationSettings
);

/**
 * @route   POST /api/notifications/test-email
 * @desc    Send a test email notification
 * @access  Private
 */
router.post(
  '/test-email',
  authMiddleware,
  validate(notificationValidation.testEmail),
  rateLimiter.strict,
  notificationController.sendTestEmailNotification
);

/**
 * @route   POST /api/notifications/batch
 * @desc    Process batch notification operations
 * @access  Private (Admin only)
 */
router.post(
  '/batch',
  authMiddleware,
  validate(notificationValidation.batchOperations),
  rateLimiter.strict,
  notificationController.processBatchNotifications
);

/**
 * @route   GET /api/notifications/types
 * @desc    Get all available notification types
 * @access  Private
 */
router.get(
  '/types',
  authMiddleware,
  rateLimiter.standard,
  notificationController.getNotificationTypes
);

module.exports = router;

