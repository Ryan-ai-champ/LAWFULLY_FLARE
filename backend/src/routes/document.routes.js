const express = require('express');
const router = express.Router();
const { authenticate } = require('../middleware/auth.middleware');
const { validateDocument, validateDocumentUpdate } = require('../middleware/validate.middleware');
const { upload, fileFilter } = require('../middleware/upload.middleware');
const { documentController } = require('../controllers/document.controller');
const { checkDocumentPermission } = require('../middleware/permission.middleware');
const rateLimit = require('../middleware/rateLimit.middleware');

/**
 * @route POST /api/documents
 * @description Upload a new document
 * @access Private
 */
router.post(
  '/',
  authenticate,
  upload.single('document'),
  fileFilter(['pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png']),
  validateDocument,
  rateLimit.documentUpload,
  documentController.uploadDocument
);

/**
 * @route GET /api/documents
 * @description Get all documents for the authenticated user
 * @access Private
 */
router.get(
  '/',
  authenticate,
  rateLimit.standard,
  documentController.getDocuments
);

/**
 * @route GET /api/documents/:id
 * @description Get a specific document by ID
 * @access Private (with permission check)
 */
router.get(
  '/:id',
  authenticate,
  checkDocumentPermission('read'),
  rateLimit.standard,
  documentController.getDocumentById
);

/**
 * @route GET /api/documents/:id/download
 * @description Download a specific document
 * @access Private (with permission check)
 */
router.get(
  '/:id/download',
  authenticate,
  checkDocumentPermission('read'),
  rateLimit.documentDownload,
  documentController.downloadDocument
);

/**
 * @route PUT /api/documents/:id
 * @description Update document metadata
 * @access Private (with permission check)
 */
router.put(
  '/:id',
  authenticate,
  checkDocumentPermission('update'),
  validateDocumentUpdate,
  rateLimit.standard,
  documentController.updateDocument
);

/**
 * @route DELETE /api/documents/:id
 * @description Delete a document
 * @access Private (with permission check)
 */
router.delete(
  '/:id',
  authenticate,
  checkDocumentPermission('delete'),
  rateLimit.standard,
  documentController.deleteDocument
);

/**
 * @route POST /api/documents/:id/share
 * @description Share a document with other users
 * @access Private (with permission check)
 */
router.post(
  '/:id/share',
  authenticate,
  checkDocumentPermission('share'),
  validateDocument.shareValidation,
  rateLimit.standard,
  documentController.shareDocument
);

/**
 * @route GET /api/documents/:id/permissions
 * @description Get all permissions for a document
 * @access Private (with permission check)
 */
router.get(
  '/:id/permissions',
  authenticate,
  checkDocumentPermission('manage'),
  rateLimit.standard,
  documentController.getDocumentPermissions
);

/**
 * @route PUT /api/documents/:id/permissions/:userId
 * @description Update permissions for a user on a document
 * @access Private (with permission check)
 */
router.put(
  '/:id/permissions/:userId',
  authenticate,
  checkDocumentPermission('manage'),
  validateDocument.permissionValidation,
  rateLimit.standard,
  documentController.updateDocumentPermission
);

/**
 * @route DELETE /api/documents/:id/permissions/:userId
 * @description Remove a user's permissions for a document
 * @access Private (with permission check)
 */
router.delete(
  '/:id/permissions/:userId',
  authenticate,
  checkDocumentPermission('manage'),
  rateLimit.standard,
  documentController.removeDocumentPermission
);

/**
 * @route POST /api/documents/:id/version
 * @description Upload a new version of a document
 * @access Private (with permission check)
 */
router.post(
  '/:id/version',
  authenticate,
  checkDocumentPermission('update'),
  upload.single('document'),
  fileFilter(['pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png']),
  rateLimit.documentUpload,
  documentController.uploadNewVersion
);

/**
 * @route GET /api/documents/:id/versions
 * @description Get all versions of a document
 * @access Private (with permission check)
 */
router.get(
  '/:id/versions',
  authenticate,
  checkDocumentPermission('read'),
  rateLimit.standard,
  documentController.getDocumentVersions
);

/**
 * @route GET /api/documents/:id/versions/:versionId
 * @description Get a specific version of a document
 * @access Private (with permission check)
 */
router.get(
  '/:id/versions/:versionId',
  authenticate,
  checkDocumentPermission('read'),
  rateLimit.standard,
  documentController.getDocumentVersion
);

/**
 * @route PUT /api/documents/:id/category
 * @description Update document category
 * @access Private (with permission check)
 */
router.put(
  '/:id/category',
  authenticate,
  checkDocumentPermission('update'),
  validateDocument.categoryValidation,
  rateLimit.standard,
  documentController.updateDocumentCategory
);

/**
 * @route PUT /api/documents/:id/metadata
 * @description Update document metadata
 * @access Private (with permission check)
 */
router.put(
  '/:id/metadata',
  authenticate,
  checkDocumentPermission('update'),
  validateDocument.metadataValidation,
  rateLimit.standard,
  documentController.updateDocumentMetadata
);

/**
 * @route GET /api/documents/search
 * @description Search documents based on various parameters
 * @access Private
 */
router.get(
  '/search',
  authenticate,
  rateLimit.search,
  documentController.searchDocuments
);

/**
 * @route GET /api/documents/categories
 * @description Get all document categories
 * @access Private
 */
router.get(
  '/categories',
  authenticate,
  rateLimit.standard,
  documentController.getDocumentCategories
);

/**
 * @route POST /api/documents/categories
 * @description Create a new document category
 * @access Private (admin only)
 */
router.post(
  '/categories',
  authenticate,
  checkDocumentPermission('admin'),
  validateDocument.categoryCreationValidation,
  rateLimit.standard,
  documentController.createDocumentCategory
);

module.exports = router;

