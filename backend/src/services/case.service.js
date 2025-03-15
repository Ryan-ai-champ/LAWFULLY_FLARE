const mongoose = require('mongoose');
const Case = require('../models/case.model');
const Document = require('../models/document.model');
const Timeline = require('../models/timeline.model');
const ApiError = require('../utils/ApiError');
const logger = require('../utils/logger');

/**
 * Case Service - Handles all business logic for immigration cases
 * Implements singleton pattern
 */
class CaseService {
  constructor() {
    if (CaseService.instance) {
      return CaseService.instance;
    }
    CaseService.instance = this;
  }

  /**
   * Create a new immigration case
   * @param {Object} caseData - Case details
   * @returns {Promise<Object>} Created case
   */
  async createCase(caseData) {
    try {
      const newCase = new Case({
        ...caseData,
        status: caseData.status || 'pending',
        createdAt: new Date(),
        updatedAt: new Date()
      });

      const savedCase = await newCase.save();
      
      // Create initial timeline entry
      await this.addTimelineEntry(savedCase._id, {
        action: 'Case Created',
        description: 'New immigration case was created',
        performedBy: caseData.createdBy
      });

      logger.info(`Case created: ${savedCase._id}`);
      return savedCase;
    } catch (error) {
      logger.error(`Error creating case: ${error.message}`);
      throw new ApiError(error.statusCode || 500, `Failed to create case: ${error.message}`);
    }
  }

  /**
   * Get case by ID
   * @param {string} caseId - Case ID
   * @returns {Promise<Object>} Case object
   */
  async getCaseById(caseId) {
    try {
      const caseRecord = await Case.findById(caseId)
        .populate('assignedTo', 'firstName lastName email')
        .populate('client', 'firstName lastName email phone')
        .exec();

      if (!caseRecord) {
        throw new ApiError(404, 'Case not found');
      }

      return caseRecord;
    } catch (error) {
      logger.error(`Error getting case ${caseId}: ${error.message}`);
      if (error instanceof ApiError) {
        throw error;
      }
      throw new ApiError(error.statusCode || 500, `Failed to get case: ${error.message}`);
    }
  }

  /**
   * Get all cases with optional filtering
   * @param {Object} filters - Filters for cases
   * @param {Object} options - Pagination and sorting options
   * @returns {Promise<Array>} Array of case objects
   */
  async getCases(filters = {}, options = { limit: 10, page: 1, sortBy: 'updatedAt:desc' }) {
    try {
      const { limit, page, sortBy } = options;
      const skip = (page - 1) * limit;

      const [sortField, sortOrder] = sortBy.split(':');
      const sort = { [sortField]: sortOrder === 'desc' ? -1 : 1 };

      // Build query based on filters
      const query = {};
      if (filters.status) query.status = filters.status;
      if (filters.assignedTo) query.assignedTo = filters.assignedTo;
      if (filters.clientId) query.client = filters.clientId;
      if (filters.caseType) query.caseType = filters.caseType;
      if (filters.dateRange) {
        query.createdAt = {
          $gte: new Date(filters.dateRange.start),
          $lte: new Date(filters.dateRange.end)
        };
      }

      const cases = await Case.find(query)
        .populate('assignedTo', 'firstName lastName email')
        .populate('client', 'firstName lastName email')
        .sort(sort)
        .limit(limit)
        .skip(skip)
        .exec();

      const total = await Case.countDocuments(query);

      return {
        results: cases,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
        totalResults: total
      };
    } catch (error) {
      logger.error(`Error getting cases: ${error.message}`);
      throw new ApiError(error.statusCode || 500, `Failed to get cases: ${error.message}`);
    }
  }

  /**
   * Update a case
   * @param {string} caseId - Case ID
   * @param {Object} updateData - Case data to update
   * @param {string} updatedBy - User ID of updater
   * @returns {Promise<Object>} Updated case
   */
  async updateCase(caseId, updateData, updatedBy) {
    try {
      const caseRecord = await Case.findById(caseId);
      
      if (!caseRecord) {
        throw new ApiError(404, 'Case not found');
      }

      // Track changes for timeline
      const changes = [];
      for (const [key, value] of Object.entries(updateData)) {
        if (JSON.stringify(caseRecord[key]) !== JSON.stringify(value)) {
          changes.push({
            field: key,
            oldValue: caseRecord[key],
            newValue: value
          });
        }
      }
      
      // Add updated timestamp
      updateData.updatedAt = new Date();
      
      const updatedCase = await Case.findByIdAndUpdate(
        caseId,
        { $set: updateData },
        { new: true, runValidators: true }
      ).populate('assignedTo', 'firstName lastName email')
       .populate('client', 'firstName lastName email');

      // Add timeline entry for the update
      if (changes.length > 0) {
        await this.addTimelineEntry(caseId, {
          action: 'Case Updated',
          description: `Case information updated: ${changes.map(c => c.field).join(', ')}`,
          changes,
          performedBy: updatedBy
        });
      }

      logger.info(`Case updated: ${caseId}`);
      return updatedCase;
    } catch (error) {
      logger.error(`Error updating case ${caseId}: ${error.message}`);
      if (error instanceof ApiError) {
        throw error;
      }
      throw new ApiError(error.statusCode || 500, `Failed to update case: ${error.message}`);
    }
  }

  /**
   * Delete a case
   * @param {string} caseId - Case ID
   * @returns {Promise<boolean>} Deletion success
   */
  async deleteCase(caseId) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Check if case exists
      const caseRecord = await Case.findById(caseId);
      if (!caseRecord) {
        throw new ApiError(404, 'Case not found');
      }

      // Delete all related documents
      await Document.deleteMany({ case: caseId }, { session });
      
      // Delete all timeline entries
      await Timeline.deleteMany({ case: caseId }, { session });
      
      // Delete the case
      await Case.findByIdAndDelete(caseId, { session });
      
      await session.commitTransaction();
      logger.info(`Case deleted: ${caseId}`);
      return true;
    } catch (error) {
      await session.abortTransaction();
      logger.error(`Error deleting case ${caseId}: ${error.message}`);
      if (error instanceof ApiError) {
        throw error;
      }
      throw new ApiError(error.statusCode || 500, `Failed to delete case: ${error.message}`);
    } finally {
      session.endSession();
    }
  }

  /**
   * Assign a case to a user
   * @param {string} caseId - Case ID
   * @param {string} userId - User ID to assign the case to
   * @param {string} assignedBy - User ID of the assigner
   * @returns {Promise<Object>} Updated case
   */
  async assignCase(caseId, userId, assignedBy) {
    try {
      const caseRecord = await Case.findById(caseId);
      
      if (!caseRecord) {
        throw new ApiError(404, 'Case not found');
      }

      const previousAssignee = caseRecord.assignedTo;
      
      const updatedCase = await Case.findByIdAndUpdate(
        caseId,
        { 
          $set: { 
            assignedTo: userId,
            updatedAt: new Date()
          } 
        },
        { new: true, runValidators: true }
      ).populate('assignedTo', 'firstName lastName email')
       .populate('client', 'firstName lastName email');

      // Add timeline entry for the assignment
      await this.addTimelineEntry(caseId, {
        action: 'Case Assigned',
        description: previousAssignee 
          ? 'Case reassigned to a different user' 
          : 'Case assigned to user',
        changes: [{
          field: 'assignedTo',
          oldValue: previousAssignee,
          newValue: userId
        }],
        performedBy: assignedBy
      });

      logger.info(`Case ${caseId} assigned to user ${userId}`);
      return updatedCase;
    } catch (error) {
      logger.error(`Error assigning case ${caseId}: ${error.message}`);
      if (error instanceof ApiError) {
        throw error;
      }
      throw new ApiError(error.statusCode || 500, `Failed to assign case: ${error.message}`);
    }
  }

  /**
   * Transfer a case to another user
   * @param {string} caseId - Case ID
   * @param {string} fromUserId - Current assignee
   * @param {string} toUserId - New assignee
   * @param {string} transferredBy - User ID of the transferrer
   * @param {string} reason - Reason for transfer
   * @returns {Promise<Object>} Updated case
   */
  async transferCase(caseId, fromUserId, toUserId, transferredBy, reason) {
    try {
      const caseRecord = await Case.findById(caseId);
      
      if (!caseRecord) {
        throw new ApiError(404, 'Case not found');
      }
      
      if (caseRecord.assignedTo.toString() !== fromUserId) {
        throw new ApiError(400, 'Case is not assigned to the specified user');
      }
      
      const updatedCase = await Case.findByIdAndUpdate(
        caseId,
        { 
          $set: { 
            assignedTo: toUserId,
            updatedAt: new Date()
          } 
        },
        { new: true, runValidators: true }
      ).populate('assignedTo', 'firstName lastName email')
       .populate('client', 'firstName lastName email');

      // Add timeline entry for the transfer
      await this.addTimelineEntry(caseId, {
        action: 'Case Transferred',
        description: `Case transferred from user ${fromUserId} to user ${toUserId}`,
        changes: [{
          field: 'assignedTo',
          oldValue: fromUserId,
          newValue: toUserId
        }],
        notes: reason,
        performedBy: transferredBy
      });

      logger.info(`Case ${caseId} transferred from user ${fromUserId} to ${toUserId}`);
      return updatedCase;
    } catch (error) {
      logger.error(`Error transferring case ${caseId}: ${error.message}`);
      if (error instanceof ApiError) {
        throw error;
      }
      throw new ApiError(error.statusCode || 500, `Failed to transfer case: ${error.message}`);
    }
  }

  /**
   * Update case status
   * @param {string} caseId - Case ID
   * @param {string} status - New status
   * @param {string} updatedBy - User ID making the change
   * @param {string} notes - Optional notes about the status change
   * @returns {Promise<Object>} Updated case
   */
  async updateCaseStatus(caseId, status, updatedBy, notes = '') {
    try {
      const validStatuses = ['pending', 'in_progress', 'review', 'approved', 'rejected', 'completed', 'on_hold'];
      
      if (!validStatuses.includes(status)) {
        throw new ApiError(400, `Invalid status: ${status}. Valid statuses are: ${validStatuses.join(', ')}`);
      }
      
      const caseRecord = await Case.findById(caseId);
      
      if (!caseRecord) {
        throw new ApiError(404, 'Case not found');
      }

      const previousStatus = caseRecord.status;
      
      if (previousStatus === status) {
        return caseRecord; // No change needed
      }
      
      const updatedCase = await Case.findByIdAndUpdate(
        caseId,
        { 
          $set: { 
            status,
            updatedAt: new Date()
          } 
        },
        { new: true, runValidators: true }
      );

      // Add timeline entry for the status change
      await this.addTimelineEntry(caseId, {
        action: 'Status Changed',
        description: `Case status changed from ${previousStatus} to ${status}`,
        changes: [{
          field: 'status',
          oldValue: previousStatus,
          newValue: status
        }],
        notes,
        performedBy: updatedBy
      });

      logger.info(`Case ${caseId} status updated to ${status}`);
      return updatedCase;
    } catch (error) {
      logger.error(`Error updating case status ${caseId}: ${error.message}`);
      if (error instanceof ApiError) {
        throw error;
      }
      throw new ApiError(error.statusCode || 500, `Failed to update case status: ${error.message}`);
    }
  }

  /**
   * Add a document to a case
   * @param {string} caseId - Case ID
   * @param {Object} documentData - Document data
   * @returns {Promise<Object>} Created document
   */
  async addDocument(caseId, documentData) {
    try {
      const caseRecord = await Case.findById(caseId);
      
      if (!caseRecord) {
        throw new ApiError(404, 'Case not found');
      }
      
      // Validate document before saving
      const isValid = await this.validateDocument(documentData);
      if (!isValid.valid) {
        throw new ApiError(400, `Invalid document: ${isValid.message}`);
      }
      
      const newDocument = new Document({
        ...documentData,
        case: caseId,
        uploadedAt: new Date()
      });
      
      const savedDocument = await newDocument.save();
      
      // Update case with the new document reference
      await Case.findByIdAndUpdate(
        caseId,
        { 
          $push: { documents: savedDocument._id },
          $set: { updatedAt: new Date() }
        }
      );

      // Add timeline entry for the document upload
      await this.addTimelineEntry(caseId, {
        action: 'Document Added',
        description: `New document added: ${documentData.name}`,
        performedBy: documentData.uploadedBy
      });

      logger.info(`Document added to case ${caseId}: ${savedDocument._id}`);
      return savedDocument;
    } catch (error) {
      logger.error(`Error adding document to case ${caseId}: ${error

