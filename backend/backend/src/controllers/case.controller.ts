import { Request, Response } from 'express';
import { Case } from '../models/case.model';
import { logger } from '../config/logger';

// Get all cases (with filtering options)
export const getCases = async (req: Request, res: Response): Promise<Response> => {
  try {
    const filters = req.query;
    const query = { ...filters };

    // Handle role-based access
    if (req.user.role === 'client') {
      query.client = req.user._id;
    } else if (req.user.role === 'lawyer') {
      query.assignedLawyer = req.user._id;
    }

    const cases = await Case.find(query)
      .populate('client', 'firstName lastName email')
      .populate('assignedLawyer', 'firstName lastName email');

    return res.status(200).json({
      success: true,
      count: cases.length,
      data: cases,
    });
  } catch (error) {
    logger.error('Error fetching cases:', error);
    return res.status(500).json({
      success: false,
      message: 'Error fetching cases',
    });
  }
};

// Get single case
export const getCase = async (req: Request, res: Response): Promise<Response> => {
  try {
    const caseId = req.params.id;
    const caseData = await Case.findById(caseId)
      .populate('client', 'firstName lastName email')
      .populate('assignedLawyer', 'firstName lastName email');

    if (!caseData) {
      return res.status(404).json({
        success: false,
        message: 'Case not found',
      });
    }

    // Check if user has access to this case
    if (
      req.user.role === 'client' && 
      caseData.client._id.toString() !== req.user._id.toString()
    ) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to access this case',
      });
    }

    if (
      req.user.role === 'lawyer' && 
      caseData.assignedLawyer._id.toString() !== req.user._id.toString()
    ) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to access this case',
      });
    }

    return res.status(200).json({
      success: true,
      data: caseData,
    });
  } catch (error) {
    logger.error('Error fetching case:', error);
    return res.status(500).json({
      success: false,
      message: 'Error fetching case',
    });
  }
};

// Create case
export const createCase = async (req: Request, res: Response): Promise<Response> => {
  try {
    const caseData = req.body;
    
    // If creator is a client, automatically assign them as the client
    if (req.user.role === 'client') {
      caseData.client = req.user._id;
    }

    const newCase = await Case.create(caseData);
    
    const populatedCase = await Case.findById(newCase._id)
      .populate('client', 'firstName lastName email')
      .populate('assignedLawyer', 'firstName lastName email');

    return res.status(201).json({
      success: true,
      data: populatedCase,
    });
  } catch (error) {
    logger.error('Error creating case:', error);
    return res.status(500).json({
      success: false,
      message: 'Error creating case',
    });
  }
};

// Update case
export const updateCase = async (req: Request, res: Response): Promise<Response> => {
  try {
    const caseId = req.params.id;
    const updates = req.body;

    const caseToUpdate = await Case.findById(caseId);

    if (!caseToUpdate) {
      return res.status(404).json({
        success: false,
        message: 'Case not found',
      });
    }

    // Check authorization
    if (
      req.user.role === 'lawyer' && 
      caseToUpdate.assignedLawyer.toString() !== req.user._id.toString()
    ) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to update this case',
      });
    }

    const updatedCase = await Case.findByIdAndUpdate(
      caseId,
      updates,
      { new: true, runValidators: true }
    ).populate('client assignedLawyer');

    return res.status(200).json({
      success: true,
      data: updatedCase,
    });
  } catch (error) {
    logger.error('Error updating case:', error);
    return res.status(500).json({
      success: false,
      message: 'Error updating case',
    });
  }
};

// Delete case
export const deleteCase = async (req: Request, res: Response): Promise<Response> => {
  try {
    const caseId = req.params.id;
    
    const caseToDelete = await Case.findById(caseId);

    if (!caseToDelete) {
      return res.status(404).json({
        success: false,
        message: 'Case not found',
      });
    }

    await Case.findByIdAndDelete(caseId);

    return res.status(200).json({
      success: true,
      message: 'Case deleted successfully',
    });
  } catch (error) {
    logger.error('Error deleting case:', error);
    return res.status(500).json({
      success: false,
      message: 'Error deleting case',
    });
  }
};

