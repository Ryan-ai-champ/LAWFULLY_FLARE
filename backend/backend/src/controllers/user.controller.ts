import { Request, Response } from 'express';
import { User } from '../models/user.model';
import { logger } from '../config/logger';

// Get all users (with optional role filter)
export const getUsers = async (req: Request, res: Response): Promise<Response> => {
  try {
    const { role } = req.query;
    const query = role ? { role } : {};

    const users = await User.find(query)
      .select('-password') // Exclude password field
      .sort('firstName lastName');

    return res.status(200).json({
      success: true,
      data: users,
    });
  } catch (error) {
    logger.error('Error fetching users:', error);
    return res.status(500).json({
      success: false,
      message: 'Error fetching users',
    });
  }
};

// Get user by ID
export const getUser = async (req: Request, res: Response): Promise<Response> => {
  try {
    const userId = req.params.id;
    const user = await User.findById(userId).select('-password');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    return res.status(200).json({
      success: true,
      data: user,
    });
  } catch (error) {
    logger.error('Error fetching user:', error);
    return res.status(500).json({
      success: false,
      message: 'Error fetching user',
    });
  }
};

// Update user
export const updateUser = async (req: Request, res: Response): Promise<Response> => {
  try {
    const userId = req.params.id;
    const updates = req.body;

    // Remove password from updates if it exists
    delete updates.password;

    const user = await User.findByIdAndUpdate(
      userId,
      updates,
      { new: true, runValidators: true }
    ).select('-password');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    return res.status(200).json({
      success: true,
      data: user,
    });
  } catch (error) {
    logger.error('Error updating user:', error);
    return res.status(500).json({
      success: false,
      message: 'Error updating user',
    });
  }
};

// Delete user
export const deleteUser = async (req: Request, res: Response): Promise<Response> => {
  try {
    const userId = req.params.id;

    // Check if user exists
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    // Check if user has any associated cases
    const Case = require('../models/case.model').Case;
    const hasActiveCases = await Case.exists({
      $or: [
        { client: userId },
        { assignedLawyer: userId }
      ]
    });

    if (hasActiveCases) {
      return res.status(400).json({
        success: false,
        message: 'Cannot delete user with active cases',
      });
    }

    await user.remove();

    return res.status(200).json({
      success: true,
      message: 'User deleted successfully',
    });
  } catch (error) {
    logger.error('Error deleting user:', error);
    return res.status(500).json({
      success: false,
      message: 'Error deleting user',
    });
  }
};

