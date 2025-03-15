const User = require('../models/user.model');
const AppError = require('../utils/appError');
const logger = require('../utils/logger');

/**
 * User Service - Singleton class to handle all user-related operations
 */
class UserService {
  constructor() {
    if (UserService.instance) {
      return UserService.instance;
    }
    UserService.instance = this;
  }

  /**
   * Create a new user
   * @param {Object} userData - User data to create
   * @returns {Object} - Created user object
   */
  async createUser(userData) {
    try {
      // Check if user with the same email already exists
      const existingUser = await User.findOne({ email: userData.email });
      if (existingUser) {
        throw new AppError('User with this email already exists', 400);
      }

      const user = await User.create(userData);
      return user;
    } catch (error) {
      logger.error(`Error creating user: ${error.message}`);
      throw error instanceof AppError 
        ? error 
        : new AppError(`Failed to create user: ${error.message}`, 500);
    }
  }

  /**
   * Get user by ID
   * @param {String} userId - User ID
   * @returns {Object} - User object
   */
  async getUserById(userId) {
    try {
      const user = await User.findById(userId);
      if (!user) {
        throw new AppError('User not found', 404);
      }
      return user;
    } catch (error) {
      logger.error(`Error getting user by ID: ${error.message}`);
      throw error instanceof AppError 
        ? error 
        : new AppError(`Failed to get user: ${error.message}`, 500);
    }
  }

  /**
   * Update user information
   * @param {String} userId - User ID
   * @param {Object} updateData - Data to update
   * @returns {Object} - Updated user
   */
  async updateUser(userId, updateData) {
    try {
      // Prevent updating sensitive fields directly
      const restrictedFields = ['password', 'role', 'verified'];
      restrictedFields.forEach(field => {
        if (updateData[field]) delete updateData[field];
      });

      const user = await User.findByIdAndUpdate(
        userId, 
        updateData, 
        { new: true, runValidators: true }
      );

      if (!user) {
        throw new AppError('User not found', 404);
      }

      return user;
    } catch (error) {
      logger.error(`Error updating user: ${error.message}`);
      throw error instanceof AppError 
        ? error 
        : new AppError(`Failed to update user: ${error.message}`, 500);
    }
  }

  /**
   * Delete a user
   * @param {String} userId - User ID
   * @returns {Boolean} - Success status
   */
  async deleteUser(userId) {
    try {
      const result = await User.findByIdAndDelete(userId);
      if (!result) {
        throw new AppError('User not found', 404);
      }
      return true;
    } catch (error) {
      logger.error(`Error deleting user: ${error.message}`);
      throw error instanceof AppError 
        ? error 
        : new AppError(`Failed to delete user: ${error.message}`, 500);
    }
  }

  /**
   * Update user profile
   * @param {String} userId - User ID
   * @param {Object} profileData - Profile data to update
   * @returns {Object} - Updated user profile
   */
  async updateUserProfile(userId, profileData) {
    try {
      // Create profile object to update
      const profile = {};
      
      // Handle allowed profile fields
      const allowedFields = ['firstName', 'lastName', 'phone', 'address', 'avatar', 'bio'];
      allowedFields.forEach(field => {
        if (profileData[field] !== undefined) {
          profile[field] = profileData[field];
        }
      });

      const user = await User.findByIdAndUpdate(
        userId,
        { profile },
        { new: true, runValidators: true }
      );

      if (!user) {
        throw new AppError('User not found', 404);
      }

      return user.profile;
    } catch (error) {
      logger.error(`Error updating user profile: ${error.message}`);
      throw error instanceof AppError 
        ? error 
        : new AppError(`Failed to update profile: ${error.message}`, 500);
    }
  }

  /**
   * Update user preferences
   * @param {String} userId - User ID
   * @param {Object} preferences - User preferences to update
   * @returns {Object} - Updated preferences
   */
  async updateUserPreferences(userId, preferences) {
    try {
      const user = await User.findByIdAndUpdate(
        userId,
        { preferences },
        { new: true, runValidators: true }
      );

      if (!user) {
        throw new AppError('User not found', 404);
      }

      return user.preferences;
    } catch (error) {
      logger.error(`Error updating user preferences: ${error.message}`);
      throw error instanceof AppError 
        ? error 
        : new AppError(`Failed to update preferences: ${error.message}`, 500);
    }
  }

  /**
   * Update user role
   * @param {String} userId - User ID
   * @param {String} role - New role
   * @returns {Object} - Updated user
   */
  async updateUserRole(userId, role) {
    try {
      // Validate role
      const allowedRoles = ['admin', 'manager', 'agent', 'client'];
      if (!allowedRoles.includes(role)) {
        throw new AppError(`Invalid role. Allowed roles: ${allowedRoles.join(', ')}`, 400);
      }

      const user = await User.findByIdAndUpdate(
        userId,
        { role },
        { new: true, runValidators: true }
      );

      if (!user) {
        throw new AppError('User not found', 404);
      }

      return user;
    } catch (error) {
      logger.error(`Error updating user role: ${error.message}`);
      throw error instanceof AppError 
        ? error 
        : new AppError(`Failed to update role: ${error.message}`, 500);
    }
  }

  /**
   * Search and filter users
   * @param {Object} filters - Search filters
   * @param {Object} options - Pagination and sorting options
   * @returns {Object} - Filtered users and pagination info
   */
  async searchUsers(filters = {}, options = {}) {
    try {
      const query = {};
      
      // Apply filters
      if (filters.name) {
        query.$or = [
          { 'profile.firstName': { $regex: filters.name, $options: 'i' } },
          { 'profile.lastName': { $regex: filters.name, $options: 'i' } }
        ];
      }
      
      if (filters.email) {
        query.email = { $regex: filters.email, $options: 'i' };
      }
      
      if (filters.role) {
        query.role = filters.role;
      }
      
      // Apply pagination
      const page = parseInt(options.page, 10) || 1;
      const limit = parseInt(options.limit, 10) || 10;
      const skip = (page - 1) * limit;
      
      // Build sort options
      const sortBy = options.sortBy || 'createdAt';
      const sortDirection = options.sortDirection === 'asc' ? 1 : -1;
      const sort = { [sortBy]: sortDirection };
      
      // Execute query with pagination
      const users = await User.find(query)
        .sort(sort)
        .skip(skip)
        .limit(limit);
      
      // Get total count for pagination
      const total = await User.countDocuments(query);
      
      return {
        users,
        pagination: {
          total,
          page,
          limit,
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      logger.error(`Error searching users: ${error.message}`);
      throw new AppError(`Failed to search users: ${error.message}`, 500);
    }
  }

  /**
   * Track user statistics
   * @param {String} userId - User ID
   * @param {String} action - Action performed
   * @returns {Object} - Updated statistics
   */
  async trackUserStatistics(userId, action) {
    try {
      const user = await User.findById(userId);
      if (!user) {
        throw new AppError('User not found', 404);
      }

      // Initialize statistics if not present
      if (!user.statistics) {
        user.statistics = {
          lastLogin: null,
          loginCount: 0,
          actionsPerformed: 0,
          casesCreated: 0,
          casesCompleted: 0
        };
      }

      // Update specific statistics based on action
      switch (action) {
        case 'login':
          user.statistics.lastLogin = new Date();
          user.statistics.loginCount += 1;
          break;
        case 'action':
          user.statistics.actionsPerformed += 1;
          break;
        case 'caseCreated':
          user.statistics.casesCreated += 1;
          break;
        case 'caseCompleted':
          user.statistics.casesCompleted += 1;
          break;
        default:
          break;
      }

      await user.save();
      return user.statistics;
    } catch (error) {
      logger.error(`Error tracking user statistics: ${error.message}`);
      throw error instanceof AppError 
        ? error 
        : new AppError(`Failed to track statistics: ${error.message}`, 500);
    }
  }

  /**
   * Get all users (with pagination)
   * @param {Object} options - Pagination and sorting options
   * @returns {Object} - Users and pagination info
   */
  async getAllUsers(options = {}) {
    try {
      const page = parseInt(options.page, 10) || 1;
      const limit = parseInt(options.limit, 10) || 10;
      const skip = (page - 1) * limit;
      
      const sortBy = options.sortBy || 'createdAt';
      const sortDirection = options.sortDirection === 'asc' ? 1 : -1;
      const sort = { [sortBy]: sortDirection };
      
      const users = await User.find()
        .sort(sort)
        .skip(skip)
        .limit(limit);
      
      const total = await User.countDocuments();
      
      return {
        users,
        pagination: {
          total,
          page,
          limit,
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      logger.error(`Error getting all users: ${error.message}`);
      throw new AppError(`Failed to get users: ${error.message}`, 500);
    }
  }
}

module.exports = new UserService();

