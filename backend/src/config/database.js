const mongoose = require('mongoose');
const config = require('./config');
const logger = require('../utils/logger');

/**
 * MongoDB connection class with error handling, reconnection logic,
 * event listeners, logging integration, and graceful shutdown support.
 */
class Database {
  constructor() {
    this.mongoose = mongoose;
    this.isConnected = false;
    this.connectionAttempts = 0;
    this.maxConnectionAttempts = 5;
    this.reconnectTimeout = 5000; // 5 seconds
  }

  /**
   * Connect to MongoDB
   */
  async connect() {
    try {
      // MongoDB connection options
      const options = {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        serverSelectionTimeoutMS: 5000, // Timeout after 5s
        maxPoolSize: 10, // Maintain up to 10 socket connections
      };

      // Connect to the MongoDB database
      await mongoose.connect(config.mongodb.uri, options);
      
      this.isConnected = true;
      this.connectionAttempts = 0;
      
      logger.info(`Connected to MongoDB: ${this.maskConnectionString(config.mongodb.uri)}`);
      
      this._registerEventListeners();
      
      return this.mongoose;
    } catch (error) {
      this.isConnected = false;
      logger.error(`MongoDB connection error: ${error.message}`);
      
      // Implement reconnection logic
      await this._handleConnectionError();
      
      return null;
    }
  }

  /**
   * Register MongoDB connection event listeners
   */
  _registerEventListeners() {
    // Connection events
    mongoose.connection.on('connected', () => {
      this.isConnected = true;
      logger.info('Mongoose connected to MongoDB');
    });

    mongoose.connection.on('error', (err) => {
      this.isConnected = false;
      logger.error(`Mongoose connection error: ${err.message}`);
      this._handleConnectionError();
    });

    mongoose.connection.on('disconnected', () => {
      this.isConnected = false;
      logger.warn('Mongoose disconnected from MongoDB');
      
      // Only attempt reconnection if not from an intentional disconnect
      if (!this.isShuttingDown) {
        this._handleConnectionError();
      }
    });

    // Log other connection events
    mongoose.connection.on('reconnected', () => {
      this.isConnected = true;
      logger.info('Mongoose reconnected to MongoDB');
    });

    mongoose.connection.on('reconnectFailed', () => {
      logger.error('Mongoose reconnection failed');
    });

    // Process termination event listeners
    process.on('SIGINT', this.disconnect.bind(this, 'SIGINT'));
    process.on('SIGTERM', this.disconnect.bind(this, 'SIGTERM'));
    process.on('exit', this.disconnect.bind(this, 'exit'));

    // Handle uncaught exceptions and rejections
    process.on('uncaughtException', (error) => {
      logger.error(`Uncaught Exception: ${error.message}`);
      this.disconnect('uncaughtException');
    });

    process.on('unhandledRejection', (reason, promise) => {
      logger.error(`Unhandled Rejection at: ${promise}, reason: ${reason}`);
      this.disconnect('unhandledRejection');
    });
  }

  /**
   * Handle connection errors with reconnection logic
   */
  async _handleConnectionError() {
    if (this.connectionAttempts < this.maxConnectionAttempts) {
      this.connectionAttempts++;
      logger.info(`Attempting to reconnect to MongoDB (Attempt ${this.connectionAttempts}/${this.maxConnectionAttempts})`);
      
      // Wait for reconnectTimeout before attempting to reconnect
      await new Promise((resolve) => setTimeout(resolve, this.reconnectTimeout));
      
      // Exponential backoff for reconnection attempts
      this.reconnectTimeout *= 1.5;
      
      // Attempt to reconnect
      await this.connect();
    } else {
      logger.error(`Failed to connect to MongoDB after ${this.maxConnectionAttempts} attempts`);
      
      // If running in production, exit the process to allow container orchestrator to restart
      if (config.environment === 'production') {
        process.exit(1);
      }
    }
  }

  /**
   * Gracefully disconnect from MongoDB
   */
  async disconnect(signal) {
    this.isShuttingDown = true;
    
    try {
      if (this.isConnected) {
        logger.info(`Disconnecting from MongoDB due to ${signal}`);
        await mongoose.connection.close();
        logger.info('MongoDB connection closed successfully');
      }
      
      // Exit with zero exit code if shutting down is due to SIGINT or SIGTERM
      if (signal === 'SIGINT' || signal === 'SIGTERM') {
        process.exit(0);
      }
    } catch (error) {
      logger.error(`Error during MongoDB disconnection: ${error.message}`);
      process.exit(1);
    }
  }

  /**
   * Mask the connection string for logging
   */
  maskConnectionString(uri) {
    try {
      const parsedUri = new URL(uri);
      if (parsedUri.password) {
        parsedUri.password = '***';
      }
      return parsedUri.toString();
    } catch (error) {
      // If URI parsing fails, return a generic message
      return 'MongoDB connection (URI masked)';
    }
  }

  /**
   * Check if the database is connected
   */
  isDbConnected() {
    return this.isConnected && mongoose.connection.readyState === 1;
  }
}

// Create a singleton instance
const database = new Database();

module.exports = database;

