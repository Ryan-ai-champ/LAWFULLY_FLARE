const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const { join } = require('path');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');

// Load environment variables
dotenv.config();

// Import routes
// Import routes
const authRoutes = require('./routes/auth.routes');
const caseRoutes = require('./routes/case.routes');
const documentRoutes = require('./routes/document.routes');
const formRoutes = require('./routes/form.routes');
const notificationRoutes = require('./routes/notification.routes');
const paymentRoutes = require('./routes/payment.routes');
const assistantRoutes = require('./routes/assistant.routes');
const userRoutes = require('./routes/user.routes');

// Log routes loading
console.log('Auth Routes loaded:', authRoutes);
console.log('Case Routes loaded:', caseRoutes);
console.log('Document Routes loaded:', documentRoutes);
console.log('Form Routes loaded:', formRoutes);
console.log('Notification Routes loaded:', notificationRoutes);
console.log('Payment Routes loaded:', paymentRoutes);
console.log('Assistant Routes loaded:', assistantRoutes);
console.log('User Routes loaded:', userRoutes);

// Import error handling utilities
const AppError = require('./utils/appError');
const globalErrorHandler = require('./middleware/error.middleware');

// Create Express app
const app = express();
const PORT = process.env.PORT || 5000;

// Connect to MongoDB
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      useCreateIndex: true,
      useFindAndModify: false,
    });
    console.log('Connected to MongoDB');
  } catch (err) {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  }
};

connectDB();

// Set security HTTP headers
app.use(helmet());

// Development logging
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
} else {
  app.use(morgan('combined'));
}

// Rate limiting
const limiter = rateLimit({
  max: 100,
  windowMs: 60 * 60 * 1000, // 1 hour
  message: 'Too many requests from this IP, please try again in an hour!'
});
app.use('/api', limiter);

// Body parser, reading data from body into req.body
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// Data compression
app.use(compression());

// CORS handling for cross-origin requests
app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:3000',
  credentials: true
}));

// Serving static files
app.use(express.static(join(__dirname, '../public')));

// Authentication middleware
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(' ')[1];

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        return res.status(403).json({ message: 'Invalid or expired token' });
      }

      req.user = user;
      next();
    });
  } else {
    res.status(401).json({ message: 'Authentication token required' });
  }
};

// Welcome route
app.get('/', (req, res) => {
  res.status(200).json({
    message: 'Welcome to the Immigration Platform API',
    documentation: '/api-docs',
    version: '1.0.0'
  });
});

// API health check route
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'Immigration platform API is running'
  });
});

// Basic health check route (alternative)
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', message: 'Server is running' });
});

// API routes - public
app.use('/api/v1/auth', authRoutes);
app.use('/api/auth', authRoutes); // Alternative path

// API routes - protected
app.use('/api/v1/cases', authenticateJWT, caseRoutes);
app.use('/api/v1/documents', authenticateJWT, documentRoutes);
app.use('/api/v1/forms', authenticateJWT, formRoutes);
app.use('/api/v1/notifications', authenticateJWT, notificationRoutes);
app.use('/api/v1/payments', authenticateJWT, paymentRoutes);
app.use('/api/v1/assistant', authenticateJWT, assistantRoutes);
app.use('/api/v1/users', authenticateJWT, userRoutes);

// Alternative API paths
app.use('/api/users', authenticateJWT, userRoutes);
app.use('/api/cases', authenticateJWT, caseRoutes);
app.use('/api/documents', authenticateJWT, documentRoutes);

// Catch 404 and forward to error handler
app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

// Global error handler middleware
app.use(globalErrorHandler);

// Socket.io setup for real-time notifications
const setupSocketServer = (server) => {
  const io = require('socket.io')(server, {
    cors: {
      origin: process.env.CLIENT_URL || 'http://localhost:3000',
      methods: ['GET', 'POST'],
      credentials: true
    }
  });

  const socketService = require('./services/socket.service');
  socketService.initialize(io);
};

// Export the app and setupSocketServer for modular use
module.exports = { app, setupSocketServer, PORT };
