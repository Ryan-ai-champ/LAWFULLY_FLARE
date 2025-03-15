const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
require('dotenv').config();

const app = express();

// Import routes
const caseRoutes = require('./routes/case.routes');
const testRoutes = require('./routes/test.routes');

// Middleware
app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

// Mount routes
app.use('/api/cases', caseRoutes);
app.use('/api', testRoutes);

// Root route
app.get('/', (req, res) => {
  res.json({ message: 'Immigration Platform API' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Internal Server Error';
  res.status(statusCode).json({
    status: err.status || 'error',
    message: message
  });
});

module.exports = app;
