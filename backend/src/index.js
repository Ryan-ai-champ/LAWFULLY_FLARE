const app = require('./app');
const mongoose = require('mongoose');
const config = require('./config');

mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/immigration-platform')
  .then(() => {
    console.log('✅ Connected to MongoDB');
    const PORT = process.env.PORT || 5001;
    app.listen(PORT, () => {
      console.log();
    });
  })
  .catch((err) => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });
