const express = require('express');
const router = express.Router();

router.get('/test', (req, res) => {
  res.json({
    message: 'Backend connection successful!',
    timestamp: new Date()
  });
});

module.exports = router;
