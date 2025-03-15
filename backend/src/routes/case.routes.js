const express = require('express');
const router = express.Router();
const {
  getAllCases,
  getCase,
  createCase,
  updateCase,
  deleteCase
} = require('../controllers/case.controller');

router
  .route('/')
  .get(getAllCases)
  .post(createCase);

router
  .route('/:id')
  .get(getCase)
  .put(updateCase)
  .delete(deleteCase);

module.exports = router;
