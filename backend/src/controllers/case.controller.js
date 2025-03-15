const Case = require('../models/case.model');
const asyncWrapper = require('../utils/asyncWrapper');
const AppError = require('../utils/appError');

// Get all cases with optional filtering
exports.getAllCases = asyncWrapper(async (req, res) => {
  const query = {};
  if (req.query.caseType) query.caseType = req.query.caseType;
  if (req.query.status) query.status = req.query.status;
  if (req.query.priority) query.priority = req.query.priority;
  const cases = await Case.find(query).sort({ submissionDate: -1 });
  res.json(cases);
});

// Get single case
exports.getCase = asyncWrapper(async (req, res, next) => {
  const case_ = await Case.findById(req.params.id);
  if (!case_) {
    return next(new AppError('Case not found', 404));
  }
  res.json(case_);
});

// Create new case
exports.createCase = asyncWrapper(async (req, res) => {
  const case_ = await Case.create({
    caseNumber: 'CASE-' + Date.now(),
    caseType: req.body.caseType,
    applicant: req.body.applicant,
    status: req.body.status || 'Pending',
    priority: req.body.priority || 'Medium',
    dueDate: req.body.dueDate
  });
  res.status(201).json(case_);
});

// Update case
exports.updateCase = asyncWrapper(async (req, res, next) => {
  const case_ = await Case.findByIdAndUpdate(
    req.params.id,
    req.body,
    { new: true, runValidators: true }
  );
  if (!case_) {
    return next(new AppError('Case not found', 404));
  }
  res.json(case_);
});

// Delete case
exports.deleteCase = asyncWrapper(async (req, res, next) => {
  const case_ = await Case.findByIdAndDelete(req.params.id);
  if (!case_) {
    return next(new AppError('Case not found', 404));
  }
  res.json({ message: 'Case deleted successfully' });
});
