const mongoose = require('mongoose');

const caseSchema = new mongoose.Schema({
  caseNumber: {
    type: String,
    required: true,
    unique: true
  },
  caseType: {
    type: String,
    required: true,
    enum: ['Green Card', 'Work Visa', 'Family Petition', 'Citizenship', 'Asylum']
  },
  applicant: {
    type: String,
    required: true
  },
  status: {
    type: String,
    required: true,
    enum: ['Pending', 'In Review', 'Approved', 'Rejected', 'On Hold'],
    default: 'Pending'
  },
  priority: {
    type: String,
    required: true,
    enum: ['High', 'Medium', 'Low'],
    default: 'Medium'
  },
  submissionDate: {
    type: Date,
    default: Date.now
  },
  dueDate: {
    type: Date,
    required: true
  }
});

module.exports = mongoose.model('Case', caseSchema);
