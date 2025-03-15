const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const immigrationCaseSchema = new Schema({
  caseNumber: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  caseType: {
    type: String,
    required: true,
    enum: ['green_card', 'citizenship', 'visa', 'asylum', 'work_permit', 'family_petition', 'deportation_defense', 'other'],
    default: 'other'
  },
  status: {
    type: String,
    required: true,
    enum: ['draft', 'submitted', 'in_review', 'rfe_received', 'approved', 'denied', 'appeal_pending', 'closed', 'on_hold'],
    default: 'draft'
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'urgent'],
    default: 'medium'
  },
  applicant: {
    firstName: {
      type: String,
      required: true,
      trim: true
    },
    lastName: {
      type: String,
      required: true,
      trim: true
    },
    middleName: {
      type: String,
      trim: true
    },
    dateOfBirth: {
      type: Date,
      required: true
    },
    email: {
      type: String,
      required: true,
      trim: true,
      lowercase: true
    },
    phone: {
      type: String,
      trim: true
    },
    address: {
      street: String,
      city: String,
      state: String,
      zipCode: String,
      country: String
    },
    alienNumber: {
      type: String,
      trim: true
    },
    nationality: {
      type: String,
      trim: true
    }
  },
  beneficiaries: [{
    firstName: {
      type: String,
      required: true,
      trim: true
    },
    lastName: {
      type: String,
      required: true,
      trim: true
    },
    middleName: {
      type: String,
      trim: true
    },
    dateOfBirth: {
      type: Date,
      required: true
    },
    email: {
      type: String,
      trim: true,
      lowercase: true
    },
    phone: {
      type: String,
      trim: true
    },
    relationship: {
      type: String,
      trim: true
    },
    alienNumber: {
      type: String,
      trim: true
    },
    nationality: {
      type: String,
      trim: true
    }
  }],
  dates: {
    filingDate: Date,
    priorityDate: Date,
    biometricsDate: Date,
    interviewDate: Date,
    receivedDate: Date,
    dueDate: Date,
    decisionDate: Date
  },
  documents: [{
    name: {
      type: String,
      required: true
    },
    description: String,
    fileUrl: {
      type: String,
      required: true
    },
    fileType: String,
    uploadDate: {
      type: Date,
      default: Date.now
    },
    isRequired: {
      type: Boolean,
      default: false
    },
    status: {
      type: String,
      enum: ['pending', 'approved', 'rejected', 'needs_review'],
      default: 'pending'
    }
  }],
  forms: [{
    formType: {
      type: String,
      required: true
    },
    formNumber: {
      type: String,
      required: true
    },
    status: {
      type: String,
      enum: ['not_started', 'in_progress', 'completed', 'submitted'],
      default: 'not_started'
    },
    completionDate: Date,
    submissionDate: Date
  }],
  notes: [{
    content: {
      type: String,
      required: true
    },
    createdBy: {
      type: Schema.Types.ObjectId,
      ref: 'User'
    },
    createdAt: {
      type: Date,
      default: Date.now
    },
    isPrivate: {
      type: Boolean,
      default: false
    }
  }],
  uscisInfo: {
    receiptNumber: {
      type: String,
      trim: true
    },
    caseStatus: {
      type: String,
      trim: true
    },
    lastUpdated: Date,
    processingCenter: {
      type: String,
      trim: true
    }
  },
  payments: [{
    amount: {
      type: Number,
      required: true
    },
    currency: {
      type: String,
      default: 'USD'
    },
    paymentDate: {
      type: Date,
      default: Date.now
    },
    paymentMethod: {
      type: String,
      enum: ['credit_card', 'bank_transfer', 'check', 'cash', 'other'],
      default: 'other'
    },
    paymentStatus: {
      type: String,
      enum: ['pending', 'completed', 'failed', 'refunded'],
      default: 'pending'
    },
    description: String,
    receiptUrl: String
  }],
  assignedTo: {
    type: Schema.Types.ObjectId,
    ref: 'User'
  },
  createdBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  isArchived: {
    type: Boolean,
    default: false
  },
  tags: [{
    type: String,
    trim: true
  }]
}, {
  timestamps: true
});

// Indexes for faster querying
immigrationCaseSchema.index({ caseNumber: 1 });
immigrationCaseSchema.index({ 'applicant.lastName': 1, 'applicant.firstName': 1 });
immigrationCaseSchema.index({ status: 1 });
immigrationCaseSchema.index({ caseType: 1 });
immigrationCaseSchema.index({ assignedTo: 1 });
immigrationCaseSchema.index({ createdBy: 1 });
immigrationCaseSchema.index({ 'dates.dueDate': 1 });

// Virtual for full name
immigrationCaseSchema.virtual('applicant.fullName').get(function() {
  return `${this.applicant.firstName} ${this.applicant.lastName}`;
});

// Static method to find cases by due date range
immigrationCaseSchema.statics.findByDueDateRange = function(startDate, endDate) {
  return this.find({
    'dates.dueDate': {
      $gte: startDate,
      $lte: endDate
    }
  });
};

// Instance method to calculate days until due
immigrationCaseSchema.methods.daysUntilDue = function() {
  if (!this.dates.dueDate) return null;
  
  const today = new Date();
  const dueDate = new Date(this.dates.dueDate);
  const diffTime = dueDate - today;
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  
  return diffDays;
};

// Pre-save hook to generate case number if not provided
immigrationCaseSchema.pre('save', async function(next) {
  if (!this.isNew) return next();
  
  if (!this.caseNumber) {
    const date = new Date();
    const year = date.getFullYear().toString().substr(-2);
    const month = (date.getMonth() + 1).toString().padStart(2, '0');
    
    // Find the latest case with similar prefix
    const prefix = `${year}${month}`;
    const latestCase = await this.constructor.findOne(
      { caseNumber: new RegExp(`^${prefix}`) },
      { caseNumber: 1 },
      { sort: { caseNumber: -1 } }
    );
    
    let sequence = '0001';
    if (latestCase && latestCase.caseNumber) {
      const lastSequence = latestCase.caseNumber.substr(-4);
      sequence = (parseInt(lastSequence, 10) + 1).toString().padStart(4, '0');
    }
    
    this.caseNumber = `${prefix}-${sequence}`;
  }
  
  next();
});

const ImmigrationCase = mongoose.model('ImmigrationCase', immigrationCaseSchema);

module.exports = ImmigrationCase;

