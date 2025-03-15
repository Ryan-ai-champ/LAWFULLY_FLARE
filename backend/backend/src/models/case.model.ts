import mongoose, { Schema, model } from 'mongoose';
import { ICase } from '../types/case';

const caseSchema = new Schema<ICase>(
  {
    caseNumber: { type: String, required: true, unique: true },
    client: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    assignedLawyer: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    caseType: { type: String, required: true },
    status: {
      type: String,
      enum: ['new', 'in-progress', 'pending', 'completed', 'cancelled'],
      default: 'new',
    },
    priority: {
      type: String,
      enum: ['low', 'medium', 'high'],
      default: 'medium',
    },
    description: { type: String, required: true },
    documents: [{
      name: String,
      type: String,
      url: String,
      uploadedBy: { type: Schema.Types.ObjectId, ref: 'User' },
      uploadedAt: Date,
    }],
    notes: [{
      content: String,
      createdBy: { type: Schema.Types.ObjectId, ref: 'User' },
      createdAt: { type: Date, default: Date.now },
    }],
    deadlines: [{
      title: String,
      date: Date,
      description: String,
      completed: { type: Boolean, default: false },
    }],
  },
  {
    timestamps: true,
  }
);

// Generate case number before saving
caseSchema.pre('save', async function (next) {
  if (this.isNew) {
    const count = await mongoose.model('Case').countDocuments();
    this.caseNumber = `CASE-${new Date().getFullYear()}-${(count + 1).toString().padStart(5, '0')}`;
  }
  next();
});

export const Case = model<ICase>('Case', caseSchema);

