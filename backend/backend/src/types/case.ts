export interface ICase {
  _id: string;
  caseNumber: string;
  client: string; // Reference to User
  assignedLawyer: string; // Reference to User
  caseType: string;
  status: 'new' | 'in-progress' | 'pending' | 'completed' | 'cancelled';
  priority: 'low' | 'medium' | 'high';
  description: string;
  documents: Array<{
    name: string;
    type: string;
    url: string;
    uploadedBy: string;
    uploadedAt: Date;
  }>;
  notes: Array<{
    content: string;
    createdBy: string;
    createdAt: Date;
  }>;
  deadlines: Array<{
    title: string;
    date: Date;
    description?: string;
    completed: boolean;
  }>;
  createdAt: Date;
  updatedAt: Date;
}

