export interface User {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  role: 'admin' | 'lawyer' | 'staff' | 'client';
  phone?: string;
  address?: {
    street: string;
    city: string;
    state: string;
    zipCode: string;
    country: string;
  };
  createdAt: string;
  updatedAt: string;
}

export interface Case {
  id: string;
  caseNumber: string;
  client: User;
  assignedLawyer: User;
  status: 'new' | 'in-progress' | 'pending' | 'completed' | 'cancelled';
  priority: 'low' | 'medium' | 'high';
  caseType: string;
  description: string;
  documents: Document[];
  notes: Note[];
  createdAt: string;
  updatedAt: string;
}

export interface Document {
  id: string;
  name: string;
  type: string;
  url: string;
  uploadedBy: User;
  caseId: string;
  createdAt: string;
  updatedAt: string;
}

export interface Note {
  id: string;
  content: string;
  createdBy: User;
  caseId: string;
  createdAt: string;
  updatedAt: string;
}

export interface AuthResponse {
  success: boolean;
  token?: string;
  user?: User;
  message?: string;
}

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  message?: string;
}

export interface PaginatedResponse<T> extends ApiResponse<T> {
  page: number;
  limit: number;
  total: number;
  hasMore: boolean;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface RegisterData extends LoginCredentials {
  firstName: string;
  lastName: string;
  role: User['role'];
  phone?: string;
  address?: User['address'];
}

export interface User {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  role: 'admin' | 'lawyer' | 'staff' | 'client';
  phone?: string;
  address?: {
    street: string;
    city: string;
    state: string;
    zipCode: string;
    country: string;
  };
}

export interface Case {
  id: string;
  caseNumber: string;
  client: User;
  assignedLawyer: User;
  caseType: string;
  status: 'new' | 'in-progress' | 'pending' | 'completed' | 'cancelled';
  priority: 'low' | 'medium' | 'high';
  description: string;
  documents: Array<{
    name: string;
    type: string;
    url: string;
    uploadedBy: User;
    uploadedAt: Date;
  }>;
  notes: Array<{
    content: string;
    createdBy: User;
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

export interface AuthResponse {
  success: boolean;
  token?: string;
  user?: User;
  message?: string;
}

export interface ApiError {
  success: false;
  message: string;
  errors?: string[];
}

