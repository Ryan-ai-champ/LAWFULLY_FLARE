export interface IUser {
  _id: string;
  firstName: string;
  lastName: string;
  email: string;
  password: string;
  role: 'admin' | 'lawyer' | 'staff' | 'client';
  phone?: string;
  address?: {
    street: string;
    city: string;
    state: string;
    zipCode: string;
    country: string;
  };
  createdAt: Date;
  updatedAt: Date;
}

export interface IUserMethods {
  comparePassword(candidatePassword: string): Promise<boolean>;
}

