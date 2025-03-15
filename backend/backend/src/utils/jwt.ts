import jwt from 'jsonwebtoken';
import { IUser } from '../types/user';

export const generateToken = (user: IUser): string => {
  return jwt.sign(
    {
      id: user._id,
      email: user.email,
      role: user.role,
    },
    process.env.JWT_SECRET as string,
    {
      expiresIn: process.env.JWT_EXPIRES_IN,
    }
  );
};

export const verifyToken = (token: string): any => {
  try {
    return jwt.verify(token, process.env.JWT_SECRET as string);
  } catch (error) {
    return null;
  }
};

