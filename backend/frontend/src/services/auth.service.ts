import api from './api';
import { AuthResponse, User } from '../types';

export const login = async (email: string, password: string): Promise<AuthResponse> => {
  try {
    const response = await api.post<AuthResponse>('/auth/login', {
      email,
      password,
    });
    
    if (response.data.token) {
      localStorage.setItem('token', response.data.token);
    }
    
    return response.data;
  } catch (error: any) {
    return {
      success: false,
      message: error.response?.data?.message || 'Login failed',
    };
  }
};

export const register = async (userData: Partial<User> & { password: string }): Promise<AuthResponse> => {
  try {
    const response = await api.post<AuthResponse>('/auth/register', userData);
    
    if (response.data.token) {
      localStorage.setItem('token', response.data.token);
    }
    
    return response.data;
  } catch (error: any) {
    return {
      success: false,
      message: error.response?.data?.message || 'Registration failed',
    };
  }
};

export const logout = (): void => {
  localStorage.removeItem('token');
  window.location.href = '/login';
};

export const getCurrentUser = async (): Promise<User | null> => {
  try {
    const response = await api.get<{ success: boolean; data: User }>('/auth/me');
    return response.data.data;
  } catch (error) {
    return null;
  }
};

