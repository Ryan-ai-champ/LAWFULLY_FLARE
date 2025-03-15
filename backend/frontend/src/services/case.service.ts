import api from './api';
import { Case } from '../types';

export const getCases = async (): Promise<Case[]> => {
  const response = await api.get('/cases');
  return response.data.data;
};

export const getCase = async (id: string): Promise<Case> => {
  const response = await api.get(`/cases/${id}`);
  return response.data.data;
};

export const createCase = async (caseData: Partial<Case>): Promise<Case> => {
  const response = await api.post('/cases', caseData);
  return response.data.data;
};

export const updateCase = async (id: string, caseData: Partial<Case>): Promise<Case> => {
  const response = await api.put(`/cases/${id}`, caseData);
  return response.data.data;
};

export const deleteCase = async (id: string): Promise<void> => {
  await api.delete(`/cases/${id}`);
};

