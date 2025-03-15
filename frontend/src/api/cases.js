import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001';

const caseService = {
  getAllCases: async (filters = {}) => {
    const queryString = new URLSearchParams(filters).toString();
    const response = await axios.get(`${API_URL}/api/cases${queryString ? `?${queryString}` : ''}`);
    return response.data;
  },

  getCase: async (id) => {
    const response = await axios.get(`${API_URL}/api/cases/${id}`);
    return response.data;
  },

  createCase: async (caseData) => {
    const response = await axios.post(`${API_URL}/api/cases`, caseData);
    return response.data;
  },

  updateCase: async (id, caseData) => {
    const response = await axios.put(`${API_URL}/api/cases/${id}`, caseData);
    return response.data;
  },

  deleteCase: async (id) => {
    const response = await axios.delete(`${API_URL}/api/cases/${id}`);
    return response.data;
  }
};

export default caseService;
