import { configureStore } from '@reduxjs/toolkit';
import casesReducer, {
  fetchCases,
  fetchCaseById,
  addCase,
  updateCase,
  deleteCase,
  setFilters,
  setSorting,
  clearSelectedCase
} from './slices/casesSlice';
import authReducer from './slices/authSlice';

export const store = configureStore({
  reducer: {
    cases: casesReducer,
    auth: authReducer,
  },
});

export {
  fetchCases,
  fetchCaseById,
  addCase,
  updateCase,
  deleteCase,
  setFilters,
  setSorting,
  clearSelectedCase
};

export default store;
