import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import caseService from '../../api/cases';

// Async thunks for API calls
export const fetchCases = createAsyncThunk(
  'cases/fetchAll',
  async (filters) => {
    const response = await caseService.getAllCases(filters);
    return response;
  }
);

export const fetchCaseById = createAsyncThunk(
  'cases/fetchOne',
  async (id) => {
    const response = await caseService.getCase(id);
    return response;
  }
);

export const createCase = createAsyncThunk(
  'cases/create',
  async (caseData) => {
    const response = await caseService.createCase(caseData);
    return response;
  }
);

export const updateCase = createAsyncThunk(
  'cases/update',
  async ({ id, caseData }) => {
    const response = await caseService.updateCase(id, caseData);
    return response;
  }
);

export const deleteCase = createAsyncThunk(
  'cases/delete',
  async (id) => {
    await caseService.deleteCase(id);
    return id;
  }
);

const casesSlice = createSlice({
  name: 'cases',
  initialState: {
    items: [],
    selectedCase: null,
    loading: false,
    error: null,
    filters: {
      caseType: 'All',
      status: 'All',
      priority: 'All',
      searchQuery: '',
    },
    sorting: {
      field: 'submissionDate',
      order: 'desc'
    }
  },
  reducers: {
    setFilters: (state, action) => {
      state.filters = { ...state.filters, ...action.payload };
    },
    setSorting: (state, action) => {
      state.sorting = action.payload;
    },
    clearSelectedCase: (state) => {
      state.selectedCase = null;
    }
  },
  extraReducers: (builder) => {
    builder
      // Fetch all cases
      .addCase(fetchCases.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchCases.fulfilled, (state, action) => {
        state.loading = false;
        state.items = action.payload;
      })
      .addCase(fetchCases.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message;
      })
      // Fetch single case
      .addCase(fetchCaseById.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchCaseById.fulfilled, (state, action) => {
        state.loading = false;
        state.selectedCase = action.payload;
      })
      .addCase(fetchCaseById.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message;
      })
      // Create case
      .addCase(createCase.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(createCase.fulfilled, (state, action) => {
        state.loading = false;
        state.items.unshift(action.payload);
      })
      .addCase(createCase.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message;
      })
      // Update case
      .addCase(updateCase.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(updateCase.fulfilled, (state, action) => {
        state.loading = false;
        const index = state.items.findIndex(item => item.id === action.payload.id);
        if (index !== -1) {
          state.items[index] = action.payload;
        }
        if (state.selectedCase?.id === action.payload.id) {
          state.selectedCase = action.payload;
        }
      })
      .addCase(updateCase.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message;
      })
      // Delete case
      .addCase(deleteCase.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(deleteCase.fulfilled, (state, action) => {
        state.loading = false;
        state.items = state.items.filter(item => item.id !== action.payload);
        if (state.selectedCase?.id === action.payload) {
          state.selectedCase = null;
        }
      })
      .addCase(deleteCase.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message;
      });
  },
});

export const { setFilters, setSorting, clearSelectedCase } = casesSlice.actions;
export default casesSlice.reducer;
