import { configureStore } from '@reduxjs/toolkit';
import { combineReducers } from 'redux';

// Import slices (will be created in separate files)
// For now, we'll set up placeholder reducers
const authReducer = (state = { user: null, isAuthenticated: false, loading: false, error: null }, action) => {
  switch (action.type) {
    case 'AUTH_LOGIN_REQUEST':
      return { ...state, loading: true, error: null };
    case 'AUTH_LOGIN_SUCCESS':
      return { ...state, user: action.payload, isAuthenticated: true, loading: false };
    case 'AUTH_LOGIN_FAIL':
      return { ...state, loading: false, error: action.payload };
    case 'AUTH_LOGOUT':
      return { user: null, isAuthenticated: false, loading: false, error: null };
    default:
      return state;
  }
};

const casesReducer = (state = { cases: [], loading: false, error: null }, action) => {
  switch (action.type) {
    case 'CASES_REQUEST':
      return { ...state, loading: true };
    case 'CASES_SUCCESS':
      return { ...state, cases: action.payload, loading: false };
    case 'CASES_FAIL':
      return { ...state, loading: false, error: action.payload };
    default:
      return state;
  }
};

const documentsReducer = (state = { documents: [], loading: false, error: null }, action) => {
  switch (action.type) {
    case 'DOCUMENTS_REQUEST':
      return { ...state, loading: true };
    case 'DOCUMENTS_SUCCESS':
      return { ...state, documents: action.payload, loading: false };
    case 'DOCUMENTS_FAIL':
      return { ...state, loading: false, error: action.payload };
    default:
      return state;
  }
};

const notificationsReducer = (state = { notifications: [], unread: 0 }, action) => {
  switch (action.type) {
    case 'NOTIFICATIONS_LOAD':
      return { ...state, notifications: action.payload, unread: action.payload.filter(n => !n.read).length };
    case 'NOTIFICATION_ADD':
      return { 
        ...state, 
        notifications: [action.payload, ...state.notifications],
        unread: state.unread + 1
      };
    case 'NOTIFICATION_MARK_READ':
      return {
        ...state,
        notifications: state.notifications.map(n => 
          n.id === action.payload ? { ...n, read: true } : n
        ),
        unread: state.unread - 1
      };
    default:
      return state;
  }
};

// Combine all reducers
const rootReducer = combineReducers({
  auth: authReducer,
  cases: casesReducer,
  documents: documentsReducer,
  notifications: notificationsReducer,
  // Add more reducers as needed
});

// Configure the Redux store
const store = configureStore({
  reducer: rootReducer,
  devTools: process.env.NODE_ENV !== 'production',
  middleware: (getDefaultMiddleware) => 
    getDefaultMiddleware({
      serializableCheck: {
        // Ignore non-serializable values in specific paths
        ignoredActions: ['AUTH_LOGIN_SUCCESS'],
        ignoredPaths: ['auth.user'],
      },
    }),
});

export default store;

