// Action Types
export const LOGIN_SUCCESS = 'LOGIN_SUCCESS';
export const LOGIN_FAIL = 'LOGIN_FAIL';
export const LOGOUT = 'LOGOUT';
export const USER_LOADED = 'USER_LOADED';
export const AUTH_ERROR = 'AUTH_ERROR';

// Action Creators
export const logout = () => (dispatch) => {
    localStorage.removeItem('token');
    dispatch({ type: LOGOUT });
};

export const loadUser = () => async (dispatch) => {
    try {
        // In a real app, you would make an API call here to get the user data
        // const res = await axios.get('/api/auth/user');
        dispatch({
            type: USER_LOADED,
            payload: { user: null } // Replace with actual user data
        });
    } catch (err) {
        dispatch({
            type: AUTH_ERROR
        });
    }
};

import {
    LOGIN_SUCCESS,
    LOGIN_FAIL,
    LOGOUT,
    REGISTER_SUCCESS,
    REGISTER_FAIL
} from './types';

// Login user
export const login = (credentials) => async (dispatch) => {
    try {
        // TODO: Replace with actual API call
        const response = await fetch('http://localhost:5000/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(credentials)
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || 'Login failed');
        }

        dispatch({
            type: LOGIN_SUCCESS,
            payload: data
        });
    } catch (error) {
        dispatch({
            type: LOGIN_FAIL,
            payload: error.message
        });
    }
};

// Register user
export const register = (userData) => async (dispatch) => {
    try {
        // TODO: Replace with actual API call
        const response = await fetch('http://localhost:5000/api/auth/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(userData)
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || 'Registration failed');
        }

        dispatch({
            type: REGISTER_SUCCESS,
            payload: data
        });
    } catch (error) {
        dispatch({
            type: REGISTER_FAIL,
            payload: error.message
        });
    }
};

// Logout user
export const logout = () => (dispatch) => {
    localStorage.removeItem('token');
    dispatch({ type: LOGOUT });
};

