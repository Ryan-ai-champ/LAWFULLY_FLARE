import React, { useState, useEffect } from 'react';
import { Box, Typography, CircularProgress, Alert } from '@mui/material';

const ConnectionTest = () => {
  const [status, setStatus] = useState({ loading: true, error: null, data: null });

  useEffect(() => {
    fetch('http://localhost:5001/api/test')
      .then(response => response.json())
      .then(data => {
        setStatus({ loading: false, error: null, data });
      })
      .catch(error => {
        setStatus({ loading: false, error: error.message, data: null });
      });
  }, []);

  if (status.loading) {
    return (
      <Box display="flex" justifyContent="center" p={3}>
        <CircularProgress />
      </Box>
    );
  }

  if (status.error) {
    return (
      <Alert severity="error" sx={{ m: 2 }}>
        Error connecting to backend: {status.error}
      </Alert>
    );
  }

  return (
    <Box p={3}>
      <Alert severity="success" sx={{ mb: 2 }}>
        {status.data?.message}
      </Alert>
      <Typography variant="body2" color="text.secondary">
        Timestamp: {new Date(status.data?.timestamp).toLocaleString()}
      </Typography>
    </Box>
  );
};

export default ConnectionTest;
