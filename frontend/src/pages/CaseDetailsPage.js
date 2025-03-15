import React, { useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useSelector, useDispatch } from 'react-redux';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Chip,
  Button,
  CircularProgress,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon
} from '@mui/material';
import {
  AccessTime as AccessTimeIcon,
  Person as PersonIcon,
  Description as DescriptionIcon,
  Category as CategoryIcon,
  Flag as FlagIcon,
  Event as EventIcon,
  ArrowBack as ArrowBackIcon
} from '@mui/icons-material';

const CaseDetailsPage = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const dispatch = useDispatch();

  // TODO: Add action to fetch single case
  const { selectedCase, loading, error } = useSelector((state) => state.cases);

  useEffect(() => {
    // TODO: Dispatch action to fetch case details
    // dispatch(fetchCaseById(id));
  }, [dispatch, id]);

  const getStatusColor = (status) => {
    switch (status) {
      case 'Approved':
        return 'success';
      case 'Rejected':
        return 'error';
      case 'Pending':
        return 'warning';
      case 'In Review':
        return 'info';
      case 'On Hold':
        return 'default';
      default:
        return 'default';
    }
  };

  const getPriorityColor = (priority) => {
    switch (priority) {
      case 'High':
        return 'error';
      case 'Medium':
        return 'warning';
      case 'Low':
        return 'success';
      default:
        return 'default';
    }
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ p: 3 }}>
        <Typography color="error">{error}</Typography>
      </Box>
    );
  }

  if (!selectedCase) {
    return (
      <Box sx={{ p: 3 }}>
        <Typography>Case not found</Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Button
        startIcon={<ArrowBackIcon />}
        onClick={() => navigate('/cases')}
        sx={{ mb: 3 }}
      >
        Back to Cases
      </Button>

      <Paper sx={{ p: 3 }}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h5">
                Case {selectedCase.caseNumber}
              </Typography>
              <Box>
                <Chip
                  label={selectedCase.status}
                  color={getStatusColor(selectedCase.status)}
                  sx={{ mr: 1 }}
                />
                <Chip
                  label={selectedCase.priority}
                  color={getPriorityColor(selectedCase.priority)}
                />
              </Box>
            </Box>
            <Divider />
          </Grid>

          <Grid item xs={12}>
            <List>
              <ListItem>
                <ListItemIcon>
                  <PersonIcon />
                </ListItemIcon>
                <ListItemText
                  primary="Applicant"
                  secondary={selectedCase.applicant}
                />
              </ListItem>

              <ListItem>
                <ListItemIcon>
                  <CategoryIcon />
                </ListItemIcon>
                <ListItemText
                  primary="Case Type"
                  secondary={selectedCase.caseType}
                />
              </ListItem>

              <ListItem>
                <ListItemIcon>
                  <AccessTimeIcon />
                </ListItemIcon>
                <ListItemText
                  primary="Submission Date"
                  secondary={selectedCase.submissionDate}
                />
              </ListItem>

              <ListItem>
                <ListItemIcon>
                  <EventIcon />
                </ListItemIcon>
                <ListItemText
                  primary="Due Date"
                  secondary={selectedCase.dueDate}
                />
              </ListItem>
            </List>
          </Grid>

          <Grid item xs={12}>
            <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 2 }}>
              <Button
                variant="outlined"
                color="primary"
                onClick={() => navigate(`/cases/${id}/edit`)}
              >
                Edit Case
              </Button>
              <Button
                variant="contained"
                color="primary"
              >
                Download Documents
              </Button>
            </Box>
          </Grid>
        </Grid>
      </Paper>
    </Box>
  );
};

export default CaseDetailsPage;

