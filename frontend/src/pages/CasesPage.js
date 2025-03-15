import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useSelector, useDispatch } from 'react-redux';
import {
  fetchCases,
  setFilters,
  setSorting,
  deleteCase
} from '../store/slices/casesSlice';
import {
  Box,
  Paper,
  Button,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  IconButton,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TableSortLabel,
  CircularProgress
} from '@mui/material';
import {
  Edit as EditIcon,
  Delete as DeleteIcon,
  Add as AddIcon,
  Search as SearchIcon
} from '@mui/icons-material';

const CasesPage = () => {
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const { items, filteredItems, loading, error, filters, sorting } = useSelector((state) => state.cases);

  useEffect(() => {
    dispatch(fetchCases());
  }, [dispatch]);

  const handleSort = (field) => {
    dispatch(setSorting({
      field,
      order: sorting.field === field && sorting.order === 'asc' ? 'desc' : 'asc'
    }));
  };

  const handleSearchChange = (event) => {
    dispatch(setFilters({
      searchQuery: event.target.value
    }));
  };

  const handleFilterChange = (event) => {
    const { name, value } = event.target;
    dispatch(setFilters({
      [name]: value
    }));
  };

  const handleDeleteCase = async (id) => {
    if (window.confirm('Are you sure you want to delete this case?')) {
      try {
        await dispatch(deleteCase(id)).unwrap();
        dispatch(fetchCases());
      } catch (err) {
        console.error('Failed to delete case:', err);
      }
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

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 3 }}>
        <Typography variant="h4">Cases</Typography>
        <Button
          variant="contained"
          color="primary"
          startIcon={<AddIcon />}
          onClick={() => navigate('/cases/new')}
        >
          New Case
        </Button>
      </Box>

      <Paper sx={{ p: 2, mb: 3 }}>
        <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
          <TextField
            placeholder="Search cases..."
            value={filters.searchQuery}
            onChange={handleSearchChange}
            InputProps={{
              startAdornment: <SearchIcon sx={{ mr: 1, color: 'text.secondary' }} />,
            }}
            sx={{ flexGrow: 1 }}
          />
          <FormControl sx={{ minWidth: 120 }}>
            <InputLabel>Type</InputLabel>
            <Select
              name="type"
              value={filters.type}
              onChange={handleFilterChange}
              label="Type"
            >
              <MenuItem value="All">All</MenuItem>
              <MenuItem value="Green Card">Green Card</MenuItem>
              <MenuItem value="Work Visa">Work Visa</MenuItem>
              <MenuItem value="Family Petition">Family Petition</MenuItem>
              <MenuItem value="Citizenship">Citizenship</MenuItem>
              <MenuItem value="Asylum">Asylum</MenuItem>
            </Select>
          </FormControl>
          <FormControl sx={{ minWidth: 120 }}>
            <InputLabel>Status</InputLabel>
            <Select
              name="status"
              value={filters.status}
              onChange={handleFilterChange}
              label="Status"
            >
              <MenuItem value="All">All</MenuItem>
              <MenuItem value="Pending">Pending</MenuItem>
              <MenuItem value="In Review">In Review</MenuItem>
              <MenuItem value="Approved">Approved</MenuItem>
              <MenuItem value="Rejected">Rejected</MenuItem>
              <MenuItem value="On Hold">On Hold</MenuItem>
            </Select>
          </FormControl>
          <FormControl sx={{ minWidth: 120 }}>
            <InputLabel>Priority</InputLabel>
            <Select
              name="priority"
              value={filters.priority}
              onChange={handleFilterChange}
              label="Priority"
            >
              <MenuItem value="All">All</MenuItem>
              <MenuItem value="High">High</MenuItem>
              <MenuItem value="Medium">Medium</MenuItem>
              <MenuItem value="Low">Low</MenuItem>
            </Select>
          </FormControl>
        </Box>
      </Paper>

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>
                <TableSortLabel
                  active={sorting.field === 'caseNumber'}
                  direction={sorting.field === 'caseNumber' ? sorting.order : 'asc'}
                  onClick={() => handleSort('caseNumber')}
                >
                  Case Number
                </TableSortLabel>
              </TableCell>
              <TableCell>
                <TableSortLabel
                  active={sorting.field === 'applicant'}
                  direction={sorting.field === 'applicant' ? sorting.order : 'asc'}
                  onClick={() => handleSort('applicant')}
                >
                  Applicant
                </TableSortLabel>
              </TableCell>
              <TableCell>
                <TableSortLabel
                  active={sorting.field === 'caseType'}
                  direction={sorting.field === 'caseType' ? sorting.order : 'asc'}
                  onClick={() => handleSort('caseType')}
                >
                  Type
                </TableSortLabel>
              </TableCell>
              <TableCell>
                <TableSortLabel
                  active={sorting.field === 'status'}
                  direction={sorting.field === 'status' ? sorting.order : 'asc'}
                  onClick={() => handleSort('status')}
                >
                  Status
                </TableSortLabel>
              </TableCell>
              <TableCell>
                <TableSortLabel
                  active={sorting.field === 'priority'}
                  direction={sorting.field === 'priority' ? sorting.order : 'asc'}
                  onClick={() => handleSort('priority')}
                >
                  Priority
                </TableSortLabel>
              </TableCell>
              <TableCell>
                <TableSortLabel
                  active={sorting.field === 'dueDate'}
                  direction={sorting.field === 'dueDate' ? sorting.order : 'asc'}
                  onClick={() => handleSort('dueDate')}
                >
                  Due Date
                </TableSortLabel>
              </TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {filteredItems.map((caseItem) => (
              <TableRow
                key={caseItem.id}
                hover
                onClick={() => navigate(`/cases/${caseItem.id}`)}
                sx={{ cursor: 'pointer' }}
              >
                <TableCell>{caseItem.caseNumber}</TableCell>
                <TableCell>{caseItem.applicant}</TableCell>
                <TableCell>{caseItem.caseType}</TableCell>
                <TableCell>{caseItem.status}</TableCell>
                <TableCell>{caseItem.priority}</TableCell>
                <TableCell>{new Date(caseItem.dueDate).toLocaleDateString()}</TableCell>
                <TableCell>
                  <Box sx={{ display: 'flex', gap: 1 }}>
                    <IconButton
                      size="small"
                      onClick={(e) => {
                        e.stopPropagation();
                        navigate(`/cases/${caseItem.id}/edit`);
                      }}
                    >
                      <EditIcon />
                    </IconButton>
                    <IconButton
                      size="small"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleDeleteCase(caseItem.id);
                      }}
                    >
                      <DeleteIcon />
                    </IconButton>
                  </Box>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
};

export default CasesPage;
