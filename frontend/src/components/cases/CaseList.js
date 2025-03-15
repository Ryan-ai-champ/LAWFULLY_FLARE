import React, { useEffect, useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
  Box,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TableSortLabel,
  Toolbar,
  Typography,
  IconButton,
  Button,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Search as SearchIcon
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { fetchCases, deleteCase, setFilters, setSorting } from '../../store/slices/casesSlice';

const CaseList = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const { items, loading, error, filters, sorting } = useSelector((state) => state.cases);

  useEffect(() => {
    dispatch(fetchCases(filters));
  }, [dispatch, filters]);

  const handleSearch = (event) => {
    dispatch(setFilters({ searchQuery: event.target.value }));
  };

  const handleFilterChange = (type, value) => {
    dispatch(setFilters({ [type]: value }));
  };

  const handleSort = (field) => {
    const isAsc = sorting.field === field && sorting.order === 'asc';
    dispatch(setSorting({
      field,
      order: isAsc ? 'desc' : 'asc'
    }));
  };

  const handleDelete = async (id) => {
    if (window.confirm('Are you sure you want to delete this case?')) {
      await dispatch(deleteCase(id));
      dispatch(fetchCases(filters));
    }
  };

  if (loading) {
    return <Typography>Loading...</Typography>;
  }

  if (error) {
    return <Typography color="error">{error}</Typography>;
  }

  return (
    <Box sx={{ width: '100%' }}>
      <Paper sx={{ width: '100%', mb: 2 }}>
        <Toolbar>
          <TextField
            placeholder="Search cases..."
            size="small"
            value={filters.searchQuery}
            onChange={handleSearch}
            sx={{ width: 300, mr: 2 }}
            InputProps={{
              startAdornment: <SearchIcon sx={{ color: 'action.active', mr: 1 }} />,
            }}
          />

          <FormControl size="small" sx={{ width: 150, mr: 2 }}>
            <InputLabel>Type</InputLabel>
            <Select
              value={filters.caseType}
              onChange={(e) => handleFilterChange('caseType', e.target.value)}
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

          <FormControl size="small" sx={{ width: 150, mr: 2 }}>
            <InputLabel>Status</InputLabel>
            <Select
              value={filters.status}
              onChange={(e) => handleFilterChange('status', e.target.value)}
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

          <Box sx={{ flexGrow: 1 }} />

          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => navigate('/cases/new')}
          >
            New Case
          </Button>
        </Toolbar>

        <TableContainer>
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
                <TableCell>Type</TableCell>
                <TableCell>Applicant</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Priority</TableCell>
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
              {items.map((case_) => (
                <TableRow key={case_.id} hover>
                  <TableCell>{case_.caseNumber}</TableCell>
                  <TableCell>{case_.caseType}</TableCell>
                  <TableCell>{case_.applicant}</TableCell>
                  <TableCell>
                    <Chip
                      label={case_.status}
                      color={
                        case_.status === 'Approved' ? 'success' :
                        case_.status === 'Rejected' ? 'error' :
                        case_.status === 'Pending' ? 'warning' :
                        'default'
                      }
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={case_.priority}
                      color={
                        case_.priority === 'High' ? 'error' :
                        case_.priority === 'Medium' ? 'warning' :
                        'success'
                      }
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    {new Date(case_.dueDate).toLocaleDateString()}
                  </TableCell>
                  <TableCell>
                    <IconButton
                      size="small"
                      onClick={() => navigate(`/cases/${case_.id}`)}
                    >
                      <EditIcon />
                    </IconButton>
                    <IconButton
                      size="small"
                      onClick={() => handleDelete(case_.id)}
                    >
                      <DeleteIcon />
                    </IconButton>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>
    </Box>
  );
};

export default CaseList;
