import React, { useState, useEffect } from 'react';
import { 
  Container, 
  Typography, 
  Button, 
  Paper, 
  Table, 
  TableBody, 
  TableCell, 
  TableContainer, 
  TableHead, 
  TableRow,
  TextField,
  Box,
  CircularProgress,
  IconButton
} from '@mui/material';
import { 
  Search as SearchIcon,
  Delete as DeleteIcon,
  Visibility as ViewIcon,
  Download as DownloadIcon
} from '@mui/icons-material';

// Mock data - replace with API calls in production
const MOCK_DOCUMENTS = [
  { id: 1, name: 'Passport.pdf', type: 'ID', uploadDate: '2023-05-15', size: '2.4 MB' },
  { id: 2, name: 'Birth Certificate.pdf', type: 'ID', uploadDate: '2023-05-16', size: '1.8 MB' },
  { id: 3, name: 'Employment Letter.pdf', type: 'Employment', uploadDate: '2023-05-20', size: '1.2 MB' },
  { id: 4, name: 'Tax Return 2022.pdf', type: 'Financial', uploadDate: '2023-05-22', size: '3.5 MB' },
  { id: 5, name: 'Medical Exam.pdf', type: 'Medical', uploadDate: '2023-06-01', size: '4.1 MB' },
];

const DocumentsPage = () => {
  const [documents, setDocuments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [fileToUpload, setFileToUpload] = useState(null);

  useEffect(() => {
    // Simulate API call
    setTimeout(() => {
      setDocuments(MOCK_DOCUMENTS);
      setLoading(false);
    }, 1000);
  }, []);

  const handleSearch = (e) => {
    setSearchTerm(e.target.value);
  };

  const handleFileChange = (e) => {
    if (e.target.files[0]) {
      setFileToUpload(e.target.files[0]);
    }
  };

  const handleUpload = () => {
    if (fileToUpload) {
      // Simulate document upload
      const newDoc = {
        id: documents.length + 1,
        name: fileToUpload.name,
        type: 'Other',
        uploadDate: new Date().toISOString().split('T')[0],
        size: `${(fileToUpload.size / (1024 * 1024)).toFixed(1)} MB`
      };
      
      setDocuments([...documents, newDoc]);
      setFileToUpload(null);
      
      // Reset file input
      document.getElementById('document-upload').value = '';
    }
  };

  const handleDelete = (id) => {
    setDocuments(documents.filter(doc => doc.id !== id));
  };

  const filteredDocuments = documents.filter(doc => 
    doc.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    doc.type.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Typography variant="h4" gutterBottom>
        Documents
      </Typography>
      
      {/* Upload Section */}
      <Paper sx={{ p: 2, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Upload New Document
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <input
            accept="application/pdf,image/*"
            style={{ display: 'none' }}
            id="document-upload"
            type="file"
            onChange={handleFileChange}
          />
          <label htmlFor="document-upload">
            <Button variant="contained" component="span">
              Select File
            </Button>
          </label>
          <Typography variant="body2">
            {fileToUpload ? fileToUpload.name : 'No file selected'}
          </Typography>
          <Button 
            variant="contained" 
            color="primary" 
            onClick={handleUpload}
            disabled={!fileToUpload}
          >
            Upload
          </Button>
        </Box>
      </Paper>
      
      {/* Search and Filter */}
      <Box sx={{ display: 'flex', mb: 3 }}>
        <TextField
          label="Search Documents"
          variant="outlined"
          fullWidth
          value={searchTerm}
          onChange={handleSearch}
          InputProps={{
            startAdornment: <SearchIcon sx={{ mr: 1, color: 'gray' }} />,
          }}
        />
      </Box>
      
      {/* Documents Table */}
      <Paper sx={{ width: '100%', overflow: 'hidden' }}>
        {loading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
            <CircularProgress />
          </Box>
        ) : (
          <TableContainer sx={{ maxHeight: 440 }}>
            <Table stickyHeader aria-label="documents table">
              <TableHead>
                <TableRow>
                  <TableCell>Name</TableCell>
                  <TableCell>Type</TableCell>
                  <TableCell>Upload Date</TableCell>
                  <TableCell>Size</TableCell>
                  <TableCell align="center">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredDocuments.length > 0 ? (
                  filteredDocuments.map((doc) => (
                    <TableRow key={doc.id} hover>
                      <TableCell>{doc.name}</TableCell>
                      <TableCell>{doc.type}</TableCell>
                      <TableCell>{doc.uploadDate}</TableCell>
                      <TableCell>{doc.size}</TableCell>
                      <TableCell align="center">
                        <IconButton aria-label="view" size="small">
                          <ViewIcon />
                        </IconButton>
                        <IconButton aria-label="download" size="small">
                          <DownloadIcon />
                        </IconButton>
                        <IconButton 
                          aria-label="delete" 
                          size="small" 
                          color="error"
                          onClick={() => handleDelete(doc.id)}
                        >
                          <DeleteIcon />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                  ))
                ) : (
                  <TableRow>
                    <TableCell colSpan={5} align="center">
                      No documents found
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Paper>
    </Container>
  );
};

export default DocumentsPage;

import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import {
  Box,
  Typography,
  Button,
  Paper,
  Grid,
  TextField,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  CircularProgress
} from '@mui/material';
import {
  Search as SearchIcon,
  FileUpload as FileUploadIcon,
  Delete as DeleteIcon,
  Download as DownloadIcon,
  FilterList as FilterListIcon,
  Clear as ClearIcon
} from '@mui/icons-material';

// Mock data - would be replaced with actual API calls
const mockDocuments = [
  { id: 1, name: 'Passport Copy.pdf', category: 'Identification', uploadDate: '2023-03-15', size: '2.4 MB', status: 'Verified' },
  { id: 2, name: 'Birth Certificate.pdf', category: 'Identification', uploadDate: '2023-02-28', size: '1.7 MB', status: 'Pending' },
  { id: 3, name: 'Employment Letter.docx', category: 'Employment', uploadDate: '2023-04-01', size: '0.8 MB', status: 'Verified' },
  { id: 4, name: 'Bank Statement.pdf', category: 'Financial', uploadDate: '2023-04-10', size: '3.5 MB', status: 'Pending' },
  { id: 5, name: 'Marriage Certificate.pdf', category: 'Relationship', uploadDate: '2023-03-22', size: '1.2 MB', status: 'Rejected' },
  { id: 6, name: 'Tax Returns 2022.pdf', category: 'Financial', uploadDate: '2023-04-05', size: '4.2 MB', status: 'Verified' },
  { id: 7, name: 'Medical Exam.pdf', category: 'Medical', uploadDate: '2023-03-30', size: '5.1 MB', status: 'Pending' },
  { id: 8, name: 'Academic Transcript.pdf', category: 'Education', uploadDate: '2023-03-18', size: '1.9 MB', status: 'Verified' },
  { id: 9, name: 'Lease Agreement.pdf', category: 'Housing', uploadDate: '2023-04-12', size: '2.8 MB', status: 'Pending' },
  { id: 10, name: 'I-20 Form.pdf', category: 'Immigration', uploadDate: '2023-03-25', size: '0.5 MB', status: 'Verified' },
];

const categories = ['All', 'Identification', 'Employment', 'Financial', 'Relationship', 'Medical', 'Education', 'Housing', 'Immigration'];
const statuses = ['All', 'Verified', 'Pending', 'Rejected'];

const DocumentsPage = () => {
  const dispatch = useDispatch();
  // const { documents, loading, error } = useSelector((state) => state.documents);
  const [documents, setDocuments] = useState(mockDocuments);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(5);
  const [searchTerm, setSearchTerm] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('All');
  const [statusFilter, setStatusFilter] = useState('All');
  const [openUploadDialog, setOpenUploadDialog] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [selectedCategory, setSelectedCategory] = useState('');
  const [uploadProgress, setUploadProgress] = useState(0);
  const [isUploading, setIsUploading] = useState(false);

  // Fetch documents on component mount
  useEffect(() => {
    // In a real app, this would dispatch an action to fetch documents from the API
    // dispatch(fetchDocuments());
    
    // Simulating API call with mock data
    setLoading(true);
    setTimeout(() => {
      setDocuments(mockDocuments);
      setLoading(false);
    }, 500);
  }, [dispatch]);

  const handleChangePage = (event, newPage) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const handleSearchChange = (event) => {
    setSearchTerm(event.target.value);
    setPage(0);
  };

  const handleCategoryFilterChange = (event) => {
    setCategoryFilter(event.target.value);
    setPage(0);
  };

  const handleStatusFilterChange = (event) => {
    setStatusFilter(event.target.value);
    setPage(0);
  };

  const handleClearFilters = () => {
    setSearchTerm('');
    setCategoryFilter('All');
    setStatusFilter('All');
    setPage(0);
  };

  const handleOpenUploadDialog = () => {
    setOpenUploadDialog(true);
  };

  const handleCloseUploadDialog = () => {
    setOpenUploadDialog(false);
    setSelectedFile(null);
    setSelectedCategory('');
    setUploadProgress(0);
    setIsUploading(false);
  };

  const handleFileSelect = (event) => {
    if (event.target.files.length > 0) {
      setSelectedFile(event.target.files[0]);
    }
  };

  const handleCategoryChange = (event) => {
    setSelectedCategory(event.target.value);
  };

  const handleUploadDocument = () => {
    if (!selectedFile || !selectedCategory) {
      return;
    }

    // In a real app, this would dispatch an action to upload the document to the API
    // dispatch(uploadDocument(selectedFile, selectedCategory));
    
    // Simulating upload progress
    setIsUploading(true);
    const interval = setInterval(() => {
      setUploadProgress((prevProgress) => {
        const newProgress = prevProgress + 10;
        if (newProgress >= 100) {
          clearInterval(interval);
          
          // Simulate adding the new document to the list
          setTimeout(() => {
            const newDocument = {
              id: documents.length + 1,
              name: selectedFile.name,
              category: selectedCategory,
              uploadDate: new Date().toISOString().split('T')[0],
              size: `${(selectedFile.size / (1024 * 1024)).toFixed(1)} MB`,
              status: 'Pending'
            };
            setDocuments([...documents, newDocument]);
            setIsUploading(false);
            handleCloseUploadDialog();
          }, 500);
          
          return 100;
        }
        return newProgress;
      });
    }, 300);
  };

  const handleDownloadDocument = (documentId) => {
    // In a real app, this would dispatch an action to download the document
    // dispatch(downloadDocument(documentId));
    
    console.log(`Downloading document with ID: ${documentId}`);
    // Mock download action
    alert(`Document download started for ID: ${documentId}`);
  };

  const handleDeleteDocument = (documentId) => {
    // In a real app, this would dispatch an action to delete the document
    // dispatch(deleteDocument(documentId));
    
    // Simulating document deletion
    setDocuments(documents.filter(doc => doc.id !== documentId));
  };

  // Apply filters to documents
  const filteredDocuments = documents.filter(doc => {
    const matchesSearch = doc.name.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = categoryFilter === 'All' || doc.category === categoryFilter;
    const matchesStatus = statusFilter === 'All' || doc.status === statusFilter;
    return matchesSearch && matchesCategory && matchesStatus;
  });

  // Pagination
  const paginatedDocuments = filteredDocuments.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );

  // Render status chip with appropriate color
  const renderStatusChip = (status) => {
    let color;
    switch (status) {
      case 'Verified':
        color = 'success';
        break;
      case 'Pending':
        color = 'warning';
        break;
      case 'Rejected':
        color = 'error';
        break;
      default:
        color = 'default';
    }
    return <Chip label={status} color={color} size="small" />;
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ p: 3 }}>
        <Typography color="error" variant="h6">
          Error loading documents: {error}
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom component="div">
        Document Management
      </Typography>
      
      <Paper sx={{ p: 2, mb: 3 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} sm={4}>
            <TextField
              fullWidth
              label="Search Documents"
              variant="outlined"
              value={searchTerm}
              onChange={handleSearchChange}
              InputProps={{
                startAdornment: <SearchIcon color="action" sx={{ mr: 1 }} />,
                endAdornment: searchTerm && (
                  <IconButton size="small" onClick={() => setSearchTerm('')}>
                    <ClearIcon />
                  </IconButton>
                )
              }}
            />
          </Grid>
          <Grid item xs={12} sm={3}>
            <FormControl fullWidth variant="outlined">
              <InputLabel>Category</InputLabel>
              <Select
                value={categoryFilter}
                onChange={handleCategoryFilterChange}
                label="Category"
              >
                {categories.map(category => (
                  <MenuItem key={category} value={category}>
                    {category}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} sm={3}>
            <FormControl fullWidth variant="outlined">
              <InputLabel>Status</InputLabel>
              <Select
                value={statusFilter}
                onChange={handleStatusFilterChange}
                label="Status"
              >
                {statuses.map(status => (
                  <MenuItem key={status} value={status}>
                    {status}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={6} sm={1}>
            <Button
              fullWidth
              variant="outlined"
              onClick={handleClearFilters}
              startIcon={<ClearIcon />}
            >
              Clear
            </Button>
          </Grid>
          <Grid item xs={6} sm={1}>
            <Button
              fullWidth
              variant="contained"
              color="primary"
              onClick={handleOpenUploadDialog}
              startIcon={<FileUploadIcon />}
            >
              Upload
            </Button>
          </Grid>
        </Grid>
      </Paper>

      <TableContainer component={Paper}>
        <Table aria-label="documents table">
          <TableHead>
            <TableRow>
              <TableCell>Document Name</TableCell>
              <TableCell>Category</TableCell>
              <TableCell>Upload Date</TableCell>
              <TableCell>Size</TableCell>
              <TableCell>Status</TableCell>
              <TableCell align="center">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {paginatedDocuments.length > 0 ? (
              paginatedDocuments.map((doc) => (
                <TableRow key={doc.id}>
                  <TableCell component="th" scope="row">
                    {doc.name}
                  </TableCell>
                  <TableCell>{doc.category}</TableCell>
                  <TableCell>{doc.uploadDate}</TableCell>
                  <TableCell>{doc.size}</TableCell>
                  <TableCell>{renderStatusChip(doc.status)}</TableCell>
                  <TableCell align="center">
                    <IconButton
                      color="primary"
                      aria-label="download document"
                      onClick={() => handleDownloadDocument(doc.id)}
                    >
                      <DownloadIcon />
                    </IconButton>
                    <IconButton
                      color="error"
                      aria-label="delete document"
                      onClick={() => handleDeleteDocument(doc.id)}
                    >
                      <DeleteIcon />
                    </IconButton>
                  </TableCell>
                </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell colSpan={6} align="center">
                  <Typography variant="body1" sx={{ py: 2 }}>
                    No documents found. Upload a document or adjust your filters.
                  </Typography>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
        <TablePagination
          rowsPerPageOptions={[5, 10, 25]}
          component="div"
          count={filteredDocuments.length}
          rowsPerPage={rowsPerPage}
          page={page}
          onPageChange={handleChangePage}
          onRowsPerPageChange={handleChangeRowsPerPage}
        />
      </TableContainer>

      {/* Upload Document Dialog */}
      <Dialog open={openUploadDialog} onClose={handleCloseUploadDialog} maxWidth="sm" fullWidth>
        <DialogTitle>Upload Document</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 1 }}>
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <Button
                  variant="outlined"
                  component="label"
                  fullWidth
                  sx={{ py: 1.5 }}
                >
                  {selectedFile ? selectedFile.name : "Choose File"}
                  <input
                    type="file"
                    hidden
                    onChange={handleFileSelect}
                  />
                </Button>
              </Grid>
              <Grid item xs={12}>
                <FormControl fullWidth>
                  <InputLabel>Document Category</InputLabel>
                  <Select
                    value={selectedCategory}
                    onChange={handleCategoryChange}
                    label="Document Category"
                  >
                    {categories.slice(1).map(category => (
                      <MenuItem key={category} value={category}>
                        {category}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              {isUploading && (

import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { 
  Box, 
  Typography, 
  Button, 
  Grid, 
  TextField, 
  Paper, 
  Table, 
  TableBody, 
  TableCell, 
  TableContainer, 
  TableHead, 
  TableRow,
  TablePagination,
  IconButton,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Alert,
  Snackbar,
  CircularProgress
} from '@mui/material';
import {
  Search as SearchIcon,
  CloudUpload as CloudUploadIcon,
  Visibility as VisibilityIcon,
  GetApp as DownloadIcon,
  Delete as DeleteIcon,
  FilterList as FilterListIcon
} from '@mui/icons-material';

// Mock data for demonstration - in a real app, this would come from Redux store
const initialDocuments = [
  { 
    id: 1, 
    name: 'Birth Certificate.pdf', 
    type: 'Identification', 
    uploadDate: '2023-11-15', 
    size: '1.2 MB',
    status: 'Verified',
    caseId: 'IM-2023-001'
  },
  { 
    id: 2, 
    name: 'Passport.pdf', 
    type: 'Identification', 
    uploadDate: '2023-11-14', 
    size: '2.5 MB',
    status: 'Pending Review',
    caseId: 'IM-2023-001'
  },
  { 
    id: 3, 
    name: 'Marriage Certificate.pdf', 
    type: 'Relationship', 
    uploadDate: '2023-11-10', 
    size: '0.8 MB',
    status: 'Verified',
    caseId: 'IM-2023-002'
  },
  { 
    id: 4, 
    name: 'Employment Letter.pdf', 
    type: 'Employment', 
    uploadDate: '2023-11-05', 
    size: '1.5 MB',
    status: 'Requires Update',
    caseId: 'IM-2023-001'
  },
  { 
    id: 5, 
    name: 'Tax Returns 2022.pdf', 
    type: 'Financial', 
    uploadDate: '2023-10-28', 
    size: '3.2 MB',
    status: 'Verified',
    caseId: 'IM-2023-003'
  },
  { 
    id: 6, 
    name: 'Bank Statements.pdf', 
    type: 'Financial', 
    uploadDate: '2023-10-25', 
    size: '4.5 MB',
    status: 'Pending Review',
    caseId: 'IM-2023-003'
  },
  { 
    id: 7, 
    name: 'Medical Examination.pdf', 
    type: 'Medical', 
    uploadDate: '2023-10-20', 
    size: '2.8 MB',
    status: 'Verified',
    caseId: 'IM-2023-002'
  },
  { 
    id: 8, 
    name: 'Police Clearance.pdf', 
    type: 'Background Check', 
    uploadDate: '2023-10-15', 
    size: '1.1 MB',
    status: 'Verified',
    caseId: 'IM-2023-001'
  },
];

const DocumentsPage = () => {
  const dispatch = useDispatch();
  // In a real app, we would fetch documents from the Redux store
  // const { documents, loading, error } = useSelector(state => state.documents);
  
  const [documents, setDocuments] = useState(initialDocuments);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  const [searchTerm, setSearchTerm] = useState('');
  const [filteredDocuments, setFilteredDocuments] = useState(documents);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(5);
  const [openUploadDialog, setOpenUploadDialog] = useState(false);
  const [openViewDialog, setOpenViewDialog] = useState(false);
  const [selectedDocument, setSelectedDocument] = useState(null);
  const [uploadFile, setUploadFile] = useState(null);
  const [documentType, setDocumentType] = useState('');
  const [caseId, setCaseId] = useState('');
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });
  
  // Filter types for dropdown
  const documentTypes = ['All', 'Identification', 'Relationship', 'Employment', 'Financial', 'Medical', 'Background Check'];
  const [selectedType, setSelectedType] = useState('All');
  
  // Status filters
  const statusTypes = ['All', 'Verified', 'Pending Review', 'Requires Update'];
  const [selectedStatus, setSelectedStatus] = useState('All');

  useEffect(() => {
    // In a real app, this would dispatch an action to fetch documents
    // dispatch(fetchDocuments());
    
    // For demonstration, we're using the mock data
    setLoading(true);
    setTimeout(() => {
      setDocuments(initialDocuments);
      setFilteredDocuments(initialDocuments);
      setLoading(false);
    }, 500);
  }, [dispatch]);

  useEffect(() => {
    // Filter documents based on search term, type, and status
    const filtered = documents.filter(doc => {
      const matchesSearch = doc.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          doc.caseId.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesType = selectedType === 'All' || doc.type === selectedType;
      const matchesStatus = selectedStatus === 'All' || doc.status === selectedStatus;
      
      return matchesSearch && matchesType && matchesStatus;
    });
    
    setFilteredDocuments(filtered);
    setPage(0); // Reset to first page when filters change
  }, [searchTerm, documents, selectedType, selectedStatus]);

  const handleChangePage = (event, newPage) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const handleSearchChange = (event) => {
    setSearchTerm(event.target.value);
  };

  const handleTypeFilterChange = (event) => {
    setSelectedType(event.target.value);
  };

  const handleStatusFilterChange = (event) => {
    setSelectedStatus(event.target.value);
  };

  const handleUploadDialogOpen = () => {
    setOpenUploadDialog(true);
  };

  const handleUploadDialogClose = () => {
    setOpenUploadDialog(false);
    setUploadFile(null);
    setDocumentType('');
    setCaseId('');
  };

  const handleFileChange = (event) => {
    if (event.target.files && event.target.files[0]) {
      setUploadFile(event.target.files[0]);
    }
  };

  const handleDocumentTypeChange = (event) => {
    setDocumentType(event.target.value);
  };

  const handleCaseIdChange = (event) => {
    setCaseId(event.target.value);
  };

  const handleUploadSubmit = () => {
    if (!uploadFile || !documentType || !caseId) {
      setSnackbar({
        open: true,
        message: 'Please fill in all required fields',
        severity: 'error'
      });
      return;
    }

    // In a real app, this would dispatch an action to upload the document
    // dispatch(uploadDocument({ file: uploadFile, type: documentType, caseId }));
    
    // For demonstration, we're adding the new document to our mock data
    setLoading(true);
    setTimeout(() => {
      const newDocument = {
        id: documents.length + 1,
        name: uploadFile.name,
        type: documentType,
        uploadDate: new Date().toISOString().split('T')[0],
        size: `${(uploadFile.size / (1024 * 1024)).toFixed(1)} MB`,
        status: 'Pending Review',
        caseId
      };
      
      const updatedDocuments = [...documents, newDocument];
      setDocuments(updatedDocuments);
      setFilteredDocuments(updatedDocuments);
      
      setSnackbar({
        open: true,
        message: 'Document uploaded successfully!',
        severity: 'success'
      });
      
      handleUploadDialogClose();
      setLoading(false);
    }, 1000);
  };

  const handleViewDocument = (document) => {
    setSelectedDocument(document);
    setOpenViewDialog(true);
  };

  const handleViewDialogClose = () => {
    setOpenViewDialog(false);
    setSelectedDocument(null);
  };

  const handleDownloadDocument = (document) => {
    // In a real app, this would dispatch an action to download the document
    // dispatch(downloadDocument(document.id));
    
    setSnackbar({
      open: true,
      message: `Downloading ${document.name}...`,
      severity: 'info'
    });
  };

  const handleDeleteDocument = (document) => {
    // In a real app, this would dispatch an action to delete the document
    // dispatch(deleteDocument(document.id));
    
    // For demonstration, we're removing the document from our mock data
    setLoading(true);
    setTimeout(() => {
      const updatedDocuments = documents.filter(doc => doc.id !== document.id);
      setDocuments(updatedDocuments);
      setFilteredDocuments(updatedDocuments);
      
      setSnackbar({
        open: true,
        message: 'Document deleted successfully!',
        severity: 'success'
      });
      
      setLoading(false);
    }, 500);
  };

  const handleSnackbarClose = () => {
    setSnackbar({ ...snackbar, open: false });
  };

  const getStatusChipColor = (status) => {
    switch (status) {
      case 'Verified':
        return 'success';
      case 'Pending Review':
        return 'warning';
      case 'Requires Update':
        return 'error';
      default:
        return 'default';
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" component="h1" gutterBottom>
        Document Management
      </Typography>
      
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <SearchIcon sx={{ mr: 1 }} />
              <TextField
                fullWidth
                variant="outlined"
                placeholder="Search documents by name or case ID..."
                value={searchTerm}
                onChange={handleSearchChange}
                size="small"
              />
            </Box>
          </Paper>
        </Grid>
        
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
              <FormControl variant="outlined" size="small" sx={{ minWidth: 120, mr: 2 }}>
                <InputLabel id="document-type-filter-label">Document Type</InputLabel>
                <Select
                  labelId="document-type-filter-label"
                  value={selectedType}
                  onChange={handleTypeFilterChange}
                  label="Document Type"
                >
                  {documentTypes.map((type) => (
                    <MenuItem key={type} value={type}>{type}</MenuItem>
                  ))}
                </Select>
              </FormControl>
              
              <FormControl variant="outlined" size="small" sx={{ minWidth: 120, mr: 2 }}>
                <InputLabel id="status-filter-label">Status</InputLabel>
                <Select
                  labelId="status-filter-label"
                  value={selectedStatus}
                  onChange={handleStatusFilterChange}
                  label="Status"
                >
                  {statusTypes.map((status) => (
                    <MenuItem key={status} value={status}>{status}</MenuItem>
                  ))}
                </Select>
              </FormControl>
              
              <Button
                variant="contained"
                color="primary"
                startIcon={<CloudUploadIcon />}
                onClick={handleUploadDialogOpen}
              >
                Upload
              </Button>
            </Box>
          </Paper>
        </Grid>
      </Grid>
      
      <Paper>
        {loading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
            <CircularProgress />
          </Box>
        ) : error ? (
          <Alert severity="error" sx={{ m: 2 }}>
            {error}
          </Alert>
        ) : (
          <>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Document Name</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Case ID</TableCell>
                    <TableCell>Upload Date</TableCell>
                    <TableCell>Size</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell align="center">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {filteredDocuments
                    .slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage)
                    .map((document) => (
                      <TableRow key={document.id}>
                        <TableCell>{document.name}</TableCell>
                        <TableCell>{document.type}</TableCell>
                        <TableCell>{document.caseId}</TableCell>
                        <TableCell>{document.uploadDate}</TableCell>
                        <TableCell>{document.size}</TableCell>
                        <TableCell>
                          <Chip 
                            label={document.status} 
                            color={getStatusChipColor(document.status)} 
                            size="small" 
                          />
                        </TableCell>
                        <TableCell align="center">
                          <IconButton 
                            size="small" 
                            color="primary" 
                            onClick={() => handleViewDocument(document)}
                            title="View Document"
                          

