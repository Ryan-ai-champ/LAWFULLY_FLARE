import React, { useState, useEffect } from 'react';
import { 
  Box, 
  Container, 
  Grid, 
  Paper, 
  Typography, 
  AppBar, 
  Toolbar, 
  IconButton, 
  Button, 
  Drawer, 
  List, 
  ListItem, 
  ListItemIcon, 
  ListItemText, 
  Divider,
  Card,
  CardContent,
  CardHeader,
  Avatar,
  Badge,
  CircularProgress
} from '@mui/material';
import { 
  Menu as MenuIcon, 
  Notifications as NotificationsIcon, 
  Dashboard as DashboardIcon,
  Person as PersonIcon,
  Folder as FolderIcon,
  Description as DescriptionIcon,
  Forum as ForumIcon,
  ExitToApp as LogoutIcon
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

// Sample case data (replace with actual API call in production)
const SAMPLE_CASES = [
  {
    id: 'C-202301-001',
    type: 'Green Card',
    client: 'John Smith',
    status: 'In Review',
    dueDate: '2023-08-15',
    priority: 'High'
  },
  {
    id: 'C-202301-002',
    type: 'Citizenship',
    client: 'Maria Rodriguez',
    status: 'Pending Documents',
    dueDate: '2023-09-20',
    priority: 'Medium'
  },
  {
    id: 'C-202301-003',
    type: 'Work Visa',
    client: 'Ahmed Khan',
    status: 'Draft',
    dueDate: '2023-08-30',
    priority: 'Low'
  },
  {
    id: 'C-202301-004',
    type: 'Family Petition',
    client: 'Sarah Johnson',
    status: 'Submitted',
    dueDate: '2023-07-28',
    priority: 'High'
  }
];

// Sample notifications (replace with actual data in production)
const SAMPLE_NOTIFICATIONS = [
  { id: 1, message: 'USCIS has issued an RFE for case C-202301-001', date: '2023-07-25' },
  { id: 2, message: 'Case C-202301-002 documents due in 5 days', date: '2023-07-24' },
  { id: 3, message: 'New forum post in community section', date: '2023-07-23' }
];

const Dashboard = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [cases, setCases] = useState(SAMPLE_CASES);
  const [notifications, setNotifications] = useState(SAMPLE_NOTIFICATIONS);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [user, setUser] = useState({
    name: 'John Doe',
    role: 'Attorney',
    avatar: '/avatar.jpg' // Replace with actual avatar path or initial logic
  });

  // In a real application, fetch data from APIs
  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        // Replace with actual API endpoints
        // const casesResponse = await axios.get('/api/cases');
        // const notificationsResponse = await axios.get('/api/notifications');
        // setCases(casesResponse.data);
        // setNotifications(notificationsResponse.data);
        
        // Simulating API call delay
        setTimeout(() => {
          setCases(SAMPLE_CASES);
          setNotifications(SAMPLE_NOTIFICATIONS);
          setLoading(false);
        }, 1000);
      } catch (error) {
        console.error('Error fetching dashboard data:', error);
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  const handleDrawerToggle = () => {
    setDrawerOpen(!drawerOpen);
  };

  const handleLogout = () => {
    // Handle logout logic here
    // localStorage.removeItem('token');
    navigate('/login');
  };

  const handleCaseClick = (caseId) => {
    navigate(`/cases/${caseId}`);
  };

  const getPriorityColor = (priority) => {
    switch (priority.toLowerCase()) {
      case 'high':
        return '#d32f2f'; // red
      case 'medium':
        return '#f57c00'; // orange
      case 'low':
        return '#388e3c'; // green
      default:
        return '#757575'; // grey
    }
  };

  const getStatusColor = (status) => {
    switch (status.toLowerCase()) {
      case 'in review':
        return '#1976d2'; // blue
      case 'pending documents':
        return '#f57c00'; // orange
      case 'draft':
        return '#757575'; // grey
      case 'submitted':
        return '#388e3c'; // green
      default:
        return '#757575'; // grey
    }
  };

  const drawer = (
    <Box sx={{ width: 250 }}>
      <Box sx={{ p: 2, display: 'flex', alignItems: 'center', gap: 2 }}>
        <Avatar src={user.avatar} alt={user.name} />
        <Box>
          <Typography variant="subtitle1">{user.name}</Typography>
          <Typography variant="body2" color="text.secondary">{user.role}</Typography>
        </Box>
      </Box>
      <Divider />
      <List>
        <ListItem button selected>
          <ListItemIcon>
            <DashboardIcon />
          </ListItemIcon>
          <ListItemText primary="Dashboard" />
        </ListItem>
        <ListItem button onClick={() => navigate('/cases')}>
          <ListItemIcon>
            <FolderIcon />
          </ListItemIcon>
          <ListItemText primary="Cases" />
        </ListItem>
        <ListItem button onClick={() => navigate('/documents')}>
          <ListItemIcon>
            <DescriptionIcon />
          </ListItemIcon>
          <ListItemText primary="Documents" />
        </ListItem>
        <ListItem button onClick={() => navigate('/forum')}>
          <ListItemIcon>
            <ForumIcon />
          </ListItemIcon>
          <ListItemText primary="Community Forum" />
        </ListItem>
        <ListItem button onClick={() => navigate('/profile')}>
          <ListItemIcon>
            <PersonIcon />
          </ListItemIcon>
          <ListItemText primary="Profile" />
        </ListItem>
      </List>
      <Divider />
      <List>
        <ListItem button onClick={handleLogout}>
          <ListItemIcon>
            <LogoutIcon />
          </ListItemIcon>
          <ListItemText primary="Logout" />
        </ListItem>
      </List>
    </Box>
  );

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      {/* App Bar */}
      <AppBar position="fixed">
        <Toolbar>
          <IconButton
            color="inherit"
            edge="start"
            onClick={handleDrawerToggle}
            sx={{ mr: 2 }}
          >
            <MenuIcon />
          </IconButton>
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            Immigration Platform
          </Typography>
          <IconButton color="inherit">
            <Badge badgeContent={notifications.length} color="error">
              <NotificationsIcon />
            </Badge>
          </IconButton>
          <Button color="inherit" onClick={handleLogout}>Logout</Button>
        </Toolbar>
      </AppBar>

      {/* Drawer */}
      <Drawer
        variant="temporary"
        open={drawerOpen}
        onClose={handleDrawerToggle}
        ModalProps={{
          keepMounted: true, // Better open performance on mobile
        }}
        sx={{
          '& .MuiDrawer-paper': { width: 250 },
        }}
      >
        {drawer}
      </Drawer>

      {/* Main Content */}
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: 3,
          mt: 8, // Space for the AppBar
        }}
      >
        <Container maxWidth="lg">
          {loading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', my: 4 }}>
              <CircularProgress />
            </Box>
          ) : (
            <>
              {/* Welcome Section */}
              <Paper sx={{ p: 3, mb: 3 }}>
                <Typography variant="h4" gutterBottom>
                  Welcome back, {user.name}!
                </Typography>
                <Typography variant="body1">
                  You have {cases.length} active cases and {notifications.length} new notifications.
                </Typography>
              </Paper>

              <Grid container spacing={3}>
                {/* Cases Overview */}
                <Grid item xs={12} md={8}>
                  <Paper sx={{ p: 2 }}>
                    <Typography variant="h6" gutterBottom>
                      Recent Cases
                    </Typography>
                    <Divider sx={{ mb: 2 }} />
                    {cases.map((caseItem) => (
                      <Card 
                        key={caseItem.id} 
                        sx={{ 
                          mb: 2, 
                          cursor: 'pointer',
                          '&:hover': {
                            boxShadow: 4
                          },
                          borderLeft: 4,
                          borderColor: getPriorityColor(caseItem.priority)
                        }}
                        onClick={() => handleCaseClick(caseItem.id)}
                      >
                        <CardContent sx={{ p: 2 }}>
                          <Grid container alignItems="center">
                            <Grid item xs={6}>
                              <Typography variant="subtitle1">{caseItem.client}</Typography>
                              <Typography variant="body2">{caseItem.type} - {caseItem.id}</Typography>
                            </Grid>
                            <Grid item xs={3}>
                              <Typography 
                                variant="body2" 
                                sx={{ 
                                  color: getStatusColor(caseItem.status),
                                  fontWeight: 'bold' 
                                }}
                              >
                                {caseItem.status}
                              </Typography>
                            </Grid>
                            <Grid item xs={3} sx={{ textAlign: 'right' }}>
                              <Typography variant="body2">
                                Due: {new Date(caseItem.dueDate).toLocaleDateString()}
                              </Typography>
                            </Grid>
                          </Grid>
                        </CardContent>
                      </Card>
                    ))}
                    <Box sx={{ mt: 2, textAlign: 'center' }}>
                      <Button 
                        variant="outlined" 
                        onClick={() => navigate('/cases')}
                      >
                        View All Cases
                      </Button>
                    </Box>
                  </Paper>
                </Grid>

                {/* Notifications & Quick Actions */}
                <Grid item xs={12} md={4}>
                  <Paper sx={{ p: 2, mb: 3 }}>
                    <Typography variant="h6" gutterBottom>
                      Notifications
                    </Typography>
                    <Divider sx={{ mb: 2 }} />
                    {notifications.map((notification) => (
                      <Box 
                        key={notification.id} 
                        sx={{ 
                          mb: 2, 
                          p: 1,
                          borderRadius: 1,
                          bgcolor: 'rgba(0, 0, 0, 0.03)'
                        }}
                      >
                        <Typography variant="body2">{notification.message}</Typography>
                        <Typography variant="caption" color="text.secondary">
                          {new Date(notification.date).toLocaleDateString()}
                        </Typography>
                      </Box>
                    ))}
                  </Paper>

                  <Paper sx={{ p: 2 }}>
                    <Typography variant="h6" gutterBottom>
                      Quick Actions
                    </Typography>
                    <Divider sx={{ mb: 2 }} />
                    <List sx={{ p: 0 }}>
                      <ListItem button onClick={() => navigate('/cases/new')}>
                        <ListItemText primary="Create New Case" />
                      </ListItem>
                      <ListItem button onClick={() => navigate('/documents/upload')}>
                        <ListItemText primary="Upload Documents" />
                      </ListItem>
                      <ListItem button onClick={() => navigate('/forum/new')}>
                        <ListItemText primary="Post to Forum" />
                      </ListItem>
                    </List>
                  </Paper>
                </Grid>
              </Grid>
            </>
          )}
        </Container>
      </Box>
    </Box>
  );
};

export default Dashboard;

