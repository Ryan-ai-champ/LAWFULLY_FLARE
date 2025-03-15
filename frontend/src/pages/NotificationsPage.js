import React, { useState, useEffect } from 'react';
import { 
  Container, 
  Typography, 
  Paper, 
  List, 
  ListItem, 
  ListItemText, 
  ListItemSecondaryAction, 
  IconButton, 
  Divider,
  Button,
  Box,
  Chip,
  CircularProgress
} from '@mui/material';
import { 
  CheckCircle as CheckCircleIcon,
  Notifications as NotificationsIcon
} from '@mui/icons-material';

// In a real application, this would be fetched from an API
const mockNotifications = [
  {
    id: 1,
    title: 'Case Status Update',
    message: 'Your I-485 application has been received by USCIS.',
    timestamp: '2023-05-15T10:30:00',
    isRead: false,
    type: 'case_update'
  },
  {
    id: 2,
    title: 'Document Request',
    message: 'Please upload your birth certificate within 30 days.',
    timestamp: '2023-05-14T14:45:00',
    isRead: false,
    type: 'document_request'
  },
  {
    id: 3,
    title: 'Appointment Reminder',
    message: 'You have a biometrics appointment scheduled for June 1, 2023 at 10:00 AM.',
    timestamp: '2023-05-10T09:15:00',
    isRead: true,
    type: 'appointment'
  },
  {
    id: 4,
    title: 'Payment Confirmation',
    message: 'Your payment of $725 for I-485 filing fees has been received.',
    timestamp: '2023-05-05T16:20:00',
    isRead: true,
    type: 'payment'
  }
];

const NotificationsPage = () => {
  const [notifications, setNotifications] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Simulate API call to fetch notifications
    const fetchNotifications = async () => {
      setLoading(true);
      try {
        // In a real app, this would be an API call
        // const response = await axios.get('/api/notifications');
        // setNotifications(response.data);
        
        // Using mock data for demonstration
        setTimeout(() => {
          setNotifications(mockNotifications);
          setLoading(false);
        }, 800);
      } catch (error) {
        console.error('Error fetching notifications:', error);
        setLoading(false);
      }
    };

    fetchNotifications();
  }, []);

  const handleMarkAsRead = (id) => {
    // Update the local state
    setNotifications(
      notifications.map(notification => 
        notification.id === id 
          ? { ...notification, isRead: true } 
          : notification
      )
    );

    // In a real app, you would also update this on the server
    // axios.patch(`/api/notifications/${id}`, { isRead: true });
  };

  const handleMarkAllAsRead = () => {
    // Update all notifications to read
    setNotifications(
      notifications.map(notification => ({ ...notification, isRead: true }))
    );

    // In a real app, you would also update this on the server
    // axios.patch('/api/notifications/mark-all-read');
  };

  const getNotificationTypeColor = (type) => {
    switch(type) {
      case 'case_update':
        return 'primary';
      case 'document_request':
        return 'error';
      case 'appointment':
        return 'warning';
      case 'payment':
        return 'success';
      default:
        return 'default';
    }
  };

  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp);
    return date.toLocaleString();
  };

  const unreadCount = notifications.filter(notification => !notification.isRead).length;

  return (
    <Container maxWidth="md" sx={{ mt: 4, mb: 4 }}>
      <Paper elevation={3} sx={{ p: 3 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center' }}>
            <NotificationsIcon sx={{ mr: 1, color: 'primary.main' }} />
            <Typography variant="h5" component="h1">
              Notifications
            </Typography>
            {unreadCount > 0 && (
              <Chip 
                label={`${unreadCount} unread`} 
                color="primary" 
                size="small" 
                sx={{ ml: 2 }}
              />
            )}
          </Box>
          {unreadCount > 0 && (
            <Button 
              variant="outlined" 
              color="primary" 
              onClick={handleMarkAllAsRead}
            >
              Mark All as Read
            </Button>
          )}
        </Box>
        
        {loading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
            <CircularProgress />
          </Box>
        ) : notifications.length > 0 ? (
          <List>
            {notifications.map((notification, index) => (
              <React.Fragment key={notification.id}>
                <ListItem 
                  alignItems="flex-start"
                  sx={{ 
                    bgcolor: notification.isRead ? 'inherit' : 'rgba(25, 118, 210, 0.08)',
                    transition: 'background-color 0.3s'
                  }}
                >
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center', mb: 0.5 }}>
                        <Typography variant="subtitle1" component="span" sx={{ fontWeight: notification.isRead ? 'normal' : 'bold' }}>
                          {notification.title}
                        </Typography>
                        <Chip 
                          label={notification.type.replace('_', ' ')} 
                          color={getNotificationTypeColor(notification.type)} 
                          size="small" 
                          sx={{ ml: 2 }}
                        />
                      </Box>
                    }
                    secondary={
                      <>
                        <Typography variant="body2" component="span" sx={{ display: 'block', mb: 1 }}>
                          {notification.message}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {formatTimestamp(notification.timestamp)}
                        </Typography>
                      </>
                    }
                  />
                  <ListItemSecondaryAction>
                    {!notification.isRead && (
                      <IconButton 
                        edge="end" 
                        aria-label="mark as read"
                        onClick={() => handleMarkAsRead(notification.id)}
                        color="primary"
                      >
                        <CheckCircleIcon />
                      </IconButton>
                    )}
                  </ListItemSecondaryAction>
                </ListItem>
                {index < notifications.length - 1 && <Divider variant="inset" component="li" />}
              </React.Fragment>
            ))}
          </List>
        ) : (
          <Box sx={{ p: 3, textAlign: 'center' }}>
            <Typography variant="body1" color="text.secondary">
              You have no notifications at this time.
            </Typography>
          </Box>
        )}
      </Paper>
    </Container>
  );
};

export default NotificationsPage;

