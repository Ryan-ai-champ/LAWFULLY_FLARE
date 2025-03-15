import React from 'react';
import { useAuth } from '../context/AuthContext';

const Dashboard = () => {
  const { user } = useAuth();

  return (
    <div>
      <h1>Dashboard</h1>
      <p>Welcome, {user.name}</p>
      <div>
        <h2>Your Content</h2>
        {/* Add user-specific content here */}
      </div>
    </div>
  );
};

export default Dashboard;

