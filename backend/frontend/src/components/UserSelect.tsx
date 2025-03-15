import React, { useState, useEffect } from 'react';
import { User } from '../types';

interface UserSelectProps {
  value: string;
  onChange: (value: string) => void;
  role: string;
  label: string;
  required?: boolean;
  error?: string;
}

const UserSelect: React.FC<UserSelectProps> = ({
  value,
  onChange,
  role,
  label,
  required = false,
  error,
}) => {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState('');

  useEffect(() => {
    const fetchUsers = async () => {
      try {
        const response = await fetch(`/api/users?role=${role}`);
        const data = await response.json();
        if (data.success) {
          setUsers(data.data);
        } else {
          setFetchError(data.message || 'Failed to fetch users');
        }
      } catch (err) {
        setFetchError('Error fetching users');
        console.error('Error fetching users:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchUsers();
  }, [role]);

  if (loading) {
    return (
      <div className="animate-pulse">
        <div className="h-10 bg-gray-200 rounded"></div>
      </div>
    );
  }

  if (fetchError) {
    return (
      <div className="text-red-500 text-sm">
        {fetchError}
      </div>
    );
  }

  return (
    <div>
      <label className="block text-sm font-medium text-gray-700">
        {label}
        {required && <span className="text-red-500">*</span>}
      </label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={`mt-1 block w-full border rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 ${
          error ? 'border-red-300' : 'border-gray-300'
        }`}
        required={required}
      >
        <option value="">Select {label}</option>
        {users.map((user) => (
          <option key={user.id} value={user.id}>
            {user.firstName} {user.lastName}
          </option>
        ))}
      </select>
      {error && (
        <p className="mt-1 text-sm text-red-500">
          {error}
        </p>
      )}
    </div>
  );
};

export default UserSelect;

