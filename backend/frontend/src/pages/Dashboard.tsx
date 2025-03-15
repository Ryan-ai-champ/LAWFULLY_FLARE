import React, { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { getCases } from '../services/case.service';
import { Case } from '../types';

const Dashboard: React.FC = () => {
  const { user } = useAuth();
  const [cases, setCases] = useState<Case[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchCases = async () => {
      try {
        const data = await getCases();
        setCases(data);
      } catch (err) {
        setError('Failed to fetch cases');
        console.error('Error fetching cases:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchCases();
  }, []);

  if (loading) {
    return (
      <div className="flex justify-center items-center h-full">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-red-500 text-center">
        {error}
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">
          Welcome, {user?.firstName}!
        </h1>
        <p className="mt-2 text-gray-600">
          Here's an overview of your cases
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-medium text-gray-900">Active Cases</h3>
          <p className="mt-2 text-3xl font-bold text-indigo-600">
            {cases.filter(c => c.status === 'in-progress').length}
          </p>
        </div>
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-medium text-gray-900">Pending Cases</h3>
          <p className="mt-2 text-3xl font-bold text-yellow-600">
            {cases.filter(c => c.status === 'pending').length}
          </p>
        </div>
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-medium text-gray-900">Completed Cases</h3>
          <p className="mt-2 text-3xl font-bold text-green-600">
            {cases.filter(c => c.status === 'completed').length}
          </p>
        </div>
      </div>

      <div className="mt-8">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Recent Cases</h2>
        <div className="bg-white shadow overflow-hidden sm:rounded-md">
          <ul className="divide-y divide-gray-200">
            {cases.slice(0, 5).map((case_) => (
              <li key={case_.id}>
                <div className="px-4 py-4 flex items-center sm:px-6">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center justify-between">
                      <p className="text-sm font-medium text-indigo-600 truncate">
                        {case_.caseNumber}
                      </p>
                      <div className="ml-2 flex-shrink-0 flex">
                        <p className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full 
                          ${case_.status === 'completed' ? 'bg-green-100 text-green-800' : 
                            case_.status === 'in-progress' ? 'bg-blue-100 text-blue-800' : 
                            'bg-yellow-100 text-yellow-800'}`}>
                          {case_.status}
                        </p>
                      </div>
                    </div>
                    <div className="mt-2 flex justify-between">
                      <div className="sm:flex">
                        <p className="flex items-center text-sm text-gray-500">
                          Client: {case_.client.firstName} {case_.client.lastName}
                        </p>
                      </div>
                      <div className="flex items-center text-sm text-gray-500">
                        {new Date(case_.updatedAt).toLocaleDateString()}
                      </div>
                    </div>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;

