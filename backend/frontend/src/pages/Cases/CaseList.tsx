import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { Case } from '../../types';

interface CaseListProps {
  cases: Case[];
  loading: boolean;
  error: string;
}

const CaseList: React.FC<CaseListProps> = ({ cases, loading, error }) => {
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');

  const filteredCases = cases.filter((case_) => {
    const matchesFilter = filter === 'all' || case_.status === filter;
    const matchesSearch = 
      case_.caseNumber.toLowerCase().includes(search.toLowerCase()) ||
      case_.client.firstName.toLowerCase().includes(search.toLowerCase()) ||
      case_.client.lastName.toLowerCase().includes(search.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-red-500 text-center p-4">
        {error}
      </div>
    );
  }

  return (
    <div>
      <div className="mb-6 flex flex-col sm:flex-row justify-between items-center gap-4">
        <div className="flex items-center gap-4">
          <input
            type="text"
            placeholder="Search cases..."
            className="px-4 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="px-4 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            <option value="all">All Status</option>
            <option value="new">New</option>
            <option value="in-progress">In Progress</option>
            <option value="pending">Pending</option>
            <option value="completed">Completed</option>
            <option value="cancelled">Cancelled</option>
          </select>
        </div>
        <Link
          to="/cases/new"
          className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
        >
          New Case
        </Link>
      </div>

      <div className="bg-white shadow overflow-hidden sm:rounded-md">
        <ul className="divide-y divide-gray-200">
          {filteredCases.map((case_) => (
            <li key={case_.id}>
              <Link to={`/cases/${case_.id}`} className="block hover:bg-gray-50">
                <div className="px-4 py-4 flex items-center sm:px-6">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-indigo-600 truncate">
                          {case_.caseNumber}
                        </p>
                        <p className="mt-1 text-sm text-gray-600">
                          Client: {case_.client.firstName} {case_.client.lastName}
                        </p>
                      </div>
                      <div className="ml-2 flex-shrink-0 flex">
                        <p className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full 
                          ${case_.status === 'completed' ? 'bg-green-100 text-green-800' : 
                            case_.status === 'in-progress' ? 'bg-blue-100 text-blue-800' : 
                            'bg-yellow-100 text-yellow-800'}`}
                        >
                          {case_.status}
                        </p>
                      </div>
                    </div>
                    <div className="mt-2 sm:flex sm:justify-between">
                      <div>
                        <p className="flex items-center text-sm text-gray-500">
                          Lawyer: {case_.assignedLawyer.firstName} {case_.assignedLawyer.lastName}
                        </p>
                      </div>
                      <div className="mt-2 flex items-center text-sm text-gray-500 sm:mt-0">
                        <p>
                          Last Updated: {new Date(case_.updatedAt).toLocaleDateString()}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              </Link>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
};

export default CaseList;

