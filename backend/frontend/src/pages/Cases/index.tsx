import React, { useEffect, useState } from 'react';
import { getCases } from '../../services/case.service';
import { Case } from '../../types';
import CaseList from './CaseList';

const Cases: React.FC = () => {
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

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Cases</h1>
        <p className="mt-2 text-gray-600">
          Manage and view all immigration cases
        </p>
      </div>

      <CaseList
        cases={cases}
        loading={loading}
        error={error}
      />
    </div>
  );
};

export default Cases;

