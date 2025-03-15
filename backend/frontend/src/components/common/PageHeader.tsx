import React from 'react';

interface PageHeaderProps {
  title: string;
  description?: string;
  children?: React.ReactNode;
}

const PageHeader: React.FC<PageHeaderProps> = ({ title, description, children }) => {
  return (
    <div className="mb-8 flex justify-between items-center">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">{title}</h1>
        {description && (
          <p className="mt-2 text-gray-600">{description}</p>
        )}
      </div>
      {children && <div>{children}</div>}
    </div>
  );
};

export default PageHeader;

