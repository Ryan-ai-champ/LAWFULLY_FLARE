import React, { useState } from 'react';
import FilePreviewModal from './FilePreviewModal';

const FileManager = ({ files }) => {
  const [previewFile, setPreviewFile] = useState(null);
  const [isPreviewOpen, setIsPreviewOpen] = useState(false);

  const handlePreview = (file) => {
    setPreviewFile(file);
    setIsPreviewOpen(true);
  };

  return (
    <div>
      <h3>Uploaded Files</h3>
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Size</th>
            <th>Upload Date</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {files.map((file) => (
            <tr key={file.id}>
              <td>{file.name}</td>
              <td>{file.type}</td>
              <td>{(file.size / 1024).toFixed(2)} KB</td>
              <td>{new Date(file.uploadDate).toLocaleString()}</td>
              <td>
                <button onClick={() => handlePreview(file)}>Preview</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <FilePreviewModal
        isOpen={isPreviewOpen}
        onRequestClose={() => setIsPreviewOpen(false)}
        fileUrl={previewFile?.url}
        fileType={previewFile?.type}
      />
    </div>
  );
};

export default FileManager;

