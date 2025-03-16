import React, { useCallback, useState, useEffect } from 'react';
import axios from 'axios';

const FileList = ({ files, onDelete }) => {
  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="file-list my-4">
      <table className="min-w-full divide-y divide-gray-200">
        <thead className="bg-gray-50">
          <tr>
            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Name
            </th>
            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Type
            </th>
            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Size
            </th>
            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Upload Date
            </th>
            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Actions
            </th>
          </tr>
        </thead>
        <tbody className="bg-white divide-y divide-gray-200">
          {files.map((file) => (
            <tr key={file.id}>
              <td className="px-6 py-4 whitespace-nowrap">
                <div className="text-sm text-gray-900">{file.name}</div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <div className="text-sm text-gray-900">{file.type}</div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <div className="text-sm text-gray-900">{formatBytes(file.size)}</div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <div className="text-sm text-gray-900">{new Date(file.createdAt).toLocaleString()}</div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <div className="flex items-center space-x-4">
                  <a
                    href={`/documents/download/${file.id}`}
                    className="text-indigo-600 hover:text-indigo-900"
                    download
                  >
                    Download
                  </a>
                  <button
                    onClick={() => onDelete(file.id)}
                    className="text-red-600 hover:text-red-900"
                  >
                    Delete
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

const FileUpload = () => {
  const [file, setFile] = useState(null);
  const [error, setError] = useState('');
  const [uploadProgress, setUploadProgress] = useState(0);
  const [isUploading, setIsUploading] = useState(false);
  const [files, setFiles] = useState([]);
  const [loadingFiles, setLoadingFiles] = useState(false);
  const [filesError, setFilesError] = useState('');

  const fetchFiles = useCallback(async () => {
    setLoadingFiles(true);
    setFilesError('');
    try {
      const { data } = await axios.get('/documents');
      setFiles(data);
    } catch (err) {
      setFilesError('Failed to fetch files');
      console.error('Error fetching files:', err);
    } finally {
      setLoadingFiles(false);
    }
  }, []);

  const handleDeleteFile = useCallback(async (fileId) => {
    if (!window.confirm('Are you sure you want to delete this file?')) {
      return;
    }

    try {
      await axios.delete(`/documents/${fileId}`);
      setFiles((prev) => prev.filter((file) => file.id !== fileId));
    } catch (err) {
      setError('Failed to delete file');
      console.error('Error deleting file:', err);
    }
  }, []);

  useEffect(() => {
    fetchFiles();
  }, [fetchFiles]);

  const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
  const maxSize = 10 * 1024 * 1024; // 10MB

  const validateFile = useCallback((file) => {
    if (!allowedTypes.includes(file.type)) {
      setError('Invalid file type. Allowed types: JPEG, PNG, PDF, DOC, DOCX.');
      return false;
    }

    if (file.size > maxSize) {
      setError(`File size too large. Maximum size is ${maxSize / 1024 / 1024}MB.`);
      return false;
    }

    return true;
  }, []);

  const handleFileChange = useCallback((e) => {
    const selectedFile = e.target.files[0];
    
    if (!selectedFile) return;

    if (validateFile(selectedFile)) {
      setFile(selectedFile);
      setError('');
    }
  }, [validateFile]);

  const handleFileDrop = useCallback((e) => {
    e.preventDefault();
    const droppedFile = e.dataTransfer.files[0];

    if (!droppedFile) return;

    if (validateFile(droppedFile)) {
      setFile(droppedFile);
      setError('');
    }
  }, [validateFile]);

  const handleFileUpload = useCallback(async () => {
    if (!file) return;

    setIsUploading(true);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const { data } = await axios.post('/documents/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
        onUploadProgress: (progressEvent) => {
          const percentCompleted = Math.round(
            (progressEvent.loaded * 100) / progressEvent.total
          );
          setUploadProgress(percentCompleted);
        },
      });

      console.log('Upload successful:', data);
      setFile(null);
      setUploadProgress(0);
    } catch (err) {
      console.error('Upload failed:', err);
      setError('File upload failed. Please try again.');
    } finally {
      setIsUploading(false);
    }
  }, [file]);

  return (
    <div 
      className="file-upload-container"
      onDragOver={(e) => e.preventDefault()}
      onDrop={handleFileDrop}
    >
      <input 
        type="file" 
        id="fileInput"
        onChange={handleFileChange}
        style={{ display: 'none' }}
      />
      <label htmlFor="fileInput" className="file-drop-area">
        {file ? file.name : 'Drag & drop or click to upload a file'}
      </label>

      {error && <div className="error-message">{error}</div>}

      {file && (
        <button 
          className="upload-button" 
          onClick={handleFileUpload}
          disabled={isUploading}
        >
          {isUploading ? 'Uploading...' : 'Upload'}
        </button>
      )}

      {uploadProgress > 0 && (
        <div className="progress-bar">
          <div 
            className="progress" 
            style={{ width: `${uploadProgress}%` }}
          />
        </div>
      )}
      {loadingFiles ? (
        <div className="flex justify-center items-center h-32">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600"></div>
        </div>
      ) : filesError ? (
        <div className="text-red-500 text-center p-4">{filesError}</div>
      ) : (
        <FileList files={files} onDelete={handleDeleteFile} />
      )}
    </div>
  );
};

export default FileUpload;

export default FileUpload;

