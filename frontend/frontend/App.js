import React from 'react';
import FileManager from './components/FileManager';

function App() {
  const files = [
    // Example file data
    {
      id: 1,
      name: 'example.pdf',
      type: 'application/pdf',
      size: 102400,
      uploadDate: Date.now(),
      url: '/files/example.pdf',
    },
    {
      id: 2,
      name: 'image.png',
      type: 'image/png',
      size: 51200,
      uploadDate: Date.now(),
      url: '/files/image.png',
    },
  ];

  return (
    <div className="App">
      <FileManager files={files} />
    </div>
  );
}

export default App;

