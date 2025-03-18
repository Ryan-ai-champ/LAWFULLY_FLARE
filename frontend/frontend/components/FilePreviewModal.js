import React, { useState, useRef } from 'react';
import Modal from 'react-modal';
import { Document, Page } from 'react-pdf';
import 'react-pdf/dist/esm/Page/AnnotationLayer.css';
import { FullscreenIcon, FullscreenExitIcon } from '@mui/icons-material';

Modal.setAppElement('#root');

const PagePreview = React.memo(({ pageNumber, zoomLevel, searchText, caseSensitive, wholeWord, useRegex }) => {
  const textLayerRef = useRef(null);

  return (
    <Page 
      pageNumber={pageNumber}
      scale={zoomLevel}
      loading="Loading page..."
      onRenderTextLayerSuccess={() => {
        // Text layer rendering logic
      }}
    >
      {({ canvasLayer, textLayer }) => (
        <>
          {canvasLayer}
          <div ref={textLayerRef}>
            {textLayer}
          </div>
        </>
      )}
    </Page>
  );
});

const FilePreviewModal = ({ isOpen, onRequestClose, fileUrl, fileType }) => {
  const [searchText, setSearchText] = useState('');
  const [matches, setMatches] = useState([]);
  const [currentMatch, setCurrentMatch] = useState(0);
  const [caseSensitive, setCaseSensitive] = useState(false);
  const [wholeWord, setWholeWord] = useState(false);
  const [useRegex, setUseRegex] = useState(false);
  const [regexError, setRegexError] = useState(null);
  const textLayerRef = useRef(null);
  const [pageNumber, setPageNumber] = useState(1);
  const [numPages, setNumPages] = useState(0);
  const [zoomLevel, setZoomLevel] = useState(1);
  const [isFullScreen, setIsFullScreen] = useState(false);
  const modalRef = useRef();
  const [annotations, setAnnotations] = useState([]);

  const exportAnnotations = () => {
    const annotationData = {
      fileUrl,
      timestamp: new Date().toISOString(),
      totalPages: numPages,
      annotations: matches.map(match => ({
        page: match.page,
        text: searchText,
        matchIndex: match.matchIndex,
        length: match.length,
        timestamp: new Date().toISOString()
      }))
    };

    const blob = new Blob([JSON.stringify(annotationData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `annotations_${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleZoomIn = () => setZoomLevel((prev) => Math.min(prev + 0.1, 2));
  const handleZoomOut = () => setZoomLevel((prev) => Math.max(prev - 0.1, 0.5));
  const handleZoomReset = () => setZoomLevel(1);

  const onDocumentLoadSuccess = ({ numPages }) => {
    setNumPages(numPages);
  };

  const goToPrevPage = () =>
    setPageNumber((prevPage) => Math.max(prevPage - 1, 1));
  const goToNextPage = () =>
    setPageNumber((prevPage) => Math.min(prevPage + 1, numPages));

  const handleThumbnailClick = (page) => {
    setPageNumber(page);
  };

    <Modal
      isOpen={isOpen}
      onRequestClose={onRequestClose}
      contentLabel="File Preview"
      className={isFullScreen ? 'modal fullscreen' : 'modal'}
      overlayClassName={isFullScreen ? 'overlay fullscreen' : 'overlay'}
      ref={modalRef}
      aria-modal="true"
      role="dialog"
      onAfterOpen={() => modalRef.current?.focus()}
    ></Modal>
    >
      <><div style={{ display: 'flex', height: '90vh' }}>
        <div
          role="navigation"
          aria-label="Page thumbnails"
          style={{ width: '200px', overflowY: 'auto', borderRight: '1px solid #ddd' }}
        >
          {[...Array(numPages || 0)].map((_, index) => {
            const isVisible = Math.abs(index + 1 - pageNumber) <= 2; // Only render nearby pages
            return (
              <div
                key={index + 1}
                onClick={() => handleThumbnailClick(index + 1)}
                style={{
                  cursor: 'pointer',
                  padding: '8px',
                  backgroundColor: pageNumber === index + 1 ? '#e2e8f0' : 'transparent',
                }}
              >
                {isVisible && (
                  <Document file={fileUrl} onLoadSuccess={onDocumentLoadSuccess}>
                    <Page
                      pageNumber={index + 1}
                      width={150}
                      renderAnnotationLayer={false}
                      renderTextLayer={false} />
                  </Document>
                )}
              </div>);
          })}
        </div>
      </div><div className="preview-container" style={{ flex: 1, height: isFullScreen ? 'calc(100vh - 60px)' : '90vh' }}>
          <Document file={fileUrl} onLoadSuccess={onDocumentLoadSuccess}>
            <PagePreview
              pageNumber={pageNumber}
              zoomLevel={zoomLevel}
              searchText={searchText}
              caseSensitive={caseSensitive}
              wholeWord={wholeWord}
              useRegex={useRegex} />
          </Document>
          <Page pageNumber={pageNumber} scale={zoomLevel} />
        </div><div className="pdf-controls">
          <div style={{ display: 'flex', gap: '8px', marginBottom: '8px' }}>
            <input
              type="text"
              placeholder="Search..."
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
              style={{ padding: '4px', flex: 1 }} />
            <label style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
              <input
                type="checkbox"
                checked={caseSensitive}
                onChange={(e) => setCaseSensitive(e.target.checked)} />
              Case Sensitive
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
              <input
                type="checkbox"
                checked={wholeWord}
                onChange={(e) => setWholeWord(e.target.checked)} />
              Whole Word
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
              <input
                type="checkbox"
                checked={useRegex}
                onChange={(e) => setUseRegex(e.target.checked)} />
              Regex
            </label>
            <button
              aria-label="Next search result"
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  setCurrentMatch(prev => {
                    const nextMatch = (prev + 1) % matches.length;
                    const match = matches[nextMatch];
                    if (match.page !== pageNumber) {
                      setPageNumber(match.page);
                    }
                    return nextMatch;
                  });
                  const match = matches[currentMatch];
                  const textSpans = textLayerRef.current?.querySelectorAll('.react-pdf__Page__textContent > span');
                  if (textSpans && textSpans[match.spanIndex]) {
                    textSpans[match.spanIndex].scrollIntoView({ block: 'center' });
                  }
                }
              } }
              disabled={!searchText || matches.length === 0}
            >
              Next
            </button>
          </div>
          <div style={{ marginBottom: '8px' }}>
            {searchText && (
              <span aria-live="polite" aria-atomic="true">
                {matches.length > 0
                  ? `Match ${currentMatch + 1} of ${matches.length} (Page ${matches[currentMatch].page})`
                  : 'No matches found'}
                : 'No matches found'
              </span>
            )}
            {regexError && (
              <span style={{ color: 'red', marginLeft: '8px' }}>
                {regexError}
              </span>
            )}
          </div>
          <button />
        </div><button
          style={{ margin: '0 4px' }}
        >
          {isFullScreen ? <FullscreenExitIcon /> : <FullscreenIcon />}
        </button><button onClick={goToPrevPage} disabled={pageNumber <= 1}>
          Previous
        </button><p>
          Page {pageNumber} of {numPages}
        </p><button onClick={goToNextPage} disabled={pageNumber >= numPages}>
          Next
        </button><button onClick={handleZoomOut}>Zoom Out</button><button onClick={handleZoomReset}>Reset Zoom</button><button onClick={handleZoomIn}>Zoom In</button><button
          onClick={exportAnnotations}
          title="Export Annotations"
          style={{ marginLeft: '8px' }}
        >
          Export Annotations
        </button></>
            </div>
          <img src={fileUrl} alt="Preview" style={{ maxWidth: '100%' }} />
        )}
      </div>
      <button 
        onClick={onRequestClose}
        aria-label="Close file preview"
        style={{
          backgroundColor: '#f0f0f0',
          color: '#333',
          padding: '8px 16px',
          border: '1px solid #ccc',
          borderRadius: '4px',
          ':hover': {
            backgroundColor: '#e0e0e0'
          }
        }}
      >
        Close Preview
      </button>
    </Modal>
  );
};

export default FilePreviewModal;

