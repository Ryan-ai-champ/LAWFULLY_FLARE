import React, { useState, useRef } from 'react';
import Modal from 'react-modal';
import { Document, Page } from 'react-pdf';
import 'react-pdf/dist/esm/Page/AnnotationLayer.css';
import { FullscreenIcon, FullscreenExitIcon } from '@mui/icons-material';

Modal.setAppElement('#root');

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
    >
    >
      <div style={{ display: 'flex', height: '90vh' }}>
        <div style={{ width: '200px', overflowY: 'auto', borderRight: '1px solid #ddd' }}>
          {[...Array(numPages || 0)].map((_, index) => (
            <div
              key={index + 1}
              onClick={() => handleThumbnailClick(index + 1)}
              style={{
                cursor: 'pointer',
                padding: '8px',
                backgroundColor: pageNumber === index + 1 ? '#e2e8f0' : 'transparent',
              }}
            >
              <Document file={fileUrl} onLoadSuccess={onDocumentLoadSuccess}>
                <Page
                  pageNumber={index + 1}
                  width={150}
                  renderAnnotationLayer={false}
                  renderTextLayer={false}
                />
              </Document>
            </div>
          ))}
        </div>
        <div className="preview-container" style={{ flex: 1, height: isFullScreen ? 'calc(100vh - 60px)' : '90vh' }}>
            <Document file={fileUrl} onLoadSuccess={onDocumentLoadSuccess}>
              <Page 
                pageNumber={pageNumber} 
                scale={zoomLevel}
                onRenderTextLayerSuccess={() => {
                  if (textLayerRef.current && searchText) {
                    const textLayer = textLayerRef.current;
                    const textSpans = textLayer.querySelectorAll('.react-pdf__Page__textContent > span');
                    const newMatches = [];
                    
                    textSpans.forEach((span, index) => {
                      const flags = caseSensitive ? 'g' : 'gi';
                      let pattern = searchText;
                      let flags = caseSensitive ? 'g' : 'gi';
                      
                      if (wholeWord) {
                        pattern = `\\\\b${searchText}\\\\b`;
                      }

                      if (useRegex) {
                        try {
                          new RegExp(pattern, flags); // Test if regex is valid
                          setRegexError(null);
                        } catch (error) {
                          setRegexError('Invalid regex pattern');
                          return;
                        }
                      } else {
                        // Escape special regex characters if not using regex
                        pattern = pattern.replace(/[.*+?^${}()|[\]\\\\]/g, '\\\\$&');
                      }

                      const matches = [...span.innerText.matchAll(new RegExp(pattern, flags))];
                      matches.forEach(match => {
                          page: pageNumber,
                          spanIndex: index,
                          matchIndex: match.index,
                          length: match[0].length
                        });
                      });
                    });
                    
                    // If this isn't the last page, search the next page
                    if (pageNumber < numPages) {
                      setPageNumber(pageNumber + 1);
                      setMatches(prevMatches => [...prevMatches, ...newMatches]);
                    } else {
                      setMatches(newMatches);
                      setCurrentMatch(0);
                      if (newMatches.length > 0) {
                        setPageNumber(newMatches[0].page);
                      }
                    }

                    setMatches(newMatches);
                    setCurrentMatch(0);

                    // Highlight matches
                    textSpans.forEach(span => span.style.backgroundColor = '');
                    newMatches.forEach(match => {
                      const span = textSpans[match.spanIndex];
                      const textNode = span.childNodes[0];
                      const range = document.createRange();
                      range.setStart(textNode, match.matchIndex);
                      range.setEnd(textNode, match.matchIndex + match.length);
                      const highlight = document.createElement('span');
                      highlight.style.backgroundColor = 'yellow';
                      range.surroundContents(highlight);
                    });
                  }
                }}
              >
                {({ canvasLayer, textLayer }) => (
                  <>
                    {canvasLayer}
                    <div 
                      ref={textLayerRef}
                      style={{ position: 'absolute', top: 0, left: 0 }}
                    >
                      {textLayer}
                    </div>
                  </>
                )}
              </Page>
            </Document>
              <Page pageNumber={pageNumber} scale={zoomLevel} />
            </Document>
            <div className="pdf-controls">
              <div style={{ display: 'flex', gap: '8px', marginBottom: '8px' }}>
                <input
                  type="text"
                  placeholder="Search..."
                  value={searchText}
                  onChange={(e) => setSearchText(e.target.value)}
                  style={{ padding: '4px', flex: 1 }}
                />
                <label style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <input
                    type="checkbox"
                    checked={caseSensitive}
                    onChange={(e) => setCaseSensitive(e.target.checked)}
                  />
                  Case Sensitive
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <input
                    type="checkbox"
                    checked={wholeWord}
                    onChange={(e) => setWholeWord(e.target.checked)}
                  />
                  Whole Word
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <input
                    type="checkbox"
                    checked={useRegex}
                    onChange={(e) => setUseRegex(e.target.checked)}
                  />
                  Regex
                </label>
                <button
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
                  }}
                  disabled={!searchText || matches.length === 0}
                >
                  Next
                </button>
              </div>
              <div style={{ marginBottom: '8px' }}>
                {searchText && (
                  <span>
                    {matches.length > 0 
                      ? `Match ${currentMatch + 1} of ${matches.length} (Page ${matches[currentMatch].page})`
                      : 'No matches found'}
                      : 'No matches found'}
                  </span>
                )}
                {regexError && (
                  <span style={{ color: 'red', marginLeft: '8px' }}>
                    {regexError}
                  </span>
                )}
              </div>
              <button
                style={{ margin: '0 4px' }}
              >
                {isFullScreen ? <FullscreenExitIcon /> : <FullscreenIcon />}
              </button>
              <button onClick={goToPrevPage} disabled={pageNumber <= 1}>
                Previous
              </button>
              <p>
                Page {pageNumber} of {numPages}
              </p>
              <button onClick={goToNextPage} disabled={pageNumber >= numPages}>
                Next
              </button>
              <button onClick={handleZoomOut}>Zoom Out</button>
              <button onClick={handleZoomReset}>Reset Zoom</button>
              <button onClick={handleZoomIn}>Zoom In</button>
            </div>
          </>
        ) : (
          <img src={fileUrl} alt="Preview" style={{ maxWidth: '100%' }} />
        )}
      </div>
      <button onClick={onRequestClose}>Close Preview</button>
    </Modal>
  );
};

export default FilePreviewModal;

