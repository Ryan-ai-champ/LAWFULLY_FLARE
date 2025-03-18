  const [searchText, setSearchText] = useState('');
  const [matches, setMatches] = useState([]);
  const [currentMatch, setCurrentMatch] = useState(0);
  const [caseSensitive, setCaseSensitive] = useState(false);
  const [wholeWord, setWholeWord] = useState(false);
  const [useRegex, setUseRegex] = useState(false);
  const [regexError, setRegexError] = useState(null);
  const [searchHistory, setSearchHistory] = useState([]);
              <div style={{ display: 'flex', gap: '8px', marginBottom: '8px' }}>
                <div style={{ flex: 1, position: 'relative' }}>
                  <input
                    type="text"
                    placeholder="Search..."
                    value={searchText}
                    onChange={(e) => setSearchText(e.target.value)}
                    style={{ padding: '4px', width: '100%', paddingRight: '30px' }}
                  />
                  {searchHistory.length > 0 && (
                    <select
                      style={{
                        position: 'absolute',
                        right: 0,
                        top: 0,
                        height: '100%',
                        width: '30px',
                        border: 'none',
                        background: 'transparent',
                        appearance: 'none',
                        cursor: 'pointer'
                      }}
                      onChange={(e) => {
                        setSearchText(searchHistory[e.target.value]);
                      }}
                    >
                      {searchHistory.slice(-10).map((term, index) => (
                        <option key={index} value={index}>
                          {term}
                        </option>
                      ))}
                    </select>
                  )}
                </div>
                  onClick={() => {
                    if (searchText) {
                      setSearchHistory((prev) => [
                        ...prev.filter((term) => term !== searchText),
                        searchText
                      ].slice(-10));
                    }
                  }}</div>
