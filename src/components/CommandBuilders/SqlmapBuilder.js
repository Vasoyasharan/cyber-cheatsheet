import { useState, useContext } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FaCopy, FaInfoCircle, FaGlobe, FaDatabase } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { useCommandHistory } from '../../contexts/CommandHistoryContext';
import { sanitizeInput } from '../../utils/commandHelpers';
import { copyToClipboard } from '../../utils/copyToClipboard';
import CommandHistory from '../UI/CommandHistory';

const SqlmapBuilder = () => {
  const [url, setUrl] = useState('');
  const [options, setOptions] = useState({
    method: 'GET',
    data: '',
    risk: 1,
    level: 1,
    dbms: '',
    os: '',
    techniques: 'BEUSTQ',
    threads: 1,
    batch: false,
    dumpAll: false,
    verbose: false
  });
  const [showAdvanced, setShowAdvanced] = useState(false);
  const { addToHistory } = useCommandHistory();

  const methods = ['GET', 'POST', 'PUT', 'DELETE'];
  const dbmsOptions = ['', 'MySQL', 'PostgreSQL', 'Oracle', 'Microsoft SQL Server', 'SQLite'];
  const osOptions = ['', 'Windows', 'Linux', 'Mac'];
  const riskLevels = [
    { value: 1, label: '1 - Low risk' },
    { value: 2, label: '2 - Medium risk' },
    { value: 3, label: '3 - High risk' }
  ];
  const testLevels = [
    { value: 1, label: '1 - Basic tests' },
    { value: 2, label: '2 - Additional tests' },
    { value: 3, label: '3 - Extensive tests' },
    { value: 4, label: '4 - Comprehensive tests' },
    { value: 5, label: '5 - All tests' }
  ];

  const buildCommand = () => {
    let cmd = 'sqlmap';
    
    if (url) cmd += ` -u "${url}"`;
    if (options.method !== 'GET') cmd += ` --method=${options.method}`;
    if (options.data) cmd += ` --data="${options.data}"`;
    if (options.risk > 1) cmd += ` --risk=${options.risk}`;
    if (options.level > 1) cmd += ` --level=${options.level}`;
    if (options.dbms) cmd += ` --dbms=${options.dbms}`;
    if (options.os) cmd += ` --os=${options.os}`;
    if (options.techniques !== 'BEUSTQ') cmd += ` --technique=${options.techniques}`;
    if (options.threads > 1) cmd += ` --threads=${options.threads}`;
    if (options.batch) cmd += ' --batch';
    if (options.dumpAll) cmd += ' --dump-all';
    if (options.verbose) cmd += ' -v';
    
    return cmd;
  };

  const handleCopy = async () => {
    if (!url) {
      toast.error('Please enter a target URL', {
        position: 'bottom-right',
        autoClose: 2000,
        hideProgressBar: true,
      });
      return;
    }

    try {
      await copyToClipboard(buildCommand());
      addToHistory(buildCommand());
      toast.success('Command copied to clipboard!', {
        position: 'bottom-right',
        autoClose: 2000,
        hideProgressBar: true,
      });
    } catch (err) {
      toast.error('Failed to copy command', {
        position: 'bottom-right',
        autoClose: 2000,
        hideProgressBar: true,
      });
    }
  };

  const handleUrlChange = (e) => {
    setUrl(sanitizeInput(e.target.value));
  };

  const handleDataChange = (e) => {
    setOptions({...options, data: sanitizeInput(e.target.value)});
  };

  const toggleTechnique = (tech) => {
    let newTech = options.techniques;
    if (newTech.includes(tech)) {
      newTech = newTech.replace(tech, '');
    } else {
      newTech += tech;
    }
    setOptions({...options, techniques: newTech});
  };

  return (
    <div className="command-builder">
      <div className="builder-header">
        <FaDatabase className="icon" />
        <h2>SQLmap Command Builder</h2>
        <p>SQL injection detection and exploitation tool</p>
      </div>
      
      <div className="form-group">
        <label>Target URL</label>
        <input
          type="text"
          value={url}
          onChange={handleUrlChange}
          placeholder="http://example.com/page.php?id=1"
          className="text-input"
        />
      </div>
      
      <div className="form-group">
        <label>HTTP Method</label>
        <select
          value={options.method}
          onChange={(e) => setOptions({...options, method: e.target.value})}
          className="select-input"
        >
          {methods.map(method => (
            <option key={method} value={method}>
              {method}
            </option>
          ))}
        </select>
      </div>
      
      {options.method === 'POST' && (
        <div className="form-group">
          <label>POST Data</label>
          <input
            type="text"
            value={options.data}
            onChange={handleDataChange}
            placeholder="param1=value1&param2=value2"
            className="text-input"
          />
        </div>
      )}
      
      <div className="form-row">
        <div className="form-group">
          <label>Risk Level</label>
          <select
            value={options.risk}
            onChange={(e) => setOptions({...options, risk: parseInt(e.target.value)})}
            className="select-input"
          >
            {riskLevels.map(level => (
              <option key={level.value} value={level.value}>
                {level.label}
              </option>
            ))}
          </select>
        </div>
        
        <div className="form-group">
          <label>Test Level</label>
          <select
            value={options.level}
            onChange={(e) => setOptions({...options, level: parseInt(e.target.value)})}
            className="select-input"
          >
            {testLevels.map(level => (
              <option key={level.value} value={level.value}>
                {level.label}
              </option>
            ))}
          </select>
        </div>
      </div>
      
      <button 
        onClick={() => setShowAdvanced(!showAdvanced)}
        className="toggle-button"
      >
        {showAdvanced ? 'Hide Advanced Options' : 'Show Advanced Options'}
      </button>
      
      <AnimatePresence>
        {showAdvanced && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.3 }}
            className="advanced-options"
          >
            <div className="form-row">
              <div className="form-group">
                <label>DBMS</label>
                <select
                  value={options.dbms}
                  onChange={(e) => setOptions({...options, dbms: e.target.value})}
                  className="select-input"
                >
                  {dbmsOptions.map(dbms => (
                    <option key={dbms} value={dbms}>
                      {dbms || 'Automatic'}
                    </option>
                  ))}
                </select>
              </div>
              
              <div className="form-group">
                <label>Operating System</label>
                <select
                  value={options.os}
                  onChange={(e) => setOptions({...options, os: e.target.value})}
                  className="select-input"
                >
                  {osOptions.map(os => (
                    <option key={os} value={os}>
                      {os || 'Automatic'}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            
            <div className="form-group">
              <label>Injection Techniques</label>
              <div className="technique-buttons">
                <button
                  className={`tech-button ${options.techniques.includes('B') ? 'active' : ''}`}
                  onClick={() => toggleTechnique('B')}
                >
                  Boolean-based
                </button>
                <button
                  className={`tech-button ${options.techniques.includes('E') ? 'active' : ''}`}
                  onClick={() => toggleTechnique('E')}
                >
                  Error-based
                </button>
                <button
                  className={`tech-button ${options.techniques.includes('U') ? 'active' : ''}`}
                  onClick={() => toggleTechnique('U')}
                >
                  UNION query
                </button>
                <button
                  className={`tech-button ${options.techniques.includes('S') ? 'active' : ''}`}
                  onClick={() => toggleTechnique('S')}
                >
                  Stacked queries
                </button>
                <button
                  className={`tech-button ${options.techniques.includes('T') ? 'active' : ''}`}
                  onClick={() => toggleTechnique('T')}
                >
                  Time-based
                </button>
                <button
                  className={`tech-button ${options.techniques.includes('Q') ? 'active' : ''}`}
                  onClick={() => toggleTechnique('Q')}
                >
                  Inline queries
                </button>
              </div>
            </div>
            
            <div className="form-row">
              <div className="form-group">
                <label>Threads</label>
                <input
                  type="number"
                  min="1"
                  max="10"
                  value={options.threads}
                  onChange={(e) => setOptions({...options, threads: parseInt(e.target.value) || 1})}
                  className="text-input"
                />
              </div>
              
              <div className="checkbox-group">
                <label>
                  <input
                    type="checkbox"
                    checked={options.batch}
                    onChange={(e) => setOptions({...options, batch: e.target.checked})}
                  />
                  Batch mode
                </label>
                
                <label>
                  <input
                    type="checkbox"
                    checked={options.dumpAll}
                    onChange={(e) => setOptions({...options, dumpAll: e.target.checked})}
                  />
                  Dump all
                </label>
                
                <label>
                  <input
                    type="checkbox"
                    checked={options.verbose}
                    onChange={(e) => setOptions({...options, verbose: e.target.checked})}
                  />
                  Verbose
                </label>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
      
      <div className="command-preview">
        <div className="preview-header">
          <h3>Generated Command</h3>
          <button onClick={handleCopy} className="copy-button">
            <FaCopy /> Copy
          </button>
        </div>
        <code>{buildCommand()}</code>
      </div>
      
      <CommandHistory />
      
      <div className="info-tip">
        <FaInfoCircle />
        <p>Important: Only test applications you own or have explicit permission to test for SQL injection vulnerabilities.</p>
      </div>
    </div>
  );
};

export default SqlmapBuilder;