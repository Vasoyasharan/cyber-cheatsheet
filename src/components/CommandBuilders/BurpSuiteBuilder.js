import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FaCopy, FaInfoCircle, FaGlobe } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { useCommandHistory } from '../../contexts/CommandHistoryContext';
import { copyToClipboard } from '../../utils/copyToClipboard';
import CommandHistory from '../UI/CommandHistory';

const BurpSuiteBuilder = () => {
  const [projectType, setProjectType] = useState('temporary');
  const [configOptions, setConfigOptions] = useState({
    proxyPort: '8080',
    headless: false,
    disableBrowser: false,
    memory: '1024',
    configFile: ''
  });
  const [showAdvanced, setShowAdvanced] = useState(false);
  const { addToHistory } = useCommandHistory();

  const projectTypes = [
    { value: 'temporary', label: 'Temporary Project', description: 'No project file will be created' },
    { value: 'new', label: 'New Project', description: 'Create a new Burp project file' },
    { value: 'existing', label: 'Existing Project', description: 'Open an existing Burp project' }
  ];

  const buildCommand = () => {
    let cmd = 'burpsuite';
    
    if (projectType === 'new') {
      cmd += ' --new-project';
    } else if (projectType === 'existing' && configOptions.configFile) {
      cmd += ` --project-file=${configOptions.configFile}`;
    }
    
    if (configOptions.proxyPort !== '8080') {
      cmd += ` --proxy-port=${configOptions.proxyPort}`;
    }
    
    if (configOptions.headless) {
      cmd += ' --headless';
    }
    
    if (configOptions.disableBrowser) {
      cmd += ' --disable-browser';
    }
    
    if (configOptions.memory !== '1024') {
      cmd += ` --memory=${configOptions.memory}`;
    }
    
    return cmd;
  };

  const handleCopy = async () => {
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

  return (
    <div className="command-builder">
      <div className="builder-header">
        <FaGlobe className="icon" />
        <h2>Burp Suite Command Builder</h2>
        <p>Web application security testing tool</p>
      </div>
      
      <div className="form-group">
        <label>Project Type</label>
        <select 
          value={projectType} 
          onChange={(e) => setProjectType(e.target.value)}
          className="select-input"
        >
          {projectTypes.map(type => (
            <option key={type.value} value={type.value}>
              {type.label}
            </option>
          ))}
        </select>
        <div className="description">
          {projectTypes.find(t => t.value === projectType).description}
        </div>
      </div>
      
      {(projectType === 'existing') && (
        <div className="form-group">
          <label>Project File Path</label>
          <input
            type="text"
            value={configOptions.configFile}
            onChange={(e) => setConfigOptions({...configOptions, configFile: e.target.value})}
            placeholder="/path/to/project.burp"
            className="text-input"
          />
        </div>
      )}
      
      <div className="form-group">
        <label>Proxy Port</label>
        <input
          type="text"
          value={configOptions.proxyPort}
          onChange={(e) => setConfigOptions({...configOptions, proxyPort: e.target.value})}
          placeholder="8080"
          className="text-input"
        />
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
            <div className="checkbox-group">
              <label>
                <input
                  type="checkbox"
                  checked={configOptions.headless}
                  onChange={(e) => setConfigOptions({...configOptions, headless: e.target.checked})}
                />
                Headless Mode
              </label>
              
              <label>
                <input
                  type="checkbox"
                  checked={configOptions.disableBrowser}
                  onChange={(e) => setConfigOptions({...configOptions, disableBrowser: e.target.checked})}
                />
                Disable Embedded Browser
              </label>
            </div>
            
            <div className="form-group">
              <label>Memory Allocation (MB)</label>
              <input
                type="number"
                min="512"
                max="8192"
                value={configOptions.memory}
                onChange={(e) => setConfigOptions({...configOptions, memory: e.target.value})}
                className="text-input"
              />
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
        <p>Note: Burp Suite commands may vary based on your installation method and operating system.</p>
      </div>
    </div>
  );
};

export default BurpSuiteBuilder;