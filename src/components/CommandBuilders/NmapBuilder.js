import { useState, useContext } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FaCopy, FaInfoCircle, FaTerminal, FaHistory } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { useCommandHistory } from '../../contexts/CommandHistoryContext';
import { validateIpAddress, validateDomain, sanitizeInput } from '../../utils/commandHelpers';
import { copyToClipboard } from '../../utils/copyToClipboard';
import CommandHistory from '../UI/CommandHistory';

const NmapBuilder = () => {
  const [scanType, setScanType] = useState('sS');
  const [target, setTarget] = useState('');
  const [options, setOptions] = useState({
    verbose: false,
    osDetection: false,
    serviceVersion: false,
    portRange: '1-1000',
    timing: 'T4',
    output: '',
    script: ''
  });
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [targetError, setTargetError] = useState('');
  const { addToHistory } = useCommandHistory();

  const scanTypes = [
    { value: 'sS', label: 'Stealth Scan (SYN)', description: 'Half-open scan that doesn\'t complete TCP connections' },
    { value: 'sT', label: 'TCP Connect Scan', description: 'Completes full TCP connections' },
    { value: 'sU', label: 'UDP Scan', description: 'Scans UDP ports (slower than TCP)' },
    { value: 'sN', label: 'NULL Scan', description: 'Sends packets with no flags set' },
    { value: 'sF', label: 'FIN Scan', description: 'Sends packets with just the FIN flag' },
    { value: 'sX', label: 'XMAS Scan', description: 'Sends packets with FIN, PSH, and URG flags' },
    { value: 'sA', label: 'ACK Scan', description: 'Used to map firewall rulesets' },
    { value: 'sW', label: 'Window Scan', description: 'Similar to ACK scan but can detect open ports' },
  ];

  const timingOptions = [
    { value: 'T0', label: 'Paranoid (T0)', description: 'Very slow, avoids IDS detection' },
    { value: 'T1', label: 'Sneaky (T1)', description: 'Quite slow, for patient people' },
    { value: 'T2', label: 'Polite (T2)', description: 'Slower but less likely to overwhelm' },
    { value: 'T3', label: 'Normal (T3)', description: 'Default speed' },
    { value: 'T4', label: 'Aggressive (T4)', description: 'Fast scan, recommended' },
    { value: 'T5', label: 'Insane (T5)', description: 'Very fast, may lose accuracy' },
  ];

  const validateTarget = (value) => {
    if (!value) {
      setTargetError('');
      return true;
    }
    
    const sanitized = sanitizeInput(value);
    const isValidIp = validateIpAddress(sanitized);
    const isValidDomain = validateDomain(sanitized);
    
    if (isValidIp || isValidDomain) {
      setTargetError('');
      return true;
    }
    
    setTargetError('Please enter a valid IP address or domain name');
    return false;
  };

  const handleTargetChange = (e) => {
    const value = e.target.value;
    setTarget(value);
    validateTarget(value);
  };

  const buildCommand = () => {
    let cmd = `nmap -${scanType}`;
    
    if (target) cmd += ` ${target}`;
    if (options.portRange) cmd += ` -p ${options.portRange}`;
    if (options.verbose) cmd += ' -v';
    if (options.osDetection) cmd += ' -O';
    if (options.serviceVersion) cmd += ' -sV';
    if (options.timing) cmd += ` -${options.timing}`;
    if (options.output) cmd += ` -oN ${options.output}`;
    if (options.script) cmd += ` --script ${options.script}`;
    
    return cmd;
  };

  const handleCopy = async () => {
    if (target && !validateTarget(target)) return;
    
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
        <FaTerminal className="icon" />
        <h2>Nmap Command Builder</h2>
        <p>Network scanning and enumeration tool</p>
      </div>
      
      <div className="form-group">
        <label>Scan Type</label>
        <select 
          value={scanType} 
          onChange={(e) => setScanType(e.target.value)}
          className="select-input"
        >
          {scanTypes.map(type => (
            <option key={type.value} value={type.value}>
              {type.label}
            </option>
          ))}
        </select>
        <div className="description">
          {scanTypes.find(t => t.value === scanType).description}
        </div>
      </div>
      
      <div className="form-group">
        <label>Target (IP or Domain)</label>
        <input
          type="text"
          value={target}
          onChange={handleTargetChange}
          placeholder="192.168.1.1 or example.com"
          className={`text-input ${targetError ? 'error' : ''}`}
        />
        {targetError && <div className="error-message">{targetError}</div>}
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
            <div className="form-group">
              <label>Port Range</label>
              <input
                type="text"
                value={options.portRange}
                onChange={(e) => setOptions({...options, portRange: e.target.value})}
                placeholder="1-1000 or 22,80,443"
                className="text-input"
              />
            </div>
            
            <div className="form-group">
              <label>Nmap Script</label>
              <input
                type="text"
                value={options.script}
                onChange={(e) => setOptions({...options, script: e.target.value})}
                placeholder="vuln, http-enum, etc."
                className="text-input"
              />
            </div>
            
            <div className="checkbox-group">
              <label>
                <input
                  type="checkbox"
                  checked={options.verbose}
                  onChange={(e) => setOptions({...options, verbose: e.target.checked})}
                />
                Verbose Output (-v)
              </label>
              
              <label>
                <input
                  type="checkbox"
                  checked={options.osDetection}
                  onChange={(e) => setOptions({...options, osDetection: e.target.checked})}
                />
                OS Detection (-O)
              </label>
              
              <label>
                <input
                  type="checkbox"
                  checked={options.serviceVersion}
                  onChange={(e) => setOptions({...options, serviceVersion: e.target.checked})}
                />
                Service Version (-sV)
              </label>
            </div>
            
            <div className="form-group">
              <label>Timing Template</label>
              <select
                value={options.timing}
                onChange={(e) => setOptions({...options, timing: e.target.value})}
                className="select-input"
              >
                {timingOptions.map(timing => (
                  <option key={timing.value} value={timing.value}>
                    {timing.label}
                  </option>
                ))}
              </select>
              <div className="description">
                {timingOptions.find(t => t.value === options.timing).description}
              </div>
            </div>
            
            <div className="form-group">
              <label>Output File (optional)</label>
              <input
                type="text"
                value={options.output}
                onChange={(e) => setOptions({...options, output: e.target.value})}
                placeholder="scan_results.txt"
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
        <p>Remember: Only scan networks you have permission to test. Unauthorized scanning may be illegal.</p>
      </div>
    </div>
  );
};

export default NmapBuilder;