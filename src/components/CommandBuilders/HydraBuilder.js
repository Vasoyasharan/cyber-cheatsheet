import { useState, useContext } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FaCopy, FaInfoCircle, FaKey, FaUser } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { useCommandHistory } from '../../contexts/CommandHistoryContext';
import { validateIpAddress, sanitizeInput } from '../../utils/commandHelpers';
import { copyToClipboard } from '../../utils/copyToClipboard';
import CommandHistory from '../UI/CommandHistory';

const HydraBuilder = () => {
  const [service, setService] = useState('ssh');
  const [target, setTarget] = useState('');
  const [options, setOptions] = useState({
    username: '',
    userList: '',
    password: '',
    passwordList: 'rockyou.txt',
    port: '',
    ssl: false,
    verbose: false,
    threads: 16,
    stopOnSuccess: true
  });
  const [showAdvanced, setShowAdvanced] = useState(false);
  const { addToHistory } = useCommandHistory();

  const services = [
    { value: 'ssh', label: 'SSH' },
    { value: 'ftp', label: 'FTP' },
    { value: 'http-post-form', label: 'HTTP POST Form' },
    { value: 'http-get-form', label: 'HTTP GET Form' },
    { value: 'rdp', label: 'RDP' },
    { value: 'smb', label: 'SMB' },
    { value: 'smtp', label: 'SMTP' },
    { value: 'pop3', label: 'POP3' }
  ];

  const defaultPorts = {
    ssh: '22',
    ftp: '21',
    'http-post-form': '80',
    'http-get-form': '80',
    rdp: '3389',
    smb: '445',
    smtp: '25',
    pop3: '110'
  };

  const buildCommand = () => {
    let cmd = 'hydra';
    
    if (target) cmd += ` ${target}`;
    if (service) cmd += ` ${service}`;
    if (options.port) cmd += ` -s ${options.port}`;
    if (options.username) cmd += ` -l ${options.username}`;
    if (options.userList) cmd += ` -L ${options.userList}`;
    if (options.password) cmd += ` -p ${options.password}`;
    if (options.passwordList) cmd += ` -P ${options.passwordList}`;
    if (options.ssl) cmd += ' -S';
    if (options.verbose) cmd += ' -v';
    if (options.threads !== 16) cmd += ` -t ${options.threads}`;
    if (options.stopOnSuccess) cmd += ' -f';
    
    return cmd;
  };

  const handleCopy = async () => {
    if (!target) {
      toast.error('Please enter a target IP or hostname', {
        position: 'bottom-right',
        autoClose: 2000,
        hideProgressBar: true,
      });
      return;
    }

    if (!options.username && !options.userList) {
      toast.error('Please specify either a username or user list', {
        position: 'bottom-right',
        autoClose: 2000,
        hideProgressBar: true,
      });
      return;
    }

    if (!options.password && !options.passwordList) {
      toast.error('Please specify either a password or password list', {
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

  const handleTargetChange = (e) => {
    setTarget(sanitizeInput(e.target.value));
  };

  const handleServiceChange = (e) => {
    const newService = e.target.value;
    setService(newService);
    setOptions({...options, port: defaultPorts[newService] || ''});
  };

  return (
    <div className="command-builder">
      <div className="builder-header">
        <FaKey className="icon" />
        <h2>Hydra Command Builder</h2>
        <p>Network login cracker</p>
      </div>
      
      <div className="form-group">
        <label>Target (IP/Hostname)</label>
        <input
          type="text"
          value={target}
          onChange={handleTargetChange}
          placeholder="192.168.1.1 or example.com"
          className="text-input"
        />
      </div>
      
      <div className="form-group">
        <label>Service</label>
        <select
          value={service}
          onChange={handleServiceChange}
          className="select-input"
        >
          {services.map(svc => (
            <option key={svc.value} value={svc.value}>
              {svc.label}
            </option>
          ))}
        </select>
      </div>
      
      <div className="form-group">
        <label>Port</label>
        <input
          type="text"
          value={options.port || defaultPorts[service] || ''}
          onChange={(e) => setOptions({...options, port: sanitizeInput(e.target.value)})}
          placeholder={defaultPorts[service] || 'Port number'}
          className="text-input"
        />
      </div>
      
      <div className="form-row">
        <div className="form-group">
          <label>Username</label>
          <input
            type="text"
            value={options.username}
            onChange={(e) => setOptions({...options, username: sanitizeInput(e.target.value)})}
            placeholder="admin"
            className="text-input"
          />
        </div>
        
        <div className="form-group">
          <label>User List</label>
          <input
            type="text"
            value={options.userList}
            onChange={(e) => setOptions({...options, userList: sanitizeInput(e.target.value)})}
            placeholder="users.txt"
            className="text-input"
          />
        </div>
      </div>
      
      <div className="form-row">
        <div className="form-group">
          <label>Password</label>
          <input
            type="text"
            value={options.password}
            onChange={(e) => setOptions({...options, password: sanitizeInput(e.target.value)})}
            placeholder="password123"
            className="text-input"
          />
        </div>
        
        <div className="form-group">
          <label>Password List</label>
          <input
            type="text"
            value={options.passwordList}
            onChange={(e) => setOptions({...options, passwordList: sanitizeInput(e.target.value)})}
            placeholder="passwords.txt"
            className="text-input"
          />
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
            <div className="checkbox-group">
              <label>
                <input
                  type="checkbox"
                  checked={options.ssl}
                  onChange={(e) => setOptions({...options, ssl: e.target.checked})}
                />
                Use SSL
              </label>
              
              <label>
                <input
                  type="checkbox"
                  checked={options.verbose}
                  onChange={(e) => setOptions({...options, verbose: e.target.checked})}
                />
                Verbose
              </label>
              
              <label>
                <input
                  type="checkbox"
                  checked={options.stopOnSuccess}
                  onChange={(e) => setOptions({...options, stopOnSuccess: e.target.checked})}
                />
                Stop on first success
              </label>
            </div>
            
            <div className="form-group">
              <label>Threads</label>
              <input
                type="number"
                min="1"
                max="64"
                value={options.threads}
                onChange={(e) => setOptions({...options, threads: parseInt(e.target.value) || 1})}
                className="text-input"
              />
            </div>
            
            {(service === 'http-post-form' || service === 'http-get-form') && (
              <div className="form-group">
                <label>Login Form Syntax</label>
                <input
                  type="text"
                  placeholder="/login.php:user=^USER^&pass=^PASS^:F=incorrect"
                  className="text-input"
                  disabled
                />
                <div className="description">
                  For HTTP forms, append this to the command after selecting options
                </div>
              </div>
            )}
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
        {(service === 'http-post-form' || service === 'http-get-form') && (
          <div className="http-form-note">
            Remember to append your login form syntax to the command (see Advanced Options)
          </div>
        )}
      </div>
      
      <CommandHistory />
      
      <div className="info-tip warning">
        <FaInfoCircle />
        <p>Warning: Brute-forcing credentials without authorization is illegal. Use only on systems you own or have permission to test.</p>
      </div>
    </div>
  );
};

export default HydraBuilder;