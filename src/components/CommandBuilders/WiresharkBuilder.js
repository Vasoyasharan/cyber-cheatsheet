import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FaCopy, FaInfoCircle, FaNetworkWired } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { useCommandHistory } from '../../contexts/CommandHistoryContext';
import { copyToClipboard } from '../../utils/copyToClipboard';
import CommandHistory from '../UI/CommandHistory';

const WiresharkBuilder = () => {
  const [captureOptions, setCaptureOptions] = useState({
    interface: '',
    filter: '',
    outputFile: '',
    packetCount: '',
    duration: '',
    promiscuous: true,
    monitorMode: false
  });
  const [showAdvanced, setShowAdvanced] = useState(false);
  const { addToHistory } = useCommandHistory();

  const commonInterfaces = ['eth0', 'wlan0', 'any'];
  const commonFilters = [
    'tcp', 'udp', 'http', 'dns', 
    'icmp', 'arp', 'port 80', 'port 443',
    'host 192.168.1.1', 'net 192.168.1.0/24'
  ];

  const buildCommand = () => {
    let cmd = 'wireshark';
    
    if (captureOptions.interface) {
      cmd += ` -i ${captureOptions.interface}`;
    }
    
    if (captureOptions.filter) {
      cmd += ` -f "${captureOptions.filter}"`;
    }
    
    if (captureOptions.outputFile) {
      cmd += ` -w ${captureOptions.outputFile}`;
    }
    
    if (captureOptions.packetCount) {
      cmd += ` -c ${captureOptions.packetCount}`;
    }
    
    if (captureOptions.duration) {
      cmd += ` -a duration:${captureOptions.duration}`;
    }
    
    if (!captureOptions.promiscuous) {
      cmd += ' -p';
    }
    
    if (captureOptions.monitorMode && captureOptions.interface && captureOptions.interface.startsWith('wlan')) {
      cmd += ' -I';
    }
    
    return cmd;
  };

  const handleCopy = async () => {
    if (!captureOptions.interface) {
      toast.error('Please specify a network interface', {
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

  const handleFilterSelect = (filter) => {
    setCaptureOptions({...captureOptions, filter});
  };

  return (
    <div className="command-builder">
      <div className="builder-header">
        <FaNetworkWired className="icon" />
        <h2>Wireshark Command Builder</h2>
        <p>Network protocol analyzer</p>
      </div>
      
      <div className="form-group">
        <label>Network Interface</label>
        <select
          value={captureOptions.interface}
          onChange={(e) => setCaptureOptions({...captureOptions, interface: e.target.value})}
          className="select-input"
        >
          <option value="">Select interface</option>
          {commonInterfaces.map(intf => (
            <option key={intf} value={intf}>
              {intf}
            </option>
          ))}
        </select>
      </div>
      
      <div className="form-group">
        <label>Capture Filter</label>
        <input
          type="text"
          value={captureOptions.filter}
          onChange={(e) => setCaptureOptions({...captureOptions, filter: e.target.value})}
          placeholder="tcp port 80 or udp port 53"
          className="text-input"
        />
        <div className="filter-suggestions">
          {commonFilters.map(filter => (
            <button
              key={filter}
              className="filter-chip"
              onClick={() => handleFilterSelect(filter)}
            >
              {filter}
            </button>
          ))}
        </div>
      </div>
      
      <div className="form-group">
        <label>Output File (optional)</label>
        <input
          type="text"
          value={captureOptions.outputFile}
          onChange={(e) => setCaptureOptions({...captureOptions, outputFile: e.target.value})}
          placeholder="capture.pcapng"
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
            <div className="form-row">
              <div className="form-group">
                <label>Packet Count Limit</label>
                <input
                  type="number"
                  min="1"
                  value={captureOptions.packetCount}
                  onChange={(e) => setCaptureOptions({...captureOptions, packetCount: e.target.value})}
                  placeholder="Unlimited"
                  className="text-input"
                />
              </div>
              
              <div className="form-group">
                <label>Duration (seconds)</label>
                <input
                  type="number"
                  min="1"
                  value={captureOptions.duration}
                  onChange={(e) => setCaptureOptions({...captureOptions, duration: e.target.value})}
                  placeholder="Unlimited"
                  className="text-input"
                />
              </div>
            </div>
            
            <div className="checkbox-group">
              <label>
                <input
                  type="checkbox"
                  checked={captureOptions.promiscuous}
                  onChange={(e) => setCaptureOptions({...captureOptions, promiscuous: e.target.checked})}
                />
                Promiscuous Mode
              </label>
              
              {captureOptions.interface && captureOptions.interface.startsWith('wlan') && (
                <label>
                  <input
                    type="checkbox"
                    checked={captureOptions.monitorMode}
                    onChange={(e) => setCaptureOptions({...captureOptions, monitorMode: e.target.checked})}
                  />
                  Monitor Mode (802.11)
                </label>
              )}
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
      
      <div className="info-tip warning">
        <FaInfoCircle />
        <p>Warning: Capturing network traffic may be subject to legal restrictions. Only capture traffic you are authorized to monitor.</p>
      </div>
    </div>
  );
};

export default WiresharkBuilder;