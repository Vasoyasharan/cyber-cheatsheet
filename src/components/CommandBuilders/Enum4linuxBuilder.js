import { useState } from 'react';
import { FaServer, FaCopy, FaInfoCircle } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { copyToClipboard } from '../../utils/copyToClipboard';

const Enum4linuxBuilder = () => {
  const [target, setTarget] = useState('');
  const [options, setOptions] = useState({ a: true, u: '', p: '', r: false, s: false });

  const buildCommand = () => {
    let cmd = 'enum4linux';
    if (options.a) cmd += ' -a';
    if (options.r) cmd += ' -r';
    if (options.s) cmd += ' -s';
    if (options.u) cmd += ` -u ${options.u}`;
    if (options.p) cmd += ` -p ${options.p}`;
    if (target) cmd += ` ${target}`;
    return cmd;
  };

  const handleCopy = async () => {
    try {
      await copyToClipboard(buildCommand());
      toast.success('Copied!', { position: 'bottom-right', autoClose: 2000, hideProgressBar: true });
    } catch {
      toast.error('Failed to copy', { position: 'bottom-right', autoClose: 2000, hideProgressBar: true });
    }
  };

  return (
    <div className="command-builder">
      <div className="builder-header">
        <FaServer className="icon" />
        <h2>Enum4linux Builder</h2>
        <p>SMB enumeration for Linux targets</p>
      </div>
      <div className="form-group">
        <label>Target IP/Host</label>
        <input className="text-input" value={target} onChange={e => setTarget(e.target.value)} placeholder="192.168.1.10" />
      </div>
      <div className="checkbox-group">
        <label><input type="checkbox" checked={options.a} onChange={e => setOptions({ ...options, a: e.target.checked })} /> All info (-a)</label>
        <label><input type="checkbox" checked={options.r} onChange={e => setOptions({ ...options, r: e.target.checked })} /> RID brute force (-r)</label>
        <label><input type="checkbox" checked={options.s} onChange={e => setOptions({ ...options, s: e.target.checked })} /> Share enumeration (-s)</label>
      </div>
      <div className="form-group">
        <label>Username (optional)</label>
        <input className="text-input" value={options.u} onChange={e => setOptions({ ...options, u: e.target.value })} placeholder="user" />
      </div>
      <div className="form-group">
        <label>Password (optional)</label>
        <input className="text-input" value={options.p} onChange={e => setOptions({ ...options, p: e.target.value })} placeholder="pass" />
      </div>
      <div className="command-preview">
        <div className="preview-header">
          <span>Preview</span>
          <button className="copy-button" onClick={handleCopy}><FaCopy /> Copy</button>
        </div>
        <code>{buildCommand()}</code>
      </div>
      <div className="info-tip">
        <FaInfoCircle className="icon" />
        <p>Enum4linux is used for SMB enumeration. Use responsibly and only on systems you have permission to test.</p>
      </div>
    </div>
  );
};

export default Enum4linuxBuilder;
