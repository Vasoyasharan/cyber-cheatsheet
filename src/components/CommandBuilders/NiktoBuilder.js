import { useState } from 'react';
import { FaGlobe, FaCopy, FaInfoCircle, FaRedo } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { useCommandHistory } from '../../contexts/CommandHistoryContext';
import { copyToClipboard } from '../../utils/copyToClipboard';

const NiktoBuilder = () => {
  const [target, setTarget] = useState('');
  const [port, setPort] = useState('80');
  const [options, setOptions] = useState({
    ssl: false, tuning: '', useProxy: false, proxy: '', output: '', followRedirects: false, evasion: '',
  });
  const [example, setExample] = useState('');
  const { addToHistory } = useCommandHistory();

  const tuningOptions = [
    { value: '', label: 'All Tests (default)' }, { value: '1', label: '1 - Interesting Files' },
    { value: '2', label: '2 - Misconfiguration' }, { value: '4', label: '4 - Injection (XSS/Script)' },
    { value: '8', label: '8 - Command Execution' }, { value: '9', label: '9 - SQL Injection' },
  ];

  const evasionOptions = [
    { value: '', label: 'None' }, { value: '1', label: '1 - Random URI Encoding' },
    { value: '3', label: '3 - Premature URL Ending' }, { value: '7', label: '7 - Change URL Case' },
  ];

  const examples = [
    { label: 'Basic Web Scan', command: 'nikto -h http://<target>' },
    { label: 'HTTPS Scan (443)', command: 'nikto -h <target> -ssl -p 443' },
    { label: 'Save HTML Report', command: 'nikto -h http://<target> -o report.html -Format htm' },
    { label: 'Via Burp Proxy', command: 'nikto -h http://<target> -useproxy http://127.0.0.1:8080' },
    { label: 'SQL Injection Focus', command: 'nikto -h http://<target> -Tuning 9' },
  ];

  const substituteTarget = (cmd) => target ? cmd.replace(/<target>/g, target) : cmd;

  const buildCommand = () => {
    if (example) return substituteTarget(example);
    let cmd = 'nikto';
    cmd += target ? ` -h ${options.ssl ? 'https' : 'http'}://${target}` : ' -h <target>';
    if (port && port !== '80') cmd += ` -p ${port}`;
    if (options.ssl) cmd += ' -ssl';
    if (options.tuning) cmd += ` -Tuning ${options.tuning}`;
    if (options.evasion) cmd += ` -evasion ${options.evasion}`;
    if (options.useProxy && options.proxy) cmd += ` -useproxy ${options.proxy}`;
    if (options.followRedirects) cmd += ' -Followredirects';
    if (options.output) cmd += ` -o ${options.output}`;
    return cmd;
  };

  const handleReset = () => {
    setTarget(''); setPort('80');
    setOptions({ ssl: false, tuning: '', useProxy: false, proxy: '', output: '', followRedirects: false, evasion: '' });
    setExample('');
  };

  const handleCopy = async () => {
    try {
      const cmd = buildCommand();
      await copyToClipboard(cmd);
      addToHistory(cmd);
      toast.success('Copied!', { position: 'bottom-right', autoClose: 2000, hideProgressBar: true });
    } catch {
      toast.error('Failed to copy', { position: 'bottom-right', autoClose: 2000, hideProgressBar: true });
    }
  };

  return (
    <div className="command-builder">
      <div className="builder-header">
        <FaGlobe className="icon" />
        <h2>Nikto Command Builder</h2>
        <p>Web server scanner — detect vulnerabilities & misconfigurations</p>
      </div>
      <div className="form-group">
        <label>Target Host/IP</label>
        <input className="text-input" value={target} onChange={e => setTarget(e.target.value)} placeholder="example.com or 192.168.1.1" />
      </div>
      <div className="form-group">
        <label>Port</label>
        <input className="text-input" type="number" value={port} onChange={e => setPort(e.target.value)} placeholder="80" />
      </div>
      <div className="form-group">
        <label>Quick Examples</label>
        <select className="select-input" value={example} onChange={e => setExample(e.target.value)}>
          <option value="">-- Select Example --</option>
          {examples.map(ex => <option key={ex.label} value={ex.command}>{ex.label}</option>)}
        </select>
        {example && <div className="description"><code>{substituteTarget(example)}</code></div>}
      </div>
      <div className="form-group">
        <label>Scan Tuning (Plugin Focus)</label>
        <select className="select-input" value={options.tuning} onChange={e => setOptions({ ...options, tuning: e.target.value })}>
          {tuningOptions.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
        </select>
      </div>
      <div className="form-group">
        <label>IDS Evasion</label>
        <select className="select-input" value={options.evasion} onChange={e => setOptions({ ...options, evasion: e.target.value })}>
          {evasionOptions.map(e => <option key={e.value} value={e.value}>{e.label}</option>)}
        </select>
      </div>
      <div className="checkbox-group">
        <label><input type="checkbox" checked={options.ssl} onChange={e => setOptions({ ...options, ssl: e.target.checked })} /> Use SSL/HTTPS</label>
        <label><input type="checkbox" checked={options.followRedirects} onChange={e => setOptions({ ...options, followRedirects: e.target.checked })} /> Follow Redirects</label>
        <label><input type="checkbox" checked={options.useProxy} onChange={e => setOptions({ ...options, useProxy: e.target.checked })} /> Route via Proxy</label>
      </div>
      {options.useProxy && (
        <div className="form-group">
          <label>Proxy URL</label>
          <input className="text-input" value={options.proxy} onChange={e => setOptions({ ...options, proxy: e.target.value })} placeholder="http://127.0.0.1:8080" />
        </div>
      )}
      <div className="form-group">
        <label>Output File (optional)</label>
        <input className="text-input" value={options.output} onChange={e => setOptions({ ...options, output: e.target.value })} placeholder="nikto_report.html" />
      </div>
      <button onClick={handleReset} className="toggle-button"><FaRedo /> Reset</button>
      <div className="command-preview">
        <div className="preview-header">
          <h3>Generated Command</h3>
          <button className="copy-button" onClick={handleCopy}><FaCopy /> Copy</button>
        </div>
        <code>{buildCommand()}</code>
      </div>
      <div className="info-tip">
        <FaInfoCircle />
        <p>Nikto scans web servers for dangerous files, outdated software, and misconfigurations. Only test on authorized targets.</p>
      </div>
    </div>
  );
};

export default NiktoBuilder;
