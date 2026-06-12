import { useState } from 'react';
import { FaSearch, FaCopy, FaInfoCircle, FaRedo } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { useCommandHistory } from '../../contexts/CommandHistoryContext';
import { copyToClipboard } from '../../utils/copyToClipboard';

const DimitryBuilder = () => {
  const [target, setTarget] = useState('');
  const [options, setOptions] = useState({
    whois: true,
    email: true,
    subdomains: true,
    ipInfo: false,
    ports: false,
    verbose: false,
    output: '',
  });
  const { addToHistory } = useCommandHistory();

  const examples = [
    { label: 'Full Recon', command: 'dmitry -winsepo output.txt <target>' },
    { label: 'Whois + Subdomains + Email', command: 'dmitry -wise <target>' },
    { label: 'Email Harvesting Only', command: 'dmitry -e <target>' },
    { label: 'Port Scan + OSINT', command: 'dmitry -wnpb <target>' },
  ];

  const [example, setExample] = useState('');

  const substituteTarget = (cmd) => {
    if (!cmd) return '';
    return target ? cmd.replace(/<target>/g, target) : cmd;
  };

  const buildCommand = () => {
    if (example) return substituteTarget(example);
    let flags = '';
    if (options.whois) flags += 'w';
    if (options.email) flags += 'e';
    if (options.subdomains) flags += 'i';
    if (options.ipInfo) flags += 'n';
    if (options.ports) flags += 'pb';
    if (options.verbose) flags += 'v';

    let cmd = `dmitry`;
    if (flags) cmd += ` -${flags}`;
    if (options.output) cmd += ` -o ${options.output}`;
    if (target) cmd += ` ${target}`;
    return cmd;
  };

  const handleReset = () => {
    setTarget('');
    setOptions({ whois: true, email: true, subdomains: true, ipInfo: false, ports: false, verbose: false, output: '' });
    setExample('');
  };

  const handleCopy = async () => {
    try {
      const cmd = buildCommand();
      await copyToClipboard(cmd);
      addToHistory(cmd);
      toast.success('Command copied!', { position: 'bottom-right', autoClose: 2000, hideProgressBar: true });
    } catch {
      toast.error('Failed to copy', { position: 'bottom-right', autoClose: 2000, hideProgressBar: true });
    }
  };

  return (
    <div className="command-builder">
      <div className="builder-header">
        <FaSearch className="icon" />
        <h2>Dmitry Command Builder</h2>
        <p>Deepmagic Information Gathering Tool — OSINT Swiss Army Knife</p>
      </div>

      <div className="form-group">
        <label>Target (Domain or IP) <FaInfoCircle title="Enter the domain or IP you want to investigate." /></label>
        <input
          className="text-input"
          value={target}
          onChange={e => setTarget(e.target.value)}
          placeholder="example.com or 192.168.1.1"
        />
      </div>

      <div className="form-group">
        <label>Quick Examples <FaInfoCircle title="Load a preset command" /></label>
        <select className="select-input" value={example} onChange={e => setExample(e.target.value)}>
          <option value="">-- Select Example --</option>
          {examples.map(ex => (
            <option key={ex.label} value={ex.command}>{ex.label}</option>
          ))}
        </select>
        {example && (
          <div className="description" style={{ marginTop: '0.5rem' }}>
            <code>{target ? substituteTarget(example) : 'Enter a target above to preview.'}</code>
          </div>
        )}
      </div>

      <div className="checkbox-group">
        <label><input type="checkbox" checked={options.whois} onChange={e => setOptions({ ...options, whois: e.target.checked })} /> Whois lookup (-w)</label>
        <label><input type="checkbox" checked={options.email} onChange={e => setOptions({ ...options, email: e.target.checked })} /> Email harvest (-e)</label>
        <label><input type="checkbox" checked={options.subdomains} onChange={e => setOptions({ ...options, subdomains: e.target.checked })} /> Subdomain search (-i)</label>
        <label><input type="checkbox" checked={options.ipInfo} onChange={e => setOptions({ ...options, ipInfo: e.target.checked })} /> IP/Netblock info (-n)</label>
        <label><input type="checkbox" checked={options.ports} onChange={e => setOptions({ ...options, ports: e.target.checked })} /> TCP Port Scan (-pb)</label>
        <label><input type="checkbox" checked={options.verbose} onChange={e => setOptions({ ...options, verbose: e.target.checked })} /> Verbose (-v)</label>
      </div>

      <div className="form-group">
        <label>Output File (optional)</label>
        <input
          className="text-input"
          value={options.output}
          onChange={e => setOptions({ ...options, output: e.target.value })}
          placeholder="results.txt"
        />
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
        <p>Dmitry (Deepmagic Information Gathering Tool) performs OSINT on a domain or IP. Use only on targets you have authorization to investigate.</p>
      </div>
    </div>
  );
};

export default DimitryBuilder;
