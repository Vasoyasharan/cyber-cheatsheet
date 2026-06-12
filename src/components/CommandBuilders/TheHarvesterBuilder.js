import { useState } from 'react';
import { FaDatabase, FaCopy, FaInfoCircle, FaRedo } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { useCommandHistory } from '../../contexts/CommandHistoryContext';
import { copyToClipboard } from '../../utils/copyToClipboard';

const TheHarvesterBuilder = () => {
  const [domain, setDomain] = useState('');
  const [options, setOptions] = useState({
    source: 'all', limit: '500', start: '0', shodan: false, dns: false, virtual: false, output: '', format: 'html',
  });
  const [example, setExample] = useState('');
  const { addToHistory } = useCommandHistory();

  const sources = [
    'all', 'baidu', 'bing', 'bingapi', 'certspotter', 'crtsh', 'dnsdumpster',
    'duckduckgo', 'github-code', 'google', 'hackertarget', 'hunter', 'linkedin',
    'netcraft', 'otx', 'rapiddns', 'shodan', 'sublist3r', 'threatcrowd',
    'twitter', 'virustotal', 'yahoo',
  ];

  const examples = [
    { label: 'Full Recon (all sources)', command: 'theHarvester -d <target> -b all -l 500' },
    { label: 'Google + LinkedIn', command: 'theHarvester -d <target> -b google,linkedin -l 200' },
    { label: 'With Shodan Integration', command: 'theHarvester -d <target> -b all -s -l 500' },
    { label: 'Save HTML Report', command: 'theHarvester -d <target> -b all -f report' },
    { label: 'DNS Brute Force', command: 'theHarvester -d <target> -b all -c' },
  ];

  const substituteTarget = (cmd) => domain ? cmd.replace(/<target>/g, domain) : cmd;

  const buildCommand = () => {
    if (example) return substituteTarget(example);
    let cmd = `theHarvester -d ${domain || '<domain>'} -b ${options.source} -l ${options.limit}`;
    if (options.start && options.start !== '0') cmd += ` -S ${options.start}`;
    if (options.shodan) cmd += ' -s';
    if (options.dns) cmd += ' -c';
    if (options.virtual) cmd += ' -v';
    if (options.output) cmd += ` -f ${options.output}`;
    return cmd;
  };

  const handleReset = () => {
    setDomain('');
    setOptions({ source: 'all', limit: '500', start: '0', shodan: false, dns: false, virtual: false, output: '', format: 'html' });
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
        <FaDatabase className="icon" />
        <h2>theHarvester Builder</h2>
        <p>Email, subdomain, host & employee OSINT harvesting tool</p>
      </div>
      <div className="form-group">
        <label>Target Domain <FaInfoCircle title="Domain to harvest information from" /></label>
        <input className="text-input" value={domain} onChange={e => setDomain(e.target.value)} placeholder="example.com" />
      </div>
      <div className="form-group">
        <label>Data Source <FaInfoCircle title="Search engine or service to query" /></label>
        <select className="select-input" value={options.source} onChange={e => setOptions({ ...options, source: e.target.value })}>
          {sources.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
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
        <label>Result Limit (-l)</label>
        <input className="text-input" type="number" value={options.limit} onChange={e => setOptions({ ...options, limit: e.target.value })} placeholder="500" />
      </div>
      <div className="form-group">
        <label>Start Offset (-S)</label>
        <input className="text-input" type="number" value={options.start} onChange={e => setOptions({ ...options, start: e.target.value })} placeholder="0" />
      </div>
      <div className="checkbox-group">
        <label><input type="checkbox" checked={options.shodan} onChange={e => setOptions({ ...options, shodan: e.target.checked })} /> Shodan Query (-s)</label>
        <label><input type="checkbox" checked={options.dns} onChange={e => setOptions({ ...options, dns: e.target.checked })} /> DNS Brute Force (-c)</label>
        <label><input type="checkbox" checked={options.virtual} onChange={e => setOptions({ ...options, virtual: e.target.checked })} /> Virtual Host (-v)</label>
      </div>
      <div className="form-group">
        <label>Output File (no extension, optional)</label>
        <input className="text-input" value={options.output} onChange={e => setOptions({ ...options, output: e.target.value })} placeholder="harvest_report" />
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
        <p>theHarvester gathers emails, subdomains, hosts, and employees using various public sources. Ethical use only.</p>
      </div>
    </div>
  );
};

export default TheHarvesterBuilder;
