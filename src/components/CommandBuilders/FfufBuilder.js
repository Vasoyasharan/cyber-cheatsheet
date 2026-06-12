import { useState } from 'react';
import { FaBolt, FaCopy, FaInfoCircle, FaRedo } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { useCommandHistory } from '../../contexts/CommandHistoryContext';
import { copyToClipboard } from '../../utils/copyToClipboard';

const FfufBuilder = () => {
  const [url, setUrl] = useState('');
  const [wordlist, setWordlist] = useState('/usr/share/seclists/Discovery/Web-Content/big.txt');
  const [options, setOptions] = useState({
    method: 'GET', extensions: '', threads: '40', filterCode: '', matchCode: '200,204,301,302',
    filterSize: '', filterWords: '', headers: '', data: '', recursion: false, output: '',
  });
  const [example, setExample] = useState('');
  const { addToHistory } = useCommandHistory();

  const wordlists = [
    '/usr/share/seclists/Discovery/Web-Content/big.txt',
    '/usr/share/seclists/Discovery/Web-Content/common.txt',
    '/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt',
    '/usr/share/seclists/Usernames/Names/names.txt',
    '/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt',
  ];

  const examples = [
    { label: 'Directory Brute', command: 'ffuf -u http://FUZZ.<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/big.txt' },
    { label: 'Subdomain Enum', command: 'ffuf -u http://FUZZ.<target>/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.<target>"' },
    { label: 'POST Login Fuzz', command: 'ffuf -u http://<target>/login -X POST -d "username=FUZZ&password=pass" -w /usr/share/seclists/Usernames/Names/names.txt -mc 302' },
    { label: 'Filter by Size', command: 'ffuf -u http://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/big.txt -fs 0' },
  ];

  const substituteTarget = (cmd) => url ? cmd.replace(/<target>/g, url.replace(/https?:\/\//, '')) : cmd;

  const buildCommand = () => {
    if (example) return substituteTarget(example);
    const target = url || 'http://<target>/FUZZ';
    const hasKeyword = target.includes('FUZZ');
    let cmd = `ffuf -u ${hasKeyword ? target : target + '/FUZZ'} -w ${wordlist}`;
    if (options.method !== 'GET') cmd += ` -X ${options.method}`;
    if (options.extensions) cmd += ` -e ${options.extensions}`;
    if (options.threads) cmd += ` -t ${options.threads}`;
    if (options.matchCode) cmd += ` -mc ${options.matchCode}`;
    if (options.filterCode) cmd += ` -fc ${options.filterCode}`;
    if (options.filterSize) cmd += ` -fs ${options.filterSize}`;
    if (options.filterWords) cmd += ` -fw ${options.filterWords}`;
    if (options.headers) cmd += ` -H "${options.headers}"`;
    if (options.data) cmd += ` -d "${options.data}"`;
    if (options.recursion) cmd += ' -recursion';
    if (options.output) cmd += ` -o ${options.output}`;
    return cmd;
  };

  const handleReset = () => {
    setUrl(''); setWordlist(wordlists[0]);
    setOptions({ method: 'GET', extensions: '', threads: '40', filterCode: '', matchCode: '200,204,301,302', filterSize: '', filterWords: '', headers: '', data: '', recursion: false, output: '' });
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
        <FaBolt className="icon" />
        <h2>FFuf Command Builder</h2>
        <p>Fast web fuzzer — directory, subdomain & parameter discovery</p>
      </div>
      <div className="form-group">
        <label>URL (use FUZZ as placeholder) <FaInfoCircle title="Place FUZZ keyword where you want the wordlist injected" /></label>
        <input className="text-input" value={url} onChange={e => setUrl(e.target.value)} placeholder="http://example.com/FUZZ" />
      </div>
      <div className="form-group">
        <label>Wordlist</label>
        <select className="select-input" value={wordlist} onChange={e => setWordlist(e.target.value)}>
          {wordlists.map(w => <option key={w} value={w}>{w}</option>)}
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
        <label>HTTP Method</label>
        <select className="select-input" value={options.method} onChange={e => setOptions({ ...options, method: e.target.value })}>
          {['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD'].map(m => <option key={m} value={m}>{m}</option>)}
        </select>
      </div>
      <div className="form-group">
        <label>Extensions (e.g. php,html,txt)</label>
        <input className="text-input" value={options.extensions} onChange={e => setOptions({ ...options, extensions: e.target.value })} placeholder=".php,.html" />
      </div>
      <div className="form-group">
        <label>Match Status Codes (-mc)</label>
        <input className="text-input" value={options.matchCode} onChange={e => setOptions({ ...options, matchCode: e.target.value })} placeholder="200,301,302" />
      </div>
      <div className="form-group">
        <label>Filter Status Codes (-fc)</label>
        <input className="text-input" value={options.filterCode} onChange={e => setOptions({ ...options, filterCode: e.target.value })} placeholder="404,403" />
      </div>
      <div className="form-group">
        <label>Filter Response Size (-fs)</label>
        <input className="text-input" value={options.filterSize} onChange={e => setOptions({ ...options, filterSize: e.target.value })} placeholder="0 or 1234" />
      </div>
      <div className="form-group">
        <label>Threads (-t)</label>
        <input className="text-input" type="number" value={options.threads} onChange={e => setOptions({ ...options, threads: e.target.value })} placeholder="40" />
      </div>
      <div className="checkbox-group">
        <label><input type="checkbox" checked={options.recursion} onChange={e => setOptions({ ...options, recursion: e.target.checked })} /> Recursive scan</label>
      </div>
      <div className="form-group">
        <label>Output File (optional)</label>
        <input className="text-input" value={options.output} onChange={e => setOptions({ ...options, output: e.target.value })} placeholder="ffuf_results.json" />
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
        <p>FFuf is an extremely fast web fuzzer. The FUZZ keyword is replaced by each word from your wordlist. Only test authorized targets.</p>
      </div>
    </div>
  );
};

export default FfufBuilder;
