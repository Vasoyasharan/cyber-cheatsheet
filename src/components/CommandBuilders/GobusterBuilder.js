import { useState } from 'react';
import { FaFolderOpen, FaCopy, FaInfoCircle, FaRedo } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { useCommandHistory } from '../../contexts/CommandHistoryContext';
import { copyToClipboard } from '../../utils/copyToClipboard';

const GobusterBuilder = () => {
  const [mode, setMode] = useState('dir');
  const [target, setTarget] = useState('');
  const [wordlist, setWordlist] = useState('/usr/share/wordlists/dirb/common.txt');
  const [options, setOptions] = useState({
    extensions: '',
    threads: '10',
    statusCodes: '200,204,301,302,307,401,403',
    noTlsVerify: false,
    followRedirect: false,
    quiet: false,
    output: '',
    userAgent: '',
    delay: '',
  });
  const { addToHistory } = useCommandHistory();

  const modes = [
    { value: 'dir', label: 'Directory Bruteforce', desc: 'Discover hidden directories and files' },
    { value: 'dns', label: 'DNS Subdomain Brute', desc: 'Enumerate subdomains via DNS' },
    { value: 'vhost', label: 'Virtual Host Enum', desc: 'Enumerate virtual hostnames' },
    { value: 'fuzz', label: 'Fuzzing Mode', desc: 'Replace FUZZ keyword in URL' },
    { value: 's3', label: 'AWS S3 Buckets', desc: 'Enumerate public S3 buckets' },
  ];

  const wordlists = [
    '/usr/share/wordlists/dirb/common.txt',
    '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
    '/usr/share/seclists/Discovery/Web-Content/big.txt',
    '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt',
  ];

  const examples = [
    { label: 'Dir Brute (Common)', command: 'gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt -t 50' },
    { label: 'DNS Subdomain Enum', command: 'gobuster dns -d <target> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt' },
    { label: 'PHP Extension Scan', command: 'gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt -x php,html,txt' },
    { label: 'Stealth Scan', command: 'gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt -t 5 --delay 500ms -q' },
  ];
  const [example, setExample] = useState('');

  const substituteTarget = (cmd) => target ? cmd.replace(/<target>/g, target) : cmd;

  const buildCommand = () => {
    if (example) return substituteTarget(example);
    let cmd = `gobuster ${mode}`;
    if (mode === 'dns') {
      cmd += target ? ` -d ${target}` : ' -d <domain>';
    } else {
      cmd += target ? ` -u http://${target}` : ' -u <url>';
    }
    cmd += ` -w ${wordlist}`;
    if (options.extensions && mode === 'dir') cmd += ` -x ${options.extensions}`;
    if (options.threads) cmd += ` -t ${options.threads}`;
    if (options.statusCodes && mode === 'dir') cmd += ` -s ${options.statusCodes}`;
    if (options.noTlsVerify) cmd += ' -k';
    if (options.followRedirect && mode === 'dir') cmd += ' -r';
    if (options.quiet) cmd += ' -q';
    if (options.delay) cmd += ` --delay ${options.delay}ms`;
    if (options.userAgent) cmd += ` -a "${options.userAgent}"`;
    if (options.output) cmd += ` -o ${options.output}`;
    return cmd;
  };

  const handleReset = () => {
    setMode('dir'); setTarget(''); setWordlist(wordlists[0]);
    setOptions({ extensions: '', threads: '10', statusCodes: '200,204,301,302,307,401,403', noTlsVerify: false, followRedirect: false, quiet: false, output: '', userAgent: '', delay: '' });
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
        <FaFolderOpen className="icon" />
        <h2>Gobuster Command Builder</h2>
        <p>Directory, DNS & Virtual Host brute-force enumeration</p>
      </div>

      <div className="form-group">
        <label>Mode <FaInfoCircle title="Select the gobuster mode" /></label>
        <select className="select-input" value={mode} onChange={e => setMode(e.target.value)}>
          {modes.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
        </select>
        <div className="description">{modes.find(m => m.value === mode)?.desc}</div>
      </div>

      <div className="form-group">
        <label>Target {mode === 'dns' ? '(Domain)' : '(URL/Host)'}</label>
        <input className="text-input" value={target} onChange={e => setTarget(e.target.value)} placeholder={mode === 'dns' ? 'example.com' : 'example.com or 192.168.1.1'} />
      </div>

      <div className="form-group">
        <label>Wordlist <FaInfoCircle title="Path to the wordlist file" /></label>
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
        <label>Extensions (dir mode, e.g. php,html,txt)</label>
        <input className="text-input" value={options.extensions} onChange={e => setOptions({ ...options, extensions: e.target.value })} placeholder="php,html,txt" />
      </div>

      <div className="form-group">
        <label>Threads</label>
        <input className="text-input" type="number" value={options.threads} onChange={e => setOptions({ ...options, threads: e.target.value })} placeholder="10" />
      </div>

      <div className="checkbox-group">
        <label><input type="checkbox" checked={options.noTlsVerify} onChange={e => setOptions({ ...options, noTlsVerify: e.target.checked })} /> Skip TLS Verification (-k)</label>
        <label><input type="checkbox" checked={options.followRedirect} onChange={e => setOptions({ ...options, followRedirect: e.target.checked })} /> Follow Redirects (-r)</label>
        <label><input type="checkbox" checked={options.quiet} onChange={e => setOptions({ ...options, quiet: e.target.checked })} /> Quiet mode (-q)</label>
      </div>

      <div className="form-group">
        <label>Output File (optional)</label>
        <input className="text-input" value={options.output} onChange={e => setOptions({ ...options, output: e.target.value })} placeholder="results.txt" />
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
        <p>Gobuster is a fast directory/file/DNS/VHost enumeration tool written in Go. Only use on authorized targets.</p>
      </div>
    </div>
  );
};

export default GobusterBuilder;
