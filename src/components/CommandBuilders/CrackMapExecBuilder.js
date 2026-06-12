import { useState } from 'react';
import { FaNetworkWired, FaCopy, FaInfoCircle, FaRedo } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { useCommandHistory } from '../../contexts/CommandHistoryContext';
import { copyToClipboard } from '../../utils/copyToClipboard';

const CrackMapExecBuilder = () => {
  const [protocol, setProtocol] = useState('smb');
  const [target, setTarget] = useState('');
  const [options, setOptions] = useState({
    username: '', password: '', hashFile: '', shares: false, sessions: false, disks: false,
    loggedon: false, users: false, groups: false, computers: false, cmd: '', module: '',
    noLoginRequired: false, credFile: '', passSpray: false,
  });
  const [example, setExample] = useState('');
  const { addToHistory } = useCommandHistory();

  const protocols = [
    { value: 'smb', label: 'SMB', desc: 'Windows file sharing and RPC protocol' },
    { value: 'rdp', label: 'RDP', desc: 'Windows Remote Desktop Protocol' },
    { value: 'winrm', label: 'WinRM', desc: 'Windows Remote Management' },
    { value: 'mssql', label: 'MSSQL', desc: 'Microsoft SQL Server' },
    { value: 'ssh', label: 'SSH', desc: 'Secure Shell connections' },
    { value: 'ldap', label: 'LDAP', desc: 'Lightweight Directory Access Protocol' },
    { value: 'ftp', label: 'FTP', desc: 'File Transfer Protocol' },
  ];

  const examples = [
    { label: 'Enumerate Hosts', command: 'crackmapexec smb <target>' },
    { label: 'Null Session (Anon)', command: 'crackmapexec smb <target> -u "" -p "" --shares' },
    { label: 'Spray Passwords', command: 'crackmapexec smb <target> -u users.txt -p Password123 --continue-on-success' },
    { label: 'Pass-the-Hash', command: 'crackmapexec smb <target> -u Administrator -H <hash> --local-auth' },
    { label: 'Run CMD', command: 'crackmapexec smb <target> -u admin -p pass -x "whoami"' },
    { label: 'Dump SAM', command: 'crackmapexec smb <target> -u admin -p pass --sam' },
    { label: 'List Users (LDAP)', command: 'crackmapexec ldap <target> -u admin -p pass --users' },
  ];

  const substituteTarget = (cmd) => target ? cmd.replace(/<target>/g, target) : cmd;

  const buildCommand = () => {
    if (example) return substituteTarget(example);
    let cmd = `crackmapexec ${protocol} ${target || '<target>'}`;
    if (options.username) cmd += ` -u ${options.username}`;
    if (options.password) cmd += ` -p '${options.password}'`;
    if (options.shares) cmd += ' --shares';
    if (options.sessions) cmd += ' --sessions';
    if (options.disks) cmd += ' --disks';
    if (options.loggedon) cmd += ' --loggedon-users';
    if (options.users) cmd += ' --users';
    if (options.groups) cmd += ' --groups';
    if (options.computers) cmd += ' --computers';
    if (options.cmd) cmd += ` -x "${options.cmd}"`;
    if (options.module) cmd += ` -M ${options.module}`;
    if (options.passSpray) cmd += ' --continue-on-success';
    return cmd;
  };

  const handleReset = () => {
    setProtocol('smb'); setTarget('');
    setOptions({ username: '', password: '', hashFile: '', shares: false, sessions: false, disks: false, loggedon: false, users: false, groups: false, computers: false, cmd: '', module: '', noLoginRequired: false, credFile: '', passSpray: false });
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
        <FaNetworkWired className="icon" />
        <h2>CrackMapExec Builder</h2>
        <p>Swiss army knife for pentesting Windows/Active Directory networks</p>
      </div>
      <div className="form-group">
        <label>Protocol <FaInfoCircle title="Select the network protocol to target" /></label>
        <select className="select-input" value={protocol} onChange={e => setProtocol(e.target.value)}>
          {protocols.map(p => <option key={p.value} value={p.value}>{p.label} — {p.desc}</option>)}
        </select>
      </div>
      <div className="form-group">
        <label>Target (IP, CIDR, or file)</label>
        <input className="text-input" value={target} onChange={e => setTarget(e.target.value)} placeholder="192.168.1.0/24 or targets.txt" />
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
        <label>Username (-u)</label>
        <input className="text-input" value={options.username} onChange={e => setOptions({ ...options, username: e.target.value })} placeholder="admin or users.txt" />
      </div>
      <div className="form-group">
        <label>Password (-p)</label>
        <input className="text-input" value={options.password} onChange={e => setOptions({ ...options, password: e.target.value })} placeholder="Password123 or passwords.txt" />
      </div>
      <div className="form-group">
        <label>Execute Command (-x)</label>
        <input className="text-input" value={options.cmd} onChange={e => setOptions({ ...options, cmd: e.target.value })} placeholder="whoami" />
      </div>
      <div className="form-group">
        <label>Module (-M)</label>
        <input className="text-input" value={options.module} onChange={e => setOptions({ ...options, module: e.target.value })} placeholder="mimikatz, lsassy, etc." />
      </div>
      <div className="checkbox-group">
        <label><input type="checkbox" checked={options.shares} onChange={e => setOptions({ ...options, shares: e.target.checked })} /> Enumerate Shares</label>
        <label><input type="checkbox" checked={options.users} onChange={e => setOptions({ ...options, users: e.target.checked })} /> Enumerate Users</label>
        <label><input type="checkbox" checked={options.groups} onChange={e => setOptions({ ...options, groups: e.target.checked })} /> Enumerate Groups</label>
        <label><input type="checkbox" checked={options.computers} onChange={e => setOptions({ ...options, computers: e.target.checked })} /> Enumerate Computers</label>
        <label><input type="checkbox" checked={options.sessions} onChange={e => setOptions({ ...options, sessions: e.target.checked })} /> List Sessions</label>
        <label><input type="checkbox" checked={options.loggedon} onChange={e => setOptions({ ...options, loggedon: e.target.checked })} /> Logged-on Users</label>
        <label><input type="checkbox" checked={options.passSpray} onChange={e => setOptions({ ...options, passSpray: e.target.checked })} /> Continue on Success (spray)</label>
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
        <p>CrackMapExec (CME) automates network assessment for Active Directory environments. Only use on authorized networks.</p>
      </div>
    </div>
  );
};

export default CrackMapExecBuilder;
