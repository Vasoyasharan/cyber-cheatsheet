import { useState } from 'react';
import { FaWifi, FaCopy, FaInfoCircle, FaRedo } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { useCommandHistory } from '../../contexts/CommandHistoryContext';
import { copyToClipboard } from '../../utils/copyToClipboard';

const AircrackBuilder = () => {
  const [mode, setMode] = useState('capture');
  const [options, setOptions] = useState({
    interface: 'wlan0', bssid: '', channel: '', essid: '', captureFile: 'capture.cap',
    wordlist: '/usr/share/wordlists/rockyou.txt', outputFile: 'output', wepKey: false,
  });
  const [example, setExample] = useState('');
  const { addToHistory } = useCommandHistory();

  const modes = [
    { value: 'monitor', label: 'Enable Monitor Mode', desc: 'Put wireless adapter into monitor mode' },
    { value: 'capture', label: 'Capture Handshake', desc: 'Capture WPA/WPA2 4-way handshake' },
    { value: 'deauth', label: 'Deauthentication Attack', desc: 'Force clients to reconnect (capture handshake)' },
    { value: 'crack', label: 'Crack Password', desc: 'Dictionary attack against captured handshake' },
    { value: 'wep', label: 'WEP Cracking', desc: 'Crack WEP encrypted networks' },
  ];

  const examples = [
    { label: 'Enable Monitor Mode', command: 'airmon-ng start wlan0' },
    { label: 'Scan for Networks', command: 'airodump-ng wlan0mon' },
    { label: 'Capture Specific AP', command: 'airodump-ng -c <channel> --bssid <bssid> -w capture wlan0mon' },
    { label: 'Deauth Attack', command: 'aireplay-ng -0 10 -a <bssid> wlan0mon' },
    { label: 'Crack WPA2 Hash', command: 'aircrack-ng -w /usr/share/wordlists/rockyou.txt -b <bssid> capture.cap' },
    { label: 'WEP Crack', command: 'aircrack-ng -b <bssid> capture.cap' },
  ];

  const substituteTarget = (cmd) => {
    let result = cmd;
    if (options.bssid) result = result.replace(/<bssid>/g, options.bssid);
    if (options.channel) result = result.replace(/<channel>/g, options.channel);
    return result;
  };

  const buildCommand = () => {
    if (example) return substituteTarget(example);
    switch (mode) {
      case 'monitor':
        return `airmon-ng start ${options.interface}`;
      case 'capture':
        let captureCmd = `airodump-ng`;
        if (options.channel) captureCmd += ` -c ${options.channel}`;
        if (options.bssid) captureCmd += ` --bssid ${options.bssid}`;
        captureCmd += ` -w ${options.outputFile} ${options.interface}mon`;
        return captureCmd;
      case 'deauth':
        return `aireplay-ng -0 10${options.bssid ? ` -a ${options.bssid}` : ''} ${options.interface}mon`;
      case 'crack':
        return `aircrack-ng -w ${options.wordlist}${options.bssid ? ` -b ${options.bssid}` : ''} ${options.captureFile}`;
      case 'wep':
        return `aircrack-ng${options.bssid ? ` -b ${options.bssid}` : ''} ${options.captureFile}`;
      default:
        return 'airmon-ng start wlan0';
    }
  };

  const handleReset = () => {
    setMode('capture');
    setOptions({ interface: 'wlan0', bssid: '', channel: '', essid: '', captureFile: 'capture.cap', wordlist: '/usr/share/wordlists/rockyou.txt', outputFile: 'output', wepKey: false });
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
        <FaWifi className="icon" />
        <h2>Aircrack-ng Suite Builder</h2>
        <p>WiFi security auditing — monitor, capture, deauth & crack</p>
      </div>
      <div className="form-group">
        <label>Mode <FaInfoCircle title="Select the operation to perform" /></label>
        <select className="select-input" value={mode} onChange={e => setMode(e.target.value)}>
          {modes.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
        </select>
        <div className="description">{modes.find(m => m.value === mode)?.desc}</div>
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
        <label>Wireless Interface</label>
        <input className="text-input" value={options.interface} onChange={e => setOptions({ ...options, interface: e.target.value })} placeholder="wlan0" />
      </div>
      <div className="form-group">
        <label>Target BSSID (AP MAC Address)</label>
        <input className="text-input" value={options.bssid} onChange={e => setOptions({ ...options, bssid: e.target.value })} placeholder="AA:BB:CC:DD:EE:FF" />
      </div>
      {(mode === 'capture') && (
        <div className="form-group">
          <label>Channel Number</label>
          <input className="text-input" type="number" value={options.channel} onChange={e => setOptions({ ...options, channel: e.target.value })} placeholder="6" />
        </div>
      )}
      {mode === 'crack' && (
        <div className="form-group">
          <label>Wordlist Path</label>
          <input className="text-input" value={options.wordlist} onChange={e => setOptions({ ...options, wordlist: e.target.value })} placeholder="/usr/share/wordlists/rockyou.txt" />
        </div>
      )}
      {(mode === 'crack' || mode === 'wep') && (
        <div className="form-group">
          <label>Capture File</label>
          <input className="text-input" value={options.captureFile} onChange={e => setOptions({ ...options, captureFile: e.target.value })} placeholder="capture.cap" />
        </div>
      )}
      {mode === 'capture' && (
        <div className="form-group">
          <label>Output Filename (no extension)</label>
          <input className="text-input" value={options.outputFile} onChange={e => setOptions({ ...options, outputFile: e.target.value })} placeholder="output" />
        </div>
      )}
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
        <p>⚠️ Aircrack-ng is for authorized WiFi security testing ONLY. Using on networks without permission is illegal.</p>
      </div>
    </div>
  );
};

export default AircrackBuilder;
