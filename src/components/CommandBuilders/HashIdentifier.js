import { useState } from 'react';
import { FaFingerprint, FaInfoCircle } from 'react-icons/fa';

const hashTypes = [
  { name: 'MD5', regex: /^[a-f0-9]{32}$/i },
  { name: 'SHA1', regex: /^[a-f0-9]{40}$/i },
  { name: 'SHA256', regex: /^[a-f0-9]{64}$/i },
  { name: 'SHA512', regex: /^[a-f0-9]{128}$/i },
  { name: 'bcrypt', regex: /^\$2[aby]?\$.{56}$/ },
  { name: 'WPA/WPA2', regex: /^[a-f0-9]{64}$/i },
];

const HashIdentifier = () => {
  const [input, setInput] = useState('');
  const [result, setResult] = useState('');

  const identify = () => {
    const found = hashTypes.find(ht => ht.regex.test(input.trim()));
    setResult(found ? found.name : 'Unknown or unsupported hash type');
  };

  return (
    <div className="command-builder">
      <div className="builder-header">
        <FaFingerprint className="icon" />
        <h2>Hash Identifier</h2>
        <p>Guess common hash types by format</p>
      </div>
      <div className="form-group">
        <label>Paste Hash</label>
        <input className="text-input" value={input} onChange={e => setInput(e.target.value)} placeholder="Paste hash here..." />
      </div>
      <button className="button" onClick={identify}>Identify</button>
      <div className="command-preview">
        <div className="preview-header">
          <span>Result</span>
        </div>
        <code>{result}</code>
      </div>
      <div className="info-tip">
        <FaInfoCircle className="icon" />
        <p>This tool guesses hash types by length and format. For more advanced detection, use hashid or online tools.</p>
      </div>
    </div>
  );
};

export default HashIdentifier;
