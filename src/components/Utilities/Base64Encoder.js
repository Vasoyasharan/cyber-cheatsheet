import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaCopy, FaExchangeAlt } from 'react-icons/fa';
import { toast } from 'react-toastify';
import './UtilityTools.css';

const Base64Encoder = () => {
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [mode, setMode] = useState('encode'); // 'encode' or 'decode'

  const encode = (text) => {
    try {
      const encoded = btoa(text);
      setOutput(encoded);
    } catch (error) {
      toast.error('Error encoding: ' + error.message);
      setOutput('');
    }
  };

  const decode = (text) => {
    try {
      const decoded = atob(text);
      setOutput(decoded);
    } catch (error) {
      toast.error('Invalid Base64 string');
      setOutput('');
    }
  };

  const handleInputChange = (e) => {
    const text = e.target.value;
    setInput(text);
    if (text) {
      if (mode === 'encode') {
        encode(text);
      } else {
        decode(text);
      }
    } else {
      setOutput('');
    }
  };

  const toggleMode = () => {
    const newMode = mode === 'encode' ? 'decode' : 'encode';
    setMode(newMode);
    if (input) {
      if (newMode === 'encode') {
        encode(input);
      } else {
        decode(input);
      }
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard!');
  };

  return (
    <div className="utility-tool">
      <div className="utility-section">
        <label>Input Text</label>
        <textarea
          value={input}
          onChange={handleInputChange}
          placeholder={`Enter text to ${mode}...`}
          className="utility-textarea"
          rows={6}
        />
      </div>

      <div className="utility-controls">
        <motion.button
          onClick={toggleMode}
          className="mode-toggle-btn"
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
        >
          <FaExchangeAlt /> Switch to {mode === 'encode' ? 'Decode' : 'Encode'}
        </motion.button>
      </div>

      <div className="utility-section">
        <label>Output Text</label>
        <textarea
          value={output}
          readOnly
          placeholder="Output will appear here..."
          className="utility-textarea"
          rows={6}
        />
        {output && (
          <motion.button
            onClick={() => copyToClipboard(output)}
            className="copy-btn"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            <FaCopy /> Copy Output
          </motion.button>
        )}
      </div>

      <div className="utility-tips">
        <h4>Tips:</h4>
        <ul>
          <li>Use Base64 encoding to obfuscate payloads and commands</li>
          <li>Useful for embedding binary data in text formats</li>
          <li>Common in privilege escalation to bypass command restrictions</li>
          <li>Example: PowerShell uses Base64 for encoded commands</li>
        </ul>
      </div>
    </div>
  );
};

export default Base64Encoder;
