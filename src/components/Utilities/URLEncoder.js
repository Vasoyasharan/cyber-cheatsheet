import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaCopy, FaExchangeAlt } from 'react-icons/fa';
import { toast } from 'react-toastify';
import './UtilityTools.css';

const URLEncoder = () => {
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [mode, setMode] = useState('encode');

  const encode = (text) => {
    try {
      const encoded = encodeURIComponent(text);
      setOutput(encoded);
    } catch (error) {
      toast.error('Error encoding: ' + error.message);
      setOutput('');
    }
  };

  const decode = (text) => {
    try {
      const decoded = decodeURIComponent(text);
      setOutput(decoded);
    } catch (error) {
      toast.error('Invalid URL encoded string');
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
          placeholder={`Enter URL to ${mode}...`}
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
          <li>URL encoding converts special characters (spaces, &, =, etc.) into %XX format</li>
          <li>Essential for crafting SQL injection payloads in URLs</li>
          <li>Use for encoding parameters in GET requests: param=value&other=data</li>
          <li>Different from Base64 - space becomes %20, not "Iw=="</li>
          <li>Useful for XSS and CSRF payload injection in query strings</li>
        </ul>
      </div>
    </div>
  );
};

export default URLEncoder;
