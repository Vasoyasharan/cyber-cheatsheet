import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaCopy } from 'react-icons/fa';
import { toast } from 'react-toastify';
import './UtilityTools.css';

const HexConverter = () => {
  const [input, setInput] = useState('');
  const [hexOutput, setHexOutput] = useState('');
  const [textOutput, setTextOutput] = useState('');
  const [binaryOutput, setBinaryOutput] = useState('');

  const stringToHex = (str) => {
    return str
      .split('')
      .map(char => char.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0'))
      .join(' ');
  };

  const hexToString = (hex) => {
    try {
      return hex
        .split(' ')
        .map(h => String.fromCharCode(parseInt(h, 16)))
        .join('');
    } catch {
      return '';
    }
  };

  const stringToBinary = (str) => {
    return str
      .split('')
      .map(char => char.charCodeAt(0).toString(2).padStart(8, '0'))
      .join(' ');
  };

  const binaryToString = (binary) => {
    try {
      return binary
        .split(' ')
        .map(b => String.fromCharCode(parseInt(b, 2)))
        .join('');
    } catch {
      return '';
    }
  };

  const handleInputChange = (e) => {
    const text = e.target.value;
    setInput(text);

    if (text) {
      setHexOutput(stringToHex(text));
      setBinaryOutput(stringToBinary(text));
    } else {
      setHexOutput('');
      setBinaryOutput('');
    }
  };

  const handleHexInput = (e) => {
    const hex = e.target.value;
    setHexOutput(hex);

    if (hex) {
      const text = hexToString(hex);
      setInput(text);
      setBinaryOutput(stringToBinary(text));
    } else {
      setInput('');
      setBinaryOutput('');
    }
  };

  const handleBinaryInput = (e) => {
    const binary = e.target.value;
    setBinaryOutput(binary);

    if (binary) {
      const text = binaryToString(binary);
      setInput(text);
      setHexOutput(stringToHex(text));
    } else {
      setInput('');
      setHexOutput('');
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard!');
  };

  return (
    <div className="utility-tool">
      <div className="hex-converter-grid">
        <div className="utility-section">
          <label>Text Input</label>
          <textarea
            value={input}
            onChange={handleInputChange}
            placeholder="Enter text to convert..."
            className="utility-textarea"
            rows={4}
          />
        </div>

        <div className="utility-section">
          <label>Hexadecimal</label>
          <textarea
            value={hexOutput}
            onChange={handleHexInput}
            placeholder="Hex output / input..."
            className="utility-textarea"
            rows={4}
          />
          {hexOutput && (
            <motion.button
              onClick={() => copyToClipboard(hexOutput)}
              className="copy-btn-small"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              <FaCopy /> Copy
            </motion.button>
          )}
        </div>

        <div className="utility-section">
          <label>Binary</label>
          <textarea
            value={binaryOutput}
            onChange={handleBinaryInput}
            placeholder="Binary output / input..."
            className="utility-textarea"
            rows={4}
          />
          {binaryOutput && (
            <motion.button
              onClick={() => copyToClipboard(binaryOutput)}
              className="copy-btn-small"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              <FaCopy /> Copy
            </motion.button>
          )}
        </div>
      </div>

      <div className="utility-tips">
        <h4>Tips:</h4>
        <ul>
          <li>Hex Format: Two hex digits per character (e.g., "A" = 41)</li>
          <li>Binary Format: Eight bits per character (e.g., "A" = 01000001)</li>
          <li>Useful for analyzing shellcode and binary data</li>
          <li>Common in exploit development and reverse engineering</li>
          <li>Can help identify encoding schemes in malware analysis</li>
        </ul>
      </div>
    </div>
  );
};

export default HexConverter;
