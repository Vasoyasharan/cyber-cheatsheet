import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaCopy, FaCheck } from 'react-icons/fa';
import { toast } from 'react-toastify';
import './UtilityTools.css';

const JSONFormatter = () => {
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [isValid, setIsValid] = useState(true);
  const [error, setError] = useState('');
  const [indent, setIndent] = useState(2);

  const formatJSON = (jsonString, indentSize) => {
    try {
      const parsed = JSON.parse(jsonString);
      const formatted = JSON.stringify(parsed, null, indentSize);
      setOutput(formatted);
      setIsValid(true);
      setError('');
      toast.success('JSON formatted successfully!');
    } catch (err) {
      setIsValid(false);
      setError(err.message);
      setOutput('');
    }
  };

  const minifyJSON = (jsonString) => {
    try {
      const parsed = JSON.parse(jsonString);
      const minified = JSON.stringify(parsed);
      setOutput(minified);
      setIsValid(true);
      setError('');
      toast.success('JSON minified successfully!');
    } catch (err) {
      setIsValid(false);
      setError(err.message);
      setOutput('');
    }
  };

  const validateJSON = (jsonString) => {
    try {
      JSON.parse(jsonString);
      setIsValid(true);
      setError('');
      toast.success('JSON is valid!');
    } catch (err) {
      setIsValid(false);
      setError(err.message);
    }
  };

  const handleInputChange = (e) => {
    const value = e.target.value;
    setInput(value);
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard!');
  };

  return (
    <div className="utility-tool">
      <div className="json-controls">
        <div className="control-group">
          <label>Indent Size</label>
          <select value={indent} onChange={(e) => setIndent(Number(e.target.value))}>
            <option value={2}>2 spaces</option>
            <option value={4}>4 spaces</option>
            <option value={8}>8 spaces</option>
            <option value={1}>Tab</option>
          </select>
        </div>

        <div className="control-buttons">
          <motion.button
            onClick={() => formatJSON(input, indent)}
            className="action-btn"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            <FaCheck /> Format
          </motion.button>
          <motion.button
            onClick={() => minifyJSON(input)}
            className="action-btn"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            Minify
          </motion.button>
          <motion.button
            onClick={() => validateJSON(input)}
            className="action-btn"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            Validate
          </motion.button>
        </div>
      </div>

      <div className="json-editor-grid">
        <div className="utility-section">
          <label>Input JSON</label>
          <textarea
            value={input}
            onChange={handleInputChange}
            placeholder='Paste your JSON here (e.g., {"key": "value"})'
            className="utility-textarea"
            rows={10}
          />
          {!isValid && input && (
            <div className="error-message">
              {error}
            </div>
          )}
        </div>

        <div className="utility-section">
          <label>Output JSON</label>
          <textarea
            value={output}
            readOnly
            placeholder="Formatted JSON will appear here..."
            className="utility-textarea"
            rows={10}
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
      </div>

      <div className="utility-tips">
        <h4>Tips:</h4>
        <ul>
          <li>Always validate JSON before sending in API requests</li>
          <li>Minify JSON to reduce payload size in requests</li>
          <li>Format for readability when analyzing API responses</li>
          <li>Check for missing quotes or commas causing parse errors</li>
          <li>Use for analyzing and crafting JSON injection payloads</li>
        </ul>
      </div>
    </div>
  );
};

export default JSONFormatter;
