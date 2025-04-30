import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FaCopy, FaInfoCircle, FaLock } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { useCommandHistory } from '../../contexts/CommandHistoryContext';
import { copyToClipboard } from '../../utils/copyToClipboard';
import CommandHistory from '../UI/CommandHistory';

const JohnTheRipperBuilder = () => {
  const [hashFile, setHashFile] = useState('');
  const [options, setOptions] = useState({
    format: '',
    wordlist: 'rockyou.txt',
    rules: 'single',
    incremental: false,
    mask: '',
    potFile: '',
    threads: 4,
    show: false
  });
  const [showAdvanced, setShowAdvanced] = useState(false);
  const { addToHistory } = useCommandHistory();

  const hashFormats = [
    { value: '', label: 'Auto-detect' },
    { value: 'md5crypt', label: 'MD5 Crypt' },
    { value: 'sha512crypt', label: 'SHA-512 Crypt' },
    { value: 'nt', label: 'NT (NTLM)' },
    { value: 'lm', label: 'LM' },
    { value: 'bcrypt', label: 'bcrypt' },
    { value: 'raw-md5', label: 'Raw MD5' },
    { value: 'raw-sha1', label: 'Raw SHA-1' }
  ];

  const ruleSets = [
    { value: 'single', label: 'Single' },
    { value: 'wordlist', label: 'Wordlist' },
    { value: 'extra', label: 'Extra' },
    { value: 'jumbo', label: 'Jumbo' },
    { value: 'none', label: 'None' }
  ];

  const buildCommand = () => {
    let cmd = 'john';

    if (hashFile) cmd += ` ${hashFile}`;
    if (options.format) cmd += ` --format=${options.format}`;
    if (options.wordlist && options.rules !== 'none' && !options.incremental) cmd += ` --wordlist=${options.wordlist}`;
    if (options.rules && options.rules !== 'none' && !options.incremental) cmd += ` --rules=${options.rules}`;
    if (options.incremental) cmd += ' --incremental';
    if (options.mask) cmd += ` --mask="${options.mask}"`;
    if (options.potFile) cmd += ` --pot=${options.potFile}`;
    if (options.threads && options.threads !== 4) cmd += ` --fork=${options.threads}`;
    if (options.show) cmd += ' --show';

    return cmd;
  };

  const handleCopy = async () => {
    if (!hashFile) {
      toast.error('Please specify a hash file', {
        position: 'bottom-right',
        autoClose: 2000,
        hideProgressBar: true,
      });
      return;
    }

    try {
      const command = buildCommand();
      await copyToClipboard(command);
      addToHistory(command);
      toast.success('Command copied to clipboard!', {
        position: 'bottom-right',
        autoClose: 2000,
        hideProgressBar: true,
      });
    } catch (err) {
      toast.error('Failed to copy command', {
        position: 'bottom-right',
        autoClose: 2000,
        hideProgressBar: true,
      });
    }
  };

  return (
    <div className="command-builder">
      <div className="builder-header">
        <FaLock className="icon" />
        <h2>John the Ripper Command Builder</h2>
        <p>Password cracking tool</p>
      </div>

      <div className="form-group">
        <label>Hash File</label>
        <input
          type="text"
          value={hashFile}
          onChange={(e) => setHashFile(e.target.value)}
          placeholder="hashes.txt or /etc/shadow"
          className="text-input"
        />
      </div>

      <div className="form-group">
        <label>Hash Format</label>
        <select
          value={options.format}
          onChange={(e) => setOptions({ ...options, format: e.target.value })}
          className="select-input"
        >
          {hashFormats.map((format) => (
            <option key={format.value} value={format.value}>
              {format.label}
            </option>
          ))}
        </select>
      </div>

      <div className="form-row">
        <div className="form-group">
          <label>Wordlist</label>
          <input
            type="text"
            value={options.wordlist}
            onChange={(e) => setOptions({ ...options, wordlist: e.target.value })}
            placeholder="rockyou.txt"
            className="text-input"
            disabled={options.rules === 'none' || options.incremental}
          />
        </div>

        <div className="form-group">
          <label>Rule Set</label>
          <select
            value={options.rules}
            onChange={(e) => setOptions({ ...options, rules: e.target.value })}
            className="select-input"
            disabled={options.incremental}
          >
            {ruleSets.map((rule) => (
              <option key={rule.value} value={rule.value}>
                {rule.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      <button onClick={() => setShowAdvanced(!showAdvanced)} className="toggle-button">
        {showAdvanced ? 'Hide Advanced Options' : 'Show Advanced Options'}
      </button>

      <AnimatePresence>
        {showAdvanced && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.3 }}
            className="advanced-options"
          >
            <div className="form-group">
              <label>Mask</label>
              <input
                type="text"
                value={options.mask}
                onChange={(e) => setOptions({ ...options, mask: e.target.value })}
                placeholder="e.g. ?u?l?l?l?d?d"
                className="text-input"
              />
            </div>

            <div className="form-group">
              <label>Pot File</label>
              <input
                type="text"
                value={options.potFile}
                onChange={(e) => setOptions({ ...options, potFile: e.target.value })}
                placeholder="john.pot"
                className="text-input"
              />
            </div>

            <div className="form-group">
              <label>Threads (Fork)</label>
              <input
                type="number"
                value={options.threads}
                min={1}
                max={64}
                onChange={(e) => setOptions({ ...options, threads: parseInt(e.target.value) })}
                className="text-input"
              />
            </div>

            <div className="checkbox-group">
              <label>
                <input
                  type="checkbox"
                  checked={options.incremental}
                  onChange={(e) =>
                    setOptions({
                      ...options,
                      incremental: e.target.checked,
                      rules: e.target.checked ? 'none' : options.rules
                    })
                  }
                />
                Incremental Mode
              </label>

              <label>
                <input
                  type="checkbox"
                  checked={options.show}
                  onChange={(e) => setOptions({ ...options, show: e.target.checked })}
                />
                Show Cracked Passwords (--show)
              </label>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="form-actions">
        <button onClick={handleCopy} className="copy-button">
          <FaCopy style={{ marginRight: '6px' }} />
          Copy Command
        </button>
      </div>

      <CommandHistory />
    </div>
  );
};

export default JohnTheRipperBuilder;
