import { useState } from 'react'; 
import { motion, AnimatePresence } from 'framer-motion';
import { FaHistory, FaTimes, FaCopy, FaTrash, FaDownload } from 'react-icons/fa';
import { useCommandHistory } from '../../contexts/CommandHistoryContext';
import { copyToClipboard } from '../../utils/copyToClipboard';
import { toast } from 'react-toastify';

const CommandHistory = () => {
  const [expanded, setExpanded] = useState(false);
  const { history, clearHistory, removeCommand } = useCommandHistory();

  if (history.length === 0) return null;

  const handleCopyCommand = (cmd) => {
    copyToClipboard(cmd);
    toast.success('Command copied!', { position: 'bottom-right', autoClose: 1500, hideProgressBar: true });
  };

  const handleDeleteCommand = (cmd) => {
    removeCommand(cmd);
    toast.info('Command removed', { position: 'bottom-right', autoClose: 1200, hideProgressBar: true });
  };

  const handleExport = () => {
    const now = new Date();
    const header = `#!/bin/bash\n# CyberCheat — Command History Export\n# Generated: ${now.toLocaleString()}\n# Total commands: ${history.length}\n\n`;
    const body = history.map((cmd, i) => `# [${i + 1}]\n${cmd}`).join('\n\n');
    const blob = new Blob([header + body + '\n'], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cybercheat_commands_${now.toISOString().slice(0, 10)}.sh`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success('📥 Exported as .sh script!', { position: 'bottom-right', autoClose: 2500, hideProgressBar: true });
  };

  return (
    <div className="command-history-container">
      <motion.button
        className="history-toggle"
        onClick={() => setExpanded(!expanded)}
        whileHover={{ scale: 1.05 }}
        whileTap={{ scale: 0.95 }}
        title="View command history (Ctrl+H)"
      >
        <FaHistory />
        <span>History ({history.length})</span>
      </motion.button>
      
      <AnimatePresence>
        {expanded && (
          <motion.div
            className="history-panel"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.3 }}
          >
            <div className="history-header">
              <h4>📋 Recently Used Commands</h4>
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                <motion.button
                  onClick={handleExport}
                  className="clear-button"
                  title="Export as .sh script"
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  style={{ color: 'var(--success)', display: 'flex', alignItems: 'center', gap: '4px' }}
                >
                  <FaDownload /> Export .sh
                </motion.button>
                <button
                  onClick={() => {
                    clearHistory();
                    toast.success('History cleared', { position: 'bottom-right', autoClose: 1500, hideProgressBar: true });
                  }}
                  className="clear-button"
                  title="Clear all commands"
                >
                  <FaTimes /> Clear
                </button>
              </div>
            </div>
            <div className="history-list">
              {history.map((cmd, index) => (
                <motion.div
                  key={index}
                  className="history-item"
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -20 }}
                  transition={{ delay: index * 0.05, duration: 0.2 }}
                >
                  <code className="command-text">{cmd}</code>
                  <div className="command-actions">
                    <motion.button
                      onClick={() => handleCopyCommand(cmd)}
                      className="action-btn copy-btn"
                      title="Copy command"
                      whileHover={{ scale: 1.1 }}
                      whileTap={{ scale: 0.95 }}
                    >
                      <FaCopy />
                    </motion.button>
                    <motion.button
                      onClick={() => handleDeleteCommand(cmd)}
                      className="action-btn delete-btn"
                      title="Delete command"
                      whileHover={{ scale: 1.1 }}
                      whileTap={{ scale: 0.95 }}
                    >
                      <FaTrash />
                    </motion.button>
                  </div>
                </motion.div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default CommandHistory;