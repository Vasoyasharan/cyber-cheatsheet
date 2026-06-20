import { useState } from 'react'; 
import { motion, AnimatePresence } from 'framer-motion';
import { FaHistory, FaTimes, FaCopy, FaTrash, FaDownload, FaTerminal } from 'react-icons/fa';
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
      <AnimatePresence>
        {expanded && (
          <motion.div
            className="history-panel"
            initial={{ opacity: 0, y: 16, scale: 0.94, transformOrigin: 'bottom right' }}
            animate={{ opacity: 1, y: 0, scale: 1, transformOrigin: 'bottom right' }}
            exit={{ opacity: 0, y: 16, scale: 0.94, transformOrigin: 'bottom right' }}
            transition={{ duration: 0.26, ease: [0.34, 1.3, 0.64, 1] }}
          >
            <div className="history-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <FaTerminal style={{ fontSize: '14px' }} />
                <h4>Command History</h4>
                <span style={{
                  background: 'rgba(255,255,255,0.2)',
                  padding: '1px 7px',
                  borderRadius: '10px',
                  fontSize: '11px',
                  fontWeight: '800'
                }}>{history.length}</span>
              </div>
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                <motion.button
                  onClick={handleExport}
                  className="clear-button"
                  title="Export as .sh script"
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  <FaDownload /> Export
                </motion.button>
                <motion.button
                  onClick={() => {
                    clearHistory();
                    toast.success('History cleared', { position: 'bottom-right', autoClose: 1500, hideProgressBar: true });
                  }}
                  className="clear-button"
                  title="Clear all commands"
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  <FaTimes />
                </motion.button>
              </div>
            </div>
            <div className="history-list">
              {history.map((cmd, index) => (
                <motion.div
                  key={index}
                  className="history-item"
                  initial={{ opacity: 0, x: 16 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 16 }}
                  transition={{ delay: index * 0.04, duration: 0.18 }}
                >
                  <span style={{
                    flexShrink: 0,
                    width: '20px', height: '20px',
                    borderRadius: '50%',
                    background: 'var(--gradient-primary)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: '9px', fontWeight: '800', color: 'white',
                  }}>{index + 1}</span>
                  <code className="command-text">{cmd}</code>
                  <div className="command-actions">
                    <motion.button
                      onClick={() => handleCopyCommand(cmd)}
                      className="action-btn copy-btn"
                      title="Copy command"
                      whileHover={{ scale: 1.15 }}
                      whileTap={{ scale: 0.9 }}
                    >
                      <FaCopy />
                    </motion.button>
                    <motion.button
                      onClick={() => handleDeleteCommand(cmd)}
                      className="action-btn delete-btn"
                      title="Delete command"
                      whileHover={{ scale: 1.15 }}
                      whileTap={{ scale: 0.9 }}
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

      <motion.button
        className="history-toggle"
        onClick={() => setExpanded(!expanded)}
        whileTap={{ scale: 0.93 }}
        title="View command history (Ctrl+H)"
      >
        <motion.span
          animate={{ rotate: expanded ? 180 : 0 }}
          transition={{ duration: 0.3 }}
          style={{ display: 'flex', alignItems: 'center' }}
        >
          <FaHistory />
        </motion.span>
        <span>History</span>
        <span className="history-badge">{history.length}</span>
      </motion.button>
    </div>
  );
};

export default CommandHistory;