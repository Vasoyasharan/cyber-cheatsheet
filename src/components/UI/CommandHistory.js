import { useState } from 'react'; 
import { motion, AnimatePresence } from 'framer-motion';
import { FaHistory, FaTimes, FaClipboard, FaCheck, FaTrash } from 'react-icons/fa';
import { useCommandHistory } from '../../contexts/CommandHistoryContext';
import { toast } from 'react-toastify';

const CommandHistory = () => {
  const [expanded, setExpanded] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState(null);
  const { history, clearHistory, removeCommand } = useCommandHistory();

  if (history.length === 0) return null;

  const handleCopyCommand = async (command, index) => {
    try {
      await navigator.clipboard.writeText(command);
      setCopiedIndex(index);
      setTimeout(() => setCopiedIndex(null), 2000);
      toast.success('✓ Copied!', {
        position: 'bottom-right',
        autoClose: 1000,
        hideProgressBar: true,
      });
    } catch (err) {
      toast.error('Failed to copy', {
        position: 'bottom-right',
        autoClose: 1000,
      });
    }
  };

  const handleRemoveCommand = (index) => {
    removeCommand(index);
    toast.info('Command removed', {
      position: 'bottom-right',
      autoClose: 800,
      hideProgressBar: true,
    });
  };

  return (
    <div className="command-history-container">
      <motion.button
        className="history-toggle"
        onClick={() => setExpanded(!expanded)}
        whileHover={{ scale: 1.08 }}
        whileTap={{ scale: 0.95 }}
        animate={{
          boxShadow: expanded ? '0 0 20px rgba(110, 72, 170, 0.4)' : '0 0 0 rgba(110, 72, 170, 0)'
        }}
        style={{
          position: 'fixed',
          bottom: '20px',
          left: '20px',
          background: 'linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%)',
          color: 'white',
          border: 'none',
          borderRadius: '50px',
          padding: '12px 20px',
          cursor: 'pointer',
          fontWeight: '600',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          zIndex: 999,
          boxShadow: '0 4px 15px rgba(110, 72, 170, 0.2)'
        }}
      >
        <FaHistory />
        <span style={{ fontSize: '12px' }}>History ({history.length})</span>
      </motion.button>
      
      <AnimatePresence>
        {expanded && (
          <motion.div
            className="history-panel"
            initial={{ opacity: 0, scale: 0.8, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.8, y: 20 }}
            transition={{ duration: 0.3, type: 'spring', stiffness: 300 }}
            style={{
              position: 'fixed',
              bottom: '80px',
              left: '20px',
              width: '400px',
              maxHeight: '500px',
              background: 'var(--card-bg)',
              borderRadius: '12px',
              boxShadow: '0 10px 40px rgba(0,0,0,0.2)',
              border: '1px solid var(--primary)',
              zIndex: 999,
              display: 'flex',
              flexDirection: 'column',
              overflow: 'hidden'
            }}
          >
            {/* Header */}
            <motion.div
              style={{
                padding: '15px',
                borderBottom: '1px solid var(--primary)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                background: 'linear-gradient(135deg, var(--primary)22 0%, transparent 100%)'
              }}
            >
              <h4 style={{ margin: 0, color: 'var(--text)', fontSize: '14px', fontWeight: '700' }}>
                📋 Command History
              </h4>
              <motion.button
                onClick={() => {
                  clearHistory();
                  setExpanded(false);
                  toast.success('✓ History cleared', {
                    position: 'bottom-right',
                    autoClose: 1500,
                    hideProgressBar: true,
                  });
                }}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--text)',
                  cursor: 'pointer',
                  fontSize: '16px'
                }}
                whileHover={{ scale: 1.2, color: '#F44336' }}
              >
                <FaTimes />
              </motion.button>
            </motion.div>

            {/* Commands List */}
            <motion.div
              style={{
                flex: 1,
                overflowY: 'auto',
                padding: '10px'
              }}
            >
              {history.map((cmd, index) => (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, x: -30 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 30 }}
                  transition={{ delay: index * 0.05 }}
                  whileHover={{ x: 5, backgroundColor: 'rgba(110, 72, 170, 0.1)' }}
                  style={{
                    padding: '10px 12px',
                    marginBottom: '8px',
                    background: 'rgba(110, 72, 170, 0.05)',
                    borderRadius: '8px',
                    border: '1px solid rgba(110, 72, 170, 0.2)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: '8px',
                    group: 'history-item'
                  }}
                >
                  {/* Command Text */}
                  <div
                    style={{
                      flex: 1,
                      minWidth: 0,
                      fontSize: '11px',
                      fontFamily: 'monospace',
                      color: 'var(--text)',
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      opacity: 0.8
                    }}
                    title={cmd}
                  >
                    {cmd}
                  </div>

                  {/* Action Buttons */}
                  <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                    <motion.button
                      onClick={() => handleCopyCommand(cmd, index)}
                      style={{
                        background: copiedIndex === index ? '#4CAF50' : 'rgba(110, 72, 170, 0.3)',
                        border: 'none',
                        color: 'white',
                        borderRadius: '6px',
                        padding: '6px 8px',
                        cursor: 'pointer',
                        fontSize: '12px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '4px'
                      }}
                      whileHover={{ scale: 1.1 }}
                      whileTap={{ scale: 0.95 }}
                    >
                      {copiedIndex === index ? <FaCheck size={10} /> : <FaClipboard size={10} />}
                    </motion.button>
                    <motion.button
                      onClick={() => handleRemoveCommand(index)}
                      style={{
                        background: 'rgba(244, 67, 54, 0.3)',
                        border: 'none',
                        color: '#F44336',
                        borderRadius: '6px',
                        padding: '6px 8px',
                        cursor: 'pointer',
                        fontSize: '12px',
                        display: 'flex',
                        alignItems: 'center'
                      }}
                      whileHover={{ scale: 1.1, background: 'rgba(244, 67, 54, 0.5)' }}
                      whileTap={{ scale: 0.95 }}
                    >
                      <FaTrash size={10} />
                    </motion.button>
                  </div>
                </motion.div>
              ))}
            </motion.div>

            {/* Footer */}
            <motion.div
              style={{
                padding: '12px',
                borderTop: '1px solid var(--primary)',
                fontSize: '12px',
                opacity: 0.6,
                textAlign: 'center',
                background: 'rgba(110, 72, 170, 0.05)'
              }}
            >
              {history.length} command{history.length !== 1 ? 's' : ''} saved
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default CommandHistory;