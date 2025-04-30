import { useState } from 'react'; 
import { motion, AnimatePresence } from 'framer-motion';
import { FaHistory, FaTimes } from 'react-icons/fa';
import { useCommandHistory } from '../../contexts/CommandHistoryContext';
import { toast } from 'react-toastify';

const CommandHistory = () => {
  const [expanded, setExpanded] = useState(false);
  const { history, clearHistory } = useCommandHistory();

  if (history.length === 0) return null;

  return (
    <div className="command-history-container">
      <motion.button
        className="history-toggle"
        onClick={() => setExpanded(!expanded)}
        whileHover={{ scale: 1.05 }}
        whileTap={{ scale: 0.95 }}
      >
        <FaHistory />
        <span>Command History</span>
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
              <h4>Recently Used Commands</h4>
              <button 
                onClick={() => {
                  clearHistory();
                  toast.success('History cleared', {
                    position: 'bottom-right',
                    autoClose: 1500,
                    hideProgressBar: true,
                  });
                }}
                className="clear-button"
              >
                <FaTimes />
              </button>
            </div>
            <ul>
              {history.map((cmd, index) => (
                <motion.li
                  key={index}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.05 }}
                >
                  <code>{cmd}</code>
                </motion.li>
              ))}
            </ul>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default CommandHistory;