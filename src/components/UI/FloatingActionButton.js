import { motion } from 'framer-motion';
import { FaTerminal, FaHistory, FaTimes } from 'react-icons/fa';
import { useCommandHistory } from '../../contexts/CommandHistoryContext';

const FloatingActionButton = () => {
  const { history, clearHistory } = useCommandHistory();
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="fab-container">
      <motion.div
        className="fab-main"
        onClick={() => setExpanded(!expanded)}
        whileHover={{ scale: 1.1 }}
        whileTap={{ scale: 0.9 }}
        animate={{ rotate: expanded ? 45 : 0 }}
      >
        {expanded ? <FaTimes /> : <FaTerminal />}
      </motion.div>

      <AnimatePresence>
        {expanded && (
          <>
            {history.length > 0 && (
              <motion.div
                className="fab-action"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 20 }}
                onClick={clearHistory}
                whileHover={{ scale: 1.05 }}
                transition={{ delay: 0.1 }}
              >
                <FaHistory />
                <span className="tooltip">Clear History</span>
              </motion.div>
            )}
          </>
        )}
      </AnimatePresence>
    </div>
  );
};

export default FloatingActionButton;