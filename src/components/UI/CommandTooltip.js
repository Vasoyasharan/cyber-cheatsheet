import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FaInfoCircle } from 'react-icons/fa';
import './CommandTooltip.css';

const CommandTooltip = ({ flag, explanation, children }) => {
  const [showTooltip, setShowTooltip] = useState(false);

  if (!explanation) {
    return children;
  }

  return (
    <div className="tooltip-wrapper">
      <div
        className="tooltip-trigger"
        onMouseEnter={() => setShowTooltip(true)}
        onMouseLeave={() => setShowTooltip(false)}
      >
        {children}
        <FaInfoCircle className="info-icon" />
      </div>

      <AnimatePresence>
        {showTooltip && (
          <motion.div
            className="tooltip-content"
            initial={{ opacity: 0, y: -5 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -5 }}
            transition={{ duration: 0.2 }}
          >
            <div className="tooltip-arrow"></div>
            <div className="tooltip-body">
              {flag && <strong className="tooltip-flag">{flag}</strong>}
              <p className="tooltip-text">{explanation}</p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default CommandTooltip;
