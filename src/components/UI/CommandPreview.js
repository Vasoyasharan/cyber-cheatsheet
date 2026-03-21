import { motion } from 'framer-motion';
import { FaClipboard, FaCheck, FaQuestionCircle } from 'react-icons/fa';
import { useState } from 'react';

const CommandPreview = ({ command, description = '', tips = [], examples = [] }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      style={{
        marginBottom: '25px',
        padding: '20px',
        background: 'var(--card-bg)',
        borderRadius: '12px',
        border: '1px solid var(--primary)',
        borderLeft: '4px solid var(--primary)'
      }}
    >
      {/* Description */}
      {description && (
        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.1 }}
          style={{
            margin: '0 0 15px 0',
            fontSize: '14px',
            opacity: 0.8,
            color: 'var(--text)'
          }}
        >
          {description}
        </motion.p>
      )}

      {/* Command Preview */}
      <motion.div
        style={{
          background: 'rgba(0,0,0,0.2)',
          padding: '12px 15px',
          borderRadius: '8px',
          marginBottom: '15px',
          fontFamily: 'monospace',
          fontSize: '13px',
          color: 'var(--text)',
          wordBreak: 'break-all',
          position: 'relative',
          overflow: 'auto',
          maxHeight: '100px'
        }}
        whileHover={{ backgroundColor: 'rgba(110, 72, 170, 0.15)' }}
      >
        {command}
      </motion.div>

      {/* Copy Button */}
      <motion.button
        onClick={handleCopy}
        style={{
          background: copied ? '#4CAF50' : 'var(--primary)',
          color: 'white',
          border: 'none',
          borderRadius: '8px',
          padding: '10px 16px',
          cursor: 'pointer',
          fontSize: '13px',
          fontWeight: '600',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          width: '100%',
          justifyContent: 'center',
          marginBottom: tips.length > 0 || examples.length > 0 ? '15px' : '0'
        }}
        whileHover={{ scale: 1.02 }}
        whileTap={{ scale: 0.98 }}
        animate={{ background: copied ? '#4CAF50' : 'var(--primary)' }}
      >
        {copied ? (
          <>
            <FaCheck /> Copied to Clipboard!
          </>
        ) : (
          <>
            <FaClipboard /> Copy Command
          </>
        )}
      </motion.button>

      {/* Tips */}
      {tips.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          style={{
            marginTop: '15px',
            paddingTop: '15px',
            borderTop: '1px solid var(--primary)',
            opacity: 0.8
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
            <FaQuestionCircle style={{ fontSize: '14px' }} />
            <strong style={{ fontSize: '13px' }}>💡 Quick Tips:</strong>
          </div>
          <ul style={{
            margin: '0',
            paddingLeft: '20px',
            fontSize: '12px',
            opacity: 0.75,
            lineHeight: '1.6'
          }}>
            {tips.map((tip, i) => (
              <li key={i}>{tip}</li>
            ))}
          </ul>
        </motion.div>
      )}

      {/* Examples */}
      {examples.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          style={{
            marginTop: '15px',
            paddingTop: '15px',
            borderTop: '1px solid var(--primary)',
            opacity: 0.85
          }}
        >
          <strong style={{ fontSize: '13px', display: 'block', marginBottom: '10px' }}>📌 Real Examples:</strong>
          {examples.map((example, i) => (
            <motion.div
              key={i}
              style={{
                background: 'rgba(0,0,0,0.1)',
                padding: '10px',
                borderRadius: '6px',
                marginBottom: '8px',
                fontFamily: 'monospace',
                fontSize: '11px',
                color: 'var(--text)',
                wordBreak: 'break-all'
              }}
            >
              {example}
            </motion.div>
          ))}
        </motion.div>
      )}
    </motion.div>
  );
};

export default CommandPreview;
