import { motion, AnimatePresence } from 'framer-motion';
import { FaClock, FaTimes } from 'react-icons/fa';

/**
 * RecentlyViewedBar
 * Props:
 *   items       – array of { id, name, icon } objects
 *   activeId    – currently active id
 *   onSelect    – (id) => void
 *   onClear     – () => void
 *   label       – e.g. "Recent tools" | "Recent sheets"
 */
const RecentlyViewedBar = ({ items = [], activeId, onSelect, onClear, label = 'Recently viewed' }) => {
  if (!items.length) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -10 }}
        style={{
          maxWidth: '1200px',
          margin: '0 auto 4px',
          padding: '0 20px',
        }}
      >
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          padding: '10px 16px',
          borderRadius: '50px',
          background: 'var(--card-bg)',
          border: '1px solid rgba(110,72,170,0.2)',
          flexWrap: 'wrap',
        }}>
          {/* Label */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexShrink: 0 }}>
            <FaClock style={{ color: 'var(--primary)', fontSize: '13px' }} />
            <span style={{ fontSize: '12px', fontWeight: '600', color: 'var(--text)', opacity: 0.6, whiteSpace: 'nowrap' }}>
              {label}:
            </span>
          </div>

          {/* Chips */}
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', flex: 1 }}>
            {items.map((item, i) => (
              <motion.button
                key={item.id}
                onClick={() => onSelect(item.id)}
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: i * 0.05 }}
                whileHover={{ scale: 1.06 }}
                whileTap={{ scale: 0.94 }}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '5px 12px',
                  borderRadius: '20px',
                  border: activeId === item.id
                    ? '1.5px solid var(--primary)'
                    : '1.5px solid rgba(110,72,170,0.25)',
                  background: activeId === item.id
                    ? 'linear-gradient(135deg, var(--primary), var(--secondary))'
                    : 'transparent',
                  color: activeId === item.id ? 'white' : 'var(--text)',
                  fontSize: '12px',
                  fontWeight: '600',
                  cursor: 'pointer',
                  transition: 'all 0.2s',
                  whiteSpace: 'nowrap',
                }}
              >
                <span style={{ fontSize: '13px', lineHeight: 1 }}>{item.icon}</span>
                {item.name}
              </motion.button>
            ))}
          </div>

          {/* Clear */}
          <motion.button
            onClick={onClear}
            whileHover={{ scale: 1.1 }}
            title="Clear recently viewed"
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text)',
              opacity: 0.35,
              cursor: 'pointer',
              fontSize: '13px',
              display: 'flex',
              alignItems: 'center',
              flexShrink: 0,
            }}
          >
            <FaTimes />
          </motion.button>
        </div>
      </motion.div>
    </AnimatePresence>
  );
};

export default RecentlyViewedBar;
