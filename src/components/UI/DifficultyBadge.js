import { motion } from 'framer-motion';
import { FaFire, FaUser, FaChartLine } from 'react-icons/fa';

const DifficultyBadge = ({ level = 'beginner', showLabel = true, size = 'md' }) => {
  const levels = {
    beginner: {
      color: '#4CAF50',
      icon: <FaUser />,
      label: 'Beginner',
      bg: 'rgba(76, 175, 80, 0.1)',
      description: 'Fundamental concepts'
    },
    intermediate: {
      color: '#FF9800',
      icon: <FaChartLine />,
      label: 'Intermediate',
      bg: 'rgba(255, 152, 0, 0.1)',
      description: 'Practical experience needed'
    },
    advanced: {
      color: '#F44336',
      icon: <FaFire />,
      label: 'Advanced',
      bg: 'rgba(244, 67, 54, 0.1)',
      description: 'Expert-level techniques'
    }
  };

  const config = levels[level] || levels.beginner;
  const sizeClass = size === 'sm' ? 'badge-sm' : size === 'lg' ? 'badge-lg' : 'badge-md';

  return (
    <motion.div
      className={`difficulty-badge ${sizeClass}`}
      style={{
        backgroundColor: config.bg,
        borderColor: config.color,
        borderWidth: '1.5px',
        borderRadius: '20px',
        padding: size === 'sm' ? '4px 8px' : size === 'lg' ? '8px 16px' : '6px 12px',
        display: 'inline-flex',
        alignItems: 'center',
        gap: '6px',
        cursor: 'pointer'
      }}
      whileHover={{ scale: 1.05 }}
      title={config.description}
    >
      <span style={{ color: config.color, display: 'flex', alignItems: 'center' }}>
        {config.icon}
      </span>
      {showLabel && (
        <span style={{ color: config.color, fontWeight: '600', fontSize: size === 'sm' ? '0.8rem' : '0.95rem' }}>
          {config.label}
        </span>
      )}
    </motion.div>
  );
};

export default DifficultyBadge;
