import { motion } from 'framer-motion';

const AnimatedCard = ({ children, onClick, isActive, delay = 0 }) => {
  return (
    <motion.div
      onClick={onClick}
      initial={{ opacity: 0, y: 20 }}
      animate={{ 
        opacity: 1, 
        y: 0,
        borderColor: isActive ? 'var(--primary)' : 'var(--border)',
        transition: { delay: delay * 0.1 }
      }}
      whileHover={{ 
        scale: 1.05,
        boxShadow: '0 10px 20px rgba(0,0,0,0.1)'
      }}
      whileTap={{ scale: 0.98 }}
      className={`card ${isActive ? 'active' : ''}`}
    >
      {children}
    </motion.div>
  );
};

export default AnimatedCard;