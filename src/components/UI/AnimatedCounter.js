import { motion } from 'framer-motion';
import { useEffect, useState } from 'react';

const AnimatedCounter = ({ from = 0, to = 100, duration = 2, label = '', icon = null }) => {
  const [count, setCount] = useState(from);

  useEffect(() => {
    let interval;
    const increment = (to - from) / (duration * 60); // 60fps
    
    const timer = setInterval(() => {
      setCount((prev) => {
        if (prev + increment >= to) {
          clearInterval(timer);
          return to;
        }
        return prev + increment;
      });
    }, 1000 / 60);

    return () => clearInterval(timer);
  }, [from, to, duration]);

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.5 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.6, type: 'spring', stiffness: 100 }}
      whileHover={{ scale: 1.1 }}
      style={{
        cursor: 'pointer'
      }}
    >
      <motion.div
        style={{
          fontSize: '32px',
          fontWeight: 'bold',
          color: 'var(--primary)',
          marginBottom: '8px'
        }}
        animate={{
          textShadow: ['0 0 20px rgba(110, 72, 170, 0)', '0 0 20px rgba(110, 72, 170, 0.5)', '0 0 20px rgba(110, 72, 170, 0)']
        }}
        transition={{ duration: 3, repeat: Infinity }}
      >
        {Math.floor(count) + (label.includes('+') ? '+' : '')}
      </motion.div>
      {icon && <div style={{ fontSize: '24px', marginBottom: '8px' }}>{icon}</div>}
      <div style={{ fontSize: '12px', opacity: 0.7, fontWeight: '600' }}>
        {label}
      </div>
    </motion.div>
  );
};

export default AnimatedCounter;
