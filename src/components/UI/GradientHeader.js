import { motion } from 'framer-motion';

const GradientHeader = ({ title, subtitle, icon }) => {
  return (
    <motion.div 
      className="gradient-header"
      initial={{ opacity: 0, y: -20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
    >
      <div className="gradient-bg"></div>
      <div className="header-content">
        <div className="header-icon">{icon}</div>
        <div>
          <h1>{title}</h1>
          <p className="subtitle">{subtitle}</p>
        </div>
      </div>
    </motion.div>
  );
};

export default GradientHeader;