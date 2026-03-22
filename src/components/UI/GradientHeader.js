import { motion } from 'framer-motion';

const GradientHeader = ({ title, subtitle, icon }) => {
  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: { duration: 0.8, staggerChildren: 0.2 }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, scale: 0.8 },
    visible: { opacity: 1, scale: 1, transition: { duration: 0.6 } }
  };

  const textVariants = {
    hidden: { opacity: 0, x: -30 },
    visible: { opacity: 1, x: 0, transition: { duration: 0.6 } }
  };

  return (
    <motion.div 
      className="gradient-header"
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      {/* Animated gradient background */}
      <motion.div 
        className="gradient-bg"
        animate={{ 
          backgroundPosition: ['0% 50%', '100% 50%', '0% 50%'],
          rotate: [0, 1, 0]
        }}
        transition={{ 
          duration: 15, 
          repeat: Infinity,
          ease: 'linear'
        }}
      ></motion.div>

      {/* Decorative elements */}
      <div className="header-decorations">
        <motion.div 
          className="decoration decoration-1"
          animate={{ 
            y: [0, 30, 0],
            opacity: [0.3, 0.6, 0.3]
          }}
          transition={{ duration: 6, repeat: Infinity }}
        />
        <motion.div 
          className="decoration decoration-2"
          animate={{ 
            y: [0, -30, 0],
            opacity: [0.3, 0.6, 0.3]
          }}
          transition={{ duration: 8, repeat: Infinity, delay: 1 }}
        />
      </div>

      {/* Main content */}
      <motion.div 
        className="header-content"
        variants={containerVariants}
      >
        {/* Icon with floating animation */}
        <motion.div 
          className="header-icon-wrapper"
          variants={itemVariants}
          animate={{ y: [0, -10, 0] }}
          transition={{ duration: 3, repeat: Infinity }}
          whileHover={{ scale: 1.1, rotate: 5 }}
        >
          <div className="header-icon">
            {icon}
          </div>
          <motion.div 
            className="icon-glow"
            animate={{ 
              boxShadow: [
                '0 0 20px rgba(109, 72, 170, 0.3)',
                '0 0 40px rgba(109, 72, 170, 0.6)',
                '0 0 20px rgba(109, 72, 170, 0.3)'
              ]
            }}
            transition={{ duration: 2, repeat: Infinity }}
          />
        </motion.div>

        {/* Text content */}
        <motion.div 
          className="header-text"
          variants={textVariants}
        >
          <motion.h1 
            className="header-title"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.2 }}
          >
            {title}
          </motion.h1>
          <motion.p 
            className="subtitle"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.4 }}
          >
            {subtitle}
          </motion.p>
        </motion.div>
      </motion.div>
    </motion.div>
  );
};

export default GradientHeader;