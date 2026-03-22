import { NavLink } from 'react-router-dom';
import { motion } from 'framer-motion';
import { FaHome, FaTools, FaBook, FaInfoCircle, FaShieldAlt } from 'react-icons/fa';
import { useContext } from 'react';
import { ThemeContext } from '../../contexts/ThemeContext';

const Navbar = () => {
  const { theme } = useContext(ThemeContext);

  const navItems = [
    { path: '/', name: 'Home', icon: <FaHome /> },
    { path: '/tools', name: 'Tools', icon: <FaTools /> },
    { path: '/cheatsheets', name: 'Cheat Sheets', icon: <FaBook /> },
    { path: '/about', name: 'About', icon: <FaInfoCircle /> }
  ];

  const navVariants = {
    hidden: { opacity: 0, y: -30 },
    visible: {
      opacity: 1,
      y: 0,
      transition: {
        duration: 0.6,
        staggerChildren: 0.1
      }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: -20 },
    visible: { 
      opacity: 1, 
      y: 0,
      transition: { duration: 0.5 }
    }
  };

  return (
    <motion.nav 
      className={`navbar ${theme}`}
      variants={navVariants}
      initial="hidden"
      animate="visible"
    >
      <div className="navbar-glow"></div>
      <div className="nav-container">
        {/* Logo with animated icon */}
        <motion.div 
          className="nav-logo"
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
        >
          <motion.div 
            className="logo-icon"
            animate={{ rotate: 360 }}
            transition={{ duration: 20, repeat: Infinity }}
          >
            <FaShieldAlt />
          </motion.div>
          <span>CyberCheat</span>
        </motion.div>

        {/* Navigation Links */}
        <motion.ul 
          className="nav-links"
          variants={navVariants}
        >
          {navItems.map((item, index) => (
            <motion.li
              key={item.path}
              variants={itemVariants}
            >
              <NavLink
                to={item.path}
                className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}
              >
                <motion.span 
                  className="nav-icon"
                  whileHover={{ scale: 1.2, rotate: 10 }}
                  whileTap={{ scale: 0.9 }}
                >
                  {item.icon}
                </motion.span>
                <span className="nav-text">{item.name}</span>
                <span className="nav-indicator"></span>
              </NavLink>
            </motion.li>
          ))}
        </motion.ul>
      </div>
    </motion.nav>
  );
};

export default Navbar;