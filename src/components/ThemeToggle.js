import { useContext } from 'react';
import { ThemeContext } from '../contexts/ThemeContext';
import { FaMoon, FaSun } from 'react-icons/fa';
import { motion } from 'framer-motion';

const ThemeToggle = () => {
  const { theme, toggleTheme } = useContext(ThemeContext);

  return (
    <motion.button
      className="theme-toggle"
      onClick={toggleTheme}
      whileHover={{ scale: 1.1 }}
      whileTap={{ scale: 0.9 }}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ delay: 0.2 }}
      aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
    >
      {theme === 'dark' ? (
        <FaSun className="theme-icon" />
      ) : (
        <FaMoon className="theme-icon" />
      )}
      <motion.span
        className="theme-tooltip"
        initial={{ opacity: 0 }}
        whileHover={{ opacity: 1 }}
      >
        {theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
      </motion.span>
    </motion.button>
  );
};

export default ThemeToggle;