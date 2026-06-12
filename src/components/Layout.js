import { useContext } from 'react';
import { ThemeContext } from '../contexts/ThemeContext';
import Navbar from './UI/Navbar';
import Footer from './UI/Footer';
import ThemeToggle from './ThemeToggle';
import { motion } from 'framer-motion';
import CommandHistory from './UI/CommandHistory';
import BackToTop from './UI/BackToTop';
import KeyboardShortcuts from './UI/KeyboardShortcuts';

const Layout = ({ children }) => {
  const { theme, toggleTheme } = useContext(ThemeContext);

  return (
    <div className={`app-container ${theme}`}>
      <Navbar />
      <ThemeToggle />
      <CommandHistory />
      <BackToTop />
      <KeyboardShortcuts onToggleTheme={toggleTheme} />
      <motion.main
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.5 }}
      >
        {children}
      </motion.main>
      <Footer />
    </div>
  );
};

export default Layout;