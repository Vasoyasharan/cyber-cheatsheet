import { useContext } from 'react';
import { motion } from 'framer-motion';
import { FaBars, FaSearch, FaSun, FaMoon } from 'react-icons/fa';
import { ThemeContext } from '../../contexts/ThemeContext';
import { useSidebar } from '../../contexts/SidebarContext';
import AdvancedSearch from './AdvancedSearch';
import { useState } from 'react';

const COLLAPSED_W = 64;
const EXPANDED_W  = 260;

const Topbar = () => {
  const { theme, toggleTheme } = useContext(ThemeContext);
  const { expanded, toggle } = useSidebar();
  const [showSearch, setShowSearch] = useState(false);

  const sideW = expanded ? EXPANDED_W : COLLAPSED_W;

  return (
    <>
      <motion.header
        animate={{ left: sideW }}
        transition={{ type: 'spring', stiffness: 280, damping: 28 }}
        className={`topbar ${theme}`}
        style={{
          position: 'fixed',
          top: 0,
          right: 0,
          height: 64,
          zIndex: 1100,
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          padding: '0 20px 0 16px',
          background: 'var(--nav-bg)',
          backdropFilter: 'blur(20px)',
          WebkitBackdropFilter: 'blur(20px)',
          borderBottom: '1px solid var(--glass-border)',
          boxShadow: '0 1px 0 var(--glass-border)',
        }}
      >
        {/* ── Hamburger ── */}
        <motion.button
          onClick={toggle}
          whileHover={{ scale: 1.08 }}
          whileTap={{ scale: 0.92 }}
          title={expanded ? 'Collapse sidebar' : 'Expand sidebar'}
          style={{
            width: 36, height: 36,
            borderRadius: 10,
            border: '1px solid var(--glass-border)',
            background: 'var(--card-bg)',
            color: 'var(--text)',
            cursor: 'pointer',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 15,
          }}
        >
          <motion.span
            animate={{ rotate: expanded ? 90 : 0 }}
            transition={{ duration: 0.25 }}
          >
            <FaBars />
          </motion.span>
        </motion.button>

        {/* ── Spacer ── */}
        <div style={{ flex: 1 }} />

        {/* ── Search ── */}
        <motion.button
          onClick={() => setShowSearch(true)}
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          title="Advanced Search"
          style={{
            height: 36,
            padding: '0 16px',
            borderRadius: 10,
            border: '1px solid var(--glass-border)',
            background: 'var(--card-bg)',
            color: 'var(--text-light)',
            cursor: 'pointer',
            display: 'flex', alignItems: 'center', gap: 8,
            fontSize: 13, fontWeight: 500,
          }}
        >
          <FaSearch style={{ color: 'var(--primary)' }} />
          <span style={{ display: window.innerWidth > 480 ? 'inline' : 'none' }}>Search...</span>
        </motion.button>

        {/* ── Theme toggle ── */}
        <motion.button
          onClick={toggleTheme}
          whileHover={{ scale: 1.08, rotate: 15 }}
          whileTap={{ scale: 0.92 }}
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          style={{
            width: 36, height: 36,
            borderRadius: '50%',
            border: '1px solid var(--glass-border)',
            background: 'var(--gradient-primary)',
            color: 'white',
            cursor: 'pointer',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 15,
            boxShadow: 'var(--glow)',
          }}
        >
          {theme === 'dark' ? <FaSun /> : <FaMoon />}
        </motion.button>
      </motion.header>

      <AdvancedSearch isOpen={showSearch} onClose={() => setShowSearch(false)} />
    </>
  );
};

export default Topbar;
