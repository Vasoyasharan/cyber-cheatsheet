import { useContext } from 'react';
import { motion } from 'framer-motion';
import { ThemeContext } from '../contexts/ThemeContext';
import { useSidebar } from '../contexts/SidebarContext';
import Sidebar from './UI/Sidebar';
import Topbar from './UI/Topbar';
import Footer from './UI/Footer';
import CommandHistory from './UI/CommandHistory';
import KeyboardShortcuts from './UI/KeyboardShortcuts';

const COLLAPSED_W = 64;
const EXPANDED_W  = 260;
const TOPBAR_H    = 64;

const Layout = ({ children }) => {
  const { theme, toggleTheme } = useContext(ThemeContext);
  const { expanded } = useSidebar();

  const sideW = expanded ? EXPANDED_W : COLLAPSED_W;

  return (
    <div className={`app-container ${theme}`} style={{ display: 'flex', minHeight: '100vh' }}>

      {/* ── Sidebar (fixed, left) ── */}
      <Sidebar />

      {/* ── Right side: Topbar + content + footer ── */}
      <motion.div
        animate={{ marginLeft: sideW }}
        transition={{ type: 'spring', stiffness: 280, damping: 28 }}
        style={{
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          minHeight: '100vh',
          minWidth: 0,
        }}
      >
        {/* Topbar */}
        <Topbar />

        {/* Floating utilities */}
        <CommandHistory />
        <KeyboardShortcuts onToggleTheme={toggleTheme} />

        {/* Page content */}
        <motion.main
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.4 }}
          style={{
            flex: 1,
            marginTop: TOPBAR_H,
            padding: '2rem',
            maxWidth: '100%',
            width: '100%',
            boxSizing: 'border-box',
          }}
        >
          {children}
        </motion.main>

        <Footer />
      </motion.div>
    </div>
  );
};

export default Layout;