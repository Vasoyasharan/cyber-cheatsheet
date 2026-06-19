import { NavLink, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { FaHome, FaTools, FaBook, FaInfoCircle, FaShieldAlt, FaSearch, FaWrench, FaRoute, FaMagic, FaGlossary, FaBomb, FaNetworkWired, FaChevronDown } from 'react-icons/fa';
import { useContext, useState } from 'react';
import { ThemeContext } from '../../contexts/ThemeContext';
import AdvancedSearch from './AdvancedSearch';

// FaGlossary doesn't exist — use FaBook alias
const FaDict = FaBook;

const Navbar = () => {
  const { theme } = useContext(ThemeContext);
  const [showSearch, setShowSearch] = useState(false);
  const [showMore, setShowMore] = useState(false);

  const mainNav = [
    { path: '/', name: 'Home', icon: <FaHome /> },
    { path: '/tools', name: 'Tools', icon: <FaTools /> },
    { path: '/cheatsheets', name: 'Cheat Sheets', icon: <FaBook /> },
    { path: '/utilities', name: 'Utilities', icon: <FaWrench /> },
  ];

  const moreNav = [
    { path: '/learning', name: 'Learning Paths', icon: <FaRoute />, color: '#34d399', desc: 'Structured roadmaps from beginner to pro' },
    { path: '/explainer', name: 'Command Explainer', icon: <FaMagic />, color: '#a78bfa', desc: 'Paste a command — get it explained' },
    { path: '/glossary', name: 'Glossary', icon: <FaDict />, color: '#38bdf8', desc: '60+ cybersecurity terms defined' },
    { path: '/payloads', name: 'Payload Library', icon: <FaBomb />, color: '#f87171', desc: 'XSS, SQLi, SSTI, CMDi payloads' },
    { path: '/ports', name: 'Port Reference', icon: <FaNetworkWired />, color: '#fbbf24', desc: '65+ ports with risk ratings' },
    { path: '/cve', name: 'CVE Lookup', icon: <FaShieldAlt />, color: '#fb923c', desc: 'Search the NVD database live' },
    { path: '/about', name: 'About', icon: <FaInfoCircle />, color: 'var(--text-lighter)', desc: 'About CyberCheat' },
  ];

  const navVariants = {
    hidden: { opacity: 0, y: -30 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.6, staggerChildren: 0.1 } }
  };
  const itemVariants = {
    hidden: { opacity: 0, y: -20 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.5 } }
  };

  return (
    <>
      <motion.nav
        className={`navbar ${theme}`}
        variants={navVariants}
        initial="hidden"
        animate="visible"
      >
        <div className="navbar-glow"></div>
        <div className="nav-container">
          {/* Logo */}
          <motion.div className="nav-logo" whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
            <motion.div
              className="logo-icon"
              animate={{ rotate: 360 }}
              transition={{ duration: 20, repeat: Infinity, ease: 'linear' }}
            >
              <FaShieldAlt />
            </motion.div>
            <span style={{ fontFamily: "'Orbitron', sans-serif", fontWeight: '800', letterSpacing: '1px' }}>CyberCheat</span>
          </motion.div>

          {/* Main nav links */}
          <motion.ul className="nav-links" variants={navVariants}>
            {mainNav.map((item) => (
              <motion.li key={item.path} variants={itemVariants}>
                <NavLink
                  to={item.path}
                  className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}
                >
                  <motion.span className="nav-icon" whileHover={{ scale: 1.2, rotate: 10 }} whileTap={{ scale: 0.9 }}>
                    {item.icon}
                  </motion.span>
                  <span className="nav-text">{item.name}</span>
                  <span className="nav-indicator"></span>
                </NavLink>
              </motion.li>
            ))}

            {/* More dropdown */}
            <motion.li variants={itemVariants} style={{ position: 'relative' }}
              onMouseEnter={() => setShowMore(true)}
              onMouseLeave={() => setShowMore(false)}>
              <button
                style={{ display: 'flex', alignItems: 'center', gap: '5px', background: 'none', border: 'none', color: 'var(--text-light)', cursor: 'pointer', fontSize: '14px', fontWeight: '600', padding: '8px 12px', borderRadius: '8px' }}
              >
                More
                <motion.span animate={{ rotate: showMore ? 180 : 0 }} transition={{ duration: 0.2 }}>
                  <FaChevronDown style={{ fontSize: '10px' }} />
                </motion.span>
              </button>

              <AnimatePresence>
                {showMore && (
                  <motion.div
                    initial={{ opacity: 0, y: 10, scale: 0.95 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, y: 10, scale: 0.95 }}
                    transition={{ duration: 0.18 }}
                    style={{
                      position: 'absolute',
                      top: '100%',
                      right: 0,
                      minWidth: '260px',
                      background: 'var(--card-bg)',
                      border: '1px solid var(--glass-border)',
                      borderRadius: '14px',
                      boxShadow: 'var(--shadow-lg)',
                      backdropFilter: 'blur(20px)',
                      padding: '8px',
                      zIndex: 9999,
                    }}
                  >
                    {moreNav.map((item) => (
                      <NavLink
                        key={item.path}
                        to={item.path}
                        onClick={() => setShowMore(false)}
                        style={{ textDecoration: 'none' }}
                      >
                        <motion.div
                          whileHover={{ x: 4, background: `${item.color}12` }}
                          style={{ display: 'flex', alignItems: 'center', gap: '12px', padding: '10px 12px', borderRadius: '10px', cursor: 'pointer', transition: 'all 0.2s' }}
                        >
                          <span style={{ color: item.color, fontSize: '16px', flexShrink: 0 }}>{item.icon}</span>
                          <div>
                            <p style={{ color: 'var(--text)', fontWeight: '700', fontSize: '13px', margin: 0 }}>{item.name}</p>
                            <p style={{ color: 'var(--text-lighter)', fontSize: '11px', margin: 0 }}>{item.desc}</p>
                          </div>
                        </motion.div>
                      </NavLink>
                    ))}
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.li>
          </motion.ul>

          {/* Search Button */}
          <motion.button
            className="nav-search-btn"
            onClick={() => setShowSearch(true)}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            title="Advanced Search (Ctrl+K)"
          >
            <FaSearch />
            <span className="search-text">Search</span>
          </motion.button>
        </div>
      </motion.nav>

      <AdvancedSearch isOpen={showSearch} onClose={() => setShowSearch(false)} />
    </>
  );
};

export default Navbar;