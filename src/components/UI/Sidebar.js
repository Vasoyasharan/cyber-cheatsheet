import { useState, useContext } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  FaHome, FaTools, FaBook, FaWrench, FaInfoCircle,
  FaRoute, FaMagic, FaBomb, FaNetworkWired, FaShieldAlt,
  FaChevronLeft,
} from 'react-icons/fa';
import { ThemeContext } from '../../contexts/ThemeContext';
import { useSidebar } from '../../contexts/SidebarContext';

const COLLAPSED_W = 64;
const EXPANDED_W = 260;

const NAV_SECTIONS = [
  {
    label: 'Main',
    items: [
      { path: '/',            name: 'Home',              icon: <FaHome />,         color: '#a78bfa' },
      { path: '/tools',       name: 'Tools',             icon: <FaTools />,        color: '#38bdf8' },
      { path: '/cheatsheets', name: 'Cheat Sheets',      icon: <FaBook />,         color: '#34d399' },
      { path: '/utilities',   name: 'Utilities',         icon: <FaWrench />,       color: '#fbbf24' },
    ],
  },
  {
    label: 'Learn',
    items: [
      { path: '/learning',    name: 'Learning Paths',    icon: <FaRoute />,        color: '#34d399' },
      { path: '/explainer',   name: 'Cmd Explainer',     icon: <FaMagic />,        color: '#a78bfa' },
      { path: '/glossary',    name: 'Glossary',          icon: <FaBook />,         color: '#38bdf8' },
    ],
  },
  {
    label: 'Reference',
    items: [
      { path: '/payloads',    name: 'Payload Library',   icon: <FaBomb />,         color: '#f87171' },
      { path: '/ports',       name: 'Port Reference',    icon: <FaNetworkWired />, color: '#fbbf24' },
      { path: '/cve',         name: 'CVE Lookup',        icon: <FaShieldAlt />,    color: '#fb923c' },
    ],
  },
  {
    label: 'Info',
    items: [
      { path: '/about',       name: 'About',             icon: <FaInfoCircle />,   color: '#94a3b8' },
    ],
  },
];

/* ── Collapsed tooltip ──────────────────────── */
const CollapsedTooltip = ({ label, color }) => {
  const [hover, setHover] = useState(false);
  return (
    <div
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{ position: 'absolute', inset: 0, pointerEvents: 'none' }}
    >
      <AnimatePresence>
        {hover && (
          <motion.div
            initial={{ opacity: 0, x: -6 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -6 }}
            transition={{ duration: 0.14 }}
            style={{
              position: 'absolute',
              left: COLLAPSED_W - 2,
              top: '50%',
              transform: 'translateY(-50%)',
              background: 'var(--card-bg-solid)',
              border: `1px solid ${color}44`,
              color: color,
              padding: '5px 13px',
              borderRadius: 8,
              fontSize: 12,
              fontWeight: 700,
              whiteSpace: 'nowrap',
              boxShadow: `0 4px 16px ${color}33`,
              zIndex: 99999,
              pointerEvents: 'none',
            }}
          >
            {label}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

/* ── Single nav item ────────────────────────── */
const SidebarItem = ({ item, expanded }) => {
  const { close } = useSidebar();
  const location = useLocation();
  const isActive = item.path === '/'
    ? location.pathname === '/'
    : location.pathname.startsWith(item.path);

  return (
    <div style={{ position: 'relative' }}>
      <NavLink
        to={item.path}
        end={item.path === '/'}
        onClick={() => { if (window.innerWidth < 768) close(); }}
        style={{ textDecoration: 'none', display: 'block' }}
      >
        <motion.div
          whileHover={{ x: expanded ? 3 : 0 }}
          whileTap={{ scale: 0.96 }}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            padding: expanded ? '10px 16px 10px 20px' : '11px 0',
            justifyContent: expanded ? 'flex-start' : 'center',
            margin: '2px 8px',
            borderRadius: 10,
            background: isActive ? `${item.color}18` : 'transparent',
            border: isActive ? `1px solid ${item.color}33` : '1px solid transparent',
            cursor: 'pointer',
            transition: 'background 0.2s, border-color 0.2s',
            position: 'relative',
            overflow: 'hidden',
          }}
          onMouseEnter={e => { if (!isActive) e.currentTarget.style.background = `${item.color}0f`; }}
          onMouseLeave={e => { if (!isActive) e.currentTarget.style.background = 'transparent'; }}
        >
          {/* Active left-bar indicator (collapsed only) */}
          {isActive && !expanded && (
            <div style={{
              position: 'absolute', left: -8,
              top: '20%', bottom: '20%',
              width: 3, borderRadius: '0 3px 3px 0',
              background: item.color,
              boxShadow: `0 0 8px ${item.color}`,
            }} />
          )}

          {/* Icon */}
          <span style={{
            color: isActive ? item.color : 'var(--text-lighter)',
            fontSize: 18, flexShrink: 0,
            filter: isActive ? `drop-shadow(0 0 5px ${item.color}99)` : 'none',
            transition: 'color 0.2s, filter 0.2s',
          }}>
            {item.icon}
          </span>

          {/* Label (expanded only) */}
          {expanded && (
            <motion.span
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 0.18 }}
              style={{
                fontSize: 13,
                fontWeight: isActive ? 700 : 500,
                color: isActive ? item.color : 'var(--text-light)',
                whiteSpace: 'nowrap',
                flex: 1,
              }}
            >
              {item.name}
            </motion.span>
          )}

          {/* Active dot (expanded only) */}
          {isActive && expanded && (
            <motion.div
              layoutId="sidebar-active-dot"
              style={{
                width: 6, height: 6, borderRadius: '50%',
                background: item.color,
                boxShadow: `0 0 8px ${item.color}`,
                flexShrink: 0,
              }}
            />
          )}
        </motion.div>
      </NavLink>

      {/* Hover tooltip when collapsed */}
      {!expanded && <CollapsedTooltip label={item.name} color={item.color} />}
    </div>
  );
};

/* ── Main Sidebar ───────────────────────────── */
const Sidebar = () => {
  const { theme } = useContext(ThemeContext);
  const { expanded, toggle } = useSidebar();
  const w = expanded ? EXPANDED_W : COLLAPSED_W;

  return (
    <motion.aside
      animate={{ width: w }}
      transition={{ type: 'spring', stiffness: 280, damping: 28 }}
      className={`sidebar ${theme}`}
      style={{
        position: 'fixed',
        top: 0, left: 0,
        height: '100vh',
        zIndex: 1200,
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        background: 'var(--nav-bg)',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        borderRight: '1px solid var(--glass-border)',
        boxShadow: expanded ? 'var(--shadow-lg)' : 'none',
      }}
    >
      {/* ── Header / Logo ── */}
      <div style={{
        height: 64, flexShrink: 0,
        display: 'flex', alignItems: 'center',
        justifyContent: expanded ? 'space-between' : 'center',
        padding: expanded ? '0 14px 0 18px' : '0',
        borderBottom: '1px solid var(--glass-border)',
        overflow: 'hidden',
      }}>
        {expanded && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.08 }}
            style={{ display: 'flex', alignItems: 'center', gap: 10 }}
          >
            <motion.div
              animate={{ rotate: 360 }}
              transition={{ duration: 20, repeat: Infinity, ease: 'linear' }}
              style={{ color: 'var(--primary)', fontSize: 20, flexShrink: 0 }}
            >
              <FaShieldAlt />
            </motion.div>
            <span style={{
              fontFamily: "'Orbitron', sans-serif",
              fontWeight: 800, fontSize: 15, letterSpacing: '1px',
              background: 'var(--gradient-primary)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              backgroundClip: 'text',
              whiteSpace: 'nowrap',
            }}>
              CyberCheat
            </span>
          </motion.div>
        )}

        {/* Collapsed: just the rotating shield */}
        {!expanded && (
          <motion.div
            animate={{ rotate: 360 }}
            transition={{ duration: 20, repeat: Infinity, ease: 'linear' }}
            style={{ color: 'var(--primary)', fontSize: 22 }}
          >
            <FaShieldAlt />
          </motion.div>
        )}

        {/* Toggle chevron — only visible when expanded */}
        {expanded && (
          <motion.button
            onClick={toggle}
            whileHover={{ scale: 1.12 }}
            whileTap={{ scale: 0.9 }}
            title="Collapse sidebar"
            style={{
              width: 30, height: 30, borderRadius: '50%',
              border: '1px solid var(--glass-border)',
              background: 'var(--card-bg)',
              color: 'var(--text-light)',
              cursor: 'pointer',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 12, flexShrink: 0,
            }}
          >
            <FaChevronLeft />
          </motion.button>
        )}
      </div>

      {/* ── Nav sections ── */}
      <div style={{
        flex: 1, overflowY: 'auto', overflowX: 'hidden',
        padding: '10px 0',
        scrollbarWidth: 'none',
        msOverflowStyle: 'none',
      }}>
        {NAV_SECTIONS.map((section, si) => (
          <div key={si} style={{ marginBottom: 6 }}>
            {/* Section label when expanded */}
            {expanded ? (
              <motion.p
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                style={{
                  fontSize: 10, fontWeight: 800,
                  color: 'var(--text-lighter)',
                  textTransform: 'uppercase', letterSpacing: '1.2px',
                  padding: '8px 20px 4px',
                  whiteSpace: 'nowrap', margin: 0,
                }}
              >
                {section.label}
              </motion.p>
            ) : (
              si > 0 && (
                <div style={{ height: 1, background: 'var(--border)', margin: '8px 12px' }} />
              )
            )}

            {section.items.map(item => (
              <SidebarItem key={item.path} item={item} expanded={expanded} />
            ))}
          </div>
        ))}
      </div>

      {/* ── Footer ── */}
      {expanded && (
        <motion.div
          initial={{ opacity: 0 }} animate={{ opacity: 1 }}
          style={{
            padding: '12px 20px',
            borderTop: '1px solid var(--glass-border)',
            flexShrink: 0,
          }}
        >
          <p style={{ fontSize: 11, color: 'var(--text-lighter)', margin: 0 }}>🛡️ CyberCheat v2.0</p>
          <p style={{ fontSize: 10, color: 'var(--text-lighter)', opacity: 0.5, margin: '2px 0 0' }}>
            For authorized testing only
          </p>
        </motion.div>
      )}
    </motion.aside>
  );
};

export default Sidebar;
