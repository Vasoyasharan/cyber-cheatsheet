import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FaKeyboard, FaTimes } from 'react-icons/fa';

const shortcuts = [
  { keys: ['?'], description: 'Show / hide this keyboard shortcuts panel' },
  { keys: ['/'], description: 'Focus the search bar on current page' },
  { keys: ['Esc'], description: 'Close active tool / cheatsheet panel' },
  { keys: ['Ctrl', 'K'], description: 'Open advanced search (Command Palette)' },
  { keys: ['Ctrl', 'D'], description: 'Toggle dark / light mode' },
  { keys: ['Ctrl', 'H'], description: 'Toggle command history panel' },
  { keys: ['Alt', '1'], description: 'Navigate to Home' },
  { keys: ['Alt', '2'], description: 'Navigate to Tools' },
  { keys: ['Alt', '3'], description: 'Navigate to Cheat Sheets' },
];

const KeyboardShortcuts = ({ onToggleTheme, onToggleHistory }) => {
  const [open, setOpen] = useState(false);

  const handle = useCallback((e) => {
    const tag = document.activeElement?.tagName;
    const isTyping = ['INPUT', 'TEXTAREA', 'SELECT'].includes(tag);

    // '?' opens shortcut panel
    if (e.key === '?' && !isTyping) { setOpen(o => !o); return; }
    // Esc closes
    if (e.key === 'Escape') { setOpen(false); return; }
    // '/' focuses search
    if (e.key === '/' && !isTyping) {
      e.preventDefault();
      const searchInput = document.querySelector('input[type="text"][placeholder*="earch"]') ||
                          document.querySelector('input[type="text"]');
      searchInput?.focus();
      return;
    }
    // Ctrl+D → theme toggle
    if (e.ctrlKey && e.key === 'd') { e.preventDefault(); onToggleTheme?.(); return; }
    // Ctrl+H → history
    if (e.ctrlKey && e.key === 'h') { e.preventDefault(); onToggleHistory?.(); return; }
    // Alt+1/2/3 navigation
    if (e.altKey) {
      const routes = { '1': '/', '2': '/tools', '3': '/cheatsheets' };
      if (routes[e.key]) { e.preventDefault(); window.location.href = routes[e.key]; }
    }
  }, [onToggleTheme, onToggleHistory]);

  useEffect(() => {
    window.addEventListener('keydown', handle);
    return () => window.removeEventListener('keydown', handle);
  }, [handle]);

  return (
    <>
      {/* Help button */}
      <motion.button
        onClick={() => setOpen(o => !o)}
        title="Keyboard shortcuts (?)"
        whileHover={{ scale: 1.08 }}
        whileTap={{ scale: 0.92 }}
        style={{
          position: 'fixed',
          bottom: '82px',
          right: '28px',
          zIndex: 9998,
          width: '46px',
          height: '46px',
          borderRadius: '50%',
          border: '2px solid var(--primary)',
          background: 'var(--card-bg)',
          color: 'var(--primary)',
          fontSize: '18px',
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: '0 4px 12px rgba(110,72,170,0.3)',
        }}
      >
        <FaKeyboard />
      </motion.button>

      {/* Modal */}
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setOpen(false)}
            style={{
              position: 'fixed', inset: 0, zIndex: 99999,
              background: 'rgba(0,0,0,0.65)', backdropFilter: 'blur(4px)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              padding: '20px',
            }}
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.88, y: 30 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.88, y: 30 }}
              transition={{ type: 'spring', stiffness: 320, damping: 28 }}
              onClick={e => e.stopPropagation()}
              style={{
                background: 'var(--card-bg)',
                borderRadius: '16px',
                border: '1px solid var(--primary)',
                padding: '32px',
                maxWidth: '520px',
                width: '100%',
                boxShadow: '0 24px 64px rgba(110,72,170,0.35)',
              }}
            >
              {/* Header */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <FaKeyboard style={{ color: 'var(--primary)', fontSize: '22px' }} />
                  <h2 style={{ margin: 0, color: 'var(--text)', fontSize: '20px', fontWeight: '700' }}>
                    Keyboard Shortcuts
                  </h2>
                </div>
                <motion.button
                  onClick={() => setOpen(false)}
                  whileHover={{ scale: 1.1, rotate: 90 }}
                  style={{ background: 'transparent', border: 'none', color: 'var(--text)', fontSize: '18px', cursor: 'pointer', opacity: 0.6 }}
                >
                  <FaTimes />
                </motion.button>
              </div>

              {/* Shortcuts list */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {shortcuts.map((s, i) => (
                  <motion.div
                    key={i}
                    initial={{ opacity: 0, x: -16 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.04 }}
                    style={{
                      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                      padding: '10px 14px', borderRadius: '10px',
                      background: 'rgba(110,72,170,0.06)', border: '1px solid rgba(110,72,170,0.12)',
                    }}
                  >
                    <span style={{ fontSize: '14px', color: 'var(--text)', opacity: 0.85 }}>{s.description}</span>
                    <div style={{ display: 'flex', gap: '4px', flexShrink: 0, marginLeft: '12px' }}>
                      {s.keys.map((k, j) => (
                        <kbd key={j} style={{
                          display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                          padding: '3px 8px', borderRadius: '6px', fontSize: '12px', fontWeight: '700',
                          fontFamily: 'monospace',
                          background: 'var(--bg)', color: 'var(--primary)',
                          border: '1px solid var(--primary)',
                          boxShadow: '0 2px 0 var(--primary)',
                          minWidth: '28px',
                        }}>{k}</kbd>
                      ))}
                    </div>
                  </motion.div>
                ))}
              </div>

              <p style={{ marginTop: '20px', fontSize: '12px', opacity: 0.45, textAlign: 'center', color: 'var(--text)' }}>
                Press <kbd style={{ fontSize: '11px', padding: '1px 5px', borderRadius: '4px', border: '1px solid var(--border)', background: 'var(--bg)' }}>?</kbd> anywhere to toggle this panel
              </p>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
};

export default KeyboardShortcuts;
