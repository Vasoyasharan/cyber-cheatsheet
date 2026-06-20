import { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FaSearch, FaShieldAlt, FaExclamationTriangle, FaExternalLinkAlt, FaCopy, FaTerminal } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { copyToClipboard } from '../utils/copyToClipboard';
import GradientHeader from '../components/UI/GradientHeader';

/* ── Creative CVE Loader ─────────────────────────────────────────── */
const HACKER_LINES = [
  '> Initializing NVD API connection...',
  '> Querying NIST vulnerability database...',
  '> Bypassing rate-limit throttle... ⚡',
  '> Decrypting CVSS vector strings...',
  '> Cross-referencing CWE taxonomy...',
  '> Pulling exploit references from CVE feed...',
  '> Scanning advisory metadata...',
  '> Parsing CVSS v3.1 base score...',
  '> Verifying CPE affected versions...',
  '> Correlating public PoC indicators...',
  '> Aggregating NVD enrichment data...',
  '> Checking for CISA KEV overlap...',
  '> Loading patch advisory links...',
  '> Almost there — NVD can be slow ☕',
  '> Still querying... hang tight, operator 🛡️',
];

const CVELoader = ({ cveId }) => {
  const [lines, setLines] = useState([HACKER_LINES[0]]);
  const [progress, setProgress] = useState(4);
  const [cursor, setCursor] = useState(true);
  const lineIndex = useRef(1);
  const progressRef = useRef(4);

  useEffect(() => {
    // Blinking cursor
    const cursorTimer = setInterval(() => setCursor(c => !c), 530);

    // Add a new terminal line every ~2.5 s, cycle after exhausting all
    const lineTimer = setInterval(() => {
      const next = HACKER_LINES[lineIndex.current % HACKER_LINES.length];
      lineIndex.current += 1;
      setLines(prev => [...prev.slice(-6), next]); // keep last 7 lines visible
    }, 2500);

    // Slow progress bar — crawls but never reaches 100 on its own
    const progressTimer = setInterval(() => {
      progressRef.current = Math.min(progressRef.current + Math.random() * 2.5, 92);
      setProgress(Math.floor(progressRef.current));
    }, 800);

    return () => {
      clearInterval(cursorTimer);
      clearInterval(lineTimer);
      clearInterval(progressTimer);
    };
  }, []);

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.96 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, scale: 0.96 }}
      style={{
        margin: '10px 0 24px',
        borderRadius: '18px',
        border: '1.5px solid rgba(99,102,241,0.35)',
        background: 'linear-gradient(135deg, rgba(10,10,20,0.95) 0%, rgba(17,24,39,0.95) 100%)',
        overflow: 'hidden',
        boxShadow: '0 0 40px rgba(99,102,241,0.18), 0 8px 32px rgba(0,0,0,0.5)',
      }}
    >
      {/* Title bar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: '8px',
        padding: '10px 16px',
        background: 'rgba(99,102,241,0.12)',
        borderBottom: '1px solid rgba(99,102,241,0.2)',
      }}>
        {['#f87171','#fbbf24','#34d399'].map(c => (
          <div key={c} style={{ width: 11, height: 11, borderRadius: '50%', background: c, opacity: 0.85 }} />
        ))}
        <FaTerminal style={{ color: '#a5b4fc', fontSize: 12, marginLeft: 6 }} />
        <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 11, color: '#a5b4fc', fontWeight: 700 }}>
          nvd-query — {cveId}
        </span>
        {/* Pulsing live dot */}
        <motion.div
          animate={{ opacity: [1, 0.2, 1] }}
          transition={{ duration: 1.2, repeat: Infinity }}
          style={{ marginLeft: 'auto', width: 8, height: 8, borderRadius: '50%', background: '#34d399' }}
        />
        <span style={{ fontSize: 10, color: '#34d399', fontFamily: "'JetBrains Mono',monospace" }}>LIVE</span>
      </div>

      {/* Terminal body */}
      <div style={{ padding: '18px 20px 14px', minHeight: '180px' }}>
        {/* Animated shield */}
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '20px' }}>
          <div style={{ flexShrink: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
            <motion.div
              animate={{ boxShadow: ['0 0 12px #6366f1aa', '0 0 32px #818cf8cc', '0 0 12px #6366f1aa'] }}
              transition={{ duration: 2, repeat: Infinity }}
              style={{ width: 56, height: 56, borderRadius: '50%', background: 'rgba(99,102,241,0.15)', border: '2px solid rgba(99,102,241,0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}
            >
              <motion.div
                animate={{ rotate: [0, 10, -10, 0] }}
                transition={{ duration: 3, repeat: Infinity }}
              >
                <FaShieldAlt style={{ fontSize: 26, color: '#818cf8' }} />
              </motion.div>
            </motion.div>
            {/* Matrix rain dots */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4, alignItems: 'center' }}>
              {[0, 1, 2, 3, 4].map(i => (
                <motion.div key={i}
                  animate={{ opacity: [0, 1, 0], y: [0, 8] }}
                  transition={{ duration: 1.2, repeat: Infinity, delay: i * 0.22, ease: 'linear' }}
                  style={{ width: 3, height: 3, borderRadius: '50%', background: '#34d399' }}
                />
              ))}
            </div>
          </div>

          {/* Terminal lines */}
          <div style={{ flex: 1, fontFamily: "'JetBrains Mono',monospace", fontSize: 12, lineHeight: '1.9' }}>
            <AnimatePresence initial={false}>
              {lines.map((line, i) => (
                <motion.div
                  key={line + i}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: i === lines.length - 1 ? 1 : 0.45, x: 0 }}
                  style={{ color: i === lines.length - 1 ? '#a5b4fc' : '#475569' }}
                >
                  {line}
                  {i === lines.length - 1 && (
                    <span style={{ opacity: cursor ? 1 : 0, color: '#818cf8' }}>█</span>
                  )}
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        </div>
      </div>

      {/* Progress bar */}
      <div style={{ padding: '0 20px 18px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
          <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: '#64748b' }}>FETCHING NVD DATA</span>
          <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: '#818cf8' }}>{progress}%</span>
        </div>
        <div style={{ height: 5, borderRadius: 99, background: 'rgba(99,102,241,0.12)', overflow: 'hidden' }}>
          <motion.div
            animate={{ width: `${progress}%` }}
            transition={{ ease: 'easeOut', duration: 0.8 }}
            style={{
              height: '100%', borderRadius: 99,
              background: 'linear-gradient(90deg, #6366f1, #818cf8, #a78bfa)',
              boxShadow: '0 0 8px #818cf8aa',
            }}
          />
        </div>
        <p style={{ fontSize: 10, color: '#475569', margin: '8px 0 0', fontFamily: "'JetBrains Mono',monospace" }}>
          NVD API can take 30s–2min · sit tight, operator 🛡️
        </p>
      </div>
    </motion.div>
  );
};

const severityColor = { CRITICAL: '#f87171', HIGH: '#fb923c', MEDIUM: '#fbbf24', LOW: '#34d399', NONE: '#64748b' };
const severityBg = { CRITICAL: 'rgba(248,113,113,0.15)', HIGH: 'rgba(251,146,60,0.15)', MEDIUM: 'rgba(251,191,36,0.15)', LOW: 'rgba(52,211,153,0.15)', NONE: 'rgba(100,116,139,0.15)' };

/* Parse the NVD API v2.0 response format */
const parseNVD = (data) => {
  const vuln = data?.vulnerabilities?.[0]?.cve;
  if (!vuln) return null;

  const desc = vuln.descriptions?.find(d => d.lang === 'en')?.value || 'No description available.';
  const metrics = vuln.metrics;
  const cvssV3 = metrics?.cvssMetricV31?.[0] || metrics?.cvssMetricV30?.[0];
  const cvssV2 = metrics?.cvssMetricV2?.[0];
  const cvssData = cvssV3?.cvssData || cvssV2?.cvssData;
  const score = cvssData?.baseScore;
  const severity = cvssData?.baseSeverity || cvssV2?.baseSeverity || 'UNKNOWN';
  const vector = cvssData?.vectorString;

  const references = (vuln.references || []).slice(0, 5);
  const published = vuln.published ? new Date(vuln.published).toLocaleDateString() : 'Unknown';
  const modified = vuln.lastModified ? new Date(vuln.lastModified).toLocaleDateString() : 'Unknown';
  const weaknesses = vuln.weaknesses?.flatMap(w => w.description?.map(d => d.value)) || [];

  return { id: vuln.id, desc, score, severity: severity.toUpperCase(), vector, references, published, modified, weaknesses };
};

const CVELookup = () => {
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const examples = [
    { id: 'CVE-2021-44228', label: 'Log4Shell' },
    { id: 'CVE-2017-0144', label: 'EternalBlue' },
    { id: 'CVE-2019-0708', label: 'BlueKeep' },
    { id: 'CVE-2020-1472', label: 'Zerologon' },
    { id: 'CVE-2021-4034', label: 'PwnKit' },
    { id: 'CVE-2014-0160', label: 'Heartbleed' },
    { id: 'CVE-2021-26855', label: 'ProxyLogon' },
    { id: 'CVE-2022-0847', label: 'DirtyPipe' },
  ];

  const lookup = async (cveId) => {
    const id = (cveId || input).trim().toUpperCase();
    if (!id) return;
    if (!id.match(/^CVE-\d{4}-\d+$/)) {
      setError('Invalid format. Use CVE-YYYY-NNNNN (e.g. CVE-2021-44228)');
      return;
    }
    setLoading(true);
    setResult(null);
    setError('');
    try {
      const res = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${id}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const parsed = parseNVD(data);
      if (!parsed) {
        setError(`No data found for ${id}. Check the CVE ID is correct.`);
      } else {
        setResult(parsed);
      }
    } catch (e) {
      setError(`Failed to fetch: ${e.message}. The NVD API may be rate-limiting requests — try again in a moment.`);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e) => { if (e.key === 'Enter') lookup(); };

  const scoreColor = (score) => {
    if (!score) return '#64748b';
    if (score >= 9.0) return '#f87171';
    if (score >= 7.0) return '#fb923c';
    if (score >= 4.0) return '#fbbf24';
    return '#34d399';
  };

  return (
    <div style={{ padding: '0 20px 60px', maxWidth: '1100px', margin: '0 auto' }}>
      <GradientHeader
        title="CVE Lookup"
        subtitle="Search the NVD database for CVE details — CVSS score, description, severity, and references"
        icon={<FaShieldAlt />}
      />

      {/* Two-column layout */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 300px', gap: '24px', alignItems: 'flex-start' }}>
        {/* Left: Search + results */}
        <div>
          {/* Famous CVEs */}
          <div style={{ margin: '20px 0 16px' }}>
            <p style={{ fontSize: '11px', color: 'var(--text-lighter)', marginBottom: '10px', fontWeight: '700', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Famous CVEs — click to load:</p>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              {examples.map(ex => (
                <motion.button key={ex.id} onClick={() => { setInput(ex.id); lookup(ex.id); }} whileHover={{ scale: 1.04 }} whileTap={{ scale: 0.96 }}
                  style={{ padding: '6px 12px', borderRadius: '20px', fontSize: '11px', fontWeight: '700', border: '1px solid var(--border-strong)', background: 'var(--card-bg)', color: 'var(--primary)', cursor: 'pointer', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '2px' }}>
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '10px' }}>{ex.id}</span>
                  <span style={{ fontSize: '9px', color: 'var(--text-lighter)', fontFamily: 'inherit' }}>{ex.label}</span>
                </motion.button>
              ))}
            </div>
          </div>

      {/* Input */}
      <div style={{ display: 'flex', gap: '12px', marginBottom: '28px' }}>
        <input
          value={input}
          onChange={e => { setInput(e.target.value.toUpperCase()); setError(''); setResult(null); }}
          onKeyDown={handleKeyDown}
          placeholder="CVE-2021-44228"
          style={{
            flex: 1, padding: '14px 18px',
            fontFamily: "'JetBrains Mono', monospace", fontSize: '15px', letterSpacing: '1px',
            background: 'var(--card-bg)', color: 'var(--text)',
            border: '1.5px solid var(--border-strong)', borderRadius: '12px', outline: 'none',
          }}
          onFocus={e => e.target.style.borderColor = 'var(--primary)'}
          onBlur={e => e.target.style.borderColor = 'var(--border-strong)'}
        />
        <motion.button onClick={() => lookup()} whileHover={{ scale: loading ? 1 : 1.04 }} whileTap={{ scale: loading ? 1 : 0.96 }}
          disabled={loading}
          style={{ padding: '14px 24px', borderRadius: '12px', border: 'none', background: loading ? 'rgba(99,102,241,0.3)' : 'var(--gradient-primary)', color: 'white', fontWeight: '700', fontSize: '14px', cursor: loading ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', gap: '8px', minWidth: '120px', justifyContent: 'center' }}>
          {loading ? (
            <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 12 }}>Scanning...</span>
          ) : (
            <><FaSearch /> Lookup</>
          )}
        </motion.button>
      </div>

      {/* Creative loader */}
      <AnimatePresence>
        {loading && <CVELoader cveId={input} />}
      </AnimatePresence>

      {/* Error */}
      {error && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
          style={{ padding: '14px 18px', borderRadius: '12px', background: 'rgba(248,113,113,0.1)', border: '1px solid rgba(248,113,113,0.3)', display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
          <FaExclamationTriangle style={{ color: '#f87171' }} />
          <p style={{ color: 'var(--text)', fontSize: '14px', margin: 0 }}>{error}</p>
        </motion.div>
      )}

      {/* Result */}
      <AnimatePresence>
        {result && (
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            style={{ background: 'var(--card-bg)', borderRadius: '20px', border: `2px solid ${severityColor[result.severity] || 'var(--border)'}33`, overflow: 'hidden' }}>
            {/* Header bar */}
            <div style={{ padding: '20px 28px', background: `${severityBg[result.severity] || 'transparent'}`, borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
              <code style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '20px', fontWeight: '800', color: 'var(--text)' }}>{result.id}</code>
              <div style={{ marginLeft: 'auto', display: 'flex', gap: '10px', alignItems: 'center' }}>
                {result.score && (
                  <div style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: '28px', fontWeight: '900', color: scoreColor(result.score), lineHeight: 1 }}>{result.score}</div>
                    <div style={{ fontSize: '10px', color: 'var(--text-lighter)', fontWeight: '700' }}>CVSS</div>
                  </div>
                )}
                <span style={{ background: severityBg[result.severity], color: severityColor[result.severity] || '#64748b', padding: '6px 16px', borderRadius: '20px', fontWeight: '800', fontSize: '13px' }}>
                  {result.severity}
                </span>
                <motion.button onClick={() => { copyToClipboard(result.id); toast.success('CVE ID copied!', { position: 'bottom-right', autoClose: 1200, hideProgressBar: true }); }}
                  whileHover={{ scale: 1.1 }} style={{ background: 'transparent', border: 'none', color: 'var(--text-lighter)', cursor: 'pointer', fontSize: '16px' }}>
                  <FaCopy />
                </motion.button>
              </div>
            </div>

            <div style={{ padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
              {/* Description */}
              <div>
                <h4 style={{ color: 'var(--primary)', fontSize: '12px', fontWeight: '800', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '10px' }}>Description</h4>
                <p style={{ color: 'var(--text)', lineHeight: '1.8', fontSize: '14px' }}>{result.desc}</p>
              </div>

              {/* Meta grid */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '12px' }}>
                {[
                  { label: 'Published', value: result.published },
                  { label: 'Last Modified', value: result.modified },
                  { label: 'CVSS Vector', value: result.vector || 'N/A' },
                  ...(result.weaknesses.length ? [{ label: 'CWE', value: result.weaknesses.slice(0, 2).join(', ') }] : []),
                ].map(m => (
                  <div key={m.label} style={{ padding: '12px 16px', background: 'var(--bg2)', borderRadius: '10px', border: '1px solid var(--border)' }}>
                    <p style={{ fontSize: '10px', fontWeight: '800', color: 'var(--text-lighter)', textTransform: 'uppercase', marginBottom: '4px' }}>{m.label}</p>
                    <code style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '12px', color: 'var(--primary)', wordBreak: 'break-all' }}>{m.value}</code>
                  </div>
                ))}
              </div>

              {/* References */}
              {result.references.length > 0 && (
                <div>
                  <h4 style={{ color: 'var(--primary)', fontSize: '12px', fontWeight: '800', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '10px' }}>References</h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    {result.references.map((ref, i) => (
                      <motion.a key={i} href={ref.url} target="_blank" rel="noopener noreferrer" whileHover={{ x: 4 }}
                        style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--secondary)', fontSize: '13px', wordBreak: 'break-all', textDecoration: 'none' }}>
                        <FaExternalLinkAlt style={{ flexShrink: 0, fontSize: '11px' }} />
                        {ref.url}
                      </motion.a>
                    ))}
                  </div>
                </div>
              )}

              {/* NVD link */}
              <a href={`https://nvd.nist.gov/vuln/detail/${result.id}`} target="_blank" rel="noopener noreferrer"
                style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: 'var(--primary)', fontSize: '13px', fontWeight: '700', textDecoration: 'none' }}>
                <FaExternalLinkAlt /> View full entry on NVD
              </a>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {!result && !loading && !error && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} style={{ textAlign: 'center', padding: '60px 20px', opacity: 0.4 }}>
          <FaShieldAlt style={{ fontSize: '48px', color: 'var(--primary)', marginBottom: '12px' }} />
          <p>Enter a CVE ID to look it up in the NVD database</p>
          <p style={{ fontSize: '12px', marginTop: '8px' }}>Uses the official NIST NVD API — no key required</p>
        </motion.div>
      )}
        </div>{/* end left column */}

        {/* Right: CVSS Guide */}
        <div style={{ position: 'sticky', top: '80px' }}>
          <div style={{
            background: 'var(--card-bg)',
            borderRadius: '16px',
            border: '1px solid var(--glass-border)',
            overflow: 'hidden',
          }}>
            <div style={{
              padding: '14px 18px',
              background: 'var(--gradient-primary)',
              display: 'flex', alignItems: 'center', gap: '8px',
            }}>
              <FaShieldAlt style={{ color: 'white', fontSize: '14px' }} />
              <h4 style={{ color: 'white', fontSize: '13px', fontWeight: '800', margin: 0 }}>CVSS Score Guide</h4>
            </div>
            <div style={{ padding: '14px' }}>
              {[
                { range: '9.0 – 10.0', label: 'Critical', color: '#f87171', note: 'Wormable, unauthenticated RCE, domain compromise' },
                { range: '7.0 – 8.9', label: 'High', color: '#fb923c', note: 'Significant impact, likely exploited in the wild' },
                { range: '4.0 – 6.9', label: 'Medium', color: '#fbbf24', note: 'Requires interaction or auth, but still dangerous' },
                { range: '0.1 – 3.9', label: 'Low', color: '#34d399', note: 'Limited impact, edge-case conditions required' },
                { range: '0.0', label: 'None', color: '#64748b', note: 'No security impact' },
              ].map(s => (
                <div key={s.label} style={{ display: 'flex', gap: '10px', padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
                  <div style={{
                    minWidth: '60px', height: '24px',
                    background: s.color + '25', color: s.color,
                    borderRadius: '6px', display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: '10px', fontWeight: '800', border: `1px solid ${s.color}44`,
                  }}>{s.label}</div>
                  <div>
                    <div style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text)', fontFamily: "'JetBrains Mono', monospace" }}>{s.range}</div>
                    <div style={{ fontSize: '10px', color: 'var(--text-lighter)', lineHeight: '1.4' }}>{s.note}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Quick tips */}
          <div style={{
            marginTop: '14px',
            background: 'var(--card-bg)',
            borderRadius: '16px',
            border: '1px solid var(--glass-border)',
            padding: '16px',
          }}>
            <h4 style={{ fontSize: '12px', fontWeight: '800', color: 'var(--primary)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '12px' }}>
              🎯 Attacker's POV
            </h4>
            {[
              { tip: 'Network vector + no auth = highest priority target' },
              { tip: 'Score ≥ 9.0 = patch within 24–48h, no exceptions' },
              { tip: 'Check NVD for public PoC references in the links' },
              { tip: 'Correlate CVSS with your asset criticality' },
              { tip: 'CVSS 7.x on internet-facing service = critical in context' },
            ].map((t, i) => (
              <div key={i} style={{ display: 'flex', gap: '8px', marginBottom: '8px', alignItems: 'flex-start' }}>
                <span style={{ color: 'var(--primary)', fontSize: '12px', flexShrink: 0, marginTop: '1px' }}>▸</span>
                <p style={{ fontSize: '11px', color: 'var(--text-light)', lineHeight: '1.5', margin: 0 }}>{t.tip}</p>
              </div>
            ))}
          </div>
        </div>{/* end right column */}
      </div>{/* end two-column grid */}
    </div>
  );
};

export default CVELookup;

