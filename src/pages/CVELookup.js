import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FaSearch, FaShieldAlt, FaExclamationTriangle, FaExternalLinkAlt, FaCopy } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { copyToClipboard } from '../utils/copyToClipboard';
import GradientHeader from '../components/UI/GradientHeader';

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

  const examples = ['CVE-2021-44228', 'CVE-2017-0144', 'CVE-2019-0708', 'CVE-2020-1472', 'CVE-2021-4034'];

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
    <div style={{ padding: '0 20px 60px', maxWidth: '900px', margin: '0 auto' }}>
      <GradientHeader
        title="CVE Lookup"
        subtitle="Search the NVD database for CVE details — CVSS score, description, severity, and references"
        icon={<FaShieldAlt />}
      />

      {/* Examples */}
      <div style={{ margin: '20px 0 12px' }}>
        <p style={{ fontSize: '12px', color: 'var(--text-lighter)', marginBottom: '8px', fontWeight: '600' }}>FAMOUS CVEs:</p>
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          {examples.map(ex => (
            <motion.button key={ex} onClick={() => { setInput(ex); lookup(ex); }} whileHover={{ scale: 1.04 }} whileTap={{ scale: 0.96 }}
              style={{ padding: '5px 12px', borderRadius: '20px', fontSize: '12px', fontWeight: '700', border: '1px solid var(--border-strong)', background: 'transparent', color: 'var(--primary)', cursor: 'pointer', fontFamily: "'JetBrains Mono', monospace" }}>
              {ex}
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
        <motion.button onClick={() => lookup()} whileHover={{ scale: 1.04 }} whileTap={{ scale: 0.96 }}
          style={{ padding: '14px 24px', borderRadius: '12px', border: 'none', background: loading ? 'var(--border)' : 'var(--gradient-primary)', color: 'white', fontWeight: '700', fontSize: '14px', cursor: loading ? 'wait' : 'pointer', display: 'flex', alignItems: 'center', gap: '8px', minWidth: '120px', justifyContent: 'center' }}>
          {loading ? (
            <motion.div animate={{ rotate: 360 }} transition={{ duration: 1, repeat: Infinity, ease: 'linear' }} style={{ width: '18px', height: '18px', border: '2px solid white', borderTopColor: 'transparent', borderRadius: '50%' }} />
          ) : (
            <><FaSearch /> Lookup</>
          )}
        </motion.button>
      </div>

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
    </div>
  );
};

export default CVELookup;
