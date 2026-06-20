import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FaCopy, FaExclamationTriangle } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { copyToClipboard } from '../../utils/copyToClipboard';

const b64url = str => {
  try {
    return JSON.parse(atob(str.replace(/-/g,'+').replace(/_/,'/')));
  } catch {
    return null;
  }
};

const Field = ({ label, val }) => (
  <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', padding:'8px 0', borderBottom:'1px solid var(--border)', gap:12 }}>
    <span style={{ fontSize:11, color:'var(--text-lighter)', fontWeight:700, textTransform:'uppercase', whiteSpace:'nowrap', flexShrink:0, marginTop:1 }}>{label}</span>
    <code style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:12, color:'var(--primary)', wordBreak:'break-all', textAlign:'right' }}>{String(val)}</code>
  </div>
);

const Section = ({ title, data, color }) => (
  <div style={{ background:'var(--bg2)', borderRadius:12, border:`1.5px solid ${color}33`, overflow:'hidden', marginBottom:12 }}>
    <div style={{ padding:'10px 14px', background:`${color}18`, borderBottom:`1px solid ${color}33` }}>
      <span style={{ fontSize:11, fontWeight:800, color, textTransform:'uppercase', letterSpacing:'0.5px' }}>{title}</span>
    </div>
    <div style={{ padding:'0 14px' }}>
      {Object.entries(data).map(([k,v]) => <Field key={k} label={k} val={v} />)}
    </div>
  </div>
);

const JWTDecoder = () => {
  const [input, setInput] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const decode = (val) => {
    const token = (val ?? input).trim();
    setError(''); setResult(null);
    if (!token) return;
    const parts = token.split('.');
    if (parts.length < 2) { setError('Not a valid JWT — expected header.payload.signature'); return; }
    const header = b64url(parts[0]);
    const payload = b64url(parts[1]);
    if (!header || !payload) { setError('Failed to decode JWT parts — ensure it is a valid Base64URL JWT.'); return; }

    const now = Math.floor(Date.now() / 1000);
    const expiry = payload.exp;
    const isExpired = expiry ? expiry < now : null;
    const expiryStr = expiry ? `${new Date(expiry * 1000).toLocaleString()} ${isExpired ? '⚠️ EXPIRED' : '✅ Valid'}` : 'No expiry set';

    const headerDisplay = { ...header };
    const payloadDisplay = {};
    for (const [k,v] of Object.entries(payload)) {
      if (k === 'exp' || k === 'iat' || k === 'nbf') {
        payloadDisplay[k] = `${v} (${new Date(v*1000).toLocaleString()})`;
      } else {
        payloadDisplay[k] = typeof v === 'object' ? JSON.stringify(v) : v;
      }
    }

    setResult({ header: headerDisplay, payload: payloadDisplay, signature: parts[2] || 'N/A', isExpired, expiryStr });
  };

  const example = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

  return (
    <div>
      <div style={{ marginBottom:12 }}>
        <label style={{ fontSize:12, fontWeight:700, color:'var(--text-lighter)', textTransform:'uppercase', letterSpacing:'0.5px', display:'block', marginBottom:8 }}>JWT Token</label>
        <textarea value={input} onChange={e => { setInput(e.target.value); decode(e.target.value); }}
          placeholder="Paste your JWT here (eyJ...)"
          rows={4}
          style={{ width:'100%', padding:'12px 14px', borderRadius:10, border:'1.5px solid var(--border-strong)', background:'var(--bg2)', color:'var(--text)', fontFamily:"'JetBrains Mono',monospace", fontSize:12, resize:'vertical', outline:'none', boxSizing:'border-box', wordBreak:'break-all' }}
          onFocus={e=>e.target.style.borderColor='var(--primary)'}
          onBlur={e=>e.target.style.borderColor='var(--border-strong)'}
        />
      </div>
      <motion.button onClick={() => { setInput(example); decode(example); }}
        whileHover={{scale:1.04}} whileTap={{scale:0.96}}
        style={{ padding:'6px 14px', borderRadius:20, fontSize:11, fontWeight:700, border:'1px solid var(--border-strong)', background:'var(--card-bg)', color:'var(--primary)', cursor:'pointer', marginBottom:16 }}>
        Load Example JWT
      </motion.button>

      {error && (
        <div style={{ padding:'10px 14px', borderRadius:10, background:'rgba(239,68,68,0.1)', border:'1px solid rgba(239,68,68,0.3)', color:'#f87171', fontSize:13, marginBottom:12, display:'flex', alignItems:'center', gap:8 }}>
          <FaExclamationTriangle /> {error}
        </div>
      )}

      <AnimatePresence>
        {result && (
          <motion.div initial={{opacity:0,y:10}} animate={{opacity:1,y:0}} exit={{opacity:0}}>
            {result.isExpired === true && (
              <div style={{ padding:'10px 14px', borderRadius:10, background:'rgba(251,191,36,0.12)', border:'1px solid rgba(251,191,36,0.4)', color:'#fbbf24', fontSize:13, marginBottom:12, fontWeight:700 }}>
                ⚠️ This token is EXPIRED — {result.expiryStr}
              </div>
            )}
            <Section title="Header (Algorithm & Type)" data={result.header} color="#60a5fa" />
            <Section title="Payload (Claims)" data={result.payload} color="#a78bfa" />
            <div style={{ background:'var(--bg2)', borderRadius:12, border:'1.5px solid rgba(100,116,139,0.3)', padding:'12px 14px' }}>
              <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:8 }}>
                <span style={{ fontSize:11, fontWeight:800, color:'var(--text-lighter)', textTransform:'uppercase', letterSpacing:'0.5px' }}>Signature</span>
                <motion.button onClick={() => { copyToClipboard(result.signature); toast.success('Signature copied!',{position:'bottom-right',autoClose:1200,hideProgressBar:true}); }}
                  whileHover={{scale:1.1}} whileTap={{scale:0.9}}
                  style={{background:'transparent',border:'none',cursor:'pointer',color:'var(--text-lighter)',fontSize:13}}>
                  <FaCopy />
                </motion.button>
              </div>
              <code style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:11, color:'var(--text-lighter)', wordBreak:'break-all' }}>{result.signature}</code>
            </div>
            <p style={{ fontSize:11, color:'var(--text-lighter)', marginTop:10, padding:'8px 12px', borderRadius:8, background:'rgba(251,191,36,0.08)', border:'1px solid rgba(251,191,36,0.2)' }}>
              ⚠️ JWT signatures are NOT verified here — this tool only decodes. Never trust a JWT without server-side verification.
            </p>
          </motion.div>
        )}
        {!input && (
          <motion.p initial={{opacity:0}} animate={{opacity:1}} style={{ textAlign:'center', color:'var(--text-lighter)', fontSize:13, padding:'20px 0' }}>
            Paste a JWT token to decode its header and payload
          </motion.p>
        )}
      </AnimatePresence>
    </div>
  );
};

export default JWTDecoder;
