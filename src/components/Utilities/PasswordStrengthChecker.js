import { useState } from 'react';
import { motion } from 'framer-motion';

const checks = [
  { label: 'Lowercase letters', regex: /[a-z]/, weight: 1 },
  { label: 'Uppercase letters', regex: /[A-Z]/, weight: 1 },
  { label: 'Numbers', regex: /[0-9]/, weight: 1 },
  { label: 'Special characters', regex: /[^A-Za-z0-9]/, weight: 2 },
  { label: '12+ characters', test: s => s.length >= 12, weight: 2 },
  { label: '16+ characters', test: s => s.length >= 16, weight: 1 },
];

function entropy(pw) {
  const charsets = [
    { r: /[a-z]/, size: 26 }, { r: /[A-Z]/, size: 26 },
    { r: /[0-9]/, size: 10 }, { r: /[^A-Za-z0-9]/, size: 32 },
  ];
  const pool = charsets.reduce((acc, c) => acc + (c.r.test(pw) ? c.size : 0), 0);
  return pw.length * Math.log2(pool || 1);
}

function crackTime(bits) {
  const guesses = Math.pow(2, bits) / 2;
  const rate = 1e10;
  const seconds = guesses / rate;
  if (seconds < 1) return 'Instant';
  if (seconds < 60) return `${Math.round(seconds)} seconds`;
  if (seconds < 3600) return `${Math.round(seconds/60)} minutes`;
  if (seconds < 86400) return `${Math.round(seconds/3600)} hours`;
  if (seconds < 31536000) return `${Math.round(seconds/86400)} days`;
  if (seconds < 3153600000) return `${Math.round(seconds/31536000)} years`;
  return 'Centuries+';
}

const PasswordStrengthChecker = () => {
  const [pw, setPw] = useState('');
  const [show, setShow] = useState(false);

  const score = checks.reduce((acc, c) => {
    const pass = c.test ? c.test(pw) : c.regex.test(pw);
    return acc + (pass ? c.weight : 0);
  }, 0);
  const maxScore = checks.reduce((acc, c) => acc + c.weight, 0);
  const pct = pw ? Math.round((score / maxScore) * 100) : 0;
  const bits = pw ? Math.round(entropy(pw)) : 0;
  const crack = pw ? crackTime(bits) : '—';

  const level = pct >= 85 ? { label: 'Strong', color: '#34d399' }
    : pct >= 60 ? { label: 'Good', color: '#60a5fa' }
    : pct >= 35 ? { label: 'Weak', color: '#fbbf24' }
    : { label: 'Very Weak', color: '#f87171' };

  return (
    <div>
      <div style={{ marginBottom:16 }}>
        <label style={{ fontSize:12, fontWeight:700, color:'var(--text-lighter)', textTransform:'uppercase', letterSpacing:'0.5px', display:'block', marginBottom:8 }}>Password</label>
        <div style={{ display:'flex', gap:10 }}>
          <input
            type={show ? 'text' : 'password'}
            value={pw} onChange={e => setPw(e.target.value)}
            placeholder="Enter a password to analyze..."
            style={{ flex:1, padding:'12px 14px', borderRadius:10, border:'1.5px solid var(--border-strong)', background:'var(--bg2)', color:'var(--text)', fontSize:15, outline:'none' }}
            onFocus={e=>e.target.style.borderColor='var(--primary)'}
            onBlur={e=>e.target.style.borderColor='var(--border-strong)'}
          />
          <motion.button onClick={() => setShow(s => !s)} whileHover={{scale:1.05}} whileTap={{scale:0.95}}
            style={{ padding:'12px 16px', borderRadius:10, border:'1.5px solid var(--border-strong)', background:'var(--card-bg)', color:'var(--text)', cursor:'pointer', fontSize:12, fontWeight:700 }}>
            {show ? 'Hide' : 'Show'}
          </motion.button>
        </div>
      </div>

      {pw && (
        <motion.div initial={{opacity:0,y:10}} animate={{opacity:1,y:0}}>
          {/* Strength bar */}
          <div style={{ marginBottom:20 }}>
            <div style={{ display:'flex', justifyContent:'space-between', marginBottom:8 }}>
              <span style={{ fontSize:13, fontWeight:700, color:level.color }}>{level.label}</span>
              <span style={{ fontSize:13, color:'var(--text-lighter)' }}>{pct}%</span>
            </div>
            <div style={{ height:8, borderRadius:99, background:'var(--bg2)', overflow:'hidden' }}>
              <motion.div animate={{ width:`${pct}%` }} transition={{ duration:0.5, ease:'easeOut' }}
                style={{ height:'100%', borderRadius:99, background:`linear-gradient(90deg, ${pct < 35 ? '#f87171' : pct < 60 ? '#fbbf24' : pct < 85 ? '#60a5fa' : '#34d399'}, ${level.color})` }} />
            </div>
          </div>

          {/* Stats row */}
          <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:10, marginBottom:20 }}>
            {[
              { label:'Length', val: pw.length },
              { label:'Entropy', val: `${bits} bits` },
              { label:'Crack Time', val: crack },
            ].map(s => (
              <div key={s.label} style={{ background:'var(--bg2)', borderRadius:10, padding:'12px', textAlign:'center', border:'1px solid var(--border)' }}>
                <div style={{ fontSize:18, fontWeight:800, color:'var(--primary)', marginBottom:4 }}>{s.val}</div>
                <div style={{ fontSize:11, color:'var(--text-lighter)', fontWeight:600 }}>{s.label}</div>
              </div>
            ))}
          </div>

          {/* Checklist */}
          <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
            {checks.map(c => {
              const pass = c.test ? c.test(pw) : c.regex.test(pw);
              return (
                <motion.div key={c.label} animate={{ opacity: pass ? 1 : 0.5 }}
                  style={{ display:'flex', alignItems:'center', gap:10 }}>
                  <div style={{ width:20, height:20, borderRadius:'50%', background: pass ? '#34d399' : 'var(--bg2)', border:`2px solid ${pass ? '#34d399' : 'var(--border-strong)'}`, display:'flex', alignItems:'center', justifyContent:'center', flexShrink:0, fontSize:10, color:'white', fontWeight:800 }}>
                    {pass ? '✓' : ''}
                  </div>
                  <span style={{ fontSize:13, color: pass ? 'var(--text)' : 'var(--text-lighter)' }}>{c.label}</span>
                  {c.weight > 1 && <span style={{ fontSize:10, color:'var(--primary)', fontWeight:700, marginLeft:'auto' }}>+{c.weight}pts</span>}
                </motion.div>
              );
            })}
          </div>
          <p style={{ fontSize:11, color:'var(--text-lighter)', marginTop:14, padding:'8px 12px', borderRadius:8, background:'rgba(251,191,36,0.06)', border:'1px solid rgba(251,191,36,0.15)' }}>
            ⚡ Crack time assumes 10 billion guesses/second (GPU-accelerated offline attack)
          </p>
        </motion.div>
      )}

      {!pw && (
        <motion.p initial={{opacity:0}} animate={{opacity:1}} style={{ textAlign:'center', color:'var(--text-lighter)', fontSize:13, padding:'20px 0' }}>
          Enter a password to analyze its strength and estimated crack time
        </motion.p>
      )}
    </div>
  );
};

export default PasswordStrengthChecker;
