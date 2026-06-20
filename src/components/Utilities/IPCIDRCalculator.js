import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FaNetworkWired, FaCopy } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { copyToClipboard } from '../../utils/copyToClipboard';

function cidrCalc(cidr) {
  const [ip, prefix] = cidr.trim().split('/');
  const p = parseInt(prefix, 10);
  if (isNaN(p) || p < 0 || p > 32) throw new Error('Invalid prefix length');
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(x => isNaN(x) || x < 0 || x > 255)) throw new Error('Invalid IP address');
  const ipInt = parts.reduce((acc, b) => (acc << 8) | b, 0) >>> 0;
  const mask = p === 0 ? 0 : (~0 << (32 - p)) >>> 0;
  const network = (ipInt & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  const firstHost = p >= 31 ? network : (network + 1) >>> 0;
  const lastHost = p >= 31 ? broadcast : (broadcast - 1) >>> 0;
  const hosts = p >= 31 ? Math.pow(2, 32 - p) : Math.pow(2, 32 - p) - 2;
  const toIP = n => [(n>>>24)&255,(n>>>16)&255,(n>>>8)&255,n&255].join('.');
  const toWildcard = m => [(~m>>>24)&255,(~m>>>16)&255,(~m>>>8)&255,(~m)&255].join('.');
  const cls = p <= 8 ? 'A' : p <= 16 ? 'B' : p <= 24 ? 'C' : 'Classless';
  return { network: toIP(network), broadcast: toIP(broadcast), mask: toIP(mask), wildcard: toWildcard(mask), firstHost: toIP(firstHost), lastHost: toIP(lastHost), hosts: hosts.toLocaleString(), prefix: p, ipClass: cls, inputIP: ip };
}

const Row = ({ label, value, accent }) => (
  <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', padding:'10px 0', borderBottom:'1px solid var(--border)' }}>
    <span style={{ fontSize:12, color:'var(--text-lighter)', fontWeight:600 }}>{label}</span>
    <div style={{ display:'flex', alignItems:'center', gap:8 }}>
      <code style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:13, color: accent || 'var(--text)', fontWeight: accent ? 700 : 400 }}>{value}</code>
      <motion.button onClick={() => { copyToClipboard(value); toast.success('Copied!',{position:'bottom-right',autoClose:1000,hideProgressBar:true}); }}
        whileHover={{scale:1.15}} whileTap={{scale:0.9}}
        style={{background:'transparent',border:'none',cursor:'pointer',color:'var(--text-lighter)',fontSize:12,padding:'2px 4px'}}>
        <FaCopy />
      </motion.button>
    </div>
  </div>
);

const IPCIDRCalculator = () => {
  const [input, setInput] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const calc = (val) => {
    const v = (val ?? input).trim();
    setError(''); setResult(null);
    if (!v) return;
    if (!v.includes('/')) { setError('Use CIDR notation: e.g. 192.168.1.0/24'); return; }
    try { setResult(cidrCalc(v)); } catch (e) { setError(e.message); }
  };

  const examples = ['192.168.1.0/24','10.0.0.0/8','172.16.0.0/12','203.0.113.0/30'];

  return (
    <div>
      <div style={{ display:'flex', gap:10, marginBottom:12 }}>
        <input value={input} onChange={e => { setInput(e.target.value); calc(e.target.value); }}
          placeholder="192.168.1.0/24"
          style={{ flex:1, padding:'12px 14px', borderRadius:10, border:'1.5px solid var(--border-strong)', background:'var(--bg2)', color:'var(--text)', fontFamily:"'JetBrains Mono',monospace", fontSize:14, outline:'none' }}
          onFocus={e=>e.target.style.borderColor='var(--primary)'}
          onBlur={e=>e.target.style.borderColor='var(--border-strong)'}
          onKeyDown={e=>{ if(e.key==='Enter') calc(); }}
        />
      </div>
      <div style={{ display:'flex', gap:8, flexWrap:'wrap', marginBottom:16 }}>
        {examples.map(ex => (
          <motion.button key={ex} onClick={() => { setInput(ex); calc(ex); }}
            whileHover={{scale:1.04}} whileTap={{scale:0.96}}
            style={{ padding:'5px 11px', borderRadius:20, fontSize:11, fontWeight:700, border:'1px solid var(--border-strong)', background:'var(--card-bg)', color:'var(--primary)', cursor:'pointer', fontFamily:"'JetBrains Mono',monospace" }}>
            {ex}
          </motion.button>
        ))}
      </div>
      {error && <div style={{ padding:'10px 14px', borderRadius:10, background:'rgba(239,68,68,0.1)', border:'1px solid rgba(239,68,68,0.3)', color:'#f87171', fontSize:13, marginBottom:12 }}>{error}</div>}
      <AnimatePresence>
        {result && (
          <motion.div initial={{opacity:0,y:10}} animate={{opacity:1,y:0}} exit={{opacity:0}}
            style={{ background:'var(--bg2)', borderRadius:14, border:'1.5px solid var(--border-strong)', padding:'0 16px' }}>
            <div style={{ padding:'14px 0 10px', borderBottom:'2px solid var(--border)', display:'flex', alignItems:'center', gap:10 }}>
              <FaNetworkWired style={{ color:'var(--primary)', fontSize:18 }} />
              <span style={{ fontFamily:"'JetBrains Mono',monospace", fontWeight:800, fontSize:16, color:'var(--text)' }}>{result.inputIP}/{result.prefix}</span>
              <span style={{ marginLeft:'auto', fontSize:11, fontWeight:700, padding:'3px 10px', borderRadius:20, background:'rgba(124,58,237,0.15)', color:'var(--primary)' }}>Class {result.ipClass}</span>
            </div>
            <Row label="Network Address" value={result.network} accent="var(--primary)" />
            <Row label="Subnet Mask" value={result.mask} />
            <Row label="Wildcard Mask" value={result.wildcard} />
            <Row label="Broadcast Address" value={result.broadcast} accent="var(--danger)" />
            <Row label="First Host" value={result.firstHost} accent="var(--success)" />
            <Row label="Last Host" value={result.lastHost} accent="var(--success)" />
            <Row label="Usable Hosts" value={result.hosts} accent="var(--accent)" />
          </motion.div>
        )}
        {!input && (
          <motion.p initial={{opacity:0}} animate={{opacity:1}} style={{ textAlign:'center', color:'var(--text-lighter)', fontSize:13, padding:'20px 0' }}>
            Enter a CIDR block (e.g. 192.168.1.0/24) to calculate
          </motion.p>
        )}
      </AnimatePresence>
    </div>
  );
};

export default IPCIDRCalculator;
