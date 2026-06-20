import { useState, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FaCopy, FaCheck, FaHashtag } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { copyToClipboard } from '../../utils/copyToClipboard';

const ALGOS = ['SHA-1', 'SHA-256', 'SHA-512'];

async function sha(algo, text) {
  const buf = await crypto.subtle.digest(algo, new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Simple MD5 (pure JS — no Web Crypto support)
function md5(str) {
  function safeAdd(x, y) { const lsw = (x & 0xffff) + (y & 0xffff); return (((x >> 16) + (y >> 16) + (lsw >> 16)) << 16) | (lsw & 0xffff); }
  function bitRotateLeft(num, cnt) { return (num << cnt) | (num >>> (32 - cnt)); }
  function md5cmn(q, a, b, x, s, t) { return safeAdd(bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b); }
  function md5ff(a,b,c,d,x,s,t){return md5cmn((b&c)|((~b)&d),a,b,x,s,t);}
  function md5gg(a,b,c,d,x,s,t){return md5cmn((b&d)|(c&(~d)),a,b,x,s,t);}
  function md5hh(a,b,c,d,x,s,t){return md5cmn(b^c^d,a,b,x,s,t);}
  function md5ii(a,b,c,d,x,s,t){return md5cmn(c^(b|(~d)),a,b,x,s,t);}
  const strToUtf8Bytes = s => { const bytes = []; for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); if (c < 128) bytes.push(c); else if (c < 2048) bytes.push((c>>6)|192,(c&63)|128); else bytes.push((c>>12)|224,((c>>6)&63)|128,(c&63)|128); } return bytes; };
  const bytes = strToUtf8Bytes(str);
  const words = [];
  for (let i = 0; i < bytes.length; i++) words[i >> 2] |= bytes[i] << ((i % 4) * 8);
  const l = bytes.length;
  words[l >> 2] |= 0x80 << ((l % 4) * 8);
  words[(((l + 8) >> 6) + 1) * 16 - 2] = l * 8;
  let a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;
  for (let i = 0; i < words.length; i += 16) {
    const [aa,bb,cc,dd]=[a,b,c,d];
    a=md5ff(a,b,c,d,words[i],7,-680876936);d=md5ff(d,a,b,c,words[i+1],12,-389564586);c=md5ff(c,d,a,b,words[i+2],17,606105819);b=md5ff(b,c,d,a,words[i+3],22,-1044525330);
    a=md5ff(a,b,c,d,words[i+4],7,-176418897);d=md5ff(d,a,b,c,words[i+5],12,1200080426);c=md5ff(c,d,a,b,words[i+6],17,-1473231341);b=md5ff(b,c,d,a,words[i+7],22,-45705983);
    a=md5ff(a,b,c,d,words[i+8],7,1770035416);d=md5ff(d,a,b,c,words[i+9],12,-1958414417);c=md5ff(c,d,a,b,words[i+10],17,-42063);b=md5ff(b,c,d,a,words[i+11],22,-1990404162);
    a=md5ff(a,b,c,d,words[i+12],7,1804603682);d=md5ff(d,a,b,c,words[i+13],12,-40341101);c=md5ff(c,d,a,b,words[i+14],17,-1502002290);b=md5ff(b,c,d,a,words[i+15],22,1236535329);
    a=md5gg(a,b,c,d,words[i+1],5,-165796510);d=md5gg(d,a,b,c,words[i+6],9,-1069501632);c=md5gg(c,d,a,b,words[i+11],14,643717713);b=md5gg(b,c,d,a,words[i],20,-373897302);
    a=md5gg(a,b,c,d,words[i+5],5,-701558691);d=md5gg(d,a,b,c,words[i+10],9,38016083);c=md5gg(c,d,a,b,words[i+15],14,-660478335);b=md5gg(b,c,d,a,words[i+4],20,-405537848);
    a=md5gg(a,b,c,d,words[i+9],5,568446438);d=md5gg(d,a,b,c,words[i+14],9,-1019803690);c=md5gg(c,d,a,b,words[i+3],14,-187363961);b=md5gg(b,c,d,a,words[i+8],20,1163531501);
    a=md5gg(a,b,c,d,words[i+13],5,-1444681467);d=md5gg(d,a,b,c,words[i+2],9,-51403784);c=md5gg(c,d,a,b,words[i+7],14,1735328473);b=md5gg(b,c,d,a,words[i+12],20,-1926607734);
    a=md5hh(a,b,c,d,words[i+5],4,-378558);d=md5hh(d,a,b,c,words[i+8],11,-2022574463);c=md5hh(c,d,a,b,words[i+11],16,1839030562);b=md5hh(b,c,d,a,words[i+14],23,-35309556);
    a=md5hh(a,b,c,d,words[i+1],4,-1530992060);d=md5hh(d,a,b,c,words[i+4],11,1272893353);c=md5hh(c,d,a,b,words[i+7],16,-155497632);b=md5hh(b,c,d,a,words[i+10],23,-1094730640);
    a=md5hh(a,b,c,d,words[i+13],4,681279174);d=md5hh(d,a,b,c,words[i],11,-358537222);c=md5hh(c,d,a,b,words[i+3],16,-722521979);b=md5hh(b,c,d,a,words[i+6],23,76029189);
    a=md5hh(a,b,c,d,words[i+9],4,-640364487);d=md5hh(d,a,b,c,words[i+12],11,-421815835);c=md5hh(c,d,a,b,words[i+15],16,530742520);b=md5hh(b,c,d,a,words[i+2],23,-995338651);
    a=md5ii(a,b,c,d,words[i],6,-198630844);d=md5ii(d,a,b,c,words[i+7],10,1126891415);c=md5ii(c,d,a,b,words[i+14],15,-1416354905);b=md5ii(b,c,d,a,words[i+5],21,-57434055);
    a=md5ii(a,b,c,d,words[i+12],6,1700485571);d=md5ii(d,a,b,c,words[i+3],10,-1894986606);c=md5ii(c,d,a,b,words[i+10],15,-1051523);b=md5ii(b,c,d,a,words[i+1],21,-2054922799);
    a=md5ii(a,b,c,d,words[i+8],6,1873313359);d=md5ii(d,a,b,c,words[i+15],10,-30611744);c=md5ii(c,d,a,b,words[i+6],15,-1560198380);b=md5ii(b,c,d,a,words[i+13],21,1309151649);
    a=md5ii(a,b,c,d,words[i+4],6,-145523070);d=md5ii(d,a,b,c,words[i+11],10,-1120210379);c=md5ii(c,d,a,b,words[i+2],15,718787259);b=md5ii(b,c,d,a,words[i+9],21,-343485551);
    a=safeAdd(a,aa);b=safeAdd(b,bb);c=safeAdd(c,cc);d=safeAdd(d,dd);
  }
  return [a,b,c,d].map(n => Array.from({length:4},(_,i)=>((n>>(i*8))&0xff).toString(16).padStart(2,'0')).join('')).join('');
}

const CopyBtn = ({ text }) => {
  const [copied, setCopied] = useState(false);
  const handle = () => { copyToClipboard(text); setCopied(true); toast.success('Hash copied!', { position:'bottom-right', autoClose:1200, hideProgressBar:true }); setTimeout(() => setCopied(false), 1800); };
  return (
    <motion.button onClick={handle} whileHover={{ scale: 1.1 }} whileTap={{ scale: 0.9 }}
      title="Copy hash" style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: copied ? 'var(--success)' : 'var(--text-lighter)', fontSize: 14, padding: '2px 6px' }}>
      {copied ? <FaCheck /> : <FaCopy />}
    </motion.button>
  );
};

const HashGenerator = () => {
  const [input, setInput] = useState('');
  const [hashes, setHashes] = useState(null);
  const [loading, setLoading] = useState(false);

  const generate = useCallback(async (val) => {
    const text = val ?? input;
    if (!text) { setHashes(null); return; }
    setLoading(true);
    const [s1, s256, s512] = await Promise.all(ALGOS.map(a => sha(a, text)));
    setHashes({ MD5: md5(text), 'SHA-1': s1, 'SHA-256': s256, 'SHA-512': s512 });
    setLoading(false);
  }, [input]);

  const handleChange = (e) => {
    setInput(e.target.value);
    generate(e.target.value);
  };

  const colors = { MD5: '#fbbf24', 'SHA-1': '#34d399', 'SHA-256': '#60a5fa', 'SHA-512': '#a78bfa' };

  return (
    <div>
      <div style={{ marginBottom: 16 }}>
        <label style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-lighter)', textTransform: 'uppercase', letterSpacing: '0.5px', display: 'block', marginBottom: 8 }}>
          Input Text
        </label>
        <textarea
          value={input}
          onChange={handleChange}
          placeholder="Enter text to hash..."
          rows={3}
          style={{ width: '100%', padding: '12px 14px', borderRadius: 10, border: '1.5px solid var(--border-strong)', background: 'var(--bg2)', color: 'var(--text)', fontFamily: "'JetBrains Mono', monospace", fontSize: 13, resize: 'vertical', outline: 'none', boxSizing: 'border-box' }}
          onFocus={e => e.target.style.borderColor = 'var(--primary)'}
          onBlur={e => e.target.style.borderColor = 'var(--border-strong)'}
        />
      </div>

      <AnimatePresence>
        {hashes && !loading && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {Object.entries(hashes).map(([algo, hash]) => (
              <div key={algo} style={{ background: 'var(--bg2)', borderRadius: 10, border: `1.5px solid ${colors[algo]}33`, padding: '12px 14px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                  <span style={{ fontSize: 11, fontWeight: 800, color: colors[algo], textTransform: 'uppercase', letterSpacing: '0.5px', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <FaHashtag style={{ fontSize: 9 }} /> {algo}
                  </span>
                  <CopyBtn text={hash} />
                </div>
                <code style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: 'var(--text)', wordBreak: 'break-all', lineHeight: 1.6 }}>{hash}</code>
              </div>
            ))}
          </motion.div>
        )}
        {!input && (
          <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} style={{ textAlign: 'center', color: 'var(--text-lighter)', fontSize: 13, padding: '20px 0' }}>
            Type something above to generate hashes instantly
          </motion.p>
        )}
      </AnimatePresence>
    </div>
  );
};

export default HashGenerator;
