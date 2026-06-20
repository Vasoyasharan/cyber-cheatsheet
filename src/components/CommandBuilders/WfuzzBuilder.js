import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaBolt, FaCopy, FaCheck } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { copyToClipboard } from '../../utils/copyToClipboard';
import { useCommandHistory } from '../../contexts/CommandHistoryContext';

const WfuzzBuilder = () => {
  const { addCommand } = useCommandHistory();
  const [url, setUrl] = useState('http://target.com/FUZZ');
  const [wordlist, setWordlist] = useState('/usr/share/wordlists/dirb/common.txt');
  const [threads, setThreads] = useState('40');
  const [filterCode, setFilterCode] = useState('404');
  const [extensions, setExtensions] = useState('');
  const [timeout, setTimeoutVal] = useState('10');
  const [headers, setHeaders] = useState('');
  const [cookie, setCookie] = useState('');
  const [postData, setPostData] = useState('');
  const [followRedirects, setFollowRedirects] = useState(false);
  const [hideChars, setHideChars] = useState('');
  const [hideLines, setHideLines] = useState('');
  const [hideWords, setHideWords] = useState('');
  const [copied, setCopied] = useState(false);

  const buildCommand = () => {
    let cmd = `wfuzz -c`;
    if (threads) cmd += ` -t ${threads}`;
    if (timeout) cmd += ` --conn-delay ${timeout}`;
    if (filterCode) cmd += ` --hc ${filterCode}`;
    if (hideChars) cmd += ` --hh ${hideChars}`;
    if (hideLines) cmd += ` --hl ${hideLines}`;
    if (hideWords) cmd += ` --hw ${hideWords}`;
    if (cookie) cmd += ` -b "${cookie}"`;
    if (headers) headers.split('\n').filter(Boolean).forEach(h => { cmd += ` -H "${h.trim()}"`; });
    if (postData) cmd += ` -d "${postData}"`;
    if (followRedirects) cmd += ` -L`;
    if (extensions) { const exts = extensions.split(',').map(e => e.trim()).join(','); cmd += ` -z list,${exts}`; }
    cmd += ` -w ${wordlist}`;
    cmd += ` "${url}"`;
    return cmd;
  };

  const command = buildCommand();

  const handleCopy = () => {
    copyToClipboard(command);
    addCommand(command);
    setCopied(true);
    toast.success('Command copied & saved to history!', { position: 'bottom-right', autoClose: 1500, hideProgressBar: true });
    setTimeout(() => setCopied(false), 2000);
  };

  const inputStyle = { width:'100%', padding:'10px 12px', borderRadius:8, border:'1px solid var(--border)', background:'var(--bg2)', color:'var(--text)', fontSize:13, outline:'none', boxSizing:'border-box', fontFamily:"'JetBrains Mono',monospace" };
  const labelStyle = { fontSize:12, fontWeight:600, color:'var(--text-lighter)', marginBottom:4, display:'block' };
  const groupStyle = { marginBottom:14 };

  return (
    <div>
      <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:20 }}>
        <FaBolt style={{ color:'var(--primary)', fontSize:22 }} />
        <div>
          <h3 style={{ margin:0, color:'var(--text)' }}>Wfuzz Command Builder</h3>
          <p style={{ margin:0, fontSize:12, color:'var(--text-lighter)' }}>Web application fuzzer — great for hidden dirs, params, auth bypass</p>
        </div>
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:14, marginBottom:14 }}>
        <div style={groupStyle}>
          <label style={labelStyle}>Target URL (use FUZZ keyword)</label>
          <input style={inputStyle} value={url} onChange={e=>setUrl(e.target.value)} placeholder="http://target.com/FUZZ" />
        </div>
        <div style={groupStyle}>
          <label style={labelStyle}>Wordlist Path</label>
          <input style={inputStyle} value={wordlist} onChange={e=>setWordlist(e.target.value)} />
        </div>
        <div style={groupStyle}>
          <label style={labelStyle}>Threads</label>
          <input style={inputStyle} value={threads} onChange={e=>setThreads(e.target.value)} type="number" min="1" max="200" />
        </div>
        <div style={groupStyle}>
          <label style={labelStyle}>Connection Timeout (s)</label>
          <input style={inputStyle} value={timeout} onChange={e=>setTimeoutVal(e.target.value)} type="number" min="1" placeholder="10" />
        </div>
        <div style={groupStyle}>
          <label style={labelStyle}>Hide HTTP codes (--hc, comma-sep)</label>
          <input style={inputStyle} value={filterCode} onChange={e=>setFilterCode(e.target.value)} placeholder="404,403" />
        </div>
        <div style={groupStyle}>
          <label style={labelStyle}>Hide by chars (--hh)</label>
          <input style={inputStyle} value={hideChars} onChange={e=>setHideChars(e.target.value)} placeholder="0" />
        </div>
        <div style={groupStyle}>
          <label style={labelStyle}>Hide by lines (--hl)</label>
          <input style={inputStyle} value={hideLines} onChange={e=>setHideLines(e.target.value)} placeholder="0" />
        </div>
        <div style={groupStyle}>
          <label style={labelStyle}>Cookie (-b)</label>
          <input style={inputStyle} value={cookie} onChange={e=>setCookie(e.target.value)} placeholder="session=abc123" />
        </div>
        <div style={groupStyle}>
          <label style={labelStyle}>POST data (-d)</label>
          <input style={inputStyle} value={postData} onChange={e=>setPostData(e.target.value)} placeholder="user=FUZZ&pass=test" />
        </div>
      </div>

      <div style={groupStyle}>
        <label style={labelStyle}>Extra Headers (one per line)</label>
        <textarea style={{...inputStyle, resize:'vertical'}} rows={2} value={headers} onChange={e=>setHeaders(e.target.value)} placeholder="Authorization: Bearer token123" />
      </div>

      <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:16 }}>
        <input type="checkbox" id="wfuzz-redir" checked={followRedirects} onChange={e=>setFollowRedirects(e.target.checked)} />
        <label htmlFor="wfuzz-redir" style={{ fontSize:13, color:'var(--text)', cursor:'pointer' }}>Follow redirects (-L)</label>
      </div>

      {/* Command preview */}
      <div style={{ background:'var(--code-bg)', borderRadius:12, padding:'14px 16px', marginBottom:12, border:'1px solid var(--border)' }}>
        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:8 }}>
          <span style={{ fontSize:11, fontWeight:700, color:'#a78bfa', textTransform:'uppercase' }}>Generated Command</span>
          <motion.button onClick={handleCopy} whileHover={{scale:1.05}} whileTap={{scale:0.95}}
            style={{ padding:'6px 14px', borderRadius:8, border:'none', background: copied ? '#34d399' : 'var(--primary)', color:'white', cursor:'pointer', fontSize:12, fontWeight:700, display:'flex', alignItems:'center', gap:6 }}>
            {copied ? <><FaCheck /> Copied!</> : <><FaCopy /> Copy</>}
          </motion.button>
        </div>
        <code style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:12, color:'#e2e8f0', wordBreak:'break-all', lineHeight:'1.7' }}>{command}</code>
      </div>

      <div style={{ padding:'10px 14px', borderRadius:10, background:'rgba(251,191,36,0.08)', border:'1px solid rgba(251,191,36,0.2)', fontSize:12, color:'var(--text-lighter)' }}>
        💡 <strong>Tip:</strong> Use <code style={{color:'#fbbf24'}}>FUZ2Z</code> for a second wordlist, or <code style={{color:'#fbbf24'}}>-z range,1-100</code> to fuzz numeric IDs.
      </div>
    </div>
  );
};

export default WfuzzBuilder;
