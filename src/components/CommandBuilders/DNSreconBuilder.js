import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaSearch, FaCopy, FaCheck } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { copyToClipboard } from '../../utils/copyToClipboard';
import { useCommandHistory } from '../../contexts/CommandHistoryContext';

const DNSreconBuilder = () => {
  const { addCommand } = useCommandHistory();
  const [domain, setDomain] = useState('');
  const [scanType, setScanType] = useState('std');
  const [nameserver, setNameserver] = useState('');
  const [outputFile, setOutputFile] = useState('');
  const [threads, setThreads] = useState('');
  const [wordlist, setWordlist] = useState('');
  const [copied, setCopied] = useState(false);

  const scanTypes = [
    { value: 'std', label: 'Standard', desc: 'SOA, NS, A, AAAA, MX, SRV, TXT records' },
    { value: 'rvs', label: 'Reverse', desc: 'Reverse lookup on IP/range' },
    { value: 'brt', label: 'Brute Force', desc: 'Subdomain brute-force with wordlist' },
    { value: 'axfr', label: 'Zone Transfer', desc: 'Attempt DNS zone transfer (AXFR)' },
    { value: 'goo', label: 'Google Enum', desc: 'Google dorking for subdomains' },
    { value: 'zonewalk', label: 'NSEC Walk', desc: 'DNSSEC zone enumeration (NSEC walk)' },
    { value: 'snoop', label: 'Cache Snoop', desc: 'Check for DNS cache snooping' },
  ];

  const buildCommand = () => {
    if (!domain) return 'dnsrecon -d <target-domain>';
    let cmd = `dnsrecon -d ${domain} -t ${scanType}`;
    if (nameserver) cmd += ` -n ${nameserver}`;
    if (threads) cmd += ` --threads ${threads}`;
    if (scanType === 'brt' && wordlist) cmd += ` -D ${wordlist}`;
    if (outputFile) cmd += ` -x ${outputFile}.xml --csv ${outputFile}.csv`;
    return cmd;
  };

  const command = buildCommand();

  const handleCopy = () => {
    copyToClipboard(command);
    addCommand(command);
    setCopied(true);
    toast.success('Command copied & saved!', { position:'bottom-right', autoClose:1500, hideProgressBar:true });
    setTimeout(() => setCopied(false), 2000);
  };

  const inputStyle = { width:'100%', padding:'10px 12px', borderRadius:8, border:'1px solid var(--border)', background:'var(--bg2)', color:'var(--text)', fontSize:13, outline:'none', boxSizing:'border-box', fontFamily:"'JetBrains Mono',monospace" };
  const labelStyle = { fontSize:12, fontWeight:600, color:'var(--text-lighter)', marginBottom:4, display:'block' };

  return (
    <div>
      <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:20 }}>
        <FaSearch style={{ color:'var(--primary)', fontSize:22 }} />
        <div>
          <h3 style={{ margin:0, color:'var(--text)' }}>DNSrecon Command Builder</h3>
          <p style={{ margin:0, fontSize:12, color:'var(--text-lighter)' }}>DNS enumeration — zone transfers, brute force, reverse lookup and more</p>
        </div>
      </div>

      <div style={{ marginBottom:14 }}>
        <label style={labelStyle}>Target Domain</label>
        <input style={inputStyle} value={domain} onChange={e=>setDomain(e.target.value)} placeholder="target.com" />
      </div>

      <div style={{ marginBottom:16 }}>
        <label style={labelStyle}>Scan Type</label>
        <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(180px,1fr))', gap:8 }}>
          {scanTypes.map(t => (
            <motion.button key={t.value} onClick={() => setScanType(t.value)}
              whileHover={{scale:1.03}} whileTap={{scale:0.97}}
              style={{ padding:'10px 12px', borderRadius:10, border:`1.5px solid ${scanType===t.value ? 'var(--primary)' : 'var(--border)'}`, background: scanType===t.value ? 'rgba(124,58,237,0.12)' : 'var(--bg2)', color: scanType===t.value ? 'var(--primary)' : 'var(--text)', cursor:'pointer', textAlign:'left' }}>
              <div style={{ fontSize:12, fontWeight:700, marginBottom:3 }}>{t.label}</div>
              <div style={{ fontSize:10, color:'var(--text-lighter)', lineHeight:1.4 }}>{t.desc}</div>
            </motion.button>
          ))}
        </div>
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:14, marginBottom:14 }}>
        <div>
          <label style={labelStyle}>Custom Nameserver (optional)</label>
          <input style={inputStyle} value={nameserver} onChange={e=>setNameserver(e.target.value)} placeholder="8.8.8.8" />
        </div>
        <div>
          <label style={labelStyle}>Threads (optional)</label>
          <input style={inputStyle} value={threads} onChange={e=>setThreads(e.target.value)} type="number" placeholder="10" />
        </div>
        {scanType === 'brt' && (
          <div style={{ gridColumn:'1/-1' }}>
            <label style={labelStyle}>Wordlist path (for brute-force)</label>
            <input style={inputStyle} value={wordlist} onChange={e=>setWordlist(e.target.value)} placeholder="/usr/share/dnsrecon/namelist.txt" />
          </div>
        )}
        <div style={{ gridColumn:'1/-1' }}>
          <label style={labelStyle}>Output file base name (optional)</label>
          <input style={inputStyle} value={outputFile} onChange={e=>setOutputFile(e.target.value)} placeholder="dnsrecon_output" />
        </div>
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

      <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
        {[
          { label:'Zone Transfer check', cmd:'dnsrecon -d target.com -t axfr' },
          { label:'Subdomain brute-force', cmd:'dnsrecon -d target.com -t brt -D /usr/share/dnsrecon/namelist.txt' },
          { label:'Full standard enum', cmd:'dnsrecon -d target.com -t std --xml output.xml' },
        ].map(ex => (
          <motion.div key={ex.label} whileHover={{x:4}} onClick={() => { copyToClipboard(ex.cmd); toast.success('Example copied!',{position:'bottom-right',autoClose:1000,hideProgressBar:true}); }}
            style={{ padding:'8px 12px', borderRadius:8, border:'1px solid var(--border)', background:'var(--bg2)', cursor:'pointer', display:'flex', gap:10, alignItems:'center' }}>
            <span style={{ fontSize:10, fontWeight:700, color:'var(--primary)', flexShrink:0 }}>{ex.label}</span>
            <code style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:11, color:'var(--text-lighter)', wordBreak:'break-all' }}>{ex.cmd}</code>
          </motion.div>
        ))}
      </div>
    </div>
  );
};

export default DNSreconBuilder;
