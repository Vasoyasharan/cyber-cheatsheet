import { useState, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FaMagic, FaCopy, FaInfoCircle, FaSearch, FaChevronDown } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { copyToClipboard } from '../utils/copyToClipboard';
import GradientHeader from '../components/UI/GradientHeader';

/* ── Flag Dictionaries ──────────────────────── */
const FLAG_DB = {
  nmap: {
    '-sS': 'Stealth SYN scan — sends SYN, does not complete the 3-way handshake (half-open). Harder to detect.',
    '-sT': 'Full TCP connect scan — completes the 3-way handshake. Logged by the OS.',
    '-sU': 'UDP scan — slower, scans UDP ports for services like DNS (53), SNMP (161).',
    '-sV': 'Service/Version detection — probes open ports to identify what software is running.',
    '-sC': 'Default NSE scripts — runs a collection of safe discovery scripts.',
    '-O': 'OS detection — guesses the remote operating system from TCP/IP fingerprinting.',
    '-A': 'Aggressive scan — enables OS detection (-O), version detection (-sV), scripts (-sC), and traceroute.',
    '-T0': 'Timing: Paranoid — extremely slow; avoids IDS detection.',
    '-T1': 'Timing: Sneaky — very slow.',
    '-T2': 'Timing: Polite — slows down to avoid overwhelming the target.',
    '-T3': 'Timing: Normal — default speed.',
    '-T4': 'Timing: Aggressive — fast; recommended for local networks.',
    '-T5': 'Timing: Insane — maximum speed, may miss results.',
    '-p': 'Port specification — defines which ports to scan (e.g. -p 80,443 or -p 1-65535).',
    '-p-': 'Scan ALL 65535 ports.',
    '--top-ports': 'Scan the most common N ports (e.g. --top-ports 1000).',
    '-oN': 'Output to file in normal (human-readable) format.',
    '-oX': 'Output to XML file — useful for parsing with other tools.',
    '-oG': 'Grepable output — easy to search with grep/awk.',
    '-oA': 'Output in all formats simultaneously.',
    '-v': 'Verbose — show more details during the scan.',
    '-vv': 'Extra verbose.',
    '--script': 'Run specific NSE scripts (e.g. --script vuln, --script http-enum).',
    '--open': 'Only show hosts with at least one open port.',
    '-n': 'No DNS resolution — speeds up scans by skipping reverse DNS.',
    '-Pn': 'Skip host discovery (ping) — treat all hosts as online.',
    '-f': 'Fragment packets — splits TCP headers into tiny fragments to evade firewalls.',
    '--min-rate': 'Set minimum packet rate (e.g. --min-rate 5000).',
    '--max-retries': 'Maximum number of port scan probe retransmissions.',
    '-D': 'Decoy scan — use fake source IPs to confuse IDS.',
    '-S': 'Spoof source address.',
    '-e': 'Specify network interface to use.',
    '--exclude': 'Exclude specific hosts from the scan.',
  },
  sqlmap: {
    '-u': 'Target URL — the URL to test for SQL injection.',
    '--data': 'POST data string — data sent in a POST request body.',
    '--cookie': 'HTTP Cookie header value — for authenticated scans.',
    '--dbs': 'Enumerate databases on the server.',
    '--tables': 'Enumerate tables in the specified database.',
    '--columns': 'Enumerate columns in the specified table.',
    '--dump': 'Dump (extract) all data from the specified table.',
    '--dump-all': 'Dump ALL data from ALL databases.',
    '-D': 'Specify database name to target.',
    '-T': 'Specify table name to target.',
    '-C': 'Specify column name to target.',
    '--batch': 'Non-interactive mode — accept all defaults automatically.',
    '--level': 'Test level (1–5) — higher levels test more injection points.',
    '--risk': 'Risk level (1–3) — higher risks use more dangerous payloads.',
    '--dbms': 'Specify the database type (mysql, mssql, oracle, sqlite, etc.).',
    '--technique': 'Injection technique: B=Boolean, E=Error, U=Union, S=Stacked, T=Time-based.',
    '--threads': 'Number of concurrent HTTP requests.',
    '--proxy': 'Route traffic through a proxy (e.g. http://127.0.0.1:8080).',
    '--tor': 'Use Tor anonymous network.',
    '--headers': 'Extra HTTP headers to include.',
    '--user-agent': 'Specify custom HTTP User-Agent string.',
    '--random-agent': 'Use a random HTTP User-Agent from a built-in list.',
    '--os-shell': 'Attempt to get an interactive OS shell.',
    '--sql-shell': 'Prompt for an interactive SQL shell.',
    '--passwords': 'Enumerate and crack database user password hashes.',
    '--users': 'Enumerate database users.',
    '--privileges': 'Enumerate database user privileges.',
    '--current-user': 'Get current database user.',
    '--current-db': 'Get current database.',
    '--hostname': 'Retrieve the server hostname.',
    '--is-dba': 'Check if current user has DBA (admin) privileges.',
    '--forms': 'Parse and test HTML forms on the target URL.',
    '-r': 'Load HTTP request from a file (captured from Burp Suite).',
    '--flush-session': 'Clear previous session for this target.',
    '--output-dir': 'Save results to a specific directory.',
  },
  gobuster: {
    'dir': 'Mode: Directory/file brute-force.',
    'dns': 'Mode: DNS subdomain brute-force.',
    'vhost': 'Mode: Virtual host enumeration.',
    'fuzz': 'Mode: Fuzzing — replace FUZZ keyword in URL.',
    '-u': 'Target URL (dir/vhost mode).',
    '-d': 'Target domain (dns mode).',
    '-w': 'Wordlist file path.',
    '-t': 'Number of concurrent threads (default 10).',
    '-x': 'File extensions to append (e.g. -x php,html,txt).',
    '-s': 'Positive status codes to show (e.g. -s 200,204,301).',
    '-b': 'Negative status codes to hide (e.g. -b 404,403).',
    '-k': 'Skip TLS certificate verification.',
    '-r': 'Follow HTTP redirects.',
    '-q': 'Quiet mode — only print results.',
    '-o': 'Output file to save results.',
    '--delay': 'Add delay between requests (e.g. --delay 500ms).',
    '-H': 'Add custom HTTP header (e.g. -H "Authorization: Bearer TOKEN").',
    '-U': 'HTTP Basic Auth username.',
    '-P': 'HTTP Basic Auth password.',
    '--proxy': 'Proxy URL (e.g. http://127.0.0.1:8080).',
    '--timeout': 'HTTP timeout duration.',
    '--no-tls-validation': 'Disable TLS certificate validation.',
  },
  ffuf: {
    '-u': 'Target URL with FUZZ keyword (e.g. http://example.com/FUZZ).',
    '-w': 'Wordlist — path to wordlist file (use FUZZ as keyword).',
    '-X': 'HTTP method to use (GET, POST, PUT, DELETE, etc.).',
    '-d': 'POST data — sent as request body (use FUZZ to inject).',
    '-H': 'Add HTTP header (e.g. -H "Authorization: Bearer TOKEN").',
    '-b': 'Cookie data (e.g. -b "session=abc123").',
    '-mc': 'Match HTTP status codes (e.g. -mc 200,301).',
    '-fc': 'Filter (hide) status codes (e.g. -fc 404,403).',
    '-fs': 'Filter by response size in bytes (e.g. -fs 1234).',
    '-fw': 'Filter by number of words in response.',
    '-fl': 'Filter by number of lines in response.',
    '-ms': 'Match by response size.',
    '-mw': 'Match by number of words.',
    '-t': 'Number of concurrent threads.',
    '-c': 'Colorize output.',
    '-v': 'Verbose output.',
    '-o': 'Output file for results.',
    '-of': 'Output format (json, ejson, html, md, csv, ecsv).',
    '-recursion': 'Enable recursive mode.',
    '-recursion-depth': 'Max recursion depth.',
    '-e': 'Comma-separated list of extensions to append (e.g. -e .php,.html).',
    '-ac': 'Automatically calibrate filtering options.',
    '-timeout': 'HTTP request timeout in seconds.',
    '--proxy': 'Proxy URL.',
    '-r': 'Follow HTTP redirects.',
    '-sf': 'Stop when 95% of responses return the same status code.',
    '-p': 'Seconds of delay between requests.',
  },
  hydra: {
    '-l': 'Single username to try.',
    '-L': 'File containing a list of usernames.',
    '-p': 'Single password to try.',
    '-P': 'File containing a list of passwords (wordlist).',
    '-C': 'Colon-separated login:pass file instead of -L/-P.',
    '-t': 'Number of parallel tasks/threads per host (default 16).',
    '-s': 'Specify port (useful for non-standard ports).',
    '-S': 'Connect using SSL.',
    '-v': 'Verbose mode — show login attempts.',
    '-V': 'Show each login:pass combination being tried.',
    '-f': 'Stop attack after the first found valid login.',
    '-F': 'Stop attack on ANY host after first found credential.',
    '-M': 'File containing target hosts (one per line).',
    '-x': 'Brute force mode: MIN:MAX:CHARSET (e.g. -x 4:8:a1).',
    '-e': 'Try additional passwords: n=null, s=username, r=reversed.',
    '-o': 'Save results to a file.',
    '-R': 'Restore a previous interrupted/crashed session.',
    '-I': 'Ignore an existing restore file.',
    '-u': 'Loop around users, not passwords (useful for spraying).',
    '-w': 'Defines the wait time between connections per thread (seconds).',
    '-W': 'Defines per-host connection limit.',
  },
  aircrack: {
    '-a': 'Force attack mode: 1 = WEP, 2 = WPA-PSK.',
    '-b': 'Target BSSID (MAC address of the access point).',
    '-e': 'Target ESSID (network name).',
    '-w': 'Path to the wordlist file.',
    '-l': 'Write the found key to a file.',
    '-q': 'Enable quiet mode.',
    '-J': 'Create Hashcat capture file.',
    '-K': 'Use PTW attack to crack WEP keys.',
    '-s': 'Log attack statistics to a file.',
  },
  metasploit: {
    'use': 'Select a module to use (e.g. use exploit/multi/handler).',
    'show': 'Display options, modules, payloads or exploits.',
    'set': 'Set an option value (e.g. set RHOSTS 192.168.1.1).',
    'setg': 'Set a global option that persists across modules.',
    'run': 'Run the current module (alias for exploit).',
    'exploit': 'Execute the configured exploit.',
    'search': 'Search for a module by name or CVE.',
    'info': 'Show detailed information about the selected module.',
    'back': 'Exit the current module context.',
    'sessions': 'Manage active Meterpreter/shell sessions.',
    'sessions -i': 'Interact with a specific session.',
    'jobs': 'List background jobs.',
    'db_nmap': 'Run Nmap and import results directly into the database.',
    'hosts': 'Show discovered hosts in the database.',
    'services': 'Show discovered services in the database.',
    'vulns': 'Show discovered vulnerabilities in the database.',
    'msfvenom': 'Standalone payload generator (run outside msfconsole).',
    'RHOSTS': 'Remote host(s) — the target IP or range.',
    'LHOST': 'Local host — your attacker IP (for reverse shells).',
    'LPORT': 'Local port — the port your handler listens on.',
    'PAYLOAD': 'The payload to deliver after exploitation.',
  },
  dmitry: {
    '-w': 'Perform a WHOIS lookup on the target.',
    '-i': 'Retrieve IP information for the domain.',
    '-n': 'Retrieve Netcraft.com information for the domain.',
    '-s': 'Perform a search for possible subdomains.',
    '-e': 'Search for possible email addresses.',
    '-p': 'Perform a TCP port scan on the host.',
    '-b': 'Read in the banner received from a scanned port.',
    '-f': 'Perform a TCP port scan showing filtered ports.',
    '-o': 'Save output to a file.',
    '-v': 'Verbose output.',
    '-a': 'Perform ALL search techniques.',
  },
};

/* Detect tool from first word of command */
const detectTool = (cmd) => {
  const first = cmd.trim().toLowerCase().split(/\s+/)[0].replace(/\.exe$/i, '');
  const map = {
    nmap: 'nmap', sqlmap: 'sqlmap', gobuster: 'gobuster', ffuf: 'ffuf',
    hydra: 'hydra', aircrack: 'aircrack', 'aircrack-ng': 'aircrack',
    msfconsole: 'metasploit', metasploit: 'metasploit',
    dmitry: 'dmitry', 'theHarvester': 'dmitry'
  };
  return map[first] || null;
};

/* Parse tokens and match to flag dictionary */
const explainCommand = (cmd, tool) => {
  if (!tool || !FLAG_DB[tool]) return [];
  const db = FLAG_DB[tool];
  const parts = cmd.trim().split(/\s+/);
  const results = [];
  const seen = new Set();

  for (let i = 0; i < parts.length; i++) {
    const token = parts[i];
    // skip the tool name itself
    if (i === 0) { results.push({ token, explanation: `Tool: ${tool.toUpperCase()} — the command being run.`, type: 'tool' }); continue; }

    // Try exact match
    if (db[token] && !seen.has(token)) {
      results.push({ token, explanation: db[token], type: 'flag' });
      seen.add(token);
      continue;
    }

    // Try prefix match (e.g. -T4 → -T)
    const prefix = token.replace(/[0-9]+$/, '');
    if (prefix !== token && db[prefix] && !seen.has(prefix)) {
      results.push({ token, explanation: db[prefix], type: 'flag' });
      seen.add(prefix);
      continue;
    }

    // It's likely a value/argument for the previous flag
    if (results.length > 0 && !token.startsWith('-')) {
      results.push({ token, explanation: `Value/argument passed to the previous flag.`, type: 'value' });
    } else if (!seen.has(token)) {
      results.push({ token, explanation: `Unrecognized flag or argument. It may be tool-specific or misspelled.`, type: 'unknown' });
      seen.add(token);
    }
  }
  return results;
};

const typeStyle = {
  tool: { bg: 'rgba(167,139,250,0.15)', color: '#a78bfa', label: 'TOOL' },
  flag: { bg: 'rgba(56,189,248,0.15)', color: '#38bdf8', label: 'FLAG' },
  value: { bg: 'rgba(52,211,153,0.15)', color: '#34d399', label: 'VALUE' },
  unknown: { bg: 'rgba(251,191,36,0.15)', color: '#fbbf24', label: '?' },
};

const CommandExplainer = () => {
  const [input, setInput] = useState('');
  const [explained, setExplained] = useState([]);
  const [tool, setTool] = useState(null);
  const [searched, setSearched] = useState(false);
  const inputRef = useRef(null);

  const handleExplain = () => {
    if (!input.trim()) return;
    const detected = detectTool(input);
    setTool(detected);
    const result = explainCommand(input, detected);
    setExplained(result);
    setSearched(true);
  };

  const handleKeyDown = (e) => { if (e.key === 'Enter') handleExplain(); };

  const loadExample = (cmd) => { setInput(cmd); setExplained([]); setSearched(false); };

  const examples = [
    'nmap -sS -T4 -p 1-1000 -sV -O 192.168.1.1',
    'gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt -x php,html -t 50',
    'sqlmap -u "http://example.com/page?id=1" --dbs --batch --level 3',
    'hydra -L users.txt -P rockyou.txt ssh://192.168.1.10 -t 4 -v',
    'ffuf -u http://example.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/big.txt -mc 200 -t 40',
    'dmitry -wise example.com -o output.txt',
  ];

  return (
    <div style={{ padding: '0 20px 60px', maxWidth: '1000px', margin: '0 auto' }}>
      <GradientHeader
        title="Command Explainer"
        subtitle="Paste any security command — get each flag and argument explained in plain English"
        icon={<FaMagic />}
      />

      {/* Example chips */}
      <div style={{ margin: '20px 0 12px' }}>
        <p style={{ fontSize: '12px', color: 'var(--text-lighter)', marginBottom: '8px', fontWeight: '600' }}>QUICK EXAMPLES:</p>
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          {examples.map((ex, i) => (
            <motion.button key={i} onClick={() => loadExample(ex)} whileHover={{ scale: 1.04 }} whileTap={{ scale: 0.96 }}
              style={{ padding: '5px 12px', borderRadius: '20px', fontSize: '11px', fontWeight: '600', border: '1px solid var(--border-strong)', background: 'transparent', color: 'var(--primary)', cursor: 'pointer' }}>
              {ex.split(' ')[0]}
            </motion.button>
          ))}
        </div>
      </div>

      {/* Input */}
      <div style={{ display: 'flex', gap: '12px', marginBottom: '28px' }}>
        <input
          ref={inputRef}
          value={input}
          onChange={e => { setInput(e.target.value); setSearched(false); }}
          onKeyDown={handleKeyDown}
          placeholder="Paste a command here (e.g. nmap -sS -T4 -p- 192.168.1.1)"
          style={{
            flex: 1, padding: '14px 18px',
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '13px',
            background: 'var(--card-bg)', color: 'var(--text)',
            border: '1.5px solid var(--border-strong)', borderRadius: '12px',
            outline: 'none',
          }}
          onFocus={e => e.target.style.borderColor = 'var(--primary)'}
          onBlur={e => e.target.style.borderColor = 'var(--border-strong)'}
        />
        <motion.button onClick={handleExplain} whileHover={{ scale: 1.04 }} whileTap={{ scale: 0.96 }}
          style={{ padding: '14px 24px', borderRadius: '12px', border: 'none', background: 'var(--gradient-primary)', color: 'white', fontWeight: '700', fontSize: '14px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <FaSearch /> Explain
        </motion.button>
      </div>

      {/* Results */}
      <AnimatePresence>
        {searched && (
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
            {!tool ? (
              <div style={{ padding: '24px', textAlign: 'center', background: 'var(--card-bg)', borderRadius: '16px', border: '1px solid var(--warning)' }}>
                <FaInfoCircle style={{ color: 'var(--warning)', fontSize: '24px', marginBottom: '8px' }} />
                <p style={{ color: 'var(--text)' }}>Tool not recognized. Supported: nmap, sqlmap, gobuster, ffuf, hydra, aircrack-ng, dmitry, metasploit.</p>
              </div>
            ) : (
              <>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
                  <span className="cyber-badge">{tool.toUpperCase()}</span>
                  <span style={{ fontSize: '13px', color: 'var(--text-lighter)' }}>{explained.length} tokens analyzed</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {explained.map((item, i) => {
                    const ts = typeStyle[item.type];
                    return (
                      <motion.div key={i} initial={{ opacity: 0, x: -16 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.05 }}
                        style={{ display: 'flex', alignItems: 'flex-start', gap: '14px', padding: '14px 18px', borderRadius: '12px', background: ts.bg, border: `1px solid ${ts.color}33` }}>
                        <code style={{ fontFamily: "'JetBrains Mono', monospace", color: ts.color, fontWeight: '700', fontSize: '13px', flexShrink: 0, minWidth: '140px', wordBreak: 'break-all' }}>
                          {item.token}
                        </code>
                        <div style={{ flex: 1 }}>
                          <span style={{ fontSize: '10px', fontWeight: '700', color: ts.color, textTransform: 'uppercase', letterSpacing: '0.5px', marginRight: '8px' }}>
                            {ts.label}
                          </span>
                          <span style={{ fontSize: '13px', color: 'var(--text)', lineHeight: '1.5' }}>{item.explanation}</span>
                        </div>
                        <button onClick={() => { copyToClipboard(item.token); toast.success('Copied!', { position: 'bottom-right', autoClose: 1200, hideProgressBar: true }); }}
                          style={{ background: 'transparent', border: 'none', color: ts.color, cursor: 'pointer', fontSize: '13px', flexShrink: 0 }}>
                          <FaCopy />
                        </button>
                      </motion.div>
                    );
                  })}
                </div>
              </>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {!searched && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} style={{ textAlign: 'center', padding: '60px 20px', opacity: 0.4 }}>
          <FaMagic style={{ fontSize: '48px', color: 'var(--primary)', marginBottom: '12px' }} />
          <p>Paste a command above and click Explain</p>
        </motion.div>
      )}
    </div>
  );
};

export default CommandExplainer;
