import { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FaBook, FaSearch, FaTimes } from 'react-icons/fa';
import GradientHeader from '../components/UI/GradientHeader';

const GLOSSARY = [
  { term: 'ARP Spoofing', category: 'Network', definition: 'Attack where a malicious actor sends fake ARP messages to link their MAC address with a legitimate IP, enabling man-in-the-middle attacks on a LAN.' },
  { term: 'Backdoor', category: 'Malware', definition: 'Hidden method for bypassing normal authentication to gain unauthorized remote access to a system.' },
  { term: 'BloodHound', category: 'Tool', definition: 'Active Directory attack path analysis tool that uses graph theory to find attack paths to domain administrator privileges.' },
  { term: 'Brute Force', category: 'Attack', definition: 'Trial-and-error method of guessing passwords, encryption keys, or login credentials by systematically checking all possible combinations.' },
  { term: 'Buffer Overflow', category: 'Vulnerability', definition: 'When a program writes more data to a buffer than it can hold, overwriting adjacent memory. Can lead to arbitrary code execution.' },
  { term: 'Burp Suite', category: 'Tool', definition: 'Industry-standard web application security testing platform with intercepting proxy, scanner, intruder, and repeater tools.' },
  { term: 'C2 / C&C', category: 'Concept', definition: 'Command and Control server — infrastructure attackers use to communicate with and control compromised systems (implants/beacons).' },
  { term: 'CIDR', category: 'Network', definition: 'Classless Inter-Domain Routing — a method for specifying IP address ranges (e.g. 192.168.1.0/24 = 256 addresses).' },
  { term: 'CSRF', category: 'Web', definition: 'Cross-Site Request Forgery — tricks a victim\'s browser into sending unauthorized requests to a site where they\'re authenticated.' },
  { term: 'CVE', category: 'Concept', definition: 'Common Vulnerabilities and Exposures — a standardized identifier for publicly known cybersecurity vulnerabilities (e.g. CVE-2021-44228).' },
  { term: 'CVSS', category: 'Concept', definition: 'Common Vulnerability Scoring System — a numerical score (0–10) representing the severity of a vulnerability.' },
  { term: 'DCSync', category: 'Attack', definition: 'Active Directory attack that simulates a Domain Controller replication request to extract password hashes for all accounts, including krbtgt.' },
  { term: 'DNS Enumeration', category: 'Recon', definition: 'Process of querying DNS records (A, MX, NS, TXT, CNAME) to map a target\'s infrastructure and discover subdomains.' },
  { term: 'Enumeration', category: 'Concept', definition: 'The process of extracting information from a target system — usernames, shares, services, OS version, etc. Critical step after initial access.' },
  { term: 'Exploit', category: 'Concept', definition: 'A piece of software, data, or sequence of commands that takes advantage of a vulnerability to cause unintended behavior on a target system.' },
  { term: 'File Inclusion (LFI/RFI)', category: 'Web', definition: 'LFI (Local File Inclusion) reads files from the server. RFI (Remote File Inclusion) loads files from external URLs, enabling code execution.' },
  { term: 'Fuzzing', category: 'Technique', definition: 'Testing technique that sends large amounts of unexpected/random data to an application to trigger crashes, errors, or security vulnerabilities.' },
  { term: 'Golden Ticket', category: 'Attack', definition: 'Kerberos attack using a forged TGT (Ticket Granting Ticket) created from the NTLM hash of the krbtgt account, granting unlimited domain access.' },
  { term: 'Hash', category: 'Cryptography', definition: 'One-way mathematical function that converts data to a fixed-length string. Cannot be reversed directly. Common types: MD5, SHA1, SHA256, NTLM, bcrypt.' },
  { term: 'IDOR', category: 'Web', definition: 'Insecure Direct Object Reference — when a web app uses user-controlled input to access objects directly without authorization checks.' },
  { term: 'IOC', category: 'Concept', definition: 'Indicator of Compromise — artifacts observed on a network/system that indicate a security breach (IP addresses, file hashes, domains, registry keys).' },
  { term: 'Kerberoasting', category: 'Attack', definition: 'AD attack that requests Kerberos TGS tickets for service accounts and cracks the NTLM hash offline. Works when SPNs are set on user accounts.' },
  { term: 'Keylogger', category: 'Malware', definition: 'Software or hardware that records keystrokes to capture sensitive information like passwords and credit card numbers.' },
  { term: 'Lateral Movement', category: 'Technique', definition: 'Techniques used after initial compromise to move through a network, accessing additional systems and escalating privileges.' },
  { term: 'LOLBAS', category: 'Technique', definition: 'Living Off the Land Binaries and Scripts — using legitimate Windows system tools (e.g. certutil, powershell, wmic) for malicious purposes to evade detection.' },
  { term: 'Man-in-the-Middle (MitM)', category: 'Attack', definition: 'Attack where the attacker secretly intercepts and relays communications between two parties who believe they are communicating directly.' },
  { term: 'Metasploit', category: 'Tool', definition: 'Open-source penetration testing framework with a huge library of exploits, payloads, and auxiliary modules. Gold standard for exploitation.' },
  { term: 'Mimikatz', category: 'Tool', definition: 'Post-exploitation tool for extracting plaintext passwords, hashes, PIN codes, and Kerberos tickets from Windows memory (LSASS).' },
  { term: 'NTLM', category: 'Cryptography', definition: 'NT LAN Manager — Windows challenge-response authentication protocol. NTLM hashes can be captured and used in Pass-the-Hash attacks.' },
  { term: 'Nmap', category: 'Tool', definition: 'Network mapper — the industry-standard tool for network discovery and security auditing. Discovers hosts, open ports, services and OS versions.' },
  { term: 'OSINT', category: 'Concept', definition: 'Open Source Intelligence — collecting information from publicly available sources (websites, social media, WHOIS, DNS records, Shodan) without touching the target.' },
  { term: 'OWASP Top 10', category: 'Web', definition: 'A regularly updated report outlining the 10 most critical web application security risks, published by the Open Web Application Security Project.' },
  { term: 'Pass-the-Hash (PtH)', category: 'Attack', definition: 'Technique where an attacker uses a captured NTLM hash to authenticate to a remote service without cracking the plaintext password.' },
  { term: 'Payload', category: 'Concept', definition: 'The part of an attack that actually causes the harm — the malicious code or data delivered via an exploit.' },
  { term: 'Persistence', category: 'Technique', definition: 'Techniques to maintain access to a compromised system across reboots and credential changes (scheduled tasks, registry keys, backdoors, cron jobs).' },
  { term: 'Phishing', category: 'Attack', definition: 'Social engineering attack using fraudulent emails, messages, or websites to trick users into revealing credentials or installing malware.' },
  { term: 'Pivoting', category: 'Technique', definition: 'Using a compromised host as a relay to attack other systems within the same network that would otherwise be unreachable from the attacker\'s position.' },
  { term: 'Port Scanning', category: 'Recon', definition: 'Process of probing a server or host to discover which ports are open, listening, or filtered — foundation of network reconnaissance.' },
  { term: 'Privilege Escalation', category: 'Technique', definition: 'Gaining higher levels of access than initially granted — from user to admin, or user to SYSTEM/root. Vertical (user→admin) or Horizontal (user A→user B).' },
  { term: 'RAT', category: 'Malware', definition: 'Remote Access Trojan — malware that gives an attacker full remote control of a victim\'s machine, often including camera/microphone access.' },
  { term: 'RCE', category: 'Vulnerability', definition: 'Remote Code Execution — critical vulnerability class allowing attackers to run arbitrary code on a target system from a remote location.' },
  { term: 'Reconnaissance', category: 'Concept', definition: 'First phase of an attack — gathering information about the target (domain, IPs, employees, technologies) to plan the attack strategy.' },
  { term: 'Reverse Shell', category: 'Technique', definition: 'A shell session initiated FROM the target BACK to the attacker, bypassing firewalls that block inbound connections.' },
  { term: 'RFI', category: 'Web', definition: 'Remote File Inclusion — web vulnerability allowing attackers to include and execute remote files (hosted by the attacker) on the target server.' },
  { term: 'SAST / DAST', category: 'Concept', definition: 'Static Application Security Testing (code analysis without execution) vs Dynamic Application Security Testing (testing running application).' },
  { term: 'Shellcode', category: 'Concept', definition: 'Small piece of machine code (bytecode) used as the payload in exploit attacks. Usually opens a shell or downloads additional malware.' },
  { term: 'Shodan', category: 'Tool', definition: 'Search engine for Internet-connected devices. Finds cameras, servers, IoT devices, industrial control systems exposed to the internet.' },
  { term: 'Silver Ticket', category: 'Attack', definition: 'Kerberos attack using a forged TGS (service ticket) for a specific service using the service account\'s NTLM hash — more targeted than Golden Ticket.' },
  { term: 'SQL Injection (SQLi)', category: 'Web', definition: 'Injection attack where malicious SQL queries are inserted into input fields to manipulate the database — read, modify, or delete data.' },
  { term: 'SSRF', category: 'Web', definition: 'Server-Side Request Forgery — forces the server to make requests to internal services, potentially accessing AWS metadata, internal APIs, or localhost services.' },
  { term: 'SSTI', category: 'Web', definition: 'Server-Side Template Injection — injecting malicious template syntax to execute code on the server through the template engine (Jinja2, Twig, Freemarker).' },
  { term: 'Subdomain Takeover', category: 'Web', definition: 'When a DNS subdomain points to an unclaimed external service (GitHub Pages, S3, etc.), attackers can claim it and serve malicious content on the legitimate domain.' },
  { term: 'THM / HackTheBox', category: 'Learning', definition: 'TryHackMe and HackTheBox — online platforms with guided cybersecurity labs and CTF-style machines for hands-on practice.' },
  { term: 'TTP', category: 'Concept', definition: 'Tactics, Techniques and Procedures — describes the behavior and methods used by threat actors, documented in frameworks like MITRE ATT&CK.' },
  { term: 'UAC Bypass', category: 'Attack', definition: 'Technique to bypass Windows User Account Control to gain administrator privileges without a UAC prompt (e.g. using fodhelper.exe, eventvwr.exe).' },
  { term: 'Vulnerability', category: 'Concept', definition: 'A weakness in a system that can be exploited by a threat actor. Classified by type (code injection, misconfiguration, design flaw) and severity (CVSS score).' },
  { term: 'WAF', category: 'Defence', definition: 'Web Application Firewall — filters and monitors HTTP traffic to block common attacks like SQLi and XSS. Can be bypassed with encoding, case variation, or chunked requests.' },
  { term: 'WHOIS', category: 'Recon', definition: 'Protocol for querying databases that contain domain registration information — owner, registrar, contact email, name servers, registration dates.' },
  { term: 'Wordlist', category: 'Tool', definition: 'A text file containing a list of words/passwords used in brute-force or dictionary attacks. Common lists: rockyou.txt, dirb/common.txt, SecLists.' },
  { term: 'XSS', category: 'Web', definition: 'Cross-Site Scripting — injecting malicious scripts into web pages viewed by other users. Stored (persists in DB), Reflected (in URL), or DOM-based.' },
  { term: 'Zero-Day (0-day)', category: 'Concept', definition: 'A vulnerability that is unknown to the software vendor and has no available patch. Extremely valuable because there is no defence on day zero.' },
  { term: 'Zombie', category: 'Malware', definition: 'A compromised computer under the control of a botnet operator, used to send spam, conduct DDoS attacks, or mine cryptocurrency without the owner\'s knowledge.' },
];

const categories = ['All', ...new Set(GLOSSARY.map(g => g.category))].sort((a, b) => a === 'All' ? -1 : a.localeCompare(b));
const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('');

const catColor = {
  Network: '#38bdf8', Malware: '#f87171', Tool: '#a78bfa', Attack: '#fb923c',
  Concept: '#34d399', Web: '#60a5fa', Vulnerability: '#f87171', Technique: '#fbbf24',
  Cryptography: '#c084fc', Recon: '#4ade80', Learning: '#34d399', Defence: '#22d3ee',
};

const Glossary = () => {
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState('All');
  const [activeLetter, setActiveLetter] = useState(null);
  const [expanded, setExpanded] = useState(null);

  const filtered = useMemo(() => GLOSSARY.filter(g => {
    const matchSearch = g.term.toLowerCase().includes(search.toLowerCase()) || g.definition.toLowerCase().includes(search.toLowerCase());
    const matchCat = category === 'All' || g.category === category;
    const matchLetter = !activeLetter || g.term.toUpperCase().startsWith(activeLetter);
    return matchSearch && matchCat && matchLetter;
  }).sort((a, b) => a.term.localeCompare(b.term)), [search, category, activeLetter]);

  return (
    <div style={{ padding: '0 20px 60px', maxWidth: '1100px', margin: '0 auto' }}>
      <GradientHeader title="Security Glossary" subtitle={`${GLOSSARY.length} cybersecurity terms explained in plain English`} icon={<FaBook />} />

      {/* Search + Filter */}
      <div style={{ display: 'flex', gap: '12px', margin: '24px 0 16px', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: '240px', display: 'flex', alignItems: 'center', gap: '10px', background: 'var(--card-bg)', border: '1.5px solid var(--border-strong)', borderRadius: '12px', padding: '10px 16px' }}>
          <FaSearch style={{ color: 'var(--primary)', flexShrink: 0 }} />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search terms or definitions..."
            style={{ border: 'none', background: 'transparent', color: 'var(--text)', outline: 'none', width: '100%', fontSize: '14px' }} />
          {search && <button onClick={() => setSearch('')} style={{ background: 'transparent', border: 'none', color: 'var(--text-lighter)', cursor: 'pointer' }}><FaTimes /></button>}
        </div>
        <select value={category} onChange={e => setCategory(e.target.value)}
          style={{ padding: '10px 16px', borderRadius: '12px', border: '1.5px solid var(--border-strong)', background: 'var(--card-bg)', color: 'var(--text)', fontSize: '14px', cursor: 'pointer' }}>
          {categories.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
      </div>

      {/* Alphabet filter */}
      <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', marginBottom: '24px' }}>
        <motion.button onClick={() => setActiveLetter(null)} whileHover={{ scale: 1.1 }}
          style={{ padding: '4px 10px', borderRadius: '8px', border: 'none', background: !activeLetter ? 'var(--primary)' : 'var(--card-bg)', color: !activeLetter ? 'white' : 'var(--text-lighter)', cursor: 'pointer', fontSize: '12px', fontWeight: '700' }}>
          ALL
        </motion.button>
        {alphabet.map(l => {
          const has = GLOSSARY.some(g => g.term.toUpperCase().startsWith(l));
          return (
            <motion.button key={l} onClick={() => has && setActiveLetter(activeLetter === l ? null : l)} whileHover={has ? { scale: 1.1 } : {}}
              style={{ padding: '4px 8px', borderRadius: '8px', border: 'none', background: activeLetter === l ? 'var(--primary)' : 'var(--card-bg)', color: activeLetter === l ? 'white' : has ? 'var(--text-lighter)' : 'var(--border)', cursor: has ? 'pointer' : 'default', fontSize: '12px', fontWeight: '700', opacity: has ? 1 : 0.3 }}>
              {l}
            </motion.button>
          );
        })}
      </div>

      <p style={{ fontSize: '12px', color: 'var(--text-lighter)', marginBottom: '16px' }}>{filtered.length} terms</p>

      {/* Term list */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {filtered.map((item, i) => {
          const color = catColor[item.category] || '#a78bfa';
          const isOpen = expanded === item.term;
          return (
            <motion.div key={item.term} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: Math.min(i * 0.02, 0.3) }}
              style={{ borderRadius: '12px', border: `1px solid ${isOpen ? color + '55' : 'var(--border)'}`, background: isOpen ? `${color}0a` : 'var(--card-bg)', overflow: 'hidden', cursor: 'pointer', transition: 'all 0.3s' }}
              onClick={() => setExpanded(isOpen ? null : item.term)}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', padding: '14px 18px' }}>
                <span style={{ fontWeight: '700', color: 'var(--text)', fontSize: '15px', flex: 1 }}>{item.term}</span>
                <span style={{ background: `${color}22`, color: color, fontSize: '10px', padding: '3px 8px', borderRadius: '10px', fontWeight: '700', whiteSpace: 'nowrap' }}>{item.category}</span>
                <motion.span animate={{ rotate: isOpen ? 180 : 0 }} style={{ color: 'var(--text-lighter)', fontSize: '12px' }}><FaChevronDown /></motion.span>
              </div>
              <AnimatePresence>
                {isOpen && (
                  <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.25 }}>
                    <p style={{ padding: '0 18px 16px', fontSize: '14px', color: 'var(--text-light)', lineHeight: '1.7', borderTop: `1px solid ${color}22`, paddingTop: '12px' }}>
                      {item.definition}
                    </p>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          );
        })}
        {filtered.length === 0 && (
          <div style={{ textAlign: 'center', padding: '60px', opacity: 0.5 }}>
            <FaBook style={{ fontSize: '40px', color: 'var(--primary)', marginBottom: '12px' }} />
            <p>No terms match your search.</p>
          </div>
        )}
      </div>
    </div>
  );
};

// Missing import fix
const FaChevronDown = () => <span>▾</span>;

export default Glossary;
