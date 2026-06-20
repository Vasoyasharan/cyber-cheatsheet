import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import { FaRoute, FaLock, FaGlobe, FaShieldAlt, FaFlag, FaChevronRight, FaCheckCircle, FaArrowRight, FaClock, FaLayerGroup, FaTrophy, FaBolt } from 'react-icons/fa';
import GradientHeader from '../components/UI/GradientHeader';

const paths = [
  {
    id: 'beginner',
    title: 'Complete Beginner',
    subtitle: 'Zero to Hacker',
    icon: <FaShieldAlt />,
    color: '#34d399',
    difficulty: 'Beginner',
    duration: '4–6 weeks',
    steps: [
      { title: 'Understand the Basics', type: 'sheet', id: 'linux', description: 'Start with Linux fundamentals and how the OS works — most targets run Linux.', link: '/cheatsheets' },
      { title: 'Network Fundamentals', type: 'tool', id: 'nmap', description: 'Learn TCP/IP, ports, protocols. Then use Nmap to discover what is running on a network.', link: '/tools' },
      { title: 'Network Traffic Analysis', type: 'tool', id: 'wireshark', description: 'Use Wireshark to capture and inspect packets — understand what\'s happening on the wire.', link: '/tools' },
      { title: 'OSINT & Reconnaissance', type: 'tool', id: 'osint', description: 'Before attacking anything, gather intelligence. Practice passive recon with OSINT techniques.', link: '/tools' },
      { title: 'Port & Service Discovery', type: 'reference', description: 'Study the Port Reference to know what each open port means.', link: '/ports' },
      { title: 'Password Security', type: 'tool', id: 'hashid', description: 'Learn hash types, then use Hash Identifier + John the Ripper to crack weak passwords.', link: '/tools' },
      { title: 'Linux Privilege Escalation', type: 'sheet', id: 'linux', description: 'Learn how to escalate privileges on a Linux box once you have initial access.', link: '/cheatsheets' },
      { title: 'Build Your Glossary', type: 'reference', description: 'Review the Cybersecurity Glossary — knowing terminology is critical.', link: '/glossary' },
    ]
  },
  {
    id: 'web',
    title: 'Web App Hacker',
    subtitle: 'Bug Bounty Ready',
    icon: <FaGlobe />,
    color: '#38bdf8',
    difficulty: 'Intermediate',
    duration: '3–5 weeks',
    steps: [
      { title: 'HTTP & Web Fundamentals', type: 'sheet', description: 'Understand HTTP methods, headers, cookies, sessions. Crucial for every web test.', link: '/cheatsheets' },
      { title: 'Web App Testing Framework', type: 'sheet', id: 'web', description: 'Study the comprehensive Web App Testing cheat sheet — covers OWASP Top 10.', link: '/cheatsheets' },
      { title: 'Burp Suite Mastery', type: 'tool', id: 'burp', description: 'Intercept, modify, and replay HTTP requests. The #1 tool for web application testing.', link: '/tools' },
      { title: 'Directory & File Discovery', type: 'tool', id: 'gobuster', description: 'Use Gobuster and FFuf to find hidden endpoints, admin panels and backup files.', link: '/tools' },
      { title: 'Web Server Scanning', type: 'tool', id: 'nikto', description: 'Scan for common vulnerabilities, outdated software and misconfigurations with Nikto.', link: '/tools' },
      { title: 'SQL Injection', type: 'tool', id: 'sqlmap', description: 'Automate SQL injection detection and exploitation with SQLmap.', link: '/tools' },
      { title: 'Payload Arsenal', type: 'reference', description: 'Build your knowledge of XSS, SQLi, SSTI, and command injection payloads.', link: '/payloads' },
      { title: 'API Security Testing', type: 'sheet', id: 'api', description: 'Test REST and GraphQL APIs for authentication flaws, IDOR, and broken access control.', link: '/cheatsheets' },
    ]
  },
  {
    id: 'ad',
    title: 'Active Directory Specialist',
    subtitle: 'Domain Domination',
    icon: <FaLock />,
    color: '#a78bfa',
    difficulty: 'Advanced',
    duration: '5–8 weeks',
    steps: [
      { title: 'Windows Fundamentals', type: 'sheet', id: 'windows', description: 'Master Windows internals, registry, services and the security model.', link: '/cheatsheets' },
      { title: 'Network Scanning', type: 'tool', id: 'nmap', description: 'Map the network, discover domain controllers and Windows hosts.', link: '/tools' },
      { title: 'SMB Enumeration', type: 'tool', id: 'enum4linux', description: 'Enumerate users, shares, and policies from Windows machines over SMB.', link: '/tools' },
      { title: 'AD Attack Techniques', type: 'sheet', id: 'active', description: 'Study Kerberoasting, Pass-the-Hash, DCSync, BloodHound and more.', link: '/cheatsheets' },
      { title: 'CrackMapExec', type: 'tool', id: 'crackmapexec', description: 'Automate credential testing and lateral movement across Active Directory environments.', link: '/tools' },
      { title: 'PowerShell for Post-Exploitation', type: 'tool', id: 'powershell', description: 'Use PowerShell for enumeration, lateral movement, and persistence.', link: '/tools' },
      { title: 'Post-Exploitation', type: 'sheet', id: 'post', description: 'Dump credentials, move laterally, and establish persistence in the domain.', link: '/cheatsheets' },
      { title: 'C2 Frameworks', type: 'sheet', id: 'c2', description: 'Understand Cobalt Strike, Sliver and other C2 frameworks for long-term operations.', link: '/cheatsheets' },
    ]
  },
  {
    id: 'ctf',
    title: 'CTF Player',
    subtitle: 'Capture The Flag',
    icon: <FaFlag />,
    color: '#fbbf24',
    difficulty: 'Mixed',
    duration: '2–4 weeks',
    steps: [
      { title: 'Recon & Enumeration', type: 'tool', id: 'nmap', description: 'Every CTF starts with recon. Map the target fast and thoroughly with Nmap.', link: '/tools' },
      { title: 'Web Exploitation', type: 'tool', id: 'gobuster', description: 'Find hidden pages, admin portals and exposed files with Gobuster and FFuf.', link: '/tools' },
      { title: 'Password Cracking', type: 'tool', id: 'hashcat', description: 'GPU-powered cracking of captured hashes with Hashcat and wordlists.', link: '/tools' },
      { title: 'CTF Payload Arsenal', type: 'reference', description: 'Have your XSS, SQLi, SSTI, and RCE payloads ready to fire instantly.', link: '/payloads' },
      { title: 'Privilege Escalation', type: 'sheet', id: 'linux', description: 'SUID binaries, cron jobs, kernel exploits — know them all.', link: '/cheatsheets' },
      { title: 'Metasploit', type: 'tool', id: 'metasploit', description: 'When manual exploitation is needed, Metasploit has a module for almost everything.', link: '/tools' },
      { title: 'CVE Research', type: 'reference', description: 'Look up CVEs for the exact service version you found during enumeration.', link: '/cve' },
      { title: 'Know Your Ports', type: 'reference', description: 'Instantly identify services from open ports using the Port Reference.', link: '/ports' },
    ]
  },
  {
    id: 'redteam',
    title: 'Red Team Operator',
    subtitle: 'Advanced Adversary Simulation',
    icon: '🎯',
    color: '#f87171',
    difficulty: 'Expert',
    duration: '8–12 weeks',
    steps: [
      { title: 'OSINT & Target Profiling', type: 'tool', id: 'osint', description: 'Build a comprehensive intelligence picture: employees, tech stack, email formats, VPN ranges, and infrastructure via LinkedIn, Shodan, Censys, and WHOIS.', link: '/tools' },
      { title: 'Phishing Infrastructure', type: 'sheet', description: 'Set up GoPhish, typosquat domains with valid TLS certs. Clone login portals. Capture credentials and tokens via Evilginx2 reverse proxy.', link: '/cheatsheets' },
      { title: 'Initial Access — External Attack Surface', type: 'sheet', description: 'Exploit exposed services, public-facing apps, VPN gateways, and forgotten staging environments. Check CVEs for found service versions.', link: '/cheatsheets' },
      { title: 'AV/EDR Evasion Techniques', type: 'sheet', description: 'Understand AV signatures, behavioral analysis, and AMSI. Use custom loaders, obfuscation, sleep masks, and PPID spoofing to evade detection.', link: '/cheatsheets' },
      { title: 'C2 Framework Setup & Tradecraft', type: 'sheet', id: 'c2', description: 'Deploy a full C2 (Cobalt Strike / Sliver / Havoc). Set up redirectors, malleable profiles, domain fronting, and DNS beacons for stealthy comms.', link: '/cheatsheets' },
      { title: 'Internal Reconnaissance & BloodHound', type: 'tool', id: 'nmap', description: 'Once inside, map the internal network: hosts, services, domain trusts. Use BloodHound to visualize AD attack paths to Domain Admin.', link: '/tools' },
      { title: 'Privilege Escalation & Credential Theft', type: 'sheet', description: 'Escalate via token impersonation, SeImpersonatePrivilege (Potatoes), UAC bypass, LAPS, and credential dumping with Mimikatz, lsassy, Rubeus.', link: '/cheatsheets' },
      { title: 'Lateral Movement Techniques', type: 'sheet', description: 'Move through the network using Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash, DCOM, WinRM, and RDP with harvested credentials.', link: '/cheatsheets' },
      { title: 'Domain Compromise & Persistence', type: 'sheet', description: 'DCSync to dump all domain hashes. Golden/Silver Tickets for long-term access. Persist via scheduled tasks, WMI subscriptions, or registry run keys.', link: '/cheatsheets' },
      { title: 'Reporting & MITRE ATT&CK Mapping', type: 'reference', description: 'Document the entire attack chain: IOCs, TTPs mapped to MITRE ATT&CK framework, business impact, and a remediation roadmap for the client.', link: '/glossary' },
    ]
  }
];

const typeColors = { tool: '#a78bfa', sheet: '#38bdf8', reference: '#34d399' };
const typeLabels = { tool: 'Tool Builder', sheet: 'Cheat Sheet', reference: 'Reference' };

const LearningPaths = () => {
  const [activePath, setActivePath] = useState(null);
  const [completed, setCompleted] = useState(() => {
    try { return JSON.parse(localStorage.getItem('lp_completed') || '{}'); } catch { return {}; }
  });
  const navigate = useNavigate();

  const toggleComplete = (pathId, stepIdx) => {
    const key = `${pathId}_${stepIdx}`;
    const next = { ...completed, [key]: !completed[key] };
    setCompleted(next);
    localStorage.setItem('lp_completed', JSON.stringify(next));
  };

  const getProgress = (pathId, steps) => {
    const done = steps.filter((_, i) => completed[`${pathId}_${i}`]).length;
    return Math.round((done / steps.length) * 100);
  };

  const totalSteps = paths.reduce((sum, p) => sum + p.steps.length, 0);
  const totalCompleted = paths.reduce((sum, p) =>
    sum + p.steps.filter((_, i) => completed[`${p.id}_${i}`]).length, 0
  );
  const pathsStarted = paths.filter(p => p.steps.some((_, i) => completed[`${p.id}_${i}`])).length;
  const pathsMastered = paths.filter(p => p.steps.every((_, i) => completed[`${p.id}_${i}`])).length;

  return (
    <div style={{ padding: '0 20px 60px', maxWidth: '1200px', margin: '0 auto' }}>
      <GradientHeader
        title="Learning Paths"
        subtitle="Structured roadmaps from beginner to specialist — follow the steps, track your progress"
        icon={<FaRoute />}
      />

      {/* Overall Progress Dashboard */}
      {totalCompleted > 0 && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
            gap: '14px',
            marginBottom: '28px',
            padding: '20px 24px',
            background: 'var(--card-bg)',
            borderRadius: '16px',
            border: '1px solid var(--glass-border)',
          }}
        >
          {[
            { label: 'Steps Done', value: totalCompleted, total: totalSteps, icon: <FaCheckCircle />, color: '#34d399' },
            { label: 'Paths Started', value: pathsStarted, total: paths.length, icon: <FaRoute />, color: '#38bdf8' },
            { label: 'Paths Mastered', value: pathsMastered, total: paths.length, icon: <FaTrophy />, color: '#fbbf24' },
            { label: 'Overall', value: `${Math.round((totalCompleted / totalSteps) * 100)}%`, icon: <FaBolt />, color: '#a78bfa' },
          ].map((stat) => (
            <div key={stat.label} style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '22px', color: stat.color, marginBottom: '4px' }}>{stat.icon}</div>
              <div style={{ fontSize: '22px', fontWeight: '800', color: 'var(--text)' }}>
                {stat.total ? `${stat.value}/${stat.total}` : stat.value}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-lighter)', fontWeight: '600' }}>{stat.label}</div>
            </div>
          ))}
        </motion.div>
      )}
      {/* Path Cards Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(270px, 1fr))', gap: '20px', margin: '30px 0' }}>
        {paths.map((path, i) => {
          const progress = getProgress(path.id, path.steps);
          const isExpert = path.id === 'redteam';
          return (
            <motion.div
              key={path.id}
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.1 }}
              onClick={() => setActivePath(activePath?.id === path.id ? null : path)}
              style={{
                padding: '24px',
                cursor: 'pointer',
                background: `linear-gradient(135deg, ${path.color}${isExpert ? '20' : '12'} 0%, var(--card-bg) 100%)`,
                border: activePath?.id === path.id ? `2px solid ${path.color}88` : `1px solid ${path.color}33`,
                borderRadius: '16px',
                boxShadow: isExpert ? `0 0 32px ${path.color}25` : 'none',
                position: 'relative',
                overflow: 'hidden',
              }}
              whileHover={{ y: -6, boxShadow: `0 16px 40px ${path.color}30` }}
              whileTap={{ scale: 0.98 }}
            >
              {isExpert && (
                <div style={{
                  position: 'absolute', top: '12px', right: '12px',
                  background: 'linear-gradient(135deg, #f87171, #fb923c)',
                  color: 'white', fontSize: '9px', fontWeight: '900',
                  padding: '3px 8px', borderRadius: '10px', letterSpacing: '0.5px',
                  textTransform: 'uppercase',
                }}>⚡ Expert</div>
              )}
              <div style={{ fontSize: '36px', color: path.color, marginBottom: '12px' }}>
                {typeof path.icon === 'string' ? path.icon : path.icon}
              </div>
              <h3 style={{ color: 'var(--text)', fontWeight: '800', marginBottom: '4px', fontSize: '18px' }}>{path.title}</h3>
              <p style={{ color: path.color, fontSize: '13px', fontWeight: '600', marginBottom: '12px' }}>{path.subtitle}</p>
              <div style={{ display: 'flex', gap: '10px', marginBottom: '16px', flexWrap: 'wrap' }}>
                <span style={{ background: `${path.color}22`, color: path.color, fontSize: '11px', padding: '3px 8px', borderRadius: '12px', fontWeight: '700' }}>
                  {path.difficulty}
                </span>
                <span style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '11px', color: 'var(--text-lighter)' }}>
                  <FaClock /> {path.duration}
                </span>
                <span style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '11px', color: 'var(--text-lighter)' }}>
                  <FaLayerGroup /> {path.steps.length} steps
                </span>
              </div>
              {/* Progress bar */}
              <div style={{ height: '4px', background: `${path.color}22`, borderRadius: '4px', overflow: 'hidden' }}>
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${progress}%` }}
                  transition={{ duration: 0.8, delay: i * 0.1 + 0.3 }}
                  style={{ height: '100%', background: path.color, borderRadius: '4px' }}
                />
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '8px' }}>
                <span style={{ fontSize: '11px', color: 'var(--text-lighter)' }}>
                  {progress === 100 ? '🏆 Complete!' : `${progress}% complete`}
                </span>
                <motion.span animate={{ x: activePath?.id === path.id ? 4 : 0 }} style={{ color: path.color, fontSize: '13px' }}>
                  <FaChevronRight />
                </motion.span>
              </div>
            </motion.div>
          );
        })}
      </div>

      {/* Expanded Path Steps */}
      <AnimatePresence>
        {activePath && (
          <motion.div
            key={activePath.id}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            style={{
              background: 'var(--card-bg)',
              border: `2px solid ${activePath.color}44`,
              borderRadius: '20px',
              padding: '32px',
              marginTop: '12px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '28px' }}>
              <div style={{ fontSize: '40px', color: activePath.color }}>{activePath.icon}</div>
              <div>
                <h2 style={{ color: 'var(--text)', fontWeight: '800', margin: 0, fontSize: '24px' }}>{activePath.title}</h2>
                <p style={{ color: 'var(--text-light)', margin: 0 }}>Follow these steps in order to build solid skills</p>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {activePath.steps.map((step, idx) => {
                const isDone = completed[`${activePath.id}_${idx}`];
                return (
                  <motion.div
                    key={idx}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: idx * 0.06 }}
                    style={{
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: '16px',
                      padding: '16px 20px',
                      borderRadius: '12px',
                      background: isDone ? `${activePath.color}12` : 'var(--bg2)',
                      border: `1px solid ${isDone ? activePath.color + '44' : 'var(--border)'}`,
                      transition: 'all 0.3s',
                    }}
                  >
                    {/* Step number / check */}
                    <button
                      onClick={() => toggleComplete(activePath.id, idx)}
                      title="Mark as complete"
                      style={{
                        flexShrink: 0,
                        width: '32px', height: '32px',
                        borderRadius: '50%',
                        border: `2px solid ${isDone ? activePath.color : 'var(--border)'}`,
                        background: isDone ? activePath.color : 'transparent',
                        color: isDone ? 'white' : 'var(--text-lighter)',
                        cursor: 'pointer',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        fontSize: isDone ? '14px' : '12px',
                        fontWeight: '700',
                        transition: 'all 0.3s',
                      }}
                    >
                      {isDone ? <FaCheckCircle /> : idx + 1}
                    </button>

                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px', flexWrap: 'wrap' }}>
                        <span style={{ fontWeight: '700', color: isDone ? activePath.color : 'var(--text)', fontSize: '15px', textDecoration: isDone ? 'line-through' : 'none', opacity: isDone ? 0.7 : 1 }}>
                          {step.title}
                        </span>
                        <span style={{ background: `${typeColors[step.type]}22`, color: typeColors[step.type], fontSize: '10px', padding: '2px 7px', borderRadius: '10px', fontWeight: '700' }}>
                          {typeLabels[step.type]}
                        </span>
                      </div>
                      <p style={{ fontSize: '13px', color: 'var(--text-light)', margin: 0, lineHeight: '1.5' }}>{step.description}</p>
                    </div>

                    <motion.button
                      onClick={() => navigate(step.link)}
                      whileHover={{ scale: 1.05 }}
                      whileTap={{ scale: 0.95 }}
                      style={{
                        flexShrink: 0,
                        padding: '7px 14px',
                        borderRadius: '8px',
                        border: `1px solid ${activePath.color}44`,
                        background: `${activePath.color}18`,
                        color: activePath.color,
                        cursor: 'pointer',
                        fontSize: '12px',
                        fontWeight: '700',
                        display: 'flex', alignItems: 'center', gap: '5px',
                      }}
                    >
                      Go <FaArrowRight />
                    </motion.button>
                  </motion.div>
                );
              })}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default LearningPaths;
