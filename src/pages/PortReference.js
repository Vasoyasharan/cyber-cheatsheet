import { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import { FaNetworkWired, FaSearch, FaCopy, FaTimes } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { copyToClipboard } from '../utils/copyToClipboard';
import GradientHeader from '../components/UI/GradientHeader';

const PORTS = [
  { port: 20, proto: 'TCP', service: 'FTP Data', risk: 'Medium', description: 'FTP active mode data transfer. Often misconfigured to allow anonymous login.' },
  { port: 21, proto: 'TCP', service: 'FTP Control', risk: 'High', description: 'FTP command channel. Anonymous login, plaintext credentials, brute-forceable.' },
  { port: 22, proto: 'TCP', service: 'SSH', risk: 'Medium', description: 'Secure Shell — encrypted remote access. Check for weak passwords, old algorithms (diffie-hellman-group1-sha1), and version vulnerabilities.' },
  { port: 23, proto: 'TCP', service: 'Telnet', risk: 'Critical', description: 'Plaintext remote access — all credentials and data sent unencrypted. Should never be used.' },
  { port: 25, proto: 'TCP', service: 'SMTP', risk: 'Medium', description: 'Email sending. Check for open relay (allows external parties to send email through it). Enumerate users with VRFY/EXPN commands.' },
  { port: 53, proto: 'TCP/UDP', service: 'DNS', risk: 'High', description: 'Domain Name System. DNS zone transfer (AXFR) can leak all hostnames. UDP for queries, TCP for large responses/zone transfers.' },
  { port: 67, proto: 'UDP', service: 'DHCP Server', risk: 'Medium', description: 'DHCP server. Rogue DHCP attacks can redirect DNS and gateway, enabling MitM attacks.' },
  { port: 68, proto: 'UDP', service: 'DHCP Client', risk: 'Low', description: 'DHCP client. Used to receive IP configuration from a DHCP server.' },
  { port: 69, proto: 'UDP', service: 'TFTP', risk: 'Critical', description: 'Trivial FTP — no authentication. Commonly used for network device configs and boot images.' },
  { port: 80, proto: 'TCP', service: 'HTTP', risk: 'High', description: 'Unencrypted web traffic. All data is visible to MitM. Test for XSS, SQLi, IDOR, file inclusion.' },
  { port: 88, proto: 'TCP/UDP', service: 'Kerberos', risk: 'High', description: 'Kerberos authentication (Active Directory). Kerberoasting, AS-REP Roasting, and Golden/Silver ticket attacks target this port.' },
  { port: 110, proto: 'TCP', service: 'POP3', risk: 'Medium', description: 'Post Office Protocol — email retrieval. Plaintext by default. Brute-force credentials.' },
  { port: 111, proto: 'TCP/UDP', service: 'RPC Portmapper', risk: 'Medium', description: 'Remote Procedure Call portmapper. Used to map RPC services to port numbers. Enumerate with rpcinfo.' },
  { port: 119, proto: 'TCP', service: 'NNTP', risk: 'Low', description: 'Network News Transfer Protocol. Rarely used, but can expose sensitive files if misconfigured.' },
  { port: 123, proto: 'UDP', service: 'NTP', risk: 'Medium', description: 'Network Time Protocol. Monlist command can be exploited for DDoS amplification.' },
  { port: 135, proto: 'TCP', service: 'MSRPC', risk: 'High', description: 'Microsoft RPC endpoint mapper. Used for many Windows services. MS03-026 (Blaster worm) and many DCOM vulnerabilities.' },
  { port: 137, proto: 'UDP', service: 'NetBIOS NS', risk: 'High', description: 'NetBIOS Name Service. Used for Windows name resolution. Vulnerable to LLMNR/NBT-NS poisoning attacks.' },
  { port: 138, proto: 'UDP', service: 'NetBIOS Datagram', risk: 'Medium', description: 'NetBIOS datagram service for connectionless communication between Windows hosts.' },
  { port: 139, proto: 'TCP', service: 'NetBIOS Session', risk: 'High', description: 'NetBIOS session service. SMB over NetBIOS. Enumerate shares, users with nbtscan, enum4linux.' },
  { port: 143, proto: 'TCP', service: 'IMAP', risk: 'Medium', description: 'Internet Message Access Protocol — email retrieval. Plaintext by default; brute-forceable.' },
  { port: 161, proto: 'UDP', service: 'SNMP', risk: 'High', description: 'Simple Network Management Protocol. Default community strings "public"/"private" expose device configs, routing tables, ARP cache.' },
  { port: 162, proto: 'UDP', service: 'SNMP Trap', risk: 'Medium', description: 'SNMP trap receiver — listens for alert messages from network devices.' },
  { port: 179, proto: 'TCP', service: 'BGP', risk: 'High', description: 'Border Gateway Protocol — backbone internet routing. Route hijacking can redirect global traffic.' },
  { port: 389, proto: 'TCP/UDP', service: 'LDAP', risk: 'High', description: 'Lightweight Directory Access Protocol. Enumerate AD users, groups, policies. Often allows anonymous bind in misconfigured environments.' },
  { port: 443, proto: 'TCP', service: 'HTTPS', risk: 'Medium', description: 'Encrypted web traffic (TLS). Test for weak ciphers (SSLv3, TLS1.0), certificate issues, and all web vulnerabilities despite encryption.' },
  { port: 445, proto: 'TCP', service: 'SMB', risk: 'Critical', description: 'Server Message Block — Windows file sharing. EternalBlue (MS17-010), PrintNightmare, PetitPotam, Pass-the-Hash. Most dangerous open port in a Windows network.' },
  { port: 465, proto: 'TCP', service: 'SMTPS', risk: 'Low', description: 'SMTP over SSL — encrypted email submission.' },
  { port: 500, proto: 'UDP', service: 'IKE (IPsec)', risk: 'Medium', description: 'Internet Key Exchange for VPN. Fingerprint VPN type and version; check for aggressive mode.' },
  { port: 512, proto: 'TCP', service: 'rexec', risk: 'Critical', description: 'Remote execution — no encryption, easily sniffed.' },
  { port: 513, proto: 'TCP', service: 'rlogin', risk: 'Critical', description: 'Remote login — plaintext, no strong auth. Trust relationships exploitable.' },
  { port: 514, proto: 'TCP/UDP', service: 'Syslog/RSH', risk: 'High', description: 'UDP: remote syslog. TCP: Remote Shell — plaintext, no password required if trusted host.' },
  { port: 548, proto: 'TCP', service: 'AFP', risk: 'Medium', description: 'Apple Filing Protocol — macOS file sharing. Check for anonymous access and credential exposure.' },
  { port: 554, proto: 'TCP', service: 'RTSP', risk: 'Medium', description: 'Real Time Streaming Protocol — IP cameras and streaming. Often no authentication on IoT devices.' },
  { port: 587, proto: 'TCP', service: 'SMTP Submission', risk: 'Low', description: 'Authenticated SMTP email submission — modern alternative to port 25.' },
  { port: 631, proto: 'TCP', service: 'IPP (CUPS)', risk: 'Medium', description: 'Internet Printing Protocol. CVE-2024-47076: CUPS RCE vulnerability chain via mDNS/IPP.' },
  { port: 636, proto: 'TCP', service: 'LDAPS', risk: 'Medium', description: 'LDAP over SSL/TLS. Check certificate validity and still enumerate AD objects.' },
  { port: 873, proto: 'TCP', service: 'rsync', risk: 'High', description: 'Remote file sync. Misconfigured rsync allows unauthenticated file read/write — common CTF vector.' },
  { port: 993, proto: 'TCP', service: 'IMAPS', risk: 'Low', description: 'IMAP over SSL/TLS — encrypted email retrieval.' },
  { port: 995, proto: 'TCP', service: 'POP3S', risk: 'Low', description: 'POP3 over SSL/TLS — encrypted email retrieval.' },
  { port: 1080, proto: 'TCP', service: 'SOCKS Proxy', risk: 'High', description: 'SOCKS proxy. Open SOCKS proxies allow attackers to tunnel traffic. Used for pivoting.' },
  { port: 1433, proto: 'TCP', service: 'MSSQL', risk: 'Critical', description: 'Microsoft SQL Server. SA account brute force, xp_cmdshell for OS command execution, linked servers.' },
  { port: 1521, proto: 'TCP', service: 'Oracle DB', risk: 'High', description: 'Oracle Database listener. Default credentials, TNS poisoning, SID enumeration.' },
  { port: 2049, proto: 'TCP/UDP', service: 'NFS', risk: 'High', description: 'Network File System. Misconfigured NFS exports allow unauthenticated file access. Check /etc/exports.' },
  { port: 2375, proto: 'TCP', service: 'Docker API', risk: 'Critical', description: 'Unauthenticated Docker daemon API. Container escape to host is trivial when exposed.' },
  { port: 2376, proto: 'TCP', service: 'Docker TLS', risk: 'High', description: 'Docker API with TLS — still dangerous if certificates are weak.' },
  { port: 3000, proto: 'TCP', service: 'Node.js/Dev', risk: 'Medium', description: 'Common development server port (Node.js, Grafana, React). Check for exposed dev tools.' },
  { port: 3128, proto: 'TCP', service: 'Squid Proxy', risk: 'Medium', description: 'Squid HTTP proxy. Misconfigured proxies can be used for SSRF and to reach internal services.' },
  { port: 3306, proto: 'TCP', service: 'MySQL', risk: 'High', description: 'MySQL database. Default root with no password, remote login enabled, SQL injection to file read/write (LOAD_FILE, INTO OUTFILE).' },
  { port: 3389, proto: 'TCP', service: 'RDP', risk: 'Critical', description: 'Remote Desktop Protocol. BlueKeep (CVE-2019-0708), DejaBlue, brute force, credential stuffing. Highest-value target in Windows networks.' },
  { port: 4444, proto: 'TCP', service: 'Metasploit Default', risk: 'High', description: 'Default Metasploit listener port. Seeing this open on a host is a strong IOC for compromise.' },
  { port: 4505, proto: 'TCP', service: 'SaltStack', risk: 'Critical', description: 'SaltStack master publish port. CVE-2020-11651/11652 — unauthenticated RCE.' },
  { port: 5432, proto: 'TCP', service: 'PostgreSQL', risk: 'High', description: 'PostgreSQL database. Default postgres user, COPY TO/FROM to read/write files, pg_read_file().' },
  { port: 5601, proto: 'TCP', service: 'Kibana', risk: 'High', description: 'Kibana dashboard. Exposed without auth gives access to all Elasticsearch data. Check for CVE-2019-7609 (RCE).' },
  { port: 5900, proto: 'TCP', service: 'VNC', risk: 'Critical', description: 'Virtual Network Computing — remote desktop. Often no password or weak password. Plaintext data transmission.' },
  { port: 5985, proto: 'TCP', service: 'WinRM HTTP', risk: 'High', description: 'Windows Remote Management (HTTP). Used by Evil-WinRM for remote administration when creds are known.' },
  { port: 5986, proto: 'TCP', service: 'WinRM HTTPS', risk: 'High', description: 'Windows Remote Management (HTTPS). Encrypted but same attack surface as 5985.' },
  { port: 6379, proto: 'TCP', service: 'Redis', risk: 'Critical', description: 'Redis in-memory store. Often no auth by default. Write SSH authorized_keys, cron jobs, or web shells directly via Redis commands.' },
  { port: 6443, proto: 'TCP', service: 'Kubernetes API', risk: 'Critical', description: 'Kubernetes API server. Unauthenticated access grants cluster control. Check RBAC misconfigurations.' },
  { port: 7001, proto: 'TCP', service: 'WebLogic', risk: 'Critical', description: 'Oracle WebLogic Server. Multiple unauthenticated RCEs (CVE-2019-2725, CVE-2020-14882).' },
  { port: 8080, proto: 'TCP', service: 'HTTP Alternate', risk: 'High', description: 'Alternative HTTP port — common for web apps, proxies, Jenkins, Tomcat. Treat same as port 80.' },
  { port: 8443, proto: 'TCP', service: 'HTTPS Alternate', risk: 'Medium', description: 'Alternative HTTPS port. Tomcat manager, web app panels often here.' },
  { port: 8888, proto: 'TCP', service: 'Jupyter Notebook', risk: 'Critical', description: 'Jupyter Notebook — unauthenticated access provides a full Python execution environment on the server.' },
  { port: 9000, proto: 'TCP', service: 'PHP-FPM / SonarQube', risk: 'High', description: 'PHP FastCGI — Nginx misconfig can expose this. Also SonarQube code analysis.' },
  { port: 9200, proto: 'TCP', service: 'Elasticsearch', risk: 'Critical', description: 'Elasticsearch REST API. No auth by default in older versions — read/delete/modify all indexed data.' },
  { port: 9300, proto: 'TCP', service: 'Elasticsearch Cluster', risk: 'High', description: 'Elasticsearch inter-node communication. Java deserialization vulnerabilities.' },
  { port: 27017, proto: 'TCP', service: 'MongoDB', risk: 'Critical', description: 'MongoDB. No authentication by default — full read/write access to all databases over the network.' },
  { port: 47808, proto: 'UDP', service: 'BACnet (SCADA)', risk: 'High', description: 'Building Automation Control network — industrial control systems. Exposed to internet = critical infrastructure risk.' },
];

const riskColor = { Critical: '#f87171', High: '#fbbf24', Medium: '#38bdf8', Low: '#34d399' };
const riskOrder = { Critical: 0, High: 1, Medium: 2, Low: 3 };

const PortReference = () => {
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState('All');
  const [protoFilter, setProtoFilter] = useState('All');
  const [sortBy, setSortBy] = useState('port');

  const filtered = useMemo(() => PORTS.filter(p => {
    const q = search.toLowerCase();
    const matchSearch = String(p.port).includes(q) || p.service.toLowerCase().includes(q) || p.description.toLowerCase().includes(q);
    const matchRisk = riskFilter === 'All' || p.risk === riskFilter;
    const matchProto = protoFilter === 'All' || p.proto.includes(protoFilter);
    return matchSearch && matchRisk && matchProto;
  }).sort((a, b) => sortBy === 'port' ? a.port - b.port : riskOrder[a.risk] - riskOrder[b.risk]), [search, riskFilter, protoFilter, sortBy]);

  return (
    <div style={{ padding: '0 20px 60px', maxWidth: '1200px', margin: '0 auto' }}>
      <GradientHeader
        title="Port Reference"
        subtitle={`${PORTS.length} common ports — service names, attack vectors, and risk ratings at a glance`}
        icon={<FaNetworkWired />}
      />

      {/* Filters */}
      <div style={{ display: 'flex', gap: '12px', margin: '24px 0', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: '220px', display: 'flex', alignItems: 'center', gap: '10px', background: 'var(--card-bg)', border: '1.5px solid var(--border-strong)', borderRadius: '12px', padding: '10px 16px' }}>
          <FaSearch style={{ color: 'var(--primary)' }} />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search port, service, or description..."
            style={{ border: 'none', background: 'transparent', color: 'var(--text)', outline: 'none', width: '100%', fontSize: '14px' }} />
          {search && <button onClick={() => setSearch('')} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-lighter)' }}><FaTimes /></button>}
        </div>
        {['All', 'Critical', 'High', 'Medium', 'Low'].map(r => (
          <motion.button key={r} onClick={() => setRiskFilter(r)} whileHover={{ scale: 1.04 }}
            style={{ padding: '10px 14px', borderRadius: '12px', border: `1.5px solid ${riskFilter === r ? (riskColor[r] || 'var(--primary)') : 'var(--border)'}`, background: riskFilter === r ? `${riskColor[r] || 'var(--primary)'}22` : 'var(--card-bg)', color: riskFilter === r ? (riskColor[r] || 'var(--primary)') : 'var(--text-light)', fontWeight: '700', fontSize: '12px', cursor: 'pointer' }}>
            {r}
          </motion.button>
        ))}
        <select value={protoFilter} onChange={e => setProtoFilter(e.target.value)}
          style={{ padding: '10px 14px', borderRadius: '12px', border: '1.5px solid var(--border)', background: 'var(--card-bg)', color: 'var(--text)', fontSize: '13px', cursor: 'pointer' }}>
          <option>All</option><option>TCP</option><option>UDP</option>
        </select>
        <select value={sortBy} onChange={e => setSortBy(e.target.value)}
          style={{ padding: '10px 14px', borderRadius: '12px', border: '1.5px solid var(--border)', background: 'var(--card-bg)', color: 'var(--text)', fontSize: '13px', cursor: 'pointer' }}>
          <option value="port">Sort by Port</option>
          <option value="risk">Sort by Risk</option>
        </select>
      </div>

      <p style={{ fontSize: '12px', color: 'var(--text-lighter)', marginBottom: '16px' }}>{filtered.length} ports shown</p>

      {/* Table */}
      <div style={{ background: 'var(--card-bg)', borderRadius: '16px', border: '1px solid var(--border)', overflow: 'hidden' }}>
        {/* Header */}
        <div style={{ display: 'grid', gridTemplateColumns: '80px 100px 180px 90px 1fr 50px', gap: '0', padding: '12px 20px', background: 'var(--bg2)', borderBottom: '1px solid var(--border)' }}>
          {['Port', 'Proto', 'Service', 'Risk', 'Description', ''].map(h => (
            <span key={h} style={{ fontSize: '11px', fontWeight: '800', color: 'var(--text-lighter)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>{h}</span>
          ))}
        </div>
        {/* Rows */}
        {filtered.map((p, i) => {
          const rc = riskColor[p.risk] || '#a78bfa';
          return (
            <motion.div key={p.port} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: Math.min(i * 0.02, 0.4) }}
              style={{ display: 'grid', gridTemplateColumns: '80px 100px 180px 90px 1fr 50px', gap: '0', padding: '14px 20px', borderBottom: '1px solid var(--border)', alignItems: 'center', transition: 'background 0.2s' }}
              onMouseEnter={e => e.currentTarget.style.background = `${rc}08`}
              onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
              <code style={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: '800', fontSize: '14px', color: 'var(--primary)' }}>{p.port}</code>
              <span style={{ fontSize: '11px', fontWeight: '600', color: 'var(--text-lighter)' }}>{p.proto}</span>
              <span style={{ fontWeight: '700', color: 'var(--text)', fontSize: '13px' }}>{p.service}</span>
              <span style={{ background: `${rc}22`, color: rc, fontSize: '10px', padding: '3px 8px', borderRadius: '10px', fontWeight: '700', width: 'fit-content' }}>{p.risk}</span>
              <span style={{ fontSize: '12px', color: 'var(--text-light)', lineHeight: '1.5', paddingRight: '12px' }}>{p.description}</span>
              <motion.button onClick={() => { copyToClipboard(String(p.port)); toast.success(`Port ${p.port} copied!`, { position: 'bottom-right', autoClose: 1200, hideProgressBar: true }); }}
                whileHover={{ scale: 1.1 }} style={{ background: 'transparent', border: 'none', color: 'var(--text-lighter)', cursor: 'pointer', fontSize: '14px' }}>
                <FaCopy />
              </motion.button>
            </motion.div>
          );
        })}
      </div>
    </div>
  );
};

export default PortReference;
