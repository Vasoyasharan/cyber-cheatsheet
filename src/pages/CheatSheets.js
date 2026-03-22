import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaSearch, FaLinux, FaWindows, FaGlobe, FaUserSecret, FaCode, FaServer, FaUserShield, FaCloud, FaFilter, FaTimes, FaBook, FaShieldAlt, FaRocket, FaStar, FaClock, FaLightbulb, FaChartLine, FaLock, FaBrain, FaMobile, FaNetworkWired, FaBot, FaTools } from 'react-icons/fa';
import LinuxPrivEsc from '../components/CheatSheets/LinuxPrivEsc';
import WindowsPrivEsc from '../components/CheatSheets/WindowsPrivEsc';
import WebAppTesting from '../components/CheatSheets/WebAppTesting';
import ActiveDirectoryAttacks from '../components/CheatSheets/ActiveDirectoryAttacks';
import InitialAccessTechniques from '../components/CheatSheets/InitialAccessTechniques';
import PayloadGeneration from '../components/CheatSheets/PayloadGeneration';
import C2Frameworks from '../components/CheatSheets/C2Frameworks';
import PostExploitation from '../components/CheatSheets/PostExploitation';
import CloudPentesting from '../components/CheatSheets/CloudPentesting';
import AnimatedCard from '../components/UI/AnimatedCard';
import GradientHeader from '../components/UI/GradientHeader';
import DifficultyBadge from '../components/UI/DifficultyBadge';
import { toast } from 'react-toastify';

const CheatSheets = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [activeSheet, setActiveSheet] = useState('linux');
  const [difficultyFilter, setDifficultyFilter] = useState('all');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [favorites, setFavorites] = useState([]);
  const [showAdvancedTips, setShowAdvancedTips] = useState(false);

  const cheatSheets = [
    { 
      id: 'linux', 
      name: 'Linux PrivEsc', 
      icon: <FaLinux />, 
      component: <LinuxPrivEsc />,
      category: 'Privilege Escalation',
      difficulty: 'beginner',
      description: 'Master privilege escalation on Linux systems',
      color: '#FF9800',
      timeToRead: '15-20 min',
      techniques: 25,
      tools: ['sudo', 'SUID', 'Capabilities', 'Cron jobs'],
      prerequisites: ['Linux basics', 'File permissions', 'Shell scripting'],
      advancedTips: [
        'Check for misconfigured SUID binaries using find command',
        'Exploit cronjobs running as root for persistent access',
        'Use kernel exploits for privilege escalation on outdated systems'
      ]
    },
    { 
      id: 'windows', 
      name: 'Windows PrivEsc', 
      icon: <FaWindows />, 
      component: <WindowsPrivEsc />,
      category: 'Privilege Escalation',
      difficulty: 'intermediate',
      description: 'Escalate privileges on Windows platforms',
      color: '#2196F3',
      timeToRead: '18-25 min',
      techniques: 30,
      tools: ['Registry', 'UAC bypass', 'Token impersonation', 'Juicy Potato'],
      prerequisites: ['Windows fundamentals', 'Registry knowledge', 'AD basics'],
      advancedTips: [
        'Use PrintSpoofer for SYSTEM access on patched systems',
        'Leverage token impersonation with multiple processes',
        'Exploit Windows Update client for persistence'
      ]
    },
    { 
      id: 'web', 
      name: 'Web App Testing', 
      icon: <FaGlobe />, 
      component: <WebAppTesting />,
      category: 'Web Security',
      difficulty: 'beginner',
      description: 'Complete web application penetration testing framework',
      color: '#4CAF50',
      timeToRead: '20-25 min',
      techniques: 28,
      tools: ['Burp Suite', 'OWASP ZAP', 'curl', 'Postman'],
      prerequisites: ['HTTP basics', 'Web technologies', 'JavaScript'],
      advancedTips: [
        'Chain multiple vulnerabilities for greater impact',
        'Test for authorization flaws across all endpoints',
        'Use API fuzzing for discovering hidden parameters'
      ]
    },
    { 
      id: 'active',
      name: 'Active Directory',
      icon: <FaShieldAlt />, 
      component: <ActiveDirectoryAttacks />,
      category: 'Enterprise Security',
      difficulty: 'intermediate',
      description: 'Advanced AD enumeration and exploitation techniques',
      color: '#9C27B0',
      timeToRead: '22-30 min',
      techniques: 35,
      tools: ['BloodHound', 'Rubeus', 'Impacket', 'GetADUsers.ps1'],
      prerequisites: ['Windows networking', 'Domain basics', 'Kerberos'],
      advancedTips: [
        'Use BloodHound for path finding to DA privileges',
        'Perform Kerberoasting on SPNs in large AD forests',
        'Chain resource-based delegation attacks'
      ]
    },
    { 
      id: 'initial',
      name: 'Initial Access',
      icon: <FaUserSecret />, 
      component: <InitialAccessTechniques />,
      category: 'Red Teaming',
      difficulty: 'intermediate',
      description: 'Proven techniques for gaining initial system access',
      color: '#F44336',
      timeToRead: '18-22 min',
      techniques: 20,
      tools: ['Evilginx2', 'GoPhish', 'Social-Engineer Toolkit'],
      prerequisites: ['General security knowledge', 'Social engineering', 'Phishing'],
      advancedTips: [
        'Use browser-in-the-browser attacks for credential harvesting',
        'Combine phishing with out-of-band channels for detection evasion',
        'Create convincing pretext frameworks'
      ]
    },
    { 
      id: 'payload',
      name: 'Payload Generation',
      icon: <FaCode />, 
      component: <PayloadGeneration />,
      category: 'Red Teaming',
      difficulty: 'advanced',
      description: 'Create and obfuscate malicious payloads',
      color: '#FF5722',
      timeToRead: '25-30 min',
      techniques: 32,
      tools: ['msfvenom', 'obfuscators', '.NET compilation'],
      prerequisites: ['Exploitation knowledge', 'Coding basics', 'Assembly'],
      advancedTips: [
        'Use polymorphic engines to evade detection',
        'Generate fileless payloads for Windows defender bypass',
        'Leverage process injection for silent execution'
      ]
    },
    { 
      id: 'c2',
      name: 'C2 Frameworks',
      icon: <FaServer />, 
      component: <C2Frameworks />,
      category: 'Red Teaming',
      difficulty: 'advanced',
      description: 'Command and Control operations and infrastructure',
      color: '#3F51B5',
      timeToRead: '28-35 min',
      techniques: 40,
      tools: ['Cobalt Strike', 'Sliver', 'Empire', 'Mythic'],
      prerequisites: ['Advanced exploitation', 'Networking', 'Linux/Windows systems'],
      advancedTips: [
        'Use domain fronting for evasive C2 communications',
        'Implement HTTPS beaconing with certificate pinning',
        'Chain multiple C2 frameworks for resilience'
      ]
    },
    { 
      id: 'post',
      name: 'Post Exploitation',
      icon: <FaUserShield />, 
      component: <PostExploitation />,
      category: 'Red Teaming',
      difficulty: 'advanced',
      description: 'Actions and techniques after gaining system access',
      color: '#607D8B',
      timeToRead: '22-28 min',
      techniques: 38,
      tools: ['Mimikatz', 'secretsdump.py', 'LaZagne'],
      prerequisites: ['Exploitation basics', 'System administration', 'Credential access'],
      advancedTips: [
        'Use in-memory credential harvesting to avoid disk writes',
        'Implement persistence mechanisms across multiple layers',
        'Perform privilege abuse for lateral movement'
      ]
    },
    { 
      id: 'cloud',
      name: 'Cloud Pentesting',
      icon: <FaCloud />, 
      component: <CloudPentesting />,
      category: 'Cloud Security',
      difficulty: 'advanced',
      description: 'Security testing in cloud environments (AWS/Azure)',
      color: '#00BCD4',
      timeToRead: '25-32 min',
      techniques: 36,
      tools: ['CloudMapper', 'Prowler', 'ScoutSuite'],
      prerequisites: ['Cloud basics', 'Infrastructure knowledge', 'IAM understanding'],
      advancedTips: [
        'Test for overpermissioned IAM roles and policies',
        'Enumerate cloud storage buckets for exposed data',
        'Exploit service elevation for cross-account access'
      ]
    },
    { 
      id: 'reverseeng',
      name: 'Reverse Engineering',
      icon: <FaBrain />,
      component: null,
      category: 'Analysis',
      difficulty: 'advanced',
      description: 'Analyze and understand compiled binaries and malware',
      color: '#E91E63',
      timeToRead: '30-40 min',
      techniques: 45,
      tools: ['IDA Pro', 'Ghidra', 'x64dbg', 'Radare2'],
      prerequisites: ['Assembly language', 'CPU architecture', 'Debugging'],
      advancedTips: [
        'Use symbolic execution for vulnerability discovery',
        'Implement dynamic analysis for anti-analysis detection',
        'Chain multiple analysis techniques for malware behavior'
      ]
    },
    { 
      id: 'crypto',
      name: 'Cryptography',
      icon: <FaLock />,
      component: null,
      category: 'Analysis',
      difficulty: 'advanced',
      description: 'Understand encryption, hashing, and cryptographic protocols',
      color: '#4CAF50',
      timeToRead: '25-30 min',
      techniques: 28,
      tools: ['OpenSSL', 'GPG', 'hashcat', 'John the Ripper'],
      prerequisites: ['Math basics', 'Boolean algebra', 'Networking'],
      advancedTips: [
        'Identify weak cryptographic implementations',
        'Exploit side-channel attacks on encryption',
        'Perform differential cryptanalysis'
      ]
    },
    { 
      id: 'mobile',
      name: 'Mobile Security',
      icon: <FaMobile />,
      component: null,
      category: 'Security Testing',
      difficulty: 'intermediate',
      description: 'Security testing for iOS and Android applications',
      color: '#00E5FF',
      timeToRead: '20-28 min',
      techniques: 32,
      tools: ['Frida', 'Charles Proxy', 'APKTool', 'Burp Suite'],
      prerequisites: ['Android/iOS basics', 'Mobile development', 'API testing'],
      advancedTips: [
        'Use Frida for certificate pinning bypass',
        'Perform memory dumping for sensitive data extraction',
        'Test for insecure local storage'
      ]
    },
    { 
      id: 'api',
      name: 'API Security',
      icon: <FaNetworkWired />,
      component: null,
      category: 'Web Security',
      difficulty: 'intermediate',
      description: 'RESTful and GraphQL API security testing methods',
      color: '#5C6BC0',
      timeToRead: '18-24 min',
      techniques: 26,
      tools: ['Postman', 'GraphQL Playground', 'Burp Suite'],
      prerequisites: ['HTTP basics', 'API knowledge', 'JSON/GraphQL'],
      advancedTips: [
        'Enumerate API endpoints using automation',
        'Test for rate limiting bypass techniques',
        'Exploit GraphQL field suggestions'
      ]
    },
    { 
      id: 'osint',
      name: 'OSINT Techniques',
      icon: <FaSearch />,
      component: null,
      category: 'Reconnaissance',
      difficulty: 'beginner',
      description: 'Open source intelligence gathering methodologies',
      color: '#795548',
      timeToRead: '15-20 min',
      techniques: 24,
      tools: ['Shodan', 'recon-ng', 'Maltego', 'theHarvester'],
      prerequisites: ['General security knowledge', 'Research skills'],
      advancedTips: [
        'Combine multiple OSINT sources for verification',
        'Use advanced Shodan queries for target discovery',
        'Leverage DNS records for infrastructure mapping'
      ]
    },
    { 
      id: 'incident',
      name: 'Incident Response',
      icon: <FaRocket />,
      component: null,
      category: 'Incident Response',
      difficulty: 'intermediate',
      description: 'Respond to and investigate security incidents',
      color: '#D32F2F',
      timeToRead: '20-26 min',
      techniques: 30,
      tools: ['YARA', 'Volatility', 'Autopsy', 'osquery'],
      prerequisites: ['Forensics basics', 'Windows/Linux systems', 'Log analysis'],
      advancedTips: [
        'Implement memory forensics for rootkit detection',
        'Chain timeline analysis with event logs',
        'Use YARA rules for IOC detection'
      ]
    }
  ];

  // Get unique categories
  const categories = ['all', ...new Set(cheatSheets.map(cs => cs.category))];
  const difficulties = ['all', 'beginner', 'intermediate', 'advanced'];

  // Filter sheets
  const filteredSheets = cheatSheets.filter(sheet => {
    const matchesSearch = sheet.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          sheet.category.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesDifficulty = difficultyFilter === 'all' || sheet.difficulty === difficultyFilter;
    const matchesCategory = categoryFilter === 'all' || sheet.category === categoryFilter;
    return matchesSearch && matchesDifficulty && matchesCategory;
  });

  const activeSheetData = cheatSheets.find(sheet => sheet.id === activeSheet);

  const toggleFavorite = (id) => {
    setFavorites(prev =>
      prev.includes(id) ? prev.filter(f => f !== id) : [...prev, id]
    );
    toast.success(favorites.includes(id) ? '❌ Removed from favorites' : '⭐ Added to favorites', {
      position: 'bottom-right',
      autoClose: 1000,
      hideProgressBar: true,
    });
  };

  // Animation variants
  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.08,
        delayChildren: 0.2,
      }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.5 } }
  };

  return (
    <div className="cheatsheets-page">
      <GradientHeader 
        title="Security References & Guides" 
        subtitle="Master cybersecurity with comprehensive, interactive cheat sheets"
        icon={<FaBook />}
      />

      {/* Quick Stats Section */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        style={{
          padding: '25px 20px',
          background: 'linear-gradient(135deg, var(--primary)11 0%, rgba(71, 118, 230, 0.05) 100%)',
          margin: '20px',
          borderRadius: '12px',
          maxWidth: '1200px',
          marginLeft: 'auto',
          marginRight: 'auto',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
          gap: '15px'
        }}
      >
        {[
          { icon: <FaBook />, label: 'Total Guides', value: cheatSheets.length },
          { icon: <FaRocket />, label: 'Total Techniques', value: cheatSheets.reduce((sum, cs) => sum + (cs.techniques || 0), 0) },
          { icon: <FaClock />, label: 'Categories', value: categories.length - 1 },
          { icon: <FaStar />, label: 'Favorites', value: favorites.length }
        ].map((stat, i) => (
          <motion.div
            key={i}
            whileHover={{ scale: 1.05 }}
            style={{
              padding: '15px',
              textAlign: 'center',
              background: 'var(--card-bg)',
              borderRadius: '10px',
              border: '1px solid var(--primary)',
              cursor: 'pointer'
            }}
          >
            <motion.div
              style={{ fontSize: '24px', marginBottom: '8px', color: 'var(--primary)' }}
              animate={{ y: [0, -3, 0] }}
              transition={{ duration: 2, repeat: Infinity, delay: i * 0.2 }}
            >
              {stat.icon}
            </motion.div>
            <div style={{ fontSize: '18px', fontWeight: 'bold', color: 'var(--text)' }}>
              {stat.value}
            </div>
            <div style={{ fontSize: '11px', opacity: 0.6, marginTop: '4px' }}>
              {stat.label}
            </div>
          </motion.div>
        ))}
      </motion.div>

      {/* Search Bar */}
      <motion.div
        className="search-bar"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        style={{ margin: '30px 20px' }}
      >
        <div className="search-input" style={{
          display: 'flex',
          alignItems: 'center',
          gap: '16px',
          background: 'var(--card-bg)',
          borderRadius: '50px',
          padding: '12px 24px',
          maxWidth: '1200px',
          margin: '0 auto',
          boxShadow: '0 4px 15px rgba(110, 72, 170, 0.15)'
        }}>
          <FaSearch className="search-icon" style={{ color: 'var(--primary)', fontSize: '16px', flexShrink: 0, marginRight: '4px' }} />
          <input
            type="text"
            placeholder="Search cheat sheets by name or category..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              flex: 1,
              padding: '8px 0',
              border: 'none',
              background: 'transparent',
              color: 'var(--text)',
              outline: 'none',
              fontSize: '14px',
              marginLeft: '8px'
            }}
          />
          {searchTerm && (
            <motion.button
              onClick={() => setSearchTerm('')}
              whileHover={{ scale: 1.1 }}
              style={{
                padding: '8px 15px',
                border: 'none',
                background: 'transparent',
                color: 'var(--text)',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center'
              }}
            >
              <FaTimes />
            </motion.button>
          )}
        </div>
      </motion.div>

      {/* Filter Section */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.35 }}
        style={{
          padding: '20px',
          maxWidth: '1200px',
          margin: '0 auto',
          display: 'flex',
          flexDirection: 'column',
          gap: '15px'
        }}
      >
        {/* Difficulty Filter */}
        <motion.div variants={containerVariants} initial="hidden" animate="visible">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
            <FaFilter style={{ color: 'var(--primary)', fontSize: '16px' }} />
            <span style={{ fontWeight: '700', color: 'var(--text)', fontSize: '14px' }}>Difficulty Level:</span>
          </div>
          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
            {difficulties.map((diff, i) => (
              <motion.button
                key={diff}
                onClick={() => setDifficultyFilter(diff)}
                variants={itemVariants}
                style={{
                  padding: '8px 16px',
                  borderRadius: '20px',
                  border: difficultyFilter === diff ? '2px solid var(--primary)' : '1px solid rgba(110, 72, 170, 0.2)',
                  background: difficultyFilter === diff ? 'linear-gradient(135deg, var(--primary), var(--secondary))' : 'var(--card-bg)',
                  color: difficultyFilter === diff ? 'white' : 'var(--text)',
                  cursor: 'pointer',
                  fontWeight: '600',
                  textTransform: 'capitalize',
                  transition: 'all 0.3s',
                  fontSize: '13px'
                }}
                whileHover={{ scale: 1.08, boxShadow: '0 5px 15px rgba(110, 72, 170, 0.2)' }}
                whileTap={{ scale: 0.95 }}
              >
                {diff === 'all' ? '📊 All' : diff === 'beginner' ? '🌱 Beginner' : diff === 'intermediate' ? '📈 Intermediate' : '⚡ Advanced'}
              </motion.button>
            ))}
          </div>
        </motion.div>

        {/* Category Filter */}
        <motion.div variants={containerVariants} initial="hidden" animate="visible">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
            <FaFilter style={{ color: 'var(--primary)', fontSize: '16px' }} />
            <span style={{ fontWeight: '700', color: 'var(--text)', fontSize: '14px' }}>Category:</span>
          </div>
          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
            {categories.map((cat, i) => (
              <motion.button
                key={cat}
                onClick={() => setCategoryFilter(cat)}
                variants={itemVariants}
                style={{
                  padding: '8px 16px',
                  borderRadius: '20px',
                  border: categoryFilter === cat ? '2px solid var(--primary)' : '1px solid rgba(110, 72, 170, 0.2)',
                  background: categoryFilter === cat ? 'linear-gradient(135deg, var(--primary), var(--secondary))' : 'var(--card-bg)',
                  color: categoryFilter === cat ? 'white' : 'var(--text)',
                  cursor: 'pointer',
                  fontWeight: '600',
                  textTransform: 'capitalize',
                  transition: 'all 0.3s',
                  fontSize: '13px'
                }}
                whileHover={{ scale: 1.08, boxShadow: '0 5px 15px rgba(110, 72, 170, 0.2)' }}
                whileTap={{ scale: 0.95 }}
              >
                {cat === 'all' ? '📊 All' : cat}
              </motion.button>
            ))}
          </div>
        </motion.div>
      </motion.div>

      {/* CheatSheets Grid with Enhanced Animations */}
      <motion.div
        className="cheatsheets-grid"
        variants={containerVariants}
        initial="hidden"
        animate="visible"
        style={{
          padding: '20px',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))',
          gap: '20px',
          maxWidth: '1200px',
          margin: '0 auto'
        }}
      >
        {filteredSheets.map((sheet, index) => (
          <AnimatedCard
            key={sheet.id}
            onClick={() => {
              setActiveSheet(sheet.id);
              setShowAdvancedTips(false);
            }}
            isActive={activeSheet === sheet.id}
            delay={index * 0.05}
          >
            <motion.div
              className="cheatsheet-card"
              style={{
                padding: '20px',
                cursor: 'pointer',
                textAlign: 'center',
                position: 'relative',
                overflow: 'hidden',
                height: '100%',
                display: 'flex',
                flexDirection: 'column'
              }}
              whileHover={{ y: -8 }}
            >
              {/* Colored background on hover */}
              <motion.div
                style={{
                  position: 'absolute',
                  inset: 0,
                  background: `linear-gradient(135deg, ${sheet.color}22 0%, transparent 100%)`,
                  opacity: 0,
                  zIndex: 0
                }}
                whileHover={{ opacity: 1 }}
                transition={{ duration: 0.3 }}
              />

              <motion.div
                className="cheatsheet-icon"
                style={{
                  fontSize: '45px',
                  marginBottom: '12px',
                  color: sheet.color,
                  position: 'relative',
                  zIndex: 1,
                  fontWeight: 'bold'
                }}
                animate={{ y: [0, -5, 0] }}
                transition={{ duration: 3, repeat: Infinity, delay: index * 0.15 }}
              >
                {sheet.icon}
              </motion.div>
              <h3 style={{ marginBottom: '8px', color: 'var(--text)', position: 'relative', zIndex: 1, fontWeight: '700' }}>
                {sheet.name}
              </h3>
              <p style={{
                fontSize: '12px',
                color: sheet.color,
                opacity: 0.8,
                marginBottom: '10px',
                fontWeight: '600',
                position: 'relative',
                zIndex: 1
              }}>
                {sheet.category}
              </p>
              <p style={{
                fontSize: '13px',
                color: 'var(--text)',
                opacity: 0.8,
                marginBottom: '12px',
                lineHeight: '1.4',
                flex: 1,
                position: 'relative',
                zIndex: 1
              }}>
                {sheet.description}
              </p>

              {/* Quick stats */}
              {sheet.techniques && (
                <motion.div
                  style={{
                    fontSize: '11px',
                    opacity: 0.6,
                    marginBottom: '12px',
                    position: 'relative',
                    zIndex: 1
                  }}
                >
                  📊 {sheet.techniques} techniques • ⏱️ {sheet.timeToRead}
                </motion.div>
              )}

              <div style={{ marginTop: 'auto', position: 'relative', zIndex: 1, display: 'flex', gap: '8px', alignItems: 'center', justifyContent: 'center' }}>
                <DifficultyBadge level={sheet.difficulty} size="sm" />
                <motion.button
                  onClick={(e) => {
                    e.stopPropagation();
                    toggleFavorite(sheet.id);
                  }}
                  whileHover={{ scale: 1.2 }}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: favorites.includes(sheet.id) ? '#FFD700' : 'var(--text)',
                    cursor: 'pointer',
                    fontSize: '16px',
                    opacity: favorites.includes(sheet.id) ? 1 : 0.5
                  }}
                >
                  <FaStar />
                </motion.button>
              </div>
            </motion.div>
          </AnimatedCard>
        ))}
      </motion.div>

      {filteredSheets.length === 0 && (
        <motion.div
          style={{
            textAlign: 'center',
            padding: '60px 20px',
            opacity: 0.6,
            color: 'var(--text)'
          }}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
        >
          <div style={{ fontSize: '48px', marginBottom: '15px' }}>🔍</div>
          <p style={{ fontSize: '16px' }}>No cheat sheets found matching your filters.</p>
          <p style={{ fontSize: '14px', opacity: 0.6 }}>Try adjusting your search or filters.</p>
        </motion.div>
      )}

      {/* CheatSheet Details Section */}
      {activeSheetData && (
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, type: 'spring', stiffness: 300 }}
          className="cheatsheet-container"
          style={{
            padding: '40px 20px',
            maxWidth: '1200px',
            margin: '50px auto 0',
            borderTop: `3px solid ${activeSheetData.color}`,
            marginRight: 'auto',
            marginLeft: 'auto'
          }}
        >
          {/* Header */}
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            style={{
              marginBottom: '30px',
              paddingBottom: '25px',
              borderBottom: `1px solid ${activeSheetData.color}33`,
              display: 'flex',
              alignItems: 'start',
              gap: '20px',
              flexWrap: 'wrap'
            }}
          >
            <motion.div
              style={{
                fontSize: '48px',
                color: activeSheetData.color,
                fontWeight: 'bold'
              }}
              animate={{ y: [0, -5, 0] }}
              transition={{ duration: 3, repeat: Infinity }}
            >
              {activeSheetData.icon}
            </motion.div>
            <div style={{ flex: 1 }}>
              <h2 style={{ margin: '0 0 8px 0', color: 'var(--text)', fontSize: '32px', fontWeight: '700' }}>
                {activeSheetData.name}
              </h2>
              <p style={{ margin: '0 0 15px 0', opacity: 0.8, fontSize: '15px' }}>
                {activeSheetData.description}
              </p>

              {/* Quick Info */}
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.15 }}
                style={{
                  display: 'flex',
                  gap: '20px',
                  flexWrap: 'wrap',
                  fontSize: '13px',
                  marginBottom: '15px'
                }}
              >
                {activeSheetData.timeToRead && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <FaClock style={{ color: activeSheetData.color, opacity: 0.7 }} />
                    <span>⏱️ {activeSheetData.timeToRead} read</span>
                  </div>
                )}
                {activeSheetData.techniques && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <FaRocket style={{ color: activeSheetData.color, opacity: 0.7 }} />
                    <span>📊 {activeSheetData.techniques} techniques</span>
                  </div>
                )}
              </motion.div>

              {/* Tools */}
              {activeSheetData.tools && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.18 }}
                  style={{ marginBottom: '12px' }}
                >
                  <p style={{ fontSize: '12px', fontWeight: '700', opacity: 0.6, marginBottom: '8px' }}>
                    🛠️ Tools & Resources:
                  </p>
                  <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                    {activeSheetData.tools.map((tool, i) => (
                      <motion.span
                        key={i}
                        style={{
                          background: `${activeSheetData.color}22`,
                          color: activeSheetData.color,
                          padding: '6px 12px',
                          borderRadius: '12px',
                          fontSize: '12px',
                          fontWeight: '600',
                          border: `1px solid ${activeSheetData.color}44`
                        }}
                        whileHover={{ scale: 1.08 }}
                      >
                        {tool}
                      </motion.span>
                    ))}
                  </div>
                </motion.div>
              )}

              {/* Prerequisites */}
              {activeSheetData.prerequisites && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.2 }}
                >
                  <p style={{ fontSize: '12px', fontWeight: '700', opacity: 0.6, marginBottom: '8px' }}>
                    📚 Prerequisites:
                  </p>
                  <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                    {activeSheetData.prerequisites.map((prereq, i) => (
                      <span
                        key={i}
                        style={{
                          background: 'var(--card-bg)',
                          padding: '6px 12px',
                          borderRadius: '12px',
                          fontSize: '11px',
                          color: 'var(--text)',
                          opacity: 0.7,
                          border: `1px solid ${activeSheetData.color}33`
                        }}
                      >
                        ✓ {prereq}
                      </span>
                    ))}
                  </div>
                </motion.div>
              )}
            </div>
            <DifficultyBadge level={activeSheetData.difficulty} size="md" />
          </motion.div>

          {/* Advanced Tips Toggle */}
          {activeSheetData.advancedTips && activeSheetData.advancedTips.length > 0 && (
            <motion.button
              onClick={() => setShowAdvancedTips(!showAdvancedTips)}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.25 }}
              style={{
                background: showAdvancedTips ? `${activeSheetData.color}22` : 'transparent',
                border: `1px solid ${activeSheetData.color}`,
                color: activeSheetData.color,
                borderRadius: '8px',
                padding: '10px 20px',
                cursor: 'pointer',
                fontWeight: '600',
                fontSize: '14px',
                marginBottom: '20px',
                display: 'flex',
                alignItems: 'center',
                gap: '8px'
              }}
              whileHover={{ scale: 1.05, background: `${activeSheetData.color}33` }}
            >
              <FaLightbulb /> {showAdvancedTips ? 'Hide' : 'Show'} Advanced Tips & Techniques
            </motion.button>
          )}

          {/* Advanced Tips */}
          {showAdvancedTips && activeSheetData.advancedTips && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3 }}
              style={{
                background: `${activeSheetData.color}11`,
                border: `1px solid ${activeSheetData.color}44`,
                borderRadius: '10px',
                padding: '20px',
                marginBottom: '30px'
              }}
            >
              <h4 style={{ margin: '0 0 15px 0', color: activeSheetData.color, fontSize: '16px', fontWeight: '700' }}>
                ⚡ Advanced Tips & Techniques
              </h4>
              <ul style={{ margin: 0, paddingLeft: '20px' }}>
                {activeSheetData.advancedTips.map((tip, i) => (
                  <motion.li
                    key={i}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.1 }}
                    style={{
                      marginBottom: '10px',
                      fontSize: '14px',
                      color: 'var(--text)',
                      opacity: 0.85,
                      lineHeight: '1.6'
                    }}
                  >
                    {tip}
                  </motion.li>
                ))}
              </ul>
            </motion.div>
          )}

          {/* CheatSheet Component */}
          {activeSheetData.component && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.3 }}
            >
              {activeSheetData.component}
            </motion.div>
          )}
        </motion.div>
      )}
    </div>
  );
};

export default CheatSheets;