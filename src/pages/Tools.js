import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaSearch, FaTerminal, FaShieldAlt, FaGlobe, FaServer, FaKey, FaNetworkWired, FaLock, FaWindows, FaFingerprint, FaTimes, FaFilter, FaStar, FaBook, FaLightbulb, FaRocket } from 'react-icons/fa';
import NmapBuilder from '../components/CommandBuilders/NmapBuilder';
import MetasploitBuilder from '../components/CommandBuilders/MetasploitBuilder';
import SqlmapBuilder from '../components/CommandBuilders/SqlmapBuilder';
import HydraBuilder from '../components/CommandBuilders/HydraBuilder';
import BurpSuiteBuilder from '../components/CommandBuilders/BurpSuiteBuilder';
import WiresharkBuilder from '../components/CommandBuilders/WiresharkBuilder';
import JohnTheRipperBuilder from '../components/CommandBuilders/JohnTheRipperBuilder';
import HashcatBuilder from '../components/CommandBuilders/HashcatBuilder';
import AnimatedCard from '../components/UI/AnimatedCard';
import GradientHeader from '../components/UI/GradientHeader';
import DifficultyBadge from '../components/UI/DifficultyBadge';
import NetcatBuilder from '../components/CommandBuilders/NetcatBuilder';
import PowerShellBuilder from '../components/CommandBuilders/PowerShellBuilder';
import OSINTQuickRef from '../components/CommandBuilders/OSINTQuickRef';
import IRChecklist from '../components/CommandBuilders/IRChecklist';
import Enum4linuxBuilder from '../components/CommandBuilders/Enum4linuxBuilder';
import HashIdentifier from '../components/CommandBuilders/HashIdentifier';

const Tools = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [activeTool, setActiveTool] = useState('nmap');
  const [difficultyFilter, setDifficultyFilter] = useState('all');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [showAdvanced, setShowAdvanced] = useState(false);

  const tools = [
    { 
      id: 'osint', 
      name: 'OSINT Quick Ref', 
      icon: <FaGlobe />,
      component: <OSINTQuickRef />,
      category: 'Recon',
      difficulty: 'beginner',
      description: 'Open Source Intelligence gathering - perfect for beginners',
      color: '#4CAF50',
      useCases: ['Reconnaissance', 'Information gathering', 'Public data research'],
      advancedTips: ['Use multiple sources for cross-verification', 'Document findings systematically']
    },
    { 
      id: 'nmap', 
      name: 'Nmap', 
      icon: <FaServer />, 
      component: <NmapBuilder />,
      category: 'Network',
      difficulty: 'beginner',
      description: 'Port scanner - essential for network mapping',
      color: '#4776e6',
      useCases: ['Host discovery', 'Port scanning', 'Service detection'],
      advancedTips: ['Use -A for aggressive scanning', 'Learn script engine for custom probes']
    },
    { 
      id: 'netcat', 
      name: 'Netcat', 
      icon: <FaNetworkWired />,
      component: <NetcatBuilder />,
      category: 'Network',
      difficulty: 'beginner',
      description: 'Swiss-army knife for TCP/UDP - great for learning network fundamentals',
      color: '#FF9800',
      useCases: ['Port listening', 'File transfer', 'Reverse shell'],
      advancedTips: ['Master pipe redirection for complex operations']
    },
    {
      id: 'hashid',
      name: 'Hash Identifier',
      icon: <FaFingerprint />,
      component: <HashIdentifier />,
      category: 'Password',
      difficulty: 'beginner',
      description: 'Identify hash types - first step in password cracking',
      color: '#9d50bb',
      useCases: ['Hash type detection', 'Cracking preparation', 'Forensics'],
      advancedTips: ['Combine with online databases for known hashes']
    },
    { 
      id: 'wireshark', 
      name: 'Wireshark', 
      icon: <FaNetworkWired />, 
      component: <WiresharkBuilder />,
      category: 'Network',
      difficulty: 'intermediate',
      description: 'Network packet analyzer - understand traffic flows',
      color: '#00BCD4',
      useCases: ['Packet analysis', 'Network troubleshooting', 'Security analysis'],
      advancedTips: ['Create custom filters for specific protocols', 'Export for further analysis']
    },
    {
      id: 'ir',
      name: 'IR Checklist',
      icon: <FaShieldAlt />,
      component: <IRChecklist />,
      category: 'Incident Response',
      difficulty: 'intermediate',
      description: 'Incident Response procedures - systematic approach to investigations',
      color: '#F44336',
      useCases: ['Investigation methodology', 'Evidence preservation', 'Timeline creation'],
      advancedTips: ['Always maintain chain of custody', 'Document everything']
    },
    { 
      id: 'burp', 
      name: 'Burp Suite', 
      icon: <FaGlobe />, 
      component: <BurpSuiteBuilder />,
      category: 'Web',
      difficulty: 'intermediate',
      description: 'Web application testing proxy - industry standard',
      color: '#FF6B35',
      useCases: ['Web app testing', 'Intercepting requests', 'Security scanning'],
      advancedTips: ['Use Intruder for automated attacks', 'Learn Burp extensions']
    },
    { 
      id: 'sqlmap', 
      name: 'SQLmap', 
      icon: <FaGlobe />, 
      component: <SqlmapBuilder />,
      category: 'Web',
      difficulty: 'intermediate',
      description: 'SQL injection automated testing - powerful when used correctly',
      color: '#FF9800',
      useCases: ['SQL injection testing', 'Database enumeration', 'Data retrieval'],
      advancedTips: ['Use --tamper scripts to bypass WAF', 'Combine with manual testing']
    },
    { 
      id: 'hydra', 
      name: 'Hydra', 
      icon: <FaKey />, 
      component: <HydraBuilder />,
      category: 'Password',
      difficulty: 'intermediate',
      description: 'Credential brute force tool - test authentication strength',
      color: '#E91E63',
      useCases: ['Credential testing', 'Authentication weakness detection', 'Authorization bypass'],
      advancedTips: ['Use -L with multiple usernames', 'Optimize with fast protocols']
    },
    { 
      id: 'john', 
      name: 'John the Ripper', 
      icon: <FaLock />, 
      component: <JohnTheRipperBuilder />, 
      category: 'Password',
      difficulty: 'intermediate',
      description: 'Password cracker - effective with wordlists and rules',
      color: '#9C27B0',
      useCases: ['Hash cracking', 'Wordlist preparation', 'Rule-based attacks'],
      advancedTips: ['Create custom rules for better cracking', 'Use jumbo version for more formats']
    },
    {
      id: 'hashcat',
      name: 'Hashcat',
      icon: <FaKey />,
      component: <HashcatBuilder />,
      category: 'Password',
      difficulty: 'intermediate',
      description: 'GPU-powered hash cracker - extreme speed',
      color: '#8BC34A',
      useCases: ['GPU-accelerated cracking', 'Large hash lists', 'Massive wordlist processing'],
      advancedTips: ['Use --workload-profile for optimization', 'Benchmark before full runs']
    },
    {
      id: 'enum4linux',
      name: 'Enum4linux',
      icon: <FaServer />,
      component: <Enum4linuxBuilder />,
      category: 'Enumeration',
      difficulty: 'intermediate',
      description: 'SMB enumeration - discover Windows shares and users',
      color: '#2196F3',
      useCases: ['Windows enumeration', 'Share discovery', 'User enumeration'],
      advancedTips: ['Combine results with manual investigation', 'Use -A for all enumeration']
    },
    { 
      id: 'powershell', 
      name: 'PowerShell', 
      icon: <FaWindows />,
      component: <PowerShellBuilder />,
      category: 'Windows',
      difficulty: 'advanced',
      description: 'Windows powerful scripting - post-exploitation powerhouse',
      color: '#4CAF50',
      useCases: ['Post-exploitation', 'Lateral movement', 'Persistence mechanisms'],
      advancedTips: ['Learn .NET invocation', 'Master reflection for bypassing defenses']
    },
    { 
      id: 'metasploit', 
      name: 'Metasploit', 
      icon: <FaShieldAlt />, 
      component: <MetasploitBuilder />,
      category: 'Exploitation',
      difficulty: 'advanced',
      description: 'Exploitation framework - orchestrate complex attacks',
      color: '#0099FF',
      useCases: ['Multi-stage exploitation', 'Payload generation', 'Post-exploitation automation'],
      advancedTips: ['Create custom modules', 'Chain exploits for advanced attacks']
    }
  ];

  // Get unique categories
  const categories = ['all', ...new Set(tools.map(t => t.category))];
  const difficulties = ['all', 'beginner', 'intermediate', 'advanced'];

  // Filter tools
  const filteredTools = tools.filter(tool => {
    const matchesSearch = tool.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          tool.category.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesDifficulty = difficultyFilter === 'all' || tool.difficulty === difficultyFilter;
    const matchesCategory = categoryFilter === 'all' || tool.category === categoryFilter;
    return matchesSearch && matchesDifficulty && matchesCategory;
  });

  const activeToolData = tools.find(tool => tool.id === activeTool);

  // Container animation variants
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
    <div className="tools-page">
      <GradientHeader 
        title="Security Tools" 
        subtitle="Interactive command builders with difficulty levels"
        icon={<FaTerminal />}
      />

      {/* Quick Stats */}
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
          { icon: <FaRocket />, label: 'Total Tools', value: tools.length },
          { icon: <FaBook />, label: 'Categories', value: categories.length - 1 },
          { icon: <FaLightbulb />, label: 'Difficulty Levels', value: difficulties.length - 1 },
          { icon: <FaStar />, label: 'Advanced Content', value: '100%' }
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

      {/* Search Bar with Enhanced Styling */}
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
            placeholder="Search tools by name or category..."
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
                alignItems: 'center',
                marginRight: '10px'
              }}
            >
              <FaTimes />
            </motion.button>
          )}
        </div>
      </motion.div>

      {/* Filter Section with Animations */}
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

      {/* Tools Grid with Enhanced Animations */}
      <motion.div
        className="tools-grid"
        variants={containerVariants}
        initial="hidden"
        animate="visible"
        style={{
          padding: '20px',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
          gap: '20px',
          maxWidth: '1200px',
          margin: '0 auto'
        }}
      >
        {filteredTools.map((tool, index) => (
          <AnimatedCard
            key={tool.id}
            onClick={() => {
              setActiveTool(tool.id);
              setShowAdvanced(false);
            }}
            isActive={activeTool === tool.id}
            delay={index * 0.05}
          >
            <motion.div
              className="tool-card"
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
                  background: `linear-gradient(135deg, ${tool.color}22 0%, transparent 100%)`,
                  opacity: 0,
                  zIndex: 0
                }}
                whileHover={{ opacity: 1 }}
                transition={{ duration: 0.3 }}
              />

              <motion.div
                className="tool-icon"
                style={{
                  fontSize: '45px',
                  marginBottom: '12px',
                  color: tool.color,
                  position: 'relative',
                  zIndex: 1,
                  fontWeight: 'bold'
                }}
                animate={{ y: [0, -5, 0] }}
                transition={{ duration: 3, repeat: Infinity, delay: index * 0.2 }}
              >
                {tool.icon}
              </motion.div>
              <h3 style={{ marginBottom: '8px', color: 'var(--text)', position: 'relative', zIndex: 1, fontWeight: '700' }}>
                {tool.name}
              </h3>
              <p style={{
                fontSize: '12px',
                color: tool.color,
                opacity: 0.8,
                marginBottom: '10px',
                fontWeight: '600',
                position: 'relative',
                zIndex: 1
              }}>
                {tool.category}
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
                {tool.description}
              </p>
              <div style={{ marginTop: 'auto', position: 'relative', zIndex: 1 }}>
                <DifficultyBadge level={tool.difficulty} size="sm" />
              </div>
            </motion.div>
          </AnimatedCard>
        ))}
      </motion.div>

      {filteredTools.length === 0 && (
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
          <p style={{ fontSize: '16px' }}>No tools found matching your filters.</p>
          <p style={{ fontSize: '14px', opacity: 0.6 }}>Try adjusting your search or filters.</p>
        </motion.div>
      )}

      {/* Tool Details Section */}
      {activeToolData && (
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, type: 'spring', stiffness: 300 }}
          className="tool-container"
          style={{
            padding: '40px 20px',
            maxWidth: '1200px',
            margin: '50px auto 0',
            borderTop: `3px solid ${activeToolData.color}`,
            marginRight: 'auto',
            marginLeft: 'auto'
          }}
        >
          {/* Tool Header */}
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            style={{
              marginBottom: '30px',
              paddingBottom: '25px',
              borderBottom: `1px solid ${activeToolData.color}33`,
              display: 'flex',
              alignItems: 'start',
              gap: '20px',
              flexWrap: 'wrap'
            }}
          >
            <motion.div
              style={{
                fontSize: '48px',
                color: activeToolData.color,
                fontWeight: 'bold'
              }}
              animate={{ y: [0, -5, 0] }}
              transition={{ duration: 3, repeat: Infinity }}
            >
              {activeToolData.icon}
            </motion.div>
            <div style={{ flex: 1 }}>
              <h2 style={{ margin: '0 0 8px 0', color: 'var(--text)', fontSize: '32px', fontWeight: '700' }}>
                {activeToolData.name}
              </h2>
              <p style={{ margin: '0 0 15px 0', opacity: 0.8, fontSize: '15px' }}>
                {activeToolData.description}
              </p>

              {/* Use Cases */}
              {activeToolData.useCases && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.2 }}
                  style={{ marginBottom: '15px' }}
                >
                  <p style={{ fontSize: '12px', fontWeight: '700', opacity: 0.6, marginBottom: '8px' }}>
                    📌 Use Cases:
                  </p>
                  <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                    {activeToolData.useCases.map((useCase, i) => (
                      <motion.span
                        key={i}
                        style={{
                          background: `${activeToolData.color}22`,
                          color: activeToolData.color,
                          padding: '6px 12px',
                          borderRadius: '12px',
                          fontSize: '12px',
                          fontWeight: '600',
                          border: `1px solid ${activeToolData.color}44`
                        }}
                        whileHover={{ scale: 1.08 }}
                      >
                        {useCase}
                      </motion.span>
                    ))}
                  </div>
                </motion.div>
              )}
            </div>
            <DifficultyBadge level={activeToolData.difficulty} size="md" />
          </motion.div>

          {/* Advanced Tips Toggle */}
          {activeToolData.advancedTips && (
            <motion.button
              onClick={() => setShowAdvanced(!showAdvanced)}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.2 }}
              style={{
                background: showAdvanced ? `${activeToolData.color}22` : 'transparent',
                border: `1px solid ${activeToolData.color}`,
                color: activeToolData.color,
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
              whileHover={{ scale: 1.05, background: `${activeToolData.color}33` }}
            >
              <FaLightbulb /> {showAdvanced ? 'Hide' : 'Show'} Advanced Tips
            </motion.button>
          )}

          {/* Advanced Tips */}
          {showAdvanced && activeToolData.advancedTips && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3 }}
              style={{
                background: `${activeToolData.color}11`,
                border: `1px solid ${activeToolData.color}44`,
                borderRadius: '10px',
                padding: '20px',
                marginBottom: '30px'
              }}
            >
              <h4 style={{ margin: '0 0 15px 0', color: activeToolData.color, fontSize: '16px', fontWeight: '700' }}>
                ⚡ Advanced Tips & Techniques
              </h4>
              <ul style={{ margin: 0, paddingLeft: '20px' }}>
                {activeToolData.advancedTips.map((tip, i) => (
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

          {/* Tool Component */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.3 }}
          >
            {activeToolData.component}
          </motion.div>
        </motion.div>
      )}
    </div>
  );
};

export default Tools;