import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaSearch, FaTerminal, FaShieldAlt, FaGlobe, FaServer, FaKey, FaNetworkWired, FaLock, FaWindows, FaFingerprint, FaTimes, FaFilter } from 'react-icons/fa';
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

  const tools = [
    { 
      id: 'osint', 
      name: 'OSINT Quick Ref', 
      icon: <FaGlobe />,
      component: <OSINTQuickRef />,
      category: 'Recon',
      difficulty: 'beginner',
      description: 'Open Source Intelligence gathering - perfect for beginners'
    },
    { 
      id: 'nmap', 
      name: 'Nmap', 
      icon: <FaServer />, 
      component: <NmapBuilder />,
      category: 'Network',
      difficulty: 'beginner',
      description: 'Port scanner - essential for network mapping'
    },
    { 
      id: 'netcat', 
      name: 'Netcat', 
      icon: <FaNetworkWired />,
      component: <NetcatBuilder />,
      category: 'Network',
      difficulty: 'beginner',
      description: 'Swiss-army knife for TCP/UDP - great for learning network fundamentals'
    },
    {
      id: 'hashid',
      name: 'Hash Identifier',
      icon: <FaFingerprint />,
      component: <HashIdentifier />,
      category: 'Password',
      difficulty: 'beginner',
      description: 'Identify hash types - first step in password cracking'
    },
    { 
      id: 'wireshark', 
      name: 'Wireshark', 
      icon: <FaNetworkWired />, 
      component: <WiresharkBuilder />,
      category: 'Network',
      difficulty: 'intermediate',
      description: 'Network packet analyzer - understand traffic flows'
    },
    {
      id: 'ir',
      name: 'IR Checklist',
      icon: <FaShieldAlt />,
      component: <IRChecklist />,
      category: 'Incident Response',
      difficulty: 'intermediate',
      description: 'Incident Response procedures - systematic approach to investigations'
    },
    { 
      id: 'burp', 
      name: 'Burp Suite', 
      icon: <FaGlobe />, 
      component: <BurpSuiteBuilder />,
      category: 'Web',
      difficulty: 'intermediate',
      description: 'Web application testing proxy - industry standard'
    },
    { 
      id: 'sqlmap', 
      name: 'SQLmap', 
      icon: <FaGlobe />, 
      component: <SqlmapBuilder />,
      category: 'Web',
      difficulty: 'intermediate',
      description: 'SQL injection automated testing - powerful when used correctly'
    },
    { 
      id: 'hydra', 
      name: 'Hydra', 
      icon: <FaKey />, 
      component: <HydraBuilder />,
      category: 'Password',
      difficulty: 'intermediate',
      description: 'Credential brute force tool - test authentication strength'
    },
    { 
      id: 'john', 
      name: 'John the Ripper', 
      icon: <FaLock />, 
      component: <JohnTheRipperBuilder />, 
      category: 'Password',
      difficulty: 'intermediate',
      description: 'Password cracker - effective with wordlists and rules'
    },
    {
      id: 'hashcat',
      name: 'Hashcat',
      icon: <FaKey />,
      component: <HashcatBuilder />,
      category: 'Password',
      difficulty: 'intermediate',
      description: 'GPU-powered hash cracker - extreme speed'
    },
    {
      id: 'enum4linux',
      name: 'Enum4linux',
      icon: <FaServer />,
      component: <Enum4linuxBuilder />,
      category: 'Enumeration',
      difficulty: 'intermediate',
      description: 'SMB enumeration - discover Windows shares and users'
    },
    { 
      id: 'powershell', 
      name: 'PowerShell', 
      icon: <FaWindows />,
      component: <PowerShellBuilder />,
      category: 'Windows',
      difficulty: 'advanced',
      description: 'Windows powerful scripting - post-exploitation powerhouse'
    },
    { 
      id: 'metasploit', 
      name: 'Metasploit', 
      icon: <FaShieldAlt />, 
      component: <MetasploitBuilder />,
      category: 'Exploitation',
      difficulty: 'advanced',
      description: 'Exploitation framework - orchestrate complex attacks'
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

  return (
    <div className="tools-page">
      <GradientHeader 
        title="Security Tools" 
        subtitle="Interactive command builders with difficulty levels"
        icon={<FaTerminal />}
      />

      {/* Search Bar */}
      <div className="search-bar" style={{ margin: '30px 20px' }}>
        <div className="search-input" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <FaSearch className="search-icon" style={{ color: 'var(--primary)', marginLeft: '10px' }} />
          <input
            type="text"
            placeholder="Search tools..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              flex: 1,
              padding: '12px',
              border: 'none',
              background: 'var(--card-bg)',
              color: 'var(--text)',
              borderRadius: '8px 0 0 8px',
              outline: 'none'
            }}
          />
          {searchTerm && (
            <button
              onClick={() => setSearchTerm('')}
              style={{
                padding: '12px 15px',
                border: 'none',
                background: 'var(--card-bg)',
                color: 'var(--text)',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center'
              }}
            >
              <FaTimes />
            </button>
          )}
        </div>
      </div>

      {/* Filter Section */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
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
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '10px' }}>
            <FaFilter style={{ color: 'var(--primary)' }} />
            <span style={{ fontWeight: '600', color: 'var(--text)' }}>Filter by Difficulty:</span>
          </div>
          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
            {difficulties.map((diff) => (
              <motion.button
                key={diff}
                onClick={() => setDifficultyFilter(diff)}
                style={{
                  padding: '8px 16px',
                  borderRadius: '20px',
                  border: 'none',
                  background: difficultyFilter === diff ? 'var(--primary)' : 'var(--card-bg)',
                  color: difficultyFilter === diff ? 'white' : 'var(--text)',
                  cursor: 'pointer',
                  fontWeight: '600',
                  textTransform: 'capitalize',
                  transition: 'all 0.3s'
                }}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                {diff === 'all' ? '📊 All' : diff === 'beginner' ? '🌱 Beginner' : diff === 'intermediate' ? '📈 Intermediate' : '⚡ Advanced'}
              </motion.button>
            ))}
          </div>
        </div>

        {/* Category Filter */}
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '10px' }}>
            <FaFilter style={{ color: 'var(--primary)' }} />
            <span style={{ fontWeight: '600', color: 'var(--text)' }}>Filter by Category:</span>
          </div>
          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
            {categories.map((cat) => (
              <motion.button
                key={cat}
                onClick={() => setCategoryFilter(cat)}
                style={{
                  padding: '8px 16px',
                  borderRadius: '20px',
                  border: 'none',
                  background: categoryFilter === cat ? 'var(--primary)' : 'var(--card-bg)',
                  color: categoryFilter === cat ? 'white' : 'var(--text)',
                  cursor: 'pointer',
                  fontWeight: '600',
                  textTransform: 'capitalize',
                  transition: 'all 0.3s'
                }}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                {cat === 'all' ? '📊 All' : cat}
              </motion.button>
            ))}
          </div>
        </div>
      </motion.div>

      {/* Tools Grid */}
      <div className="tools-grid" style={{
        padding: '20px',
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
        gap: '20px',
        maxWidth: '1200px',
        margin: '0 auto'
      }}>
        {filteredTools.map((tool, index) => (
          <AnimatedCard
            key={tool.id}
            onClick={() => setActiveTool(tool.id)}
            isActive={activeTool === tool.id}
            delay={index * 0.1}
          >
            <motion.div
              className="tool-card"
              style={{
                padding: '20px',
                cursor: 'pointer',
                textAlign: 'center'
              }}
            >
              <div className="tool-icon" style={{
                fontSize: '40px',
                marginBottom: '12px',
                color: 'var(--primary)'
              }}>
                {tool.icon}
              </div>
              <h3 style={{ marginBottom: '8px', color: 'var(--text)' }}>{tool.name}</h3>
              <p style={{ fontSize: '12px', color: 'var(--text)', opacity: 0.6, marginBottom: '10px' }}>
                {tool.category}
              </p>
              <p style={{ fontSize: '13px', color: 'var(--text)', opacity: 0.8, marginBottom: '12px', lineHeight: '1.4' }}>
                {tool.description}
              </p>
              <div style={{ marginTop: '10px' }}>
                <DifficultyBadge level={tool.difficulty} size="sm" />
              </div>
            </motion.div>
          </AnimatedCard>
        ))}
      </div>

      {filteredTools.length === 0 && (
        <motion.div
          style={{
            textAlign: 'center',
            padding: '40px 20px',
            opacity: 0.6,
            color: 'var(--text)'
          }}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
        >
          <p>No tools found matching your filters. Try adjusting your search or filters.</p>
        </motion.div>
      )}

      {/* Tool Details Section */}
      {activeToolData && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="tool-container"
          style={{
            padding: '30px 20px',
            maxWidth: '1200px',
            margin: '40px auto 0',
            borderTop: '2px solid var(--primary)',
            marginRight: 'auto',
            marginLeft: 'auto'
          }}
        >
          {/* Tool Header */}
          <div style={{
            marginBottom: '30px',
            paddingBottom: '20px',
            borderBottom: '1px solid var(--primary)',
            opacity: 0.5
          }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '15px',
              marginBottom: '15px'
            }}>
              <div style={{ fontSize: '32px', color: 'var(--primary)' }}>
                {activeToolData.icon}
              </div>
              <div>
                <h2 style={{ margin: '0 0 5px 0', color: 'var(--text)' }}>{activeToolData.name}</h2>
                <p style={{ margin: 0, opacity: 0.7 }}>{activeToolData.description}</p>
              </div>
              <DifficultyBadge level={activeToolData.difficulty} size="md" />
            </div>
          </div>

          {/* Tool Component */}
          {activeToolData.component}
        </motion.div>
      )}
    </div>
  );
};

export default Tools;