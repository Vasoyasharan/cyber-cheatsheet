import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaSearch, FaLinux, FaWindows, FaGlobe, FaUserSecret, FaCode, FaServer, FaUserShield, FaCloud, FaFilter, FaTimes } from 'react-icons/fa';
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

const CheatSheets = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [activeSheet, setActiveSheet] = useState('linux'); // Default to linux
  const [difficultyFilter, setDifficultyFilter] = useState('all');
  const [categoryFilter, setCategoryFilter] = useState('all');

  const cheatSheets = [
    { 
      id: 'linux', 
      name: 'Linux PrivEsc', 
      icon: <FaLinux />, 
      component: <LinuxPrivEsc />,
      category: 'Privilege Escalation',
      difficulty: 'beginner',
      description: 'Elevate privileges on Linux systems',
      prerequisites: ['Linux basics', 'File permissions']
    },
    { 
      id: 'windows', 
      name: 'Windows PrivEsc', 
      icon: <FaWindows />, 
      component: <WindowsPrivEsc />,
      category: 'Privilege Escalation',
      difficulty: 'intermediate',
      description: 'Escalate privileges on Windows systems',
      prerequisites: ['Windows fundamentals', 'Registry knowledge']
    },
    { 
      id: 'web', 
      name: 'Web App Testing', 
      icon: <FaGlobe />, 
      component: <WebAppTesting />,
      category: 'Web Security',
      difficulty: 'beginner',
      description: 'Test web applications for vulnerabilities',
      prerequisites: ['HTTP basics', 'Web technologies']
    },
    { 
      id: 'active',
      name: 'Active Directory',
      icon: <FaGlobe />, 
      component: <ActiveDirectoryAttacks />,
      category: 'Enterprise Security',
      difficulty: 'intermediate',
      description: 'Attack and enumerate Active Directory',
      prerequisites: ['Windows networking', 'Domain basics']
    },
    { 
      id: 'initial',
      name: 'Initial Access',
      icon: <FaUserSecret />, 
      component: <InitialAccessTechniques />,
      category: 'Red Teaming',
      difficulty: 'intermediate',
      description: 'Common techniques to gain initial access',
      prerequisites: ['General security knowledge', 'Social engineering']
    },
    { 
      id: 'payload',
      name: 'Payload Generation',
      icon: <FaCode />, 
      component: <PayloadGeneration />,
      category: 'Red Teaming',
      difficulty: 'advanced',
      description: 'Create and obfuscate malicious payloads',
      prerequisites: ['Exploitation knowledge', 'Coding basics']
    },
    { 
      id: 'c2',
      name: 'C2 Frameworks',
      icon: <FaServer />, 
      component: <C2Frameworks />,
      category: 'Red Teaming',
      difficulty: 'advanced',
      description: 'Command and Control operations',
      prerequisites: ['Advanced exploitation', 'Networking']
    },
    { 
      id: 'post',
      name: 'Post Exploitation',
      icon: <FaUserShield />, 
      component: <PostExploitation />,
      category: 'Red Teaming',
      difficulty: 'advanced',
      description: 'Actions after gaining system access',
      prerequisites: ['Exploitation basics', 'System administration']
    },
    { 
      id: 'cloud',
      name: 'Cloud Pentesting',
      icon: <FaCloud />, 
      component: <CloudPentesting />,
      category: 'Cloud Security',
      difficulty: 'advanced',
      description: 'Security testing in cloud environments',
      prerequisites: ['Cloud basics', 'Infrastructure knowledge']
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

  // Find the active component based on activeSheet state
  const activeComponentData = cheatSheets.find(sheet => sheet.id === activeSheet);
  const activeComponent = activeComponentData?.component;

  return (
    <div className="cheatsheets-page">
      <GradientHeader 
        title="Cheat Sheets" 
        subtitle="In-depth reference guides for every skill level"
        icon={<FaSearch />}
      />

      {/* Search Bar */}
      <div className="search-bar" style={{ margin: '30px 20px' }}>
        <div className="search-input" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <FaSearch className="search-icon" style={{ color: 'var(--primary)', marginLeft: '10px' }} />
          <input
            type="text"
            placeholder="Search cheat sheets..."
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

      {/* CheatSheets Grid */}
      <div className="cheatsheets-grid" style={{
        padding: '20px',
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
        gap: '20px',
        maxWidth: '1200px',
        margin: '0 auto'
      }}>
        {filteredSheets.map((sheet, index) => (
          <AnimatedCard
            key={sheet.id}
            onClick={() => setActiveSheet(sheet.id)}
            isActive={activeSheet === sheet.id}
            delay={index * 0.1}
          >
            <motion.div
              className="cheatsheet-card"
              style={{
                padding: '20px',
                cursor: 'pointer',
                textAlign: 'center'
              }}
            >
              <div className="cheatsheet-icon" style={{
                fontSize: '40px',
                marginBottom: '12px',
                color: 'var(--primary)'
              }}>
                {sheet.icon}
              </div>
              <h3 style={{ marginBottom: '8px', color: 'var(--text)' }}>{sheet.name}</h3>
              <p style={{ fontSize: '12px', color: 'var(--text)', opacity: 0.6, marginBottom: '10px' }}>
                {sheet.category}
              </p>
              <p style={{ fontSize: '13px', color: 'var(--text)', opacity: 0.8, marginBottom: '12px', lineHeight: '1.4' }}>
                {sheet.description}
              </p>
              <div style={{ marginTop: '10px' }}>
                <DifficultyBadge level={sheet.difficulty} size="sm" />
              </div>
            </motion.div>
          </AnimatedCard>
        ))}
      </div>

      {filteredSheets.length === 0 && (
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
          <p>No cheat sheets found matching your filters. Try adjusting your search or filters.</p>
        </motion.div>
      )}

      {/* CheatSheet Details Section */}
      {activeComponentData && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="cheatsheet-container"
          style={{
            padding: '30px 20px',
            maxWidth: '1200px',
            margin: '40px auto 0',
            borderTop: '2px solid var(--primary)',
            marginRight: 'auto',
            marginLeft: 'auto'
          }}
        >
          {/* CheatSheet Header */}
          <div style={{
            marginBottom: '30px',
            paddingBottom: '20px',
            borderBottom: '1px solid var(--primary)',
            opacity: 0.5
          }}>
            <div style={{
              display: 'flex',
              alignItems: 'start',
              gap: '15px',
              marginBottom: '15px',
              flexWrap: 'wrap'
            }}>
              <div style={{ fontSize: '32px', color: 'var(--primary)' }}>
                {activeComponentData.icon}
              </div>
              <div style={{ flex: 1 }}>
                <h2 style={{ margin: '0 0 5px 0', color: 'var(--text)' }}>{activeComponentData.name}</h2>
                <p style={{ margin: '0 0 10px 0', opacity: 0.7 }}>{activeComponentData.description}</p>
                
                {/* Prerequisites */}
                {activeComponentData.prerequisites && activeComponentData.prerequisites.length > 0 && (
                  <div style={{ marginTop: '10px' }}>
                    <p style={{ fontSize: '12px', fontWeight: '600', opacity: 0.6, marginBottom: '6px' }}>
                      📚 Prerequisites:
                    </p>
                    <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                      {activeComponentData.prerequisites.map((prereq, i) => (
                        <span
                          key={i}
                          style={{
                            background: 'var(--card-bg)',
                            padding: '4px 10px',
                            borderRadius: '12px',
                            fontSize: '11px',
                            color: 'var(--text)',
                            opacity: 0.7
                          }}
                        >
                          ✓ {prereq}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
              <DifficultyBadge level={activeComponentData.difficulty} size="md" />
            </div>
          </div>

          {/* CheatSheet Component */}
          {activeComponent}
        </motion.div>
      )}
    </div>
  );
};

export default CheatSheets;