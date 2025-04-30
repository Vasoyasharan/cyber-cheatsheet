import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaSearch, FaTerminal, FaShieldAlt, FaGlobe, FaServer, FaKey, FaNetworkWired, FaLock } from 'react-icons/fa';
import NmapBuilder from '../components/CommandBuilders/NmapBuilder';
import MetasploitBuilder from '../components/CommandBuilders/MetasploitBuilder';
import SqlmapBuilder from '../components/CommandBuilders/SqlmapBuilder';
import HydraBuilder from '../components/CommandBuilders/HydraBuilder';
import BurpSuiteBuilder from '../components/CommandBuilders/BurpSuiteBuilder';
import WiresharkBuilder from '../components/CommandBuilders/WiresharkBuilder';
import JohnTheRipperBuilder from '../components/CommandBuilders/JohnTheRipperBuilder';
import AnimatedCard from '../components/UI/AnimatedCard';
import GradientHeader from '../components/UI/GradientHeader';

const Tools = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [activeTool, setActiveTool] = useState('nmap');

  const tools = [
    { 
      id: 'nmap', 
      name: 'Nmap', 
      icon: <FaServer />, 
      component: <NmapBuilder />,
      category: 'Network'
    },
    { 
      id: 'metasploit', 
      name: 'Metasploit', 
      icon: <FaShieldAlt />, 
      component: <MetasploitBuilder />,
      category: 'Exploitation'
    },
    { 
      id: 'sqlmap', 
      name: 'SQLmap', 
      icon: <FaGlobe />, 
      component: <SqlmapBuilder />,
      category: 'Web'
    },
    { 
      id: 'hydra', 
      name: 'Hydra', 
      icon: <FaKey />, 
      component: <HydraBuilder />,
      category: 'Password'
    },
    { 
      id: 'burp', 
      name: 'Burp Suite', 
      icon: <FaGlobe />, 
      component: <BurpSuiteBuilder />,
      category: 'Web'
    },
    { 
      id: 'wireshark', 
      name: 'Wireshark', 
      icon: <FaNetworkWired />, 
      component: <WiresharkBuilder />,
      category: 'Network'
    },
    { 
      id: 'john', 
      name: 'John the Ripper', 
      icon: <FaLock />, 
      component: <JohnTheRipperBuilder />,
      category: 'Password'
    }
  ];

  const filteredTools = tools.filter(tool =>
    tool.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    tool.category.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="tools-page">
      <GradientHeader 
        title="Security Tools" 
        subtitle="Interactive command builders"
        icon={<FaTerminal />}
      />

      <div className="search-bar">
        <div className="search-input">
          <FaSearch className="search-icon" />
          <input
            type="text"
            placeholder="Search tools..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
      </div>

      <div className="tools-grid">
        {filteredTools.map((tool, index) => (
          <AnimatedCard
            key={tool.id}
            onClick={() => setActiveTool(tool.id)}
            isActive={activeTool === tool.id}
            delay={index * 0.1}
          >
            <div className="tool-card">
              <div className="tool-icon">{tool.icon}</div>
              <h3>{tool.name}</h3>
              <span className="tool-category">{tool.category}</span>
            </div>
          </AnimatedCard>
        ))}
      </div>

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.3 }}
        className="tool-container"
      >
        {tools.find(tool => tool.id === activeTool).component}
      </motion.div>
    </div>
  );
};

export default Tools;