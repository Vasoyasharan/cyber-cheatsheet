import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaSearch, FaLinux, FaWindows, FaGlobe, FaUserSecret, FaCode, FaServer, FaUserShield, FaCloud } from 'react-icons/fa';
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

const CheatSheets = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [activeSheet, setActiveSheet] = useState('linux'); // Default to linux

  const cheatSheets = [
    { 
      id: 'linux', 
      name: 'Linux PrivEsc', 
      icon: <FaLinux />, 
      component: <LinuxPrivEsc />,
      category: 'Privilege Escalation'
    },
    { 
      id: 'windows', 
      name: 'Windows PrivEsc', 
      icon: <FaWindows />, 
      component: <WindowsPrivEsc />,
      category: 'Privilege Escalation'
    },
    { 
      id: 'web', 
      name: 'Web App Testing', 
      icon: <FaGlobe />, 
      component: <WebAppTesting />,
      category: 'Web Security'
    },
    { 
      id: 'active',
      name: 'Active Directory',
      icon: <FaGlobe />, 
      component: <ActiveDirectoryAttacks />,
      category: 'Enterprise Security'
    },
    { 
      id: 'initial',
      name: 'Initial Access',
      icon: <FaUserSecret />, 
      component: <InitialAccessTechniques />,
      category: 'Red Teaming'
    },
    { 
      id: 'payload',
      name: 'Payload Generation',
      icon: <FaCode />, 
      component: <PayloadGeneration />,
      category: 'Red Teaming'
    },
    { 
      id: 'c2',
      name: 'C2 Frameworks',
      icon: <FaServer />, 
      component: <C2Frameworks />,
      category: 'Red Teaming'
    },
    { 
      id: 'post',
      name: 'Post Exploitation',
      icon: <FaUserShield />, 
      component: <PostExploitation />,
      category: 'Red Teaming'
    },
    { 
      id: 'cloud',
      name: 'Cloud Pentesting',
      icon: <FaCloud />, 
      component: <CloudPentesting />,
      category: 'Cloud Security'
    }
  ];

  const filteredSheets = cheatSheets.filter(sheet =>
    sheet.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    sheet.category.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // Find the active component based on activeSheet state
  const activeComponent = cheatSheets.find(sheet => sheet.id === activeSheet)?.component;

  return (
    <div className="cheatsheets-page">
      <GradientHeader 
        title="Cheat Sheets" 
        subtitle="Quick reference guides"
        icon={<FaSearch />}
      />

      <div className="search-bar">
        <div className="search-input">
          <FaSearch className="search-icon" />
          <input
            type="text"
            placeholder="Search cheat sheets..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
      </div>

      <div className="cheatsheets-grid">
        {filteredSheets.map((sheet, index) => (
          <AnimatedCard
            key={sheet.id}
            onClick={() => setActiveSheet(sheet.id)}
            isActive={activeSheet === sheet.id}
            delay={index * 0.1}
          >
            <div className="cheatsheet-card">
              <div className="cheatsheet-icon">{sheet.icon}</div>
              <h3>{sheet.name}</h3>
              <span className="cheatsheet-category">{sheet.category}</span>
            </div>
          </AnimatedCard>
        ))}
      </div>

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.3 }}
        className="cheatsheet-container"
      >
        {activeComponent}
      </motion.div>
    </div>
  );
};

export default CheatSheets;