import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaCode, FaExchangeAlt, FaRobot, FaCheck, FaWindows } from 'react-icons/fa';
import { LuRegex } from 'react-icons/lu';
import GradientHeader from '../components/UI/GradientHeader';
import AnimatedCard from '../components/UI/AnimatedCard';
import Base64Encoder from '../components/Utilities/Base64Encoder';
import URLEncoder from '../components/Utilities/URLEncoder';
import ReverseShellGenerator from '../components/Utilities/ReverseShellGenerator';
import RegexTester from '../components/Utilities/RegexTester';
import JSONFormatter from '../components/Utilities/JSONFormatter';
import HexConverter from '../components/Utilities/HexConverter';
import './Utilities.css';

const Utilities = () => {
  const [activeTool, setActiveTool] = useState('base64');

  const tools = [
    {
      id: 'base64',
      name: 'Base64 Encoder/Decoder',
      icon: <FaCode />,
      component: <Base64Encoder />,
      description: 'Encode and decode Base64 - essential for payload obfuscation and data encoding',
      category: 'Encoding',
      color: '#FF9800'
    },
    {
      id: 'url',
      name: 'URL Encoder/Decoder',
      icon: <FaExchangeAlt />,
      component: <URLEncoder />,
      description: 'URL encode/decode - format payloads for HTTP requests',
      category: 'Encoding',
      color: '#2196F3'
    },
    {
      id: 'hex',
      name: 'Hex Converter',
      icon: <FaCode />,
      component: <HexConverter />,
      description: 'Convert between hex, ASCII, and binary formats',
      category: 'Encoding',
      color: '#4CAF50'
    },
    {
      id: 'reverse-shell',
      name: 'Reverse Shell Generator',
      icon: <FaRobot />,
      component: <ReverseShellGenerator />,
      description: 'Generate reverse shell payloads for bash, PowerShell, Python, and more',
      category: 'Payloads',
      color: '#f44336'
    },
    {
      id: 'regex',
      name: 'Regex Tester',
      icon: <LuRegex />,
      component: <RegexTester />,
      description: 'Test and validate regex patterns with instant feedback',
      category: 'Tools',
      color: '#9C27B0'
    },
    {
      id: 'json',
      name: 'JSON Formatter',
      icon: <FaCheck />,
      component: <JSONFormatter />,
      description: 'Format, validate, and minify JSON data',
      category: 'Formatting',
      color: '#FF5722'
    },
  ];

  const activeTool_data = tools.find(t => t.id === activeTool);

  return (
    <div className="utilities-page">
      <GradientHeader
        title="Utility Tools"
        subtitle="Essential utilities for penetration testing and security research"
        gradient="linear-gradient(135deg, #667eea 0%, #764ba2 100%)"
      />

      <div className="utilities-container">
        {/* Sidebar */}
        <motion.div
          className="utilities-sidebar"
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.5 }}
        >
          <div className="sidebar-title">Tools</div>
          {tools.map((tool, idx) => (
            <motion.button
              key={tool.id}
              className={`tool-btn ${activeTool === tool.id ? 'active' : ''}`}
              onClick={() => setActiveTool(tool.id)}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: idx * 0.05 }}
              whileHover={{ x: 4 }}
              whileTap={{ scale: 0.98 }}
            >
              <span className="tool-icon">{tool.icon}</span>
              <span className="tool-label">{tool.name}</span>
            </motion.button>
          ))}
        </motion.div>

        {/* Main Content */}
        <motion.div
          className="utilities-content"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.3 }}
        >
          {activeTool_data && (
            <>
              <div className="tool-header">
                <div className="tool-info">
                  <div className="tool-icon-large" style={{ color: activeTool_data.color }}>
                    {activeTool_data.icon}
                  </div>
                  <div>
                    <h2>{activeTool_data.name}</h2>
                    <p>{activeTool_data.description}</p>
                    <span className="tool-category">{activeTool_data.category}</span>
                  </div>
                </div>
              </div>

              <AnimatedCard>
                <div className="tool-component">
                  {activeTool_data.component}
                </div>
              </AnimatedCard>
            </>
          )}
        </motion.div>
      </div>

      {/* Quick Reference */}
      <motion.div
        className="utilities-reference"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
      >
        <h3>Quick Reference</h3>
        <div className="reference-grid">
          {tools.map(tool => (
            <motion.div
              key={tool.id}
              className="reference-card"
              onClick={() => setActiveTool(tool.id)}
              whileHover={{ translateY: -4 }}
            >
              <div className="ref-icon" style={{ color: tool.color }}>
                {tool.icon}
              </div>
              <h4>{tool.name}</h4>
              <p>{tool.description}</p>
            </motion.div>
          ))}
        </div>
      </motion.div>
    </div>
  );
};

export default Utilities;
