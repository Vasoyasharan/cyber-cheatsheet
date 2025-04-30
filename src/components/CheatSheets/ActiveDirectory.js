import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaChevronDown, FaServer, FaInfoCircle } from 'react-icons/fa';
import ReactMarkdown from 'react-markdown';
import { copyToClipboard } from '../../utils/copyToClipboard';
import { toast } from 'react-toastify';

const ActiveDirectory = () => {
  const [expandedSection, setExpandedSection] = useState('enum');

  const toggleSection = (section) => {
    setExpandedSection(expandedSection === section ? null : section);
  };

  const handleCopy = (command) => {
    copyToClipboard(command);
    toast.success('Command copied to clipboard!');
  };

  const sections = [
    {
      id: 'enum',
      title: 'Enumeration',
      content: [
        {
          type: 'markdown',
          value: `### Tools & Commands
\`\`\`bash
# enum4linux
enum4linux -a 10.10.10.1

# LDAP Enumeration
ldapsearch -x -H ldap://10.10.10.1 -s base

# BloodHound Collection
SharpHound.exe -c All
\`\`\``
        }
      ]
    },
    {
      id: 'attacks',
      title: 'Common Attacks',
      content: [
        {
          type: 'markdown',
          value: `### Techniques
- **Kerberoasting**: Extract TGS tickets with \`Rubeus\`
- **AS-REP Roasting**: For users without preauth
- **Pass-the-Hash**: Using NTLM hashes for lateral movement`
        }
      ]
    }
  ];

  return (
    <div className="cheatsheet-container">
      <h2 className="cheatsheet-title">
        <FaServer /> Active Directory Cheat Sheet
      </h2>
      
      <div className="info-banner">
        <FaInfoCircle />
        <p>
          Enumeration and exploitation guide for Active Directory environments.
        </p>
      </div>
      
      <div className="sections-container">
        {sections.map((section) => (
          <div key={section.id} className="section">
            <motion.div
              className="section-header"
              onClick={() => toggleSection(section.id)}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              <h3>{section.title}</h3>
              <motion.div
                animate={{ rotate: expandedSection === section.id ? 180 : 0 }}
              >
                <FaChevronDown />
              </motion.div>
            </motion.div>
            
            <motion.div
              className="section-content"
              initial={{ opacity: 0, height: 0 }}
              animate={{
                opacity: expandedSection === section.id ? 1 : 0,
                height: expandedSection === section.id ? 'auto' : 0
              }}
              transition={{ duration: 0.3 }}
            >
              {expandedSection === section.id && (
                <div className="content-inner">
                  {section.content.map((item, index) => (
                    <div key={index} className="content-item">
                      <div className="markdown-content">
                        <ReactMarkdown>{item.value}</ReactMarkdown>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </motion.div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default ActiveDirectory;