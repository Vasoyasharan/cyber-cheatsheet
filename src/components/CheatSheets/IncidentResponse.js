import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaChevronDown, FaRocket, FaInfoCircle } from 'react-icons/fa';
import ReactMarkdown from 'react-markdown';
import { copyToClipboard } from '../../utils/copyToClipboard';
import { useCommandHistory } from '../../contexts/CommandHistoryContext';
import { toast } from 'react-toastify';

const IncidentResponse = () => {
  const [expandedSection, setExpandedSection] = useState(null);
  const { addToHistory } = useCommandHistory();

  const toggleSection = (section) => {
    setExpandedSection(expandedSection === section ? null : section);
  };

  const handleCopy = (command) => {
    copyToClipboard(command);
    addToHistory(command);
    toast.success('Copied to clipboard!');
  };

  const sections = [
    {
      id: 'walkthrough',
      title: '🚨 IR Walkthrough — From Alert to Containment',
      content: [
        {
          type: 'markdown',
          value: `Incident Response follows the **PICERL cycle**: Preparation → Identification → Containment → Eradication → Recovery → Lessons Learned. This walkthrough guides you through an active incident step by step.`
        },
        {
          type: 'step',
          title: '1. Identification — Is this a Real Incident?',
          description: 'Triage the alert. Gather initial facts without disturbing evidence.',
          commands: [
            { value: 'who', description: 'Who is logged in right now?' },
            { value: 'w', description: 'Who is logged in and what are they doing?' },
            { value: 'last -n 20', description: 'Last 20 login sessions' },
            { value: 'ps aux --sort=-%cpu | head -20', description: 'Top CPU-consuming processes' },
            { value: 'ss -tulnp', description: 'Active network connections with PIDs' },
            { value: 'netstat -anp | grep ESTABLISHED', description: 'Established connections' },
          ]
        },
        {
          type: 'step',
          title: '2. Containment — Stop the Bleeding',
          description: 'Isolate compromised systems. Take memory images BEFORE shutting down.',
          commands: [
            { value: 'ip link set eth0 down', description: 'Isolate host from network (Linux)' },
            { value: 'netsh advfirewall set allprofiles state on', description: 'Enable Windows Firewall immediately' },
            { value: 'netsh advfirewall firewall add rule name="BLOCK_C2" dir=out action=block remoteip=1.2.3.4', description: 'Block C2 IP in Windows firewall' },
            { value: 'avml /mnt/usb/memory.lime', description: 'Capture Linux memory image (requires avml)' },
            { value: 'winpmem_mini_x64.exe memory.raw', description: 'Capture Windows memory image' },
          ]
        },
        {
          type: 'step',
          title: '3. Eradication — Find & Remove the Threat',
          description: 'Identify all persistence mechanisms and malicious files. Remove them completely.',
          commands: [
            { value: 'find / -newer /tmp/ref_file -type f 2>/dev/null', description: 'Find files modified recently' },
            { value: 'crontab -l && ls -la /etc/cron*', description: 'Check all cron jobs' },
            { value: 'systemctl list-units --type=service | grep -v native', description: 'Check for suspicious services' },
            { value: 'grep -r "authorized_keys" /home /root 2>/dev/null', description: 'Check for backdoor SSH keys' },
          ]
        },
        {
          type: 'step',
          title: '4. Evidence Collection — Preserve for Forensics',
          description: 'Collect logs, memory dumps, and timeline artifacts before they are lost.',
          commands: [
            { value: 'journalctl -xe > /tmp/syslog_export.txt', description: 'Export systemd journal logs' },
            { value: 'cp /var/log/auth.log /evidence/', description: 'Copy authentication logs' },
            { value: 'dd if=/dev/sda of=/mnt/usb/disk.img bs=4M status=progress', description: 'Full disk image (forensic copy)' },
            { value: 'sha256sum /evidence/* > /evidence/hashes.txt', description: 'Hash all collected evidence' },
          ]
        }
      ]
    },
    {
      id: 'windows-ir',
      title: '🪟 Windows Incident Response Commands',
      content: [
        {
          type: 'markdown',
          value: `### Initial Triage (Run as Administrator)
\`\`\`powershell
# System info
systeminfo | findstr /B /C:"Host Name" /C:"OS" /C:"Hotfix"

# Logged-in users
query user

# Running processes with full paths
Get-Process | Select-Object Name, Id, Path | Format-Table -AutoSize

# Network connections with process info
Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | Format-Table

# Map PIDs to process names
netstat -anob

# Scheduled tasks
schtasks /query /fo LIST /v | findstr /i "task name\|run as\|task to run"

# Startup items
reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run

# Services
sc query | findstr "SERVICE_NAME\|STATE"
Get-Service | Where-Object {$_.Status -eq "Running"} | Format-Table -AutoSize
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Windows Event Log Analysis

| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4648 | Logon using explicit credentials (RunAs) |
| 4672 | Special privileges assigned (admin logon) |
| 4688 | New process created |
| 4698 | Scheduled task created |
| 4700 | Scheduled task enabled |
| 4720 | User account created |
| 4732 | Member added to security-enabled local group |
| 4768 | Kerberos TGT requested |
| 4769 | Kerberos service ticket requested (Kerberoasting) |
| 7045 | New service installed |
| 1102 | Security log cleared (potential cover-up!) |`
        },
        {
          type: 'markdown',
          value: `### PowerShell Event Log Queries
\`\`\`powershell
# Find failed logins (4625) — last 24h
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-1)} | 
  Select-Object TimeCreated, Message | Format-List

# Find new services installed (7045)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
  Select-Object TimeCreated, Message | Format-List

# Find cleared logs (1102)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} | Format-List

# Export security log to CSV
Get-WinEvent -LogName Security | Export-Csv -Path C:\\evidence\\security.csv -NoTypeInformation
\`\`\``
        }
      ]
    },
    {
      id: 'linux-ir',
      title: '🐧 Linux Incident Response Commands',
      content: [
        {
          type: 'markdown',
          value: `### Live System Triage
\`\`\`bash
# Order of volatility — collect most volatile first!

# 1. Running processes
ps auxfww
ls -la /proc/*/exe 2>/dev/null | grep deleted  # Detect deleted-but-running malware

# 2. Network connections
ss -tulnp
netstat -anp
lsof -i  # Open files and network connections by process

# 3. Logged in users
who
w
last -n 50

# 4. Command history (volatile — may be cleared)
cat /home/*/.bash_history
cat /root/.bash_history
cat /home/*/.zsh_history

# 5. Cron jobs
crontab -l
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Log Analysis — Key Linux Log Files
\`\`\`bash
# Authentication logs
/var/log/auth.log       # Debian/Ubuntu
/var/log/secure         # CentOS/RHEL

# Syslog
/var/log/syslog         # General system messages
/var/log/messages       # CentOS/RHEL

# Web server
/var/log/apache2/access.log
/var/log/nginx/access.log

# SSH — find successful logins
grep "Accepted" /var/log/auth.log | awk '{print $1, $2, $3, $9, $11}'

# SSH — brute force attempts
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head -10

# Find new users added
grep "useradd\|adduser" /var/log/auth.log

# Sudo abuse
grep "sudo:" /var/log/auth.log | grep -v "session opened\|session closed"
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Persistence Mechanism Checks
\`\`\`bash
# SSH authorized keys backdoors
find /home /root -name "authorized_keys" -exec cat {} \\; -print

# SUID binaries (check against baseline)
find / -perm /4000 -type f 2>/dev/null | sort

# Unusual files in /tmp, /dev/shm (common malware drop zones)
ls -la /tmp /dev/shm /var/tmp
find /tmp /dev/shm -type f -newer /tmp -exec ls -la {} \\;

# World-writable directories with files
find / -perm -o=w -type d 2>/dev/null | grep -v proc

# systemd services (check for unusual ones)
systemctl list-units --type=service --state=running
cat /etc/systemd/system/*.service 2>/dev/null

# Init scripts
ls /etc/init.d/
ls /etc/rc*.d/

# LD_PRELOAD hijacking
cat /etc/ld.so.preload 2>/dev/null
env | grep LD_

# PAM backdoors
grep -r "pam_exec" /etc/pam.d/ 2>/dev/null
\`\`\``
        }
      ]
    },
    {
      id: 'memory-forensics',
      title: '🧠 Memory Forensics with Volatility',
      content: [
        {
          type: 'markdown',
          value: `### Volatility 3 Basics
\`\`\`bash
# Install
pip install volatility3

# Identify OS and profile
vol -f memory.raw windows.info
vol -f memory.raw linux.bash

# List running processes
vol -f memory.raw windows.pslist
vol -f memory.raw windows.pstree  # Process tree

# Find hidden processes (detects rootkits)
vol -f memory.raw windows.psscan

# Network connections
vol -f memory.raw windows.netstat

# Dump process memory
vol -f memory.raw windows.memmap --pid 1234 --dump

# Find injected code (hollowing/injection)
vol -f memory.raw windows.malfind

# Extract strings from process memory
vol -f memory.raw windows.strings --pid 1234
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Volatility — Credential & Artifact Extraction
\`\`\`bash
# Dump Windows hashes (SAM)
vol -f memory.raw windows.hashdump

# Dump cached domain credentials
vol -f memory.raw windows.cachedump

# LSA secrets
vol -f memory.raw windows.lsadump

# Browser history/cookies
vol -f memory.raw windows.iehistory

# Registry hives
vol -f memory.raw windows.registry.hivelist
vol -f memory.raw windows.registry.printkey --key "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

# Clipboard contents
vol -f memory.raw windows.clipboard

# Find URLs in memory
vol -f memory.raw windows.strings | grep -oE 'https?://[^ ]+' | sort -u
\`\`\``
        }
      ]
    },
    {
      id: 'yara',
      title: '🔬 YARA Rules — Malware Detection',
      content: [
        {
          type: 'markdown',
          value: `### YARA Rule Syntax
\`\`\`yara
rule SuspiciousMimikatz {
    meta:
        description = "Detects Mimikatz credential dumper"
        author = "Security Team"
        date = "2024-01-01"
    strings:
        $s1 = "mimikatz" ascii nocase
        $s2 = "sekurlsa::logonpasswords" ascii
        $s3 = "lsadump::sam" ascii
        $hex = { 6D 69 6D 69 6B 61 74 7A }
    condition:
        any of them
}

rule SuspiciousShell {
    meta:
        description = "Detects reverse shell indicators"
    strings:
        $tcp = "/dev/tcp/" ascii
        $nc = "nc -e /bin/bash" ascii
        $bash = "bash -i >& /dev/tcp" ascii
        $python = "import socket,subprocess,os" ascii
    condition:
        any of them
}
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Using YARA
\`\`\`bash
# Install YARA
apt install yara
pip install yara-python

# Scan a file
yara rule.yar suspicious_file.exe

# Scan a directory recursively
yara -r rule.yar /var/www/

# Scan a memory dump
yara -r rules/ memory.raw

# Use public rulesets
git clone https://github.com/Neo23x0/signature-base
yara -r signature-base/yara/ /suspected/malware/

# Scan with multiple rule files
yara rules1.yar rules2.yar target/

# Only show matches (no "no match" output)
yara --no-warnings rule.yar /tmp/
\`\`\``
        }
      ]
    },
    {
      id: 'ioc-collection',
      title: '📋 IOC Collection & Reporting',
      content: [
        {
          type: 'markdown',
          value: `### What to Collect (IOC Types)

| Type | Examples |
|------|---------|
| **File Hashes** | MD5, SHA1, SHA256 of malicious files |
| **IP Addresses** | C2 servers, attacker IPs |
| **Domains** | C2 domains, phishing domains |
| **URLs** | Download URLs, C2 endpoints |
| **File Paths** | Paths where malware was found |
| **Registry Keys** | Persistence registry keys |
| **Mutex Names** | Malware mutex names (unique identifiers) |
| **Email Addresses** | Phishing sender addresses |
| **User Agents** | Malicious HTTP User-Agent strings |`
        },
        {
          type: 'markdown',
          value: `### Hash Collection Commands
\`\`\`bash
# Hash suspicious files
md5sum /tmp/suspicious.exe
sha256sum /tmp/suspicious.exe

# Hash all files in a directory
find /tmp -type f -exec sha256sum {} \\; > hashes.txt

# Check hash against VirusTotal (CLI)
curl "https://www.virustotal.com/vtapi/v2/file/report?apikey=YOUR_KEY&resource=HASH"

# Mass hash comparison (check against known malware)
hashdeep -r -k known_good.txt /suspicious/ | grep NOMATCH
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Incident Report Template
\`\`\`
INCIDENT REPORT
==============
Date/Time Detected: 
Incident ID: INC-YYYY-001
Severity: Critical / High / Medium / Low

EXECUTIVE SUMMARY
-----------------
[1-2 paragraph description for management]

TECHNICAL DETAILS
-----------------
Attack Vector: [How attacker gained access]
Initial Compromise: [First evidence of compromise]
Affected Systems: [List of systems]
Attacker IP(s): 
C2 Domain(s): 
Malware Hash(es): 

TIMELINE
--------
[Date/Time] - [Event]
[Date/Time] - [Event]

INDICATORS OF COMPROMISE (IOCs)
-------------------------------
[List all IOCs here]

ACTIONS TAKEN
-------------
[Containment steps]
[Eradication steps]
[Recovery steps]

RECOMMENDATIONS
---------------
[Preventive measures to avoid recurrence]
\`\`\``
        }
      ]
    }
  ];

  return (
    <div className="cheatsheet-container">
      <h2 className="cheatsheet-title">
        <FaRocket /> Incident Response Cheat Sheet
      </h2>

      <div className="info-banner">
        <FaInfoCircle />
        <p>
          Comprehensive incident response guide covering the PICERL framework, Windows and Linux 
          triage commands, memory forensics with Volatility, YARA rule writing, and IOC collection.
          Suitable for SOC analysts and DFIR professionals at all levels.
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
              <motion.div animate={{ rotate: expandedSection === section.id ? 180 : 0 }}>
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
                          <div className="step-header"><strong>{item.title}</strong></div>
                          <div className="step-description">{item.description}</div>
                          <div className="step-commands">
                            {item.commands.map((cmd, i) => (
                              <div key={i} className="command-item">
                                <div className="command-header">
                                  <code>{cmd.value}</code>
                                  <button onClick={() => handleCopy(cmd.value)} className="copy-button small">Copy</button>
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

export default IncidentResponse;
