// Command flag explanations for all major tools

export const commandExplanations = {
  nmap: {
    'name': 'Port scanner and network mapping utility',
    'flags': {
      '-p': 'Specify ports to scan (e.g., -p 80,443 or -p 1-1000)',
      '-sV': 'Version detection - identify service versions running on ports',
      '-sC': 'Script scanning - run nmap scripts for vulnerability detection',
      '-A': 'Aggressive scan - combines -sV, -sC, OS detection, and traceroute',
      '-O': 'OS detection - attempt to identify the operating system',
      '-Pn': 'Skip ping - treat host as online (useful for firewalled hosts)',
      '-sn': 'Ping scan - only discover hosts (no port scanning)',
      '-T4': 'Timing template (T0-T5) - faster scanning, T5 is fastest but less accurate',
      '-oN': 'Output normal format - save results in standard text format',
      '-oG': 'Output greppable format - save results in parseable format',
      '-v': 'Verbose output - show more details during scan',
      '-iL': 'Input from file - scan targets from a list file',
      '--script': 'Run specific Nmap scripts (e.g., --script=vuln)',
      '–exclude': 'Exclude specific hosts from scan',
    }
  },
  metasploit: {
    'name': 'Penetration testing framework for exploitation',
    'flags': {
      'use': 'Select an exploit or module to use',
      'set': 'Set module options (e.g., set LHOST 192.168.1.1)',
      'exploit': 'Run the selected exploit/payload',
      'run': 'Execute the selected module',
      'show': 'Display module options and information',
      'search': 'Search for exploits and modules',
      'info': 'Display detailed information about a module',
      'sessions': 'List active sessions and interact with them',
      'kill': 'Kill an active session',
      'background': 'Background the current session',
    }
  },
  sqlmap: {
    'name': 'Automated SQL injection detection and exploitation tool',
    'flags': {
      '-u': 'Target URL (e.g., -u "http://target.com/page?id=1")',
      '-p': 'Parameter to test for injection (e.g., -p id)',
      '--data': 'POST data to send with request',
      '--cookie': 'HTTP cookie header value',
      '-b': 'Retrieve database banner/version',
      '--current-db': 'Retrieve current database name',
      '--dbs': 'Enumerate all databases',
      '--tables': 'Enumerate tables in database',
      '--dump': 'Dump table data',
      '--proxy': 'Use HTTP proxy (e.g., --proxy="http://127.0.0.1:8080")',
      '--level': 'Level of SQL injection testing (1-5, 5 is most aggressive)',
      '--risk': 'Risk of payload (1-3, 3 is most dangerous)',
    }
  },
  hashcat: {
    'name': 'Fast GPU-based password cracking tool',
    'flags': {
      '-m': 'Hash type (e.g., -m 0 for MD5)',
      '-a': 'Attack mode (0=straight, 1=combination, 6=hybrid)',
      '-w': 'Workload intensity (1-4, 4 is fastest)',
      '--force': 'Force attack even if device appears unsuitable',
      '-O': 'Optimize for GPU (slower but reduces memory)',
      '--gpu-devices': 'Select specific GPU devices',
      '--custom-charset': 'Define custom character set for brute-force',
      '-o': 'Output file for found passwords',
      '--outfile-format': 'Format for output file',
      '-r': 'Use rules file for password generation',
    }
  },
  hydra: {
    'name': 'Parallel login brute-force attack tool',
    'flags': {
      '-l': 'Single username (e.g., -l admin)',
      '-L': 'Username list file',
      '-p': 'Single password (e.g., -p password)',
      '-P': 'Password list file',
      '-f': 'Exit after finding one valid pair',
      '-V': 'Verbose output',
      '-t': 'Number of parallel connections (e.g., -t 4)',
      'http-get': 'HTTP Basic/GET authentication',
      'http-post-form': 'HTTP POST form login',
      'ssh': 'SSH login brute-force',
      'ftp': 'FTP login brute-force',
      'smb': 'SMB/Windows share login brute-force',
    }
  },
  wireshark: {
    'name': 'Network packet analyzer for traffic inspection',
    'flags': {
      '-i': 'Interface to capture on (e.g., -i eth0)',
      '-c': 'Capture count - number of packets to capture',
      '-w': 'Write output to file (pcap format)',
      '-r': 'Read from file instead of live capture',
      '-f': 'BPF filter after capture (e.g., -f "tcp port 80")',
      'http': 'Filter HTTP traffic',
      'dns': 'Filter DNS traffic',
      'tcp': 'Filter TCP traffic',
      'ip.addr': 'Filter by IP address',
      'tcp.port': 'Filter by TCP port',
    }
  },
  johntheripper: {
    'name': 'Password cracking tool using dictionary and brute-force attacks',
    'flags': {
      '--wordlist': 'Use specific wordlist file',
      '--format': 'Hash format (e.g., --format=md5)',
      '--single': 'Single crack mode - uses username variations',
      '--incremental': 'Incremental mode - brute-force all characters',
      '--mask': 'Use mask attack for unknown parts',
      '--rules': 'Apply password generation rules',
      '-o': 'Output file for found passwords',
      '--show': 'Show cracked passwords',
      '--test': 'Test hashes (verification)',
    }
  },
  burpsuite: {
    'name': 'Web vulnerability scanner and proxy for testing',
    'flags': {
      'Intercept': 'Capture and modify requests in real-time',
      'Repeater': 'Manually repeat requests with modifications',
      'Spider': 'Automatically crawl and discover web application pages',
      'Scanner': 'Automated vulnerability scanning',
      'Intruder': 'Automated fuzzing and parameter testing',
      'Decoder': 'Decode/encode payloads (Base64, URL, etc.)',
      'Comparer': 'Compare requests and responses for differences',
    }
  },
  powershell: {
    'name': 'Windows command-line shell and scripting language',
    'flags': {
      '-NoProfile': 'Do not load user profile',
      '-NonInteractive': 'Non-interactive mode',
      '-Command': 'PowerShell command to execute',
      '-ExecutionPolicy': 'Set execution policy (Bypass, RemoteSigned, etc.)',
      '-EncodedCommand': 'Encoded PowerShell command (Base64)',
      '-WindowStyle': 'Set window style (Hidden, Minimized, Normal)',
      'Get-Help': 'Display help for cmdlets',
      'Get-Process': 'List running processes',
      'Get-Service': 'List Windows services',
    }
  },
  netcat: {
    'name': 'Network utility for reading/writing to network connections',
    'flags': {
      '-l': 'Listen mode - wait for incoming connections',
      '-p': 'Port to listen on (e.g., -p 4444)',
      '-v': 'Verbose output',
      '-n': 'Do not resolve DNS names',
      '-e': 'Execute program (for reverse shells)',
      '-u': 'UDP mode (default is TCP)',
      '-z': 'Zero I/O mode - just scan, no data transfer',
      '-w': 'Connection timeout in seconds',
    }
  },
};

// Helper function to get explanation for a command flag
export const getCommandExplanation = (tool, flag) => {
  const toolData = commandExplanations[tool.toLowerCase()];
  if (!toolData) return null;
  return toolData.flags[flag] || null;
};

// Helper function to get tool overview
export const getToolOverview = (tool) => {
  const toolData = commandExplanations[tool.toLowerCase()];
  if (!toolData) return null;
  return toolData.name;
};

// Get all flags for a tool
export const getToolFlags = (tool) => {
  const toolData = commandExplanations[tool.toLowerCase()];
  if (!toolData) return [];
  return Object.keys(toolData.flags);
};
