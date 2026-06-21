import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaChevronDown, FaLock, FaInfoCircle } from 'react-icons/fa';
import ReactMarkdown from 'react-markdown';
import { copyToClipboard } from '../../utils/copyToClipboard';
import { useCommandHistory } from '../../contexts/CommandHistoryContext';
import { toast } from 'react-toastify';

const Cryptography = () => {
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
      id: 'intro',
      title: '📚 Cryptography Fundamentals (Beginner)',
      content: [
        {
          type: 'markdown',
          value: `## Core Concepts

**Encryption** — Converts plaintext to ciphertext using a key. Only someone with the key can decrypt.
- **Symmetric** (one key): AES, DES, 3DES, RC4 — fast, same key for encrypt/decrypt
- **Asymmetric** (two keys): RSA, ECC, DSA — public key encrypts, private key decrypts

**Hashing** — One-way function. Same input always produces same output (digest). Cannot be reversed.
- MD5 (128-bit) — **Broken for security, collision-prone**
- SHA-1 (160-bit) — **Deprecated, vulnerable to collisions**
- SHA-256 (256-bit) — Widely used, currently secure
- SHA-3 (256/512-bit) — Newer, different design from SHA-2
- bcrypt / argon2 — Slow by design, used for passwords (brute-force resistant)

**Digital Signatures** — Prove authenticity and integrity. Signed with private key, verified with public key.

**Key Exchange** — Diffie-Hellman (DH), ECDH — establishes shared secret over insecure channel.`
        },
        {
          type: 'markdown',
          value: `### Quick Hash Reference Table

| Algorithm | Output Length | Status | Use Case |
|-----------|-------------|--------|----------|
| MD5 | 128-bit (32 hex) | ❌ Broken | Legacy only |
| SHA-1 | 160-bit (40 hex) | ❌ Deprecated | Do not use |
| SHA-256 | 256-bit (64 hex) | ✅ Secure | TLS, integrity |
| SHA-512 | 512-bit (128 hex) | ✅ Secure | High security |
| bcrypt | 60 chars | ✅ Best for passwords | Password storage |
| Argon2 | Variable | ✅ Best modern | Password storage |
| NTLM | 32 hex | ⚠️ Windows legacy | Windows auth |
| LM | 32 hex | ❌ Broken | Very old Windows |`
        }
      ]
    },
    {
      id: 'hash-cracking',
      title: '🔨 Hash Identification & Cracking',
      content: [
        {
          type: 'markdown',
          value: `### Identifying Hash Types
\`\`\`bash
# hashid — identify hash type
pip install hashid
hashid 5f4dcc3b5aa765d61d8327deb882cf99
hashid -m -j 5f4dcc3b5aa765d61d8327deb882cf99  # Show hashcat/john mode

# hash-identifier (Kali built-in)
hash-identifier

# By length/format:
32 chars hex   → MD5 or NTLM
40 chars hex   → SHA-1
56 chars hex   → SHA-224
64 chars hex   → SHA-256
96 chars hex   → SHA-384
128 chars hex  → SHA-512
$2a$...        → bcrypt
$1$...         → MD5-crypt
$5$...         → SHA-256-crypt
$6$...         → SHA-512-crypt
$NT$...        → NTLM
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Hashcat — GPU Hash Cracking
\`\`\`bash
# Basic wordlist attack
hashcat -m 0 hash.txt rockyou.txt        # MD5
hashcat -m 100 hash.txt rockyou.txt      # SHA-1
hashcat -m 1400 hash.txt rockyou.txt     # SHA-256
hashcat -m 1000 hash.txt rockyou.txt     # NTLM
hashcat -m 3200 hash.txt rockyou.txt     # bcrypt
hashcat -m 13100 hash.txt rockyou.txt    # Kerberos TGS-REP (Kerberoast)
hashcat -m 18200 hash.txt rockyou.txt    # Kerberos AS-REP (AS-REP Roast)

# Rule-based attack (mutate wordlist)
hashcat -m 1000 hash.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 1000 hash.txt rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule

# Brute force (mask attack)
hashcat -m 0 hash.txt -a 3 '?l?l?l?l?l?l?l?l'  # 8 lowercase letters
hashcat -m 0 hash.txt -a 3 '?u?l?l?l?d?d?d?s'   # Capital+letters+3digits+symbol

# Combination attack (combine two wordlists)
hashcat -m 0 hash.txt -a 1 words1.txt words2.txt

# Show cracked hashes
hashcat -m 0 hash.txt --show
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Online & Offline Hash Lookup
\`\`\`bash
# Check public databases
# https://crackstation.net/      — Large MD5/SHA1 database
# https://hashes.com/            — Multi-algorithm lookup
# https://md5decrypt.net/        — MD5 specific

# Generate test hashes
echo -n "password" | md5sum
echo -n "password" | sha256sum
echo -n "password" | sha1sum
python3 -c "import hashlib; print(hashlib.sha256(b'password').hexdigest())"

# John the Ripper
john hash.txt --wordlist=rockyou.txt --format=raw-md5
john hash.txt --wordlist=rockyou.txt --format=NT
john hash.txt --show  # Show cracked
\`\`\``
        }
      ]
    },
    {
      id: 'openssl',
      title: '🔐 OpenSSL — Certificates & Encryption',
      content: [
        {
          type: 'markdown',
          value: `### Certificate Analysis
\`\`\`bash
# View certificate details
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -text -noout
openssl x509 -in cert.pem -text -noout

# Check certificate expiry
echo | openssl s_client -connect target.com:443 2>/dev/null | \\
  openssl x509 -noout -dates

# Test TLS/SSL version support
nmap --script ssl-enum-ciphers -p 443 target.com
openssl s_client -connect target.com:443 -tls1   # Force TLS 1.0 (deprecated)
openssl s_client -connect target.com:443 -ssl3    # Force SSLv3 (deprecated)

# Test cipher suites
testssl.sh target.com        # Comprehensive TLS testing tool
sslscan target.com           # Quick SSL scan

# View certificate chain
openssl s_client -connect target.com:443 -showcerts

# Verify certificate against CA
openssl verify -CAfile ca.crt server.crt
\`\`\``
        },
        {
          type: 'markdown',
          value: `### File Encryption & Decryption
\`\`\`bash
# Symmetric encryption (AES-256)
openssl enc -aes-256-cbc -salt -in plaintext.txt -out encrypted.enc -k "YourPassword"
openssl enc -aes-256-cbc -d -in encrypted.enc -out decrypted.txt -k "YourPassword"

# Asymmetric encryption (RSA)
# Generate key pair:
openssl genrsa -out private.pem 4096
openssl rsa -in private.pem -pubout -out public.pem

# Encrypt with public key (for recipient):
openssl rsautl -encrypt -inkey public.pem -pubin -in message.txt -out message.enc

# Decrypt with private key:
openssl rsautl -decrypt -inkey private.pem -in message.enc -out message.txt

# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \\
  -subj "/C=US/ST=CA/L=SF/O=Test/CN=test.local"
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Hashing with OpenSSL
\`\`\`bash
# Hash a file
openssl dgst -md5 file.txt
openssl dgst -sha256 file.txt
openssl dgst -sha512 file.txt

# HMAC (keyed hash)
openssl dgst -sha256 -hmac "secret-key" file.txt

# Hash a string (pipe)
echo -n "plaintext" | openssl dgst -sha256

# Base64 encode/decode
echo "Hello World" | openssl base64
echo "SGVsbG8gV29ybGQ=" | openssl base64 -d

# Generate random bytes
openssl rand -hex 32    # 32 random hex bytes
openssl rand -base64 32 # Random base64
\`\`\``
        }
      ]
    },
    {
      id: 'attacks',
      title: '⚠️ Cryptographic Weaknesses & Attacks',
      content: [
        {
          type: 'markdown',
          value: `### Common Cryptographic Vulnerabilities

| Vulnerability | Description | Example Tool/Technique |
|--------------|-------------|----------------------|
| **Weak key size** | RSA < 2048-bit, DES, RC4 | testssl.sh, nmap ssl-enum-ciphers |
| **MD5/SHA-1** | Collision attacks possible | Rainbow tables, CrackStation |
| **ECB mode** | Blocks encrypted independently → patterns visible | Penguin ECB attack |
| **Padding Oracle** | Guess plaintext via error responses | padbuster, POET |
| **POODLE** | SSLv3 CBC padding oracle | testssl.sh |
| **BEAST** | TLS 1.0 CBC vulnerability | testssl.sh |
| **CRIME/BREACH** | Compression + encryption = info leak | n/a (server-side fix) |
| **Heartbleed** | OpenSSL memory disclosure (CVE-2014-0160) | heartbleed.py |
| **Weak RNG** | Predictable random numbers → key recovery | N/A (code audit) |`
        },
        {
          type: 'markdown',
          value: `### Padding Oracle Attack
\`\`\`bash
# padbuster — automate CBC padding oracle attacks
# Useful when app reveals "Invalid padding" vs "Invalid MAC"

# Install
apt install padbuster

# Usage (must have valid ciphertext + IV)
padbuster https://target.com/api/token ENCRYPTED_VALUE 8 -cookies "session=ENCRYPTED_VALUE"

# PadBuster will:
# 1. Flip bytes in ciphertext
# 2. Observe server response
# 3. Recover plaintext byte by byte

# If you can forge plaintext → encrypt arbitrary data
padbuster https://target.com/ CIPHER_TEXT 8 -plaintext "user=admin"
\`\`\``
        },
        {
          type: 'markdown',
          value: `### RSA Attacks
\`\`\`python
# Small exponent attack (e=3, small message)
# If c = m^3 mod n and m^3 < n, then m = cube_root(c)
import gmpy2
c = int("CIPHERTEXT_HEX", 16)
m, exact = gmpy2.iroot(c, 3)  # Cube root
print(bytes.fromhex(hex(m)[2:]))  # Plaintext

# Common factor attack (if two keys share a prime factor)
from math import gcd
p = gcd(n1, n2)  # If p != 1, both keys are broken!

# RsaCtfTool — automated RSA attacks
pip install RsaCtfTool
python3 RsaCtfTool.py -n N_VALUE -e E_VALUE --uncipher C_VALUE
python3 RsaCtfTool.py --publickey key.pub --private  # Derive private key
python3 RsaCtfTool.py --publickey key.pub --uncipher cipher.txt --attack all
\`\`\``
        }
      ]
    },
    {
      id: 'tls-ssl',
      title: '🔒 TLS/SSL Testing & Hardening',
      content: [
        {
          type: 'markdown',
          value: `### testssl.sh — Comprehensive TLS Testing
\`\`\`bash
# Full TLS test
./testssl.sh target.com

# Specific checks
./testssl.sh --protocols target.com     # Which TLS versions
./testssl.sh --ciphers target.com       # Cipher suites
./testssl.sh --headers target.com       # HTTP security headers
./testssl.sh --vulns target.com         # All known TLS vulns (Heartbleed, POODLE, etc.)

# Output to JSON
./testssl.sh --jsonfile results.json target.com
\`\`\``
        },
        {
          type: 'markdown',
          value: `### TLS Security Checklist

\`\`\`
✅ Enabled (Good):
  - TLS 1.2 and TLS 1.3
  - ECDHE key exchange (forward secrecy)
  - AES-GCM / ChaCha20-Poly1305 ciphers
  - Certificate is valid, not expired
  - Strong key size (RSA 2048+, ECC P-256+)
  - HSTS header (Strict-Transport-Security)
  - Certificate Transparency (CT) logs

❌ Disabled (Required):
  - SSLv2, SSLv3, TLS 1.0, TLS 1.1
  - RC4, DES, 3DES, NULL ciphers
  - MD5, SHA-1 in certificates
  - Export-grade ciphers (FREAK/LOGJAM)
  - Anonymous DH (no authentication)
  - Self-signed certificates in production
  - Wildcard certs for high-security apps
\`\`\``
        }
      ]
    }
  ];

  return (
    <div className="cheatsheet-container">
      <h2 className="cheatsheet-title">
        <FaLock /> Cryptography Cheat Sheet
      </h2>

      <div className="info-banner">
        <FaInfoCircle />
        <p>
          Complete cryptography reference covering hash types and cracking, OpenSSL commands,
          TLS/SSL testing, common crypto weaknesses (padding oracle, RSA attacks), and 
          practical tools. Suitable for beginners learning hash cracking through advanced
          cryptographic attack techniques.
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

export default Cryptography;
