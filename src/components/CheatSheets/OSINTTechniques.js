import { useState } from 'react';
import { motion } from 'framer-motion';
import { FaChevronDown, FaSearch, FaInfoCircle } from 'react-icons/fa';
import ReactMarkdown from 'react-markdown';
import { copyToClipboard } from '../../utils/copyToClipboard';
import { useCommandHistory } from '../../contexts/CommandHistoryContext';
import { toast } from 'react-toastify';

const OSINTTechniques = () => {
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
      title: '🗺️ Guided OSINT Recon Walkthrough (Beginner → Advanced)',
      content: [
        {
          type: 'markdown',
          value: `**OSINT (Open Source Intelligence)** is the art of gathering information about a target using only publicly available data — search engines, social media, WHOIS, DNS records, and more. Always ensure you have authorization before performing active OSINT on a real target.`
        },
        {
          type: 'step',
          title: '1. Passive Recon — Google Dorks',
          description: 'Use Google advanced search operators to find sensitive data about a target domain. Completely passive — no direct contact with target.',
          commands: [
            { value: 'site:target.com filetype:pdf', description: 'Find all PDFs on the target domain' },
            { value: 'site:target.com inurl:admin OR inurl:login', description: 'Find admin and login pages' },
            { value: 'site:target.com intitle:"index of"', description: 'Find open directory listings' },
            { value: '"@target.com" filetype:xls OR filetype:xlsx', description: 'Find spreadsheets with email addresses' },
            { value: 'site:pastebin.com "target.com" password', description: 'Check Pastebin for leaked credentials' },
          ]
        },
        {
          type: 'step',
          title: '2. DNS & Infrastructure Enumeration',
          description: 'Map the target\'s infrastructure using DNS records and certificate transparency logs.',
          commands: [
            { value: 'whois target.com', description: 'WHOIS lookup — registrant, registrar, dates' },
            { value: 'nslookup -type=MX target.com', description: 'Find mail servers' },
            { value: 'nslookup -type=TXT target.com', description: 'Find TXT/SPF records — reveals email security config' },
            { value: 'dig axfr @ns1.target.com target.com', description: 'Attempt DNS zone transfer (often disabled)' },
            { value: 'subfinder -d target.com -o subs.txt', description: 'Passive subdomain enumeration via multiple sources' },
            { value: 'amass enum -passive -d target.com', description: 'Comprehensive passive DNS enumeration' },
          ]
        },
        {
          type: 'step',
          title: '3. Shodan — Internet-Wide Scanning',
          description: 'Search Shodan for exposed services, IoT devices, and infrastructure belonging to the target.',
          commands: [
            { value: 'shodan search "target.com"', description: 'Search for services mentioning the target' },
            { value: 'shodan search "org:Target Inc"', description: 'Find all hosts for an organization' },
            { value: 'shodan search "ssl.cert.subject.cn:target.com"', description: 'Find hosts using target SSL certs' },
            { value: 'shodan host 1.2.3.4', description: 'Detailed info on a specific IP' },
          ]
        },
        {
          type: 'step',
          title: '4. Email & Employee OSINT',
          description: 'Identify employee emails, names, and job titles for social engineering assessment.',
          commands: [
            { value: 'theHarvester -d target.com -b all', description: 'Gather emails and subdomains from all sources' },
            { value: 'hunter.io (web)', description: 'Find email format and known emails at a company (web UI)' },
            { value: 'linkedin (web)', description: 'Find employees, titles, and tech stack from job postings' },
          ]
        },
        {
          type: 'step',
          title: '5. Breach Data & Credentials',
          description: 'Check if company emails appear in known data breaches.',
          commands: [
            { value: 'haveibeenpwned.com (web)', description: 'Check if email was in a breach (web UI)' },
            { value: 'dehashed.com (web)', description: 'Search leaked credentials databases (paid)' },
          ]
        }
      ]
    },
    {
      id: 'google-dorks',
      title: '🔍 Google Dorks — Advanced Search Operators',
      content: [
        {
          type: 'markdown',
          value: `### Core Operators

| Operator | Example | Purpose |
|----------|---------|---------|
| \`site:\` | \`site:target.com\` | Restrict results to a domain |
| \`inurl:\` | \`inurl:admin\` | URL must contain keyword |
| \`intitle:\` | \`intitle:"login"\` | Page title must contain keyword |
| \`filetype:\` | \`filetype:pdf\` | Find specific file types |
| \`intext:\` | \`intext:password\` | Body text must contain keyword |
| \`cache:\` | \`cache:target.com\` | View Google's cached version |
| \`link:\` | \`link:target.com\` | Find pages linking to target |`
        },
        {
          type: 'markdown',
          value: `### Common Dorking Recipes
\`\`\`
# Find login/admin panels
site:target.com inurl:login
site:target.com inurl:admin
site:target.com intitle:"Dashboard"

# Find exposed files
site:target.com filetype:pdf
site:target.com filetype:xml
site:target.com filetype:sql
site:target.com filetype:env

# Find credentials/sensitive data
site:target.com "password" filetype:txt
site:target.com "api_key" OR "apikey" filetype:json
"target.com" intext:"BEGIN RSA PRIVATE KEY"

# Find open directories
intitle:"index of" site:target.com
intitle:"index of" "backup" site:target.com

# Find error messages (reveals tech stack)
site:target.com "Warning: mysql_"
site:target.com "ORA-" (Oracle errors)
\`\`\``
        }
      ]
    },
    {
      id: 'shodan',
      title: '🛰️ Shodan — Internet-Wide Intelligence',
      content: [
        {
          type: 'markdown',
          value: `### Shodan Search Filters

| Filter | Example | Purpose |
|--------|---------|---------|
| \`org:\` | \`org:"Cloudflare"\` | Organization name |
| \`country:\` | \`country:US\` | Country code |
| \`port:\` | \`port:8080\` | Open port |
| \`product:\` | \`product:nginx\` | Software name |
| \`version:\` | \`version:1.14\` | Software version |
| \`ssl.cert.subject.cn:\` | \`ssl.cert.subject.cn:target.com\` | SSL cert domain |
| \`hostname:\` | \`hostname:target.com\` | Hostname |
| \`net:\` | \`net:1.2.3.0/24\` | CIDR range |`
        },
        {
          type: 'markdown',
          value: `### Shodan CLI Commands
\`\`\`bash
# Install CLI
pip install shodan
shodan init YOUR_API_KEY

# Search
shodan search "target.com"
shodan search --fields ip_str,port,org "apache"

# Host details
shodan host 1.2.3.4

# Count results
shodan count "org:Target Inc"

# Download results
shodan download results.json.gz "org:Target Inc"
shodan parse --fields ip_str,port,org results.json.gz

# Find vulnerable services
shodan search "vuln:CVE-2021-44228"  # Log4Shell exposed
shodan search "product:Elasticsearch" port:9200  # Unauth Elasticsearch
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Powerful Shodan Queries
\`\`\`
# Exposed databases
port:27017 (MongoDB)
port:9200 "elasticsearch" 
port:5432 "PostgreSQL"

# Industrial / OT systems
product:"SCADA"
port:102 (Siemens S7)
port:502 (Modbus)

# Exposed admin panels
http.title:"Cisco ASDM" port:443
http.title:"Fortinet" port:443
http.favicon.hash:-1776962843 (Grafana)

# Find by SSL cert org
ssl.cert.subject.O:"Target Inc"
\`\`\``
        }
      ]
    },
    {
      id: 'dns-recon',
      title: '🌐 DNS & Domain Intelligence',
      content: [
        {
          type: 'markdown',
          value: `### WHOIS & RDAP
\`\`\`bash
# WHOIS lookup
whois target.com
whois 1.2.3.4  # Reverse WHOIS on IP

# RDAP (modern WHOIS replacement)
curl https://rdap.org/domain/target.com | jq
\`\`\``
        },
        {
          type: 'markdown',
          value: `### DNS Record Enumeration
\`\`\`bash
# All record types
dig ANY target.com @8.8.8.8

# Specific records
dig A target.com        # IPv4 addresses
dig AAAA target.com     # IPv6 addresses
dig MX target.com       # Mail servers
dig TXT target.com      # TXT/SPF/DKIM records
dig NS target.com       # Nameservers
dig CNAME sub.target.com # Canonical names

# Zone transfer attempt (axfr)
dig axfr target.com @ns1.target.com

# Reverse DNS lookup
dig -x 1.2.3.4
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Subdomain Enumeration
\`\`\`bash
# Subfinder (passive — uses public sources)
subfinder -d target.com -o subs.txt -silent

# Amass (comprehensive)
amass enum -passive -d target.com
amass enum -active -d target.com -brute -w wordlist.txt

# Assetfinder
assetfinder --subs-only target.com

# CRTSH (certificate transparency — passive)
curl "https://crt.sh/?q=%25.target.com&output=json" | jq '.[].name_value' | sort -u

# ffuf for active brute-force
ffuf -w subdomains.txt -u http://FUZZ.target.com -mc 200,301,302
\`\`\``
        }
      ]
    },
    {
      id: 'email-osint',
      title: '📧 Email & Employee OSINT',
      content: [
        {
          type: 'markdown',
          value: `### theHarvester
\`\`\`bash
# Harvest from all available sources
theHarvester -d target.com -b all -f results.html

# Specific sources
theHarvester -d target.com -b google,bing,linkedin,hunter

# Search for specific TLD
theHarvester -d target.com -b all -l 500
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Email Format Discovery
\`\`\`
Techniques:
1. hunter.io — directly shows format (e.g. {first}.{last}@company.com)
2. LinkedIn job postings — check CC'd emails in postings
3. Company website — press releases, contact pages
4. Breach databases — pattern analysis from leaked emails

Common formats to test:
  first.last@company.com
  flast@company.com
  firstl@company.com
  first@company.com
\`\`\``
        },
        {
          type: 'markdown',
          value: `### OSINT for People
\`\`\`bash
# Spokeo / BeenVerified — US people search (web)
# Pipl — professional people search (web)
# LinkedIn — job history, skills, connections
# Twitter/X — check @mentions, profile links
# Instagram — location data in photos (EXIF)
# GitHub — find employee repos, commit emails

# Check social handles
sherlock <username>     # Check username across 300+ sites
holehe <email>          # Check email registration on sites
\`\`\``
        }
      ]
    },
    {
      id: 'recon-ng',
      title: '🕵️ recon-ng Framework',
      content: [
        {
          type: 'markdown',
          value: `### Getting Started
\`\`\`bash
# Launch recon-ng
recon-ng

# Create a new workspace
workspaces create target_corp

# Install modules
marketplace install all
marketplace install recon/domains-hosts/hackertarget

# Load a module
modules load recon/domains-hosts/hackertarget
info  # show module info
options set SOURCE target.com
run
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Useful Module Categories
\`\`\`
recon/domains-hosts/*      — Subdomain enumeration
recon/hosts-ports/*        — Port scanning integration
recon/domains-contacts/*   — Email harvesting
recon/companies-contacts/* — LinkedIn enumeration
recon/hosts-hosts/*        — Reverse DNS, shodan
reporting/*                — Generate reports (HTML, CSV, JSON)
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Workflow Example
\`\`\`bash
# Full passive OSINT workflow
workspaces create acme_corp
db insert domains acme.com

# Enumerate subdomains
modules load recon/domains-hosts/hackertarget
options set SOURCE acme.com
run

# Get host IPs
modules load recon/hosts-hosts/resolve
run

# Shodan lookup
modules load recon/hosts-ports/shodan_ip
keys add shodan_api YOUR_KEY
run

# Generate HTML report
modules load reporting/html
options set CREATOR "Pentest Team"
options set CUSTOMER "Acme Corp"
run
\`\`\``
        }
      ]
    },
    {
      id: 'advanced',
      title: '⚡ Advanced OSINT — Red Team Techniques',
      content: [
        {
          type: 'markdown',
          value: `### Maltego Graph Intelligence
\`\`\`
Maltego entities to chain:
Domain → DNS → IP → ASN → Org
Email → Person → Social Media → Phone
Company → People → Infrastructure

Useful transforms:
- AlienVault OTX — threat intel
- Shodan — exposed services
- Have I Been Pwned — breach data
- VirusTotal — passive DNS, URL history
\`\`\``
        },
        {
          type: 'markdown',
          value: `### OSINT on Cloud Infrastructure
\`\`\`bash
# S3 bucket discovery
s3scanner scan --domains-file domains.txt
aws s3 ls s3://target-backup --no-sign-request  # Check public buckets

# Azure blob storage
https://target.blob.core.windows.net/  

# Google Cloud Storage
https://storage.googleapis.com/target-backup

# GrayhatWarfare — public bucket search
https://buckets.grayhatwarfare.com/

# Find exposed .git repos
git-dumper http://target.com/.git ./output
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Wayback Machine & Historical Data
\`\`\`bash
# Archive.org Wayback Machine CDX API
curl "http://web.archive.org/cdx/search/cdx?url=target.com/*&output=json&fl=original,timestamp&collapse=urlkey" 

# gau — Get All URLs (crawls WaybackMachine, Common Crawl, OTX)
gau target.com | grep -E "\\.php|\\.asp|\\.aspx|\\.json|\\.xml"

# Waybackurls
waybackurls target.com | tee urls.txt

# Find JS files with hardcoded endpoints
gau target.com | grep "\\.js$" | sort -u | xargs -I{} sh -c 'curl -s {} | grep -oE "https?://[a-zA-Z0-9./\\_-]+"'
\`\`\``
        },
        {
          type: 'markdown',
          value: `### Metadata Extraction
\`\`\`bash
# FOCA / exiftool — extract metadata from public documents
# Download docs with wget:
wget -r -A "*.pdf,*.docx,*.xlsx,*.pptx" http://target.com/

# Extract metadata
exiftool *.pdf | grep -E "Author|Creator|LastSavedBy|Producer|Company"

# This can reveal:
# - Internal usernames
# - Software versions
# - Internal paths (C:\Users\john.doe\...)
# - Company info / network shares
\`\`\``
        }
      ]
    }
  ];

  return (
    <div className="cheatsheet-container">
      <h2 className="cheatsheet-title">
        <FaSearch /> OSINT Techniques Cheat Sheet
      </h2>

      <div className="info-banner">
        <FaInfoCircle />
        <p>
          Open Source Intelligence gathering — from passive Google dorks to advanced Shodan queries,
          subdomain enumeration, email harvesting, and metadata analysis. Always obtain proper
          authorization before performing reconnaissance on real targets.
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

export default OSINTTechniques;
