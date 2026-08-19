# 🌐 WebRecon - All-in-One Web Reconnaissance Tool

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.0-red.svg)](https://github.com/yourusername/webrecon)
[![Security Research](https://img.shields.io/badge/security-research-orange.svg)](https://github.com/yourusername/webrecon)

> **Advanced Web Reconnaissance Tool for Security Researchers and Penetration Testers**

<p align="center">
  <img src="https://img.shields.io/badge/Developer-HIMA-brightgreen.svg" alt="Developer: HIMA">
  <img src="https://img.shields.io/badge/Purpose-Security%20Research-purple.svg">
  <img src="https://img.shields.io/badge/Status-Active-success.svg">
</p>

---

## 📋 Table of Contents
- [🌟 Features](#-features)
- [📸 Screenshots](#-screenshots)
- [🚀 Quick Start](#-quick-start)
- [📦 Installation](#-installation)
- [💻 Usage](#-usage)
- [🔧 Modules](#-modules)
- [📊 Reports](#-reports)
- [🛠️ Configuration](#-configuration)
- [⚠️ Disclaimer](#-disclaimer)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

---

## 🌟 Features

### 🔍 Core Capabilities
- **DNS Enumeration** - A, AAAA, MX, NS, TXT, CNAME, SOA, SRV records
- **Port Scanning** - 21 common ports with service detection
- **HTTP Headers Analysis** - Security headers, server information
- **SSL/TLS Analysis** - Certificate details, TLS versions, vulnerabilities
- **WHOIS Lookup** - Domain registration information
- **Technology Detection** - CMS, frameworks, libraries, servers
- **Subdomain Bruteforce** - 50+ common subdomains
- **Directory Bruteforce** - 50+ common directories and files
- **WAF Detection** - Identify Web Application Firewalls
- **Email Extraction** - Discover email addresses
- **CMS Detection** - WordPress, Drupal, Joomla, and more
- **Cloud Provider Detection** - AWS, Azure, GCP, Heroku
- **CDN Detection** - Cloudflare, Akamai, Fastly, etc.
- **Subdomain Takeover** - Check for vulnerable subdomains
- **Security Headers Check** - HSTS, CSP, X-Frame-Options
- **Git Repository Discovery** - Exposed .git folders
- **S3 Bucket Discovery** - Identify exposed AWS buckets
- **Backup File Scanning** - Find sensitive backup files
- **Social Media Discovery** - Find social media presence
- **Cookie Analysis** - Security analysis of cookies
- **Form Analysis** - Security analysis of web forms

### 📊 Output Options
- **JSON Reports** - Structured data for automation
- **HTML Reports** - Beautiful dashboard with statistics
- **Console Output** - Real-time progress with emojis

### 🚀 Performance
- **Multi-threading** - Up to 20 concurrent threads
- **Auto-installer** - Automatically installs dependencies
- **Progress Tracking** - Shows completion percentage
- **Verbose Mode** - Detailed debugging information

---

## 📸 Screenshots

### Banner and Startup
╔══════════════════════════════════════════════════════════════════════════════╗
║ ║
║ ██╗ ██╗███████╗██████╗ ██████╗ ███████╗ ██████╗ ███╗ ██╗ ║
║ ██║ ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔═══██╗████╗ ██║ ║
║ ██║ █╗ ██║█████╗ ██████╔╝██████╔╝█████╗ ██║ ██║██╔██╗ ██║ ║
║ ██║███╗██║██╔══╝ ██╔══██╗██╔══██╗██╔══╝ ██║ ██║██║╚██╗██║ ║
║ ╚███╔███╔╝███████╗██████╔╝██║ ██║███████╗╚██████╔╝██║ ╚████║ ║
║ ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝ ╚═╝╚══════╝ ╚═════╝ ╚═╝ ╚═══╝ ║
║ ║
║ 🌐 ALL-IN-ONE WEB RECONNAISSANCE TOOL 🌐 ║
║ 👨‍💻 Developed by: HIMA 👨‍💻 ║
║ 📅 Version: 3.0 (2024) ║
║ 🔒 For Security Research Only ║
╚══════════════════════════════════════════════════════════════════════════════╝

text

### HTML Report Dashboard
- Modern, responsive design
- Statistics cards with key metrics
- Organized sections with color coding
- Professional styling with gradients

---

## 🚀 Quick Start

### One-Line Installation & Scan
```bash
# Clone and run with auto-install
git clone https://github.com/yourusername/webrecon.git
cd webrecon
python3 recon.py -u https://example.com
Basic Scan
bash
python3 recon.py -u https://example.com
Scan Without Protocol
bash
python3 recon.py -u example.com
Verbose Mode
bash
python3 recon.py -u https://example.com -v
Save Reports to Specific Directory
bash
python3 recon.py -u https://example.com -o reports/
📦 Installation
Prerequisites
Python 3.8 or higher

pip (Python package manager)

Automatic Installation (Recommended)
The tool automatically installs required packages when you run it:

bash
python3 recon.py -u https://example.com
Manual Installation
bash
# Install required packages
pip install requests dnspython python-whois beautifulsoup4 pyOpenSSL

# For optional features
pip install shodan censys
Package Details
Package	Purpose	Required
requests	HTTP requests	✅ Yes
dnspython	DNS enumeration	✅ Yes
python-whois	WHOIS lookup	✅ Yes
beautifulsoup4	HTML parsing	✅ Yes
pyOpenSSL	SSL/TLS analysis	✅ Yes
shodan	Shodan integration	❌ Optional
censys	Censys integration	❌ Optional
💻 Usage
Command Line Arguments
Argument	Short	Description	Required
--url	-u	Target URL to scan	✅ Yes
--verbose	-v	Enable verbose output	❌ No
--output	-o	Output directory for reports	❌ No
Examples
1. Basic Security Scan
bash
python3 recon.py -u https://testasp.vulnweb.com/
2. Comprehensive Scan with Verbose Output
bash
python3 recon.py -u https://example.com -v
3. Save Reports to Custom Directory
bash
python3 recon.py -u https://example.com -o /path/to/reports/
4. Scan Multiple Domains (using bash loop)
bash
for domain in example1.com example2.com example3.com; do
    python3 recon.py -u $domain -o reports/
done
5. Batch Scan from File
bash
while read domain; do
    python3 recon.py -u $domain -v
done < domains.txt
🔧 Modules
1. DNS Enumeration
Records: A, AAAA, MX, NS, TXT, CNAME, SOA, SRV

Purpose: Discover DNS configuration and mail servers

2. Port Scanning
Ports: 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443

Purpose: Identify open services and attack surface

3. HTTP Headers Analysis
Checks: Server info, Security headers, Response codes

Purpose: Identify technologies and security posture

4. SSL/TLS Analysis
Checks: Certificate details, TLS version, Expiry

Purpose: Identify SSL/TLS vulnerabilities

5. Technology Detection
Frameworks: WordPress, Drupal, Laravel, Django, Rails

Libraries: jQuery, React, Angular, Vue.js

Servers: Apache, Nginx, IIS, Tomcat

Cloud: AWS, Azure, GCP

6. Subdomain Bruteforce
Wordlist: 50+ common subdomains

Method: DNS resolution

Purpose: Discover hidden services

7. Directory Bruteforce
Wordlist: 50+ common directories

Method: HTTP requests

Purpose: Find sensitive or hidden paths

8. WAF Detection
WAFs: Cloudflare, AWS WAF, ModSecurity, Akamai, Imperva, F5, Barracuda, Sucuri, Wordfence

Method: Header analysis

9. Subdomain Takeover
Services: AWS S3, Azure, GitHub, Heroku, Shopify, Tumblr, WordPress, Zendesk

Method: DNS + HTTP response analysis

10. Backup File Scanning
Files: .env, .git, .htaccess, config files, backup archives

Purpose: Find sensitive exposed files

📊 Reports
JSON Report
json
{
  "target": "https://example.com",
  "timestamp": "2024-01-01T12:00:00",
  "developer": "HIMA",
  "subdomains": ["www.example.com", "mail.example.com"],
  "technologies": ["Apache", "PHP", "WordPress"],
  "emails": ["contact@example.com"],
  "dns_records": {
    "A": ["192.168.1.1"],
    "MX": ["mail.example.com"]
  }
}
HTML Report Features
Responsive Design - Works on all devices

Statistics Dashboard - Quick overview

Color Coding - Easy visual parsing

Organized Sections - Logical grouping

Professional Styling - Modern gradients and shadows

🛠️ Configuration
Adding Custom Directories
python
# In WebReconTool.__init__()
self.common_dirs.extend([
    'custom-dir-1',
    'custom-dir-2'
])
Adding Custom Subdomains
python
# In WebReconTool.__init__()
self.common_subdomains.extend([
    'custom-subdomain-1',
    'custom-subdomain-2'
])
Adding Custom Technology Signatures
python
# In WebReconTool.__init__()
self.tech_signatures['CustomCMS'] = [
    'custom-signature-1',
    'custom-signature-2'
]
⚠️ Disclaimer
📢 Important Notice
This tool is designed for educational and research purposes only.

✅ Authorized Use Only: Only use this tool on systems you own or have explicit permission to test

❌ Illegal Use: Unauthorized scanning may violate laws and regulations

🔒 Privacy: Respect privacy and data protection laws

📋 Compliance: Ensure compliance with local, national, and international laws

🛡️ Responsible Disclosure
If you discover vulnerabilities while using this tool:

Document the findings

Report responsibly to the system owner

Follow responsible disclosure guidelines

📜 Legal
By using this tool, you agree that:

You are authorized to test the target

You accept full responsibility for your actions

The developer is not liable for misuse

🤝 Contributing
How to Contribute
Fork the Repository

Create a Feature Branch

bash
git checkout -b feature/amazing-feature
Commit Changes

bash
git commit -m 'Add amazing feature'
Push to Branch

bash
git push origin feature/amazing-feature
Open a Pull Request

Development Guidelines
Follow PEP 8 style guide

Add docstrings to functions

Update README if needed

Test your changes

Add comments for complex logic

Feature Requests
Open an issue with the enhancement label

Describe the feature in detail

Explain the use case

Provide examples if possible

Bug Reports
Open an issue with the bug label

Include steps to reproduce

Provide error messages

Mention Python version and OS

📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

text
MIT License

Copyright (c) 2024 HIMA

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
📞 Contact
Developer
Name: HIMA

GitHub: @yourusername

Email: your.email@example.com

Support
Issues: GitHub Issues

Discussions: GitHub Discussions

🙏 Acknowledgments
Thanks To
Open source community

Security researchers worldwide

All contributors and users

Built With
Python - Programming language

Requests - HTTP library

BeautifulSoup - HTML parsing

python-whois - WHOIS queries

📈 Roadmap
Future Features
□ Screenshot capture
□ Vulnerability scanning
□ API endpoint discovery
□ GraphQL endpoint detection
□ JWT token analysis
□ WebSocket scanning
□ CORS misconfiguration check
□ Rate limiting testing
□ Parameter fuzzing
□ JavaScript analysis
□ Mobile app API detection
Planned Improvements
□ Better performance optimization
□ More wordlists
□ Proxy support
□ Tor support
□ Docker container
□ Web interface
□ Database storage
□ Continuous monitoring
⭐ Star History
If you find this tool useful, please consider giving it a star ⭐ on GitHub!

https://api.star-history.com/svg?repos=yourusername/webrecon&type=Date

<p align="center"> <b>Made with ❤️ by HIMA</b><br> <i>Security Research Tool - Use Responsibly</i> </p><p align="center"> <a href="#-features">Features</a> • <a href="#-quick-start">Quick Start</a> • <a href="#-installation">Installation</a> • <a href="#-usage">Usage</a> • <a href="#-disclaimer">Disclaimer</a> </p> ```
This comprehensive README.md includes:

📋 Complete Documentation
Professional Layout - Clean, organized, and visually appealing

Feature Overview - All 25+ features listed with descriptions

Quick Start Guide - One-line installation and basic usage

Detailed Installation - Both automatic and manual installation

Usage Examples - Various command-line examples

Module Documentation - Each scanning module explained

Report Formats - JSON and HTML report details

Configuration Guide - How to customize the tool

Legal Disclaimer - Important legal notices

Contributing Guide - How to contribute to the project

License Information - MIT License details

Roadmap - Future features and improvements

Contact Information - Developer contact details

📊 Badges and Visual Elements
Version badges

Python version compatibility

License information

Developer credit

Status indicators
