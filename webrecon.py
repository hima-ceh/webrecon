#!/usr/bin/env python3
"""
All-in-One Web Reconnaissance Tool
Developer: Hima
Version: 2.0
Description: Comprehensive web reconnaissance tool with multiple scanning modules
"""

import requests
import socket
import dns.resolver
import whois
import subprocess
import json
import time
import threading
import queue
import ssl
import OpenSSL
import hashlib
import base64
import urllib.parse
from urllib.parse import urlparse
import re
from datetime import datetime
import argparse
import sys
import os
from typing import Dict, List, Set, Tuple, Optional
import concurrent.futures
from bs4 import BeautifulSoup
import ipaddress
import nmap
import shodan
import censys
import xml.etree.ElementTree as ET

class WebReconTool:
    """Main class for web reconnaissance operations"""
    
    def __init__(self, target: str, verbose: bool = False):
        self.target = target
        self.verbose = verbose
        self.results = {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self.threads = []
        self.queue = queue.Queue()
        
        # Initialize results structure
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'developer': 'Hima',
            'dns': {},
            'ports': {},
            'http_headers': {},
            'technologies': {},
            'subdomains': set(),
            'directories': set(),
            'emails': set(),
            'ssl_info': {},
            'whois': {},
            'screenshots': [],
            'vulnerabilities': [],
            'cms': {},
            'cloud': {},
            'waf': {},
            'cookies': [],
            'forms': [],
            'links': set(),
            'sitemap': [],
            'robots_txt': '',
            'security_headers': {},
            'cdn': {},
            'server_info': {},
            'backup_files': [],
            'git_repos': [],
            's3_buckets': [],
            'dns_records': {},
            'email_servers': [],
            'social_media': [],
            'subdomain_takeover': []
        }
        
        # Common directories and files for scanning
        self.common_dirs = [
            'admin', 'login', 'wp-admin', 'dashboard', 'api', 'v1', 'v2',
            'backup', 'tmp', 'temp', 'logs', 'test', 'dev', 'stage', 
            'staging', 'beta', 'old', 'new', 'private', 'secure',
            'config', 'settings', 'env', '.env', 'git', '.git',
            'phpinfo', 'phpmyadmin', 'mysql', 'database', 'db',
            'uploads', 'downloads', 'files', 'images', 'css', 'js',
            'assets', 'static', 'media', 'data', 'docs', 'documentation'
        ]
        
        self.common_extensions = [
            'php', 'html', 'htm', 'asp', 'aspx', 'jsp', 'do',
            'txt', 'log', 'bak', 'backup', 'sql', 'tar', 'gz',
            'zip', 'rar', '7z', 'pdf', 'doc', 'xls', 'ppt',
            'xml', 'json', 'yaml', 'yml', 'env', 'ini', 'conf'
        ]
        
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1',
            'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig',
            'm', 'img', 'images', 'css', 'js', 'static', 'media', 'cdn',
            'api', 'app', 'dev', 'staging', 'test', 'beta', 'qa', 'stage',
            'secure', 'vpn', 'remote', 'ssh', 'mysql', 'db', 'database',
            'admin', 'dashboard', 'portal', 'blog', 'forums', 'wiki',
            'docs', 'support', 'help', 'downloads', 'files', 'assets'
        ]
        
        # Technology signatures
        self.tech_signatures = {
            'WordPress': ['wp-content', 'wp-includes', 'wp-admin'],
            'Drupal': ['sites/all', 'misc/drupal.js'],
            'Joomla': ['media/system', 'components/com_'],
            'Magento': ['skin/frontend', 'js/mage'],
            'Laravel': ['vendor/laravel', 'js/app.js'],
            'Django': ['static/admin', 'csrfmiddlewaretoken'],
            'Rails': ['assets/application', 'data-turbolinks'],
            'Node.js': ['node_modules', 'package.json'],
            'Angular': ['angular.js', 'ng-app'],
            'React': ['react.js', 'react-dom.js'],
            'Vue.js': ['vue.js', 'v-app'],
            'Bootstrap': ['bootstrap.css', 'bootstrap.js'],
            'jQuery': ['jquery.js', 'jquery.min.js'],
            'Apache': ['Server: Apache'],
            'Nginx': ['Server: nginx'],
            'IIS': ['Server: Microsoft-IIS'],
            'Cloudflare': ['cf-ray', 'cf-cache-status'],
            'AWS': ['x-amz-', 'aws-lb'],
            'Google Cloud': ['x-cloud-trace-context'],
            'Azure': ['x-ms-', 'azure'],
            'nginx': ['nginx'],
            'Apache': ['apache'],
            'IIS': ['iis'],
            'Tomcat': ['tomcat'],
            'Jetty': ['jetty'],
            'WildFly': ['wildfly'],
            'WebLogic': ['weblogic'],
            'WebSphere': ['websphere']
        }

    def display_banner(self):
        """Display attractive banner with developer credit"""
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ██╗    ██╗███████╗██████╗ ██████╗ ███████╗ ██████╗ ███╗   ██╗            ║
║   ██║    ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔═══██╗████╗  ██║            ║
║   ██║ █╗ ██║█████╗  ██████╔╝██████╔╝█████╗  ██║   ██║██╔██╗ ██║            ║
║   ██║███╗██║██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██║   ██║██║╚██╗██║            ║
║   ╚███╔███╔╝███████╗██████╔╝██║  ██║███████╗╚██████╔╝██║ ╚████║            ║
║    ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝            ║
║                                                                              ║
║   ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███╗   ██╗ █████╗ ██╗███████╗ ║
║   ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║████╗  ██║██╔══██╗██║╚══███╔╝ ║
║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██╔██╗ ██║███████║██║  ███╔╝  ║
║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║╚██╗██║██╔══██║██║ ███╔╝   ║
║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║ ╚████║██║  ██║██║███████╗ ║
║   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝╚══════╝ ║
║                                                                              ║
║                    🌐 ALL-IN-ONE WEB RECONNAISSANCE TOOL 🌐                   ║
║                                                                              ║
║                         👨‍💻 Developed by: HIMA 👨‍💻                          ║
║                         📅 Version: 2.0 (2024)                               ║
║                         🔒 For Security Research Only                        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        print(banner)
        print("\n" + "="*80)
        print(f"🎯 Target: {self.target}")
        print(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80 + "\n")

    def log(self, message: str, level: str = "INFO"):
        """Logging function with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        symbols = {
            "INFO": "ℹ️",
            "SUCCESS": "✅",
            "WARNING": "⚠️",
            "ERROR": "❌",
            "PROGRESS": "🔄"
        }
        if self.verbose or level in ["ERROR", "SUCCESS"]:
            print(f"{symbols.get(level, 'ℹ️')} [{timestamp}] [{level}] {message}")

    def validate_url(self) -> bool:
        """Validate and normalize the target URL"""
        try:
            if not self.target.startswith(('http://', 'https://')):
                self.target = 'https://' + self.target
            
            parsed = urlparse(self.target)
            if not parsed.netloc:
                self.log(f"Invalid target: {self.target}", "ERROR")
                return False
            
            self.domain = parsed.netloc
            self.scheme = parsed.scheme
            self.base_url = f"{self.scheme}://{self.domain}"
            self.hostname = parsed.hostname
            self.port = parsed.port or (443 if self.scheme == 'https' else 80)
            
            self.log(f"✅ Target validated: {self.base_url}", "SUCCESS")
            return True
        except Exception as e:
            self.log(f"URL validation failed: {e}", "ERROR")
            return False

    def run_all(self):
        """Execute all reconnaissance modules"""
        if not self.validate_url():
            return
        
        self.display_banner()
        self.log(f"Starting comprehensive reconnaissance on: {self.target}", "PROGRESS")
        
        # Run all modules
        modules = [
            (self.dns_enumeration, "DNS Enumeration"),
            (self.port_scanning, "Port Scanning"),
            (self.http_headers_analysis, "HTTP Headers Analysis"),
            (self.ssl_tls_analysis, "SSL/TLS Analysis"),
            (self.whois_lookup, "WHOIS Lookup"),
            (self.technology_detection, "Technology Detection"),
            (self.subdomain_bruteforce, "Subdomain Bruteforce"),
            (self.directory_bruteforce, "Directory Bruteforce"),
            (self.robots_analysis, "Robots.txt Analysis"),
            (self.sitemap_analysis, "Sitemap Analysis"),
            (self.security_headers_check, "Security Headers Check"),
            (self.waf_detection, "WAF Detection"),
            (self.email_extraction, "Email Extraction"),
            (self.backup_file_scanning, "Backup File Scanning"),
            (self.cms_detection, "CMS Detection"),
            (self.cloud_provider_check, "Cloud Provider Check"),
            (self.cdn_detection, "CDN Detection"),
            (self.link_extraction, "Link Extraction"),
            (self.social_media_discovery, "Social Media Discovery"),
            (self.git_repo_discovery, "Git Repository Discovery"),
            (self.s3_bucket_discovery, "S3 Bucket Discovery"),
            (self.subdomain_takeover_check, "Subdomain Takeover Check"),
            (self.cookie_analysis, "Cookie Analysis"),
            (self.form_analysis, "Form Analysis")
        ]
        
        total_modules = len(modules)
        completed = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_module = {executor.submit(module): name for module, name in modules}
            for future in concurrent.futures.as_completed(future_to_module):
                module_name = future_to_module[future]
                completed += 1
                progress = (completed / total_modules) * 100
                try:
                    future.result()
                    self.log(f"✅ Completed: {module_name} ({progress:.0f}%)", "SUCCESS")
                except Exception as e:
                    self.log(f"❌ Error in {module_name}: {e}", "ERROR")
        
        self.log("🎉 Reconnaissance completed successfully!", "SUCCESS")
        self.generate_report()

    def dns_enumeration(self):
        """Perform DNS enumeration"""
        self.log("Starting DNS enumeration...", "PROGRESS")
        
        dns_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SRV']
        
        for record_type in dns_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                self.results['dns_records'][record_type] = []
                for answer in answers:
                    self.results['dns_records'][record_type].append(str(answer))
                if self.results['dns_records'][record_type]:
                    self.log(f"Found {len(self.results['dns_records'][record_type])} {record_type} records")
            except dns.resolver.NoAnswer:
                pass
            except Exception as e:
                self.log(f"DNS {record_type} lookup failed: {e}", "WARNING")

    def port_scanning(self):
        """Perform port scanning"""
        self.log("Starting port scanning...", "PROGRESS")
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 
                        445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        
        open_ports = []
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.hostname, port))
                if result == 0:
                    service = self.get_service_name(port)
                    open_ports.append({
                        'port': port,
                        'service': service
                    })
                    self.log(f"✅ Port {port} open ({service})", "SUCCESS")
                sock.close()
            except Exception:
                pass
        
        self.results['ports']['open'] = open_ports
        self.log(f"Found {len(open_ports)} open ports")

    def get_service_name(self, port: int) -> str:
        """Get service name for port number"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC', 139: 'NetBIOS',
            143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
            1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-ALT',
            8443: 'HTTPS-ALT'
        }
        return services.get(port, 'Unknown')

    def http_headers_analysis(self):
        """Analyze HTTP headers"""
        self.log("Analyzing HTTP headers...", "PROGRESS")
        
        try:
            response = self.session.get(self.base_url, timeout=10, verify=False)
            headers = dict(response.headers)
            self.results['http_headers'] = headers
            
            # Security headers
            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-Frame-Options': 'Clickjacking Protection',
                'X-Content-Type-Options': 'MIME Sniffing Protection',
                'X-XSS-Protection': 'XSS Protection',
                'Referrer-Policy': 'Referrer Policy',
                'Permissions-Policy': 'Permissions Policy'
            }
            
            for header, name in security_headers.items():
                if header in headers:
                    self.results['security_headers'][name] = headers[header]
                    self.log(f"✅ Found security header: {name}", "SUCCESS")
            
            # Server info
            if 'Server' in headers:
                self.results['server_info'] = {'server': headers['Server']}
                self.log(f"✅ Server: {headers['Server']}")
                
        except Exception as e:
            self.log(f"HTTP headers analysis failed: {e}", "ERROR")

    def ssl_tls_analysis(self):
        """Analyze SSL/TLS configuration"""
        self.log("Analyzing SSL/TLS...", "PROGRESS")
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    self.results['ssl_info'] = {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'subject_alt_name': cert.get('subjectAltName', []),
                        'ocsp': cert.get('OCSP', []),
                        'ca_issuers': cert.get('caIssuers', [])
                    }
                    
                    # SSL/TLS version
                    self.results['ssl_info']['tls_version'] = ssock.version()
                    self.log(f"✅ TLS Version: {ssock.version()}")
                    
        except Exception as e:
            self.log(f"SSL/TLS analysis failed: {e}", "WARNING")

    def whois_lookup(self):
        """Perform WHOIS lookup"""
        self.log("Performing WHOIS lookup...", "PROGRESS")
        
        try:
            w = whois.whois(self.domain)
            self.results['whois'] = {
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'name_servers': w.name_servers,
                'registrant': w.registrant,
                'admin': w.admin,
                'tech': w.tech,
                'emails': w.emails
            }
            self.log(f"✅ WHOIS lookup completed for {self.domain}")
        except Exception as e:
            self.log(f"WHOIS lookup failed: {e}", "WARNING")

    def technology_detection(self):
        """Detect technologies used by the target"""
        self.log("Detecting technologies...", "PROGRESS")
        
        try:
            response = self.session.get(self.base_url, timeout=10, verify=False)
            html = response.text.lower()
            headers = response.headers
            
            detected_tech = []
            
            # Check headers
            server = headers.get('Server', '').lower()
            for tech, patterns in self.tech_signatures.items():
                if tech.lower() in server:
                    detected_tech.append(tech)
                    continue
                
                if tech.lower() in str(headers).lower():
                    detected_tech.append(tech)
                    continue
                
                for pattern in patterns:
                    if pattern.lower() in html or pattern.lower() in str(headers).lower():
                        detected_tech.append(tech)
                        break
            
            self.results['technologies'] = list(set(detected_tech))
            if detected_tech:
                self.log(f"✅ Detected technologies: {', '.join(detected_tech)}")
            
        except Exception as e:
            self.log(f"Technology detection failed: {e}", "ERROR")

    def subdomain_bruteforce(self):
        """Bruteforce subdomains"""
        self.log("Starting subdomain bruteforce...", "PROGRESS")
        
        found_subdomains = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_subdomain = {
                executor.submit(self.check_subdomain, sub): sub 
                for sub in self.common_subdomains
            }
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                sub = future_to_subdomain[future]
                try:
                    if future.result():
                        found_subdomains.append(sub)
                        self.log(f"✅ Found subdomain: {sub}.{self.domain}", "SUCCESS")
                except Exception:
                    pass
        
        self.results['subdomains'] = list(set(found_subdomains))
        self.log(f"Found {len(found_subdomains)} subdomains")

    def check_subdomain(self, subdomain: str) -> bool:
        """Check if a subdomain exists"""
        try:
            domain = f"{subdomain}.{self.domain}"
            socket.gethostbyname(domain)
            return True
        except socket.gaierror:
            return False

    def directory_bruteforce(self):
        """Bruteforce directories"""
        self.log("Starting directory bruteforce...", "PROGRESS")
        
        found_dirs = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_dir = {
                executor.submit(self.check_directory, dir_path): dir_path 
                for dir_path in self.common_dirs
            }
            
            for future in concurrent.futures.as_completed(future_to_dir):
                dir_path = future_to_dir[future]
                try:
                    result = future.result()
                    if result:
                        found_dirs.append(result)
                        self.log(f"✅ Found directory: {result}", "SUCCESS")
                except Exception:
                    pass
        
        self.results['directories'] = list(set(found_dirs))
        self.log(f"Found {len(found_dirs)} directories")

    def check_directory(self, directory: str) -> Optional[str]:
        """Check if a directory exists"""
        try:
            url = f"{self.base_url}/{directory}"
            response = self.session.get(url, timeout=5, verify=False)
            
            if response.status_code in [200, 301, 302, 403]:
                return url
        except Exception:
            pass
        return None

    def robots_analysis(self):
        """Analyze robots.txt"""
        self.log("Analyzing robots.txt...", "PROGRESS")
        
        try:
            response = self.session.get(f"{self.base_url}/robots.txt", timeout=5, verify=False)
            if response.status_code == 200:
                self.results['robots_txt'] = response.text
                
                # Extract disallowed paths
                disallowed = re.findall(r'Disallow:\s*(.+)', response.text, re.IGNORECASE)
                self.results['robots_disallowed'] = disallowed
                self.log(f"✅ Found robots.txt with {len(disallowed)} disallowed paths")
        except Exception:
            pass

    def sitemap_analysis(self):
        """Analyze sitemap.xml"""
        self.log("Analyzing sitemap.xml...", "PROGRESS")
        
        try:
            response = self.session.get(f"{self.base_url}/sitemap.xml", timeout=5, verify=False)
            if response.status_code == 200:
                self.results['sitemap'] = response.text
                self.log("✅ Found sitemap.xml")
        except Exception:
            pass

    def security_headers_check(self):
        """Check security headers"""
        self.log("Checking security headers...", "PROGRESS")
        # Already handled in http_headers_analysis
        pass

    def waf_detection(self):
        """Detect WAF"""
        self.log("Detecting WAF...", "PROGRESS")
        
        try:
            headers = self.results.get('http_headers', {})
            waf_signatures = {
                'Cloudflare': ['cf-ray', 'cf-cache-status'],
                'AWS WAF': ['x-amzn-requestid'],
                'ModSecurity': ['mod_security', 'Sec-'],
                'Akamai': ['akamai', 'x-akamai'],
                'Imperva': ['incapsula', 'x-iinfo'],
                'F5': ['x-f5', 'f5'],
                'Barracuda': ['barra', 'cuda'],
                'Sucuri': ['sucuri', 'x-sucuri'],
                'Wordfence': ['wordfence'],
                'Shield': ['shield']
            }
            
            detected_waf = []
            for waf, signatures in waf_signatures.items():
                for sig in signatures:
                    if sig.lower() in str(headers).lower():
                        detected_waf.append(waf)
                        break
            
            if detected_waf:
                self.results['waf'] = list(set(detected_waf))
                self.log(f"✅ Detected WAF: {', '.join(detected_waf)}", "SUCCESS")
                
        except Exception as e:
            self.log(f"WAF detection failed: {e}", "WARNING")

    def email_extraction(self):
        """Extract email addresses"""
        self.log("Extracting email addresses...", "PROGRESS")
        
        try:
            response = self.session.get(self.base_url, timeout=10, verify=False)
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            emails = re.findall(email_pattern, response.text)
            
            # Filter out common non-email matches
            valid_emails = [e for e in emails if len(e) > 5 and not e.startswith('http')]
            
            self.results['emails'] = list(set(valid_emails))
            if valid_emails:
                self.log(f"✅ Found emails: {', '.join(valid_emails[:5])}", "SUCCESS")
            
        except Exception as e:
            self.log(f"Email extraction failed: {e}", "ERROR")

    def backup_file_scanning(self):
        """Scan for backup files"""
        self.log("Scanning for backup files...", "PROGRESS")
        
        backup_patterns = [
            'backup', 'backup.zip', 'backup.tar.gz', 'backup.sql',
            '.env', '.git', '.svn', '.htaccess', '.htpasswd',
            'config.php', 'config.ini', 'settings.py', 'web.config',
            'wp-config.php', 'app.config', 'web.xml', 'application.properties'
        ]
        
        found_backups = []
        
        for pattern in backup_patterns:
            try:
                url = f"{self.base_url}/{pattern}"
                response = self.session.get(url, timeout=3, verify=False)
                if response.status_code == 200:
                    found_backups.append(url)
                    self.log(f"⚠️ Found backup file: {url}", "WARNING")
            except Exception:
                pass
        
        self.results['backup_files'] = found_backups
        self.log(f"Found {len(found_backups)} backup files")

    def cms_detection(self):
        """Detect CMS"""
        self.log("Detecting CMS...", "PROGRESS")
        
        cms_signatures = {
            'WordPress': ['wp-content', 'wp-includes', 'wp-admin'],
            'Drupal': ['sites/all', 'misc/drupal.js'],
            'Joomla': ['media/system', 'components/com_'],
            'Magento': ['skin/frontend', 'js/mage'],
            'Shopify': ['shopify'],
            'Wix': ['wix.com'],
            'Squarespace': ['squarespace'],
            'Ghost': ['ghost.org'],
            'Prestashop': ['prestashop'],
            'OpenCart': ['opencart']
        }
        
        try:
            response = self.session.get(self.base_url, timeout=10, verify=False)
            html = response.text.lower()
            
            detected_cms = []
            for cms, signatures in cms_signatures.items():
                for sig in signatures:
                    if sig.lower() in html:
                        detected_cms.append(cms)
                        break
            
            self.results['cms'] = list(set(detected_cms))
            if detected_cms:
                self.log(f"✅ Detected CMS: {', '.join(detected_cms)}", "SUCCESS")
            
        except Exception as e:
            self.log(f"CMS detection failed: {e}", "ERROR")

    def cloud_provider_check(self):
        """Check for cloud provider"""
        self.log("Checking cloud provider...", "PROGRESS")
        
        cloud_indicators = {
            'AWS': ['ec2', 's3.amazonaws', 'aws.amazon', 'x-amz-'],
            'Azure': ['azurewebsites', 'cloudapp.azure', 'azure.com'],
            'Google Cloud': ['googleapis', 'appspot.com', 'cloud.google'],
            'Heroku': ['herokuapp.com'],
            'Digital Ocean': ['digitalocean'],
            'Linode': ['linode'],
            'Vultr': ['vultr']
        }
        
        try:
            response = self.session.get(self.base_url, timeout=10, verify=False)
            headers = str(response.headers).lower()
            
            detected_cloud = []
            for cloud, indicators in cloud_indicators.items():
                for ind in indicators:
                    if ind.lower() in headers or ind.lower() in self.domain.lower():
                        detected_cloud.append(cloud)
                        break
            
            self.results['cloud'] = list(set(detected_cloud))
            if detected_cloud:
                self.log(f"✅ Cloud provider: {', '.join(detected_cloud)}", "SUCCESS")
            
        except Exception as e:
            self.log(f"Cloud provider check failed: {e}", "ERROR")

    def cdn_detection(self):
        """Detect CDN"""
        self.log("Detecting CDN...", "PROGRESS")
        
        cdn_indicators = {
            'Cloudflare': ['cloudflare', 'cf-ray'],
            'Akamai': ['akamai', 'akamaiedge'],
            'Fastly': ['fastly'],
            'CloudFront': ['cloudfront'],
            'Varnish': ['varnish'],
            'Squid': ['squid'],
            'StackPath': ['stackpath']
        }
        
        try:
            response = self.session.get(self.base_url, timeout=10, verify=False)
            headers = str(response.headers).lower()
            
            detected_cdn = []
            for cdn, indicators in cdn_indicators.items():
                for ind in indicators:
                    if ind.lower() in headers:
                        detected_cdn.append(cdn)
                        break
            
            self.results['cdn'] = list(set(detected_cdn))
            if detected_cdn:
                self.log(f"✅ CDN: {', '.join(detected_cdn)}", "SUCCESS")
            
        except Exception as e:
            self.log(f"CDN detection failed: {e}", "ERROR")

    def link_extraction(self):
        """Extract links from the page"""
        self.log("Extracting links...", "PROGRESS")
        
        try:
            response = self.session.get(self.base_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            links = set()
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith('http'):
                    links.add(href)
                elif href.startswith('/'):
                    links.add(f"{self.base_url}{href}")
                elif href.startswith('#'):
                    continue
                else:
                    links.add(f"{self.base_url}/{href}")
            
            self.results['links'] = links
            
            # Also extract JavaScript files
            js_links = [link for link in links if link.endswith('.js')]
            self.results['js_files'] = js_links
            self.log(f"✅ Found {len(links)} links, {len(js_links)} JavaScript files")
            
        except Exception as e:
            self.log(f"Link extraction failed: {e}", "ERROR")

    def social_media_discovery(self):
        """Discover social media presence"""
        self.log("Discovering social media...", "PROGRESS")
        
        social_platforms = {
            'Facebook': ['facebook.com', 'fb.com'],
            'Twitter': ['twitter.com', 'x.com'],
            'LinkedIn': ['linkedin.com'],
            'Instagram': ['instagram.com'],
            'YouTube': ['youtube.com'],
            'GitHub': ['github.com'],
            'GitLab': ['gitlab.com'],
            'Reddit': ['reddit.com'],
            'Pinterest': ['pinterest.com'],
            'TikTok': ['tiktok.com'],
            'Snapchat': ['snapchat.com'],
            'WhatsApp': ['whatsapp.com'],
            'Telegram': ['t.me', 'telegram.org']
        }
        
        try:
            response = self.session.get(self.base_url, timeout=10, verify=False)
            html = response.text.lower()
            
            found_social = []
            for platform, domains in social_platforms.items():
                for domain in domains:
                    if domain in html:
                        found_social.append(platform)
                        break
            
            self.results['social_media'] = list(set(found_social))
            if found_social:
                self.log(f"✅ Social media presence: {', '.join(found_social)}", "SUCCESS")
            
        except Exception as e:
            self.log(f"Social media discovery failed: {e}", "ERROR")

    def git_repo_discovery(self):
        """Discover Git repositories"""
        self.log("Discovering Git repositories...", "PROGRESS")
        
        git_paths = [
            '.git/config',
            '.git/HEAD',
            '.git/index',
            '.git/objects',
            '.git/refs',
            '.git/logs'
        ]
        
        found_git = []
        for path in git_paths:
            try:
                url = f"{self.base_url}/{path}"
                response = self.session.get(url, timeout=3, verify=False)
                if response.status_code == 200:
                    found_git.append(url)
                    self.log(f"⚠️ Found Git path: {url}", "WARNING")
            except Exception:
                pass
        
        self.results['git_repos'] = found_git
        self.log(f"Found {len(found_git)} Git repository paths")

    def s3_bucket_discovery(self):
        """Discover S3 buckets"""
        self.log("Discovering S3 buckets...", "PROGRESS")
        
        # Check common S3 bucket patterns
        patterns = [
            self.domain.replace('.', '-'),
            self.domain.replace('.', ''),
            f"{self.domain.split('.')[0]}-assets",
            f"{self.domain.split('.')[0]}-media",
            f"{self.domain.split('.')[0]}-uploads",
            f"{self.domain.split('.')[0]}-images",
            f"{self.domain.split('.')[0]}-static",
            f"{self.domain.split('.')[0]}-data",
            f"assets-{self.domain}",
            f"media-{self.domain}",
            f"static-{self.domain}"
        ]
        
        found_buckets = []
        for pattern in patterns:
            url = f"http://{pattern}.s3.amazonaws.com"
            try:
                response = requests.get(url, timeout=5)
                if response.status_code != 404:
                    found_buckets.append({
                        'url': url,
                        'status': response.status_code,
                        'content_type': response.headers.get('Content-Type')
                    })
                    self.log(f"⚠️ Found S3 bucket: {url}", "WARNING")
            except Exception:
                pass
        
        self.results['s3_buckets'] = found_buckets
        self.log(f"Found {len(found_buckets)} S3 buckets")

    def subdomain_takeover_check(self):
        """Check for subdomain takeover vulnerabilities"""
        self.log("Checking for subdomain takeover...", "PROGRESS")
        
        takeover_signatures = {
            'Amazon S3': 'NoSuchBucket',
            'Azure': 'The specified account does not exist',
            'GitHub': 'There isn\'t a GitHub Pages site here',
            'Heroku': 'No such app',
            'Shopify': 'Sorry, this shop is currently unavailable',
            'Tumblr': 'There\'s nothing here',
            'WordPress': 'This blog is no longer available',
            'Zendesk': 'This help center is no longer active'
        }
        
        takeover_candidates = []
        
        for subdomain in self.results.get('subdomains', []):
            domain = f"{subdomain}.{self.domain}"
            try:
                response = requests.get(f"http://{domain}", timeout=5)
                if response.status_code in [404, 403, 410]:
                    for service, signature in takeover_signatures.items():
                        if signature.lower() in response.text.lower():
                            takeover_candidates.append({
                                'subdomain': domain,
                                'service': service,
                                'signature': signature
                            })
                            self.log(f"🚨 Potential subdomain takeover: {domain} -> {service}", "WARNING")
            except Exception:
                pass
        
        self.results['subdomain_takeover'] = takeover_candidates
        self.log(f"Found {len(takeover_candidates)} subdomain takeover candidates")

    def cookie_analysis(self):
        """Analyze cookies for security issues"""
        self.log("Analyzing cookies...", "PROGRESS")
        
        try:
            response = self.session.get(self.base_url, timeout=10, verify=False)
            cookies = response.cookies
            
            cookie_analysis = []
            for cookie in cookies:
                analysis = {
                    'name': cookie.name,
                    'secure': cookie.secure,
                    'http_only': cookie.has_nonstandard_attr('HttpOnly'),
                    'same_site': cookie.get_nonstandard_attr('SameSite'),
                    'domain': cookie.domain,
                    'path': cookie.path,
                    'expires': cookie.expires
                }
                
                # Security checks
                if not cookie.secure:
                    analysis['issue'] = 'Cookie not marked as secure'
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    analysis['issue'] = 'Cookie not marked as HttpOnly'
                
                cookie_analysis.append(analysis)
            
            self.results['cookies'] = cookie_analysis
            self.log(f"✅ Found {len(cookie_analysis)} cookies")
            
        except Exception as e:
            self.log(f"Cookie analysis failed: {e}", "ERROR")

    def form_analysis(self):
        """Analyze forms for security issues"""
        self.log("Analyzing forms...", "PROGRESS")
        
        try:
            response = self.session.get(self.base_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = []
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET'),
                    'fields': []
                }
                
                for input_tag in form.find_all('input'):
                    field = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', ''),
                        'required': input_tag.get('required') is not None
                    }
                    form_data['fields'].append(field)
                
                # Security checks
                if form.get('method', '').upper() == 'GET' and any(f['name'] == 'password' for f in form_data['fields']):
                    form_data['issue'] = 'Password field in GET form'
                
                forms.append(form_data)
            
            self.results['forms'] = forms
            self.log(f"✅ Found {len(forms)} forms")
            
        except Exception as e:
            self.log(f"Form analysis failed: {e}", "ERROR")

    def generate_report(self):
        """Generate comprehensive report"""
        self.log("Generating report...", "PROGRESS")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"webrecon_{self.domain}_{timestamp}"
        
        # JSON report
        json_file = f"{filename}.json"
        with open(json_file, 'w') as f:
            # Convert sets to lists for JSON serialization
            json_results = self.results.copy()
            for key, value in json_results.items():
                if isinstance(value, set):
                    json_results[key] = list(value)
            json.dump(json_results, f, indent=2, default=str)
        
        self.log(f"📄 JSON report saved: {json_file}", "SUCCESS")
        
        # HTML report
        html_file = f"{filename}.html"
        self.generate_html_report(html_file)
        
        self.log(f"📄 HTML report saved: {html_file}", "SUCCESS")
        
        # Print summary
        self.print_summary()

    def generate_html_report(self, filename: str):
        """Generate HTML report"""
        
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>WebRecon Report - {self.domain}</title>
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{ 
                    font-family: 'Segoe UI', Arial, sans-serif; 
                    margin: 20px; 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                }}
                .container {{ 
                    max-width: 1200px; 
                    margin: 0 auto; 
                    background: white; 
                    padding: 30px; 
                    border-radius: 15px; 
                    box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    border-radius: 10px;
                    margin-bottom: 30px;
                    text-align: center;
                }}
                .header h1 {{ font-size: 36px; margin-bottom: 10px; }}
                .header .developer {{
                    background: rgba(255,255,255,0.2);
                    display: inline-block;
                    padding: 5px 20px;
                    border-radius: 20px;
                    font-size: 14px;
                    margin-top: 10px;
                }}
                h2 {{ 
                    color: #444; 
                    margin: 30px 0 20px; 
                    padding-bottom: 10px; 
                    border-bottom: 3px solid #667eea;
                }}
                .section {{ 
                    background: #f9f9f9; 
                    padding: 20px; 
                    margin: 15px 0; 
                    border-radius: 10px; 
                    border-left: 5px solid #667eea;
                }}
                .info {{ background: #d4edda; padding: 10px; border-radius: 5px; }}
                .warning {{ background: #fff3cd; padding: 10px; border-radius: 5px; }}
                .danger {{ background: #f8d7da; padding: 10px; border-radius: 5px; }}
                table {{ 
                    width: 100%; 
                    border-collapse: collapse; 
                    margin: 15px 0;
                    border-radius: 8px;
                    overflow: hidden;
                }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    font-weight: 600;
                }}
                tr:hover {{ background: #f5f5f5; }}
                .badge {{ 
                    display: inline-block; 
                    padding: 4px 12px; 
                    border-radius: 15px; 
                    font-size: 12px;
                    font-weight: 600;
                }}
                .badge-success {{ background: #28a745; color: white; }}
                .badge-warning {{ background: #ffc107; color: black; }}
                .badge-danger {{ background: #dc3545; color: white; }}
                .badge-info {{ background: #17a2b8; color: white; }}
                .badge-primary {{ background: #007bff; color: white; }}
                .footer {{
                    text-align: center;
                    margin-top: 40px;
                    padding-top: 20px;
                    border-top: 1px solid #ddd;
                    color: #666;
                }}
                .stats-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                    gap: 15px;
                    margin: 20px 0;
                }}
                .stat-box {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 15px;
                    border-radius: 10px;
                    text-align: center;
                }}
                .stat-box .number {{
                    font-size: 28px;
                    font-weight: bold;
                }}
                .stat-box .label {{
                    font-size: 12px;
                    opacity: 0.8;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🌐 WebRecon Report</h1>
                    <p><strong>Target:</strong> {self.target}</p>
                    <p><strong>Domain:</strong> {self.domain}</p>
                    <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <div class="developer">👨‍💻 Developed by HIMA</div>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-box">
                        <div class="number">{len(self.results.get('subdomains', []))}</div>
                        <div class="label">Subdomains</div>
                    </div>
                    <div class="stat-box">
                        <div class="number">{len(self.results.get('ports', {}).get('open', []))}</div>
                        <div class="label">Open Ports</div>
                    </div>
                    <div class="stat-box">
                        <div class="number">{len(self.results.get('technologies', []))}</div>
                        <div class="label">Technologies</div>
                    </div>
                    <div class="stat-box">
                        <div class="number">{len(self.results.get('emails', []))}</div>
                        <div class="label">Emails</div>
                    </div>
                    <div class="stat-box">
                        <div class="number">{len(self.results.get('directories', []))}</div>
                        <div class="label">Directories</div>
                    </div>
                </div>

                <h2>📊 DNS Records</h2>
                <div class="section">
                    {self._dict_to_html(self.results.get('dns_records', {}))}
                </div>

                <h2>🔌 Open Ports</h2>
                <div class="section">
                    {self._list_to_html(self.results.get('ports', {}).get('open', []), 'port', 'service')}
                </div>

                <h2>🛠️ Technologies</h2>
                <div class="section">
                    {self._list_to_html_simple(self.results.get('technologies', []))}
                </div>

                <h2>🌐 Subdomains</h2>
                <div class="section">
                    {self._list_to_html_simple(self.results.get('subdomains', []))}
                </div>

                <h2>📁 Directories</h2>
                <div class="section">
                    {self._list_to_html_simple(self.results.get('directories', []))}
                </div>

                <h2>📧 Emails</h2>
                <div class="section">
                    {self._list_to_html_simple(self.results.get('emails', []))}
                </div>

                <h2>🛡️ Security Headers</h2>
                <div class="section">
                    {self._dict_to_html(self.results.get('security_headers', {}))}
                </div>

                <h2>🔐 SSL/TLS Information</h2>
                <div class="section">
                    {self._dict_to_html(self.results.get('ssl_info', {}))}
                </div>

                <h2>📝 WHOIS Information</h2>
                <div class="section">
                    {self._dict_to_html(self.results.get('whois', {}))}
                </div>

                <h2>🛡️ WAF Detection</h2>
                <div class="section">
                    {self._list_to_html_simple(self.results.get('waf', []))}
                </div>

                <h2>☁️ Cloud Provider</h2>
                <div class="section">
                    {self._list_to_html_simple(self.results.get('cloud', []))}
                </div>

                <h2>🌐 CDN</h2>
                <div class="section">
                    {self._list_to_html_simple(self.results.get('cdn', []))}
                </div>

                <h2>📸 Social Media</h2>
                <div class="section">
                    {self._list_to_html_simple(self.results.get('social_media', []))}
                </div>

                <h2>⚠️ Backup Files</h2>
                <div class="section">
                    {self._list_to_html_simple(self.results.get('backup_files', []))}
                </div>

                <h2>📦 Git Repositories</h2>
                <div class="section">
                    {self._list_to_html_simple(self.results.get('git_repos', []))}
                </div>

                <h2>🪣 S3 Buckets</h2>
                <div class="section">
                    {self._list_to_html_simple([b.get('url') for b in self.results.get('s3_buckets', [])])}
                </div>

                <h2>🚨 Subdomain Takeover</h2>
                <div class="section">
                    {self._list_to_html(self.results.get('subdomain_takeover', []), 'subdomain', 'service')}
                </div>

                <div class="footer">
                    <p>🚀 Webrecon v2.0 | Developed by HIMA | Security Research Only</p>
                    <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        with open(filename, 'w') as f:
            f.write(html_template)

    def _list_to_html(self, items, *keys):
        """Convert list to HTML table"""
        if not items:
            return "<p>No data found</p>"
        
        if not keys:
            return "<ul>" + "".join(f"<li>{item}</li>" for item in items) + "</ul>"
        
        html = "<table><thead><tr>"
        for key in keys:
            html += f"<th>{key.title()}</th>"
        html += "</tr></thead><tbody>"
        
        for item in items:
            html += "<tr>"
            if isinstance(item, dict):
                for key in keys:
                    html += f"<td>{item.get(key, '')}</td>"
            else:
                html += f"<td>{item}</td>"
            html += "</tr>"
        
        html += "</tbody></table>"
        return html

    def _list_to_html_simple(self, items):
        """Convert simple list to HTML"""
        if not items:
            return "<p>No data found</p>"
        
        return "<ul>" + "".join(f"<li>{item}</li>" for item in items) + "</ul>"

    def _dict_to_html(self, data):
        """Convert dict to HTML table"""
        if not data:
            return "<p>No data found</p>"
        
        html = "<table><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>"
        for key, value in data.items():
            if isinstance(value, (list, tuple)):
                value = ", ".join(str(v) for v in value)
            html += f"<tr><td><strong>{key}</strong></td><td>{value}</td></tr>"
        html += "</tbody></table>"
        return html

    def print_summary(self):
        """Print summary of findings"""
        print("\n" + "="*80)
        print("📊 RECONNAISSANCE SUMMARY")
        print("="*80)
        
        print(f"🎯 Target: {self.target}")
        print(f"⏰ Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        summary_items = [
            ("🌐 Subdomains", len(self.results.get('subdomains', []))),
            ("🔌 Open Ports", len(self.results.get('ports', {}).get('open', []))),
            ("🛠️ Technologies", len(self.results.get('technologies', []))),
            ("📁 Directories", len(self.results.get('directories', []))),
            ("📧 Emails", len(self.results.get('emails', []))),
            ("📦 S3 Buckets", len(self.results.get('s3_buckets', []))),
            ("📄 Backup Files", len(self.results.get('backup_files', []))),
            ("🔐 SSL/TLS", "✅" if self.results.get('ssl_info') else "❌"),
        ]
        
        for label, value in summary_items:
            if isinstance(value, str):
                print(f"  {label}: {value}")
            else:
                print(f"  {label}: {value}")
        
        print("\n" + "="*80)
        print(f"👨‍💻 Developed by: HIMA")
        print("📄 Full reports generated successfully!")
        print("="*80 + "\n")


def main():
    """Main function with argument parsing and URL input"""
    parser = argparse.ArgumentParser(
        description='All-in-One Web Reconnaissance Tool - Developed by HIMA',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python webrecon.py -u https://example.com
  python webrecon.py -u example.com -v
  python webrecon.py --url example.com
        """
    )
    
    parser.add_argument(
        '-u', '--url',
        help='Target URL to scan (e.g., https://example.com or example.com)',
        required=True
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output directory for reports (default: current directory)',
        default='.'
    )
    
    args = parser.parse_args()
    
    # Change to output directory if specified
    if args.output != '.':
        os.makedirs(args.output, exist_ok=True)
        os.chdir(args.output)
    
    # Create and run the tool
    tool = WebReconTool(args.url, args.verbose)
    tool.run_all()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️ Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)