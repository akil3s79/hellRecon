#!/usr/bin/env python3
"""
HellRecon - Advanced technology scanner with vulnerability intelligence
Author: akil3s
"""

import subprocess
import requests
import sys
import re
import json
import os
import csv
import time
import concurrent.futures
import hashlib
import urllib.parse
import signal
from datetime import datetime
from argparse import ArgumentParser
from urllib3.exceptions import InsecureRequestWarning

def signal_handler(sig, frame):
    """Handle Ctrl+C for graceful exit"""
    print(f"\n{Colors.RED}[!] Scan interrupted by user. Shutting down...{Colors.END}")
    sys.exit(0)

# Register signal handler
try:
    signal.signal(signal.SIGINT, signal_handler)
except ImportError:
    pass

def load_nvd_api_key():
    """Load NVD API key from configuration file"""
    config_path = os.path.expanduser("~/.hellrecon/config")
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
                return config.get('nvd_api_key')
    except Exception:
        pass
    return None

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

USE_COLORS = sys.stdout.isatty()

class Colors:
    RED = '\033[91m' if USE_COLORS else ''
    GREEN = '\033[92m' if USE_COLORS else ''
    YELLOW = '\033[93m' if USE_COLORS else ''
    BLUE = '\033[94m' if USE_COLORS else ''
    CYAN = '\033[96m' if USE_COLORS else ''
    MAGENTA = '\033[95m' if USE_COLORS else ''
    ORANGE = '\033[33m' if USE_COLORS else ''
    END = '\033[0m' if USE_COLORS else ''

def show_banner(method='GET'):
    print(f"""{Colors.MAGENTA}
    ╔══════════════════════════════════════════════════╗
    ║                  HellRecon PRO v2.1              ║
    ║           Technology Intelligence Scanner        ║
    ║               HTTP method: {method:<8}           ║
    ╚══════════════════════════════════════════════════╝{Colors.END}
    """)

class NVDClient:
    def __init__(self, api_key=None):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key or load_nvd_api_key()
        self.cache = {}
        self.last_request_time = 0
        self.request_delay = 6 if not self.api_key else 0.5

    def search_cves(self, tech_name, version):
        cache_key = f"{tech_name}_{version}"
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.request_delay and not self.api_key:
            time.sleep(self.request_delay - time_since_last)
        
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        try:
            url = f"{self.base_url}?keywordSearch={tech_name} {version}"
            headers = {'User-Agent': 'HellRecon-Scanner/1.0'}
            if self.api_key:
                headers['apiKey'] = self.api_key
                self.request_delay = 0.5
            
            response = requests.get(url, headers=headers, timeout=10)
            self.last_request_time = time.time()
            
            if response.status_code == 200:
                data = response.json()
                cves = []
                for vuln in data.get('vulnerabilities', []):
                    cve_id = vuln['cve']['id']
                    cves.append(cve_id)
                self.cache[cache_key] = cves
                return cves
            elif response.status_code == 403:
                print(f"{Colors.YELLOW}[WARNING] NVD API rate limit. Get free API key at: https://nvd.nist.gov/developers/request-an-api-key{Colors.END}")
            else:
                print(f"{Colors.YELLOW}[WARNING] NVD API returned {response.status_code}{Colors.END}")
        except Exception as e:
            print(f"{Colors.YELLOW}[WARNING] NVD API error: {e}{Colors.END}")
        return []

class TechnologyDetector:
    PATTERNS = {
        'servers': {
            'Apache': r'Apache[/\s-]?(\d+\.\d+(\.\d+)?)|Apache-Coyote',
            'Nginx': r'nginx[/\s](\d+\.\d+(\.\d+)?)',
            'IIS': r'Microsoft-IIS[/\s](\d+\.\d+)',
            'LiteSpeed': r'LiteSpeed',
            'Tomcat': r'Tomcat[/\s]?(\d+\.\d+(\.\d+)?)|Apache-Coyote|JSESSIONID|Apache.Tomcat/(\d+\.\d+(\.\d+)?)|<title>Apache Tomcat/(\d+\.\d+(\.\d+)?)</title>',
            'OpenResty': r'openresty[/\s](\d+\.\d+(\.\d+)?)',
        },
        'cms': {
            'WordPress': r'wp-|wordpress|/wp-content/|wp-includes/|wp-json/|wp-admin/|xmlrpc.php|/wp-links-opml.php',
            'Joomla': r'joomla|Joomla!',
            'Drupal': r'Drupal|drupal',
            'Magento': r'Magento|/static/version',
            'Shopify': r'shopify|Shopify',
            'PrestaShop': r'prestashop|PrestaShop',
            'OpenCart': r'opencart|OpenCart',
            'WooCommerce': r'woocommerce|WooCommerce',
        },
        'frameworks': {
            'React': r'react|React',
            'Angular': r'angular|Angular',
            'Vue.js': r'vue|Vue',
            'jQuery': r'jquery|jQuery',
            'Bootstrap': r'bootstrap|Bootstrap|data-bs-|btn-primary',
            'Laravel': r'laravel|Laravel',
            'Symfony': r'symfony|Symfony',
            'Django': r'django|Django',
            'Flask': r'flask|Flask',
            'Express': r'\bexpress[/\s]?\d|X-Powered-By:\s*Express|Server:\s*Express',
        },
        'languages': {
            'PHP': r'PHP[/\s](\d+\.\d+(\.\d+)?)|X-Powered-By: PHP',
            'ASP.NET': r'ASP\.NET|X-AspNet-Version',
            'Python': r'Python|Django|Flask',
            'Node.js': r'Node\.js|Express',
            'Java': r'\bJava[/\s]|JSP|JSESSIONID',
            'Ruby': r'ruby|Ruby|Rails',
            'Go': r'\bgolang\b|\bGo\s+[0-9]|X-Powered-By:\s*Go|Server:\s*Go',
        },
        'javascript': {
            'Google Analytics': r'ga\.js|google-analytics',
            'Google Tag Manager': r'googletagmanager',
            'Facebook Pixel': r'facebook\.com/tr/',
            'Hotjar': r'hotjar',
            'Stripe': r'stripe|Stripe',
            'PayPal': r'paypal|PayPal',
        },
        'control_panels': {
            'Plesk': r'Plesk|plesk',
            'cPanel': r'cPanel',
            'Webmin': r'Webmin',
            'DirectAdmin': r'DirectAdmin',
        },
        'wafs': {
            'CloudFlare': r'cloudflare|cf-ray|__cfduid|cf-cache-status',
            'AWS CloudFront': r'aws.?cloudfront|x-amz-cf-pop|x-amz-cf-id',
            'AWS WAF': r'awselb/|x-amz-id|awswaf',
            'Akamai': r'akamai|X-Akamai',
            'Sucuri': r'sucuri|sucuri_cloudproxy',
            'Incapsula': r'incapsula|incap_ses|visid_incap',
            'ModSecurity': r'mod_security|modsecurity',
            'Wordfence': r'wordfence|wfwaf',
            'Comodo': r'comodo.waf',
            'FortiWeb': r'fortiweb',
        },
        'cdns': {
            'CloudFlare CDN': r'cloudflare',
            'Akamai CDN': r'akamai',
            'Fastly': r'fastly|X-Fastly',
            'Google Cloud CDN': r'google',
            'Azure CDN': r'azure|microsoft',
            'AWS CloudFront CDN': r'cloudfront',
            'CloudFront': r'cloudfront',
            'MaxCDN': r'maxcdn|netdna',
        },
        'databases': {
            'MySQL': r'mysql|MySQL|MariaDB',
            'PostgreSQL': r'postgresql|PostgreSQL', 
            'MongoDB': r'mongodb|MongoDB',
            'Redis': r'redis|Redis',
            'SQLite': r'sqlite|SQLite'
        }
    }

    def __init__(self, verbose=False, method='GET', user_agent=None, delay=0):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        })
        self.session.verify = False
        self.verbose = verbose
        self.method = method
        self.delay = delay

    def auto_detect_method(self, url):
        """Auto-detect best HTTP method based on WAF detection"""
        methods = ['HEAD', 'GET', 'POST']
        
        for method in methods:
            try:
                if method == 'HEAD':
                    response = self.session.head(url, timeout=5, allow_redirects=True)
                elif method == 'GET':
                    response = self.session.get(url, timeout=5, allow_redirects=True)
                elif method == 'POST':
                    response = self.session.post(url, data={'test': 'scan'}, timeout=5, allow_redirects=True)
                
                if response.status_code == 200:
                    # Check for WAF indicators
                    headers_str = str(response.headers).lower()
                    waf_indicators = ['cloudflare', 'akamai', 'imperva', 'f5', 'barracuda', 'fortinet']
                    
                    if any(waf in headers_str for waf in waf_indicators):
                        if self.verbose:
                            print(f"{Colors.YELLOW}[*] WAF detected, preferring POST method{Colors.END}")
                        return 'POST'  # POST often bypasses WAFs better
                    
                    return method  # Use first working method
                    
            except Exception:
                continue
        
        return 'GET'  # Default fallback

    def aggressive_tomcat_version_hunt(self, base_url):
        """Aggressive Tomcat version detection"""
        tomcat_paths = {
            '/docs/': r'Apache Tomcat/(\d+\.\d+\.\d+)',
            '/manager/': r'Tomcat Manager Application.*?(\d+\.\d+\.\d+)',
            '/host-manager/': r'Tomcat Host Manager.*?(\d+\.\d+\.\d+)',
            '/examples/': r'Apache Tomcat/(\d+\.\d+\.\d+)',
        }
        
        for path, pattern in tomcat_paths.items():
            try:
                full_url = base_url.rstrip('/') + path
                response = self.session.get(full_url, timeout=8, allow_redirects=True)
                if response.status_code == 200:
                    match = re.search(pattern, response.text, re.IGNORECASE | re.DOTALL)
                    if match:
                        return match.group(1)
            except Exception:
                continue
        return None

    def aggressive_jboss_detection(self, base_url):
        """Aggressive JBoss version and configuration detection"""
        jboss_paths = {
            '/web-console/': r'JBoss[^\d]*(\d+\.\d+(\.\d+)?)',
            '/jmx-console/': r'JBoss[^\d]*(\d+\.\d+(\.\d+)?)',
            '/admin-console/': r'JBoss[^\d]*(\d+\.\d+(\.\d+)?)',
            '/status/': r'JBoss[^\d]*(\d+\.\d+(\.\d+)?)',
        }
        
        for path, pattern in jboss_paths.items():
            try:
                full_url = base_url.rstrip('/') + path
                response = self.session.get(full_url, timeout=8, allow_redirects=True)
                if response.status_code == 200:
                    match = re.search(pattern, response.text, re.IGNORECASE | re.DOTALL)
                    if match:
                        return match.group(1)
            except Exception:
                continue
        return None

    def aggressive_weblogic_detection(self, base_url):
        """Aggressive WebLogic version detection"""
        weblogic_paths = {
            '/console/': r'WebLogic Server.*?(\d+\.\d+(\.\d+)?)',
            '/console/login/': r'WebLogic Server.*?(\d+\.\d+(\.\d+)?)',
            '/ws_utc/': r'WebLogic',
            '/bea_wls_deployment_internal/': r'WebLogic',
        }
        
        for path, pattern in weblogic_paths.items():
            try:
                full_url = base_url.rstrip('/') + path
                response = self.session.get(full_url, timeout=8, allow_redirects=True)
                if response.status_code == 200:
                    match = re.search(pattern, response.text, re.IGNORECASE | re.DOTALL)
                    if match:
                        return match.group(1) if match.groups() else 'Unknown'
            except Exception:
                continue
        return None

    def wp_checksum_analysis(self, base_url):
        """WordPress version detection via file checksums and GPL source analysis"""
        if self.verbose:
            print(f"{Colors.CYAN}[*] Starting checksum analysis...{Colors.END}")
        
        # Critical WordPress files with unique checksums per version
        wp_signature_files = {
            '/wp-includes/version.php': 'version_core',
            '/wp-admin/js/common.js': 'admin_common', 
            '/wp-includes/js/jquery/jquery.js': 'jquery_wrapped',
            '/wp-includes/js/wp-embed.min.js': 'embed_script',
            '/wp-includes/css/dist/block-library/style.min.css': 'block_library',
            '/wp-login.php': 'login_page',
            '/wp-admin/install.php': 'install_page'
        }
        
        file_signatures = {}
        
        for path, file_type in wp_signature_files.items():
            try:
                full_url = base_url.rstrip('/') + path
                response = self.session.get(full_url, timeout=10, allow_redirects=True)
                
                if response.status_code == 200:
                    content = response.text
                    
                    # Generate signature: hash + key characteristics
                    file_hash = hashlib.md5(content.encode()).hexdigest()
                    file_length = len(content)
                    line_count = content.count('\n')
                    
                    file_signatures[file_type] = {
                        'hash': file_hash,
                        'length': file_length, 
                        'lines': line_count,
                        'content_sample': content[:500]  # First 500 chars for pattern matching
                    }
                    
                    if self.verbose:
                        print(f"{Colors.CYAN}[*] Got signature for {file_type}: {file_hash[:8]}...{Colors.END}")
                        
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.YELLOW}[*] Failed {path}: {e}{Colors.END}")
                continue
        
        # Analyze signatures to determine version
        if file_signatures:
            version = self._analyze_wp_signatures(file_signatures)
            if version:
                return version
        
        return None

    def _analyze_wp_signatures(self, signatures):
        """Analyze file signatures to determine WordPress version"""
        
        # Check for specific version patterns in content
        version_patterns = [
            # WordPress 6.x patterns
            (r'wp\.blocks', '6.0+'),
            (r'wp\.blockEditor', '5.0+'),
            (r'wp\-embed', '4.4+'),
            (r'rest-api', '4.4+'),
            (r'wp\-api', '4.4+'),
            # jQuery version wrapped by WordPress
            (r'jQuery v1\.12\.4-wp', '4.5-5.9'),
            (r'jQuery v1\.12\.4', '4.5+'),
            (r'jQuery v3\.6\.0', '5.7+'),
            # Block editor patterns
            (r'wp-block-editor', '5.0+'),
            (r'wp-block-library', '5.0+'),
            # Gutenberg patterns
            (r'gutenberg', '4.9.8-5.0'),
        ]
        
        found_versions = {}
        
        for file_type, signature in signatures.items():
            content = signature['content_sample']
            
            # Check patterns in content
            for pattern, version in version_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    found_versions[version] = found_versions.get(version, 0) + 2
                    if self.verbose:
                        print(f"{Colors.GREEN}[CHECKSUM] Pattern {pattern} -> {version}{Colors.END}")
            
            # Analyze file lengths for version clues
            if file_type == 'version_core' and signature['length'] > 0:
                if signature['length'] < 2000:
                    found_versions['4.0-5.0'] = found_versions.get('4.0-5.0', 0) + 1
                elif signature['length'] > 3000:
                    found_versions['5.5+'] = found_versions.get('5.5+', 0) + 1
        
        if found_versions:
            best_version = max(found_versions, key=found_versions.get)
            if self.verbose:
                print(f"{Colors.GREEN}[CHECKSUM] Version estimate: {best_version}{Colors.END}")
            return best_version
        
        return None

    def scan_target(self, url, deep_wp_scan=False):
        """Scan a single target and return technologies and response"""
        if self.verbose:
            print(f"{Colors.CYAN}[*] Scanning: {url} [{self.method}]{Colors.END}")
        
        technologies = {}
        try:
            # Apply delay if configured
            if self.delay > 0:
                time.sleep(self.delay)
                
            # Multi-method support
            if self.method == 'POST':
                response = self.session.post(url, data={'scan': 'hellrecon'}, timeout=10, allow_redirects=True)
            elif self.method == 'HEAD':
                response = self.session.head(url, timeout=10, allow_redirects=True)
            else:  # GET
                response = self.session.get(url, timeout=10, allow_redirects=True)

            tech_from_headers = self.detect_from_headers(response.headers)
            technologies.update(tech_from_headers)
            # tech_from_content = self.detect_from_content(response.text)
            tech_from_content = {}
            # Buscar Tomcat directamente en el título
            title_match = re.search(r'<title>Apache Tomcat/(\d+\.\d+(\.\d+)?)</title>', response.text, re.IGNORECASE)
            if title_match:
                tech_from_content['Tomcat'] = {
                    'type': 'server',
                    'version': title_match.group(1),
                    'confidence': 'high',
                    'source': 'html_title'
                }
                if verbose:
                    print(f"{Colors.CYAN}[DIRECT SCAN] Found Tomcat {title_match.group(1)} in HTML title{Colors.END}")
            technologies.update(tech_from_content)
            
            # Deep WordPress scanning for hardened sites
            if deep_wp_scan and 'WordPress' in technologies:
                wp_versions = self.deep_wp_version_scan(url)
                if wp_versions:
                    # Update with the best version found
                    best_version = max(wp_versions, key=wp_versions.get)
                    technologies['WordPress'] = {
                        'type': 'cms',
                        'version': best_version,
                        'confidence': 'high',
                        'source': 'deep_scan'
                    }
                    if self.verbose:
                        print(f"{Colors.GREEN}[DEEP SCAN] WordPress version found: {best_version}{Colors.END}")
            
            return technologies, response
        except Exception as e:
            if self.verbose:
                print(f"{Colors.RED}[ERROR] Scanning {url}: {e}{Colors.END}")
            return {}, None

    def detect_from_headers(self, headers):
        technologies = {}
        server_header = headers.get('Server', '')
        powered_by = headers.get('X-Powered-By', '')
        php_version = headers.get('X-PHP-Version', '')
        aspnet_version = headers.get('X-AspNet-Version', '')
        aspnet_mvc = headers.get('X-AspNetMvc-Version', '')

        for server, pattern in self.PATTERNS['servers'].items():
            match = re.search(pattern, server_header, re.IGNORECASE)
            if match:
                # Extract version properly
                version = 'Unknown'
                if match.groups():
                    for group in match.groups():
                        if group and re.match(r'\d+\.\d+(\.\d+)?', str(group)):
                            version = group
                            break
                # Special case for Apache-Coyote
                if server == 'Apache' and 'Apache-Coyote' in server_header:
                    version = 'Tomcat-Coyote'
                # Special cases for embedded servers
                if server == 'Apache' and 'Apache-Coyote' in server_header:
                    # This is actually Tomcat
                    technologies['Tomcat'] = {
                        'type': 'server', 
                        'version': 'Tomcat-Coyote',
                        'confidence': 'high',
                        'source': 'header'
                    }
                    continue  # Skip adding Apache    
                technologies[server] = {
                    'type': 'server',
                    'version': version,
                    'confidence': 'high',
                    'source': 'header'
                }

        if php_version:
            technologies['PHP'] = {
                'type': 'language',
                'version': php_version,
                'confidence': 'high',
                'source': 'header'
            }
        elif 'PHP' in powered_by:
            php_match = re.search(r'PHP[/\s](\d+\.\d+(\.\d+)?)', powered_by)
            if php_match:
                technologies['PHP'] = {
                    'type': 'language',
                    'version': php_match.group(1),
                    'confidence': 'high',
                    'source': 'header'
                }

        if aspnet_version:
            technologies['ASP.NET'] = {
                'type': 'language',
                'version': aspnet_version,
                'confidence': 'high',
                'source': 'header'
            }
        elif aspnet_mvc:
            technologies['ASP.NET MVC'] = {
                'type': 'framework',
                'version': aspnet_mvc,
                'confidence': 'high',
                'source': 'header'
            }

        for panel, pattern in self.PATTERNS['control_panels'].items():
            if re.search(pattern, powered_by, re.IGNORECASE):
                technologies[panel] = {
                    'type': 'control_panel',
                    'version': 'Unknown',
                    'confidence': 'medium',
                    'source': 'header'
                }

        os_patterns = {
            'Ubuntu': {'pattern': r'ubuntu[/\s]?(\d+\.\d+(\.\d+)?)|ubuntu(\d+\.\d+(\.\d+)?)', 'default_version': 'Unknown'},
            'Debian': {'pattern': r'debian[/\s]?(\d+\.\d+(\.\d+)?)|debian(\d+\.\d+(\.\d+)?)', 'default_version': 'Unknown'},
            'CentOS': {'pattern': r'centos[/\s]?(\d+\.\d+(\.\d+)?)|centos(\d+\.\d+(\.\d+)?)', 'default_version': 'Unknown'},
            'Windows': {'pattern': r'Windows|Microsoft', 'default_version': 'Unknown'},
            'Red Hat': {'pattern': r'redhat|Red.Hat', 'default_version': 'Unknown'},
        }

        combined_headers = f"{server_header} {powered_by}"
        for os_name, os_info in os_patterns.items():
            match = re.search(os_info['pattern'], combined_headers, re.IGNORECASE)
            if match:
                version = os_info['default_version']
                if match.groups():
                    for group in match.groups():
                        if group and re.match(r'\d+\.\d+', str(group)):
                            version = group
                            break
                
                # Adjust confidence based on evidence
                confidence = 'low'
                source = 'header'
                
                # Higher confidence if found in Server header specifically
                if match.group(0) in server_header:
                    confidence = 'medium'
                
                # Lower confidence for Ubuntu specifically (common false positive)
                if os_name == 'Ubuntu':
                    confidence = 'low'
                    
                technologies[os_name] = {
                    'type': 'os',
                    'version': version,
                    'confidence': confidence,
                    'source': source
                }
                break

        # Avoid duplicates: If it has already been detected as a WAF, do not mark it as a CDN
        for cdn, pattern in self.PATTERNS['cdns'].items():
            if cdn not in technologies:  # Only if not already detected
                if re.search(pattern, combined_headers, re.IGNORECASE):
                    technologies[cdn] = {
                        'type': 'cdn', 
                        'version': 'Unknown',
                        'confidence': 'medium',
                        'source': 'header'
                    }
        return technologies

    def parse_html_metadata(self, content):
        """Parse obvious version information from HTML metadata"""
        metadata_tech = {}
        
        # Search in meta tags
        meta_generator = re.search(r'<meta name="generator" content="([^"]+)"', content, re.IGNORECASE)
        if meta_generator:
            generator_content = meta_generator.group(1)
            # Detect Tomcat in generator
            tomcat_match = re.search(r'Tomcat[/\s]?(\d+\.\d+(\.\d+)?)', generator_content, re.IGNORECASE)
            if tomcat_match:
                metadata_tech['Tomcat'] = {
                    'type': 'server', 
                    'version': tomcat_match.group(1),
                    'confidence': 'high',
                    'source': 'meta_generator'
                }
        
        # Search in titles
        title_match = re.search(r'<title>Apache Tomcat/(\d+\.\d+(\.\d+)?)</title>', content, re.IGNORECASE)
        if title_match:
            metadata_tech['Tomcat'] = {
                'type': 'server',
                'version': title_match.group(1), 
                'confidence': 'high',
                'source': 'html_title'
            }
        
        return metadata_tech

    def detect_from_content(self, content):                    
        technologies = {}
        
        # NEW: Parse HTML metadata first
        metadata_tech = self.parse_html_metadata(content)
        technologies.update(metadata_tech)
        
        # If we found Tomcat in metadata, we're done
        if 'Tomcat' in technologies:
            return technologies
        
        comment_pattern = r'<!--.*?-->'
        comments = re.findall(comment_pattern, content)
           
        for comment in comments:
            php_match = re.search(r'PHP[/\s]?(\d+\.\d+(\.\d+)?)', comment, re.IGNORECASE)
            if php_match:
                technologies['PHP'] = {
                    'type': 'language',
                    'version': php_match.group(1),
                    'confidence': 'medium',
                    'source': 'comment'
                }

            if 'WordPress' in comment:
                wp_match = re.search(r'WordPress[/\s]?(\d+\.\d+(\.\d+)?)', comment, re.IGNORECASE)
                if wp_match:
                    technologies['WordPress'] = {
                        'type': 'cms',
                        'version': wp_match.group(1),
                        'confidence': 'high',
                        'source': 'comment'
                    }

        # Search for Tomcat in page title
        title_match = re.search(r'<title>Apache Tomcat/(\d+\.\d+(\.\d+)?)</title>', content, re.IGNORECASE)
        if title_match:
            technologies['Tomcat'] = {
                'type': 'server',
                'version': title_match.group(1),
                'confidence': 'high',
                'source': 'html_title'
            }
            if self.verbose:
                print(f"{Colors.CYAN}[TITLE SCAN] Found Tomcat {title_match.group(1)} in HTML title{Colors.END}")

        # Search for Tomcat anywhere in content
        tomcat_patterns = [
            r'Apache Tomcat/(\d+\.\d+(\.\d+)?)',
            r'Tomcat[/\s]?(\d+\.\d+(\.\d+)?)',
        ]
        
        for pattern in tomcat_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match and 'Tomcat' not in technologies:
                version = match.group(1)
                technologies['Tomcat'] = {
                    'type': 'server',
                    'version': version,
                    'confidence': 'medium',
                    'source': 'content_scan'
                }
                break

        # Rest of the existing detection code
        wp_links_urls = ['/wp-links-opml.php', '/wp-includes/wlwmanifest.xml', '/wp-json/wp/v2/', '/readme.html']
        for wp_path in wp_links_urls:
            if wp_path in content:
                try:
                    version_match = re.search(r'WordPress (\d+\.\d+(\.\d+)?)', content)
                    if version_match:
                        technologies['WordPress'] = {
                            'type': 'cms',
                            'version': version_match.group(1),
                            'confidence': 'high',
                            'source': 'wp_specific_file'
                        }
                    elif 'WordPress' not in technologies:
                        technologies['WordPress'] = {
                            'type': 'cms',
                            'version': 'Unknown',
                            'confidence': 'high',
                            'source': 'wp_specific_file'
                        }
                    break
                except Exception:
                    pass

        # [MANTEN EL RESTO DEL CÓDIGO ORIGINAL AQUÍ - desde wp_version_patterns hasta el final]
        # Advanced WordPress version detection
        wp_version_patterns = [
            r'<meta name="generator" content="WordPress (\d+\.\d+(\.\d+)?)"',
            r'wp-includes/js/wp-embed.min.js\?ver=(\d+\.\d+(\.\d+)?)',
            r'wp-includes/css/dist/block-library/style.min.css\?ver=(\d+\.\d+(\.\d+)?)',
            r'Version (\d+\.\d+(\.\d+)?)',
            r'wp-includes/js/jquery/jquery.js\?ver=(\d+\.\d+(\.\d+)?)',
            r'wp-content/themes/.+?/style.css\?ver=(\d+\.\d+(\.\d+)?)',
            r'wp-content/plugins/.+?/.+?\.js\?ver=(\d+\.\d+(\.\d+)?)'
        ]

        for pattern in wp_version_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match and match.group(1):
                technologies['WordPress'] = {
                    'type': 'cms',
                    'version': match.group(1),
                    'confidence': 'high',
                    'source': 'meta_tag' if 'meta' in pattern else 'file_version'
                }
                break

        # [SIGUE CON TODO EL RESTO DEL CÓDIGO ORIGINAL...]
        # WooCommerce version detection
        wc_patterns = [
            r'woocommerce/assets/js/frontend/(.+?)\.js\?ver=(\d+\.\d+(\.\d+)?)',
            r'Woocommerce.*?(\d+\.\d+(\.\d+)?)',
            r'wc-(.+?)-(\d+\.\d+(\.\d+)?)'
        ]

        for pattern in wc_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                version = None
                for group in match.groups():
                    if group and re.match(r'\d+\.\d+(\.\d+)?', str(group)):
                        version = group
                        break
                if version:
                    technologies['WooCommerce'] = {
                        'type': 'cms', 
                        'version': version,
                        'confidence': 'medium',
                        'source': 'file_version'
                    }
                    break
                
        version_patterns = {
            'Bootstrap': [
                r'bootstrap[.-](\d+\.\d+(\.\d+)?)\.(js|css)',
                r'bootstrap.*?v?(\d+\.\d+(\.\d+)?)',
                r'Bootstrap\s+(\d+\.\d+(\.\d+)?)'
            ],
            'jQuery': [
                r'jquery[.-](\d+\.\d+(\.\d+)?)\.js',
                r'jquery/(\d+\.\d+(\.\d+)?)/jquery',
                r'jQuery\s+(\d+\.\d+(\.\d+)?)'
            ],
            'React': [
                r'react[.-](\d+\.\d+(\.\d+)?)\.js',
                r'react@(\d+\.\d+(\.\d+)?)'
            ],
            'Vue.js': [
                r'vue[.-](\d+\.\d+(\.\d+)?)\.js',
                r'vue@(\d+\.\d+(\.\d+)?)'
            ],
            'Font Awesome': [
                r'font-awesome[.-](\d+\.\d+(\.\d+)?)',
                r'Font.Awesome\s+(\d+\.\d+(\.\d+)?)'
            ]
        }

        for tech, patterns in version_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    if tech in technologies:
                        if technologies[tech]['version'] == 'Unknown' or len(version) > len(technologies[tech]['version']):
                            technologies[tech]['version'] = version
                            technologies[tech]['confidence'] = 'high'
                            technologies[tech]['source'] = 'version_detection'
                    else:
                        tech_type = 'framework' if tech in ['Bootstrap', 'jQuery', 'React', 'Vue.js'] else 'icons'
                        technologies[tech] = {
                            'type': tech_type,
                            'version': version,
                            'confidence': 'high',
                            'source': 'version_detection'
                        }
                    break

        js_patterns = {
            'jQuery': r'jquery[.-](\d+\.\d+(\.\d+)?)\.js',
            'React': r'react[.-](\d+\.\d+(\.\d+)?)\.js',
            'Vue.js': r'vue[.-](\d+\.\d+(\.\d+)?)\.js',
            'Bootstrap': r'bootstrap[.-](\d+\.\d+(\.\d+)?)\.(js|css)',
        }

        for tech, pattern in js_patterns.items():
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                technologies[tech] = {
                    'type': 'framework',
                    'version': match.group(1),
                    'confidence': 'high',
                    'source': 'js_css'
                }

        for js_tech, pattern in self.PATTERNS['javascript'].items():
            if re.search(pattern, content, re.IGNORECASE):
                technologies[js_tech] = {
                    'type': 'javascript',
                    'version': 'Unknown',
                    'confidence': 'medium',
                    'source': 'content'
                }

        if re.search(r'PHPSESSID[= ]', content):
            technologies['PHP Sessions'] = {
                'type': 'feature',
                'version': 'Unknown',
                'confidence': 'medium',
                'source': 'cookie'
            }
        if re.search(r'JSESSIONID[= ]', content):
            technologies['Java Sessions'] = {
                'type': 'feature',
                'version': 'Unknown',
                'confidence': 'medium',
                'source': 'cookie'
            }

        for category in ['cms', 'frameworks', 'languages']:
            for tech, pattern in self.PATTERNS[category].items():
                if re.search(pattern, content, re.IGNORECASE) and tech not in technologies:
                    if tech == 'Java' and not re.search(r'JSESSIONID[= ]', content):
                        continue
                    tech_type = 'cms' if category == 'cms' else (category[:-1] if category.endswith('s') else category)
                    technologies[tech] = {
                        'type': tech_type,
                        'version': 'Unknown',
                        'confidence': 'medium',
                        'source': 'content'
                    }

        # Database detection
        for db, pattern in self.PATTERNS['databases'].items():
            if re.search(pattern, content, re.IGNORECASE) and db not in technologies:
                technologies[db] = {
                    'type': 'database',
                    'version': 'Unknown',
                    'confidence': 'low',
                    'source': 'content'
                }

        # Advanced WordPress version fuzzing for hardened sites
        if 'WordPress' in technologies and technologies['WordPress']['version'] == 'Unknown':
            wp_fuzz_paths = [
                '/wp-includes/version.php',
                '/readme.html', 
                '/wp-admin/install.php',
                '/wp-login.php'
            ]
            technologies['WordPress']['confidence'] = 'medium'

        # WordPress plugin and theme detection
        if 'WordPress' in technologies:
            plugin_patterns = {
                'Yoast SEO': r'wp-content/plugins/wordpress-seo/',
                'Contact Form 7': r'wp-content/plugins/contact-form-7/', 
                'WooCommerce': r'wp-content/plugins/woocommerce/',
                'Elementor': r'wp-content/plugins/elementor/',
                'Akismet': r'wp-content/plugins/akismet/',
            }
            
            for plugin, pattern in plugin_patterns.items():
                if re.search(pattern, content, re.IGNORECASE) and plugin not in technologies:
                    technologies[plugin] = {
                        'type': 'wordpress_plugin',
                        'version': 'Unknown',
                        'confidence': 'medium',
                        'source': 'content'
                    }
            
            theme_match = re.search(r'wp-content/themes/([^/]+)/', content, re.IGNORECASE)
            if theme_match:
                theme_name = theme_match.group(1)
                technologies[f'WordPress Theme: {theme_name}'] = {
                    'type': 'wordpress_theme', 
                    'version': 'Unknown',
                    'confidence': 'medium',
                    'source': 'content'
                }

        return technologies

    def deep_wp_version_scan(self, base_url):
        """Deep scan for WordPress version in common files"""
        wp_version_files = {
            '/wp-includes/version.php': [
                r'\$wp_version\s*=\s*[\'"]([\d.]+)[\'"]',
                r'wp_version\s*=\s*[\'"]([\d.]+)[\'"]'
            ],
            '/readme.html': [
                r'Version\s+([\d.]+)\s*-\s*WordPress',  # "Version 6.2 - WordPress"
                r'WordPress\s+([\d.]+)',                # "WordPress 6.2"
                r'<h1>WordPress\s+([\d.]+)</h1>',       # "<h1>WordPress 6.2</h1>"
                r'WordPress Version\s+([\d.]+)',        # "WordPress Version 6.2"
                r'version\s+([\d.]+)\s+of\s+WordPress', # "version 6.2 of WordPress"
                r'Tested up to:\s+([\d.]+)'             # "Tested up to: 6.2"
            ],
            '/wp-admin/includes/version.php': [
                r'\$wp_version\s*=\s*[\'"]([\d.]+)[\'"]',
                r'wp_version\s*=\s*[\'"]([\d.]+)[\'"]'
            ],
            '/wp-links-opml.php': [
                r'WordPress\s*([\d.]+)',
                r'generator="WordPress/([\d.]+)"',
                r'WordPress/([\d.]+)',
                r'wp\.version\s*=\s*[\'"]([\d.]+)[\'"]',
                r'Version:\s*([\d.]+)'
            ],
        }
        
        found_versions = {}
        
        for path, patterns in wp_version_files.items():
            try:
                full_url = base_url.rstrip('/') + path
                if self.verbose:
                    print(f"{Colors.CYAN}[DEEP SCAN] Trying: {full_url}{Colors.END}")
                
                response = self.session.get(full_url, timeout=8, allow_redirects=True)
                
                if self.verbose:
                    print(f"{Colors.CYAN}[DEEP SCAN] Status: {response.status_code}{Colors.END}")
                
                if response.status_code == 200:
                    content = response.text
                   
                    version_found = False
                    for pattern in patterns:
                        match = re.search(pattern, content, re.IGNORECASE)
                        if match:
                            version = match.group(1)
                            # EAL-TIME VALIDATION - only accept plausible versions
                            if version and re.match(r'^\d+\.\d+(\.\d+)?$', version) and len(version) >= 3:
                                found_versions[version] = found_versions.get(version, 0) + 1
                                if self.verbose:
                                    print(f"{Colors.GREEN}[DEEP SCAN] Valid WP {version} in {path} with pattern: {pattern}{Colors.END}")
                            else:
                                if self.verbose:
                                    print(f"{Colors.YELLOW}[DEEP SCAN] Rejected invalid version '{version}' from {path} with pattern: {pattern}{Colors.END}")
                            if self.verbose:
                                print(f"{Colors.GREEN}[DEEP SCAN] Found WP {version} in {path} with pattern: {pattern}{Colors.END}")
                            version_found = True
                            break
                    
                    if not version_found and self.verbose:
                        print(f"{Colors.RED}[DEEP SCAN] NO MATCH for any pattern in {path}{Colors.END}")
                        
                else:
                    if self.verbose:
                        print(f"{Colors.YELLOW}[DEEP SCAN] HTTP {response.status_code} for {path}{Colors.END}")
                    
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.RED}[DEEP SCAN] Failed {path}: {e}{Colors.END}")
                continue
        
        return found_versions        
        
    def aggressive_wp_version_hunt(self, base_url):
        """Aggressive WordPress version hunting for hardened sites"""
        if self.verbose:
            print(f"{Colors.CYAN}[AGGRESSIVE HUNT] Launching ultimate WordPress version hunt...{Colors.END}")
            
        wp_hunt_paths = {
            # Critical paths that always leak version
            '/wp-includes/version.php': [
                r'\$wp_version\s*=\s*[\'"]([\d.]+)[\'"]',
                r'wp_version\s*=\s*[\'"]([\d.]+)[\'"]'
            ],
            '/wp-admin/includes/version.php': [
                r'\$wp_version\s*=\s*[\'"]([\d.]+)[\'"]',
                r'wp_version\s*=\s*[\'"]([\d.]+)[\'"]'  
            ],
            '/readme.html': [
                r'Version\s+([\d.]+)\s*-\s*WordPress',
                r'WordPress\s+([\d.]+)',
                r'<h1>WordPress\s+([\d.]+)</h1>',
                r'WordPress Version\s+([\d.]+)',
                r'version\s+([\d.]+)\s+of\s+WordPress',
                r'Tested up to:\s+([\d.]+)'
            ],
            # Style and script files with versions
            '/wp-includes/css/dist/block-library/style.min.css': [
                r'ver=([\d.]+)',
                r'wp-([\d.]+)'
            ],
            '/wp-includes/js/wp-embed.min.js': [
                r'ver=([\d.]+)',
                r'embed-([\d.]+)'
            ],
            '/wp-admin/load-styles.php': [
                r'ver=([\d.]+)',
                r'wp-([\d.]+)'
            ],
            '/wp-admin/load-scripts.php': [
                r'ver=([\d.]+)', 
                r'wp-([\d.]+)'
            ],
            # RSS feeds with versions
            '/feed/': [
                r'wordpress/([\d.]+)',
                r'wp-([\d.]+)'
            ],
            '/comments/feed/': [
                r'wordpress/([\d.]+)',
                r'wp-([\d.]+)'
            ],
            # WP-JSON API
            '/wp-json/wp/v2/': [
                r'wordpress/([\d.]+)',
                r'wp-([\d.]+)'
            ]
        }
            
        found_versions = {}
            
        for path, patterns in wp_hunt_paths.items():
            try:
                full_url = base_url.rstrip('/') + path
                if self.verbose:
                    print(f"{Colors.CYAN}[AGGRESSIVE HUNT] Trying: {full_url}{Colors.END}")
                    
                response = self.session.get(full_url, timeout=8, allow_redirects=True)
                    
                if response.status_code == 200:
                    content = response.text
                        
                    for pattern in patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            if isinstance(match, tuple):
                                # Take first group matching version pattern
                                for group in match:
                                    if group and re.match(r'^\d+\.\d+(\.\d+)?$', str(group)):
                                        version = group
                                        found_versions[version] = found_versions.get(version, 0) + 3  # Higher weight
                                        if self.verbose:
                                            print(f"{Colors.GREEN}[AGGRESSIVE HUNT] Found WP {version} in {path}{Colors.END}")
                                        break
                            else:
                                if match and re.match(r'^\d+\.\d+(\.\d+)?$', str(match)):
                                    version = match
                                    found_versions[version] = found_versions.get(version, 0) + 3
                                    if self.verbose:
                                        print(f"{Colors.GREEN}[AGGRESSIVE HUNT] Found WP {version} in {path}{Colors.END}")
                        
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.YELLOW}[AGGRESSIVE HUNT] Failed {path}: {e}{Colors.END}")
                continue
            
        # Also try HEAD requests for common files
        common_wp_files = [
            '/wp-includes/js/jquery/jquery.js',
            '/wp-admin/js/common.js', 
            '/wp-includes/js/wp-emoji-release.min.js',
            '/wp-content/themes/twentyTwenty/style.css'
        ]
            
        for wp_file in common_wp_files:
            try:
                full_url = base_url.rstrip('/') + wp_file
                response = self.session.head(full_url, timeout=5, allow_redirects=False)
                if response.status_code == 200:
                    # Look for version in URLs or headers
                    etag = response.headers.get('ETag', '')
                    version_match = re.search(r'wp-?(\d+\.\d+(\.\d+)?)', etag, re.IGNORECASE)
                    if version_match:
                        version = version_match.group(1)
                        found_versions[version] = found_versions.get(version, 0) + 1
                        if self.verbose:
                            print(f"{Colors.GREEN}[AGGRESSIVE HUNT] Found WP {version} in ETag{Colors.END}")
            except Exception:
                continue
            
        if found_versions:
            # Return version with most "points"
            best_version = max(found_versions, key=found_versions.get)
            return best_version
   
        # NUCLEAR OPTION: Try HTTPS if HTTP fails
        if base_url.startswith('http://') and not found_versions:
            https_url = base_url.replace('http://', 'https://')
            if self.verbose:
                print(f"{Colors.CYAN}[AGGRESSIVE HUNT] Trying HTTPS: {https_url}{Colors.END}")
            return self.aggressive_wp_version_hunt(https_url)
        
        # LAST RESORT: Check ONLY official WordPress meta generator
        try:
            main_response = self.session.get(base_url, timeout=10, allow_redirects=True)
            main_content = main_response.text
            
            # Only check official WordPress generator meta tag - most reliable source
            generator_pattern = r'<meta name="generator" content="WordPress (\d+\.\d+(\.\d+)?)"'
            match = re.search(generator_pattern, main_content, re.IGNORECASE)
            
            if match:
                version = match.group(1)
                # Validate it's a plausible WordPress version
                if version and re.match(r'^\d+\.\d+(\.\d+)?$', version) and len(version) >= 3:
                    found_versions[version] = found_versions.get(version, 0) + 5  # High confidence
                    if self.verbose:
                        print(f"{Colors.GREEN}[AGGRESSIVE HUNT] Found valid WP {version} in official generator meta tag{Colors.END}")
            
        except Exception as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[AGGRESSIVE HUNT] Meta scan failed: {e}{Colors.END}")

        return None

    def wp_version_fingerprint(self, base_url):
        """WordPress version fingerprinting by API behavior and features"""
        if self.verbose:
            print(f"{Colors.CYAN}[FINGERPRINT] Starting behavioral fingerprinting...{Colors.END}")
        
        version_clues = {}
        
        # Check WP-JSON API features (different versions have different endpoints)
        api_endpoints = [
            '/wp-json/wp/v2/users',
            '/wp-json/wp/v2/posts', 
            '/wp-json/wp/v2/types',
            '/wp-json/wp/v2/taxonomies'
        ]
        
        for endpoint in api_endpoints:
            try:
                full_url = base_url.rstrip('/') + endpoint
                response = self.session.get(full_url, timeout=8, allow_redirects=True)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Version clues from API structure
                    if isinstance(data, list) and len(data) > 0:
                        # Check for specific fields that indicate version
                        if any('content' in item for item in data):
                            version_clues['5.0+'] = version_clues.get('5.0+', 0) + 1
                        if any('excerpt' in item for item in data):
                            version_clues['4.7+'] = version_clues.get('4.7+', 0) + 1
                            
            except Exception:
                continue
        
        # Check login page features
        try:
            login_url = base_url.rstrip('/') + '/wp-login.php'
            response = self.session.get(login_url, timeout=8, allow_redirects=True)
            
            if response.status_code == 200:
                content = response.text
                
                # Login page changes by version
                if 'wp-core-ui' in content:
                    version_clues['3.8+'] = version_clues.get('3.8+', 0) + 2
                if 'language_switcher' in content:
                    version_clues['5.0+'] = version_clues.get('5.0+', 0) + 1
                if 'interim-login' in content:
                    version_clues['4.9+'] = version_clues.get('4.9+', 0) + 1
                    
        except Exception:
            pass
        
        if version_clues:
            best_clue = max(version_clues, key=version_clues.get)
            if self.verbose:
                print(f"{Colors.GREEN}[FINGERPRINT] Behavioral clue: {best_clue}{Colors.END}")
            return best_clue
        
        return None

    def extract_woocommerce_details(self, base_url):
        """Extract detailed WooCommerce information including templates version"""
        try:
            # WooCommerce API endpoints that reveal version
            wc_endpoints = [
                '/wp-json/wc/v3/system_status',
                '/wp-json/wc/v2/system_status',
                '/wp-content/plugins/woocommerce/woocommerce.php'
            ]
            
            for endpoint in wc_endpoints:
                full_url = base_url.rstrip('/') + endpoint
                response = self.session.get(full_url, timeout=8, allow_redirects=True)
                
                if response.status_code == 200:
                    content = response.text
                    
                    # WooCommerce version in system status
                    wc_version_match = re.search(r'"woocommerce_version":"([\d.]+)"', content)
                    if wc_version_match:
                        return wc_version_match.group(1)
                    
                    # WooCommerce version in plugin header
                    wc_plugin_match = re.search(r'Version:\s*([\d.]+)', content)
                    if wc_plugin_match:
                        return wc_plugin_match.group(1)
                        
        except Exception as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[WOOCOMMERCE] Detail extraction failed: {e}{Colors.END}")
        
        return None

    def detect_plugin_versions(self, base_url):
        """Detect versions for common WordPress plugins"""
        plugin_version_patterns = {
            'Contact Form 7': {
                'file': '/wp-content/plugins/contact-form-7/readme.txt',
                'pattern': r'Stable tag:\s*([\d.]+)'
            },
            'Yoast SEO': {
                'file': '/wp-content/plugins/wordpress-seo/readme.txt', 
                'pattern': r'Stable tag:\s*([\d.]+)'
            },
            'WooCommerce': {
                'file': '/wp-content/plugins/woocommerce/readme.txt',
                'pattern': r'Stable tag:\s*([\d.]+)'
            }
        }
        
        plugin_versions = {}
        
        for plugin_name, plugin_info in plugin_version_patterns.items():
            try:
                full_url = base_url.rstrip('/') + plugin_info['file']
                response = self.session.get(full_url, timeout=5, allow_redirects=True)
                
                if response.status_code == 200:
                    match = re.search(plugin_info['pattern'], response.text)
                    if match:
                        plugin_versions[plugin_name] = match.group(1)
                        if self.verbose:
                            print(f"{Colors.GREEN}[PLUGIN] {plugin_name} version found: {match.group(1)}{Colors.END}")
                            
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.YELLOW}[PLUGIN] Failed to detect {plugin_name}: {e}{Colors.END}")
        
        return plugin_versions

    def detect_theme_version(self, base_url, theme_name):
        """Detect version for a specific WordPress theme"""
        theme_files = [
            f'/wp-content/themes/{theme_name}/style.css',
            f'/wp-content/themes/{theme_name}/readme.txt',
        ]
        
        for theme_file in theme_files:
            try:
                full_url = base_url.rstrip('/') + theme_file
                response = self.session.get(full_url, timeout=5, allow_redirects=True)
                
                if response.status_code == 200:
                    # Pattern for style.css
                    version_match = re.search(r'Version:\s*([\d.]+)', response.text)
                    if version_match:
                        return version_match.group(1)
                    
                    # Pattern for readme.txt  
                    stable_match = re.search(r'Stable tag:\s*([\d.]+)', response.text)
                    if stable_match:
                        return stable_match.group(1)
                        
            except Exception:
                continue
        
        return 'Unknown'

# REST OF THE CODE REMAINS THE SAME (SearchSploitClient, VulnerabilityChecker, ReportGenerator, etc.)
# ... [El resto del código se mantiene igual que en tu versión original]

class SearchSploitClient:
    # ... [Código idéntico al original]
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.cache = {}
    
    def update_database(self):
        """Update the SearchSploit database"""
        try:
            print(f"{Colors.CYAN}[*] Updating SearchSploit database...{Colors.END}")
            print(f"{Colors.YELLOW}[INFO] This may take several minutes. Be patient...{Colors.END}")
            
            # Redirect stderr for mute warnings apt 
            result = subprocess.run(['searchsploit', '-u'], 
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, timeout=300)
            
            if result.returncode == 0:
                print(f"{Colors.GREEN}[+] SearchSploit database updated successfully{Colors.END}")
                return True
            else:
                print(f"{Colors.YELLOW}[WARNING] SearchSploit update completed with warnings{Colors.END}")
                return True
        except subprocess.TimeoutExpired:
            print(f"{Colors.YELLOW}[WARNING] SearchSploit update timed out. Using existing database.{Colors.END}")
            return True
        except Exception as e:
            print(f"{Colors.YELLOW}[WARNING] SearchSploit update error: {e}. Using existing database.{Colors.END}")
            return True
    
    def search_exploit(self, cve_id):
        """Search for exploits for a CVE using SearchSploit"""
        if cve_id in self.cache:
            return self.cache[cve_id]
        
        try:
            # Searchsploit busca por CVE
            result = subprocess.run(['searchsploit', '--cve', cve_id, '--json'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                if data.get('RESULTS_EXPLOIT'):
                    # Encontramos exploits - devolver info
                    exploits = []
                    for exploit in data['RESULTS_EXPLOIT']:
                        exploits.append({
                            'title': exploit.get('Title', ''),
                            'path': exploit.get('Path', ''),
                            'date': exploit.get('Date', '')
                        })
                    self.cache[cve_id] = exploits
                    return exploits
        except Exception as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[WARNING] SearchSploit search failed for {cve_id}: {e}{Colors.END}")
        
        self.cache[cve_id] = None
        return None

class VulnerabilityChecker:
    # ... [Código idéntico al original]
    def __init__(self, nvd_client=None, use_nvd=True, exploit_client=None):
        self.nvd_client = nvd_client
        self.use_nvd = use_nvd
        self.exploit_client = exploit_client
        self.KNOWN_VULNS = {
            'Apache': {
                '2.4.49': ['CVE-2021-41773', 'CVE-2021-42013'],
                '2.4.50': ['CVE-2021-42013'],
                '2.4.46': ['CVE-2021-26690'],
            },
            'Nginx': {
                '1.19.0': ['CVE-2021-23017'],
                '1.18.0': ['CVE-2021-23017'],
                '1.16.0': ['CVE-2019-20372'],
            },
            'PHP': {
                '5.6.40': ['CVE-2019-11043', 'CVE-2019-11044', 'CVE-2019-11045'],
                '7.4.0': ['CVE-2020-7068'],
                '7.3.0': ['CVE-2019-11048'],
                '5.6.0': ['CVE-2016-3185'],
            },
            'WordPress': {
                '5.7': ['CVE-2021-24291'],
                '5.6': ['CVE-2021-24290'],
                '5.5': ['CVE-2020-28032'],
            },
            'Ubuntu': {
                '20.04': ['CVE-2021-3493', 'CVE-2021-3156'],
                '18.04': ['CVE-2021-3493', 'CVE-2021-3156'],
            }
        }

    def check_technology(self, tech_name, version):
        vulns = []
        if tech_name in self.KNOWN_VULNS:
            if version in self.KNOWN_VULNS[tech_name]:
                vulns.extend(self.KNOWN_VULNS[tech_name][version])
            for vuln_version, cves in self.KNOWN_VULNS[tech_name].items():
                if version != vuln_version and self._is_similar_version(version, vuln_version):
                    vulns.extend(cves)
        if self.use_nvd and self.nvd_client and version != 'Unknown':
            nvd_vulns = self.nvd_client.search_cves(tech_name, version)
            vulns.extend(nvd_vulns)
        return list(set(vulns))
        
    def check_technology_with_exploits(self, tech_name, version, confidence='medium'):
        """Enhanced version that also searches for exploits"""
        # Filter CVEs based on detection confidence
        vulns = []

        # Only search for CVEs if we have good confidence or specific conditions
        if confidence == 'high':
            vulns = self.check_technology(tech_name, version)
        elif confidence == 'medium' and version not in ['Unknown', 'None', '']:
            vulns = self.check_technology(tech_name, version)
        elif confidence == 'low':
            # For low confidence, don't show CVEs for OS detection (too noisy)
            vulns = []
        # SPECIAL CASE: Don't show CVEs for WordPress with unknown version (too noisy)
        if tech_name == 'WordPress' and version == 'Unknown':
            vulns = []        
            
        exploits_info = {}
        if self.exploit_client and vulns:
            for cve in vulns:
                exploit_url = self.exploit_client.search_exploit(cve)
                if exploit_url:
                    exploits_info[cve] = exploit_url
        
        return vulns, exploits_info
        
    def _is_similar_version(self, version1, version2):
        try:
            v1_parts = version1.split('.')
            v2_parts = version2.split('.')
            if len(v1_parts) >= 2 and len(v2_parts) >= 2:
                return v1_parts[0] == v2_parts[0] and v1_parts[1] == v2_parts[1]
        except Exception:
            pass
        return False

class ReportGenerator:
    @staticmethod
    def generate_html_report(scan_results, output_file):
        html_template = """<!DOCTYPE html>
<html>
<head>
    <title>HellRecon Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .technology {{ margin: 10px 0; padding: 10px; border-left: 4px solid #3498db; }}
        .vulnerable {{ border-left-color: #e74c3c; background: #fdf2f2; }}
        .safe {{ border-left-color: #27ae60; }}
        .vuln-list {{ margin-left: 20px; color: #c0392b; }}
        .exploit-list {{ margin-left: 30px; color: #d35400; font-size: 0.9em; }}
        .stats {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .target-section {{ margin: 30px 0; }}
        a {{ color: #2980b9; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .exploit {{ background: #fff3cd; padding: 5px; margin: 2px 0; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>HellRecon Scan Report</h1>
        <p>Generated on: {timestamp}</p>
    </div>
    <div class="stats">
        <h3>Scan Statistics</h3>
        <p>Targets Scanned: {target_count}</p>
        <p>Total Technologies Found: {tech_count}</p>
        <p>Total Vulnerabilities: {vuln_count}</p>
        <p>Total Exploits Found: {exploit_count}</p>
    </div>
    {content}
</body>
</html>"""
        content = ""
        total_tech = 0
        total_vuln = 0
        total_exploit = 0
        
        for target, data in scan_results.items():
            content += '<div class="target-section">'
            content += f"<h2>Target: {target}</h2>"
            technologies = data['technologies']
            vuln_checker = data['vuln_checker']
            
            for tech, info in technologies.items():
                total_tech += 1
                version = info['version']
                tech_type = info['type']
                
                # USE THE FUNCTION WITH EXPLOITS
                if hasattr(vuln_checker, 'check_technology_with_exploits'):
                    vulns, exploits = vuln_checker.check_technology_with_exploits(tech, version, info.get('confidence', 'medium'))
                else:
                    vulns = vuln_checker.check_technology(tech, version)
                    exploits = {}
                
                total_vuln += len(vulns)
                total_exploit += len(exploits)
                
                vuln_class = "vulnerable" if vulns else "safe"
                content += f'<div class="technology {vuln_class}"><strong>{tech} {version}</strong> - {tech_type}'
                
                if vulns:
                    content += "<div class='vuln-list'>"
                    for vuln in vulns:
                        content += f'<div><a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln}" target="_blank">{vuln}</a>'
                        
                        # ADD EXPLOITS IF AVAILABLE
                        if vuln in exploits and exploits[vuln]:
                            content += "<div class='exploit-list'>"
                            for exploit in exploits[vuln][:2]:  # Max 2 exploits
                                title = exploit.get('title', 'Unknown')
                                path = exploit.get('path', '')
                                filename = os.path.basename(path) if path else "Unknown"
                                content += f'<div class="exploit"><strong>Exploit:</strong> {title} <em>({filename})</em></div>'
                            content += "</div>"
                        content += "</div>"
                    content += "</div>"
                content += "</div>"
            content += '</div>'
        
        html_content = html_template.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            target_count=len(scan_results),
            tech_count=total_tech,
            vuln_count=total_vuln,
            exploit_count=total_exploit,
            content=content
        )
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"{Colors.GREEN}[+] HTML report generated: {output_file}{Colors.END}")

    @staticmethod
    def generate_csv_report(scan_results, output_file):
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Target', 'Technology', 'Version', 'Type', 'Vulnerabilities'])
            for target, data in scan_results.items():
                technologies = data['technologies']
                vuln_checker = data['vuln_checker']
                for tech, info in technologies.items():
                    version = info['version']
                    tech_type = info['type']
                    vulns = vuln_checker.check_technology(tech, version)
                    writer.writerow([target, tech, version, tech_type, '; '.join(vulns) if vulns else 'None'])
        print(f"{Colors.GREEN}[+] CSV report generated: {output_file}{Colors.END}")

    @staticmethod
    def generate_json_report(scan_results, output_file):
        """Generate JSON report with full scan details"""
        report_data = {
            'scan_metadata': {
                'generated_at': datetime.now().isoformat(),
                'scanner': 'HellRecon PRO',
                'version': '2.0'
            },
            'targets': {}
        }
        
        for target, data in scan_results.items():
            technologies = data['technologies']
            vuln_checker = data['vuln_checker']
            
            target_data = {
                'url': target,
                'technologies': []
            }
            
            for tech, info in technologies.items():
                tech_data = {
                    'name': tech,
                    'version': info['version'],
                    'type': info['type'],
                    'confidence': info['confidence'],
                    'source': info['source']
                }
                
                # Add vulnerabilities if any
                vulns = vuln_checker.check_technology(tech, info['version'])
                if vulns:
                    tech_data['vulnerabilities'] = vulns
                
                target_data['technologies'].append(tech_data)
            
            report_data['targets'][target] = target_data
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"{Colors.GREEN}[+] JSON report generated: {output_file}{Colors.END}")

    @staticmethod
    def generate_pwndoc_report(scan_results, output_file):
        """Generate Pwndoc-compatible JSON report for enterprise pentesting"""
        pwndoc_template = {
            "name": "HellRecon Technology Assessment",
            "version": "2.1",
            "creator": "HellRecon PRO",
            "created": datetime.now().isoformat(),
            "tests": []
        }
        
        for target, data in scan_results.items():
            technologies = data['technologies']
            vuln_checker = data['vuln_checker']
            
            for tech, info in technologies.items():
                version = info['version']
                tech_type = info['type']
                
                # USE THE FUNCTION WITH EXPLOITS
                if hasattr(vuln_checker, 'check_technology_with_exploits'):
                    vulns, exploits = vuln_checker.check_technology_with_exploits(tech, version, info.get('confidence', 'medium'))
                else:
                    vulns = vuln_checker.check_technology(tech, version)
                    exploits = {}
                
                # Create finding for each technology with vulnerabilities
                if vulns:
                    finding = {
                        "title": f"{tech} {version} - Technology Detection",
                        "description": f"Identified {tech} version {version} with associated vulnerabilities.",
                        "observation": f"The technology {tech} version {version} was detected during reconnaissance.",
                        "proof": f"Detection method: {info.get('source', 'unknown')}. Confidence: {info.get('confidence', 'medium')}",
                        "severity": "Info",  # Base severity, can be upgraded based on CVEs
                        "cves": vulns,
                        "exploits": list(exploits.keys()) if exploits else [],
                        "references": [f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}" for cve in vulns]
                    }
                    pwndoc_template["tests"].append(finding)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(pwndoc_template, f, indent=2, ensure_ascii=False)
        
        print(f"{Colors.GREEN}[+] Pwndoc report generated: {output_file}{Colors.END}")

def is_valid_wordpress_version(version):
    """
    Validate if a version string is a plausible WordPress version
    Returns: (is_valid, confidence)
    """
    if not version or version == 'Unknown':
        return False, 0
    
    # Basic format validation
    if not re.match(r'^\d+(\.\d+)*$', version):
        return False, 0
    
    parts = version.split('.')
    
    # Single digit (like "2") - LOW confidence
    if len(parts) == 1:
        return False, 0  # Changed from (True, 1) to (False, 0)
        # WordPress started at 0.7, current is 6.x
        if 1 <= version_num <= 7:
            return True, 1  # Plausible but low confidence
        else:
            return False, 0
    
    # Major version (like "6.8") - MEDIUM confidence  
    elif len(parts) == 2:
        major, minor = int(parts[0]), int(parts[1])
        if (0 <= major <= 6) and (0 <= minor <= 99):
            return True, 3
        else:
            return False, 0
    
    # Full version (like "6.8.3") - HIGH confidence
    elif len(parts) == 3:
        major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
        if (0 <= major <= 6) and (0 <= minor <= 99) and (0 <= patch <= 99):
            return True, 5
        else:
            return False, 0
    
    # Unusual format - very low confidence
    else:
        return True, 0.5

def get_wordpress_version_fallback(version_candidates):
    """
    Intelligent fallback system for WordPress version detection
    Returns best version or None if no good candidate
    """
    if not version_candidates:
        return None
    
    validated_candidates = {}
    
    for version, score in version_candidates.items():
        is_valid, validity_confidence = is_valid_wordpress_version(version)
        
        if is_valid:
            # Combine detection score with validity confidence
            final_score = score * validity_confidence
            validated_candidates[version] = final_score
    
    if not validated_candidates:
        return None
    
    # Get best candidate
    best_version = max(validated_candidates, key=validated_candidates.get)
    best_score = validated_candidates[best_version]
    
    # INCREASE THRESHOLD - ONLY ACCEPT MEDIUM/HIGH CONFIDENCE
    if best_score >= 8:  # Increased from 5 to 8
        return best_version
    else:
        return None

def scan_single_target(url, verbose=False, use_nvd=True, nvd_key=None, use_searchsploit=False, deep_wp_scan=False, method='GET', user_agent=None, delay=0):
    detector = TechnologyDetector(verbose=verbose, method=method, user_agent=user_agent, delay=delay)
    # Auto-detect method if not specified
    if method == 'AUTO':
        auto_method = detector.auto_detect_method(url)
        if verbose:
            print(f"{Colors.CYAN}[*] Auto-detected method: {auto_method}{Colors.END}")
        detector.method = auto_method
    nvd_client = NVDClient(nvd_key) if use_nvd else None
    searchsploit_client = SearchSploitClient(verbose=verbose) if use_searchsploit else None
    vuln_checker = VulnerabilityChecker(nvd_client, use_nvd, searchsploit_client)
    
    try:
        response = detector.session.get(url, timeout=10, allow_redirects=True)
        technologies = {}
        technologies = {}
        tech_from_headers = detector.detect_from_headers(response.headers)
        technologies.update(tech_from_headers)
        tech_from_content = detector.detect_from_content(response.text)
        technologies.update(tech_from_content)
        
        # Initialize version_candidates for all cases
        version_candidates = {}
        
        # NEW STRATEGY: SCORING SYSTEM FOR WORDPRESS
        if 'WordPress' in technologies:
            if verbose:
                print(f"{Colors.CYAN}[*] WordPress detected, launching multi-layer detection...{Colors.END}")
            
            version_candidates = {}
            
            # LAYER 1: Deep Scan (High confidence)
            wp_versions = detector.deep_wp_version_scan(url)
            for version, count in wp_versions.items():
                # HIGHER WEIGHT FOR EXACT VERSIONS (X.X.X) vs MAJOR VERSIONS (X)
                if version.count('.') >= 2:  # Exact version like 6.8.3
                    weight = 15
                elif version.count('.') == 1:  # Major version like 6.8  
                    weight = 10
                else:  # Single digit like 2
                    weight = 5
                version_candidates[version] = version_candidates.get(version, 0) + (count * weight)
            
            # LAYER 2: Aggressive Hunt (Medium confidence)  
            ultimate_version = detector.aggressive_wp_version_hunt(url)
            if ultimate_version:
                # Higher weight for exact versions from aggressive hunt
                if ultimate_version.count('.') >= 2:
                    version_candidates[ultimate_version] = version_candidates.get(ultimate_version, 0) + 12
                else:
                    version_candidates[ultimate_version] = version_candidates.get(ultimate_version, 0) + 8
            
            # LAYER 3: Behavioral Fingerprinting (Low confidence)
            behavioral_version = detector.wp_version_fingerprint(url)
            if behavioral_version:
                version_candidates[behavioral_version] = version_candidates.get(behavioral_version, 0) + 3
            
            # LAYER 4: Checksum Analysis (Medium confidence)
            checksum_version = detector.wp_checksum_analysis(url)
            if checksum_version:
                version_candidates[checksum_version] = version_candidates.get(checksum_version, 0) + 6
            
        # SELECT BEST VERSION WITH VALIDATION (only if we have candidates)
        if version_candidates and len(version_candidates) > 0:
            # Apply intelligent validation and fallback
            best_valid_version = get_wordpress_version_fallback(version_candidates)
            
            if best_valid_version:
                confidence_score = version_candidates[best_valid_version]
                
                # DETERMINE CONFIDENCE AND SOURCE
                if confidence_score >= 10:
                    confidence = 'high'
                    source = 'multi_layer'
                elif confidence_score >= 5:
                    confidence = 'medium' 
                    source = 'multi_layer'
                else:
                    confidence = 'low'
                    source = 'behavioral'
                
                technologies['WordPress'] = {
                    'type': 'cms',
                    'version': best_valid_version,
                    'confidence': confidence,
                    'source': source,
                    'score': confidence_score
                }
                
                if verbose:
                    print(f"{Colors.GREEN}[MULTI-LAYER] WordPress {best_valid_version} detected (score: {confidence_score}){Colors.END}")
            else:
                # NO GOOD CANDIDATE FOUND - mark as unknown but detected
                technologies['WordPress'] = {
                    'type': 'cms',
                    'version': 'Unknown',
                    'confidence': 'low', 
                    'source': 'version_not_detected',
                    'score': 0
                }
                if verbose:
                    print(f"{Colors.YELLOW}[MULTI-LAYER] WordPress detected but version could not be determined{Colors.END}")
                    
        # APPLICATION SERVERS DETECTION - ENHANCED VERSION
        # Tomcat version detection for Coyote servers
        if 'Tomcat' in technologies and technologies['Tomcat']['version'] == 'Unknown':
            tomcat_version = detector.aggressive_tomcat_version_hunt(url)
            if tomcat_version:
                technologies['Tomcat']['version'] = tomcat_version
                technologies['Tomcat']['confidence'] = 'high'
                if verbose:
                    print(f"{Colors.GREEN}[*] Tomcat version found: {tomcat_version}{Colors.END}")

        # JBoss detection from headers or content
        jboss_indicators = ['JBoss', 'jboss', 'JBossAS', 'JBossWeb']
        if any(indicator in str(technologies) for indicator in jboss_indicators) or \
           any(indicator in str(response.headers) for indicator in jboss_indicators) or \
           any(indicator in response.text for indicator in jboss_indicators):
            
            jboss_version = detector.aggressive_jboss_detection(url)
            if jboss_version:
                technologies['JBoss'] = {
                    'type': 'server',
                    'version': jboss_version,
                    'confidence': 'medium',
                    'source': 'aggressive_detection'
                }
                if verbose:
                    print(f"{Colors.GREEN}[*] JBoss version found: {jboss_version}{Colors.END}")

        # WebLogic detection
        weblogic_indicators = ['WebLogic', 'weblogic', 'WebLogicServer', 'Oracle-WebLogic']
        if any(indicator in str(technologies) for indicator in weblogic_indicators) or \
           any(indicator in str(response.headers) for indicator in weblogic_indicators) or \
           any(indicator in response.text for indicator in weblogic_indicators):
            
            weblogic_version = detector.aggressive_weblogic_detection(url)
            if weblogic_version:
                technologies['WebLogic'] = {
                    'type': 'server', 
                    'version': weblogic_version,
                    'confidence': 'medium',
                    'source': 'aggressive_detection'
                }
                if verbose:
                    print(f"{Colors.GREEN}[*] WebLogic version found: {weblogic_version}{Colors.END}")

        # Enhanced WooCommerce version detection (keep as is)
        if 'WooCommerce' in technologies and technologies['WooCommerce']['version'] == 'Unknown':
            wc_detailed_version = detector.extract_woocommerce_details(url)
            if wc_detailed_version:
                technologies['WooCommerce'] = {
                    'type': 'cms',
                    'version': wc_detailed_version,
                    'confidence': 'high',
                    'source': 'api_detection'
                }
                if verbose:
                    print(f"{Colors.GREEN}[WOOCOMMERCE] Detailed version found: {wc_detailed_version}{Colors.END}")

        # Enhanced plugin and theme version detection
        if 'WordPress' in technologies:
            # Detect plugin versions
            plugin_versions = detector.detect_plugin_versions(url)
            for plugin, version in plugin_versions.items():
                if plugin in technologies:
                    technologies[plugin]['version'] = version
                    technologies[plugin]['confidence'] = 'medium'
                else:
                    technologies[plugin] = {
                        'type': 'wordpress_plugin',
                        'version': version,
                        'confidence': 'medium',
                        'source': 'plugin_detection'
                    }
            
            # Detect theme versions
            for tech_name, tech_info in technologies.items():
                if tech_info.get('type') == 'wordpress_theme':
                    theme_name = tech_name.replace('WordPress Theme: ', '')
                    theme_version = detector.detect_theme_version(url, theme_name)
                    if theme_version != 'Unknown':
                        technologies[tech_name]['version'] = theme_version
                        technologies[tech_name]['confidence'] = 'medium'

    except Exception as e:
        if verbose:
            print(f"{Colors.RED}[ERROR] Scanning {url}: {e}{Colors.END}")
        technologies = {}
        response = None
    
    return {
        'technologies': technologies,
        'vuln_checker': vuln_checker,
        'response': response
    }

def main():
    parser = ArgumentParser(description='HellRecon PRO - Advanced technology intelligence scanner')
    parser.add_argument('--nvd-key', help='NVD API key (overrides config file)')
    parser.add_argument('target', nargs='*', help='Target URL(s) to scan')
    parser.add_argument('-f', '--file', help='File containing list of URLs')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('--report-format', choices=['html', 'csv', 'json', 'pwndoc'], default='none', help='Report format')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show debug information')
    parser.add_argument('--no-nvd', action='store_true', help='Disable NVD API lookups')
    parser.add_argument('--searchsploit', action='store_true', help='Enable SearchSploit lookups')
    parser.add_argument('--deep-wp-scan', action='store_true', help='Deep WordPress version scanning for hardened sites')
    parser.add_argument('--update-searchsploit', action='store_true', help='Update SearchSploit database before scanning')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads for batch scanning')
    parser.add_argument('--method', choices=['GET', 'POST', 'HEAD', 'AUTO'], default='GET', help='HTTP method for scanning (default: GET)')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    parser.add_argument('--delay', type=float, default=0, help='Delay between requests in seconds')
    parser.add_argument('--format', choices=['html', 'csv', 'json', 'pwndoc'], default='none', help='Report format')
    args = parser.parse_args()
    show_banner(args.method)
    targets = []
    if args.target:
        targets.extend(args.target)
    if args.file:
        try:
            with open(args.file, 'r') as f:
                targets.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(f"{Colors.RED}[ERROR] File not found: {args.file}{Colors.END}")
            sys.exit(1)
    if not targets:
        print(f"{Colors.RED}[ERROR] No targets specified. Use -f or provide URLs.{Colors.END}")
        parser.print_help()
        sys.exit(1)

    valid_targets = []
    for target in targets:
        if target.startswith(('http://', 'https://')):
            valid_targets.append(target)
        else:
            print(f"{Colors.YELLOW}[WARNING] Skipping invalid URL: {target}{Colors.END}")
    if not valid_targets:
        print(f"{Colors.RED}[ERROR] No valid URLs found.{Colors.END}")
        sys.exit(1)
    # Actualizar SearchSploit si se solicita
    if args.update_searchsploit:
        client = SearchSploitClient(verbose=args.verbose)
        client.update_database()
        
    print(f"{Colors.CYAN}[*] Starting scan of {len(valid_targets)} target(s){Colors.END}")
    print(f"{Colors.CYAN}[*] Threads: {args.threads} | NVD: {not args.no_nvd} | Method: {args.method}{Colors.END}")
    print("-" * 60)

    start_time = time.time()
    scan_results = {}

    if len(valid_targets) == 1:
        result = scan_single_target(
            valid_targets[0], 
            args.verbose, 
            not args.no_nvd, 
            args.nvd_key, 
            args.searchsploit, 
            args.deep_wp_scan,
            args.method,
            args.user_agent,
            args.delay
        )
        scan_results[valid_targets[0]] = result
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_url = {
                executor.submit(scan_single_target, url, args.verbose, not args.no_nvd, args.nvd_key, args.searchsploit, args.deep_wp_scan, args.method, args.user_agent, args.delay): url
                for url in valid_targets
            }
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    scan_results[url] = result
                    print(f"{Colors.GREEN}[+] Completed: {url}{Colors.END}")
                except Exception as e:
                    print(f"{Colors.RED}[ERROR] Failed scanning {url}: {e}{Colors.END}")
                        
                    url = future_to_url[future]
                    try:
                        result = future.result(timeout=2)
                        scan_results[url] = result
                        print(f"{Colors.GREEN}[+] Completed: {url}{Colors.END}")
                    except concurrent.futures.TimeoutError:
                        continue
                    except Exception as e:
                        print(f"{Colors.RED}[ERROR] Failed scanning {url}: {e}{Colors.END}")
                            
                except KeyboardInterrupt:
                    print(f"{Colors.YELLOW}[!] Immediate shutdown requested{Colors.END}")
                    for f in future_to_url:
                        f.cancel()
    total_tech = 0
    total_vuln = 0
    for url, data in scan_results.items():
        technologies = data['technologies']
        vuln_checker = data['vuln_checker']
        if technologies:
            print(f"\n{Colors.CYAN}[*] Results for: {url}{Colors.END}")
            print("-" * 50)
        for tech, info in technologies.items():
            total_tech += 1
            version = info['version']
            tech_type = info['type']
            confidence = info['confidence']
            icons = {
                'server': '[SERVER]', 'cms': '[CMS]', 'framework': '[FRAMEWORK]', 'language': '[LANGUAGE]',
                'os': '[OS]', 'javascript': '[JS]', 'feature': '[FEATURE]', 'control_panel': '[PANEL]',
                'waf': '[WAF]', 'cdn': '[CDN]'
            }
            icon = icons.get(tech_type, '[?]')
            
            # USE THE NEW FEATURE WITH EXPLOITS AND CONFIDENCE
            if hasattr(vuln_checker, 'check_technology_with_exploits'):
                vulns, exploits = vuln_checker.check_technology_with_exploits(tech, version, info['confidence'])
            else:
                vulns = vuln_checker.check_technology(tech, version)
                exploits = {}
            
            total_vuln += len(vulns)
            if vulns:
                print(f"{icon} {Colors.RED}{tech} {version}{Colors.END} - {tech_type}")
                for vuln in vulns:
                    if vuln in exploits:
                        exploit_info = exploits[vuln]
                        if exploit_info and len(exploit_info) > 0:
                            print(f"   └── {Colors.RED}{vuln}{Colors.END}")
                            for i, exploit in enumerate(exploit_info[:2]):  
                                title = exploit.get('title', 'Unknown')
                                path = exploit.get('path', '')
                                filename = os.path.basename(path) if path else "Unknown"
                                
                                # EPIC COLORS - LOOKS GREAT ON ANY DEVICE
                                print(f"       {Colors.MAGENTA}╔═[EXPLOIT {i+1}]{Colors.END}")
                                print(f"       {Colors.MAGENTA}║  {Colors.CYAN}{title}{Colors.END}")
                                print(f"       {Colors.MAGENTA}╚═>{Colors.GREEN} {filename}{Colors.END}")
                    else:
                        print(f"   └── {Colors.RED}{vuln}{Colors.END}")
            else:  
                color = Colors.GREEN if confidence == 'high' else Colors.YELLOW
                confidence_icon = '✓' if info['confidence'] == 'high' else '?' if info['confidence'] == 'medium' else '⁇'
                print(f"{icon} {color}{tech} {version}{Colors.END} - {tech_type} {confidence_icon}")

    if args.output:
        if args.report_format == 'html' or args.report_format is None:
            ReportGenerator.generate_html_report(scan_results, args.output)
        elif args.report_format == 'csv':
            ReportGenerator.generate_csv_report(scan_results, args.output)
        elif args.report_format == 'json':
            ReportGenerator.generate_json_report(scan_results, args.output)
        elif args.report_format == 'pwndoc':
            ReportGenerator.generate_pwndoc_report(scan_results, args.output)

    total_time = time.time() - start_time
    print(f"\n{Colors.CYAN}[*] Scan completed in {total_time:.2f} seconds{Colors.END}")
    print(f"{Colors.CYAN}[*] Total: {len(scan_results)} targets, {total_tech} technologies, {total_vuln} vulnerabilities{Colors.END}")
    if args.output:
        print(f"{Colors.GREEN}[+] Report saved to: {args.output}{Colors.END}")

if __name__ == "__main__":
    main()