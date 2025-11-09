#!/usr/bin/env python3
"""
HellRecon - Advanced technology scanner with vulnerability intelligence
Author: akil3s
"""

import requests
import sys
import re
import json
import os
import csv
import time
import concurrent.futures
from datetime import datetime
from argparse import ArgumentParser
from urllib3.exceptions import InsecureRequestWarning
import urllib.parse

def load_nvd_api_key():
    """Carga la API key de NVD desde archivo de configuracion"""
    config_path = os.path.expanduser("~/.hellrecon/config")
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
                return config.get('nvd_api_key')
    except Exception:
        pass
    return None

# Suprimir warnings de SSL
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

def show_banner():
    print(f"""{Colors.MAGENTA}
    ╔══════════════════════════════════════════════════╗
    ║                   HellRecon PRO                  ║
    ║           Technology Intelligence Scanner        ║
    ║               HTTP method: GET                   ║
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
            'Apache': r'Apache[/\s](\d+\.\d+(\.\d+)?)',
            'Nginx': r'nginx[/\s](\d+\.\d+(\.\d+)?)',
            'IIS': r'Microsoft-IIS[/\s](\d+\.\d+)',
            'LiteSpeed': r'LiteSpeed',
            'Tomcat': r'Tomcat[/\s](\d+\.\d+(\.\d+)?)',
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
            'Express': r'express|Express',
        },
        'languages': {
            'PHP': r'PHP[/\s](\d+\.\d+(\.\d+)?)|X-Powered-By: PHP',
            'ASP.NET': r'ASP\.NET|X-AspNet-Version',
            'Python': r'Python|Django|Flask',
            'Node.js': r'Node\.js|Express',
            'Java': r'\bJava[/\s]|JSP|JSESSIONID',
            'Ruby': r'ruby|Ruby|Rails',
            'Go': r'golang|Go',
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
        }
    }

    def __init__(self, verbose=False):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        })
        self.session.verify = False
        self.verbose = verbose

    def detect_from_headers(self, headers):
        technologies = {}
        server_header = headers.get('Server', '')
        powered_by = headers.get('X-Powered-By', '')
        php_version = headers.get('X-PHP-Version', '')
        aspnet_version = headers.get('X-AspNet-Version', '')
        aspnet_mvc = headers.get('X-AspNetMvc-Version', '')

        if self.verbose:
            print(f"{Colors.CYAN}[DEBUG] Server: {server_header}{Colors.END}")
            print(f"{Colors.CYAN}[DEBUG] X-Powered-By: {powered_by}{Colors.END}")
            print(f"{Colors.CYAN}[DEBUG] X-PHP-Version: {php_version}{Colors.END}")
            print(f"{Colors.CYAN}[DEBUG] X-AspNet-Version: {aspnet_version}{Colors.END}")

        for server, pattern in self.PATTERNS['servers'].items():
            match = re.search(pattern, server_header, re.IGNORECASE)
            if match:
                version = match.group(1) if match.groups() else 'Unknown'
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
                        if group and re.match(r'\d+\.\d+', group):
                            version = group
                            break
                technologies[os_name] = {
                    'type': 'os',
                    'version': version,
                    'confidence': 'medium',
                    'source': 'header'
                }
                break

        for waf, pattern in self.PATTERNS['wafs'].items():
            if re.search(pattern, combined_headers, re.IGNORECASE):
                technologies[waf] = {
                    'type': 'waf',
                    'version': 'Unknown',
                    'confidence': 'high',
                    'source': 'header'
                }

        for cdn, pattern in self.PATTERNS['cdns'].items():
            if re.search(pattern, combined_headers, re.IGNORECASE):
                technologies[cdn] = {
                    'type': 'cdn',
                    'version': 'Unknown',
                    'confidence': 'medium',
                    'source': 'header'
                }
        return technologies

    def detect_from_content(self, content):
        technologies = {}
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
        return technologies

    def scan_target(self, url):
        if self.verbose:
            print(f"{Colors.CYAN}[*] Scanning: {url}{Colors.END}")
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
            technologies = {}
            tech_from_headers = self.detect_from_headers(response.headers)
            technologies.update(tech_from_headers)
            tech_from_content = self.detect_from_content(response.text)
            technologies.update(tech_from_content)
            return technologies, response
        except Exception as e:
            if self.verbose:
                print(f"{Colors.RED}[ERROR] Scanning {url}: {e}{Colors.END}")
            return {}, None
class ExploitDBClient:
    def __init__(self, verbose=False):
        self.base_url = "https://www.exploit-db.com/search"
        self.cache = {}
        self.verbose = verbose
    
    def search_exploit(self, cve_id):
        """Busca si hay exploit público para un CVE"""
        if cve_id in self.cache:
            return self.cache[cve_id]
        
        try:
            # Searchsploit tiene API REST  
            url = f"https://www.exploit-db.com/search?cve={cve_id}"
            headers = {'User-Agent': 'HellRecon-Scanner/1.0'}
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                # Analizar si hay resultados
                if "exploits" in response.text and cve_id in response.text:
                    exploit_url = f"https://www.exploit-db.com/exploits/?cve={cve_id}"
                    self.cache[cve_id] = exploit_url
                    return exploit_url
        except Exception as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[WARNING] ExploitDB search failed: {e}{Colors.END}")
        
        self.cache[cve_id] = None
        return None
        
class VulnerabilityChecker:
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
        
    def check_technology_with_exploits(self, tech_name, version):
        """Versión mejorada que también busca exploits"""
        vulns = self.check_technology(tech_name, version)
        
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
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .technology { margin: 10px 0; padding: 10px; border-left: 4px solid #3498db; }
        .vulnerable { border-left-color: #e74c3c; background: #fdf2f2; }
        .safe { border-left-color: #27ae60; }
        .vuln-list { margin-left: 20px; color: #c0392b; }
        .stats { background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .target-section { margin: 30px 0; }
        a { color: #2980b9; text-decoration: none; }
        a:hover { text-decoration: underline; }
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
    </div>
    {content}
</body>
</html>"""
        content = ""
        total_tech = 0
        total_vuln = 0
        for target, data in scan_results.items():
            content += f'<div class="target-section">'
            content += f"<h2>Target: {target}</h2>"
            technologies = data['technologies']
            vuln_checker = data['vuln_checker']
            for tech, info in technologies.items():
                total_tech += 1
                version = info['version']
                tech_type = info['type']
                vulns = vuln_checker.check_technology(tech, version)
                total_vuln += len(vulns)
                vuln_class = "vulnerable" if vulns else "safe"
                content += f'<div class="technology {vuln_class}"><strong>{tech} {version}</strong> - {tech_type}'
                if vulns:
                    content += "<div class='vuln-list'>"
                    for vuln in vulns:
                        content += f'<div><a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln}" target="_blank">{vuln}</a></div>'
                    content += "</div>"
                content += "</div>"
            content += '</div>'
        html_content = html_template.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            target_count=len(scan_results),
            tech_count=total_tech,
            vuln_count=total_vuln,
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

def scan_single_target(url, verbose=False, use_nvd=True, nvd_key=None):
    detector = TechnologyDetector(verbose=verbose)
    nvd_client = NVDClient(nvd_key) if use_nvd else None
    vuln_checker = VulnerabilityChecker(nvd_client, use_nvd)
    technologies, response = detector.scan_target(url)
    return {
        'technologies': technologies,
        'vuln_checker': vuln_checker,
        'response': response
    }

def main():
    show_banner()
    parser = ArgumentParser(description='HellRecon PRO - Advanced technology intelligence scanner')
    parser.add_argument('--nvd-key', help='NVD API key (overrides config file)')
    parser.add_argument('target', nargs='*', help='Target URL(s) to scan')
    parser.add_argument('-f', '--file', help='File containing list of URLs')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('--format', choices=['html', 'csv', 'json'], default='html', help='Report format')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show debug information')
    parser.add_argument('--no-nvd', action='store_true', help='Disable NVD API lookups')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads for batch scanning')
    args = parser.parse_args()

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

    print(f"{Colors.CYAN}[*] Starting scan of {len(valid_targets)} target(s){Colors.END}")
    print(f"{Colors.CYAN}[*] Threads: {args.threads} | NVD: {not args.no_nvd} | Format: {args.format}{Colors.END}")
    print("-" * 60)

    start_time = time.time()
    scan_results = {}

    if len(valid_targets) == 1:
        result = scan_single_target(valid_targets[0], args.verbose, not args.no_nvd, args.nvd_key)
        scan_results[valid_targets[0]] = result
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_url = {
                executor.submit(scan_single_target, url, args.verbose, not args.no_nvd, args.nvd_key): url
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
                vulns = vuln_checker.check_technology(tech, version)
                total_vuln += len(vulns)
                if vulns:
                    print(f"{icon} {Colors.RED}{tech} {version}{Colors.END} - {tech_type}")
                    for vuln in vulns:
                        print(f"   └── {Colors.RED}{vuln}{Colors.END}")
                else:
                    color = Colors.GREEN if confidence == 'high' else Colors.YELLOW
                    print(f"{icon} {color}{tech} {version}{Colors.END} - {tech_type}")
        else:
            print(f"{Colors.YELLOW}[!] No technologies found for {url}{Colors.END}")

    if args.output:
        if args.format == 'html':
            ReportGenerator.generate_html_report(scan_results, args.output)
        elif args.format == 'csv':
            ReportGenerator.generate_csv_report(scan_results, args.output)
        elif args.format == 'json':
            with open(args.output, 'w') as f:
                json.dump(scan_results, f, indent=2)
            print(f"{Colors.GREEN}[+] JSON report generated: {args.output}{Colors.END}")

    total_time = time.time() - start_time
    print(f"\n{Colors.CYAN}[*] Scan completed in {total_time:.2f} seconds{Colors.END}")
    print(f"{Colors.CYAN}[*] Total: {len(scan_results)} targets, {total_tech} technologies, {total_vuln} vulnerabilities{Colors.END}")
    if args.output:
        print(f"{Colors.GREEN}[+] Report saved to: {args.output}{Colors.END}")

if __name__ == "__main__":
    main()
