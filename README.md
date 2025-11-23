Advanced Technology Intelligence Scanner with Vulnerability and Exploit Integration

# HellRecon PRO v2.0

## Features:
- Detection of 50+ technologies (servers, CMS, frameworks, WAFs, CDNs)
- **Multi-layer WordPress version detection** with intelligent scoring system
- **WordPress plugin and theme detection** with version extraction  
- **Advanced validation systems** to eliminate false positives
- Automatic CVE lookup using NVD API
- Local exploit integration with SearchSploit
- Automatic SearchSploit database updates
- HTML/CSV/JSON reports with exploit information
- **Professional JSON reports** with full metadata and statistics
- Multithreaded scanning
- Colored console output with exploit visualization

## Usage:
- **Basic scan**: `python3 hellRecon.py https://example.com`
- **Deep WordPress scan**: `python3 hellRecon.py https://example.com --deep-wp-scan -v`
- **Scan with exploit lookup**: `python3 hellRecon.py https://example.com --searchsploit`
- **Update database and scan**: `python3 hellRecon.py https://example.com --update-searchsploit`
- **Batch scan with threads**: `python3 hellRecon.py -f targets.txt --threads 10`
- **Scan without NVD API**: `python3 hellRecon.py https://example.com --no-nvd`

## Generate Reports:
- **HTML report**: `python3 hellRecon.py https://example.com -o report.html --format html`
- **JSON report**: `python3 hellRecon.py https://example.com -o report.json --format json` 
- **CSV report**: `python3 hellRecon.py https://example.com -o report.csv --format csv`

# Installation
git clone https://github.com/akil3s79/hellRecon
cd hellRecon

(SearchSploit comes pre-installed in Kali Linux)

# Requirements:
- **Python 3.x**
- **requests library** - `pip install requests`
- **SearchSploit** (pre-installed in Kali Linux)

## Legal Notice
This tool is intended for:
- **Authorized penetration testing**
- **Security research**  
- **Educational purposes**

Only use HellRecon on systems you own or have explicit permission to test.

## Contributing
Found a bug? Have a feature request? Feel free to open an issue or pull request!

## Puedes invitarme a un café si quieres!
<a href="https://www.buymeacoffee.com/akil3s1979" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="27" width="104"></a>

## You can buy me a coffee if you want!
<a href="https://www.buymeacoffee.com/akil3s1979" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="27" width="104"></a>