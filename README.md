# HellRecon PRO

Advanced Technology Intelligence Scanner with Vulnerability and Exploit Integration

## Features:
- Detection of 50+ technologies (servers, CMS, frameworks, WAFs, CDNs)
- Automatic CVE lookup using NVD API
- Local exploit integration with SearchSploit
- HTML/CSV/JSON reports
- Multithreaded scanning
- Colored console output

## Basic Usage:
# Basic scan
python3 hellRecon.py https://example.com

# Scan with exploit lookup and database update
python3 hellRecon.py https://example.com --searchsploit --update-searchsploit

# Batch scan with multiple threads
python3 hellRecon.py -f targets.txt --threads 10 --searchsploit

# Installation
git clone https://github.com/akil3s79/hellRecon
cd hellRecon
(SearchSploit comes pre-installed in Kali Linux)

# Requirements:
- **Python 3.x** -
- **requests library** -
- **SearchSploit (usually pre-installed in penetration testing distributions)** -

## Legal Notice
This tool is intended for:
- **Authorized penetration testing** - 
- **Security research** - 
- **Educational purposes** - 

## Only use hellRecon on systems you own or have explicit permission to test.

## Contributing
Found a bug? Have a feature request? Feel free to open an issue or pull request!

## Puedes invitarme a un café si quieres!
<a href="https://www.buymeacoffee.com/akil3s1979" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="27" width="104"></a>

## You can buy me a coffe if you want!
<a href="https://www.buymeacoffee.com/akil3s1979" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="27" width="104"></a>
