# hellRecon

**Advanced technology intelligence scanner with vulnerability correlation and secret-leak detection for web applications.**

## What is hellRecon?

hellRecon is a Python-based reconnaissance tool that fingerprints web technologies, correlates them with public CVE databases, and hunts for leaked secrets in JavaScript bundles. Designed for penetration testers who need fast, accurate and actionable data about their targets.

**New in v3.0-alpha:** Token-Leak Hunter module – automatically discovers hard-coded secrets (GitHub PATs, AWS keys, Slack tokens, RSA keys, etc.) with entropy-based detection and live verification.

## Why I Built This

While existing recon tools show banners or headers, I wanted something that:
- **Identifies exact technology versions** (Tomcat 7.0.88, WordPress 5.7.2, etc.)
- **Correlates versions with public CVEs** in seconds
- **Hunts secrets inside JS bundles** without exposing full credentials
- **Exports professional reports** (HTML, CSV, JSON, Pwndoc) for client deliverables
- **Works out-of-the-box** with zero configuration and intuitive CLI

## Key Features

- **Deep version detection** – Apache, Nginx, WordPress, Joomla, Django, Spring, etc.
- **CVE correlation** – automatic lookup against NVD (free API key supported)
- **Token-Leak Hunter** – entropy-based secret discovery in inline & external JS
- **Multi-layer WordPress scan** – checksum, aggressive hunt, fingerprinting
- **Smart tomcat/jboss/weblogic hunt** – version extraction from manager paths
- **Professional reports** – HTML, CSV, JSON, Pwndoc-compatible
- **Multi-target support** – scan list of URLs with configurable threads
- **Authenticated testing** – cookies, headers, basic auth, POST mode
- **Cross-platform** – full color output on Windows, Linux, macOS
- **CI-friendly** – clean JSON mode for pipelines

## Installation

`pip3 install -r requirements.txt`

## Usage Examples

- Basic scan:  
  `python3 hellRecon.py https://target.com`

- Scan + secret hunt (verbose):  
  `python3 hellRecon.py https://target.com --token-leak -v`

- Deep WordPress version + plugins:  
  `python3 hellRecon.py https://blog.com --deep-wp-scan -v`

- Multi-target with threads:  
  `python3 hellRecon.py -f urls.txt -t 20`

- Authenticated scan (cookies):  
  `python3 hellRecon.py https://admin.site.com -c "session=abc123" --token-leak`

- CVE lookup + exploit search:  
  `python3 hellRecon.py https://site.com --nvd-key YOUR_NVD_API_KEY --searchsploit`

- Export Pwndoc JSON:  
  `python3 hellRecon.py https://client.com --token-leak --format pwndoc -o report.json`

- CI pipeline (clean JSON):  
  `python3 hellRecon.py https://ci.target.com --format json --ci`

## Token-Leak Hunter Output
[LEAK] Critical: github_pat at https://example.com/js/app.js:42 (entropy 5.1) redacted=ghp_⋯abcd
[LEAK] High: slack_token at https://example.com/js/chat.js:17 (entropy 4.5) redacted=xoxb⋯wxyz

## Technology Detection Samples
[SERVER] Tomcat 7.0.88 - server
└── CVE-2018-8014
└── CVE-2018-8034
[CMS] WordPress 5.7.2 - cms ✓
└── CVE-2021-24291

## Legal Notice

This tool is intended for authorized penetration testing, security research and educational purposes only.  
**Only use hellRecon on systems you own or have explicit permission to test.**

## Buy Me a Coffee

<a href="https://www.buymeacoffee.com/akil3s1979" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="27" width="104">
</a>