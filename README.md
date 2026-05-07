# Advanced-Bug-Bounty-Reconnaissance-Tool
# 🔍 Advanced Bug Bounty Reconnaissance Tool

> ⚠️ **LEGAL NOTICE**: This tool is for **authorized security testing only**.
> Only use on domains you have **explicit written permission** to test.
> Unauthorized testing is illegal under computer crime laws worldwide.

---

## Features

| Phase | Module | What It Does |
|-------|--------|-------------|
| 1 | Subdomain Finder | DNS brute-force + crt.sh CT logs + HackerTarget API |
| 2 | Real IP Finder | WAF/CDN bypass, origin IP discovery, historical DNS |
| 3 | Port Scanner | Top 50 ports, banner grabbing, dangerous service alerts |
| 4 | WAF Detection | Identifies Cloudflare, Akamai, AWS WAF, Sucuri, F5, etc. |
| 5 | CMS Detection | WordPress, Joomla, Drupal, Laravel, Django, etc. |
| 6 | URL Gathering | Wayback Machine + recursive spider + endpoint discovery |
| 7 | JS Analyzer | Secrets, API keys, hidden endpoints in JavaScript files |
| 8 | Auth Bypass | 403 bypass, path tricks, JWT checks, default creds |
| 9 | IDOR Testing | ID manipulation, object reference enumeration |
| 10 | SQL Injection | Error-based, time-based, UNION, POST forms |
| 11 | XSS Testing | Reflected, DOM sinks, template injection |
| 12 | SSRF Testing | Cloud metadata, internal network, protocol confusion |
| 13 | File Upload | Upload endpoint discovery + bypass hints |
| 14 | API Security | Swagger/GraphQL, method testing, mass assignment |
| 15 | Sensitive Data | Headers, cookies, SSL, data exposure patterns |
| 16 | Manual Guide | Full exploitation guide tailored to your target |

---

## Installation

```bash
# Clone or download the tool
cd bugbounty_tool/

# Install dependency
pip3 install requests

# Run
python3 bugbounty.py example.com
```

---

## Usage

```bash
# Full scan
python3 bugbounty.py target.com

# Subdomain enumeration only
python3 bugbounty.py target.com --subdomains-only

# Skip port scanning (faster)
python3 bugbounty.py target.com --skip-ports

# Skip vulnerability tests (recon only)
python3 bugbounty.py target.com --skip-vuln
```

---

## Output Files

- `report_<domain>_<timestamp>.json` — Machine-readable findings
- `manual_guide_<domain>_<timestamp>.txt` — Complete manual testing guide

---

## Recommended Additional Tools

```bash
# Install these for deeper testing:
pip3 install requests beautifulsoup4

# External tools (install separately):
# subfinder   - advanced subdomain enumeration
# nmap        - detailed port/service scanning
# sqlmap      - automated SQL injection
# dalfox      - XSS scanner
# ffuf        - directory/parameter fuzzing
# wpscan      - WordPress specific scanning
# trufflehog  - secrets in git repos
# katana      - fast web crawler
# nuclei      - vulnerability templates
```

---

## Legal & Ethics

- ✅ Bug bounty programs (HackerOne, Bugcrowd, etc.)
- ✅ Penetration testing with signed contract
- ✅ Your own systems
- ❌ Systems without written permission
- ❌ Government/critical infrastructure
- ❌ Any unauthorized testing

Always follow responsible disclosure and report within the program's scope.
