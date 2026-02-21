# g0tsp1p — SPIP CMS Security Scanner

**SPIP** (Système de Publication pour l'Internet Partagé) is a French CMS used by many organizations. This scanner performs comprehensive security assessment of SPIP installations.

```
 ██████   ██████  ████████ ███████ ██████   ██ ██████  ██████  
██       ██  ████    ██    ██      ██   ██ ███ ██   ██      ██ 
██   ███ ██ ██ ██    ██    ███████ ██████   ██ ██████    ▄███  
██    ██ ████  ██    ██         ██ ██       ██ ██        ▀▀    
 ██████   ██████     ██    ███████ ██       ██ ██        ██    
```

**Author:** c0d3Ninja  

---

## Features

| Module | Description |
|--------|-------------|
| **WAF Detection** | Detects Cloudflare, AWS WAF, Akamai, Sucuri, ModSecurity, Imperva, F5, Barracuda |
| **Version Detection** | SPIP version via meta tag, X-Spip-Cache, Composed-By headers |
| **CVE Checks** | Auto-checks CVE-2023-27372, CVE-2024-7954, CVE-2024-8517 |
| **CVE Auto-Exploit** | Attempts exploitation of known CVEs |
| **User Enumeration** | Via `informer_auteur` (cnx=1, logo) |
| **Password Spray** | With login lockout detection |
| **Endpoint Discovery** | 30+ SPIP endpoints |
| **Plugin Enumeration** | Lists installed plugins |
| **Path Traversal** | Tests redirect param and common payloads |
| **Open Redirect** | Tests redirect/url parameters |
| **XSS** | Tests common injection points |
| **SSTI** | SPIP template injection (7*191) |
| **RSS/Data Leak** | Parses RSS for sensitive data |
| **Directory Bruteforce** | Custom wordlist support |
| **Composer Analysis** | Parses composer.lock/json — PHP version, EOL packages, CVEs, dev emails |

---

## Requirements

```bash
pip install requests
```

Python 3.7+

---

## Usage

### Basic

```bash
# Full scan (default)
python3 g0tsp1p.py -t https://target.com

# Save report
python3 g0tsp1p.py -t https://target.com -o report.txt
```

### Modes

| Mode | Description |
|------|-------------|
| `all` | Full scan (default) |
| `recon` | WAF + version + methods + endpoints + plugins + composer |
| `waf` | WAF/CDN detection only |
| `enum` | User enumeration |
| `spray` | Password spray |
| `exploit` | CVE auto-exploit |
| `endpoints` | Endpoint discovery |
| `methods` | HTTP method checks (TRACE, XST) |
| `traversal` | Path traversal |
| `redirect` | Open redirect |
| `xss` | XSS testing |
| `ssti` | SSTI testing |
| `rss` | RSS data leak check |
| `plugins` | Plugin enumeration |
| `dirbrute` | Directory bruteforce |
| `composer` | composer.lock/json analysis |

### Examples

```bash
# Recon only
python3 g0tsp1p.py -t https://target.com -m recon

# User enum with custom wordlist
python3 g0tsp1p.py -t https://target.com -m enum -U usernames.txt

# Password spray (uses enumerated users if no -u)
python3 g0tsp1p.py -t https://target.com -m spray -u admin,editor -P passwords.txt

# CVE exploit only
python3 g0tsp1p.py -t https://target.com -m exploit

# Composer analysis (PHP version, CVEs, deps)
python3 g0tsp1p.py -t https://target.com -m composer

# Directory bruteforce
python3 g0tsp1p.py -t https://target.com -m dirbrute -W wordlist.txt

# Verbose + custom timeout
python3 g0tsp1p.py -t https://target.com -c 5 --timeout 15 -v
```

---

## Options

| Option | Description |
|--------|-------------|
| `-t, --target` | Target URL (required) |
| `-m, --mode` | Scan mode (default: all) |
| `-U, --userlist` | Username file for enum/spray |
| `-P, --passlist` | Password file for spray |
| `-u, --username` | Username(s), comma-separated |
| `-p, --password` | Password(s), comma-separated |
| `-W, --wordlist` | Directory wordlist for dirbrute |
| `-c, --concurrency` | Threads (default: 10) |
| `--timeout` | Request timeout seconds (default: 10) |
| `--delay` | Delay between requests (default: 0.5) |
| `-o, --output` | Save report to file |
| `-v, --verbose` | Verbose output |

---

## CVEs Covered

| CVE | Severity | Description |
|-----|----------|-------------|
| CVE-2023-27372 | Critical | RCE via page parameter (before 4.2.1) |
| CVE-2024-7954 | Critical | PHP code execution via porte_plume (before 4.2.13) |
| CVE-2024-8517 | High | RCE via BigUp plugin (before 4.2.16) |

---

## Composer Mode

When `composer.lock` or `composer.json` is exposed, the scanner:

- Parses SPIP core and dependency versions
- Detects PHP version (platform-overrides)
- Flags EOL PHP (7.4, 8.0)
- Checks PHP CVEs (CVE-2022-37454, CVE-2023-3824, CVE-2024-4577, etc.)
- Flags EOL Symfony components
- Extracts developer emails

---

## Shodan / Discovery

```
"X-Spip-Cache"
```

---

## Disclaimer

Use only on targets you are authorized to test. Unauthorized access is illegal.

---

## License

MIT
