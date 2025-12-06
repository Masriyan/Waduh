# W.A.D.U.H. Scanner v3.0 - Complete Automation Edition

> **WordPress Analysis & Debugging Utility Helper**
> The ultimate WordPress security scanner for authorized penetration testing

<div align="center">

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-success)
![Precision Mode](https://img.shields.io/badge/precision-advanced-red)

</div>

---

## What Makes WADUH Terrifyingly Powerful?

WADUH v3.0 isn't just another WordPress scanner—it's a **complete security automation platform** that combines the power of multiple professional tools into one unified solution. Here's what sets it apart:

### The Fear Factor

- **100+ Attack Vectors**: From basic enumeration to advanced XXE, SSRF, and deserialization attacks
- **Multi-Tool Integration**: Exports findings to Metasploit, Burp Suite, ZAP, Nuclei, and SQLMap
- **WPScan API Integration**: Real-time vulnerability database lookups for plugins, themes, and WordPress core
- **Parallel Scanning**: Attack multiple targets simultaneously with intelligent concurrency
- **Zero False Positives**: Confidence scoring system ensures you only act on real vulnerabilities
- **Automated Exploitation**: Generates ready-to-use PoC scripts and Metasploit resource files

---

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/Masriyan/Waduh.git
cd Waduh

# Install required dependencies
pip install -r requirements.txt

# Run the scanner
python waduh_v3.py -h
```

### Dependencies

```bash
pip install requests colorama urllib3
```

### Optional: WPScan API Token

For enhanced vulnerability detection, get a free WPScan API token:

1. Visit https://wpscan.com/api
2. Sign up for a free account
3. Get your API token
4. Use it with `--wpscan-token YOUR_TOKEN` or set `WPSCAN_API_TOKEN` environment variable

```bash
export WPSCAN_API_TOKEN="your-token-here"
```

---

## Usage

### Basic Scan

```bash
# Interactive mode
python waduh_v3.py

# Direct URL scan
python waduh_v3.py -u http://target-wordpress.com
```

### Deep Scan with WPScan API

```bash
python waduh_v3.py -u http://target.com --deep --wpscan-token YOUR_TOKEN
```

### Precision Mode - All Advanced Tests

```bash
python waduh_v3.py -u http://target.com --advanced --wpscan-token YOUR_TOKEN
```

This enables **ALL** advanced attack vectors:
- XML External Entity (XXE)
- Server-Side Request Forgery (SSRF)
- SQL Injection (time-based, error-based, union-based)
- Authentication bypass techniques
- CSRF token analysis
- JWT token security testing
- Server-Side Template Injection (SSTI)
- Insecure deserialization
- Path traversal / LFI
- OS command injection
- File upload security

### Multi-Target Scanning

```bash
# Create targets.txt with one URL per line
python waduh_v3.py --target-list targets.txt --parallel 5
```

### Export to Professional Tools

```bash
# Export findings to Metasploit
python waduh_v3.py -u http://target.com --export-metasploit

# Export to Burp Suite
python waduh_v3.py -u http://target.com --export-burp

# Export to OWASP ZAP
python waduh_v3.py -u http://target.com --export-zap

# Generate Nuclei templates
python waduh_v3.py -u http://target.com --export-nuclei

# Export SQLMap commands
python waduh_v3.py -u http://target.com --export-sqlmap

# Generate PoC Python scripts
python waduh_v3.py -u http://target.com --generate-pocs
```

### Complete Automation Example

```bash
python waduh_v3.py \
  -u http://target.com \
  --deep \
  --advanced \
  --wpscan-token YOUR_TOKEN \
  --export-metasploit \
  --export-sqlmap \
  --export-nuclei \
  --export-burp \
  --generate-pocs \
  --generate-wordlist \
  --scan-secrets \
  --scan-cors \
  --scan-cookies \
  --scan-ssl \
  --cvss-scoring \
  --webhook https://hooks.slack.com/your-webhook \
  -o ./scan_results \
  -v
```

---

## Core Features

### Reconnaissance & Enumeration

- **WordPress Version Detection**: Multiple detection methods (meta tags, readme.html, RSS feeds)
- **Plugin Enumeration**: Automatic detection from HTML sources and deep scanning
- **Theme Detection**: Identify active and installed themes
- **User Enumeration**: Author archives, REST API users, login form differential analysis
- **REST API Analysis**: Complete endpoint mapping with 100+ routes analyzed
- **Directory Listing Detection**: Check for browsable directories
- **Subdomain Enumeration**: Discover WordPress installations on subdomains

### Vulnerability Assessment

- **Security Headers Analysis**: Check for missing CSP, HSTS, X-Frame-Options, etc.
- **XMLRPC Vulnerabilities**: Test for pingback DDoS, brute force amplification
- **Sensitive File Exposure**: Scan for .git, .env, wp-config backups, SQL dumps
- **Database Error Detection**: Trigger and detect SQL error messages
- **CVE Mapping**: Automatic CVE database lookup for detected versions
- **WPScan Integration**: Real-time vulnerability checks for 50,000+ plugins/themes

### Advanced Attack Surface Testing

#### Web Application Attacks
- **SQL Injection**: Time-based, error-based, and union-based SQLi testing
- **Cross-Site Scripting (XSS)**: Reflected, stored, and DOM-based XSS detection
- **XXE (XML External Entity)**: Test XML parsers for external entity injection
- **SSRF (Server-Side Request Forgery)**: Identify internal network access vulnerabilities
- **SSTI (Server-Side Template Injection)**: Test template engines for code injection

#### Authentication & Authorization
- **Authentication Bypass**: Test for login bypass techniques
- **CSRF Protection**: Analyze cross-site request forgery defenses
- **JWT Security**: Test JSON Web Token implementation vulnerabilities
- **Session Management**: Cookie security analysis (HttpOnly, Secure, SameSite)

#### Advanced Exploitation
- **Insecure Deserialization**: Test for PHP object injection
- **Path Traversal / LFI**: Local file inclusion vulnerability testing
- **Command Injection**: OS command injection detection
- **File Upload Security**: Analyze upload restrictions and bypasses
- **CORS Misconfiguration**: Test cross-origin resource sharing policies

### Security Analysis

- **API Key Scanner**: Detect exposed AWS, Google, Stripe, and other API keys
- **SSL/TLS Analysis**: Check certificate validity, cipher suites, protocol versions
- **Cookie Security**: Analyze HttpOnly, Secure, SameSite attributes
- **GraphQL Testing**: Test GraphQL endpoints for introspection and injection
- **Enhanced Backup Fuzzing**: 50+ backup file patterns

### Intelligence & Reporting

- **CVSS v3.1 Scoring**: Automatic vulnerability severity scoring
- **Confidence Levels**: High/Medium/Low confidence ratings to reduce false positives
- **Comparison Mode**: Compare current scan with previous results to track changes
- **Custom Wordlist Generation**: Build targeted wordlists from site content
- **Webhook Notifications**: Real-time alerts to Slack, Discord, or Microsoft Teams

---

## Command-Line Options

### Basic Options

| Option | Description |
|--------|-------------|
| `-u, --url URL` | Target URL (e.g., http://example.com) |
| `-v, --verbose` | Verbose output with debug information |
| `-q, --quiet` | Minimal output mode |
| `-d, --deep` | Deep scan mode (thorough but slower) |
| `-o, --output DIR` | Output directory for reports |
| `--verify-ssl` | Verify SSL certificates (disabled by default) |
| `-r, --rate-limit SECONDS` | Delay between requests (default: 0.5s) |

### Integration Options

| Option | Description |
|--------|-------------|
| `--wpscan-token TOKEN` | WPScan API token for vulnerability database |
| `--webhook URL` | Webhook for Slack/Discord/Teams notifications |
| `--compare-with FILE` | Compare with previous scan JSON file |

### Export Options

| Option | Description |
|--------|-------------|
| `--export-metasploit` | Generate Metasploit resource file (.rc) |
| `--export-sqlmap` | Export SQLMap commands |
| `--export-nuclei` | Generate Nuclei YAML templates |
| `--export-burp` | Export Burp Suite XML file |
| `--export-zap` | Export OWASP ZAP session |
| `--generate-pocs` | Generate proof-of-concept Python scripts |
| `--generate-wordlist` | Create custom wordlist from site |

### Advanced Testing

| Option | Description |
|--------|-------------|
| `--advanced` | Enable ALL precision tests |
| `--test-xxe` | XML External Entity testing |
| `--test-ssrf` | Server-Side Request Forgery |
| `--test-sqli` | Advanced SQL injection |
| `--test-auth` | Authentication bypass |
| `--test-csrf` | CSRF protection analysis |
| `--test-jwt` | JWT token security |
| `--test-ssti` | Server-Side Template Injection |
| `--test-deserial` | Insecure deserialization |
| `--test-traversal` | Path traversal / LFI |
| `--test-cmdi` | OS command injection |
| `--test-upload` | File upload security |

### Additional Scans

| Option | Description |
|--------|-------------|
| `--scan-secrets` | Scan for exposed API keys |
| `--scan-cors` | Test CORS misconfigurations |
| `--scan-cookies` | Analyze cookie security |
| `--scan-ssl` | SSL/TLS configuration analysis |
| `--scan-graphql` | GraphQL endpoint testing |
| `--enhanced-backups` | Enhanced backup fuzzing (50+ patterns) |
| `--scan-subdomains` | WordPress subdomain enumeration |
| `--cvss-scoring` | Calculate CVSS v3.1 scores |

### Multi-Target Options

| Option | Description |
|--------|-------------|
| `--target-list FILE` | File with target URLs (one per line) |
| `--parallel N` | Number of parallel scans (default: 3) |

---

## Output Files

WADUH generates comprehensive reports in multiple formats:

### JSON Reports
- `waduh_[target]_endpoints_[timestamp].json` - Complete REST API endpoint data
- `waduh_[target]_full_report_[timestamp].json` - Comprehensive security findings

### Text Reports
- `waduh_[target]_endpoints_[timestamp].txt` - Human-readable endpoint list
- `waduh_[target]_exploitation_guide_[timestamp].txt` - Step-by-step exploitation manual

### Tool-Specific Exports
- `waduh_[target]_metasploit_[timestamp].rc` - Metasploit resource file
- `waduh_[target]_sqlmap_[timestamp].txt` - SQLMap commands
- `waduh_[target]_nuclei_[timestamp].yaml` - Nuclei templates
- `waduh_[target]_burp_[timestamp].xml` - Burp Suite import
- `waduh_[target]_zap_[timestamp].xml` - OWASP ZAP session

### Proof of Concept
- `poc_[vulnerability]_[timestamp].py` - Ready-to-run Python exploitation scripts

---

## Real-World Examples

### Example 1: Quick Security Audit

```bash
python waduh_v3.py -u https://example.com --wpscan-token YOUR_TOKEN
```

**Output**: Basic security posture, plugin vulnerabilities, exposed endpoints

### Example 2: Comprehensive Penetration Test

```bash
python waduh_v3.py \
  -u https://target.com \
  --deep \
  --advanced \
  --wpscan-token YOUR_TOKEN \
  --export-metasploit \
  --generate-pocs \
  --cvss-scoring \
  -v
```

**Output**: Full vulnerability assessment, exploitation guides, ready-to-use Metasploit modules

### Example 3: Bug Bounty Hunting

```bash
python waduh_v3.py \
  -u https://target.com \
  --test-xxe \
  --test-ssrf \
  --test-sqli \
  --scan-secrets \
  --generate-wordlist \
  --webhook https://hooks.slack.com/your-webhook
```

**Output**: High-impact vulnerabilities with Slack notifications

### Example 4: Mass Scanning

```bash
# targets.txt contains multiple WordPress sites
python waduh_v3.py \
  --target-list targets.txt \
  --parallel 10 \
  --deep \
  --wpscan-token YOUR_TOKEN \
  --export-nuclei \
  -o ./mass_scan_results
```

**Output**: Parallel scanning of multiple targets with Nuclei templates

---

## What Gets Detected?

### Critical Vulnerabilities
- Exposed wp-config.php files
- Accessible database backups (.sql files)
- Git repositories (.git directory)
- Environment files (.env)
- Outdated WordPress core with known CVEs
- Vulnerable plugins with public exploits
- XMLRPC amplification attacks
- SQL injection points
- Authentication bypass vulnerabilities

### High-Severity Issues
- User enumeration via REST API
- Plugin version disclosure
- Theme vulnerabilities
- SSRF vulnerabilities
- XXE vulnerabilities
- Insecure deserialization
- Command injection
- Path traversal / LFI

### Medium-Severity Issues
- Missing security headers (CSP, HSTS, X-Frame-Options)
- Directory listing enabled
- Information disclosure
- CORS misconfigurations
- Insecure cookie configuration
- CSRF token issues
- JWT vulnerabilities

### Informational
- WordPress version disclosure
- Plugin/theme enumeration
- REST API endpoint exposure
- Server header disclosure
- Sitemap and robots.txt analysis

---

## Why WADUH is Terrifying for Vulnerable Sites

### Automation at Scale
- **Multi-Target Mode**: Scan hundreds of WordPress sites simultaneously
- **Zero Configuration**: Works out-of-the-box with intelligent defaults
- **Smart Rate Limiting**: Evades basic WAF detection while maintaining speed

### Exploitation Ready
- **Metasploit Integration**: Automatically generates .rc files for instant exploitation
- **PoC Scripts**: Ready-to-run Python scripts for each vulnerability
- **SQLMap Commands**: Copy-paste SQL injection exploitation commands

### Intelligence Gathering
- **50,000+ Vulnerability Database**: Real-time WPScan API integration
- **CVE Mapping**: Automatic Common Vulnerabilities and Exposures lookup
- **Version Analysis**: Detects outdated software with known exploits

### Professional Grade
- **Burp Suite Export**: Import findings directly into Burp for manual testing
- **Nuclei Templates**: Generate custom Nuclei templates for your targets
- **CVSS Scoring**: Industry-standard vulnerability severity ratings

### Stealth Capabilities
- **Custom User-Agent**: Mimics real Chrome browser traffic
- **Rate Limiting**: Configurable request delays to avoid detection
- **SSL Flexibility**: Works with self-signed certificates (testing environments)

---

## Advanced Use Cases

### Red Team Operations

```bash
# Stealthy reconnaissance with slow rate limiting
python waduh_v3.py -u https://target.com -r 2.0 --scan-subdomains -q
```

### Blue Team Defense

```bash
# Compare security posture over time
python waduh_v3.py -u https://mysite.com --compare-with previous_scan.json --cvss-scoring
```

### Bug Bounty Automation

```bash
# Focus on high-impact vulnerabilities with webhook alerts
python waduh_v3.py \
  --target-list bug_bounty_targets.txt \
  --parallel 5 \
  --test-xxe \
  --test-ssrf \
  --test-sqli \
  --test-deserial \
  --webhook https://hooks.slack.com/bounty-alerts
```

### Security Training

```bash
# Generate comprehensive PoCs for training purposes
python waduh_v3.py -u https://vulnerable-site.local --generate-pocs --deep
```

---

## Responsible Disclosure

### Legal Warning

```
⚠️  AUTHORIZED USE ONLY
This tool is designed for authorized security testing and research purposes only.

NEVER use this tool against systems you don't own or have explicit permission to test.

Unauthorized access to computer systems is illegal under:
- Computer Fraud and Abuse Act (CFAA) in the United States
- Computer Misuse Act in the United Kingdom
- Similar laws in virtually every country

YOU are responsible for your actions. The authors assume no liability.
```

### Ethical Guidelines

1. **Get Permission**: Always obtain written authorization before scanning
2. **Respect Scope**: Stay within the agreed-upon testing boundaries
3. **Be Responsible**: Report vulnerabilities through proper channels
4. **No Harm**: Never exploit vulnerabilities to cause damage or steal data
5. **Rate Limiting**: Use appropriate delays to avoid DoS conditions

---

## Contributing

We welcome contributions! Here's how you can help:

- Report bugs and issues
- Suggest new features
- Submit pull requests
- Improve documentation
- Share your use cases

### Development Setup

```bash
git clone https://github.com/Masriyan/Waduh.git
cd Waduh
pip install -r requirements-dev.txt
```

---

## FAQ

**Q: Do I need a WPScan API token?**
A: No, but it's highly recommended. Without it, you'll miss vulnerability database checks for plugins and themes.

**Q: Will this crash the target site?**
A: No. WADUH uses intelligent rate limiting and non-destructive testing methods.

**Q: Can I use this for bug bounty programs?**
A: Yes! Many bug bounty hunters use WADUH for WordPress target reconnaissance.

**Q: Does it bypass WAF/IDS?**
A: WADUH includes rate limiting and realistic headers, but it's designed for testing, not evasion.

**Q: Can I scan HTTPS sites with self-signed certificates?**
A: Yes, SSL verification is disabled by default for testing environments. Use `--verify-ssl` for production.

**Q: How long does a scan take?**
A: Basic scan: 1-3 minutes. Deep scan: 5-15 minutes. Advanced mode: 10-30 minutes (depending on target).

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## Credits

**Author**: Masriyan
**Repository**: https://github.com/Masriyan/Waduh
**Version**: 3.0 - Complete Automation Edition

### Acknowledgments

- WPScan Team for their excellent vulnerability database API
- WordPress Security Community
- All contributors and bug reporters

---

## Changelog

### v3.0 - Complete Automation Edition
- Multi-target parallel scanning
- Advanced attack surface testing (XXE, SSRF, SSTI, Deserialization)
- Export to Nuclei, Burp Suite, OWASP ZAP
- Webhook notifications (Slack, Discord, Teams)
- CVSS v3.1 scoring system
- API key and secrets scanner
- CORS, Cookie, SSL/TLS analysis
- GraphQL endpoint testing
- Enhanced backup file fuzzing (50+ patterns)
- Subdomain enumeration
- Scan comparison mode
- Custom wordlist generation
- Confidence scoring system

### v2.1 - Previous Release
- WPScan API integration
- REST API comprehensive analysis
- Plugin/theme vulnerability checking
- Metasploit and SQLMap exports
- PoC script generation

---

<div align="center">

**Made with 💀 for Security Researchers**

[Report Issues](https://github.com/Masriyan/Waduh/issues) • [Request Features](https://github.com/Masriyan/Waduh/issues) • [Documentation](https://github.com/Masriyan/Waduh/wiki)

</div>
