# WADUH v3.0 - Detailed Usage Guide

> **WordPress Analysis & Debugging Utility Helper**
> Complete usage documentation with real-world scenarios

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Basic Usage](#basic-usage)
3. [Scenario-Based Walkthroughs](#scenario-based-walkthroughs)
4. [Advanced Techniques](#advanced-techniques)
5. [Output Analysis](#output-analysis)
6. [Integration Workflows](#integration-workflows)
7. [Troubleshooting](#troubleshooting)
8. [Best Practices](#best-practices)

---

## Getting Started

### First-Time Setup

```bash
# 1. Clone the repository
git clone https://github.com/Masriyan/Waduh.git
cd Waduh

# 2. Install dependencies
pip install requests colorama urllib3

# 3. (Optional) Get WPScan API token
# Visit: https://wpscan.com/api
# Sign up and get your free token

# 4. Set environment variable (optional)
export WPSCAN_API_TOKEN="your-token-here"

# 5. Test installation
python waduh_v3.py --help
```

### Quick Test Run

```bash
# Test on a known WordPress site (ethical testing only!)
python waduh_v3.py -u https://wordpress.org
```

---

## Basic Usage

### Interactive Mode

The simplest way to use WADUH:

```bash
python waduh_v3.py
```

You'll be prompted to enter the target URL:

```
[?] Enter Target URL (e.g., http://localhost or https://example.com):
```

**Example interaction:**
```
$ python waduh_v3.py

    ========================================
      W.A.D.U.H. SCANNER v3.0 - Complete Automation Edition
(Wordpress Analysis & Debugging Utility Helper)
    ========================================
    [!] AUTHORIZED USE ONLY
    [!] DO NOT SCAN TARGETS WITHOUT PERMISSION
    ========================================

[?] Enter Target URL (e.g., http://localhost or https://example.com): https://example.com
[*] Target set to: https://example.com

[*] Attempting to connect to: https://example.com ...
[+] Connection Established! (HTTP 200)
```

### Command-Line Mode

Specify the target directly:

```bash
python waduh_v3.py -u https://target.com
```

### Essential Options

```bash
# Verbose output (recommended for first-time use)
python waduh_v3.py -u https://target.com -v

# Quiet mode (minimal output)
python waduh_v3.py -u https://target.com -q

# Deep scan (thorough but slower)
python waduh_v3.py -u https://target.com --deep

# With WPScan API integration
python waduh_v3.py -u https://target.com --wpscan-token YOUR_TOKEN

# Save reports to specific directory
python waduh_v3.py -u https://target.com -o ./scan_results
```

---

## Scenario-Based Walkthroughs

### Scenario 1: Initial Security Assessment

**Context**: You've been hired to perform an initial security assessment of a WordPress site.

**Objective**: Quick overview of security posture, exposed vulnerabilities, and configuration issues.

**Command:**
```bash
python waduh_v3.py \
  -u https://target-site.com \
  --wpscan-token YOUR_TOKEN \
  -o ./client_assessment \
  -v
```

**What happens:**
1. ✓ Connection and server fingerprinting
2. ✓ WordPress version detection
3. ✓ Security headers analysis
4. ✓ Common WordPress artifacts check
5. ✓ Plugin and theme enumeration
6. ✓ REST API endpoint discovery
7. ✓ User enumeration attempts
8. ✓ XMLRPC vulnerability testing
9. ✓ Sensitive file detection
10. ✓ CVE database lookup via WPScan API

**Expected Output:**
```
[+] WordPress Version Detected: 6.1.1
[!] WARNING: This appears to be an outdated WordPress version!
[+] Detected Plugins (3):
  - contact-form-7
  - wordfence
  - yoast-seo
[-] X-Frame-Options: (missing) - Prevents clickjacking
[-] Content-Security-Policy: (missing) - Helps prevent XSS attacks
[!] FOUND: /readme.html (HTTP 200)
[+] REST API is Exposed (Status 200 OK)
[!] User found (ID 1): admin
```

**Reports Generated:**
- `waduh_target-site.com_full_report_[timestamp].json`
- `waduh_target-site.com_exploitation_guide_[timestamp].txt`
- `waduh_target-site.com_endpoints_[timestamp].json`

**Time Required:** 2-5 minutes

---

### Scenario 2: Deep Penetration Testing

**Context**: Comprehensive security audit with exploitation attempts.

**Objective**: Identify all possible vulnerabilities and generate exploitation guides.

**Command:**
```bash
python waduh_v3.py \
  -u https://target-site.com \
  --deep \
  --advanced \
  --wpscan-token YOUR_TOKEN \
  --export-metasploit \
  --export-sqlmap \
  --generate-pocs \
  --cvss-scoring \
  -o ./pentest_results \
  -v
```

**What happens (in order):**

**Phase 1: Reconnaissance (2-3 min)**
- WordPress version detection (3 methods)
- Server fingerprinting
- Directory structure analysis
- Plugin/theme enumeration with version detection
- User enumeration (3 methods)
- REST API complete mapping

**Phase 2: Vulnerability Assessment (5-8 min)**
- Security headers check (7 headers)
- Sensitive file scanning (20+ files)
- Database error detection
- XMLRPC exploitation testing
- Directory listing checks
- Backup file fuzzing
- CVE database lookups for all detected components

**Phase 3: Advanced Testing (10-15 min)**
- XXE (XML External Entity) injection attempts
- SSRF (Server-Side Request Forgery) testing
- SQL Injection (time-based, error-based, union-based)
- Authentication bypass techniques
- CSRF token analysis
- JWT security testing
- SSTI (Server-Side Template Injection)
- Deserialization vulnerability testing
- Path traversal / LFI attempts
- Command injection testing
- File upload security analysis

**Phase 4: Reporting (1-2 min)**
- CVSS v3.1 score calculation
- Severity classification
- Metasploit RC file generation
- SQLMap command export
- PoC script generation
- Exploitation guide creation

**Expected Output:**
```
[*] Testing for XXE vulnerabilities...
    [!] Potential XXE vulnerability in /wp-json/contact/v1/submit

[*] Testing for SSRF vulnerabilities...
    [+] No SSRF vulnerabilities detected

[*] Advanced SQL injection testing...
    [!] Time-based SQLi detected: /?p=1
    [!] SQLMap command generated: sqlmap_commands.txt

[*] CVSS Scoring enabled
    [!] XXE Vulnerability - CVSS Score: 8.6 (HIGH)
    [!] SQL Injection - CVSS Score: 9.1 (CRITICAL)
```

**Reports Generated:**
- `waduh_target_full_report_[timestamp].json` - Complete findings
- `waduh_target_exploitation_guide_[timestamp].txt` - Step-by-step exploitation
- `waduh_target_metasploit_[timestamp].rc` - Metasploit resource file
- `waduh_target_sqlmap_[timestamp].txt` - SQLMap commands
- `poc_xxe_[timestamp].py` - XXE exploitation script
- `poc_sqli_[timestamp].py` - SQLi exploitation script

**Time Required:** 15-30 minutes

---

### Scenario 3: Bug Bounty Hunting

**Context**: You're hunting for high-impact vulnerabilities on a bug bounty platform.

**Objective**: Focus on high-severity vulnerabilities with immediate notifications.

**Step 1: Setup Webhook for Real-Time Alerts**

First, create a Slack webhook:
1. Go to https://api.slack.com/apps
2. Create new app → Incoming Webhooks
3. Copy webhook URL

**Step 2: Run Targeted Scan**

```bash
python waduh_v3.py \
  -u https://bounty-target.com \
  --test-xxe \
  --test-ssrf \
  --test-sqli \
  --test-deserial \
  --test-auth \
  --scan-secrets \
  --scan-cors \
  --generate-wordlist \
  --webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
  --cvss-scoring \
  -o ./bug_bounty/target_com \
  -r 1.0 \
  -v
```

**Why these flags?**
- `--test-xxe` - XXE often qualifies for high bounties
- `--test-ssrf` - SSRF can lead to internal network access
- `--test-sqli` - SQL injection is almost always critical
- `--test-deserial` - Deserialization can lead to RCE
- `--test-auth` - Authentication bypass is high-impact
- `--scan-secrets` - Exposed API keys are quick wins
- `--scan-cors` - CORS misconfig can be medium-high severity
- `--generate-wordlist` - Useful for additional fuzzing
- `--webhook` - Get instant Slack notifications
- `--cvss-scoring` - Prioritize findings by severity
- `-r 1.0` - Rate limiting to avoid detection

**Expected Slack Notifications:**
```
🚨 WADUH Alert - High Severity Finding!
Target: https://bounty-target.com
Vulnerability: SQL Injection (Time-Based Blind)
Severity: CRITICAL (CVSS 9.1)
Location: /api/v1/search?q=
Evidence: 5-second delay detected with sleep payload
```

**Best Practices for Bug Bounty:**
- Start with quick wins: `--scan-secrets` often finds exposed API keys
- Check CORS misconfigurations for easy reports
- Use custom wordlist for further directory fuzzing
- Document everything with screenshots
- Verify findings manually before submission

**Time Required:** 10-20 minutes per target

---

### Scenario 4: Multi-Target Mass Scanning

**Context**: Security team needs to audit 50 WordPress installations across the company.

**Objective**: Scan multiple targets efficiently and generate consolidated reports.

**Step 1: Prepare Target List**

Create `targets.txt`:
```
https://blog.company.com
https://shop.company.com
https://support.company.com
https://news.company.com
https://careers.company.com
# ... add more targets
```

**Step 2: Run Parallel Scan**

```bash
python waduh_v3.py \
  --target-list targets.txt \
  --parallel 5 \
  --deep \
  --wpscan-token YOUR_TOKEN \
  --export-nuclei \
  --webhook https://hooks.slack.com/your-webhook \
  -o ./mass_audit_2024 \
  -r 0.5 \
  -q
```

**What happens:**
- Scans 5 targets simultaneously
- Each scan runs independently
- Results aggregated in output directory
- Slack notifications for critical findings
- Nuclei templates generated for all targets

**Output Structure:**
```
mass_audit_2024/
├── waduh_blog.company.com_full_report_20240115_143022.json
├── waduh_blog.company.com_nuclei_20240115_143022.yaml
├── waduh_shop.company.com_full_report_20240115_143145.json
├── waduh_shop.company.com_nuclei_20240115_143145.yaml
├── waduh_support.company.com_full_report_20240115_143301.json
└── ...
```

**Analysis Workflow:**

```bash
# 1. Find all critical vulnerabilities across all scans
grep -r "critical" mass_audit_2024/*.json

# 2. Consolidate all Nuclei templates
cat mass_audit_2024/*_nuclei_*.yaml > consolidated_nuclei.yaml

# 3. Extract all vulnerable targets
grep -l "vulnerabilities.*critical" mass_audit_2024/*.json | \
  sed 's/.*waduh_//; s/_full_report.*//'
```

**Time Required:** 10-15 minutes for 50 targets (with parallel=5)

---

### Scenario 5: Red Team Operations

**Context**: Simulating advanced persistent threat for defense testing.

**Objective**: Stealthy reconnaissance and foothold establishment.

**Phase 1: Passive Reconnaissance**

```bash
# Slow, stealthy scan with maximum rate limiting
python waduh_v3.py \
  -u https://target.corp \
  --scan-subdomains \
  --generate-wordlist \
  -r 3.0 \
  -q \
  -o ./red_team/recon
```

**Rate limiting explained:**
- `-r 3.0` = 3 seconds between requests
- Avoids triggering IDS/IPS
- Appears as normal user browsing
- Takes longer but reduces detection risk

**Phase 2: Active Enumeration**

```bash
# After confirming target is not heavily monitored
python waduh_v3.py \
  -u https://target.corp \
  --deep \
  --test-auth \
  --test-sqli \
  --scan-secrets \
  -r 2.0 \
  -v \
  -o ./red_team/enumeration
```

**Phase 3: Exploitation Preparation**

```bash
# Generate exploitation tools
python waduh_v3.py \
  -u https://target.corp \
  --export-metasploit \
  --generate-pocs \
  --export-sqlmap \
  -o ./red_team/exploitation
```

**Using Generated Resources:**

```bash
# 1. Launch Metasploit with generated RC file
msfconsole -r waduh_target.corp_metasploit_*.rc

# 2. Use SQLMap with generated commands
cat waduh_target.corp_sqlmap_*.txt
# Copy and execute SQLMap commands

# 3. Run generated PoC scripts
python poc_auth_bypass_*.py
```

**OPSEC Considerations:**
- Use VPN/proxy chains
- Rotate user agents
- Implement random delays
- Monitor target's security logs if possible
- Document all actions for debrief

**Time Required:** Several hours to days (stealthy approach)

---

### Scenario 6: Blue Team Defense Assessment

**Context**: Internal security team wants to track security improvements over time.

**Objective**: Compare current security posture with previous assessments.

**Month 1: Baseline Scan**

```bash
python waduh_v3.py \
  -u https://oursite.com \
  --deep \
  --wpscan-token YOUR_TOKEN \
  --cvss-scoring \
  --scan-secrets \
  --scan-cors \
  --scan-cookies \
  --scan-ssl \
  -o ./blue_team/baseline \
  -v
```

**Save the baseline:**
```bash
cp ./blue_team/baseline/waduh_oursite.com_full_report_*.json \
   ./blue_team/baseline_2024_01.json
```

**Month 2: After Security Improvements**

```bash
python waduh_v3.py \
  -u https://oursite.com \
  --deep \
  --wpscan-token YOUR_TOKEN \
  --cvss-scoring \
  --compare-with ./blue_team/baseline_2024_01.json \
  --scan-secrets \
  --scan-cors \
  --scan-cookies \
  --scan-ssl \
  -o ./blue_team/month_02 \
  -v
```

**Comparison Output:**
```
[*] Comparing with previous scan: baseline_2024_01.json

[+] IMPROVEMENTS DETECTED:
    - Fixed: Outdated WordPress Version (6.1.1 → 6.4.2)
    - Fixed: Missing X-Frame-Options header
    - Fixed: Missing Content-Security-Policy header
    - Removed: 2 vulnerable plugins (contact-form-7, old-plugin)

[!] NEW VULNERABILITIES:
    - Added: New plugin with known XSS (new-gallery-plugin v1.0)

[!] PERSISTENT ISSUES:
    - Still Present: User enumeration via REST API
    - Still Present: XMLRPC enabled
    - Still Present: Directory listing on /wp-content/uploads/

[*] Security Score:
    Previous: 62/100
    Current: 78/100
    Improvement: +16 points
```

**Monthly Reporting Workflow:**

```bash
# Generate trend report
python waduh_v3.py \
  -u https://oursite.com \
  --deep \
  --compare-with ./blue_team/baseline_2024_01.json \
  --cvss-scoring \
  --webhook https://teams.microsoft.com/webhook \
  -o ./blue_team/monthly_reports/2024_02 \
  -v
```

**Time Required:** 10-15 minutes per assessment

---

### Scenario 7: Pre-Production Security Gate

**Context**: CI/CD pipeline security check before deploying WordPress updates.

**Objective**: Automated security validation in staging environment.

**Integration Script: `pre_deploy_check.sh`**

```bash
#!/bin/bash

STAGING_URL="https://staging.company.com"
WPSCAN_TOKEN="your-token"
WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK"
OUTPUT_DIR="./ci_security_checks/$(date +%Y%m%d_%H%M%S)"

echo "🔒 Running WADUH Security Check on Staging..."

python waduh_v3.py \
  -u "$STAGING_URL" \
  --deep \
  --wpscan-token "$WPSCAN_TOKEN" \
  --cvss-scoring \
  --test-sqli \
  --test-xss \
  --test-auth \
  --scan-secrets \
  --webhook "$WEBHOOK" \
  -o "$OUTPUT_DIR" \
  -q

# Parse results
CRITICAL_COUNT=$(grep -o '"severity": "critical"' "$OUTPUT_DIR"/*.json | wc -l)
HIGH_COUNT=$(grep -o '"severity": "high"' "$OUTPUT_DIR"/*.json | wc -l)

echo "Critical: $CRITICAL_COUNT, High: $HIGH_COUNT"

# Fail deployment if critical vulnerabilities found
if [ "$CRITICAL_COUNT" -gt 0 ]; then
  echo "❌ DEPLOYMENT BLOCKED: Critical vulnerabilities detected!"
  exit 1
elif [ "$HIGH_COUNT" -gt 3 ]; then
  echo "⚠️  DEPLOYMENT WARNING: Multiple high-severity issues detected!"
  exit 1
else
  echo "✅ Security check passed!"
  exit 0
fi
```

**Jenkins/GitLab CI Integration:**

```yaml
# .gitlab-ci.yml
security_scan:
  stage: test
  script:
    - pip install requests colorama urllib3
    - bash pre_deploy_check.sh
  only:
    - staging
  artifacts:
    paths:
      - ci_security_checks/
    expire_in: 30 days
```

**Time Required:** 5-10 minutes per pipeline run

---

### Scenario 8: WordPress Plugin Security Audit

**Context**: Security researcher analyzing a specific WordPress plugin.

**Objective**: Deep dive into plugin security, find 0-days.

**Command:**
```bash
python waduh_v3.py \
  -u https://test-environment.local \
  --deep \
  --test-sqli \
  --test-xss \
  --test-csrf \
  --test-auth \
  --test-upload \
  --test-traversal \
  --generate-pocs \
  -v \
  -o ./plugin_audit/vulnerable_plugin_v1.2.3
```

**Manual Testing Workflow:**

1. **Install plugin on test WordPress**
```bash
wp plugin install vulnerable-plugin --activate
```

2. **Run WADUH scan**
```bash
python waduh_v3.py -u http://localhost:8080 --deep --advanced -v
```

3. **Analyze REST API endpoints**
```bash
cat waduh_localhost_endpoints_*.json | jq '.endpoints[] | select(.namespace | contains("vulnerable-plugin"))'
```

4. **Test each endpoint manually**
```bash
# Example: Test discovered endpoint
curl -X POST http://localhost:8080/wp-json/vulnerable-plugin/v1/upload \
  -H "Content-Type: application/json" \
  -d '{"file": "../../etc/passwd"}'
```

5. **Generate PoC for vulnerability report**
```bash
# WADUH auto-generates PoCs
cat poc_path_traversal_*.py
```

**Vulnerability Report Template:**

```markdown
## Vulnerability: Path Traversal in Vulnerable Plugin v1.2.3

**Severity:** High (CVSS 8.6)
**Affected Component:** /wp-json/vulnerable-plugin/v1/upload
**Attack Vector:** Network
**Privileges Required:** None

### Description
The plugin fails to sanitize file paths in the upload endpoint...

### Proof of Concept
[Attach WADUH-generated PoC script]

### Remediation
- Sanitize all file paths with realpath()
- Implement whitelist of allowed directories
- Add authentication requirement
```

**Time Required:** 2-4 hours for thorough analysis

---

### Scenario 9: WordPress Migration Security Check

**Context**: Company is migrating WordPress from old hosting to new infrastructure.

**Objective**: Ensure no security regressions during migration.

**Pre-Migration Scan:**

```bash
python waduh_v3.py \
  -u https://old-server.company.com \
  --deep \
  --wpscan-token YOUR_TOKEN \
  --cvss-scoring \
  --scan-ssl \
  --scan-cookies \
  -o ./migration/pre_migration \
  -v
```

**Post-Migration Scan:**

```bash
python waduh_v3.py \
  -u https://new-server.company.com \
  --deep \
  --wpscan-token YOUR_TOKEN \
  --cvss-scoring \
  --compare-with ./migration/pre_migration/waduh_old-server*.json \
  --scan-ssl \
  --scan-cookies \
  -o ./migration/post_migration \
  -v
```

**Migration Validation Checklist:**

```
[+] WordPress version matches: ✓
[+] All plugins present: ✓
[+] Plugin versions match: ✓
[+] SSL configuration improved: ✓
[+] Security headers maintained: ✓
[!] New issue: Directory listing on new server
[!] Action required: Disable directory listing
```

**Time Required:** 20-30 minutes total

---

### Scenario 10: Security Training & CTF

**Context**: Setting up a WordPress security training lab.

**Objective**: Create comprehensive exploitation exercises for students.

**Lab Setup:**

```bash
# 1. Deploy vulnerable WordPress (DVWP, WPScan Vulnerable VM, etc.)
docker run -d -p 8080:80 wpscanteam/vulnerablewordpress

# 2. Run comprehensive scan
python waduh_v3.py \
  -u http://localhost:8080 \
  --advanced \
  --generate-pocs \
  --export-metasploit \
  --export-sqlmap \
  --generate-wordlist \
  -v \
  -o ./training_lab/student_materials
```

**Student Exercise Generation:**

```bash
# Generate training materials
cd training_lab/student_materials

# Extract vulnerability list for exercises
cat waduh_localhost_full_report_*.json | \
  jq -r '.vulnerabilities[] | "\(.title) - \(.severity)"' > \
  exercises_list.txt

# Create hint sheets
cat waduh_localhost_exploitation_guide_*.txt > hints.txt

# PoC scripts for answer key
mv poc_*.py ./answer_key/
```

**Training Scenarios:**

**Exercise 1: User Enumeration**
```
Task: Use WADUH findings to enumerate all WordPress users
Hint: Check REST API endpoints discovered by WADUH
Expected Result: List of usernames for brute force exercise
```

**Exercise 2: XMLRPC Exploitation**
```
Task: Exploit XMLRPC for brute force amplification
Hint: Review WADUH's XMLRPC vulnerability findings
Tool: Use generated Metasploit RC file
```

**Exercise 3: SQL Injection**
```
Task: Exploit SQLi vulnerability found by WADUH
Hint: Review SQLMap commands in generated file
Expected Result: Database dump
```

**Time Required:** 2-3 hours for full lab setup

---

## Advanced Techniques

### Custom Rate Limiting Strategies

**Bypass Basic WAF Detection:**
```bash
# Random delays between 1-3 seconds
python waduh_v3.py -u https://target.com -r 2.0 --deep

# Very slow scan (stealth mode)
python waduh_v3.py -u https://target.com -r 5.0
```

**Aggressive Scanning (Test Environment Only):**
```bash
# Minimal delays for maximum speed
python waduh_v3.py -u http://localhost -r 0.1 --deep
```

### Combining Multiple Export Formats

**Complete Toolkit Generation:**
```bash
python waduh_v3.py \
  -u https://target.com \
  --deep \
  --export-metasploit \
  --export-sqlmap \
  --export-nuclei \
  --export-burp \
  --export-zap \
  --generate-pocs \
  -o ./complete_toolkit
```

**Use each tool:**

```bash
# 1. Metasploit
msfconsole -r complete_toolkit/waduh_target_metasploit_*.rc

# 2. Nuclei
nuclei -t complete_toolkit/waduh_target_nuclei_*.yaml -u https://target.com

# 3. Burp Suite
# Import complete_toolkit/waduh_target_burp_*.xml into Burp

# 4. OWASP ZAP
zap.sh -session complete_toolkit/waduh_target_zap_*.xml

# 5. SQLMap
bash complete_toolkit/waduh_target_sqlmap_*.txt
```

### Advanced Filtering

**Focus on Specific Vulnerability Types:**

```bash
# Only test for injection vulnerabilities
python waduh_v3.py \
  -u https://target.com \
  --test-sqli \
  --test-cmdi \
  --test-ssti \
  --test-deserial

# Only configuration issues
python waduh_v3.py \
  -u https://target.com \
  --scan-cors \
  --scan-cookies \
  --scan-ssl

# Only secrets and exposure
python waduh_v3.py \
  -u https://target.com \
  --scan-secrets \
  --enhanced-backups
```

### Webhook Integrations

**Slack Webhook:**
```bash
python waduh_v3.py \
  -u https://target.com \
  --webhook https://hooks.slack.com/services/T00/B00/XXX
```

**Discord Webhook:**
```bash
python waduh_v3.py \
  -u https://target.com \
  --webhook https://discord.com/api/webhooks/123/abc
```

**Microsoft Teams:**
```bash
python waduh_v3.py \
  -u https://target.com \
  --webhook https://outlook.office.com/webhook/xxx
```

**Custom Webhook Script:**
```python
# custom_webhook.py
import requests
import json

def send_alert(findings):
    webhook_url = "https://your-custom-endpoint.com/webhook"

    data = {
        "title": "WADUH Security Alert",
        "vulnerabilities": findings['vulnerabilities'],
        "severity": "HIGH" if findings['critical_count'] > 0 else "MEDIUM"
    }

    requests.post(webhook_url, json=data)
```

---

## Output Analysis

### Understanding JSON Reports

**Full Report Structure:**
```json
{
  "target": "https://target.com",
  "scan_timestamp": "2024-01-15T14:30:22Z",
  "wordpress_version": "6.1.1",
  "vulnerabilities": [
    {
      "title": "SQL Injection - Time-Based Blind",
      "description": "Parameter 'id' is vulnerable to time-based SQL injection",
      "severity": "critical",
      "confidence": "high",
      "cvss_score": 9.1,
      "evidence": "5-second delay observed with payload: ' AND SLEEP(5)--",
      "location": "/wp-json/api/v1/search?id=",
      "exploit_available": true
    }
  ],
  "info_leaks": [...],
  "security_issues": [...],
  "detected_plugins": [...],
  "detected_themes": [...]
}
```

**Parsing with jq:**

```bash
# Extract all critical vulnerabilities
jq '.vulnerabilities[] | select(.severity == "critical")' report.json

# Get CVSS scores
jq '.vulnerabilities[] | "\(.title): \(.cvss_score)"' report.json

# List all vulnerable plugins
jq '.detected_plugins[] | select(.vulnerabilities) | .slug' report.json

# Count vulnerabilities by severity
jq '[.vulnerabilities[] | .severity] | group_by(.) | map({severity: .[0], count: length})' report.json
```

### Exploitation Guide Format

```
============================================================
WADUH EXPLOITATION GUIDE
Target: https://target.com
Generated: 2024-01-15 14:30:22 UTC
============================================================

[CRITICAL] SQL Injection (Time-Based Blind)
------------------------------------------------------------
Location: /wp-json/api/v1/search?id=1
CVSS Score: 9.1
Confidence: HIGH

Description:
The 'id' parameter is vulnerable to time-based blind SQL injection.
Server delays 5 seconds when SQL sleep command is injected.

Exploitation Steps:

1. Verify vulnerability:
   curl "https://target.com/wp-json/api/v1/search?id=1' AND SLEEP(5)--"

2. Use SQLMap for automated exploitation:
   sqlmap -u "https://target.com/wp-json/api/v1/search?id=1" \
          --batch --dbs

3. Extract database:
   sqlmap -u "https://target.com/wp-json/api/v1/search?id=1" \
          --batch -D wordpress --dump

4. Or use generated PoC script:
   python poc_sqli_20240115_143022.py

Remediation:
- Use prepared statements
- Implement input validation
- Enable WAF rules for SQL injection
```

---

## Integration Workflows

### Workflow 1: WADUH → Nuclei → Manual Testing

```bash
# Step 1: WADUH scan
python waduh_v3.py -u https://target.com --export-nuclei -o ./scan1

# Step 2: Run Nuclei with generated templates
nuclei -t ./scan1/waduh_target_nuclei_*.yaml \
       -u https://target.com \
       -o nuclei_results.txt

# Step 3: Manual verification in Burp Suite
# Import findings from both tools
```

### Workflow 2: WADUH → Metasploit → Post-Exploitation

```bash
# Step 1: WADUH reconnaissance
python waduh_v3.py -u https://target.com \
  --export-metasploit \
  --wpscan-token YOUR_TOKEN \
  -o ./recon

# Step 2: Launch Metasploit
msfconsole -r ./recon/waduh_target_metasploit_*.rc

# Step 3: In Metasploit console
msf6 > workspace -a target_com
msf6 > run
msf6 > sessions -l
```

### Workflow 3: Continuous Monitoring

```bash
#!/bin/bash
# monitor_wordpress.sh

while true; do
  # Daily scan
  python waduh_v3.py \
    -u https://production.com \
    --compare-with ./baseline.json \
    --webhook https://slack.webhook \
    --cvss-scoring \
    -o ./daily_scans/$(date +%Y%m%d) \
    -q

  # Wait 24 hours
  sleep 86400
done
```

---

## Troubleshooting

### Common Issues

**Issue 1: SSL Certificate Errors**
```
[!] SSL Certificate Error.
```

**Solution:**
```bash
# For testing environments with self-signed certificates
python waduh_v3.py -u https://target.com --verify-ssl
```

---

**Issue 2: Connection Timeouts**
```
[!] Connection timed out while waiting for a response.
```

**Solutions:**
```bash
# Increase rate limiting (longer delays)
python waduh_v3.py -u https://slow-server.com -r 2.0

# Or target may be blocking you - try different user agent
# (WADUH already uses realistic Chrome UA by default)
```

---

**Issue 3: WPScan API Rate Limiting**
```
[!] WPScan API: Rate limit exceeded
```

**Solution:**
```bash
# Increase rate limiting to reduce API calls per minute
python waduh_v3.py -u https://target.com -r 1.5 --wpscan-token YOUR_TOKEN

# Or upgrade WPScan API plan for higher limits
```

---

**Issue 4: No Vulnerabilities Found (But Site is Vulnerable)**
```
[+] No vulnerabilities found
```

**Solutions:**
```bash
# 1. Use deep scan mode
python waduh_v3.py -u https://target.com --deep

# 2. Enable advanced testing
python waduh_v3.py -u https://target.com --advanced

# 3. Add WPScan token for plugin/theme vuln checks
python waduh_v3.py -u https://target.com --wpscan-token YOUR_TOKEN

# 4. Use verbose mode to see what's being tested
python waduh_v3.py -u https://target.com -v
```

---

**Issue 5: Target is Not WordPress**
```
[-] WordPress Version is hidden
[-] REST API not found (404)
```

**Verification:**
```bash
# Manually check if target is WordPress
curl -s https://target.com | grep -i wordpress
curl -s https://target.com/wp-json/
```

---

**Issue 6: Permission Denied Writing Reports**
```
[!] Failed to write JSON export
```

**Solution:**
```bash
# Create output directory first
mkdir -p ./scan_results
python waduh_v3.py -u https://target.com -o ./scan_results

# Or use absolute path
python waduh_v3.py -u https://target.com -o /home/user/scans
```

---

### Debug Mode

**Enable Maximum Verbosity:**
```bash
python waduh_v3.py -u https://target.com -v 2>&1 | tee debug.log
```

**Check What's Being Tested:**
```bash
# Verbose mode shows all checks
python waduh_v3.py -u https://target.com -v | grep "Testing"
```

**Output:**
```
[*] Testing for user enumeration vulnerabilities...
[*] Testing wp-login.php for user enumeration...
[*] Testing XMLRPC endpoint for vulnerabilities...
[*] Testing for XXE vulnerabilities...
[*] Testing for SSRF vulnerabilities...
```

---

## Best Practices

### 1. Always Get Permission

```bash
# Create permission log
echo "Scan authorized by: John Doe <john@company.com>" > authorization.txt
echo "Date: $(date)" >> authorization.txt
echo "Scope: https://authorized-target.com" >> authorization.txt
echo "Purpose: Security assessment" >> authorization.txt
```

### 2. Start Conservative, Then Go Deeper

```bash
# Phase 1: Basic scan
python waduh_v3.py -u https://target.com -o ./scan_basic

# Phase 2: If basic scan shows promise, go deeper
python waduh_v3.py -u https://target.com --deep -o ./scan_deep

# Phase 3: Advanced testing on confirmed targets
python waduh_v3.py -u https://target.com --advanced -o ./scan_advanced
```

### 3. Rate Limiting for Production Sites

```bash
# Never hammer production sites
python waduh_v3.py -u https://production.com -r 1.0 --deep

# For test environments, you can be faster
python waduh_v3.py -u http://localhost -r 0.1 --deep
```

### 4. Use Version Control for Scans

```bash
# Track security posture over time
mkdir -p scans/target.com/$(date +%Y-%m)
python waduh_v3.py -u https://target.com -o scans/target.com/$(date +%Y-%m)

# Commit to git
git add scans/
git commit -m "Security scan for $(date +%Y-%m-%d)"
```

### 5. Validate Findings Manually

```bash
# WADUH finds potential SQLi
# ALWAYS verify manually before reporting

# Example verification:
curl "https://target.com/api/search?id=1'"
# Check for SQL error

curl "https://target.com/api/search?id=1' AND SLEEP(5)--"
# Check for 5-second delay
```

### 6. Secure Your Scan Data

```bash
# Scan data contains sensitive information
# Encrypt output directory
tar -czf scan_results.tar.gz scan_results/
gpg -c scan_results.tar.gz
rm -rf scan_results/ scan_results.tar.gz

# Decrypt when needed
gpg scan_results.tar.gz.gpg
tar -xzf scan_results.tar.gz
```

### 7. Use Webhooks for Critical Findings Only

```bash
# Configure webhook for high/critical only
# (This requires custom filtering, WADUH sends all findings)

# Wrapper script to filter:
#!/bin/bash
python waduh_v3.py -u $1 -o /tmp/scan -q
CRITICAL=$(grep -c '"critical"' /tmp/scan/*.json)
if [ $CRITICAL -gt 0 ]; then
  curl -X POST https://webhook.site/critical-alert \
    -d "Critical vulnerabilities found on $1"
fi
```

### 8. Documentation

```bash
# Always document your scans
cat > scan_log.md <<EOF
# Security Scan Log

**Target:** https://target.com
**Date:** $(date)
**Operator:** $(whoami)
**Authorization:** Reference #12345
**Scope:** Full WordPress security assessment

## Command Used:
\`\`\`bash
python waduh_v3.py -u https://target.com --deep --advanced
\`\`\`

## Key Findings:
- SQL injection in /api/search
- User enumeration via REST API
- Outdated WordPress version 6.1.1

## Next Steps:
- Report findings to client
- Provide remediation guidance
- Schedule retest in 30 days
EOF
```

---

## Appendix: Quick Reference

### Most Common Commands

```bash
# Basic scan
python waduh_v3.py -u https://target.com

# Full audit
python waduh_v3.py -u https://target.com --deep --wpscan-token TOKEN --advanced

# Bug bounty
python waduh_v3.py -u https://target.com --test-sqli --test-ssrf --scan-secrets

# Multi-target
python waduh_v3.py --target-list targets.txt --parallel 5

# With all exports
python waduh_v3.py -u https://target.com --export-metasploit --export-sqlmap --generate-pocs
```

### Severity Levels

| Severity | CVSS Score | Examples | Action |
|----------|------------|----------|--------|
| **Critical** | 9.0 - 10.0 | RCE, SQLi with admin access | Immediate fix |
| **High** | 7.0 - 8.9 | Auth bypass, SSRF, XXE | Fix within 7 days |
| **Medium** | 4.0 - 6.9 | XSS, CORS misconfig | Fix within 30 days |
| **Low** | 0.1 - 3.9 | Info disclosure, user enum | Fix when possible |

### Recommended Scan Frequency

| Environment | Frequency | Command |
|-------------|-----------|---------|
| **Production** | Weekly | `--deep --wpscan-token` |
| **Staging** | Before each deployment | `--advanced` |
| **Development** | Daily (automated) | `--deep --compare-with baseline.json` |
| **Public Bug Bounty** | Continuous | `--advanced --webhook` |

---

**For additional help, visit:** https://github.com/Masriyan/Waduh/wiki

**Report issues:** https://github.com/Masriyan/Waduh/issues
