# Vibe Security Checker

[![CI](https://github.com/sondberg84/vibe-security-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/sondberg84/vibe-security-checker/actions/workflows/ci.yml)
[![Security Scan](https://github.com/sondberg84/vibe-security-checker/actions/workflows/self-scan.yml/badge.svg)](https://github.com/sondberg84/vibe-security-checker/actions/workflows/self-scan.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A fast, standalone security scanner for AI-generated ("vibe-coded") Python and JavaScript projects. Detects secrets, injection flaws, weak crypto, JWT misconfigs, SSRF, CVE-affected dependencies, and more — with no external API keys required.

---

## Quick start

```bash
# Scan the current directory
python scripts/scan_security.py .

# Full scan (all checks) with JSON output
python scripts/scan_security.py /path/to/project --full --json

# Scan only staged files (pre-commit style)
python scripts/scan_security.py . --staged
```

---

## Installation

### Option A — run directly (no install needed)
Clone the repo and run `python scripts/scan_security.py`.

### Option B — pip install
```bash
pip install vibe-security-checker
vibe-security-checker /path/to/project --full
```

### Option C — GitHub Actions

Add to any workflow (`.github/workflows/security.yml`):

```yaml
name: Security Scan

on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # for SARIF upload

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Vibe Security Check
        id: vibe
        uses: sondberg84/vibe-security-checker@v1
        with:
          path: .            # directory to scan
          full: true         # run all check categories
          fail_on: HIGH      # fail the build on HIGH or CRITICAL findings
          sarif: true        # upload results to GitHub Security tab

      - name: Print summary
        if: always()
        run: |
          echo "Grade: ${{ steps.vibe.outputs.grade }}"
          echo "Findings: ${{ steps.vibe.outputs.findings_count }}"
```

**All inputs:**

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Directory to scan |
| `full` | `true` | Run all check categories |
| `checks` | — | Comma-separated subset: `secrets,injection,xss,auth,crypto,cloud,data,debug,https,ssrf,jwt,headers` |
| `min_severity` | `LOW` | Minimum severity to report |
| `fail_on` | `HIGH` | Fail build at this severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE` |
| `sarif` | `true` | Upload SARIF to GitHub Advanced Security |
| `sarif_file` | `vibe-security-results.sarif` | SARIF output path |
| `baseline` | — | Path to baseline file — only report new findings |
| `scan_history` | `false` | Also scan git history for committed secrets |
| `max_history_commits` | `200` | Commit limit for history scan |

**All outputs:**

| Output | Description |
|---|---|
| `findings_count` | Total findings after severity filter |
| `critical_count` | CRITICAL finding count |
| `high_count` | HIGH finding count |
| `grade` | Security grade A–F |
| `sarif_file` | Path to generated SARIF file |

> **Note:** SARIF upload requires `permissions: security-events: write`. On public repos this is free. Private repos require GitHub Advanced Security.

**Using a baseline** (suppress known findings, only alert on new ones):

```yaml
- uses: sondberg84/vibe-security-checker@v1
  with:
    baseline: .vibe-security-baseline.json
    fail_on: HIGH
```

Commit `.vibe-security-baseline.json` to your repo. Generate it locally with:
```bash
python scripts/scan_security.py . --full --save-baseline .vibe-security-baseline.json
```

---

## What it checks

| Category | Example findings |
|---|---|
| Secrets & API keys | Hardcoded AWS keys, OpenAI tokens, private keys |
| High-entropy strings | Random-looking values assigned to secret-named vars |
| Injection | SQL injection, command injection, path traversal |
| Authentication | Missing auth checks, insecure session config |
| Cryptography | MD5/SHA1 for passwords, `random` for secrets, ECB mode |
| Cloud | Public S3 buckets, service account keys in code |
| Sensitive data | PII patterns, SSNs, credit card numbers |
| Debug code | `debug=True`, `print(password)`, hardcoded admin bypasses |
| HTTPS | HTTP URLs in production code, SSL verification disabled |
| SSRF | `requests.get(user_input)` without validation |
| JWT | `algorithm="none"`, `verify=False`, expired-token ignoring |
| Security headers | Missing X-Frame-Options, CORS wildcard, no HSTS/CSP |
| Dependencies | CVE lookup via OSV.dev, typosquatting detection |
| Git history | Secrets committed and later deleted (still need rotation) |

Every finding includes:
- **CWE** and **OWASP Top 10 (2021)** category
- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Confidence**: HIGH / MEDIUM / LOW (LOW-confidence findings are labelled)
- **Fix hint**: corrected code snippet for the most common patterns
- **Fingerprint**: stable ID for baseline/diff tracking

---

## CLI flags

```
scan_security.py [PATH] [options]

  --full              Run all check categories (default: secrets + injection + auth + crypto)
  --check CATEGORY    Enable a specific check category (repeatable):
                      secrets, injection, xss, auth, crypto, cloud, data,
                      debug, https, ssrf, jwt, headers
  --staged            Scan only git-staged files (pre-commit)
  --diff              Scan only files changed since last commit
  --json              JSON output
  --vscode            VS Code problem-matcher output (file:line: error: message)
  --min-severity      Minimum severity to report: CRITICAL, HIGH, MEDIUM, LOW
  --save-baseline [FILE]  Save current findings as baseline (default: .vibe-security-baseline.json)
  --baseline [FILE]   Only report findings not in the baseline
  --fail-on-findings  Exit code 1 if any findings meet threshold (for CI without config file)
```

---

## Configuration file

Place `.vibe-security.json` in your project root:

```json
{
  "checks": ["secrets", "injection", "auth", "crypto"],
  "severity_threshold": "MEDIUM",
  "exclude_paths": ["tests/", "fixtures/", "*.min.js"],
  "exclude_rules": ["SEC-008", "AUTH-020"],
  "fail_on": "HIGH"
}
```

---

## Inline suppression

Suppress a specific rule on a line:
```python
secret = os.environ["API_KEY"]  # vibe-ignore SEC-001
```

Suppress all rules on a line:
```python
test_key = "sk-test-placeholder"  # vibe-ignore
```

---

## Git history scan

Finds secrets that were committed and later deleted. A deleted secret is still exposed — anyone who cloned before deletion can read it from git history.

```bash
python scripts/scan_git_history.py /path/to/repo --max-commits 1000
```

Output separates:
- **Still present in HEAD** — fix the code AND rotate the credential
- **Removed from HEAD** — rotate the credential (history is permanent)

---

## HTML report

```bash
python scripts/generate_report.py /path/to/project --format html --output report.html
```

Generates a self-contained HTML file with a security grade badge (A-F), severity summary, and findings with fix hints.

---

## VS Code integration

```bash
python scripts/install_vscode.py /path/to/project
```

Installs four tasks into `.vscode/tasks.json`:
- **Vibe: Security Scan (full)** — default build task (Ctrl+Shift+B)
- **Vibe: Security Scan (staged only)** — fast pre-commit check
- **Vibe: Generate HTML Report**
- **Vibe: Save Baseline**

Findings appear inline in the Problems panel (Ctrl+Shift+M).

---

## Pre-commit hook

```bash
python scripts/install_hooks.py /path/to/repo
```

Installs a `pre-commit` hook that blocks commits containing HIGH or CRITICAL findings.

---

## Security grade

| Grade | Meaning |
|---|---|
| A | No findings |
| B | Low severity only |
| C | Medium severity present |
| D | High severity present |
| F | Critical severity present |

---

## Architecture

```
scripts/
  scan_security.py      Main entry point + SecurityScanner class
  _models.py            Severity, Finding, ScanResult dataclasses
  _config.py            ScanConfig, .vibe-security.json loader
  _rules.py             All detection patterns, CWE/OWASP maps, entropy helpers
  _baseline.py          Baseline save / load / apply
  _output.py            Console, JSON, VS Code formatters
  check_dependencies.py OSV.dev CVE lookup + typosquatting
  scan_git_history.py   Git history secret scanner
  generate_report.py    HTML report generator
  install_hooks.py      Pre-commit hook installer
  install_vscode.py     VS Code tasks.json installer
```

---

## Running tests

```bash
python -m unittest discover tests
# 242 tests, ~1-2 seconds
```

---

## License

MIT
