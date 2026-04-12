# Vibe Security Checker

[![CI](https://github.com/sondberg84/vibe-security-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/sondberg84/vibe-security-checker/actions/workflows/ci.yml)
[![Security Scan](https://github.com/sondberg84/vibe-security-checker/actions/workflows/self-scan.yml/badge.svg)](https://github.com/sondberg84/vibe-security-checker/actions/workflows/self-scan.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A fast, standalone security scanner for AI-generated ("vibe-coded") Python and JavaScript projects. Detects secrets, injection flaws, weak crypto, JWT misconfigs, SSRF, CVE-affected dependencies, and more — with no external API keys required.

---

## Quick start

```bash
pip install vibe-security-checker
vibe-security-checker /path/to/project --full
```

Or clone and run directly — no install needed:

```bash
python scripts/scan_security.py /path/to/project --full
```

---

## Installation

### pip (recommended)

```bash
pip install vibe-security-checker
```

Installs six commands:

| Command | What it does |
|---|---|
| `vibe-security-checker` | Main scanner |
| `vibe-check-deps` | CVE lookup + typosquatting detection |
| `vibe-git-history` | Scan git history for committed secrets |
| `vibe-report` | Generate HTML / SARIF / Markdown report |
| `vibe-install-hooks` | Install pre-commit hook |
| `vibe-install-vscode` | Install VS Code tasks |

### Clone and run directly

```bash
git clone https://github.com/sondberg84/vibe-security-checker
python vibe-security-checker/scripts/scan_security.py /path/to/project --full
```

### GitHub Actions

```yaml
- uses: sondberg84/vibe-security-checker@v1
  with:
    path: .
    fail_on: HIGH
```

See [GitHub Actions](#github-actions) below for the full reference.

---

## What it checks

| Category | Example findings |
|---|---|
| Secrets & API keys | Hardcoded AWS keys, OpenAI tokens, private keys |
| High-entropy strings | Random-looking values assigned to secret-named vars |
| Injection | SQL, command, path traversal, XSS, NoSQL |
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
- **Confidence**: HIGH / MEDIUM / LOW (low-confidence findings are labelled)
- **Fix hint**: corrected code snippet for the most common patterns
- **Fingerprint**: stable ID for baseline/diff tracking

---

## CLI

```
vibe-security-checker PATH [options]

  --full              Run all check categories
  --check CATEGORY    Run a specific category (repeatable):
                        secrets, injection, xss, auth, crypto, cloud,
                        data, debug, https, ssrf, jwt, headers
  --staged            Scan only git-staged files (pre-commit)
  --diff              Scan only files changed since last commit
  --json              JSON output
  --vscode            VS Code problem-matcher format
  --min-severity      Minimum severity to report: CRITICAL, HIGH, MEDIUM, LOW
  --save-baseline [FILE]  Save findings as baseline
  --baseline [FILE]   Only report findings not in the baseline
  --fail-on-findings  Exit 1 if any findings meet threshold
```

---

## Configuration file

Place `.vibe-security.json` in your project root to set project-wide defaults:

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

## Baseline (suppress known findings)

Save a baseline so the scanner only alerts on new findings:

```bash
vibe-security-checker . --full --save-baseline
```

On subsequent runs:

```bash
vibe-security-checker . --full --baseline
```

Commit `.vibe-security-baseline.json` to your repo. Useful for existing codebases where you want to track regressions without being overwhelmed by pre-existing issues.

---

## Inline suppression

Suppress a specific rule on one line:
```python
secret = os.environ["API_KEY"]  # vibe-ignore SEC-001
```

Suppress all rules on one line:
```python
test_key = "sk-test-placeholder"  # vibe-ignore
```

---

## Git history scan

Finds secrets that were committed and later deleted. A deleted secret is still exposed — anyone who cloned before deletion can read it from git history.

```bash
vibe-git-history /path/to/repo --max-commits 1000
```

Output separates:
- **Still present in HEAD** — fix the code AND rotate the credential
- **Removed from HEAD** — rotate the credential (history is permanent)

---

## HTML report

```bash
vibe-report /path/to/project --format html --output report.html
```

Generates a self-contained HTML file with a security grade badge (A–F), severity summary cards, and findings with fix hints. Also supports `--format sarif` and `--format markdown`.

---

## VS Code integration

```bash
vibe-install-vscode /path/to/project
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
vibe-install-hooks /path/to/repo
```

Installs a git `pre-commit` hook that blocks commits containing CRITICAL findings.

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

## Python API

```python
from vibe_security_checker import SecurityScanner, ScanConfig, Severity

config = ScanConfig(
    checks=None,          # None = all checks
    severity_threshold="medium",
    exclude_paths=["tests/"],
    fail_on="high",
)

scanner = SecurityScanner("/path/to/project", config=config)
result = scanner.scan()

print(f"Grade: {result.grade()}")
for finding in result.findings:
    print(f"[{finding.severity.name}] {finding.rule_id} {finding.file_path}:{finding.line_number}")
    print(f"  {finding.description}")
```

---

## GitHub Actions

Add to any workflow:

```yaml
name: Security Scan

on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # for SARIF upload to GitHub Security tab

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Vibe Security Check
        id: vibe
        uses: sondberg84/vibe-security-checker@v1
        with:
          path: .
          full: true
          fail_on: HIGH
          sarif: true

      - name: Print summary
        if: always()
        run: |
          echo "Grade:    ${{ steps.vibe.outputs.grade }}"
          echo "Findings: ${{ steps.vibe.outputs.findings_count }}"
          echo "Critical: ${{ steps.vibe.outputs.critical_count }}"
```

**Inputs:**

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

**Outputs:**

| Output | Description |
|---|---|
| `findings_count` | Total findings after severity filter |
| `critical_count` | CRITICAL finding count |
| `high_count` | HIGH finding count |
| `grade` | Security grade A–F |
| `sarif_file` | Path to generated SARIF file |

> **Note:** SARIF upload requires `permissions: security-events: write`. Free for public repos. Private repos require GitHub Advanced Security.

**With baseline** (only alert on new findings):

```yaml
- uses: sondberg84/vibe-security-checker@v1
  with:
    baseline: .vibe-security-baseline.json
    fail_on: HIGH
```

Generate the baseline locally:
```bash
vibe-security-checker . --full --save-baseline
```

---

## Architecture

```
scripts/                      (installed as vibe_security_checker package)
  scan_security.py            Main entry point + SecurityScanner class
  _models.py                  Severity, Finding, ScanResult dataclasses
  _config.py                  ScanConfig, .vibe-security.json loader
  _rules.py                   All detection patterns, CWE/OWASP maps, entropy helpers
  _baseline.py                Baseline save / load / apply
  _output.py                  Console, JSON, VS Code formatters
  check_dependencies.py       OSV.dev CVE lookup + typosquatting
  scan_git_history.py         Git history secret scanner
  generate_report.py          HTML / SARIF / Markdown report generator
  install_hooks.py            Pre-commit hook installer
  install_vscode.py           VS Code tasks.json installer
```

---

## Running tests

```bash
python -m unittest discover tests
# 244 tests, ~1-2 seconds
```

---

## License

MIT
