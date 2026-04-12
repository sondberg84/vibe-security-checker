# Changelog

All notable changes to vibe-security-checker are documented here.

## [1.0.0] - 2026-04-12

### Added
- **Core scanner** (`scan_security.py`) with 12 detection categories:
  - Secrets & API keys (Shannon entropy + regex patterns)
  - Injection (SQL, command, path traversal)
  - Authentication & session management
  - Cryptography (weak algorithms, insecure random)
  - Cloud misconfigurations (S3, GCP, Azure)
  - Sensitive data exposure (PII, SSN, credit cards)
  - Debug/development code left in production
  - HTTPS enforcement issues
  - SSRF (Server-Side Request Forgery)
  - JWT misconfigurations (algorithm=none, verify=False)
  - Security headers (X-Frame-Options, CORS, HSTS, CSP)
  - Dependency vulnerabilities (via OSV.dev CVE API)

- **Severity levels**: CRITICAL, HIGH, MEDIUM, LOW with A-F security grade
- **Confidence scores**: HIGH/MEDIUM/LOW per rule to reduce alert fatigue
- **Secret masking**: actual secret values replaced with `****` in output
- **Baseline/diff mode**: `--save-baseline` and `--diff-only` to suppress known issues
- **Inline suppression**: `# vibe-ignore` or `# vibe-ignore RULE-ID`
- **Language-aware filtering**: rules only fire for relevant file types
- **Git staged-only scan**: `--staged` for fast pre-commit checking
- **CWE + OWASP mapping** for every finding

- **Git history scanner** (`scan_git_history.py`): finds secrets committed and later deleted
- **Dependency checker** (`check_dependencies.py`): CVE lookup + typosquatting detection
- **HTML report generator** (`generate_report.py`): self-contained report with grade badge
- **Pre-commit hook installer** (`install_hooks.py`)
- **VS Code integration installer** (`install_vscode.py`): problem matcher, 4 tasks
- **SARIF 2.1.0 output**: for GitHub Advanced Security integration

- **Module architecture**:
  - `_models.py` — Severity, Finding, ScanResult dataclasses
  - `_config.py` — ScanConfig, load_config, .vibe-security.json support
  - `_rules.py` — all detection patterns, CWE/OWASP maps, entropy helpers
  - `_baseline.py` — baseline save/load/apply
  - `_output.py` — console, JSON, VS Code, SARIF output formatters

- **242 unit tests** across 4 test files
- **GitHub Actions marketplace action** (`action.yml`)
- **pip-installable package** (`pyproject.toml`)
