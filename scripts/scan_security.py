#!/usr/bin/env python3
"""
Vibe Security Checker - Main scanning script
Detects security vulnerabilities in AI-generated code

This module is the public entry point. It re-exports all symbols from the
focused submodules so that existing imports continue to work unchanged:

    from scan_security import SecurityScanner, Finding, Severity, ScanConfig, ...
"""

import os
import re
import argparse
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Set

# ---------------------------------------------------------------------------
# Re-exports — keep backward compatibility for all existing test imports
# ---------------------------------------------------------------------------

try:
    from ._models import Severity, Finding, ScanResult                      # noqa: F401
    from ._config import ScanConfig, load_config, CONFIG_FILENAME           # noqa: F401
    from ._rules import (                                                    # noqa: F401
        CWE_MAP, CONFIDENCE_MAP, FIX_HINTS, RULE_EXTENSIONS,
        SECRETS_PATTERNS, INJECTION_PATTERNS, AUTH_PATTERNS,
        CRYPTO_PATTERNS, CLOUD_PATTERNS, DATA_PATTERNS,
        DEBUG_PATTERNS, HTTPS_PATTERNS, SSRF_PATTERNS,
        JWT_PATTERNS, HEADER_PATTERNS, SCANNABLE_EXTENSIONS,
        SKIP_DIRS, _shannon_entropy, _ENTROPY_VAR_RE,
        ENTROPY_THRESHOLD, _mask_snippet, _MASK_RE,
    )
    from ._baseline import save_baseline, load_baseline, apply_baseline, DEFAULT_BASELINE  # noqa: F401
    from ._output import print_results, _display_snippet                    # noqa: F401
except ImportError:
    from _models import Severity, Finding, ScanResult                      # noqa: F401
    from _config import ScanConfig, load_config, CONFIG_FILENAME           # noqa: F401
    from _rules import (                                                    # noqa: F401
        CWE_MAP, CONFIDENCE_MAP, FIX_HINTS, RULE_EXTENSIONS,
        SECRETS_PATTERNS, INJECTION_PATTERNS, AUTH_PATTERNS,
        CRYPTO_PATTERNS, CLOUD_PATTERNS, DATA_PATTERNS,
        DEBUG_PATTERNS, HTTPS_PATTERNS, SSRF_PATTERNS,
        JWT_PATTERNS, HEADER_PATTERNS, SCANNABLE_EXTENSIONS,
        SKIP_DIRS, _shannon_entropy, _ENTROPY_VAR_RE,
        ENTROPY_THRESHOLD, _mask_snippet, _MASK_RE,
    )
    from _baseline import save_baseline, load_baseline, apply_baseline, DEFAULT_BASELINE  # noqa: F401
    from _output import print_results, _display_snippet                    # noqa: F401

# Also pull in the fnmatch helper used by SecurityScanner
from fnmatch import fnmatch

__version__ = "1.0.0"

# ============================================================================
# SCANNER
# ============================================================================

class SecurityScanner:
    def __init__(self, root_path: str, config: ScanConfig = None):
        self.root = Path(root_path).resolve()
        self.config = config or ScanConfig()
        self.result = ScanResult()

    def scan(self, checks: Optional[List[str]] = None) -> ScanResult:
        """Run security scan on the project."""
        # Build effective check list: CLI arg > config > all
        effective_checks = checks or self.config.checks

        # Merge custom patterns into secrets
        custom_secrets = [
            (p["pattern"], p.get("rule_id", "CUSTOM-001"), p.get("description", "Custom pattern"))
            for p in self.config.custom_patterns
        ]

        for file_path in self._get_files():
            self._scan_file(file_path, effective_checks, custom_secrets)

        # .gitignore check (not per-file — runs once)
        if not effective_checks or 'secrets' in effective_checks:
            self._check_gitignore()

        return self.result

    def _get_files(self):
        """Yield all scannable files, respecting exclude_paths and diff_files."""
        for root, dirs, files in os.walk(self.root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for file in files:
                file_path = Path(root) / file
                rel = str(file_path.relative_to(self.root))

                # Incremental mode: only scan files changed in git diff
                if self.config.diff_files is not None:
                    rel_posix = file_path.relative_to(self.root).as_posix()
                    if rel_posix not in self.config.diff_files and rel not in self.config.diff_files:
                        continue

                # Check against configured exclude_paths (glob-style prefix match)
                if any(
                    rel.startswith(ex.rstrip("/")) or
                    file_path.match(ex)
                    for ex in self.config.exclude_paths
                ):
                    continue

                if file_path.suffix.lower() in SCANNABLE_EXTENSIONS or file.startswith('.env'):
                    yield file_path
                    self.result.files_scanned += 1

    def _scan_file(self, file_path: Path, checks: Optional[List[str]], custom_secrets: list = None):
        """Scan a single file for vulnerabilities."""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            lines = content.split('\n')

            secrets_patterns = SECRETS_PATTERNS + (custom_secrets or [])

            # Run applicable checks
            if not checks or 'secrets' in checks:
                self._check_patterns(file_path, lines, secrets_patterns, 'Secrets', Severity.CRITICAL,
                    'Move secrets to environment variables or a secrets manager')

            if not checks or 'injection' in checks or 'xss' in checks:
                for category, patterns in INJECTION_PATTERNS.items():
                    # --check xss runs only the xss subcategory; --check injection runs all
                    if checks and 'injection' not in checks and category != 'xss':
                        continue
                    severity = Severity.CRITICAL if category in ('sql', 'command') else Severity.HIGH
                    self._check_patterns(file_path, lines, patterns, f'Injection ({category})', severity,
                        'Use parameterized queries/safe APIs')

            if not checks or 'auth' in checks:
                self._check_patterns(file_path, lines, AUTH_PATTERNS, 'Authentication', Severity.HIGH,
                    'See references/auth.md for secure patterns')

            if not checks or 'crypto' in checks:
                self._check_patterns(file_path, lines, CRYPTO_PATTERNS, 'Cryptography', Severity.HIGH,
                    'Use modern algorithms (AES-256, SHA-256, bcrypt)')

            if not checks or 'cloud' in checks:
                self._check_patterns(file_path, lines, CLOUD_PATTERNS, 'Cloud/Infrastructure', Severity.HIGH,
                    'See references/infrastructure.md')

            if not checks or 'data' in checks:
                self._check_patterns(file_path, lines, DATA_PATTERNS, 'Data Handling', Severity.HIGH,
                    'Use safe deserialization methods')

            if not checks or 'debug' in checks:
                self._check_patterns(file_path, lines, DEBUG_PATTERNS, 'Debug', Severity.MEDIUM,
                    'Disable debug mode before deploying to production')

            if not checks or 'https' in checks:
                self._check_patterns(file_path, lines, HTTPS_PATTERNS, 'Network', Severity.MEDIUM,
                    'Use HTTPS and set Secure/HttpOnly cookie flags')

            if not checks or 'ssrf' in checks:
                self._check_patterns(file_path, lines, SSRF_PATTERNS, 'SSRF', Severity.HIGH,
                    'Validate and allowlist URLs before making server-side requests')

            if not checks or 'jwt' in checks:
                self._check_patterns(file_path, lines, JWT_PATTERNS, 'JWT', Severity.CRITICAL,
                    'Use a well-tested JWT library with explicit algorithm and expiry validation')

            if not checks or 'headers' in checks:
                self._check_patterns(file_path, lines, HEADER_PATTERNS, 'Security Headers', Severity.MEDIUM,
                    'Set strict security headers (CSP, HSTS, X-Frame-Options)')

            # Entropy scan — catches secrets that don't match known patterns
            if not checks or 'secrets' in checks:
                self._check_entropy(file_path, lines)

        except Exception as e:
            pass  # Skip files that can't be read

    @staticmethod
    def _is_suppressed(line: str, rule_id: str) -> bool:
        """
        Return True if the line carries a vibe-ignore comment that covers rule_id.
        Supported forms:
          # vibe-ignore            — suppress any rule on this line
          # vibe-ignore SEC-013    — suppress only SEC-013 on this line
          // vibe-ignore SEC-013   — same, for JS/TS files
        """
        marker = "vibe-ignore"
        for comment_char in ("#", "//"):
            idx = line.find(f"{comment_char} {marker}")
            if idx == -1:
                continue
            rest = line[idx + len(comment_char) + 1 + len(marker):].strip()
            if not rest:          # bare vibe-ignore → suppress everything
                return True
            if rule_id in rest.split():   # specific rule listed
                return True
        return False

    def _check_gitignore(self):
        """Flag .env files that exist in the project but are not covered by .gitignore."""
        gitignore_path = self.root / ".gitignore"
        gitignore_patterns: List[str] = []
        if gitignore_path.exists():
            for raw in gitignore_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                raw = raw.strip()
                if raw and not raw.startswith("#"):
                    gitignore_patterns.append(raw)

        if "GIT-001" in self.config.exclude_rules:
            return

        # Collect .env* files (skip .example / .sample / .template)
        env_candidates = list(self.root.glob(".env")) + list(self.root.glob(".env.*"))
        env_candidates += list(self.root.glob("**/.env"))
        env_candidates += list(self.root.glob("**/.env.*"))

        for env_file in set(env_candidates):
            if any(x in env_file.name for x in ("example", "sample", "template", "test")):
                continue
            try:
                rel = env_file.relative_to(self.root)
            except ValueError:
                continue
            rel_posix = rel.as_posix()
            rel_name = env_file.name

            covered = any(
                fnmatch(rel_posix, pat) or fnmatch(rel_name, pat)
                or rel_posix == pat.lstrip("/") or rel_name == pat.lstrip("/")
                for pat in gitignore_patterns
            )
            if not covered:
                cwe_id, cwe_name, owasp = CWE_MAP.get("GIT-001", ("", "", ""))
                self.result.add(Finding(
                    rule_id="GIT-001",
                    severity=Severity.CRITICAL,
                    category="Secrets",
                    description=f".env file not covered by .gitignore — credentials risk being committed",
                    file_path=rel_posix,
                    line_number=1,
                    code_snippet=f"{rel_posix} (not in .gitignore)",
                    remediation="Add .env (or *.env) to .gitignore immediately",
                    cwe_id=cwe_id,
                    cwe_name=cwe_name,
                    owasp=owasp,
                ))

    def _check_patterns(self, file_path: Path, lines: List[str], patterns: List[tuple],
                        category: str, severity: Severity, remediation: str):
        """Check file content against patterns. Reports first match per rule per file."""
        content = '\n'.join(lines)
        rel_path = str(file_path.relative_to(self.root))
        ext = file_path.suffix.lower()

        for entry in patterns:
            pattern, rule_id, description = entry[0], entry[1], entry[2]
            rule_remediation = entry[3] if len(entry) > 3 else remediation

            if rule_id in self.config.exclude_rules:
                continue

            # Language-aware filtering: skip rules not applicable to this file type
            allowed_exts = RULE_EXTENSIONS.get(rule_id)
            if allowed_exts is not None and ext not in allowed_exts:
                continue

            raw_matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
            if not raw_matches:
                continue

            # Filter out matches on suppressed lines
            valid: list = []
            for m in raw_matches:
                ln = content[:m.start()].count('\n') + 1
                raw_line = lines[ln - 1] if ln <= len(lines) else ''
                if not self._is_suppressed(raw_line, rule_id):
                    valid.append((m, ln, raw_line))

            if not valid:
                continue

            # First non-suppressed match becomes the finding
            match, line_num, raw_line = valid[0]
            snippet = raw_line.strip()

            # "and N more" counts remaining non-suppressed matches
            extra = len(valid) - 1
            display_description = f"{description} (and {extra} more in this file)" if extra else description

            cwe_id, cwe_name, owasp = CWE_MAP.get(rule_id, ("", "", ""))
            fix_hint = FIX_HINTS.get(rule_id, "")
            confidence = CONFIDENCE_MAP.get(rule_id, "HIGH")
            finding = Finding(
                rule_id=rule_id,
                severity=severity,
                category=category,
                description=display_description,
                file_path=rel_path,
                line_number=line_num,
                code_snippet=snippet[:100],
                remediation=rule_remediation,
                cwe_id=cwe_id,
                cwe_name=cwe_name,
                owasp=owasp,
                fix_hint=fix_hint,
                confidence=confidence,
            )
            self.result.add(finding)

    def _check_entropy(self, file_path: Path, lines: List[str]):
        """Flag high-entropy strings assigned to secret-sounding variable names."""
        content = '\n'.join(lines)
        rel_path = str(file_path.relative_to(self.root))

        if "SEC-ENT" in self.config.exclude_rules:
            return

        seen_snippets: Set[str] = set()
        for match in _ENTROPY_VAR_RE.finditer(content):
            candidate = match.group(1)
            entropy = _shannon_entropy(candidate)
            if entropy < ENTROPY_THRESHOLD:
                continue
            line_num = content[:match.start()].count('\n') + 1
            raw_line = lines[line_num - 1] if line_num <= len(lines) else ''
            snippet = raw_line.strip()
            if snippet in seen_snippets:
                continue
            # Respect inline suppression
            if self._is_suppressed(raw_line, "SEC-ENT"):
                continue
            seen_snippets.add(snippet)
            cwe_id, cwe_name, owasp = CWE_MAP.get("SEC-ENT", CWE_MAP.get("SEC-013", ("", "", "")))
            self.result.add(Finding(
                rule_id="SEC-ENT",
                severity=Severity.CRITICAL,
                category="Secrets",
                description=f"High-entropy secret string (entropy={entropy:.2f} bits/char)",
                file_path=rel_path,
                line_number=line_num,
                code_snippet=snippet[:100],
                remediation="Move secrets to environment variables or a secrets manager",
                cwe_id=cwe_id,
                cwe_name=cwe_name,
                owasp=owasp,
                fix_hint=FIX_HINTS.get("SEC-013", ""),
                confidence="MEDIUM",
            ))


def _git_changed_files(repo_path: str, staged_only: bool = False) -> Optional[Set[str]]:
    """
    Return the set of changed file paths (relative, posix) from git.
    Returns None if git is unavailable or repo_path is not a git repo.
    """
    cmd = ['git', 'diff', '--name-only', '--diff-filter=ACMR']
    if staged_only:
        cmd.append('--cached')
    else:
        cmd.append('HEAD')
    try:
        out = subprocess.run(
            cmd, cwd=repo_path, capture_output=True, text=True, timeout=15
        )
        if out.returncode != 0:
            return None
        return {line.strip() for line in out.stdout.splitlines() if line.strip()}
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser(description='Vibe Security Checker - Scan AI-generated code for vulnerabilities')
    parser.add_argument('path', help='Path to project directory')
    parser.add_argument('--check', action='append',
                        choices=['secrets', 'injection', 'auth', 'crypto', 'cloud', 'data',
                                 'xss', 'debug', 'https', 'ssrf', 'jwt', 'headers'],
                        help='Specific check to run (can specify multiple)')
    parser.add_argument('--full', action='store_true', help='Run all checks')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--min-severity', dest='severity',
                        choices=['critical', 'high', 'medium', 'low'],
                        help='Minimum severity to report')
    parser.add_argument('--fail-on-findings', action='store_true',
                        help='Exit with code 1 if findings at or above severity')
    parser.add_argument('--save-baseline', nargs='?', const=DEFAULT_BASELINE, metavar='FILE',
                        help=f'Save current findings as baseline (default: {DEFAULT_BASELINE})')
    parser.add_argument('--baseline', nargs='?', const=DEFAULT_BASELINE, metavar='FILE',
                        help=f'Compare against baseline, report only new findings (default: {DEFAULT_BASELINE})')
    parser.add_argument('--vscode', action='store_true',
                        help='Output in VS Code problem matcher format (file:line: severity: message)')
    parser.add_argument('--diff', action='store_true',
                        help='Only scan files changed since last commit (git diff HEAD)')
    parser.add_argument('--staged', action='store_true',
                        help='Only scan staged files (git diff --cached) — useful in pre-commit hooks')

    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"Error: Path '{args.path}' does not exist")
        sys.exit(1)

    # Resolve git diff files when incremental mode requested
    diff_files = None
    if args.diff or args.staged:
        diff_files = _git_changed_files(args.path, staged_only=args.staged)
        if diff_files is not None:
            print(f"Incremental scan: {len(diff_files)} changed file(s)", file=sys.stderr)
        else:
            print("Warning: git diff failed — falling back to full scan", file=sys.stderr)

    # Load project config — CLI flags override config values
    config = load_config(args.path)

    # CLI overrides
    if args.full:
        config.checks = None  # all checks
    elif args.check:
        config.checks = args.check
    if args.severity:
        config.severity_threshold = args.severity
    if diff_files is not None:
        config.diff_files = diff_files
    if args.baseline:
        config.baseline = args.baseline
    if args.save_baseline:
        config.baseline = None  # don't auto-apply when saving

    scanner = SecurityScanner(args.path, config=config)
    result = scanner.scan()

    # Filter by severity threshold
    min_severity = Severity[config.severity_threshold.upper()]
    result.findings = [f for f in result.findings if f.severity.value >= min_severity.value]

    # Save baseline before applying diff
    if args.save_baseline:
        baseline_path = args.save_baseline if os.path.isabs(args.save_baseline) else str(Path(args.path) / args.save_baseline)
        save_baseline(result, baseline_path)

    # Apply baseline diff (from CLI flag or config)
    suppressed = 0
    effective_baseline = None if args.save_baseline else (args.baseline or config.baseline)
    if effective_baseline:
        baseline_path = effective_baseline if os.path.isabs(effective_baseline) else str(Path(args.path) / effective_baseline)
        known = load_baseline(baseline_path)
        result.findings, suppressed = apply_baseline(result, known)

    print_results(result, args.json, suppressed=suppressed,
                  vscode_output=getattr(args, 'vscode', False))

    # Exit code for CI/CD — threshold from config.fail_on (default: critical)
    # --fail-on-findings enables exit-1 behaviour when config file is absent
    fail_severity = Severity[config.fail_on.upper()]
    critical_new = [f for f in result.findings if f.severity.value >= fail_severity.value]
    if critical_new:
        sys.exit(1)


if __name__ == '__main__':
    main()
