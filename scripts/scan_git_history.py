#!/usr/bin/env python3
"""
Vibe Security Checker - Git History Scanner
Scans git history for secrets that were committed and later removed.
A deleted secret is still exposed — anyone who cloned the repo before
the deletion can read it, and it lives forever in the object store.

Usage:
    python scripts/scan_git_history.py [REPO_PATH] [--json] [--max-commits N]
"""

import os
import re
import json
import sys
import hashlib
import argparse
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional

# Import secret patterns from the main scanner
try:
    from .scan_security import SECRETS_PATTERNS, _shannon_entropy, _ENTROPY_VAR_RE, ENTROPY_THRESHOLD
except ImportError:
    _scripts_dir = str(Path(__file__).parent)
    if _scripts_dir not in sys.path:
        sys.path.insert(0, _scripts_dir)
    from scan_security import SECRETS_PATTERNS, _shannon_entropy, _ENTROPY_VAR_RE, ENTROPY_THRESHOLD

# ── data ─────────────────────────────────────────────────────────────────────

@dataclass
class HistoryFinding:
    rule_id: str
    description: str
    commit_hash: str
    commit_date: str
    commit_author: str
    commit_message: str
    file_path: str
    line_snippet: str
    still_present: bool   # True if the secret still exists in HEAD

    def fingerprint(self) -> str:
        key = f"{self.rule_id}:{self.file_path}:{self.line_snippet.strip()}"
        return hashlib.sha1(key.encode()).hexdigest()[:16]


# Patterns to skip in git diff output (false-positive-prone in diffs)
_SKIP_RULES_IN_HISTORY = {
    "SEC-008",   # bare "secret" — too generic in commit messages
    "SEC-009",   # password123 placeholder
    "SEC-010",   # admin@example.com — common in tests
    "SEC-011",   # changeme placeholder
    "AUTH-020",  # Flask route pattern — not useful in diffs
    "AUTH-021",  # Express route — not useful in diffs
}

# Diff lines we care about
_ADDED_LINE = re.compile(r'^\+(?!\+\+)')
_DIFF_HEADER = re.compile(r'^diff --git a/(.+) b/(.+)$')
_COMMIT_HEADER = re.compile(r'^commit ([0-9a-f]{40})')
_AUTHOR_HEADER = re.compile(r'^Author:\s*(.+)')
_DATE_HEADER = re.compile(r'^Date:\s*(.+)')
_MESSAGE_HEADER = re.compile(r'^\s{4}(.+)')


# ── git helpers ───────────────────────────────────────────────────────────────

def _run_git(args: list, cwd: str, timeout: int = 120) -> Optional[str]:
    try:
        r = subprocess.run(
            ["git"] + args, cwd=cwd,
            capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=timeout,
        )
        return r.stdout if r.returncode == 0 else None
    except Exception:
        return None


def _is_git_repo(path: str) -> bool:
    return _run_git(["rev-parse", "--git-dir"], path) is not None


def _get_current_content(repo: str) -> str:
    """Return concatenated content of all current HEAD files (for still_present check)."""
    result = _run_git(["grep", "-r", "--cached", "-l", ""], repo, timeout=10)
    return result or ""


# ── scanner ───────────────────────────────────────────────────────────────────

class GitHistoryScanner:
    def __init__(self, repo_path: str, max_commits: int = 500):
        self.repo = repo_path
        self.max_commits = max_commits
        self.findings: List[HistoryFinding] = []
        self._seen_fingerprints: set = set()

    def scan(self) -> List[HistoryFinding]:
        if not _is_git_repo(self.repo):
            print(f"Error: '{self.repo}' is not a git repository.", file=sys.stderr)
            return []

        print(f"Scanning git history (up to {self.max_commits} commits)...", file=sys.stderr)

        # Get full diff log
        log = _run_git(
            ["log", "--all", "--diff-filter=AM", "-p",
             f"--max-count={self.max_commits}",
             "--format=COMMIT:%H%nAUTHOR:%an%nDATE:%ad%nMSG:%s%nEND_META",
             "--date=short"],
            self.repo,
        )
        if not log:
            print("Warning: could not read git log.", file=sys.stderr)
            return []

        self._parse_log(log)
        self._mark_still_present()
        return self.findings

    def _parse_log(self, log: str):
        """Walk through git log -p output and check added lines for secrets."""
        commit_hash = ""
        commit_author = ""
        commit_date = ""
        commit_msg = ""
        current_file = ""
        in_meta = False

        for line in log.splitlines():
            # Commit metadata lines
            if line.startswith("COMMIT:"):
                commit_hash = line[7:].strip()
                in_meta = True
                continue
            if line.startswith("AUTHOR:"):
                commit_author = line[7:].strip()
                continue
            if line.startswith("DATE:"):
                commit_date = line[5:].strip()
                continue
            if line.startswith("MSG:"):
                commit_msg = line[4:].strip()
                continue
            if line == "END_META":
                in_meta = False
                continue

            # File being diffed
            m = _DIFF_HEADER.match(line)
            if m:
                current_file = m.group(2)
                continue

            # Only scan added lines
            if not _ADDED_LINE.match(line):
                continue

            added_content = line[1:]  # strip the leading +
            self._check_line(added_content, current_file,
                             commit_hash, commit_date, commit_author, commit_msg)

    def _check_line(self, content: str, file_path: str,
                    commit_hash: str, commit_date: str,
                    commit_author: str, commit_msg: str):
        """Check a single added line against all secret patterns."""
        for pattern, rule_id, description in SECRETS_PATTERNS:
            if rule_id in _SKIP_RULES_IN_HISTORY:
                continue
            if re.search(pattern, content, re.IGNORECASE):
                self._record(rule_id, description, content.strip(),
                             file_path, commit_hash, commit_date,
                             commit_author, commit_msg)
                break  # one finding per line

        # Entropy check
        for m in _ENTROPY_VAR_RE.finditer(content):
            candidate = m.group(1)
            if _shannon_entropy(candidate) >= ENTROPY_THRESHOLD:
                self._record("SEC-ENT",
                             f"High-entropy secret in history (entropy={_shannon_entropy(candidate):.2f})",
                             content.strip(), file_path, commit_hash,
                             commit_date, commit_author, commit_msg)
                break

    def _record(self, rule_id: str, description: str, snippet: str,
                file_path: str, commit_hash: str, commit_date: str,
                commit_author: str, commit_msg: str):
        finding = HistoryFinding(
            rule_id=rule_id,
            description=description,
            commit_hash=commit_hash,
            commit_date=commit_date,
            commit_author=commit_author,
            commit_message=commit_msg,
            file_path=file_path,
            line_snippet=snippet[:120],
            still_present=False,  # filled in later
        )
        fp = finding.fingerprint()
        if fp not in self._seen_fingerprints:
            self._seen_fingerprints.add(fp)
            self.findings.append(finding)

    def _mark_still_present(self):
        """Check whether each finding's pattern still exists in HEAD."""
        for f in self.findings:
            head_file = Path(self.repo) / f.file_path
            if not head_file.exists():
                f.still_present = False
                continue
            try:
                content = head_file.read_text(encoding="utf-8", errors="ignore")
                # Simple heuristic: check if the snippet still appears
                f.still_present = f.line_snippet.strip() in content
            except Exception:
                f.still_present = False


# ── output ────────────────────────────────────────────────────────────────────

def print_results(findings: List[HistoryFinding], json_output: bool = False):
    if json_output:
        print(json.dumps({
            "total_findings": len(findings),
            "still_present": sum(1 for f in findings if f.still_present),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "description": f.description,
                    "commit": f.commit_hash,
                    "date": f.commit_date,
                    "author": f.commit_author,
                    "message": f.commit_message,
                    "file": f.file_path,
                    "snippet": f.line_snippet,
                    "still_present": f.still_present,
                }
                for f in findings
            ],
        }, indent=2))
        return

    print(f"\n{'='*60}")
    print("VIBE SECURITY CHECKER - GIT HISTORY SCAN")
    print(f"{'='*60}\n")

    if not findings:
        print("No secrets found in git history.")
        return

    still = [f for f in findings if f.still_present]
    removed = [f for f in findings if not f.still_present]

    print(f"Total findings in history: {len(findings)}")
    print(f"  Still present in HEAD:   {len(still)}  <-- fix immediately")
    print(f"  Removed from HEAD:       {len(removed)}  <-- rotate credentials\n")

    if still:
        print("STILL PRESENT (fix AND rotate):")
        print("-" * 50)
        for f in still:
            print(f"\n  [{f.rule_id}] {f.description}")
            print(f"  File:    {f.file_path}")
            print(f"  Commit:  {f.commit_hash[:12]}  {f.commit_date}  {f.commit_author}")
            print(f"  Message: {f.commit_message}")
            print(f"  Code:    {f.line_snippet[:80]}")

    if removed:
        print("\nREMOVED FROM HEAD (rotate credentials — history is permanent):")
        print("-" * 50)
        for f in removed:
            print(f"\n  [{f.rule_id}] {f.description}")
            print(f"  File:    {f.file_path}")
            print(f"  Commit:  {f.commit_hash[:12]}  {f.commit_date}  {f.commit_author}")
            print(f"  Message: {f.commit_message}")

    print("\nIMPORTANT: Even removed secrets must be rotated.")
    print("To fully purge: git filter-repo or BFG Repo Cleaner.")


def main():
    parser = argparse.ArgumentParser(description="Scan git history for committed secrets")
    parser.add_argument("path", nargs="?", default=".",
                        help="Path to git repository (default: current directory)")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--max-commits", type=int, default=500, metavar="N",
                        help="Maximum commits to scan (default: 500)")
    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"Error: '{args.path}' does not exist")
        sys.exit(1)

    scanner = GitHistoryScanner(args.path, max_commits=args.max_commits)
    findings = scanner.scan()
    print_results(findings, json_output=args.json)

    # Exit 1 if any secrets still present in HEAD
    if any(f.still_present for f in findings):
        sys.exit(1)


if __name__ == "__main__":
    main()
