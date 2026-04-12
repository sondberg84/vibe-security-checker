#!/usr/bin/env python3
"""
Vibe Security Checker - Pre-commit Hook Installer

Installs a Git pre-commit hook that runs the security scanner before every
commit and blocks the commit if new CRITICAL findings are introduced.

Usage:
    python scripts/install_hooks.py [TARGET_REPO_PATH]

If TARGET_REPO_PATH is omitted the current directory is used.
"""

import os
import sys
import stat
import argparse
from pathlib import Path

HOOK_SCRIPT = """\
#!/bin/sh
# Vibe Security Checker pre-commit hook
# Installed by: scripts/install_hooks.py
# Docs: https://github.com/sondberg84/vibe-security-checker

# Locate scanner relative to repo root (adjust if your layout differs)
SCANNER_DIR="$(git rev-parse --show-toplevel)"

# Try local install first, then fall back to a sibling checkout
if [ -f "$SCANNER_DIR/vibe-security-checker/scripts/scan_security.py" ]; then
    SCANNER="$SCANNER_DIR/vibe-security-checker/scripts/scan_security.py"
elif [ -f "$SCANNER_DIR/../vibe-security-checker/scripts/scan_security.py" ]; then
    SCANNER="$SCANNER_DIR/../vibe-security-checker/scripts/scan_security.py"
else
    echo "[vibe-security] scanner not found — skipping pre-commit check"
    exit 0
fi

echo "[vibe-security] Running security scan (staged files only)..."
python "$SCANNER" "$SCANNER_DIR" --full --staged --json > /tmp/vibe_scan_result.json 2>/dev/null

CRITICAL=$(python -c "import json,sys; d=json.load(open('/tmp/vibe_scan_result.json')); sys.stdout.write(str(d.get('critical',0)))" 2>/dev/null)
TOTAL=$(python -c "import json,sys; d=json.load(open('/tmp/vibe_scan_result.json')); sys.stdout.write(str(d.get('total_findings',0)))" 2>/dev/null)

if [ "$CRITICAL" -gt 0 ] 2>/dev/null; then
    echo ""
    echo "[vibe-security] ⛔  COMMIT BLOCKED: $CRITICAL critical finding(s) detected."
    echo "[vibe-security] Run the scanner to see details:"
    echo "    python $SCANNER . --full"
    echo ""
    rm -f /tmp/vibe_scan_result.json
    exit 1
fi

echo "[vibe-security] ✅  $TOTAL finding(s) — none critical. Commit allowed."
rm -f /tmp/vibe_scan_result.json
exit 0
"""


def install(repo_path: str, force: bool = False) -> bool:
    """Install the pre-commit hook into a Git repo. Returns True on success."""
    repo = Path(repo_path).resolve()
    git_dir = repo / ".git"

    if not git_dir.is_dir():
        print(f"Error: '{repo}' is not a Git repository (no .git directory found).")
        return False

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)

    hook_file = hooks_dir / "pre-commit"

    if hook_file.exists() and not force:
        # Check if it's already ours
        content = hook_file.read_text(encoding="utf-8", errors="ignore")
        if "vibe-security" in content:
            print(f"Hook already installed at {hook_file}")
            return True
        print(
            f"Error: a pre-commit hook already exists at {hook_file}.\n"
            "Use --force to overwrite it."
        )
        return False

    hook_file.write_text(HOOK_SCRIPT, encoding="utf-8")

    # Make executable (Unix/Linux/Mac); on Windows Git reads the shebang via Git Bash
    current = hook_file.stat().st_mode
    hook_file.chmod(current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    print(f"[OK] Pre-commit hook installed at {hook_file}")
    print("   The scanner will now run automatically before every commit.")
    print("   Commits with CRITICAL findings will be blocked.")
    print("")
    print("   To bypass the hook for a single commit (emergency only):")
    print("   git commit --no-verify")
    return True


def uninstall(repo_path: str) -> bool:
    """Remove the vibe-security pre-commit hook if present."""
    repo = Path(repo_path).resolve()
    hook_file = repo / ".git" / "hooks" / "pre-commit"

    if not hook_file.exists():
        print("No pre-commit hook found.")
        return True

    content = hook_file.read_text(encoding="utf-8", errors="ignore")
    if "vibe-security" not in content:
        print("The existing pre-commit hook was not installed by vibe-security-checker.")
        print("Remove it manually if needed.")
        return False

    hook_file.unlink()
    print(f"[OK] Pre-commit hook removed from {hook_file}")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Install or remove the vibe-security pre-commit hook"
    )
    parser.add_argument(
        "repo_path",
        nargs="?",
        default=".",
        help="Path to the target Git repository (default: current directory)",
    )
    parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="Overwrite an existing pre-commit hook",
    )
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="Remove the hook instead of installing it",
    )

    args = parser.parse_args()

    if args.uninstall:
        success = uninstall(args.repo_path)
    else:
        success = install(args.repo_path, force=args.force)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
