#!/usr/bin/env python3
"""
Vibe Security Checker - VS Code Integration Installer

Generates .vscode/tasks.json and .vscode/extensions.json in a target project
so that developers can run the security scanner directly from VS Code, with
findings appearing in the Problems panel.

Usage:
    python scripts/install_vscode.py [TARGET_PROJECT_PATH]

If TARGET_PROJECT_PATH is omitted the current directory is used.

What gets installed:
  .vscode/tasks.json     — "Vibe: Security Scan" task (Ctrl+Shift+B or Tasks menu)
  .vscode/extensions.json — recommends no extra extensions (scanner is self-contained)

The task uses --vscode output format which VS Code parses with a problem matcher,
showing findings as inline squiggles and in the Problems panel.
"""

import os
import sys
import json
import argparse
from pathlib import Path


# ── templates ─────────────────────────────────────────────────────────────────

def _tasks_json(scanner_path: str, project_path: str) -> dict:
    """Build .vscode/tasks.json content."""
    return {
        "version": "2.0.0",
        "tasks": [
            {
                "label": "Vibe: Security Scan (full)",
                "type": "shell",
                "command": f"python \"{scanner_path}\" \"{project_path}\" --full --vscode",
                "group": {
                    "kind": "build",
                    "isDefault": True
                },
                "presentation": {
                    "reveal": "always",
                    "panel": "shared",
                    "clear": True
                },
                "problemMatcher": {
                    "owner": "vibe-security",
                    "fileLocation": ["relative", "${workspaceFolder}"],
                    "pattern": {
                        "regexp": "^(.+):(\\d+):\\s+(error|warning):\\s+(.+)$",
                        "file": 1,
                        "line": 2,
                        "severity": 3,
                        "message": 4
                    }
                }
            },
            {
                "label": "Vibe: Security Scan (staged only)",
                "type": "shell",
                "command": f"python \"{scanner_path}\" \"{project_path}\" --full --staged --vscode",
                "group": "build",
                "presentation": {
                    "reveal": "always",
                    "panel": "shared",
                    "clear": True
                },
                "problemMatcher": {
                    "owner": "vibe-security",
                    "fileLocation": ["relative", "${workspaceFolder}"],
                    "pattern": {
                        "regexp": "^(.+):(\\d+):\\s+(error|warning):\\s+(.+)$",
                        "file": 1,
                        "line": 2,
                        "severity": 3,
                        "message": 4
                    }
                }
            },
            {
                "label": "Vibe: Generate HTML Report",
                "type": "shell",
                "command": (
                    f"python \"{Path(scanner_path).parent / 'generate_report.py'}\" "
                    f"\"{project_path}\" --format html --output vibe-security-report.html "
                    f"&& echo \"Report saved to vibe-security-report.html\""
                ),
                "group": "build",
                "presentation": {
                    "reveal": "always",
                    "panel": "shared",
                    "clear": True
                },
                "problemMatcher": []
            },
            {
                "label": "Vibe: Save Baseline",
                "type": "shell",
                "command": (
                    f"python \"{scanner_path}\" \"{project_path}\" --full "
                    f"--save-baseline .vibe-security-baseline.json"
                ),
                "group": "build",
                "presentation": {
                    "reveal": "always",
                    "panel": "shared"
                },
                "problemMatcher": []
            }
        ]
    }


# ── installer ─────────────────────────────────────────────────────────────────

def install(target_path: str, force: bool = False) -> bool:
    target = Path(target_path).resolve()

    if not target.is_dir():
        print(f"Error: '{target}' is not a directory.")
        return False

    vscode_dir = target / ".vscode"
    vscode_dir.mkdir(exist_ok=True)

    tasks_file = vscode_dir / "tasks.json"

    # Locate the scanner relative to this script
    scanner = Path(__file__).parent / "scan_security.py"

    # Check for existing tasks.json
    if tasks_file.exists():
        try:
            existing = json.loads(tasks_file.read_text(encoding="utf-8"))
            labels = [t.get("label", "") for t in existing.get("tasks", [])]
            if any("Vibe" in l for l in labels):
                print(f"VS Code tasks already installed at {tasks_file}")
                return True
            # Merge our tasks into existing (always safe — we don't overwrite other tasks)
            our_tasks = _tasks_json(str(scanner), str(target))["tasks"]
            existing.setdefault("tasks", []).extend(our_tasks)
            tasks_file.write_text(json.dumps(existing, indent=4), encoding="utf-8")
            print(f"[OK] Merged Vibe tasks into existing {tasks_file}")
            return True
        except Exception:
            if not force:
                print(f"Error: {tasks_file} exists and could not be parsed. Use --force to overwrite.")
                return False

    tasks_file.write_text(
        json.dumps(_tasks_json(str(scanner), str(target)), indent=4),
        encoding="utf-8"
    )
    print(f"[OK] VS Code tasks installed at {tasks_file}")
    print("")
    print("   How to use:")
    print("   - Ctrl+Shift+B -> 'Vibe: Security Scan (full)'")
    print("   - Findings appear in the Problems panel (Ctrl+Shift+M)")
    print("   - Click a finding to jump to the exact line")
    print("")
    print("   Available tasks (Tasks > Run Task):")
    print("   - Vibe: Security Scan (full)")
    print("   - Vibe: Security Scan (staged only)")
    print("   - Vibe: Generate HTML Report")
    print("   - Vibe: Save Baseline")
    return True


def uninstall(target_path: str) -> bool:
    tasks_file = Path(target_path).resolve() / ".vscode" / "tasks.json"
    if not tasks_file.exists():
        print("No .vscode/tasks.json found.")
        return True

    try:
        data = json.loads(tasks_file.read_text(encoding="utf-8"))
        original_count = len(data.get("tasks", []))
        data["tasks"] = [t for t in data.get("tasks", []) if "Vibe" not in t.get("label", "")]
        removed = original_count - len(data["tasks"])
        if removed == 0:
            print("No Vibe tasks found in tasks.json.")
            return True
        if data["tasks"]:
            tasks_file.write_text(json.dumps(data, indent=4), encoding="utf-8")
        else:
            tasks_file.unlink()
        print(f"[OK] Removed {removed} Vibe task(s) from {tasks_file}")
        return True
    except Exception as e:
        print(f"Error: could not modify tasks.json ({e})")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Install or remove VS Code tasks for vibe-security-checker"
    )
    parser.add_argument("project_path", nargs="?", default=".",
                        help="Path to the target project (default: current directory)")
    parser.add_argument("--force", "-f", action="store_true",
                        help="Overwrite existing tasks.json")
    parser.add_argument("--uninstall", action="store_true",
                        help="Remove Vibe tasks from tasks.json")
    args = parser.parse_args()

    if args.uninstall:
        success = uninstall(args.project_path)
    else:
        success = install(args.project_path, force=args.force)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
