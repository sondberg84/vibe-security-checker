"""
_baseline.py — Baseline management for Vibe Security Checker.

Contains:
  - BASELINE_VERSION constant
  - DEFAULT_BASELINE constant
  - save_baseline() function
  - load_baseline() function
  - apply_baseline() function
"""

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Set

from _models import ScanResult


BASELINE_VERSION = 1
DEFAULT_BASELINE = ".vibe-security-baseline.json"


def save_baseline(result: ScanResult, path: str):
    """Persist current findings as a baseline for future diff runs."""
    data = {
        "version": BASELINE_VERSION,
        "created": datetime.now().isoformat(),
        "files_scanned": result.files_scanned,
        "fingerprints": [f.fingerprint() for f in result.findings],
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.name,
                "file": f.file_path,
                "line": f.line_number,
                "snippet": f.code_snippet,
                "fingerprint": f.fingerprint(),
            }
            for f in result.findings
        ],
    }
    Path(path).write_text(json.dumps(data, indent=2))
    print(f"Baseline saved: {len(result.findings)} findings → {path}", file=sys.stderr)


def load_baseline(path: str) -> Set[str]:
    """Return set of fingerprints from a baseline file."""
    try:
        data = json.loads(Path(path).read_text())
        return set(data.get("fingerprints", []))
    except FileNotFoundError:
        print(f"Warning: baseline file not found: {path}", file=sys.stderr)
        return set()
    except Exception as e:
        print(f"Warning: could not load baseline ({e})", file=sys.stderr)
        return set()


def apply_baseline(result: ScanResult, baseline_fingerprints: Set[str]) -> tuple:
    """
    Split findings into new (not in baseline) and suppressed (in baseline).
    Returns (new_findings, suppressed_count).
    """
    new_findings = [f for f in result.findings if f.fingerprint() not in baseline_fingerprints]
    suppressed = len(result.findings) - len(new_findings)
    return new_findings, suppressed
