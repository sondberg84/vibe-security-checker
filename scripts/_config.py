"""
_config.py — Configuration loading for Vibe Security Checker.

Contains:
  - CONFIG_FILENAME constant
  - ScanConfig dataclass
  - load_config() function
"""

import json
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Set

try:
    from ._models import Severity  # noqa: F401 — re-exported for convenience
except ImportError:
    from _models import Severity  # noqa: F401


CONFIG_FILENAME = ".vibe-security.json"


@dataclass
class ScanConfig:
    checks: Optional[List[str]] = None          # None = all checks
    severity_threshold: str = "low"
    baseline: Optional[str] = None
    exclude_paths: List[str] = field(default_factory=list)
    exclude_rules: Set[str] = field(default_factory=set)
    fail_on: str = "critical"
    custom_patterns: List[dict] = field(default_factory=list)
    diff_files: Optional[Set[str]] = None       # When set, only scan these files (relative paths)


def load_config(project_path: str) -> ScanConfig:
    """Load .vibe-security.json from project root, return defaults if absent."""
    config_file = Path(project_path) / CONFIG_FILENAME
    if not config_file.exists():
        return ScanConfig()
    try:
        data = json.loads(config_file.read_text(encoding="utf-8"))
        return ScanConfig(
            checks=data.get("checks"),
            severity_threshold=data.get("severity_threshold", "low"),
            baseline=data.get("baseline"),
            exclude_paths=data.get("exclude_paths", []),
            exclude_rules=set([data["exclude_rules"]] if isinstance(data.get("exclude_rules"), str) else data.get("exclude_rules", [])),
            fail_on=data.get("fail_on", "critical"),
            custom_patterns=data.get("custom_patterns", []),
        )
    except Exception as e:
        print(f"Warning: could not load {CONFIG_FILENAME} ({e})", file=sys.stderr)
        return ScanConfig()
