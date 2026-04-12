"""
_models.py — Core data models for Vibe Security Checker.

Contains:
  - Severity enum
  - Finding dataclass
  - ScanResult dataclass
"""

import hashlib
from dataclasses import dataclass, field
from typing import List
from enum import Enum


class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    category: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    remediation: str
    cwe_id: str = ""
    cwe_name: str = ""
    owasp: str = ""
    fix_hint: str = ""
    confidence: str = "HIGH"   # HIGH | MEDIUM | LOW

    def fingerprint(self) -> str:
        """Stable identity for this finding — survives line number shifts."""
        key = f"{self.rule_id}:{self.file_path}:{self.code_snippet.strip()}"
        return hashlib.sha1(key.encode()).hexdigest()[:16]


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0

    def add(self, finding: Finding):
        self.findings.append(finding)

    def get_by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def has_critical(self) -> bool:
        return len(self.get_by_severity(Severity.CRITICAL)) > 0

    def grade(self) -> str:
        """Return A–F security grade based on findings."""
        if self.has_critical():
            return "F"
        if self.get_by_severity(Severity.HIGH):
            return "D"
        if self.get_by_severity(Severity.MEDIUM):
            return "C"
        if self.get_by_severity(Severity.LOW):
            return "B"
        return "A"
