"""
_output.py — Output formatting for Vibe Security Checker.

Contains:
  - _display_snippet() helper
  - print_results() function
"""

import json
import sys

from _models import Finding, ScanResult, Severity
from _rules import _mask_snippet


def _display_snippet(f: Finding) -> str:
    """Return a masked snippet for Secrets findings, original for everything else."""
    if f.category == "Secrets":
        return _mask_snippet(f.code_snippet)
    return f.code_snippet


def print_results(result: ScanResult, json_output: bool = False,
                  suppressed: int = 0, vscode_output: bool = False):
    """Print scan results."""
    grade = result.grade()

    # VS Code problem matcher format: file:line: severity: [RULE] message
    if vscode_output:
        for f in result.findings:
            sev = "error" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "warning"
            print(f"{f.file_path}:{f.line_number}: {sev}: [{f.rule_id}] {f.description}")
        return

    if json_output:
        output = {
            'files_scanned': result.files_scanned,
            'total_findings': len(result.findings),
            'suppressed_by_baseline': suppressed,
            'grade': grade,
            'critical': len(result.get_by_severity(Severity.CRITICAL)),
            'high': len(result.get_by_severity(Severity.HIGH)),
            'medium': len(result.get_by_severity(Severity.MEDIUM)),
            'low': len(result.get_by_severity(Severity.LOW)),
            'findings': [
                {
                    'rule_id': f.rule_id,
                    'severity': f.severity.name,
                    'category': f.category,
                    'description': f.description,
                    'file': f.file_path,
                    'line': f.line_number,
                    'snippet': _display_snippet(f),
                    'remediation': f.remediation,
                    'cwe_id': f.cwe_id,
                    'cwe_name': f.cwe_name,
                    'owasp': f.owasp,
                    'fix_hint': f.fix_hint,
                    'confidence': f.confidence,
                }
                for f in result.findings
            ]
        }
        print(json.dumps(output, indent=2))
        return

    # Console output
    grade_label = {'A': 'No issues', 'B': 'Low only', 'C': 'Medium issues',
                   'D': 'High issues', 'F': 'Critical issues'}
    print(f"\n{'='*60}")
    print("VIBE SECURITY CHECKER - SCAN RESULTS")
    print(f"{'='*60}\n")

    print(f"Files scanned: {result.files_scanned}")
    print(f"Total findings: {len(result.findings)}", end="")
    if suppressed:
        print(f"  ({suppressed} suppressed by baseline)", end="")
    print()
    print(f"Security Grade: {grade}  ({grade_label.get(grade, '')})")

    # Summary by severity
    print("\nSUMMARY BY SEVERITY:")
    print(f"  CRITICAL: {len(result.get_by_severity(Severity.CRITICAL))}")
    print(f"  HIGH:     {len(result.get_by_severity(Severity.HIGH))}")
    print(f"  MEDIUM:   {len(result.get_by_severity(Severity.MEDIUM))}")
    print(f"  LOW:      {len(result.get_by_severity(Severity.LOW))}")
    print()

    # Group findings by severity
    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        findings = result.get_by_severity(severity)
        if findings:
            print(f"\n{severity.name} FINDINGS ({len(findings)}):")
            print("-" * 50)

            for f in findings:
                cwe_str = f" [{f.cwe_id}]" if f.cwe_id else ""
                conf_str = f" [{f.confidence} CONFIDENCE]" if f.confidence != "HIGH" else ""
                print(f"\n[{f.rule_id}]{cwe_str}{conf_str} {f.description}")
                print(f"  File: {f.file_path}:{f.line_number}")
                print(f"  Code: {_display_snippet(f)}")
                print(f"  Fix:  {f.remediation}")
                if f.fix_hint:
                    print(f"  Hint: {f.fix_hint}")

    if not result.findings:
        print("No security issues found!")
    elif result.has_critical():
        print(f"\n{len(result.get_by_severity(Severity.CRITICAL))} CRITICAL issues must be fixed before deployment!")
