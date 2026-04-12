#!/usr/bin/env python3
"""
Vibe Security Checker - Report Generator
Generates comprehensive security report in multiple formats
"""

import os
import json
import argparse
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

def run_all_checks(project_path: str) -> Dict[str, Any]:
    """Run all security checks and collect results."""
    results = {
        'scan_date': datetime.now().isoformat(),
        'project_path': project_path,
        'project_info': None,
        'security_findings': None,
        'dependency_findings': None,
    }
    
    script_dir = Path(__file__).parent
    
    # Run project detection
    try:
        result = subprocess.run(
            ['python3', str(script_dir / 'detect_project.py'), project_path, '--json'],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            results['project_info'] = json.loads(result.stdout)
    except Exception as e:
        results['project_info'] = {'error': str(e)}
    
    # Run security scan
    try:
        result = subprocess.run(
            ['python3', str(script_dir / 'scan_security.py'), project_path, '--full', '--json'],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            results['security_findings'] = json.loads(result.stdout)
    except Exception as e:
        results['security_findings'] = {'error': str(e)}
    
    # Run dependency check
    try:
        result = subprocess.run(
            ['python3', str(script_dir / 'check_dependencies.py'), project_path, '--json'],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            results['dependency_findings'] = json.loads(result.stdout)
    except Exception as e:
        results['dependency_findings'] = {'error': str(e)}
    
    return results

def generate_markdown_report(results: Dict[str, Any]) -> str:
    """Generate a markdown security report."""
    lines = []
    
    lines.append("# Vibe Security Checker Report")
    lines.append(f"\n**Scan Date:** {results['scan_date']}")
    lines.append(f"**Project:** {results['project_path']}")
    lines.append("")
    
    # Executive Summary
    lines.append("## Executive Summary")
    lines.append("")
    
    sec = results.get('security_findings', {})
    dep = results.get('dependency_findings', {})
    
    critical = sec.get('critical', 0)
    high = sec.get('high', 0)
    medium = sec.get('medium', 0)
    low = sec.get('low', 0)
    dep_total = dep.get('total_findings', 0)
    
    if critical > 0:
        lines.append(f"⛔ **DEPLOYMENT BLOCKED:** {critical} critical vulnerabilities found")
    elif high > 0:
        lines.append(f"⚠️ **ACTION REQUIRED:** {high} high-severity issues need attention")
    elif medium > 0:
        lines.append(f"📋 **REVIEW NEEDED:** {medium} medium-severity issues found")
    else:
        lines.append("✅ **PASSED:** No critical or high-severity issues found")
    
    lines.append("")
    lines.append("### Finding Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    lines.append(f"| 🔴 Critical | {critical} |")
    lines.append(f"| 🟠 High | {high} |")
    lines.append(f"| 🟡 Medium | {medium} |")
    lines.append(f"| 🔵 Low | {low} |")
    lines.append(f"| 📦 Dependencies | {dep_total} |")
    lines.append("")
    
    # Project Info
    proj = results.get('project_info', {})
    if proj and 'error' not in proj:
        lines.append("## Project Analysis")
        lines.append("")
        lines.append(f"- **Type:** {proj.get('project_type', 'Unknown')}")
        lines.append(f"- **Languages:** {', '.join(proj.get('languages', [])) or 'Unknown'}")
        lines.append(f"- **Frameworks:** {', '.join(proj.get('frameworks', [])) or 'None'}")
        lines.append(f"- **Databases:** {', '.join(proj.get('databases', [])) or 'None'}")
        lines.append(f"- **Cloud:** {', '.join(proj.get('cloud_services', [])) or 'None'}")
        
        ai_tools = proj.get('ai_tool_indicators', [])
        if ai_tools:
            lines.append(f"- **AI Tools Detected:** {', '.join(ai_tools)} ⚠️")
        lines.append("")
    
    # Detailed Findings
    if sec.get('findings'):
        lines.append("## Security Findings")
        lines.append("")
        
        # Group by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            severity_findings = [f for f in sec['findings'] if f['severity'] == severity]
            if severity_findings:
                icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}[severity]
                lines.append(f"### {icon} {severity} ({len(severity_findings)})")
                lines.append("")
                
                for f in severity_findings:
                    lines.append(f"#### [{f['rule_id']}] {f['description']}")
                    lines.append(f"- **File:** `{f['file']}:{f['line']}`")
                    lines.append(f"- **Code:** `{f['snippet']}`")
                    lines.append(f"- **Fix:** {f['remediation']}")
                    lines.append("")
    
    # Dependency Findings
    if dep.get('findings'):
        lines.append("## Dependency Findings")
        lines.append("")
        
        for f in dep['findings']:
            icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡'}[f['severity']]
            lines.append(f"### {icon} {f['package']} ({f['type']})")
            lines.append(f"- **Version:** {f.get('version', 'Unknown')}")
            lines.append(f"- **Issue:** {f['description']}")
            lines.append(f"- **File:** `{f['file']}`")
            lines.append(f"- **Fix:** {f['remediation']}")
            lines.append("")
    
    # Recommendations
    lines.append("## Recommendations")
    lines.append("")
    lines.append("### Immediate Actions")
    if critical > 0:
        lines.append("1. **Fix all CRITICAL findings before deployment**")
    if high > 0:
        lines.append("2. Address HIGH severity issues in next sprint")
    
    lines.append("")
    lines.append("### Best Practices for Vibe Coding")
    lines.append("- Always review AI-generated code before committing")
    lines.append("- Run this scanner as part of CI/CD pipeline")
    lines.append("- Never trust AI-generated authentication/authorization code without manual review")
    lines.append("- Verify all suggested packages exist before installing")
    lines.append("- Keep secrets in environment variables, never in code")
    lines.append("")
    
    lines.append("---")
    lines.append("*Generated by Vibe Security Checker*")
    
    return '\n'.join(lines)

def generate_sarif_report(results: Dict[str, Any]) -> Dict[str, Any]:
    """Generate SARIF format for GitHub integration."""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Vibe Security Checker",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/your-org/vibe-security-checker",
                    "rules": []
                }
            },
            "results": []
        }]
    }
    
    rules_seen = set()
    sec = results.get('security_findings', {})
    
    for finding in sec.get('findings', []):
        # Add rule if not seen
        if finding['rule_id'] not in rules_seen:
            sarif['runs'][0]['tool']['driver']['rules'].append({
                "id": finding['rule_id'],
                "name": finding['description'],
                "shortDescription": {"text": finding['description']},
                "defaultConfiguration": {
                    "level": "error" if finding['severity'] in ['CRITICAL', 'HIGH'] else "warning"
                }
            })
            rules_seen.add(finding['rule_id'])
        
        # Add result
        sarif['runs'][0]['results'].append({
            "ruleId": finding['rule_id'],
            "level": "error" if finding['severity'] in ['CRITICAL', 'HIGH'] else "warning",
            "message": {"text": finding['description']},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding['file']},
                    "region": {"startLine": finding['line']}
                }
            }]
        })
    
    return sarif

def main():
    parser = argparse.ArgumentParser(description='Generate security report')
    parser.add_argument('path', help='Path to project directory')
    parser.add_argument('--format', choices=['markdown', 'json', 'sarif'], default='markdown',
                        help='Output format')
    parser.add_argument('--output', '-o', help='Output file path')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.path):
        print(f"Error: Path '{args.path}' does not exist")
        return
    
    print("Running security analysis...")
    results = run_all_checks(args.path)
    
    if args.format == 'markdown':
        output = generate_markdown_report(results)
    elif args.format == 'sarif':
        output = json.dumps(generate_sarif_report(results), indent=2)
    else:
        output = json.dumps(results, indent=2)
    
    if args.output:
        Path(args.output).write_text(output)
        print(f"Report saved to: {args.output}")
    else:
        print(output)

if __name__ == '__main__':
    main()