#!/usr/bin/env python3
"""
Vibe Security Checker - Report Generator
Generates comprehensive security report in multiple formats
"""

import os
import sys
import json
import argparse
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

def _load_project_config(project_path: str) -> Dict:
    """Read .vibe-security.json if present."""
    cfg_file = Path(project_path) / ".vibe-security.json"
    if cfg_file.exists():
        try:
            return json.loads(cfg_file.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def run_all_checks(project_path: str, baseline: str = None) -> Dict[str, Any]:
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
            [sys.executable, str(script_dir / 'detect_project.py'), project_path, '--json'],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            results['project_info'] = json.loads(result.stdout)
    except Exception as e:
        results['project_info'] = {'error': str(e)}
    
    # Run security scan
    try:
        scan_cmd = [sys.executable, str(script_dir / 'scan_security.py'), project_path, '--full', '--json']
        if baseline:
            scan_cmd += ['--baseline', baseline]
        result = subprocess.run(scan_cmd, capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            results['security_findings'] = json.loads(result.stdout)
    except Exception as e:
        results['security_findings'] = {'error': str(e)}
    
    # Run dependency check
    try:
        result = subprocess.run(
            [sys.executable, str(script_dir / 'check_dependencies.py'), project_path, '--json'],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            results['dependency_findings'] = json.loads(result.stdout)
    except Exception as e:
        results['dependency_findings'] = {'error': str(e)}

    # Run semgrep if available (optional — skips silently if not installed)
    results['semgrep_findings'] = _run_semgrep(project_path)

    return results


def _run_semgrep(project_path: str) -> Dict[str, Any]:
    """Run semgrep with the security-audit ruleset if installed."""
    try:
        # Check semgrep is available
        subprocess.run(['semgrep', '--version'], capture_output=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {'available': False}

    try:
        result = subprocess.run(
            ['semgrep', '--config', 'p/security-audit', '--json', '--quiet', project_path],
            capture_output=True, text=True, timeout=120,
        )
        data = json.loads(result.stdout)
        findings = []
        for r in data.get('results', []):
            findings.append({
                'rule_id': r.get('check_id', ''),
                'severity': r.get('extra', {}).get('severity', 'WARNING').upper(),
                'message': r.get('extra', {}).get('message', ''),
                'file': r.get('path', ''),
                'line': r.get('start', {}).get('line', 0),
                'cwe': r.get('extra', {}).get('metadata', {}).get('cwe', []),
                'owasp': r.get('extra', {}).get('metadata', {}).get('owasp', []),
            })
        return {'available': True, 'total': len(findings), 'findings': findings}
    except Exception as e:
        return {'available': True, 'error': str(e)}

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
    
    sec = results.get('security_findings') or {}
    dep = results.get('dependency_findings') or {}
    
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
    suppressed = sec.get('suppressed_by_baseline', 0)
    if suppressed:
        lines.append(f"| ✅ Suppressed by baseline | {suppressed} |")
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
                    cwe = f"| {f['cwe_id']} – {f['cwe_name']}" if f.get('cwe_id') else ""
                    owasp = f"| {f['owasp']}" if f.get('owasp') else ""
                    lines.append(f"#### [{f['rule_id']}] {f['description']}")
                    if cwe or owasp:
                        lines.append(f"- **Classification:** {cwe} {owasp}".strip())
                    lines.append(f"- **File:** `{f['file']}:{f['line']}`")
                    lines.append(f"- **Code:** `{f['snippet']}`")
                    lines.append(f"- **Fix:** {f['remediation']}")
                    lines.append("")
    
    # Dependency Findings
    if dep.get('findings'):
        lines.append("## Dependency Findings")
        lines.append("")
        
        for f in dep['findings']:
            icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}.get(f['severity'], '🔵')
            lines.append(f"### {icon} {f['package']} ({f['type']})")
            lines.append(f"- **Version:** {f.get('version', 'Unknown')}")
            lines.append(f"- **Issue:** {f['description']}")
            lines.append(f"- **File:** `{f['file']}`")
            lines.append(f"- **Fix:** {f['remediation']}")
            lines.append("")
    
    # Semgrep findings
    semgrep = results.get('semgrep_findings') or {}
    if semgrep.get('available') and semgrep.get('findings'):
        lines.append("## Semgrep Findings (p/security-audit)")
        lines.append("")
        for f in semgrep['findings']:
            cwe_str = ', '.join(f['cwe']) if f.get('cwe') else ''
            owasp_str = ', '.join(f['owasp']) if f.get('owasp') else ''
            lines.append(f"#### [{f['severity']}] {f['rule_id']}")
            if cwe_str or owasp_str:
                lines.append(f"- **Classification:** {cwe_str} {owasp_str}".strip())
            lines.append(f"- **File:** `{f['file']}:{f['line']}`")
            lines.append(f"- **Message:** {f['message']}")
            lines.append("")
    elif semgrep.get('available') and not semgrep.get('error'):
        lines.append("## Semgrep")
        lines.append("")
        lines.append("No additional findings from semgrep p/security-audit.")
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
    sec = results.get('security_findings') or {}

    for finding in sec.get('findings', []):
        # Add rule if not seen
        if finding['rule_id'] not in rules_seen:
            rule_entry = {
                "id": finding['rule_id'],
                "name": finding['description'].split(" (and ")[0],  # strip dedup suffix
                "shortDescription": {"text": finding['description'].split(" (and ")[0]},
                "defaultConfiguration": {
                    "level": "error" if finding['severity'] in ['CRITICAL', 'HIGH'] else "warning"
                },
            }
            # CWE / OWASP metadata
            tags = []
            if finding.get('cwe_id'):
                cwe_num = finding['cwe_id'].replace("CWE-", "")
                rule_entry["helpUri"] = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
                rule_entry["fullDescription"] = {
                    "text": f"{finding['cwe_id']}: {finding.get('cwe_name', '')}. {finding.get('owasp', '')}"
                }
                tags.append(finding['cwe_id'])
            if finding.get('owasp'):
                tags.append(finding['owasp'].split(" – ")[0])  # e.g. "A03:2021"
            if tags:
                rule_entry["properties"] = {"tags": tags}
            sarif['runs'][0]['tool']['driver']['rules'].append(rule_entry)
            rules_seen.add(finding['rule_id'])

        # Build message including fix hint when available
        msg = finding['description']
        if finding.get('fix_hint'):
            msg += f"\n\nFix hint:\n{finding['fix_hint']}"

        # Add result
        sarif['runs'][0]['results'].append({
            "ruleId": finding['rule_id'],
            "level": "error" if finding['severity'] in ['CRITICAL', 'HIGH'] else "warning",
            "message": {"text": msg},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding['file'].replace("\\", "/")},
                    "region": {"startLine": max(1, finding['line'])}
                }
            }]
        })
    
    return sarif

def generate_html_report(results: Dict[str, Any]) -> str:
    """Generate a self-contained HTML security report."""
    sec = results.get('security_findings') or {}
    dep = results.get('dependency_findings') or {}
    proj = results.get('project_info') or {}

    grade = sec.get('grade', '?')
    critical = sec.get('critical', 0)
    high = sec.get('high', 0)
    medium = sec.get('medium', 0)
    low = sec.get('low', 0)
    total = sec.get('total_findings', 0)
    suppressed = sec.get('suppressed_by_baseline', 0)
    dep_total = dep.get('total_findings', 0)
    scan_date = results.get('scan_date', '')[:10]

    grade_color = {'A': '#22c55e', 'B': '#84cc16', 'C': '#f59e0b',
                   'D': '#f97316', 'F': '#ef4444'}.get(grade, '#6b7280')

    def sev_badge(sev: str) -> str:
        colors = {'CRITICAL': '#ef4444', 'HIGH': '#f97316',
                  'MEDIUM': '#f59e0b', 'LOW': '#3b82f6'}
        bg = colors.get(sev, '#6b7280')
        return f'<span style="background:{bg};color:#fff;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:600">{sev}</span>'

    def conf_badge(conf: str) -> str:
        if conf == 'HIGH':
            return ''
        colors = {'MEDIUM': '#f59e0b', 'LOW': '#6b7280'}
        bg = colors.get(conf, '#6b7280')
        return f' <span style="background:{bg};color:#fff;padding:1px 6px;border-radius:4px;font-size:0.7rem">{conf} CONF</span>'

    def esc(s: str) -> str:
        return (str(s)
                .replace('&', '&amp;').replace('<', '&lt;')
                .replace('>', '&gt;').replace('"', '&quot;'))

    # Build findings rows
    findings_html = ""
    for f in sec.get('findings', []):
        cwe = f'<small style="color:#6b7280">{esc(f.get("cwe_id",""))} {esc(f.get("cwe_name",""))}</small>' if f.get('cwe_id') else ''
        fix = f'<div style="margin-top:4px;color:#374151"><strong>Fix:</strong> {esc(f.get("remediation",""))}</div>'
        hint = ''
        if f.get('fix_hint'):
            hint = f'<pre style="margin:6px 0 0;background:#f3f4f6;padding:6px 8px;border-radius:4px;font-size:0.78rem;overflow:auto">{esc(f["fix_hint"])}</pre>'
        findings_html += f"""
        <div style="border:1px solid #e5e7eb;border-radius:8px;padding:14px 16px;margin-bottom:12px">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
            {sev_badge(f.get('severity',''))}
            {conf_badge(f.get('confidence','HIGH'))}
            <strong style="font-family:monospace">[{esc(f.get('rule_id',''))}]</strong>
            <span>{esc(f.get('description',''))}</span>
          </div>
          <div style="color:#6b7280;font-size:0.85rem">{esc(f.get('file',''))}:{f.get('line',0)} {cwe}</div>
          <pre style="margin:6px 0;background:#f3f4f6;padding:6px 8px;border-radius:4px;font-size:0.78rem;overflow:auto">{esc(f.get('snippet',''))}</pre>
          {fix}{hint}
        </div>"""

    # Dependency rows
    dep_html = ""
    for f in dep.get('findings', []):
        dep_html += f"""
        <div style="border:1px solid #e5e7eb;border-radius:8px;padding:12px 16px;margin-bottom:10px">
          <div style="display:flex;gap:8px;align-items:center">
            {sev_badge(f.get('severity','HIGH'))}
            <strong>{esc(f.get('package',''))}</strong>
            <span style="color:#6b7280;font-size:0.85rem">{esc(f.get('version') or '')}</span>
            <span style="color:#6b7280;font-size:0.85rem">({esc(f.get('type',''))})</span>
          </div>
          <div style="margin-top:4px">{esc(f.get('description',''))}</div>
          <div style="color:#6b7280;font-size:0.85rem;margin-top:2px">{esc(f.get('file',''))}</div>
          <div style="margin-top:4px;color:#374151"><strong>Fix:</strong> {esc(f.get('remediation',''))}</div>
        </div>"""

    # Semgrep rows
    semgrep = results.get('semgrep_findings') or {}
    semgrep_html = ""
    if semgrep.get('available') and semgrep.get('findings'):
        for f in semgrep['findings']:
            semgrep_html += f"""
            <div style="border:1px solid #e5e7eb;border-radius:8px;padding:12px 16px;margin-bottom:10px">
              <div><strong>[{esc(f.get('rule_id',''))}]</strong> {sev_badge(f.get('severity','WARNING'))}</div>
              <div style="color:#6b7280;font-size:0.85rem">{esc(f.get('file',''))}:{f.get('line',0)}</div>
              <div style="margin-top:4px">{esc(f.get('message',''))}</div>
            </div>"""

    proj_html = ""
    if proj and 'error' not in proj:
        proj_html = f"""
        <section style="margin-bottom:32px">
          <h2 style="font-size:1.2rem;border-bottom:2px solid #e5e7eb;padding-bottom:6px">Project Analysis</h2>
          <table style="border-collapse:collapse;width:100%;font-size:0.9rem">
            <tr><td style="padding:4px 8px;color:#6b7280;width:160px">Type</td><td>{esc(proj.get('project_type',''))}</td></tr>
            <tr><td style="padding:4px 8px;color:#6b7280">Languages</td><td>{esc(', '.join(proj.get('languages',[])) or 'Unknown')}</td></tr>
            <tr><td style="padding:4px 8px;color:#6b7280">Frameworks</td><td>{esc(', '.join(proj.get('frameworks',[])) or 'None')}</td></tr>
            <tr><td style="padding:4px 8px;color:#6b7280">Databases</td><td>{esc(', '.join(proj.get('databases',[])) or 'None')}</td></tr>
            <tr><td style="padding:4px 8px;color:#6b7280">Cloud</td><td>{esc(', '.join(proj.get('cloud_services',[])) or 'None')}</td></tr>
          </table>
        </section>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vibe Security Report — {esc(results.get('project_path',''))}</title>
<style>
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;background:#f9fafb;color:#111827}}
  .container{{max-width:900px;margin:0 auto;padding:32px 24px}}
  h1{{font-size:1.6rem;margin-bottom:4px}}
  h2{{font-size:1.2rem;border-bottom:2px solid #e5e7eb;padding-bottom:6px;margin-top:32px}}
  .grade{{display:inline-flex;align-items:center;justify-content:center;width:72px;height:72px;
          border-radius:50%;font-size:2.4rem;font-weight:800;color:#fff;background:{grade_color}}}
  .summary-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:12px;margin:20px 0}}
  .card{{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:14px;text-align:center}}
  .card .num{{font-size:2rem;font-weight:700}}
  .card .lbl{{font-size:0.75rem;color:#6b7280;text-transform:uppercase;letter-spacing:.05em}}
</style>
</head>
<body>
<div class="container">
  <header style="display:flex;align-items:center;gap:24px;margin-bottom:24px">
    <div class="grade">{grade}</div>
    <div>
      <h1>Vibe Security Report</h1>
      <div style="color:#6b7280">{esc(results.get('project_path',''))}</div>
      <div style="color:#6b7280;font-size:0.85rem">Scanned {esc(scan_date)}</div>
    </div>
  </header>

  <div class="summary-grid">
    <div class="card"><div class="num" style="color:#ef4444">{critical}</div><div class="lbl">Critical</div></div>
    <div class="card"><div class="num" style="color:#f97316">{high}</div><div class="lbl">High</div></div>
    <div class="card"><div class="num" style="color:#f59e0b">{medium}</div><div class="lbl">Medium</div></div>
    <div class="card"><div class="num" style="color:#3b82f6">{low}</div><div class="lbl">Low</div></div>
    <div class="card"><div class="num" style="color:#6b7280">{dep_total}</div><div class="lbl">Dependency</div></div>
    {"" if not suppressed else f'<div class="card"><div class="num" style="color:#22c55e">{suppressed}</div><div class="lbl">Suppressed</div></div>'}
  </div>

  {proj_html}

  {"<section><h2>Security Findings</h2>" + findings_html + "</section>" if sec.get('findings') else '<section><h2>Security Findings</h2><p style="color:#22c55e;font-weight:600">No security findings.</p></section>'}

  {"<section><h2>Dependency Findings</h2>" + dep_html + "</section>" if dep.get('findings') else ""}

  {"<section><h2>Semgrep Findings</h2>" + semgrep_html + "</section>" if semgrep_html else ""}

  <section style="margin-top:40px;padding-top:16px;border-top:1px solid #e5e7eb">
    <h2>Best Practices</h2>
    <ul style="line-height:1.8;color:#374151">
      <li>Always review AI-generated code before committing</li>
      <li>Run this scanner as part of your CI/CD pipeline</li>
      <li>Never commit secrets — use environment variables or a secrets manager</li>
      <li>Verify all AI-suggested packages exist before installing</li>
      <li>Rotate any credential that has ever appeared in git history</li>
    </ul>
  </section>

  <footer style="margin-top:40px;color:#9ca3af;font-size:0.8rem;text-align:center">
    Generated by <strong>Vibe Security Checker</strong>
  </footer>
</div>
</body>
</html>"""
    return html


def main():
    parser = argparse.ArgumentParser(description='Generate security report')
    parser.add_argument('path', help='Path to project directory')
    parser.add_argument('--format', choices=['markdown', 'json', 'sarif', 'html'], default='markdown',
                        help='Output format')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--baseline', metavar='FILE',
                        help='Suppress findings present in baseline file (pass to scanner)')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.path):
        print(f"Error: Path '{args.path}' does not exist")
        return
    
    # If no --baseline flag, check project config
    baseline = args.baseline
    if not baseline:
        cfg = _load_project_config(args.path)
        baseline = cfg.get("baseline")

    print("Running security analysis...")
    results = run_all_checks(args.path, baseline=baseline)
    
    if args.format == 'markdown':
        output = generate_markdown_report(results)
    elif args.format == 'sarif':
        output = json.dumps(generate_sarif_report(results), indent=2)
    elif args.format == 'html':
        output = generate_html_report(results)
    else:
        output = json.dumps(results, indent=2)
    
    if args.output:
        Path(args.output).write_text(output)
        print(f"Report saved to: {args.output}")
    else:
        print(output)

if __name__ == '__main__':
    main()