#!/usr/bin/env python3
"""
Vibe Security Checker - Dependency Analysis
Detects supply chain risks including hallucinated packages
"""

import os
import json
import argparse
import sys
import subprocess
import re
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Set, Optional

# Known hallucinated packages that AI frequently generates
HALLUCINATED_PACKAGES = {
    # Python packages AI commonly invents
    'python': {
        'huggingface-cli',  # Real package is 'huggingface-hub'
        'flask-security-utils',
        'django-rest-utils',
        'pytorch-utils',
        'tensorflow-utils',
        'numpy-tools',
        'pandas-utils',
        'scikit-utils',
        'aws-sdk',  # Real package is 'boto3'
        'google-cloud-utils',
        'openai-utils',
        'langchain-utils',
    },
    # NPM packages AI commonly invents
    'npm': {
        'react-utils',
        'vue-utils',
        'next-utils',
        'express-utils',
        'node-utils',
        'typescript-utils',
        'mongodb-utils',
        'postgres-utils',
        'aws-sdk-utils',
        'stripe-utils',
    }
}

# Packages with known critical vulnerabilities (example subset)
VULNERABLE_PACKAGES = {
    'python': {
        'pyyaml': {'< 5.4': 'CVE-2020-14343 - Arbitrary code execution'},
        'urllib3': {'< 1.26.5': 'CVE-2021-33503 - ReDoS'},
        'requests': {'< 2.31.0': 'CVE-2023-32681 - Header injection'},
        'cryptography': {'< 41.0.0': 'Multiple CVEs'},
        'pillow': {'< 10.0.1': 'CVE-2023-44271 - DoS'},
        'django': {'< 4.2.4': 'Multiple security fixes'},
        'flask': {'< 2.3.2': 'Security updates'},
        'jinja2': {'< 3.1.2': 'XSS vulnerability'},
        'werkzeug': {'< 2.3.7': 'Security updates'},
        'numpy': {'< 1.22.0': 'Buffer overflow'},
    },
    'npm': {
        'lodash': {'< 4.17.21': 'CVE-2021-23337 - Command injection'},
        'axios': {'< 1.6.0': 'SSRF vulnerability'},
        'express': {'< 4.18.2': 'Multiple security fixes'},
        'jsonwebtoken': {'< 9.0.0': 'Multiple CVEs'},
        'mongoose': {'< 6.10.0': 'Prototype pollution'},
        'sequelize': {'< 6.29.0': 'SQL injection'},
        'minimist': {'< 1.2.6': 'Prototype pollution'},
        'node-fetch': {'< 3.3.0': 'Security updates'},
        'got': {'< 11.8.5': 'Security updates'},
        'ws': {'< 8.11.0': 'ReDoS'},
    }
}

@dataclass
class DependencyFinding:
    package: str
    version: Optional[str]
    issue_type: str  # 'hallucinated', 'vulnerable', 'outdated', 'suspicious'
    severity: str
    description: str
    file_path: str
    remediation: str

class DependencyChecker:
    def __init__(self, root_path: str):
        self.root = Path(root_path).resolve()
        self.findings: List[DependencyFinding] = []
        
    def check(self) -> List[DependencyFinding]:
        """Run all dependency checks."""
        self._check_python_deps()
        self._check_npm_deps()
        self._check_requirements_files()
        self._check_package_json()
        return self.findings
    
    def _check_requirements_files(self):
        """Check Python requirements files."""
        req_files = list(self.root.glob('**/requirements*.txt'))
        req_files.extend(self.root.glob('**/pyproject.toml'))
        
        for req_file in req_files:
            if 'node_modules' in str(req_file) or '.venv' in str(req_file):
                continue
                
            try:
                content = req_file.read_text()
                
                # Extract package names
                if req_file.suffix == '.txt':
                    packages = self._parse_requirements_txt(content)
                else:
                    packages = self._parse_pyproject(content)
                
                for pkg, version in packages.items():
                    self._check_python_package(pkg, version, str(req_file.relative_to(self.root)))
                    
            except Exception:
                pass
    
    def _parse_requirements_txt(self, content: str) -> Dict[str, Optional[str]]:
        """Parse requirements.txt format."""
        packages = {}
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('-'):
                continue
            
            # Handle various formats: pkg, pkg==1.0, pkg>=1.0, pkg[extra]
            match = re.match(r'^([a-zA-Z0-9_-]+)(?:\[.*\])?(?:([=<>!~]+)(.+))?', line)
            if match:
                pkg = match.group(1).lower()
                version = match.group(3) if match.group(3) else None
                packages[pkg] = version
        return packages
    
    def _parse_pyproject(self, content: str) -> Dict[str, Optional[str]]:
        """Parse pyproject.toml dependencies."""
        packages = {}
        # Simple regex for dependencies section
        deps_match = re.search(r'dependencies\s*=\s*\[(.*?)\]', content, re.DOTALL)
        if deps_match:
            deps = deps_match.group(1)
            for match in re.finditer(r'["\']([a-zA-Z0-9_-]+)(?:[=<>!~]+([^"\']+))?["\']', deps):
                packages[match.group(1).lower()] = match.group(2)
        return packages
    
    def _check_python_package(self, pkg: str, version: Optional[str], file_path: str):
        """Check a Python package for issues."""
        pkg_lower = pkg.lower()
        
        # Check for hallucinated packages
        if pkg_lower in HALLUCINATED_PACKAGES['python']:
            self.findings.append(DependencyFinding(
                package=pkg,
                version=version,
                issue_type='hallucinated',
                severity='CRITICAL',
                description=f'Package "{pkg}" is commonly hallucinated by AI and may not exist',
                file_path=file_path,
                remediation='Verify package exists on PyPI: pip search or visit pypi.org'
            ))
        
        # Check for known vulnerabilities
        if pkg_lower in VULNERABLE_PACKAGES['python']:
            for vuln_version, cve_info in VULNERABLE_PACKAGES['python'][pkg_lower].items():
                self.findings.append(DependencyFinding(
                    package=pkg,
                    version=version,
                    issue_type='vulnerable',
                    severity='HIGH',
                    description=f'{pkg} {vuln_version}: {cve_info}',
                    file_path=file_path,
                    remediation=f'Update {pkg} to latest version'
                ))
    
    def _check_package_json(self):
        """Check package.json files."""
        for pkg_file in self.root.glob('**/package.json'):
            if 'node_modules' in str(pkg_file):
                continue
                
            try:
                content = json.loads(pkg_file.read_text())
                rel_path = str(pkg_file.relative_to(self.root))
                
                for dep_type in ['dependencies', 'devDependencies']:
                    if dep_type in content:
                        for pkg, version in content[dep_type].items():
                            self._check_npm_package(pkg, version, rel_path)
                            
            except Exception:
                pass
    
    def _check_npm_package(self, pkg: str, version: str, file_path: str):
        """Check an NPM package for issues."""
        pkg_lower = pkg.lower()
        
        # Check for hallucinated packages
        if pkg_lower in HALLUCINATED_PACKAGES['npm']:
            self.findings.append(DependencyFinding(
                package=pkg,
                version=version,
                issue_type='hallucinated',
                severity='CRITICAL',
                description=f'Package "{pkg}" is commonly hallucinated by AI and may not exist',
                file_path=file_path,
                remediation='Verify package exists on npm: npm view or visit npmjs.com'
            ))
        
        # Check for known vulnerabilities
        if pkg_lower in VULNERABLE_PACKAGES['npm']:
            for vuln_version, cve_info in VULNERABLE_PACKAGES['npm'][pkg_lower].items():
                self.findings.append(DependencyFinding(
                    package=pkg,
                    version=version,
                    issue_type='vulnerable',
                    severity='HIGH',
                    description=f'{pkg} {vuln_version}: {cve_info}',
                    file_path=file_path,
                    remediation=f'Run: npm update {pkg}'
                ))
        
        # Check for suspicious version patterns
        if version in ['*', 'latest', '']:
            self.findings.append(DependencyFinding(
                package=pkg,
                version=version,
                issue_type='suspicious',
                severity='MEDIUM',
                description=f'Package "{pkg}" uses unpinned version "{version}"',
                file_path=file_path,
                remediation='Pin to specific version: npm install pkg@x.y.z --save-exact'
            ))
    
    def _check_python_deps(self):
        """Try to run pip-audit if available."""
        try:
            result = subprocess.run(
                ['pip-audit', '--desc', '--format', 'json'],
                capture_output=True,
                text=True,
                cwd=self.root,
                timeout=60
            )
            if result.returncode == 0:
                vulns = json.loads(result.stdout)
                for vuln in vulns:
                    self.findings.append(DependencyFinding(
                        package=vuln.get('name', 'unknown'),
                        version=vuln.get('version'),
                        issue_type='vulnerable',
                        severity='HIGH',
                        description=f"{vuln.get('vulns', [{}])[0].get('id', 'Unknown CVE')}",
                        file_path='(installed)',
                        remediation=f"pip install --upgrade {vuln.get('name')}"
                    ))
        except Exception:
            pass  # pip-audit not available
    
    def _check_npm_deps(self):
        """Try to run npm audit if package-lock.json exists."""
        lock_file = self.root / 'package-lock.json'
        if not lock_file.exists():
            return
            
        try:
            result = subprocess.run(
                ['npm', 'audit', '--json'],
                capture_output=True,
                text=True,
                cwd=self.root,
                timeout=60
            )
            audit_data = json.loads(result.stdout)
            
            if 'vulnerabilities' in audit_data:
                for pkg, info in audit_data['vulnerabilities'].items():
                    self.findings.append(DependencyFinding(
                        package=pkg,
                        version=info.get('range'),
                        issue_type='vulnerable',
                        severity=info.get('severity', 'unknown').upper(),
                        description=info.get('via', [{}])[0].get('title', 'Security vulnerability') if isinstance(info.get('via', [{}])[0], dict) else str(info.get('via', [])),
                        file_path='package-lock.json',
                        remediation=f"npm audit fix or npm update {pkg}"
                    ))
        except Exception:
            pass

def print_results(findings: List[DependencyFinding], json_output: bool = False):
    """Print dependency check results."""
    if json_output:
        output = {
            'total_findings': len(findings),
            'findings': [
                {
                    'package': f.package,
                    'version': f.version,
                    'type': f.issue_type,
                    'severity': f.severity,
                    'description': f.description,
                    'file': f.file_path,
                    'remediation': f.remediation
                }
                for f in findings
            ]
        }
        print(json.dumps(output, indent=2))
        return
    
    print(f"\n{'='*60}")
    print("VIBE SECURITY CHECKER - DEPENDENCY ANALYSIS")
    print(f"{'='*60}\n")
    
    print(f"Total findings: {len(findings)}\n")
    
    # Group by type
    hallucinated = [f for f in findings if f.issue_type == 'hallucinated']
    vulnerable = [f for f in findings if f.issue_type == 'vulnerable']
    suspicious = [f for f in findings if f.issue_type == 'suspicious']
    
    if hallucinated:
        print("🔴 POTENTIALLY HALLUCINATED PACKAGES (AI may have invented these):")
        print("-" * 50)
        for f in hallucinated:
            print(f"  ⚠️  {f.package}")
            print(f"      File: {f.file_path}")
            print(f"      Action: {f.remediation}")
        print()
    
    if vulnerable:
        print("🟠 VULNERABLE PACKAGES:")
        print("-" * 50)
        for f in vulnerable:
            print(f"  [{f.severity}] {f.package} {f.version or ''}")
            print(f"      {f.description}")
            print(f"      Fix: {f.remediation}")
        print()
    
    if suspicious:
        print("🟡 SUSPICIOUS CONFIGURATIONS:")
        print("-" * 50)
        for f in suspicious:
            print(f"  {f.package}: {f.description}")
            print(f"      Fix: {f.remediation}")
        print()
    
    if not findings:
        print("✅ No dependency issues found!")
    elif hallucinated:
        print(f"\n⛔ {len(hallucinated)} packages may be hallucinated! Verify they exist before installing.")

def main():
    parser = argparse.ArgumentParser(description='Check dependencies for supply chain risks')
    parser.add_argument('path', help='Path to project directory')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--fail-on-findings', action='store_true', help='Exit with code 1 if findings')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.path):
        print(f"Error: Path '{args.path}' does not exist")
        sys.exit(1)
    
    checker = DependencyChecker(args.path)
    findings = checker.check()
    
    print_results(findings, args.json)
    
    if args.fail_on_findings and findings:
        sys.exit(1)

if __name__ == '__main__':
    main()