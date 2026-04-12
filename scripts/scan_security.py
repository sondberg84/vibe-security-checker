#!/usr/bin/env python3
"""
Vibe Security Checker - Main scanning script
Detects security vulnerabilities in AI-generated code
"""

import os
import re
import json
import argparse
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional
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

# ============================================================================
# DETECTION PATTERNS
# ============================================================================

SECRETS_PATTERNS = [
    # API Keys
    (r'["\'](?:sk|pk)[-_](?:live|test)[-_][a-zA-Z0-9]{24,}["\']', 'SEC-001', 'Stripe API key'),
    (r'["\']AIza[a-zA-Z0-9_-]{35}["\']', 'SEC-002', 'Google API key'),
    (r'["\']AKIA[A-Z0-9]{16}["\']', 'SEC-003', 'AWS Access Key ID'),
    (r'["\']ghp_[a-zA-Z0-9]{36}["\']', 'SEC-004', 'GitHub Personal Access Token'),
    (r'["\']xox[baprs]-[a-zA-Z0-9-]{10,}["\']', 'SEC-005', 'Slack Token'),
    (r'["\']eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*["\']', 'SEC-006', 'JWT Token'),
    
    # Common AI-generated secrets
    (r'["\']your[-_]?256[-_]?bit[-_]?secret["\']', 'SEC-007', 'AI-generated placeholder secret'),
    (r'["\']secret["\']', 'SEC-008', 'Hardcoded "secret" value'),
    (r'["\']password123["\']', 'SEC-009', 'Weak hardcoded password'),
    (r'["\']admin@example\.com["\']', 'SEC-010', 'AI-generated test credential'),
    (r'["\']changeme["\']', 'SEC-011', 'Placeholder password'),
    (r'password\s*=\s*["\'][^"\']+["\']', 'SEC-012', 'Hardcoded password assignment'),
    (r'api[_-]?key\s*[=:]\s*["\'][a-zA-Z0-9]{16,}["\']', 'SEC-013', 'Hardcoded API key'),
    (r'api[_-]?secret\s*[=:]\s*["\'][a-zA-Z0-9]{16,}["\']', 'SEC-017', 'Hardcoded API secret'),
    (r'["\'](?:PK|AK)[A-Z0-9]{20,}["\']', 'SEC-018', 'Alpaca API key (paper=PK, live=AK)'),

    # Database connection strings
    (r'mongodb(?:\+srv)?://[^"\'\s]+:[^"\'\s]+@', 'SEC-014', 'MongoDB connection with credentials'),
    (r'postgres(?:ql)?://[^"\'\s]+:[^"\'\s]+@', 'SEC-015', 'PostgreSQL connection with credentials'),
    (r'mysql://[^"\'\s]+:[^"\'\s]+@', 'SEC-016', 'MySQL connection with credentials'),
]

INJECTION_PATTERNS = {
    'sql': [
        (r'execute\s*\(\s*["\'].*?\%s.*?["\'].*?\%', 'INJ-001', 'SQL string formatting (use parameterized queries)'),
        (r'execute\s*\(\s*f["\']', 'INJ-002', 'SQL f-string injection risk'),
        (r'execute\s*\(\s*["\'].*?\+', 'INJ-003', 'SQL string concatenation'),
        (r'cursor\.execute\s*\([^,)]*\+', 'INJ-004', 'Cursor execute with concatenation'),
        (r'\.query\s*\(\s*[`"\'].*?\$\{', 'INJ-005', 'SQL template literal injection'),
        (r'SELECT.*FROM.*WHERE.*\+.*\+', 'INJ-006', 'Raw SQL with concatenation'),
    ],
    'command': [
        (r'os\.system\s*\(', 'INJ-010', 'os.system() is dangerous'),
        (r'subprocess\.[a-z]+\s*\([^)]*shell\s*=\s*True', 'INJ-011', 'subprocess with shell=True'),
        (r'eval\s*\(\s*(?:request|req|input|user)', 'INJ-012', 'eval() with user input'),
        (r'exec\s*\(\s*(?:request|req|input|user)', 'INJ-013', 'exec() with user input'),
        (r'child_process\.exec\s*\(', 'INJ-014', 'Node.js exec() command injection risk'),
    ],
    'xss': [
        (r'innerHTML\s*=\s*(?![\'"]\s*[\'"])', 'INJ-020', 'innerHTML assignment (XSS risk)'),
        (r'document\.write\s*\(', 'INJ-021', 'document.write() XSS risk'),
        (r'\.html\s*\(\s*(?:req|request|user|data)', 'INJ-022', 'jQuery .html() with user data'),
        (r'dangerouslySetInnerHTML', 'INJ-023', 'React dangerouslySetInnerHTML'),
        (r'v-html\s*=', 'INJ-024', 'Vue v-html directive (XSS risk)'),
        (r'\{\{\{.*\}\}\}', 'INJ-025', 'Handlebars unescaped output'),
    ],
    'nosql': [
        (r'\.find\s*\(\s*(?:req\.body|request\.body)', 'INJ-030', 'NoSQL injection via req.body'),
        (r'\.findOne\s*\(\s*(?:req\.body|request\.body)', 'INJ-031', 'NoSQL injection via req.body'),
        (r'\$where.*(?:req|request|user)', 'INJ-032', 'MongoDB $where injection'),
    ],
}

AUTH_PATTERNS = [
    # Weak password hashing
    (r'hashlib\.md5\s*\(', 'AUTH-001', 'MD5 for password hashing (use bcrypt/Argon2)'),
    (r'hashlib\.sha1\s*\(', 'AUTH-002', 'SHA1 for password hashing (use bcrypt/Argon2)'),
    (r'crypto\.createHash\s*\(\s*["\']md5', 'AUTH-003', 'Node.js MD5 hashing'),
    (r'crypto\.createHash\s*\(\s*["\']sha1', 'AUTH-004', 'Node.js SHA1 hashing'),
    
    # Session/Token issues
    (r'localStorage\.setItem\s*\(\s*["\'](?:token|jwt|auth)', 'AUTH-010', 'Token in localStorage (use HttpOnly cookies)'),
    (r'sessionStorage\.setItem\s*\(\s*["\'](?:token|jwt|auth)', 'AUTH-011', 'Token in sessionStorage'),
    
    # Missing auth patterns
    (r'@app\.route\s*\([^)]*\)\s*\ndef\s+\w+\s*\([^)]*\):', 'AUTH-020', 'Flask route without auth decorator (verify manually)'),
    (r'router\.(get|post|put|delete|patch)\s*\([^)]*,\s*(?:async\s+)?\([^)]*\)\s*=>', 'AUTH-021', 'Express route (verify auth middleware)'),
]

CRYPTO_PATTERNS = [
    (r'\bDES\s*\(', 'CRYPTO-001', 'DES encryption (use AES-256)'),
    (r'\bBlowfish\s*\(', 'CRYPTO-002', 'Blowfish (use AES-256)'),
    (r'\bRC4\s*\(', 'CRYPTO-003', 'RC4 encryption (use AES-256)'),
    (r'random\.randint\s*\(.*(?:token|key|secret|password)', 'CRYPTO-010', 'Insecure random for security (use secrets module)'),
    (r'Math\.random\s*\(\).*(?:token|key|secret|id)', 'CRYPTO-011', 'Math.random() for security tokens'),
    (r'random\.choice\s*\(.*(?:token|key|secret)', 'CRYPTO-012', 'random.choice for security (use secrets.choice)'),
]

CLOUD_PATTERNS = [
    # Firebase/Supabase
    (r'\.ref\s*\(\s*["\']["\'\s]*\)\.set', 'CLOUD-001', 'Firebase write without path validation'),
    (r'supabase\s*=\s*createClient\s*\([^)]*anon[^)]*\)', 'CLOUD-002', 'Supabase anon key in client (expected but verify RLS)'),
    (r'service[_-]?role[_-]?key', 'CLOUD-003', 'Supabase service role key exposure'),
    
    # CORS
    (r'cors\s*\(\s*\{\s*origin\s*:\s*["\']?\*["\']?', 'CLOUD-010', 'CORS allows all origins'),
    (r'Access-Control-Allow-Origin.*\*', 'CLOUD-011', 'CORS header allows all origins'),
    (r"res\.setHeader\s*\(\s*['\"]Access-Control-Allow-Origin['\"]\s*,\s*['\"]\\*['\"]", 'CLOUD-012', 'Wildcard CORS header'),
    
    # S3/Storage
    (r'ACL\s*[=:]\s*["\']public-read', 'CLOUD-020', 'S3 public read ACL'),
    (r'BlockPublicAccess.*false', 'CLOUD-021', 'S3 public access enabled'),
]

DATA_PATTERNS = [
    (r'pickle\.loads?\s*\(', 'DATA-001', 'Unsafe pickle deserialization'),
    (r'yaml\.load\s*\([^)]*(?!Loader)', 'DATA-002', 'YAML load without safe loader'),
    (r'torch\.load\s*\([^)]*(?!weights_only)', 'DATA-003', 'PyTorch load without weights_only=True'),
    (r'json\.loads?\s*\(.*request', 'DATA-010', 'JSON parse of request (verify schema validation)'),
]

# File extensions to scan
SCANNABLE_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.vue', '.svelte',
    '.java', '.kt', '.go', '.rs', '.rb', '.php',
    '.html', '.htm', '.json', '.yaml', '.yml', '.toml',
    '.env', '.config', '.conf'
}

SKIP_DIRS = {
    'node_modules', '.git', '__pycache__', '.next', '.nuxt',
    'dist', 'build', '.venv', 'venv', 'env', '.env',
    'vendor', 'target', '.idea', '.vscode'
}

# ============================================================================
# SCANNER
# ============================================================================

class SecurityScanner:
    def __init__(self, root_path: str):
        self.root = Path(root_path).resolve()
        self.result = ScanResult()
        
    def scan(self, checks: Optional[List[str]] = None) -> ScanResult:
        """Run security scan on the project."""
        for file_path in self._get_files():
            self._scan_file(file_path, checks)
        return self.result
    
    def _get_files(self):
        """Yield all scannable files."""
        for root, dirs, files in os.walk(self.root):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            
            for file in files:
                file_path = Path(root) / file
                if file_path.suffix.lower() in SCANNABLE_EXTENSIONS or file.startswith('.env'):
                    yield file_path
                    self.result.files_scanned += 1
    
    def _scan_file(self, file_path: Path, checks: Optional[List[str]]):
        """Scan a single file for vulnerabilities."""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            lines = content.split('\n')
            
            # Run applicable checks
            if not checks or 'secrets' in checks:
                self._check_patterns(file_path, lines, SECRETS_PATTERNS, 'Secrets', Severity.CRITICAL,
                    'Move secrets to environment variables or a secrets manager')
            
            if not checks or 'injection' in checks:
                for category, patterns in INJECTION_PATTERNS.items():
                    severity = Severity.CRITICAL if category in ('sql', 'command') else Severity.HIGH
                    self._check_patterns(file_path, lines, patterns, f'Injection ({category})', severity,
                        'Use parameterized queries/safe APIs')
            
            if not checks or 'auth' in checks:
                self._check_patterns(file_path, lines, AUTH_PATTERNS, 'Authentication', Severity.HIGH,
                    'See references/auth.md for secure patterns')
            
            if not checks or 'crypto' in checks:
                self._check_patterns(file_path, lines, CRYPTO_PATTERNS, 'Cryptography', Severity.HIGH,
                    'Use modern algorithms (AES-256, SHA-256, bcrypt)')
            
            if not checks or 'cloud' in checks:
                self._check_patterns(file_path, lines, CLOUD_PATTERNS, 'Cloud/Infrastructure', Severity.HIGH,
                    'See references/infrastructure.md')
            
            if not checks or 'data' in checks:
                self._check_patterns(file_path, lines, DATA_PATTERNS, 'Data Handling', Severity.HIGH,
                    'Use safe deserialization methods')
                    
        except Exception as e:
            pass  # Skip files that can't be read
    
    def _check_patterns(self, file_path: Path, lines: List[str], patterns: List[tuple], 
                        category: str, severity: Severity, remediation: str):
        """Check file content against patterns."""
        content = '\n'.join(lines)
        
        for pattern, rule_id, description in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                # Find line number
                line_num = content[:match.start()].count('\n') + 1
                
                # Get code snippet
                snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ''
                
                finding = Finding(
                    rule_id=rule_id,
                    severity=severity,
                    category=category,
                    description=description,
                    file_path=str(file_path.relative_to(self.root)),
                    line_number=line_num,
                    code_snippet=snippet[:100],
                    remediation=remediation
                )
                self.result.add(finding)

def print_results(result: ScanResult, json_output: bool = False):
    """Print scan results."""
    if json_output:
        output = {
            'files_scanned': result.files_scanned,
            'total_findings': len(result.findings),
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
                    'snippet': f.code_snippet,
                    'remediation': f.remediation
                }
                for f in result.findings
            ]
        }
        print(json.dumps(output, indent=2))
        return
    
    # Console output
    print(f"\n{'='*60}")
    print("VIBE SECURITY CHECKER - SCAN RESULTS")
    print(f"{'='*60}\n")
    
    print(f"Files scanned: {result.files_scanned}")
    print(f"Total findings: {len(result.findings)}\n")
    
    # Summary by severity
    print("SUMMARY BY SEVERITY:")
    print(f"  🔴 CRITICAL: {len(result.get_by_severity(Severity.CRITICAL))}")
    print(f"  🟠 HIGH:     {len(result.get_by_severity(Severity.HIGH))}")
    print(f"  🟡 MEDIUM:   {len(result.get_by_severity(Severity.MEDIUM))}")
    print(f"  🔵 LOW:      {len(result.get_by_severity(Severity.LOW))}")
    print()
    
    # Group findings by severity
    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        findings = result.get_by_severity(severity)
        if findings:
            icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}[severity.name]
            print(f"\n{icon} {severity.name} FINDINGS ({len(findings)}):")
            print("-" * 50)
            
            for f in findings:
                print(f"\n[{f.rule_id}] {f.description}")
                print(f"  File: {f.file_path}:{f.line_number}")
                print(f"  Code: {f.code_snippet}")
                print(f"  Fix:  {f.remediation}")
    
    if not result.findings:
        print("✅ No security issues found!")
    elif result.has_critical():
        print(f"\n⛔ {len(result.get_by_severity(Severity.CRITICAL))} CRITICAL issues must be fixed before deployment!")

def main():
    parser = argparse.ArgumentParser(description='Vibe Security Checker - Scan AI-generated code for vulnerabilities')
    parser.add_argument('path', help='Path to project directory')
    parser.add_argument('--check', action='append', choices=['secrets', 'injection', 'auth', 'crypto', 'cloud', 'data', 'xss'],
                        help='Specific check to run (can specify multiple)')
    parser.add_argument('--full', action='store_true', help='Run all checks')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--severity', choices=['critical', 'high', 'medium', 'low'], 
                        help='Minimum severity to report')
    parser.add_argument('--fail-on-findings', action='store_true', 
                        help='Exit with code 1 if findings at or above severity')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.path):
        print(f"Error: Path '{args.path}' does not exist")
        sys.exit(1)
    
    scanner = SecurityScanner(args.path)
    checks = None if args.full else args.check
    result = scanner.scan(checks)
    
    # Filter by severity if specified
    if args.severity:
        min_severity = Severity[args.severity.upper()]
        result.findings = [f for f in result.findings if f.severity.value >= min_severity.value]
    
    print_results(result, args.json)
    
    # Exit code for CI/CD
    if args.fail_on_findings and result.findings:
        sys.exit(1)

if __name__ == '__main__':
    main()