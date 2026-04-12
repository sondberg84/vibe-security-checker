#!/usr/bin/env python3
"""
Vibe Security Checker - Main scanning script
Detects security vulnerabilities in AI-generated code
"""

import os
import re
import json
import hashlib
import argparse
import sys
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
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

# ============================================================================
# CONFIG
# ============================================================================

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
            exclude_rules=set(data.get("exclude_rules", [])),
            fail_on=data.get("fail_on", "critical"),
            custom_patterns=data.get("custom_patterns", []),
        )
    except Exception as e:
        print(f"Warning: could not load {CONFIG_FILENAME} ({e})", file=sys.stderr)
        return ScanConfig()


# ============================================================================
# CWE / OWASP TOP 10 (2021) MAPPING
# ============================================================================
# (rule_id) -> (CWE-ID, CWE name, OWASP 2021 category)

CWE_MAP: Dict[str, tuple] = {
    # Secrets — CWE-798: Use of Hard-coded Credentials
    **{r: ("CWE-798", "Use of Hard-coded Credentials", "A02:2021 – Cryptographic Failures")
       for r in ("SEC-001","SEC-002","SEC-003","SEC-004","SEC-005","SEC-006",
                 "SEC-007","SEC-008","SEC-010","SEC-011","SEC-012","SEC-013",
                 "SEC-014","SEC-015","SEC-016","SEC-017","SEC-018","SEC-019",
                 "SEC-020","SEC-021")},
    "SEC-009": ("CWE-521", "Weak Password Requirements", "A07:2021 – Identification and Authentication Failures"),

    # SQL Injection
    **{r: ("CWE-89", "SQL Injection", "A03:2021 – Injection")
       for r in ("INJ-001","INJ-002","INJ-003","INJ-004","INJ-005","INJ-006")},

    # Command / Code Injection
    **{r: ("CWE-78", "OS Command Injection", "A03:2021 – Injection")
       for r in ("INJ-010","INJ-011","INJ-014","INJ-015")},
    "INJ-012": ("CWE-94",  "Code Injection", "A03:2021 – Injection"),
    "INJ-013": ("CWE-94",  "Code Injection", "A03:2021 – Injection"),

    # XSS
    **{r: ("CWE-79", "Cross-site Scripting", "A03:2021 – Injection")
       for r in ("INJ-020","INJ-021","INJ-022","INJ-023","INJ-024","INJ-025")},

    # NoSQL Injection
    **{r: ("CWE-943", "Improper Neutralization of Special Elements in Data Query Logic", "A03:2021 – Injection")
       for r in ("INJ-030","INJ-031","INJ-032")},

    # Path Traversal
    **{r: ("CWE-22", "Path Traversal", "A01:2021 – Broken Access Control")
       for r in ("INJ-040","INJ-041","INJ-042")},

    # Authentication
    **{r: ("CWE-916", "Use of Password Hash With Insufficient Computational Effort", "A02:2021 – Cryptographic Failures")
       for r in ("AUTH-001","AUTH-002","AUTH-003","AUTH-004")},
    **{r: ("CWE-922", "Insecure Storage of Sensitive Information", "A02:2021 – Cryptographic Failures")
       for r in ("AUTH-010","AUTH-011")},
    **{r: ("CWE-306", "Missing Authentication for Critical Function", "A01:2021 – Broken Access Control")
       for r in ("AUTH-020","AUTH-021")},

    # Cryptography
    **{r: ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm", "A02:2021 – Cryptographic Failures")
       for r in ("CRYPTO-001","CRYPTO-002","CRYPTO-003")},
    **{r: ("CWE-338", "Use of Cryptographically Weak Pseudo-Random Number Generator", "A02:2021 – Cryptographic Failures")
       for r in ("CRYPTO-010","CRYPTO-011","CRYPTO-012")},

    # Cloud / Infrastructure
    "CLOUD-001": ("CWE-863", "Incorrect Authorization", "A01:2021 – Broken Access Control"),
    "CLOUD-002": ("CWE-732", "Incorrect Permission Assignment for Critical Resource", "A05:2021 – Security Misconfiguration"),
    "CLOUD-003": ("CWE-798", "Use of Hard-coded Credentials", "A02:2021 – Cryptographic Failures"),
    **{r: ("CWE-346", "Origin Validation Error", "A05:2021 – Security Misconfiguration")
       for r in ("CLOUD-010","CLOUD-011","CLOUD-012")},
    **{r: ("CWE-732", "Incorrect Permission Assignment for Critical Resource", "A05:2021 – Security Misconfiguration")
       for r in ("CLOUD-020","CLOUD-021")},

    # Data handling
    **{r: ("CWE-502", "Deserialization of Untrusted Data", "A08:2021 – Software and Data Integrity Failures")
       for r in ("DATA-001","DATA-002","DATA-003")},
    "DATA-010": ("CWE-20", "Improper Input Validation", "A03:2021 – Injection"),
}

# ============================================================================
# AUTO-FIX HINTS
# Maps rule_id -> corrected code snippet shown alongside the finding
# ============================================================================

FIX_HINTS: Dict[str, str] = {
    # Injection
    "INJ-001": "cursor.execute('SELECT * FROM t WHERE id = %s', (user_id,))",
    "INJ-002": "cursor.execute('SELECT * FROM t WHERE id = %s', (user_id,))",
    "INJ-003": "cursor.execute('SELECT * FROM t WHERE id = %s', (user_id,))",
    "INJ-004": "cursor.execute('SELECT * FROM t WHERE id = %s', (user_id,))",
    "INJ-010": "subprocess.run(['cmd', arg], check=True)  # list args, no shell",
    "INJ-011": "subprocess.run(['cmd', arg], check=True)  # remove shell=True",
    "INJ-015": "subprocess.run(['cmd', arg], check=True)  # use list, not string concat",
    "INJ-020": "element.textContent = userInput  # textContent is safe",
    "INJ-021": "element.textContent = content  # avoid document.write()",
    "INJ-040": "# Validate and sanitise path; use os.path.abspath() and check prefix",
    "INJ-041": "safe = os.path.abspath(os.path.join(base_dir, user_path))\nassert safe.startswith(base_dir)",
    "INJ-042": "safe = os.path.abspath(os.path.join(base_dir, user_path))\nassert safe.startswith(base_dir)",

    # Auth / Crypto
    "AUTH-001": "import bcrypt\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
    "AUTH-002": "import bcrypt\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
    "AUTH-003": "const bcrypt = require('bcrypt')\nawait bcrypt.hash(password, 12)",
    "AUTH-004": "const bcrypt = require('bcrypt')\nawait bcrypt.hash(password, 12)",
    "AUTH-010": "# Store token in an HttpOnly cookie instead of localStorage",
    "AUTH-011": "# Store token in an HttpOnly cookie instead of sessionStorage",
    "CRYPTO-001": "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n# Use AES-256-GCM",
    "CRYPTO-002": "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n# Use AES-256-GCM",
    "CRYPTO-003": "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n# Use AES-256-GCM",
    "CRYPTO-010": "import secrets\ntoken = secrets.token_hex(32)",
    "CRYPTO-011": "crypto.randomUUID()  // or crypto.getRandomValues()",
    "CRYPTO-012": "import secrets\nvalue = secrets.choice(sequence)",

    # Data
    "DATA-001": "import json\ndata = json.loads(serialized)  # use JSON, not pickle",
    "DATA-002": "import yaml\ndata = yaml.safe_load(f)  # safe_load prevents code execution",
    "DATA-003": "model = torch.load(path, weights_only=True)",

    # Secrets
    "SEC-012": "password = os.environ.get('DB_PASSWORD')  # use env var",
    "SEC-013": "api_key = os.environ.get('API_KEY')  # use env var",
    "SEC-017": "api_secret = os.environ.get('API_SECRET')  # use env var",
}

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
    (r'["\']?password["\']?\s*[=:]\s*["\'][^"\']{1,}["\']', 'SEC-012', 'Hardcoded password assignment'),
    (r'["\']?api[_-]?key["\']?\s*[=:]\s*["\'][a-zA-Z0-9]{16,}["\']', 'SEC-013', 'Hardcoded API key'),
    (r'["\']?api[_-]?secret["\']?\s*[=:]\s*["\'][a-zA-Z0-9]{16,}["\']', 'SEC-017', 'Hardcoded API secret'),
    (r'["\'](?:PK|AK)[A-Z0-9]{20,}["\']', 'SEC-018', 'Alpaca API key (paper=PK, live=AK)'),
    (r'["\']sk-ant-[a-zA-Z0-9_-]{40,}["\']', 'SEC-019', 'Anthropic API key'),
    (r'["\']sk-[a-zA-Z0-9]{48}["\']', 'SEC-020', 'OpenAI API key'),

    # .env-style unquoted secrets (KEY=value without quotes)
    (r'^[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD)[A-Z_]*=[A-Za-z0-9+/]{16,}$', 'SEC-021', 'Unquoted secret in env/config file'),

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
        (r'subprocess\.[a-z]+\s*\(\s*[^)\[]*\+', 'INJ-015', 'subprocess with string concatenation (use list args)'),
    ],
    'path_traversal': [
        (r'\.\.[\\/]', 'INJ-040', 'Path traversal sequence ../'),
        (r'os\.path\.join\s*\([^)]*(?:request\.|req\.|input\(|user_)', 'INJ-041', 'os.path.join with user input'),
        (r'open\s*\(\s*(?:request\.|req\.|input\(|user_)', 'INJ-042', 'open() with user-controlled path'),
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
    def __init__(self, root_path: str, config: ScanConfig = None):
        self.root = Path(root_path).resolve()
        self.config = config or ScanConfig()
        self.result = ScanResult()

    def scan(self, checks: Optional[List[str]] = None) -> ScanResult:
        """Run security scan on the project."""
        # Build effective check list: CLI arg > config > all
        effective_checks = checks or self.config.checks

        # Merge custom patterns into secrets
        custom_secrets = [
            (p["pattern"], p.get("rule_id", "CUSTOM-001"), p.get("description", "Custom pattern"))
            for p in self.config.custom_patterns
        ]

        for file_path in self._get_files():
            self._scan_file(file_path, effective_checks, custom_secrets)
        return self.result

    def _get_files(self):
        """Yield all scannable files, respecting exclude_paths from config."""
        for root, dirs, files in os.walk(self.root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for file in files:
                file_path = Path(root) / file
                rel = str(file_path.relative_to(self.root))

                # Check against configured exclude_paths (glob-style prefix match)
                if any(
                    rel.startswith(ex.rstrip("/")) or
                    file_path.match(ex)
                    for ex in self.config.exclude_paths
                ):
                    continue

                if file_path.suffix.lower() in SCANNABLE_EXTENSIONS or file.startswith('.env'):
                    yield file_path
                    self.result.files_scanned += 1

    def _scan_file(self, file_path: Path, checks: Optional[List[str]], custom_secrets: list = None):
        """Scan a single file for vulnerabilities."""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            lines = content.split('\n')

            secrets_patterns = SECRETS_PATTERNS + (custom_secrets or [])

            # Run applicable checks
            if not checks or 'secrets' in checks:
                self._check_patterns(file_path, lines, secrets_patterns, 'Secrets', Severity.CRITICAL,
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
        """Check file content against patterns. Reports first match per rule per file."""
        content = '\n'.join(lines)
        rel_path = str(file_path.relative_to(self.root))

        for entry in patterns:
            pattern, rule_id, description = entry[0], entry[1], entry[2]
            rule_remediation = entry[3] if len(entry) > 3 else remediation

            if rule_id in self.config.exclude_rules:
                continue

            matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
            if not matches:
                continue

            # First match becomes the finding
            match = matches[0]
            line_num = content[:match.start()].count('\n') + 1
            snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ''

            # Append "and N more" to description when duplicates exist
            extra = len(matches) - 1
            display_description = f"{description} (and {extra} more in this file)" if extra else description

            cwe_id, cwe_name, owasp = CWE_MAP.get(rule_id, ("", "", ""))
            fix_hint = FIX_HINTS.get(rule_id, "")
            finding = Finding(
                rule_id=rule_id,
                severity=severity,
                category=category,
                description=display_description,
                file_path=rel_path,
                line_number=line_num,
                code_snippet=snippet[:100],
                remediation=rule_remediation,
                cwe_id=cwe_id,
                cwe_name=cwe_name,
                owasp=owasp,
                fix_hint=fix_hint,
            )
            self.result.add(finding)

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


def print_results(result: ScanResult, json_output: bool = False, suppressed: int = 0):
    """Print scan results."""
    if json_output:
        output = {
            'files_scanned': result.files_scanned,
            'total_findings': len(result.findings),
            'suppressed_by_baseline': suppressed,
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
                    'remediation': f.remediation,
                    'cwe_id': f.cwe_id,
                    'cwe_name': f.cwe_name,
                    'owasp': f.owasp,
                    'fix_hint': f.fix_hint,
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
    print(f"Total findings: {len(result.findings)}", end="")
    if suppressed:
        print(f"  ({suppressed} suppressed by baseline)", end="")
    print()
    
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
                cwe_str = f" [{f.cwe_id}]" if f.cwe_id else ""
                owasp_str = f" | {f.owasp}" if f.owasp else ""
                print(f"\n[{f.rule_id}]{cwe_str} {f.description}{owasp_str}")
                print(f"  File: {f.file_path}:{f.line_number}")
                print(f"  Code: {f.code_snippet}")
                print(f"  Fix:  {f.remediation}")
                if f.fix_hint:
                    print(f"  Hint: {f.fix_hint}")
    
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
    parser.add_argument('--save-baseline', nargs='?', const=DEFAULT_BASELINE, metavar='FILE',
                        help=f'Save current findings as baseline (default: {DEFAULT_BASELINE})')
    parser.add_argument('--baseline', nargs='?', const=DEFAULT_BASELINE, metavar='FILE',
                        help=f'Compare against baseline, report only new findings (default: {DEFAULT_BASELINE})')

    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"Error: Path '{args.path}' does not exist")
        sys.exit(1)

    # Load project config — CLI flags override config values
    config = load_config(args.path)

    # CLI overrides
    if args.full:
        config.checks = None  # all checks
    elif args.check:
        config.checks = args.check
    if args.severity:
        config.severity_threshold = args.severity
    if args.baseline:
        config.baseline = args.baseline
    if args.save_baseline:
        config.baseline = None  # don't auto-apply when saving

    scanner = SecurityScanner(args.path, config=config)
    result = scanner.scan()

    # Filter by severity threshold
    min_severity = Severity[config.severity_threshold.upper()]
    result.findings = [f for f in result.findings if f.severity.value >= min_severity.value]

    # Save baseline before applying diff
    if args.save_baseline:
        baseline_path = args.save_baseline if os.path.isabs(args.save_baseline) else str(Path(args.path) / args.save_baseline)
        save_baseline(result, baseline_path)

    # Apply baseline diff (from CLI flag or config)
    suppressed = 0
    effective_baseline = None if args.save_baseline else (args.baseline or config.baseline)
    if effective_baseline:
        baseline_path = effective_baseline if os.path.isabs(effective_baseline) else str(Path(args.path) / effective_baseline)
        known = load_baseline(baseline_path)
        result.findings, suppressed = apply_baseline(result, known)

    print_results(result, args.json, suppressed=suppressed)

    # Exit code for CI/CD — use config.fail_on unless --fail-on-findings flag is set
    fail_severity = Severity[config.fail_on.upper()]
    critical_new = [f for f in result.findings if f.severity.value >= fail_severity.value]
    if (args.fail_on_findings or config.fail_on) and critical_new:
        sys.exit(1)

if __name__ == '__main__':
    main()