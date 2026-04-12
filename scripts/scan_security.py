#!/usr/bin/env python3
"""
Vibe Security Checker - Main scanning script
Detects security vulnerabilities in AI-generated code
"""

import os
import re
import math
import json
import hashlib
import argparse
import subprocess
import sys
from datetime import datetime
from fnmatch import fnmatch
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

    # Entropy-based secret detection
    "SEC-ENT": ("CWE-798", "Use of Hard-coded Credentials", "A02:2021 – Cryptographic Failures"),

    # .env not gitignored
    "GIT-001": ("CWE-312", "Cleartext Storage of Sensitive Information", "A02:2021 – Cryptographic Failures"),

    # Debug mode
    **{r: ("CWE-215", "Insertion of Sensitive Information Into Debugging Code", "A05:2021 – Security Misconfiguration")
       for r in ("DBG-001","DBG-002","DBG-003","DBG-004","DBG-005")},

    # Network / HTTPS
    "NET-001": ("CWE-319", "Cleartext Transmission of Sensitive Information", "A02:2021 – Cryptographic Failures"),
    **{r: ("CWE-614", "Sensitive Cookie Without 'Secure' Attribute", "A05:2021 – Security Misconfiguration")
       for r in ("NET-002","NET-003","NET-004")},

    # SSRF
    **{r: ("CWE-918", "Server-Side Request Forgery", "A10:2021 – Server-Side Request Forgery")
       for r in ("SSRF-001","SSRF-002","SSRF-003","SSRF-004","SSRF-005")},

    # JWT
    **{r: ("CWE-347", "Improper Verification of Cryptographic Signature", "A02:2021 – Cryptographic Failures")
       for r in ("JWT-001","JWT-002","JWT-003","JWT-004","JWT-005")},

    # Security headers
    **{r: ("CWE-693", "Protection Mechanism Failure", "A05:2021 – Security Misconfiguration")
       for r in ("HDR-001","HDR-002","HDR-003","HDR-004","HDR-005","HDR-006")},
}

# ============================================================================
# CONFIDENCE MAP
# HIGH   — pattern is specific enough that false positives are rare
# MEDIUM — pattern may fire on test/example code; manual verify recommended
# LOW    — heuristic; many false positives expected
# ============================================================================

CONFIDENCE_MAP: Dict[str, str] = {
    # Very specific key formats → HIGH (default, no entry needed)

    # Generic patterns that fire on placeholders → MEDIUM
    "SEC-007": "MEDIUM",   # AI placeholder secret
    "SEC-008": "MEDIUM",   # bare "secret"
    "SEC-009": "MEDIUM",   # password123
    "SEC-010": "MEDIUM",   # admin@example.com
    "SEC-011": "MEDIUM",   # changeme
    "SEC-012": "MEDIUM",   # generic password assignment
    "SEC-013": "MEDIUM",   # generic api_key assignment
    "SEC-017": "MEDIUM",   # generic api_secret

    # Injection — f-string SQL is usually real, concatenation sometimes test code
    "INJ-003": "MEDIUM",
    "INJ-004": "MEDIUM",
    "INJ-006": "MEDIUM",

    # Heuristic / broad patterns → LOW
    "AUTH-020": "LOW",     # Flask route (no auth decorator — many false positives)
    "AUTH-021": "LOW",     # Express route — same
    "INJ-040": "LOW",      # Path traversal sequence in content
    "DBG-003": "LOW",      # debug:true in JSON (may be in test configs)
    "NET-001": "MEDIUM",   # HTTP URL (may be intentional for internal services)
    "SSRF-001": "MEDIUM",  # SSRF heuristics
    "SSRF-002": "MEDIUM",
    "SSRF-003": "MEDIUM",
    "SSRF-004": "MEDIUM",
    "SSRF-005": "MEDIUM",
    "HDR-001": "MEDIUM",
    "HDR-002": "MEDIUM",
    "HDR-003": "LOW",
    "HDR-004": "LOW",
    "HDR-005": "LOW",
    "HDR-006": "LOW",
    "JWT-004": "LOW",      # algorithm list — may be intentional
    "JWT-005": "LOW",
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
# LANGUAGE-AWARE RULE FILTERING
# Maps rule_id -> set of file extensions where it applies (None = all files)
# This eliminates false positives (e.g. Python XSS rules, JS pickle rules)
# ============================================================================

_JS = frozenset({'.js', '.ts', '.jsx', '.tsx', '.vue', '.svelte', '.html', '.htm'})
_PY = frozenset({'.py'})

RULE_EXTENSIONS: Dict[str, Optional[frozenset]] = {
    # XSS — only meaningful in JS/HTML files
    "INJ-020": _JS, "INJ-021": _JS, "INJ-022": _JS,
    "INJ-023": _JS, "INJ-024": _JS, "INJ-025": _JS,
    # Node.js-specific patterns
    "INJ-014": _JS,   # child_process.exec
    "INJ-030": _JS,   # NoSQL req.body
    "INJ-031": _JS,
    "INJ-032": _JS,
    "AUTH-003": _JS,  # Node.js MD5
    "AUTH-004": _JS,  # Node.js SHA1
    "AUTH-010": _JS,  # localStorage
    "AUTH-011": _JS,  # sessionStorage
    "AUTH-021": _JS,  # Express route
    "CRYPTO-011": _JS,  # Math.random
    # Debug mode — language-specific
    "DBG-001": _PY,   # app.run(debug=True)
    "DBG-002": _PY,   # DEBUG = True
    "DBG-004": _JS,   # console.log sensitive
    "DBG-005": _PY,   # print() sensitive
    # DBG-003 (debug:true in JSON/config) and NET-* apply to all file types — no entry needed

    # SSRF — language-specific
    "SSRF-001": _PY,   # requests.*
    "SSRF-002": _PY,   # urllib
    "SSRF-003": _JS,   # fetch()
    "SSRF-004": _JS,   # axios
    "SSRF-005": _JS,   # http.get

    # JWT — Python by default, but JWT-003/004/005 are language-agnostic
    "JWT-001": _PY | frozenset({'.js', '.ts', '.jsx', '.tsx'}),
    "JWT-002": _PY,
    "JWT-005": _PY,

    # Security headers — JS/config primarily
    "HDR-003": _JS,   # helmet hsts:false
    "HDR-004": _PY,   # Django SECURE_HSTS_SECONDS
    "HDR-005": _PY,   # Django SECURE_SSL_REDIRECT

    # Python-specific patterns
    "AUTH-001": _PY,  # hashlib.md5
    "AUTH-002": _PY,  # hashlib.sha1
    "AUTH-020": _PY,  # @app.route Flask
    "CRYPTO-010": _PY,  # random.randint
    "CRYPTO-012": _PY,  # random.choice
    "DATA-001": _PY,  # pickle
    "DATA-002": _PY | frozenset({'.yaml', '.yml'}),
    "DATA-003": _PY,  # torch.load
    "INJ-002": _PY,   # f-string SQL
    "INJ-010": _PY,   # os.system
    "INJ-011": _PY,   # subprocess shell=True
    "INJ-012": _PY,   # eval() with user input
    "INJ-013": _PY,   # exec() with user input
    "INJ-015": _PY,   # subprocess string concat
    "INJ-041": _PY,   # os.path.join user input
    "INJ-042": _PY,   # open() user path
}

# ============================================================================
# ENTROPY-BASED SECRET DETECTION
# Catches high-entropy strings near secret variable names — catches secrets
# that don't match any known pattern (custom keys, invented credentials, etc.)
# ============================================================================

ENTROPY_THRESHOLD = 4.5      # bits/char — random secrets typically > 4.5
ENTROPY_MIN_LENGTH = 20      # minimum string length to analyse

# Matches: secret-sounding variable = "long string"
_ENTROPY_VAR_RE = re.compile(
    r'(?:api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?key|private[_-]?key|'
    r'auth[_-]?token|bearer|client[_-]?secret|app[_-]?secret|signing[_-]?key|'
    r'encryption[_-]?key|webhook[_-]?secret|jwt[_-]?secret|hmac[_-]?key)'
    r'\s*[=:]\s*["\']([A-Za-z0-9+/=_\-]{%d,})["\']' % ENTROPY_MIN_LENGTH,
    re.IGNORECASE
)


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string in bits per character."""
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


# ============================================================================
# SECRET VALUE MASKING
# Replaces the actual secret value in display output so credentials don't
# appear in CI logs or terminal output a second time.
# ============================================================================

_MASK_RE = re.compile(r'(["\'])([A-Za-z0-9+/=_\-\.@]{8,})\1')


def _mask_snippet(snippet: str) -> str:
    """Replace literal secret values with **** in a code snippet."""
    return _MASK_RE.sub(r'\g<1>****\g<1>', snippet)


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

DEBUG_PATTERNS = [
    (r'app\.run\s*\([^)]*debug\s*=\s*True', 'DBG-001', 'Flask app.run() with debug=True — disable before deployment'),
    (r'(?<!\w)DEBUG\s*=\s*True', 'DBG-002', 'DEBUG=True — disable in production settings'),
    (r'["\']debug["\']\s*:\s*true', 'DBG-003', 'debug:true in config — disable before deployment'),
    (r'console\.log\s*\([^)]*(?:password|token|secret|key|auth|credential)', 'DBG-004', 'console.log with sensitive data'),
    (r'print\s*\([^)]*(?:password|token|secret|api_key|credential)', 'DBG-005', 'print() with sensitive data'),
]

HTTPS_PATTERNS = [
    # HTTP in string literals (not localhost / internal addresses)
    (r'''["\']http://(?!localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|example\.com)[a-zA-Z0-9][^"\']{4,}["\']''',
     'NET-001', 'Hardcoded HTTP URL — use HTTPS in production'),
    # Cookie security
    (r'httpOnly\s*[=:]\s*false', 'NET-002', 'Cookie httpOnly=false — token readable by JavaScript'),
    (r'''sameSite\s*[=:]\s*["\']?none["\']?(?!.*[Ss]ecure)''', 'NET-003', 'Cookie SameSite=None without Secure flag'),
    (r'(?:SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE|SESSION_COOKIE_HTTPONLY)\s*=\s*False',
     'NET-004', 'Django cookie security setting disabled'),
]

SSRF_PATTERNS = [
    (r'requests\.(get|post|put|delete|patch|head)\s*\([^)]*(?:request\.|req\.|\.args|\.form|\.data|user_|input\()',
     'SSRF-001', 'SSRF: requests called with user-controlled URL'),
    (r'urllib\.request\.urlopen\s*\([^)]*(?:request\.|req\.|\.args|\.form|user_|input\()',
     'SSRF-002', 'SSRF: urllib.urlopen with user-controlled URL'),
    (r'fetch\s*\(\s*(?:req\b|request\b|user|params|searchParams|formData)',
     'SSRF-003', 'SSRF: fetch() with user-controlled URL'),
    (r'axios\.(get|post|put|delete|patch)\s*\(\s*(?:req\b|request\b|user|params)',
     'SSRF-004', 'SSRF: axios called with user-controlled URL'),
    (r'http(?:s)?\.(?:get|request)\s*\(\s*(?:req\b|request\b|user|params)',
     'SSRF-005', 'SSRF: http.get/request with user-controlled URL'),
]

JWT_PATTERNS = [
    (r'algorithms?\s*[=:]\s*["\']none["\']', 'JWT-001', 'JWT algorithm=none disables signature verification'),
    (r'(?:verify\s*=\s*False|options\s*=\s*\{[^}]*["\']verify["\']\s*:\s*False)',
     'JWT-002', 'JWT signature verification disabled'),
    (r'jwt\.decode\s*\([^)]*,\s*["\'][^"\']+["\'][^)]*\)',
     'JWT-003', 'JWT decode — verify algorithms param is explicit and restricted'),
    (r'(?:HS|RS|ES)(?:256|384|512).*(?:HS|RS|ES)(?:256|384|512)',
     'JWT-004', 'Multiple JWT algorithms accepted — use exactly one'),
    (r'ignore_expiration\s*=\s*True', 'JWT-005', 'JWT expiration check disabled'),
]

HEADER_PATTERNS = [
    (r'X-Frame-Options.{0,30}[=:,]\s*["\']?ALLOW(?!ED)',
     'HDR-001', 'X-Frame-Options ALLOW is permissive — use DENY or SAMEORIGIN'),
    (r'Access-Control-Allow-Credentials["\']?\s*[=:]\s*["\']?true',
     'HDR-002', 'CORS credentials=true — ensure origin is not wildcard *'),
    (r'hsts\s*:\s*false',
     'HDR-003', 'HSTS disabled in helmet — required for HTTPS enforcement'),
    (r'SECURE_HSTS_SECONDS\s*=\s*0',
     'HDR-004', 'Django HSTS disabled (SECURE_HSTS_SECONDS=0)'),
    (r'SECURE_SSL_REDIRECT\s*=\s*False',
     'HDR-005', 'Django HTTPS redirect disabled'),
    (r'Content-Security-Policy["\']?\s*[=:]\s*["\']?\*',
     'HDR-006', "CSP wildcard '*' defeats the policy"),
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

        # .gitignore check (not per-file — runs once)
        if not effective_checks or 'secrets' in effective_checks:
            self._check_gitignore()

        return self.result

    def _get_files(self):
        """Yield all scannable files, respecting exclude_paths and diff_files."""
        for root, dirs, files in os.walk(self.root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for file in files:
                file_path = Path(root) / file
                rel = str(file_path.relative_to(self.root))

                # Incremental mode: only scan files changed in git diff
                if self.config.diff_files is not None:
                    rel_posix = file_path.relative_to(self.root).as_posix()
                    if rel_posix not in self.config.diff_files and rel not in self.config.diff_files:
                        continue

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

            if not checks or 'debug' in checks:
                self._check_patterns(file_path, lines, DEBUG_PATTERNS, 'Debug', Severity.MEDIUM,
                    'Disable debug mode before deploying to production')

            if not checks or 'https' in checks:
                self._check_patterns(file_path, lines, HTTPS_PATTERNS, 'Network', Severity.MEDIUM,
                    'Use HTTPS and set Secure/HttpOnly cookie flags')

            if not checks or 'ssrf' in checks:
                self._check_patterns(file_path, lines, SSRF_PATTERNS, 'SSRF', Severity.HIGH,
                    'Validate and allowlist URLs before making server-side requests')

            if not checks or 'jwt' in checks:
                self._check_patterns(file_path, lines, JWT_PATTERNS, 'JWT', Severity.CRITICAL,
                    'Use a well-tested JWT library with explicit algorithm and expiry validation')

            if not checks or 'headers' in checks:
                self._check_patterns(file_path, lines, HEADER_PATTERNS, 'Security Headers', Severity.MEDIUM,
                    'Set strict security headers (CSP, HSTS, X-Frame-Options)')

            # Entropy scan — catches secrets that don't match known patterns
            if not checks or 'secrets' in checks:
                self._check_entropy(file_path, lines)

        except Exception as e:
            pass  # Skip files that can't be read
    
    @staticmethod
    def _is_suppressed(line: str, rule_id: str) -> bool:
        """
        Return True if the line carries a vibe-ignore comment that covers rule_id.
        Supported forms:
          # vibe-ignore            — suppress any rule on this line
          # vibe-ignore SEC-013    — suppress only SEC-013 on this line
          // vibe-ignore SEC-013   — same, for JS/TS files
        """
        marker = "vibe-ignore"
        for comment_char in ("#", "//"):
            idx = line.find(f"{comment_char} {marker}")
            if idx == -1:
                continue
            rest = line[idx + len(comment_char) + 1 + len(marker):].strip()
            if not rest:          # bare vibe-ignore → suppress everything
                return True
            if rule_id in rest.split():   # specific rule listed
                return True
        return False

    def _check_gitignore(self):
        """Flag .env files that exist in the project but are not covered by .gitignore."""
        gitignore_path = self.root / ".gitignore"
        gitignore_patterns: List[str] = []
        if gitignore_path.exists():
            for raw in gitignore_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                raw = raw.strip()
                if raw and not raw.startswith("#"):
                    gitignore_patterns.append(raw)

        if "GIT-001" in self.config.exclude_rules:
            return

        # Collect .env* files (skip .example / .sample / .template)
        env_candidates = list(self.root.glob(".env")) + list(self.root.glob(".env.*"))
        env_candidates += list(self.root.glob("**/.env"))
        env_candidates += list(self.root.glob("**/.env.*"))

        for env_file in set(env_candidates):
            if any(x in env_file.name for x in ("example", "sample", "template", "test")):
                continue
            try:
                rel = env_file.relative_to(self.root)
            except ValueError:
                continue
            rel_posix = rel.as_posix()
            rel_name = env_file.name

            covered = any(
                fnmatch(rel_posix, pat) or fnmatch(rel_name, pat)
                or rel_posix == pat.lstrip("/") or rel_name == pat.lstrip("/")
                for pat in gitignore_patterns
            )
            if not covered:
                cwe_id, cwe_name, owasp = CWE_MAP.get("GIT-001", ("", "", ""))
                self.result.add(Finding(
                    rule_id="GIT-001",
                    severity=Severity.CRITICAL,
                    category="Secrets",
                    description=f".env file not covered by .gitignore — credentials risk being committed",
                    file_path=rel_posix,
                    line_number=1,
                    code_snippet=f"{rel_posix} (not in .gitignore)",
                    remediation="Add .env (or *.env) to .gitignore immediately",
                    cwe_id=cwe_id,
                    cwe_name=cwe_name,
                    owasp=owasp,
                ))

    def _check_patterns(self, file_path: Path, lines: List[str], patterns: List[tuple],
                        category: str, severity: Severity, remediation: str):
        """Check file content against patterns. Reports first match per rule per file."""
        content = '\n'.join(lines)
        rel_path = str(file_path.relative_to(self.root))
        ext = file_path.suffix.lower()

        for entry in patterns:
            pattern, rule_id, description = entry[0], entry[1], entry[2]
            rule_remediation = entry[3] if len(entry) > 3 else remediation

            if rule_id in self.config.exclude_rules:
                continue

            # Language-aware filtering: skip rules not applicable to this file type
            allowed_exts = RULE_EXTENSIONS.get(rule_id)
            if allowed_exts is not None and ext not in allowed_exts:
                continue

            raw_matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
            if not raw_matches:
                continue

            # Filter out matches on suppressed lines
            valid: list = []
            for m in raw_matches:
                ln = content[:m.start()].count('\n') + 1
                raw_line = lines[ln - 1] if ln <= len(lines) else ''
                if not self._is_suppressed(raw_line, rule_id):
                    valid.append((m, ln, raw_line))

            if not valid:
                continue

            # First non-suppressed match becomes the finding
            match, line_num, raw_line = valid[0]
            snippet = raw_line.strip()

            # "and N more" counts remaining non-suppressed matches
            extra = len(valid) - 1
            display_description = f"{description} (and {extra} more in this file)" if extra else description

            cwe_id, cwe_name, owasp = CWE_MAP.get(rule_id, ("", "", ""))
            fix_hint = FIX_HINTS.get(rule_id, "")
            confidence = CONFIDENCE_MAP.get(rule_id, "HIGH")
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
                confidence=confidence,
            )
            self.result.add(finding)

    def _check_entropy(self, file_path: Path, lines: List[str]):
        """Flag high-entropy strings assigned to secret-sounding variable names."""
        content = '\n'.join(lines)
        rel_path = str(file_path.relative_to(self.root))

        if "SEC-ENT" in self.config.exclude_rules:
            return

        seen_snippets: Set[str] = set()
        for match in _ENTROPY_VAR_RE.finditer(content):
            candidate = match.group(1)
            entropy = _shannon_entropy(candidate)
            if entropy < ENTROPY_THRESHOLD:
                continue
            line_num = content[:match.start()].count('\n') + 1
            raw_line = lines[line_num - 1] if line_num <= len(lines) else ''
            snippet = raw_line.strip()
            if snippet in seen_snippets:
                continue
            # Respect inline suppression
            if self._is_suppressed(raw_line, "SEC-ENT"):
                continue
            seen_snippets.add(snippet)
            cwe_id, cwe_name, owasp = CWE_MAP.get("SEC-013", ("", "", ""))
            self.result.add(Finding(
                rule_id="SEC-ENT",
                severity=Severity.CRITICAL,
                category="Secrets",
                description=f"High-entropy secret string (entropy={entropy:.2f} bits/char)",
                file_path=rel_path,
                line_number=line_num,
                code_snippet=snippet[:100],
                remediation="Move secrets to environment variables or a secrets manager",
                cwe_id=cwe_id,
                cwe_name=cwe_name,
                owasp=owasp,
                fix_hint=FIX_HINTS.get("SEC-013", ""),
                confidence="MEDIUM",
            ))

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

def _git_changed_files(repo_path: str, staged_only: bool = False) -> Optional[Set[str]]:
    """
    Return the set of changed file paths (relative, posix) from git.
    Returns None if git is unavailable or repo_path is not a git repo.
    """
    cmd = ['git', 'diff', '--name-only', '--diff-filter=ACMR']
    if staged_only:
        cmd.append('--cached')
    else:
        cmd.append('HEAD')
    try:
        out = subprocess.run(
            cmd, cwd=repo_path, capture_output=True, text=True, timeout=15
        )
        if out.returncode != 0:
            return None
        return {line.strip() for line in out.stdout.splitlines() if line.strip()}
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser(description='Vibe Security Checker - Scan AI-generated code for vulnerabilities')
    parser.add_argument('path', help='Path to project directory')
    parser.add_argument('--check', action='append',
                        choices=['secrets', 'injection', 'auth', 'crypto', 'cloud', 'data',
                                 'xss', 'debug', 'https', 'ssrf', 'jwt', 'headers'],
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
    parser.add_argument('--vscode', action='store_true',
                        help='Output in VS Code problem matcher format (file:line: severity: message)')
    parser.add_argument('--diff', action='store_true',
                        help='Only scan files changed since last commit (git diff HEAD)')
    parser.add_argument('--staged', action='store_true',
                        help='Only scan staged files (git diff --cached) — useful in pre-commit hooks')

    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"Error: Path '{args.path}' does not exist")
        sys.exit(1)

    # Resolve git diff files when incremental mode requested
    diff_files = None
    if args.diff or args.staged:
        diff_files = _git_changed_files(args.path, staged_only=args.staged)
        if diff_files is not None:
            print(f"Incremental scan: {len(diff_files)} changed file(s)", file=sys.stderr)
        else:
            print("Warning: git diff failed — falling back to full scan", file=sys.stderr)

    # Load project config — CLI flags override config values
    config = load_config(args.path)

    # CLI overrides
    if args.full:
        config.checks = None  # all checks
    elif args.check:
        config.checks = args.check
    if args.severity:
        config.severity_threshold = args.severity
    if diff_files is not None:
        config.diff_files = diff_files
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

    print_results(result, args.json, suppressed=suppressed,
                  vscode_output=getattr(args, 'vscode', False))

    # Exit code for CI/CD — use config.fail_on unless --fail-on-findings flag is set
    fail_severity = Severity[config.fail_on.upper()]
    critical_new = [f for f in result.findings if f.severity.value >= fail_severity.value]
    if (args.fail_on_findings or config.fail_on) and critical_new:
        sys.exit(1)

if __name__ == '__main__':
    main()