"""
_rules.py — Detection rules, patterns, and helper utilities for Vibe Security Checker.

Contains:
  - CWE_MAP, CONFIDENCE_MAP, FIX_HINTS
  - RULE_EXTENSIONS, _JS, _PY frozensets
  - ENTROPY_THRESHOLD, ENTROPY_MIN_LENGTH, _ENTROPY_VAR_RE, _shannon_entropy()
  - _MASK_RE, _mask_snippet()
  - All pattern lists: SECRETS_PATTERNS, INJECTION_PATTERNS, AUTH_PATTERNS,
    CRYPTO_PATTERNS, CLOUD_PATTERNS, DATA_PATTERNS, DEBUG_PATTERNS,
    HTTPS_PATTERNS, SSRF_PATTERNS, JWT_PATTERNS, HEADER_PATTERNS
  - SCANNABLE_EXTENSIONS, SKIP_DIRS
"""

import re
import math
from typing import Dict, Optional


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
