# Guardrail Rules Database

Complete reference of all security rules with detection logic and remediation.

## Secrets Rules (SEC-xxx)

| Rule ID | Severity | Description | Detection Pattern | Remediation |
|---------|----------|-------------|-------------------|-------------|
| SEC-001 | Critical | Stripe API key | `sk-live-*`, `pk-live-*` | Use environment variables |
| SEC-002 | Critical | Google API key | `AIza*` | Use environment variables |
| SEC-003 | Critical | AWS Access Key | `AKIA*` | Use IAM roles or secrets manager |
| SEC-004 | Critical | GitHub token | `ghp_*` | Use environment variables |
| SEC-005 | Critical | Slack token | `xox[baprs]-*` | Use environment variables |
| SEC-006 | High | JWT in code | `eyJ*.*.*` pattern | Generate at runtime |
| SEC-007 | Critical | AI placeholder secret | `your-256-bit-secret` | Replace with real secret |
| SEC-008 | High | Generic "secret" | `= "secret"` | Use strong generated secret |
| SEC-009 | Critical | Weak password | `password123` | Remove test credentials |
| SEC-010 | High | Test credential | `admin@example.com` | Remove test data |
| SEC-011 | High | Placeholder password | `changeme` | Require password change |
| SEC-012 | Critical | Password assignment | `password = "..."` | Use environment variable |
| SEC-013 | Critical | Hardcoded API key | `api_key = "..."` | Use environment variable |
| SEC-014 | Critical | MongoDB credentials in URL | `mongodb://user:pass@` | Use environment variable |
| SEC-015 | Critical | PostgreSQL credentials in URL | `postgres://user:pass@` | Use environment variable |
| SEC-016 | Critical | MySQL credentials in URL | `mysql://user:pass@` | Use environment variable |

## Injection Rules (INJ-xxx)

| Rule ID | Severity | Description | Detection Pattern | Remediation |
|---------|----------|-------------|-------------------|-------------|
| INJ-001 | Critical | SQL string formatting | `execute("...%s..." % var)` | Use parameterized queries |
| INJ-002 | Critical | SQL f-string | `execute(f"SELECT...")` | Use parameterized queries |
| INJ-003 | Critical | SQL concatenation | `execute("..." + var)` | Use parameterized queries |
| INJ-004 | Critical | Cursor concatenation | `cursor.execute(...+...)` | Use parameterized queries |
| INJ-005 | Critical | SQL template literal | `query(\`...${var}...\`)` | Use parameterized queries |
| INJ-006 | Critical | Raw SQL concat | `SELECT...WHERE...+...+` | Use ORM or prepared statements |
| INJ-010 | Critical | os.system | `os.system(...)` | Use subprocess with arrays |
| INJ-011 | Critical | shell=True | `subprocess(..., shell=True)` | Use shell=False |
| INJ-012 | Critical | eval user input | `eval(request...)` | Never use eval with user input |
| INJ-013 | Critical | exec user input | `exec(request...)` | Never use exec with user input |
| INJ-014 | Critical | Node.js exec | `child_process.exec(...)` | Use execFile with arrays |
| INJ-020 | High | innerHTML assignment | `innerHTML = var` | Use textContent or sanitize |
| INJ-021 | High | document.write | `document.write(...)` | Use DOM methods |
| INJ-022 | High | jQuery .html() | `.html(userData)` | Use .text() or sanitize |
| INJ-023 | High | dangerouslySetInnerHTML | `dangerouslySetInnerHTML` | Sanitize with DOMPurify |
| INJ-024 | High | Vue v-html | `v-html="..."` | Use v-text or sanitize |
| INJ-025 | High | Unescaped Handlebars | `{{{...}}}` | Use `{{...}}` |
| INJ-030 | High | NoSQL object injection | `.find(req.body)` | Validate/whitelist fields |
| INJ-031 | High | NoSQL findOne injection | `.findOne(req.body)` | Validate/whitelist fields |
| INJ-032 | Critical | MongoDB $where | `$where` with user input | Avoid $where |

## Authentication Rules (AUTH-xxx)

| Rule ID | Severity | Description | Detection Pattern | Remediation |
|---------|----------|-------------|-------------------|-------------|
| AUTH-001 | High | MD5 password hashing | `hashlib.md5(` | Use bcrypt/Argon2 |
| AUTH-002 | High | SHA1 password hashing | `hashlib.sha1(` | Use bcrypt/Argon2 |
| AUTH-003 | High | Node MD5 | `createHash('md5')` | Use bcrypt |
| AUTH-004 | High | Node SHA1 | `createHash('sha1')` | Use bcrypt |
| AUTH-010 | High | Token in localStorage | `localStorage.setItem('token'` | Use HttpOnly cookies |
| AUTH-011 | High | Token in sessionStorage | `sessionStorage.setItem('token'` | Use HttpOnly cookies |
| AUTH-020 | Medium | Flask route without decorator | Route definition pattern | Verify auth requirement |
| AUTH-021 | Medium | Express route | Router handler pattern | Verify auth middleware |

## Cryptography Rules (CRYPTO-xxx)

| Rule ID | Severity | Description | Detection Pattern | Remediation |
|---------|----------|-------------|-------------------|-------------|
| CRYPTO-001 | High | DES encryption | `DES(` | Use AES-256 |
| CRYPTO-002 | High | Blowfish | `Blowfish(` | Use AES-256 |
| CRYPTO-003 | High | RC4 | `RC4(` | Use AES-256 |
| CRYPTO-010 | High | random for tokens | `random.randint(...token` | Use secrets module |
| CRYPTO-011 | High | Math.random for security | `Math.random()...token` | Use crypto.randomBytes |
| CRYPTO-012 | High | random.choice for secrets | `random.choice(...secret` | Use secrets.choice |

## Cloud/Infrastructure Rules (CLOUD-xxx)

| Rule ID | Severity | Description | Detection Pattern | Remediation |
|---------|----------|-------------|-------------------|-------------|
| CLOUD-001 | High | Firebase unvalidated write | `.ref("").set` | Add path validation |
| CLOUD-002 | Medium | Supabase anon key (info) | `createClient(...anon...` | Verify RLS is configured |
| CLOUD-003 | Critical | Supabase service key exposure | `service_role_key` | Server-side only |
| CLOUD-010 | High | CORS wildcard | `cors({ origin: '*' })` | Specify allowed origins |
| CLOUD-011 | High | CORS header wildcard | `Allow-Origin: *` | Specify allowed origins |
| CLOUD-012 | High | Manual CORS wildcard | `setHeader(..., '*')` | Specify allowed origins |
| CLOUD-020 | High | S3 public ACL | `ACL: 'public-read'` | Remove public access |
| CLOUD-021 | High | S3 public access | `BlockPublicAccess: false` | Enable block |

## Data Handling Rules (DATA-xxx)

| Rule ID | Severity | Description | Detection Pattern | Remediation |
|---------|----------|-------------|-------------------|-------------|
| DATA-001 | Critical | Unsafe pickle | `pickle.loads(` | Use JSON or validate source |
| DATA-002 | High | Unsafe YAML load | `yaml.load(` without Loader | Use yaml.safe_load |
| DATA-003 | High | Unsafe torch.load | `torch.load(` without weights_only | Add weights_only=True |
| DATA-010 | Medium | JSON from request | `json.loads(request...` | Add schema validation |

## Rule Severity Guide

| Severity | Action | Timeline |
|----------|--------|----------|
| Critical | Block deployment | Immediate |
| High | Fix before production | This sprint |
| Medium | Schedule fix | Next sprint |
| Low | Track as tech debt | Backlog |

## Using Rules in CI/CD

```yaml
# GitHub Actions
- name: Security Scan
  run: |
    python3 scripts/scan_security.py . --full --json > security-report.json
    python3 scripts/scan_security.py . --severity critical --fail-on-findings

# GitLab CI
security_scan:
  script:
    - python3 scripts/scan_security.py . --full --severity high --fail-on-findings
  allow_failure: false
```

## Custom Rules

To add custom rules, modify `scripts/scan_security.py`:

```python
# Add to SECRETS_PATTERNS, INJECTION_PATTERNS, etc.
CUSTOM_PATTERNS = [
    (r'your_pattern_regex', 'CUSTOM-001', 'Description'),
]
```