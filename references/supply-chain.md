# Supply Chain Security Reference

## Overview

**19.7% of AI-generated code references non-existent packages** (USENIX 2025)
**Only 20% of AI-suggested dependencies are safe** (Endor Labs)

## Package Hallucination ("Slopsquatting")

AI models frequently "hallucinate" package names that don't exist. Attackers register these names with malicious code.

### Known Hallucinated Packages

**Python (commonly invented by AI):**
- `huggingface-cli` (real: `huggingface-hub`)
- `flask-security-utils`
- `django-rest-utils`
- `pytorch-utils`
- `aws-sdk` (real: `boto3`)

**NPM (commonly invented by AI):**
- `react-utils`
- `vue-utils`
- `express-utils`
- `typescript-utils`

### Detection

Before installing any AI-suggested package:

```bash
# Python - verify on PyPI
pip index versions package-name
# Or visit: https://pypi.org/project/package-name/

# NPM - verify on npm
npm view package-name
# Or visit: https://www.npmjs.com/package/package-name
```

### Real-World Impact

**huggingface-cli proof-of-concept:** 30,000 downloads in 3 months. Alibaba included it in official documentation.

## Vulnerable Dependencies

### Common Vulnerable Packages

**Python:**
| Package | Vulnerable Versions | CVE |
|---------|--------------------|----|
| pyyaml | < 5.4 | CVE-2020-14343 |
| urllib3 | < 1.26.5 | CVE-2021-33503 |
| requests | < 2.31.0 | CVE-2023-32681 |
| pillow | < 10.0.1 | CVE-2023-44271 |
| django | < 4.2.4 | Multiple |

**NPM:**
| Package | Vulnerable Versions | CVE |
|---------|--------------------|----|
| lodash | < 4.17.21 | CVE-2021-23337 |
| axios | < 1.6.0 | SSRF |
| express | < 4.18.2 | Multiple |
| jsonwebtoken | < 9.0.0 | Multiple |
| mongoose | < 6.10.0 | Prototype pollution |

### Scanning Tools

```bash
# Python
pip-audit
safety check

# NPM
npm audit
yarn audit

# Multi-language
snyk test
```

## Malicious MCP Servers

**First malicious MCP server (September 2025):** `postmark-mcp` on npm had 1,643 downloads, silently BCCed all emails.

### Safe MCP Usage

1. Only use MCP servers from official vendors
2. Verify package is from official organization on npm/PyPI
3. Check GitHub repository ownership
4. Review server capabilities before enabling

## Version Pinning

### Bad Practices

```json
// package.json - BAD
{
  "dependencies": {
    "express": "*",
    "lodash": "latest",
    "axios": ""
  }
}
```

### Good Practices

```json
// package.json - GOOD
{
  "dependencies": {
    "express": "4.18.2",
    "lodash": "4.17.21",
    "axios": "1.6.0"
  }
}
```

```txt
# requirements.txt - GOOD
django==4.2.7
requests==2.31.0
pyyaml==6.0.1
```

## Dependency Lockfiles

Always commit lockfiles:
- `package-lock.json` (npm)
- `yarn.lock` (Yarn)
- `poetry.lock` (Python Poetry)
- `Pipfile.lock` (Pipenv)

## CI/CD Integration

```yaml
# GitHub Actions example
- name: Security audit
  run: |
    npm audit --audit-level=high
    # Or: pip-audit --strict
```

## Checklist

1. ✅ Verify every AI-suggested package exists before installing
2. ✅ Pin dependencies to specific versions
3. ✅ Commit lockfiles to version control
4. ✅ Run `npm audit` / `pip-audit` in CI/CD
5. ✅ Update dependencies regularly with security patches
6. ✅ Only use MCP servers from trusted sources
7. ✅ Review package download counts and maintainers