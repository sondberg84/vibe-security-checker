# Secrets and Credentials Reference

## Overview

AI-generated code frequently contains hardcoded secrets. Veracode found AI models use "common secrets that they reuse repeatedly."

## Common AI-Generated Secrets

These appear in 20%+ of vibe-coded projects:

| Secret | Context | Detection |
|--------|---------|-----------|
| `your-256-bit-secret` | JWT signing | SEC-007 |
| `secret` | Generic secret value | SEC-008 |
| `password123` | Test passwords | SEC-009 |
| `admin@example.com` | Test credentials | SEC-010 |
| `changeme` | Placeholder passwords | SEC-011 |

## API Key Patterns

| Pattern | Service | Rule ID |
|---------|---------|---------|
| `sk-live-*`, `pk-live-*` | Stripe | SEC-001 |
| `AIza*` | Google | SEC-002 |
| `AKIA*` | AWS | SEC-003 |
| `ghp_*` | GitHub | SEC-004 |
| `xox[baprs]-*` | Slack | SEC-005 |

## Detection Rules

**SEC-001 to SEC-006**: API key patterns in string literals
**SEC-007 to SEC-011**: Common AI placeholder secrets  
**SEC-012**: Password assignments in code
**SEC-013**: Hardcoded API keys
**SEC-014 to SEC-016**: Database connection strings with credentials

## Remediation

### Environment Variables
```python
# BAD
api_key = "sk-live-abc123..."

# GOOD
import os
api_key = os.environ.get("STRIPE_API_KEY")
```

### Secrets Management
- **Development**: `.env` files (gitignored)
- **Production**: AWS Secrets Manager, HashiCorp Vault, Doppler
- **CI/CD**: GitHub Secrets, GitLab CI variables

### Pre-commit Hooks
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
```

## Real-World Incidents

**Enrichlead (March 2025)**: Hardcoded API keys in frontend bundle led to complete shutdown.

**Tea App (July 2025)**: Firebase credentials in client-side code contributed to 72,000 image breach.