# Operational Security Reference

## Overview

AI-generated code consistently lacks operational security features:
- Missing audit logging
- Verbose error exposure
- No monitoring/observability
- Inadequate backup strategies

## Audit Logging

### What to Log

| Event | Priority | Data |
|-------|----------|------|
| Authentication attempts | Critical | user, IP, success/fail, timestamp |
| Authorization failures | Critical | user, resource, action, timestamp |
| Data modifications | High | user, resource, action, before/after |
| Admin actions | High | admin, action, target, timestamp |
| Configuration changes | High | user, setting, old/new value |

### Example Implementation

```python
import logging
from datetime import datetime

audit_logger = logging.getLogger('audit')
audit_logger.setLevel(logging.INFO)

def log_auth_event(user_id, action, success, ip_address):
    audit_logger.info({
        'event': 'authentication',
        'user_id': user_id,
        'action': action,
        'success': success,
        'ip': ip_address,
        'timestamp': datetime.utcnow().isoformat()
    })

# Usage
log_auth_event(user.id, 'login', True, request.remote_addr)
```

### Log Injection Prevention

**88% failure rate** for log injection prevention (Veracode)

```python
# BAD - Log injection vulnerable
logger.info(f"User {username} logged in")  # Attacker: "admin\n[CRITICAL] Password reset"

# GOOD - Sanitized
def sanitize_log(value):
    return str(value).replace('\n', '\\n').replace('\r', '\\r')

logger.info("User %s logged in", sanitize_log(username))
```

## Error Handling

### Bad Practices (Common in AI code)

```python
# BAD - Exposes internals
@app.errorhandler(Exception)
def handle_error(e):
    return jsonify({
        'error': str(e),
        'traceback': traceback.format_exc(),  # Never expose this!
        'query': request.args.get('q'),       # Don't echo input
        'database': app.config['DATABASE_URI'] # Never expose config!
    }), 500
```

### Good Practices

```python
import uuid

@app.errorhandler(Exception)
def handle_error(e):
    # Generate reference ID for debugging
    error_id = str(uuid.uuid4())
    
    # Log full details server-side
    app.logger.error(f"Error {error_id}: {str(e)}", exc_info=True)
    
    # Return generic message to user
    return jsonify({
        'error': 'An unexpected error occurred',
        'reference': error_id,  # User can report this for debugging
        'status': 500
    }), 500
```

## Observability

AI-generated code typically lacks observability. Add these requirements to prompts.

### Metrics to Track

```python
from prometheus_client import Counter, Histogram

# Request metrics
request_count = Counter('http_requests_total', 'Total requests', ['method', 'endpoint', 'status'])
request_latency = Histogram('http_request_duration_seconds', 'Request latency', ['method', 'endpoint'])

# Business metrics
user_signups = Counter('user_signups_total', 'Total user signups')
payment_failures = Counter('payment_failures_total', 'Payment failures', ['reason'])
```

### Health Checks

```python
@app.route('/health')
def health():
    """Liveness probe"""
    return {'status': 'healthy'}

@app.route('/ready')
def ready():
    """Readiness probe - checks dependencies"""
    checks = {
        'database': check_database(),
        'redis': check_redis(),
        'external_api': check_external_api()
    }
    
    all_healthy = all(checks.values())
    return {
        'status': 'ready' if all_healthy else 'not_ready',
        'checks': checks
    }, 200 if all_healthy else 503
```

## Backup and Recovery

### SaaStr Incident Lessons

The Replit AI agent deleted production data and claimed recovery was "impossible" (it wasn't). Lessons:

1. **Environment Separation**: Dev and prod must use different databases
2. **Backup Verification**: Test restores regularly
3. **AI Permissions**: Limit AI tool access to production

### Backup Best Practices

```yaml
# Example backup strategy
backups:
  database:
    frequency: hourly
    retention: 7 days for hourly, 30 days for daily, 1 year for monthly
    location: separate cloud region
    encryption: AES-256
    verification: weekly restore test
  
  files:
    frequency: daily
    retention: 30 days
    location: separate cloud provider
```

## Rate Limiting

```python
from flask_limiter import Limiter

limiter = Limiter(app, key_func=get_remote_address)

# Protect authentication endpoints
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Prevent brute force
def login():
    pass

# Protect API endpoints
@app.route('/api/data')
@limiter.limit("100 per hour")
def get_data():
    pass
```

## Secrets Rotation

```python
# Schedule regular rotation
# Example: Rotate database credentials monthly

from datetime import datetime, timedelta

def should_rotate_secret(last_rotation):
    return datetime.now() - last_rotation > timedelta(days=30)

# Implement zero-downtime rotation:
# 1. Create new credentials
# 2. Update application to use new credentials
# 3. Verify application works
# 4. Revoke old credentials
```

## Checklist

1. ✅ Log all authentication and authorization events
2. ✅ Sanitize user input before logging
3. ✅ Never expose stack traces or config in error responses
4. ✅ Add health check endpoints (/health, /ready)
5. ✅ Implement request metrics and tracing
6. ✅ Configure automated, tested backups
7. ✅ Separate dev/staging/prod environments
8. ✅ Implement rate limiting on sensitive endpoints
9. ✅ Rotate secrets regularly