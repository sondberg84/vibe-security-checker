# Authentication & Authorization Reference

## Overview

AI-generated authentication code frequently:
- Uses weak hashing algorithms (MD5, SHA1)
- Stores tokens insecurely (localStorage)
- Checks authentication but not authorization
- Misses RLS policies on database tables

## Weak Password Hashing

### Detection Patterns

| Pattern | Rule ID | Issue |
|---------|---------|-------|
| `hashlib.md5()` | AUTH-001 | MD5 is broken |
| `hashlib.sha1()` | AUTH-002 | SHA1 is deprecated |
| `crypto.createHash('md5')` | AUTH-003 | Node MD5 |
| `crypto.createHash('sha1')` | AUTH-004 | Node SHA1 |

### Remediation

```python
# BAD
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()

# GOOD
import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Or use Argon2
from argon2 import PasswordHasher
ph = PasswordHasher()
password_hash = ph.hash(password)
```

```javascript
// BAD
const hash = crypto.createHash('md5').update(password).digest('hex');

// GOOD
const bcrypt = require('bcrypt');
const hash = await bcrypt.hash(password, 10);
```

## Token Storage

### Detection Patterns

| Pattern | Rule ID | Issue |
|---------|---------|-------|
| `localStorage.setItem('token',...)` | AUTH-010 | XSS can steal tokens |
| `sessionStorage.setItem('token',...)` | AUTH-011 | Same issue |

### Remediation

```javascript
// BAD - Vulnerable to XSS
localStorage.setItem('jwt', token);

// GOOD - HttpOnly cookie (set by server)
// Server response:
res.cookie('jwt', token, {
  httpOnly: true,    // JavaScript can't access
  secure: true,      // HTTPS only
  sameSite: 'strict' // CSRF protection
});
```

## Missing Authorization (IDOR)

AI code often checks authentication but not ownership:

```python
# BAD - Checks auth but not ownership
@app.route('/api/document/<id>')
@login_required
def get_document(id):
    return Document.query.get(id)  # Any authenticated user can access any doc

# GOOD - Validates ownership
@app.route('/api/document/<id>')
@login_required
def get_document(id):
    doc = Document.query.get(id)
    if doc.owner_id != current_user.id:
        abort(403)
    return doc
```

## Row-Level Security (RLS)

**CVE-2025-48757**: 170 Lovable apps exposed due to missing/incorrect RLS.

### Supabase RLS

```sql
-- Enable RLS on table
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

-- BAD: Policy exists but allows all
CREATE POLICY "allow_all" ON documents FOR ALL USING (true);

-- GOOD: Proper authorization check
CREATE POLICY "users_own_documents" ON documents 
  FOR ALL 
  USING (auth.uid() = user_id);

-- For public read, private write
CREATE POLICY "public_read" ON documents FOR SELECT USING (true);
CREATE POLICY "owner_write" ON documents FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "owner_update" ON documents FOR UPDATE USING (auth.uid() = user_id);
CREATE POLICY "owner_delete" ON documents FOR DELETE USING (auth.uid() = user_id);
```

### Firebase Rules

```javascript
// BAD - Open database
{
  "rules": {
    ".read": true,
    ".write": true
  }
}

// GOOD - User-specific access
{
  "rules": {
    "users": {
      "$uid": {
        ".read": "$uid === auth.uid",
        ".write": "$uid === auth.uid"
      }
    },
    "documents": {
      "$docId": {
        ".read": "data.child('ownerId').val() === auth.uid",
        ".write": "data.child('ownerId').val() === auth.uid"
      }
    }
  }
}
```

## Session Management

```python
# Secure session configuration
app.config.update(
    SESSION_COOKIE_SECURE=True,      # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,    # No JS access
    SESSION_COOKIE_SAMESITE='Lax',   # CSRF protection
    PERMANENT_SESSION_LIFETIME=3600   # 1 hour timeout
)
```

## Checklist

1. ✅ Use bcrypt or Argon2 for password hashing
2. ✅ Store tokens in HttpOnly cookies, not localStorage
3. ✅ Check resource ownership, not just authentication
4. ✅ Enable and properly configure RLS on all tables
5. ✅ Set secure session cookie attributes
6. ✅ Implement rate limiting on auth endpoints
7. ✅ Use HTTPS everywhere