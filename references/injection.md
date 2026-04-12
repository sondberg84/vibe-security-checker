# Injection Vulnerabilities Reference

## Overview

Injection flaws are the most common AI-generated vulnerability. Veracode found:
- **86% failure rate** for XSS prevention
- **88% failure rate** for log injection
- **20% failure rate** for SQL injection

## SQL Injection (CWE-89)

### Detection Patterns

| Pattern | Rule ID | Risk |
|---------|---------|------|
| `execute(f"SELECT...")` | INJ-002 | F-string in SQL |
| `execute("..." + var)` | INJ-003 | String concatenation |
| `query(\`...${var}...\`)` | INJ-005 | Template literal |

### Examples

```python
# BAD - SQL Injection vulnerable
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
cursor.execute("SELECT * FROM users WHERE id = " + user_id)

# GOOD - Parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

```javascript
// BAD
db.query(`SELECT * FROM users WHERE id = ${userId}`);

// GOOD
db.query("SELECT * FROM users WHERE id = $1", [userId]);
```

## Command Injection (CWE-78)

### Detection Patterns

| Pattern | Rule ID | Risk |
|---------|---------|------|
| `os.system(...)` | INJ-010 | Direct shell execution |
| `subprocess.call(..., shell=True)` | INJ-011 | Shell interpolation |
| `child_process.exec(...)` | INJ-014 | Node.js shell execution |

### Examples

```python
# BAD - Command injection
os.system(f"convert {user_file} output.png")
subprocess.call(f"grep {pattern} file.txt", shell=True)

# GOOD - Safe subprocess
subprocess.run(["convert", user_file, "output.png"], check=True)
subprocess.run(["grep", pattern, "file.txt"], check=True)
```

## Cross-Site Scripting (CWE-79)

**86% of AI-generated code fails XSS prevention** (Veracode 2025)

### Detection Patterns

| Pattern | Rule ID | Risk |
|---------|---------|------|
| `innerHTML = var` | INJ-020 | DOM XSS |
| `document.write(...)` | INJ-021 | DOM XSS |
| `dangerouslySetInnerHTML` | INJ-023 | React XSS |
| `v-html="..."` | INJ-024 | Vue XSS |

### Examples

```javascript
// BAD - XSS vulnerable
element.innerHTML = userInput;
document.write(userData);

// GOOD - Safe alternatives
element.textContent = userInput;  // Escapes HTML
// Or use a sanitization library
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

```jsx
// BAD - React XSS
<div dangerouslySetInnerHTML={{__html: userContent}} />

// GOOD - Let React escape
<div>{userContent}</div>
// Or sanitize if HTML is required
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userContent)}} />
```

## Log Injection (CWE-117)

**88% failure rate** - worst-performing category

### Detection

```python
# BAD - Log injection
logger.info(f"User logged in: {username}")  # Can inject newlines, fake entries

# GOOD - Sanitized logging
logger.info("User logged in: %s", username.replace('\n', '\\n'))
```

## NoSQL Injection

### Detection Patterns

| Pattern | Rule ID | Risk |
|---------|---------|------|
| `.find(req.body)` | INJ-030 | Object injection |
| `$where` with user input | INJ-032 | Code execution |

### Examples

```javascript
// BAD - NoSQL injection
db.users.find(req.body);  // Attacker sends {$gt: ""}

// GOOD - Explicit field access
db.users.find({ 
  username: String(req.body.username),
  password: String(req.body.password)
});
```

## Remediation Checklist

1. ✅ Use parameterized queries for all database operations
2. ✅ Never use `shell=True` with subprocess
3. ✅ Use `textContent` instead of `innerHTML`
4. ✅ Sanitize all user input before logging
5. ✅ Validate input types before database queries
6. ✅ Use prepared statements in all languages