# Cryptography Reference

## Overview

AI models are trained on older code and frequently suggest deprecated algorithms.

## Deprecated Algorithms

### Detection Patterns

| Pattern | Rule ID | Issue |
|---------|---------|-------|
| `DES()` | CRYPTO-001 | 56-bit key, trivially broken |
| `Blowfish()` | CRYPTO-002 | Deprecated, use AES |
| `RC4()` | CRYPTO-003 | Broken, biases in keystream |
| `MD5` for security | AUTH-001 | Collision attacks |
| `SHA1` for security | AUTH-002 | Collision attacks |

### Recommended Algorithms

| Use Case | Algorithm | Notes |
|----------|-----------|-------|
| Symmetric encryption | AES-256-GCM | Authenticated encryption |
| Password hashing | bcrypt, Argon2 | Memory-hard |
| General hashing | SHA-256+ | SHA-2 family |
| Key derivation | PBKDF2, scrypt | With high iterations |
| Signatures | Ed25519, ECDSA | Modern curves |

## Insecure Random

### Detection Patterns

| Pattern | Rule ID | Issue |
|---------|---------|-------|
| `random.randint()` for tokens | CRYPTO-010 | Predictable |
| `Math.random()` for security | CRYPTO-011 | Not cryptographic |
| `random.choice()` for secrets | CRYPTO-012 | Predictable |

### Examples

```python
# BAD - Predictable random
import random
token = ''.join(random.choices('abcdef0123456789', k=32))
session_id = random.randint(0, 999999999)

# GOOD - Cryptographically secure
import secrets
token = secrets.token_hex(32)
session_id = secrets.token_urlsafe(32)
```

```javascript
// BAD - Predictable
const token = Math.random().toString(36).slice(2);

// GOOD - Cryptographically secure
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('hex');
```

## Encryption Examples

### Python (cryptography library)

```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Simple symmetric encryption
key = Fernet.generate_key()
f = Fernet(key)
encrypted = f.encrypt(b"secret data")
decrypted = f.decrypt(encrypted)

# AES-256-GCM
key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)
nonce = os.urandom(12)
encrypted = aesgcm.encrypt(nonce, b"secret data", None)
```

### JavaScript (Node.js)

```javascript
const crypto = require('crypto');

// AES-256-GCM
function encrypt(text, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();
  return { iv: iv.toString('hex'), encrypted, authTag: authTag.toString('hex') };
}

function decrypt(encrypted, key, iv, authTag) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(authTag, 'hex'));
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}
```

## Key Management

### Bad Practices

```python
# BAD - Hardcoded key
ENCRYPTION_KEY = "my-secret-key-12345678901234567890"

# BAD - Key in code
key = b"0123456789abcdef0123456789abcdef"
```

### Good Practices

```python
# GOOD - Key from environment
import os
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")

# GOOD - Key from secrets manager
import boto3
client = boto3.client('secretsmanager')
key = client.get_secret_value(SecretId='encryption-key')['SecretString']
```

## Checklist

1. ✅ Never use MD5, SHA1, DES, RC4, Blowfish
2. ✅ Use AES-256-GCM for symmetric encryption
3. ✅ Use bcrypt/Argon2 for passwords
4. ✅ Use `secrets` module (Python) or `crypto.randomBytes` (Node) for tokens
5. ✅ Store keys in environment variables or secrets manager
6. ✅ Rotate encryption keys periodically
7. ✅ Use authenticated encryption (GCM mode)