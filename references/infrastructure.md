# Infrastructure Security Reference

## Overview

**20% of vibe-coded apps have serious cloud misconfigurations** (Wiz)

## Firebase Misconfigurations

### Detection Patterns

| Pattern | Rule ID | Issue |
|---------|---------|-------|
| Open database rules | CLOUD-001 | Anyone can read/write |
| Public storage bucket | CLOUD-020 | Data exposure |

### Tea App Breach (July 2025)

Firebase database and storage bucket were completely open, exposing:
- 72,000 user images (13,000 government IDs)
- 1.1 million direct messages
- Personal information leading to 4chan harassment

### Secure Firebase Rules

```javascript
// BAD - Completely open
{
  "rules": {
    ".read": true,
    ".write": true
  }
}

// GOOD - Authenticated and authorized
{
  "rules": {
    "users": {
      "$uid": {
        ".read": "$uid === auth.uid",
        ".write": "$uid === auth.uid"
      }
    }
  }
}
```

### Firebase Storage Rules

```javascript
// BAD - Public bucket
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /{allPaths=**} {
      allow read, write: if true;
    }
  }
}

// GOOD - User-specific access
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /users/{userId}/{allPaths=**} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
```

## Supabase Security

### Row-Level Security (RLS)

**CVE-2025-48757:** 170 Lovable apps exposed due to missing RLS.

```sql
-- CRITICAL: Enable RLS on every table
ALTER TABLE your_table ENABLE ROW LEVEL SECURITY;

-- Create policies for each operation
CREATE POLICY "Users can view own data"
  ON your_table FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own data"
  ON your_table FOR INSERT
  WITH CHECK (auth.uid() = user_id);
```

### Supabase Key Security

| Key Type | Safe Location | Notes |
|----------|--------------|-------|
| anon key | Frontend OK | Limited by RLS |
| service_role key | Server only! | Bypasses RLS |

```javascript
// BAD - Service role in frontend
const supabase = createClient(url, 'eyJ...service_role_key...');

// GOOD - Anon key in frontend, service role only on server
// Frontend:
const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY);

// Server only:
const supabaseAdmin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);
```

## CORS Misconfigurations

### Detection Patterns

| Pattern | Rule ID | Issue |
|---------|---------|-------|
| `origin: '*'` | CLOUD-010 | Allows any origin |
| `Access-Control-Allow-Origin: *` | CLOUD-011 | Same |

### Secure CORS

```javascript
// BAD
app.use(cors({ origin: '*' }));

// GOOD - Explicit origins
app.use(cors({
  origin: ['https://yourdomain.com', 'https://app.yourdomain.com'],
  credentials: true
}));

// Or dynamic validation
app.use(cors({
  origin: function(origin, callback) {
    const allowed = ['https://yourdomain.com'];
    if (!origin || allowed.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('CORS not allowed'));
    }
  }
}));
```

## AWS S3 Security

### Detection Patterns

| Pattern | Rule ID | Issue |
|---------|---------|-------|
| `ACL: 'public-read'` | CLOUD-020 | Public bucket |
| `BlockPublicAccess: false` | CLOUD-021 | Public access enabled |

### Secure S3 Configuration

```javascript
// GOOD - Block public access
const bucket = new s3.Bucket(this, 'MyBucket', {
  blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
  encryption: s3.BucketEncryption.S3_MANAGED,
  enforceSSL: true,
});
```

## Environment Separation

### SaaStr Incident (July 2025)

Replit AI agent deleted production database because:
- No separation between dev and prod environments
- AI had direct production database access
- No environment-specific credentials

### Best Practices

```bash
# Separate environment files
.env.development
.env.staging
.env.production

# Never share credentials across environments
# Use different database instances for each environment
```

## Security Headers

```javascript
// Express.js security headers
const helmet = require('helmet');
app.use(helmet());

// Or manual configuration
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  next();
});
```

## Checklist

1. ✅ Enable and properly configure Firebase/Supabase security rules
2. ✅ Never expose service role keys in frontend
3. ✅ Configure CORS with explicit allowed origins
4. ✅ Block public access on S3/storage buckets
5. ✅ Separate development and production environments
6. ✅ Use security headers (helmet.js or equivalent)
7. ✅ Enable HTTPS everywhere
8. ✅ Audit cloud configurations regularly