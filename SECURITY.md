# Security Documentation - Educational Project

> **Note**: This document explains the security features implemented in this educational project. While these are real, production-grade security techniques, this application is designed for learning and demonstration rather than production deployment.

## Security Features Implemented

### 1. Hybrid Encryption (AES + RSA)

**Implementation**:
- **AES-256-CBC**: Encrypts file content (fast, efficient for large files)
  - 256-bit key (32 bytes of random data)
  - 128-bit IV (16 bytes) for randomization
  - PKCS7 padding for block alignment
  
- **RSA-2048-OAEP**: Encrypts the AES key (secure key exchange)
  - 2048-bit key size
  - OAEP padding with SHA-256
  - Public key encryption, private key decryption

**Why Hybrid?**
- AES is fast but requires shared secret keys
- RSA enables secure key distribution but is slow for large data
- Combined approach: "Best of both worlds"

**Code Location**: `app.py` (upload_file route), `security.py` (crypto helpers)

### 2. Digital Signatures (RSA-PSS)

**Implementation**:
- SHA-256 hash of file content
- RSA-PSS signature with private key
- Signature verification with public key
- PSS padding for security against attacks

**Purpose**:
- Proves document wasn't modified
- Proves signature by key holder (non-repudiation)
- Detects any tampering

**Verification Process**:
1. Decrypt file with RSA + AES
2. Hash decrypted content (SHA-256)
3. Verify signature matches hash using public key
4. Display VALID  or TAMPERED 

**Code Location**: `security.py` (create_digital_signature, verify_digital_signature)

### 3. Multi-Factor Authentication (MFA)

**Two-Factor Flow**:

1. **First Factor**: Password (something you know)
   - PBKDF2-SHA256 hashing
   - Automatic salt generation
   - Computationally expensive (slows brute force)
   
2. **Second Factor**: 6-digit OTP (simulated SMS)
   - Random code generated server-side
   - Displayed in console (simulates SMS delivery)
   - 5-minute expiration (configurable)
   - 3-attempt limit before lockout

**Security Benefits**:
- Compromised password alone isn't sufficient
- Time-limited codes prevent replay attacks
- Attempt limits prevent brute force

**Code Location**: `app.py` (login, verify_otp routes), `security.py` (is_otp_expired)

### 4. Password Security

**Hashing**: PBKDF2-SHA256
- Industry-standard algorithm
- Automatic salt generation (prevents rainbow tables)
- Configurable iterations (computationally expensive)
- One-way function (can't reverse to get password)

**Requirements Enforced**:
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number

**Real-time Validation**: JavaScript checks requirements as user types (UX improvement)

**Code Location**: `security.py` (validate_password), `templates/register.html` (client-side validation)

### 5. Rate Limiting

**Implemented Limits**:

| Action | Limit | Lockout |
|--------|-------|---------|
| Login attempts | 10/minute | Account lockout after 5 failures (15 min) |
| OTP verification | 5/minute | New login required after 3 failures |
| Failed logins | 5 total | 15-minute account lockout |

**How It Works**:
- Flask-Limiter for IP-based rate limiting
- Database tracking for account-specific limits
- Automatic reset on successful authentication

**Code Location**: `security.py` (check_rate_limit, limiter setup), `app.py` (route decorators)

### 6. Role-Based Access Control (RBAC)

**Three Roles with Different Permissions**:

| Action | Student | Verifier | Admin |
|--------|---------|----------|-------|
| Upload certificates | ✅ | ❌ | ❌ |
| View own certificates | ✅ | ❌ | ❌ |
| View public certificates | ❌ | ✅ | ✅ |
| View all certificates | ❌ | ❌ | ✅ |
| Download own files | ✅ | ❌ | ❌ |
| Download public files | ❌ | ✅ | ✅ |
| Download all files | ❌ | ❌ | ✅ |
| View audit logs | ❌ | ❌ | ✅ |

**Authorization Checks**:
- Every route validates user permissions
- Certificate visibility enforced (public vs private)
- Owner-only operations (delete, toggle visibility)

**Code Location**: `app.py` (authorization checks in all routes)

### 7. Security Auditing

**What's Logged**:
- User registration
- Login attempts (success and failure)
- OTP verification (success and failure)
- Certificate uploads
- Certificate verifications
- File downloads
- Visibility changes
- Deletions
- Access denials

**Log Contents**:
- User ID (who)
- Action description (what)
- Timestamp (when)
- Indexed for efficient querying

**Admin Access**: Complete audit trail viewable in admin dashboard

**Code Location**: `security.py` (log_access), `models.py` (AccessLog model)

### 8. Input Validation

**File Upload Validation**:
- Type whitelist (pdf, png, jpg, jpeg, doc, docx)
- Size limit (10MB default, configurable)
- Filename sanitization (prevents path traversal)
- Content presence check

**User Input Validation**:
- Username: 3-50 chars, alphanumeric + underscore only
- Password: Complexity requirements (client + server side)
- Access codes: Exact match required
- All inputs sanitized before database storage

**Code Location**: `security.py` (validation functions), `templates/register.html` (client-side)

### 9. Key Management

**RSA Private Key**:
- Encrypted on disk with passphrase
- Passphrase stored in environment variable (`.env`)
- Uses `BestAvailableEncryption` algorithm
- Never exposed in plaintext

**Key Generation**:
- Automatic on first run
- 2048-bit RSA keys
- Persistent across restarts
- **Critical**: Loss of private key = permanent data loss

**Security Consideration**: In a real system, keys would be stored in a Hardware Security Module (HSM) or key management service.

**Code Location**: `app.py` (key loading/generation)

## Threat Model (Educational Analysis)

### What This Project Protects Against

 **Password Attacks**
- Hashing prevents password recovery from database
- Rate limiting prevents brute force
- Account lockout after multiple failures

 **Session Hijacking**
- Cryptographically signed cookies (Flask secret key)
- HTTPOnly flag prevents XSS cookie theft
- Server-side session validation

 **Unauthorized Access**
- Role-based access control
- Certificate visibility enforcement
- Owner verification on all operations

 **Data Tampering**
- Digital signatures detect any modification
- Signature verification on every access
- Clear TAMPERED status displayed

 **MFA Bypass**
- OTP required after password
- OTP expiration prevents replay
- Attempt limits prevent brute force of OTP

 **Malicious File Uploads**
- File type validation
- Size limits
- Filename sanitization

### Known Limitations (Educational Awareness)

 **Key Compromise**
- If private RSA key is leaked, all encrypted data is accessible
- Mitigation: Keep key encrypted, secure backups
- Real-world: Use HSM or cloud key management

 **Database Access**
- Physical access to database + private key = full access
- Mitigation: Disk encryption, physical security
- Real-world: Encrypted file systems, secure hosting

 **Side-Channel Attacks**
- Timing attacks not specifically mitigated
- Mitigation: Use constant-time comparisons
- Real-world: Hardware-level protections

 **Denial of Service**
- Rate limiting helps but not DDoS-proof
- Mitigation: Basic rate limiting implemented
- Real-world: CDN, DDoS mitigation services

 **CSRF**
- Not fully implemented
- Mitigation: Add CSRF tokens for state changes
- Educational: Left as potential enhancement

## Security Best Practices Demonstrated

### Development Practices
1. **No hardcoded secrets**: All secrets in environment variables
2. **Secrets in .gitignore**: Private keys and .env never committed
3. **Principle of least privilege**: Role-based restrictions
4. **Defense in depth**: Multiple security layers
5. **Secure defaults**: Private visibility, strong encryption

### Cryptography Practices
1. **Industry-standard algorithms**: AES-256, RSA-2048, SHA-256
2. **Proper padding**: OAEP for RSA, PKCS7 for AES
3. **Random IVs**: Different IV for each encryption
4. **Key encryption**: Private key encrypted with passphrase
5. **Signature verification**: Every access validates integrity

### Authentication Practices
1. **Strong password hashing**: PBKDF2-SHA256
2. **Automatic salts**: Each password has unique salt
3. **Multi-factor authentication**: Password + OTP
4. **Rate limiting**: Brute force prevention
5. **Session security**: Cryptographic signing