# Security Documentation

## Security Features

### 1. Hybrid Encryption (AES + RSA)

**Implementation**: Combined symmetric and asymmetric encryption

- **AES-256 (CBC mode)**: Encrypts file content
  - 256-bit key (32 bytes of random data)
  - 128-bit IV (16 bytes of random data)
  - PKCS7 padding for block alignment
  
- **RSA-2048 (OAEP padding)**: Encrypts AES key
  - 2048-bit key size
  - OAEP padding with SHA-256
  - Public key for encryption, private key for decryption

**Why Hybrid?**
- AES is fast for large files
- RSA provides secure key exchange
- Best of both worlds: speed + security

### 2. Digital Signatures (RSA-PSS)

**Implementation**: RSA signature with PSS padding

- SHA-256 hash of file content
- RSA-PSS signature with private key
- Signature verification with public key

**Purpose**:
- Proves document authenticity
- Detects tampering
- Non-repudiation (can't deny signing)

**Verification Process**:
1. Decrypt file
2. Hash decrypted content
3. Verify signature matches hash
4. Display VALID or TAMPERED status

### 3. Multi-Factor Authentication

**Two-Factor Flow**:

1. **First Factor**: Username + Password
   - Password hashed with PBKDF2-SHA256
   - Automatic salting
   
2. **Second Factor**: 6-digit OTP
   - Random code generated server-side
   - Displayed in console (simulates SMS)
   - Expires after 5 minutes (configurable)
   - Maximum 3 attempts before lockout

### 4. Password Security

**Hashing**: PBKDF2-SHA256
- Industry-standard algorithm
- Automatic salt generation
- Computationally expensive (slows brute force)

**Requirements**:
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number

**Storage**: Only hashes stored, never plaintext

### 5. Rate Limiting

**Login Protection**:
- 10 login attempts per minute per IP
- 5 failed attempts per account → 15-minute lockout
- Automatic reset on successful login

**OTP Protection**:
- 5 OTP attempts per minute per IP
- 3 failed attempts → require new login
- Prevents OTP brute force (1M combinations)

### 6. Access Control

**Role-Based Authorization**:

| Role | Can Upload | View Own | View Public | View All | Download |
|------|-----------|----------|-------------|----------|----------|
| **Student** | ✅ | ✅ | ❌ | ❌ | Own files |
| **Verifier** | ❌ | ❌ | ✅ | ❌ | Public files |
| **Admin** | ❌ | ❌ | ❌ | ✅ | All files |

**Authorization Checks**:
- Every route validates user permissions
- Certificate visibility enforced (public/private)
- Owner-only operations (delete, toggle visibility)

### 7. Audit Logging

**Logged Actions**:
- User registration
- Login attempts (success/failure)
- OTP verification (success/failure)
- Certificate uploads
- Certificate verification
- Downloads
- Visibility changes
- Deletions
- Access denials

**Log Contents**:
- User ID
- Action description
- Timestamp
- Indexed for efficient querying

### 8. Session Security

**Flask Sessions**:
- Cryptographically signed with `SECRET_KEY`
- Cannot be forged without key
- Secure cookie attributes (HTTPOnly, Secure in production)

**OTP Session**:
- Temporary storage in session
- Expiration timestamp checked
- Attempt counter to prevent brute force
- Automatic cleanup on success/failure

### 9. Input Validation

**File Uploads**:
- Type whitelist (pdf, png, jpg, jpeg, doc, docx)
- Size limit (10MB default)
- Filename sanitization (prevent path traversal)
- Content validation

**User Input**:
- Username: 3-50 chars, alphanumeric + underscore
- Password: Strength requirements enforced
- Access codes: Exact match required

### 10. Key Management

**RSA Private Key**:
- Encrypted on disk with passphrase
- Passphrase from environment variable
- Uses BestAvailableEncryption algorithm
- Never stored unencrypted

**Key Generation**:
- Automatic on first run
- 2048-bit RSA keys
- Persistent across restarts
- Backup required for disaster recovery

## Threat Model

### Protected Against

✅ **Password Attacks**
- Hashing prevents password recovery
- Rate limiting prevents brute force
- Account lockout after failed attempts

✅ **Session Hijacking**
- Signed cookies prevent forgery
- HTTPOnly flag prevents XSS cookie theft
- Secure flag for HTTPS-only transmission

✅ **Unauthorized Access**
- Role-based access control
- Certificate visibility enforcement
- Owner verification on all operations

✅ **Data Tampering**
- Digital signatures detect modifications
- Signature verification on every access
- Clear TAMPERED status display

✅ **MFA Bypass**
- OTP required after password
- OTP expiration prevents replay
- Attempt limits prevent brute force

✅ **Malicious File Uploads**
- Type validation
- Size limits
- Filename sanitization

### Limitations

⚠️ **Key Compromise**
- If private key leaked, all data decryptable
- Requires secure backup and storage
- No key rotation implemented yet

⚠️ **Physical Access**
- Database file contains encrypted data
- If attacker has database + private key = compromise
- Disk encryption recommended

⚠️ **Side-Channel Attacks**
- Timing attacks not specifically mitigated
- Consider constant-time comparisons for production

⚠️ **Denial of Service**
- Rate limiting helps but not DDoS-proof
- Use reverse proxy with DDoS protection

⚠️ **CSRF (Partially)**
- Not fully implemented
- Should add CSRF tokens for state-changing requests

## Security Best Practices

### Deployment

1. **Use HTTPS**: Encrypt all traffic
2. **Reverse Proxy**: Hide Flask behind Nginx/Apache
3. **Firewall**: Restrict access to necessary ports
4. **Updates**: Keep dependencies up to date
5. **Monitoring**: Watch access logs for suspicious activity

### Secrets Management

1. **Never commit**:
   - `.env` file
   - `private_key.pem`
   - `public_key.pem`
   - Database files

2. **Use strong secrets**:
   - `SECRET_KEY`: 32+ random characters
   - `RSA_KEY_PASSPHRASE`: 32+ random characters
   - Change all default access codes

3. **Backup securely**:
   - Private key must be backed up
   - Encrypt backups
   - Store offsite

### Key Rotation

**When to rotate**:
- Suspected compromise
- Employee departure
- Regular schedule (annually)

**How to rotate** (manual process):
1. Backup all certificates
2. Decrypt with old key
3. Generate new key pair
4. Re-encrypt with new key
5. Update database
6. Destroy old key securely

### Incident Response

**If private key compromised**:
1. Immediately generate new key pair
2. Notify all users
3. Re-encrypt all certificates
4. Investigate breach source
5. Review access logs

**If database compromised**:
- Data is encrypted (safe if key not compromised)
- Signatures prevent undetected tampering
- Access logs show who accessed what

**If `SECRET_KEY` compromised**:
1. Generate new secret key
2. All sessions invalidated
3. Users must re-login
4. Investigate source of leak

## Compliance Considerations

**Data Protection**:
- Encryption at rest (AES-256)
- Access control (RBAC)
- Audit logging (complete trail)
- User consent (role-based registration)

**Authentication**:
- Multi-factor authentication
- Password complexity requirements
- Rate limiting and lockouts

**Integrity**:
- Digital signatures
- Tamper detection
- Verification workflow

## Security Checklist

### Before Production

- [ ] Change all default passwords
- [ ] Set strong `SECRET_KEY` (32+ chars)
- [ ] Set strong `RSA_KEY_PASSPHRASE` (32+ chars)
- [ ] Change all access codes
- [ ] Set `DEBUG=False`
- [ ] Enable HTTPS
- [ ] Configure firewall
- [ ] Set up backup system
- [ ] Test disaster recovery
- [ ] Review access logs
- [ ] Implement CSRF tokens
- [ ] Add content security policy
- [ ] Enable security headers
- [ ] Perform penetration testing

### Regular Maintenance

- [ ] Monitor access logs weekly
- [ ] Review user accounts monthly
- [ ] Update dependencies quarterly
- [ ] Backup database daily
- [ ] Test recovery procedures quarterly
- [ ] Rotate keys annually
- [ ] Security audit annually

## Vulnerability Reporting

If you discover a security vulnerability:

1. **DO NOT** create a public issue
2. Email security details privately
3. Include steps to reproduce
4. Allow reasonable time for fix
5. Coordinate disclosure timeline

---

**Last Updated**: 2026-01-25
**Security Version**: 2.0 (After security overhaul)
