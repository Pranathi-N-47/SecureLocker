# SecureLocker

A Flask-based secure document management system demonstrating enterprise-grade security practices including hybrid encryption (AES + RSA), digital signatures, multi-factor authentication, and role-based access control.

## What This Project Demonstrates

### Core Security Concepts
- **Hybrid Encryption**: AES-256 (symmetric) + RSA-2048 (asymmetric)
- **Digital Signatures**: RSA-PSS for document authenticity verification
- **Multi-Factor Authentication**: Password + Time-based OTP
- **Role-Based Access Control**: Three-tier permission system
- **Security Auditing**: Complete access logging and audit trails
- **Input Validation**: Protection against injection and malicious uploads
- **Rate Limiting**: Brute force attack prevention

### Technologies & Security Features
- **Cryptography**: Python `cryptography` library for industry-standard encryption
- **Password Hashing**: PBKDF2-SHA256 with automatic salting
- **Session Management**: Secure Flask sessions with cryptographic signing
- **Database Security**: Encrypted data at rest, secure foreign key relationships
- **Configuration Management**: Environment-based secrets (never hardcoded)

## Quick Start (Local Development)

### Installation

1. **Clone and navigate to the repository**
   ```bash
   cd SecureLocker
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   venv\Scripts\activate    # Windows
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Generate secrets**
   ```bash
   python generate_secrets.py
   ```
   This creates a `.env` file with secure random secrets.

5. **Initialize database**
   ```bash
   python init_db.py
   ```

6. **Run the application**
   ```bash
   python app.py
   ```
   Access at `http://localhost:5000`

### Default Credentials

- **Admin**: username `admin`, password `admin123`
- **Access codes**: Check your `.env` file after running `generate_secrets.py`

## System Architecture

### User Roles & Permissions

| Role | Upload | View Own | View Public | View All | Download | Audit Logs |
|------|--------|----------|-------------|----------|----------|------------|
| **Student** | ✅ | ✅ | ❌ | ❌ | Own files | ❌ |
| **Verifier** | ❌ | ❌ | ✅ | ❌ | Public files | ❌ |
| **Admin** | ❌ | ❌ | ❌ | ✅ | All files | ✅ |

### Security Workflow

1. **Upload**: Student uploads certificate → AES-256 encryption → RSA-2048 key encryption → Digital signature generation
2. **Storage**: Encrypted data + encrypted key + signature stored in database
3. **Verification**: Verifier accesses public certificate → Decryption → Signature verification → VALID/TAMPERED status
4. **Auditing**: All actions logged with timestamp, user, and action details

## Project Structure

```
SecureLocker/
├── templates/              # HTML templates
│   ├── dashboard_*.html    # Role-specific dashboards
│   ├── login.html          # Authentication pages
│   └── register.html       # Real-time password validation
├── app.py                  # Main Flask application
├── models.py               # Database models (User, Certificate, AccessLog)
├── config.py               # Configuration management
├── security.py             # Security utilities & validation
├── init_db.py             # Database initialization
├── generate_secrets.py     # Secret generation utility
├── requirements.txt        # Python dependencies
├── .env.example           # Configuration template
└── SECURITY.md            # Security documentation
```

## Security Implementation Details

### Encryption (Hybrid AES + RSA)
- Files encrypted with AES-256-CBC (fast for large files)
- AES keys encrypted with RSA-2048-OAEP (secure key management)
- Initialization vectors (IV) for randomization
- PKCS7 padding for block alignment

### Digital Signatures
- SHA-256 hashing of file content
- RSA-PSS signature scheme
- Public key verification
- Tamper detection on every access

### Authentication & Authorization
- Password hashing with PBKDF2-SHA256
- Automatic salt generation
- 6-digit OTP with 5-minute expiration
- Maximum 3 OTP attempts before re-login required
- Account lockout after 5 failed login attempts

### Rate Limiting
- Login: 10 attempts/minute
- OTP: 5 attempts/minute
- Failed logins: 15-minute lockout after 5 attempts


## Technologies Used

- **Backend**: Flask 2.3.3, SQLAlchemy 3.0.5
- **Security**: cryptography 41.0.7, Flask-Login 0.6.3, Flask-Limiter 3.5.0
- **Database**: SQLite (file-based, portable)
- **Authentication**: Custom MFA with OTP
- **Frontend**: Bootstrap 5, Vanilla JavaScript (real-time validation)

## Key Files & Their Purpose

- **app.py**: Routes, authentication logic, file upload/download handlers
- **models.py**: Database schema with security considerations (indexes, cascades)
- **security.py**: Reusable security functions (validation, rate limiting, crypto helpers)
- **config.py**: Environment-based configuration (12-factor app pattern)
- **init_db.py**: Database setup with proper schema initialization

## Important Notes

⚠️ **Educational Project**: This is designed for learning and demonstration purposes. While it implements real security features correctly, it's optimized for educational clarity rather than enterprise scale.

🔐 **Key Management**: The RSA private key is critical - without it, encrypted data cannot be recovered. The key is encrypted with a passphrase from your `.env` file.

📊 **Database**: Uses SQLite for simplicity. All encryption happens before storage, so even raw database access reveals only encrypted data.

## Documentation

- **SECURITY.md**: Detailed security features, threat model, and best practices
- **Code Comments**: Extensive inline documentation explaining security decisions
- **.env.example**: Configuration template with explanations

## License

Educational project demonstrating cybersecurity concepts.

---

**Project Purpose**: Academic demonstration of secure application development practices and cryptographic implementation.

**Author**: Pranathi N  
**Repository**: [github.com/Pranathi-N-47/SecureLocker](https://github.com/Pranathi-N-47/SecureLocker)
