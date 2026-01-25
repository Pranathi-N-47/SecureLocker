# SecureLocker - Secure Document Management System

A Flask-based secure document management system with hybrid encryption (AES + RSA), digital signatures, multi-factor authentication, and role-based access control.

## Features

- **Hybrid Encryption**: AES-256 for file encryption + RSA-2048 for key encryption
- **Digital Signatures**: RSA-PSS signatures for document authenticity verification
- **Multi-Factor Authentication (MFA)**: OTP-based second factor with expiration
- **Role-Based Access Control**: Three roles (Student, Verifier, Admin) with different permissions
- **Secure Storage**: Encrypted RSA private keys, hashed passwords with salt
- **Rate Limiting**: Protection against brute force attacks
- **Access Logging**: Complete audit trail of all actions
- **QR Code Integration**: Easy certificate verification via QR codes

## Quick Start

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Installation

1. **Clone the repository**
   ```bash
   cd SecureLocker
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   
   # Windows
   venv\Scripts\activate
   
   # macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   
   Copy `.env.example` to `.env`:
   ```bash
   copy .env.example .env    # Windows
   cp .env.example .env      # macOS/Linux
   ```
   
   Edit `.env` and set secure values:
   ```bash
   # Generate a secure secret key
   python -c "import secrets; print(secrets.token_hex(32))"
   
   # Use this output for SECRET_KEY in .env
   ```
   
   **IMPORTANT**: Change ALL default values in `.env`, especially:
   - `SECRET_KEY`
   - `RSA_KEY_PASSPHRASE`
   - Access codes for each role

5. **Run the application**
   ```bash
   python app.py
   ```
   
   The application will be available at `http://localhost:5000`

### Default Admin Account

- **Username**: `admin`
- **Password**: `admin123`
- **⚠️ CHANGE THIS PASSWORD IMMEDIATELY IN PRODUCTION**

## Usage

### Student Workflow

1. Register with student access code
2. Login with username and password
3. Enter OTP (displayed in console)
4. Upload encrypted certificates
5. Toggle visibility (public/private)
6. Generate QR codes for verification

### Verifier Workflow

1. Register with verifier access code
2. View public certificates
3. Scan QR codes to verify authenticity
4. Download and verify signatures

### Admin Workflow

1. Login as admin
2. View all certificates
3. Monitor access logs
4. Manage system security

## Security Configuration

### Password Requirements

- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number

### Rate Limiting

- Login: 10 attempts per minute
- OTP verification: 5 attempts per minute
- Failed logins: 5 attempts before 15-minute lockout
- OTP attempts: 3 attempts before requiring re-login

### File Upload Limits

- Maximum file size: 10MB (configurable in `.env`)
- Allowed extensions: pdf, png, jpg, jpeg, doc, docx (configurable in `.env`)

## Environment Variables

See `.env.example` for all available configuration options:

- **Security**: `SECRET_KEY`, `RSA_KEY_PASSPHRASE`
- **Access Control**: `STUDENT_ACCESS_CODE`, `VERIFIER_ACCESS_CODE`, `ADMIN_ACCESS_CODE`
- **MFA Settings**: `OTP_EXPIRATION_SECONDS`, `OTP_MAX_ATTEMPTS`
- **Rate Limiting**: `MAX_LOGIN_ATTEMPTS`, `LOGIN_LOCKOUT_DURATION`
- **File Upload**: `MAX_FILE_SIZE`, `ALLOWED_EXTENSIONS`
- **Flask Settings**: `DEBUG`, `FLASK_HOST`, `FLASK_PORT`

## Final Project Structure

```
SecureLocker/
│
├── templates/               # HTML templates (Flask views)
│   ├── base.html               # Base template with navbar
│   ├── dashboard_admin.html    # Admin panel with tabs (certs + logs)
│   ├── dashboard_student.html  # Student dashboard (upload & manage)
│   ├── dashboard_verifier.html # Verifier portal (verify public certs)
│   ├── login.html              # Login page
│   ├── otp.html                # OTP verification (MFA)
│   ├── register.html           # Registration with real-time validation
│   ├── upload.html             # File upload form
│   └── verify_result.html      # Certificate verification result
│
├── instance/                # Database storage (gitignored)
│   └── locker.db               # SQLite database (if using instance path)
│
├── venv/                    # Virtual environment (gitignored)
│
├── __pycache__/             # Python cache (gitignored)
│
├── app.py                   # Main Flask application (routes + MFA)
├── models.py                # Database models (User, Certificate, AccessLog)
├── config.py                # Configuration management (loads .env)
├── security.py              # Security utilities (validation, rate limiting, crypto)
│
├── init_db.py               # Database initialization script
├── generate_secrets.py      # Generates random secrets for .env
│
├── private_key.pem          # RSA private key (gitignored, ENCRYPTED)
├── public_key.pem           # RSA public key (gitignored)
│
├── locker.db                # SQLite database (gitignored, in project root)
│
├── .env                      # Environment variables (gitignored, SECRETS)
├── .env.example             # Template for .env (committed)
├── .gitignore               # Git ignore rules
│
├── requirements.txt         # Python dependencies
│
├── README.md                # Setup guide & documentation
└── SECURITY.md              # Security features & best practices
```

## Key Management

### RSA Keys

- Generated automatically on first run
- Private key encrypted with passphrase from `.env`
- Stored in `private_key.pem` and `public_key.pem`
- **CRITICAL**: Backup `private_key.pem` - loss means permanent data loss!

### Key Rotation

Currently, key rotation requires:
1. Backup all existing certificates
2. Decrypt with old key
3. Generate new keys
4. Re-encrypt with new key

## Troubleshooting

### "Decryption Failed" error
- Private key passphrase may have changed
- Database was created with different keys
- Solution: Delete database and start fresh (loses all data)

### "OTP has expired"
- OTP valid for 5 minutes (default)
- Increase `OTP_EXPIRATION_SECONDS` in `.env` if needed

### "Account temporarily locked"
- Too many failed login attempts
- Wait for lockout duration (default: 15 minutes)
- Or reset `failed_login_attempts` in database

### Database errors after model changes
- Delete `instance/locker.db` to recreate
- Or use Flask-Migrate for proper migrations (coming soon)

## License

Educational project for cybersecurity demonstrations.

## Support

For issues and questions, please check the documentation files:
- `SECURITY.md` - Security features and threat model
- `implementation_plan.md` - Technical implementation details

---

**⚠️ IMPORTANT**: This system is designed for educational purposes. Ensure proper security review before production deployment.
