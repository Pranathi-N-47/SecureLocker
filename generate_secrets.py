"""
Generate secure random secrets for SecureLocker .env file
Writes directly to .env file with proper UTF-8 encoding
"""
import secrets
import os

# Generate secrets
secret_key = secrets.token_hex(32)
rsa_passphrase = secrets.token_hex(32)
student_code = secrets.token_urlsafe(16)
verifier_code = secrets.token_urlsafe(16)
admin_code = secrets.token_urlsafe(16)

# Build .env content
env_content = f"""# SecureLocker Environment Variables
# Generated on: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

# Flask Secret Key - Used to sign session cookies
SECRET_KEY={secret_key}

# RSA Private Key Passphrase - Encrypts the private key on disk
RSA_KEY_PASSPHRASE={rsa_passphrase}

# Registration Access Codes
STUDENT_ACCESS_CODE={student_code}
VERIFIER_ACCESS_CODE={verifier_code}
ADMIN_ACCESS_CODE={admin_code}

# Database Configuration
DATABASE_URI=sqlite:///instance/locker.db

# Security Settings
OTP_EXPIRATION_SECONDS=300
OTP_MAX_ATTEMPTS=3
MAX_LOGIN_ATTEMPTS=5
LOGIN_LOCKOUT_DURATION=900

# File Upload Settings
MAX_FILE_SIZE=10485760
ALLOWED_EXTENSIONS=pdf,png,jpg,jpeg,doc,docx

# Flask Runtime Settings
DEBUG=True
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
"""

# Write to .env file with UTF-8 encoding
env_path = os.path.join(os.path.dirname(__file__), '.env')
with open(env_path, 'w', encoding='utf-8') as f:
    f.write(env_content)

print("✓ .env file created successfully!")
print("\nGenerated secrets:")
print(f"  SECRET_KEY: {secret_key[:16]}... (64 chars)")
print(f"  RSA_KEY_PASSPHRASE: {rsa_passphrase[:16]}... (64 chars)")
print(f"\nAccess Codes:")
print(f"  Student: {student_code}")
print(f"  Verifier: {verifier_code}")
print(f"  Admin: {admin_code}")
print("\n✓ Ready to run: python app.py")
