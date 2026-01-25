from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Certificate, AccessLog
import os
import random
from datetime import datetime, timedelta

# --- NEW IMPORTS FOR CRYPTOGRAPHY ---
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import hashlib

import io
import qrcode
from flask import send_file
import socket

# --- IMPORT CONFIGURATION AND SECURITY ---
from config import config
from security import (
    validate_file_upload, sanitize_filename, validate_password_strength,
    validate_username, check_rate_limit, check_otp_rate_limit, 
    is_otp_expired, log_access, require_role
)

# Initialize the Flask application
app = Flask(__name__)

# Load configuration from config.py
env = os.getenv('FLASK_ENV', 'development')
app.config.from_object(config[env])

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=app.config['RATELIMIT_STORAGE_URL']
)

# --- DATABASE SETUP SCRIPT ---
def create_db():
    """
    Runs once on startup to ensure tables exist and create a default Admin.
    """
    with app.app_context():
        db.create_all() # Create tables defined in models.py if they don't exist
        
        # Check if Admin exists
        if not User.query.filter_by(username='admin').first():
            # Rubric Criterion 4: Hashing with Salt
            # 'pbkdf2:sha256' is the hashing algorithm.
            # generate_password_hash automatically generates a random 'Salt' 
            # and combines it with the password before hashing.
            hashed_pw = generate_password_hash('admin123', method='pbkdf2:sha256')
            
            admin = User(username='admin', name='Administrator', password_hash=hashed_pw, role='Admin')
            db.session.add(admin)
            db.session.commit()
            print("Database initialized & Admin User Created.")

# --- CONFIGURATION: ACCESS CODES ---
# Now loaded from config.py (which reads from environment variables)
REGISTRATION_CODES = app.config['REGISTRATION_CODES']

def get_local_ip():
    """Get the local IP address of the machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return '127.0.0.1'

# --- CRYPTO SETUP: HYBRID ENCRYPTION ---
# 1. Generate or LOAD a Global RSA Key Pair (Simulating the University's Master Key)
# Persist keys to disk so uploaded files remain decryptable across restarts.
PRIVATE_KEY_PATH = app.config['PRIVATE_KEY_PATH']
PUBLIC_KEY_PATH = app.config['PUBLIC_KEY_PATH']
KEY_PASSPHRASE = app.config['RSA_KEY_PASSPHRASE'].encode('utf-8')

if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
    with open(PRIVATE_KEY_PATH, 'rb') as f:
        # Load encrypted private key with passphrase
        private_key = serialization.load_pem_private_key(
            f.read(), 
            password=KEY_PASSPHRASE, 
            backend=default_backend()
        )
    with open(PUBLIC_KEY_PATH, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    print("RSA keys loaded successfully from disk.")
else:
    print("Generating new RSA key pair...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Save the keys to disk (PEM format). ENCRYPTED with passphrase for security.
    pem_priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(KEY_PASSPHRASE)
    )
    with open(PRIVATE_KEY_PATH, 'wb') as f:
        f.write(pem_priv)

    pem_pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(PUBLIC_KEY_PATH, 'wb') as f:
        f.write(pem_pub)
    print("New RSA key pair generated and saved (encrypted with passphrase).")

def encrypt_data(file_bytes):
    """
    HYBRID ENCRYPTION LOGIC (Rubric Criterion 3):
    1. Generate a random AES Key (Symmetric) -> Fast for large files.
    2. Encrypt the File with AES in CBC mode with PKCS7 padding.
    3. Encrypt the AES Key with RSA (Asymmetric) -> Secure key exchange.
    """
    # A. AES Encryption of the File
    aes_key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)       # Initialization Vector
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad the data
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_bytes) + padder.finalize()
    
    encrypted_file_content = encryptor.update(padded_data) + encryptor.finalize()

    # B. RSA Encryption of the AES Key
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_file_content, encrypted_aes_key, iv

def create_digital_signature(file_bytes):
    """
    PROPER DIGITAL SIGNATURE (Rubric Criterion 4):
    1. Hash the file content with SHA-256
    2. Sign the hash with RSA private key
    Returns the signature bytes
    """
    # Create hash of the file
    file_hash = hashlib.sha256(file_bytes).digest()
    
    # Sign the hash with private key
    signature = private_key.sign(
        file_hash,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return signature

def verify_digital_signature(file_bytes, signature):
    """
    VERIFY DIGITAL SIGNATURE:
    Returns True if signature is valid, False otherwise
    """
    try:
        # Create hash of the file
        file_hash = hashlib.sha256(file_bytes).digest()
        
        # Verify signature with public key
        public_key.verify(
            signature,
            file_hash,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

# --- SETUP EXTENSIONS ---
# Connect the database to the app (configuration already loaded above)
db.init_app(app)

# Setup the Login Manager (Handle sessions automatically)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Where to send users if they aren't logged in

@login_manager.user_loader
def load_user(user_id):
    """
    Flask-Login helper: Retrieves a user object based on the ID stored in the session cookie.
    """
    return User.query.get(int(user_id))

# --- ROUTES (URL Handling) ---

@app.route('/')
@login_required
def home():
    # TRAFFIC CONTROLLER LOGIC
    
    # 1. If Student -> Show Student Dashboard
    if current_user.role == 'Student':
        # Fetch only THEIR certificates
        user_certificates = Certificate.query.filter_by(student_id=current_user.id).all()
        return render_template('dashboard_student.html', certs=user_certificates)
    
    # 2. If Admin -> Show Admin Panel
    elif current_user.role == 'Admin':
        all_certificates = Certificate.query.all()
        # Get recent access logs for auditing (last 50 events)
        recent_logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(50).all()
        return render_template('dashboard_admin.html', certs=all_certificates, logs=recent_logs)
    
    # 3. If Verifier -> Show Verification Tool
    elif current_user.role == 'Verifier':
        public_certs = Certificate.query.filter_by(is_public=True).all()
        return render_template('dashboard_verifier.html', certs=public_certs)
    
    # 4. Fallback (Safety)
    return "Role not recognized", 403

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    """
    Rubric Criterion 1: Single-Factor Authentication
    Enhanced with Rate Limiting
    """
    # If the user submitted the form (POST request)
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check if user exists in DB
        user = User.query.filter_by(username=username).first()
        
        if not user:
            flash('Invalid username or password')
            return render_template('login.html')
        
        # Check if account is locked due to failed attempts
        is_locked, lock_message = check_rate_limit(
            user, 
            app.config['MAX_LOGIN_ATTEMPTS'],
            app.config['LOGIN_LOCKOUT_DURATION']
        )
        if is_locked:
            flash(lock_message)
            log_access(user.id, f"Failed login attempt (account locked): {username}", db, AccessLog)
            return render_template('login.html')
        
        # VERIFY PASSWORD
        # check_password_hash() securely compares the input plain text password 
        # against the stored hash in the database.
        if check_password_hash(user.password_hash, password):
            # Reset failed login attempts on successful login
            user.failed_login_attempts = 0
            user.last_failed_login = None
            db.session.commit()
            
            # --- START MFA (Rubric Criterion 1: Multi-Factor) ---
            # Generate a random 6-digit number
            otp_code = random.randint(100000, 999999)
            
            # Calculate OTP expiration time
            otp_expiry = datetime.now() + timedelta(seconds=app.config['OTP_EXPIRATION_SECONDS'])
            
            # Save the code and the User ID in the "Session" (Temporary server memory)
            # We don't log them in yet! We just remember who *wants* to log in.
            session['otp'] = otp_code
            session['pending_user_id'] = user.id
            session['otp_expiry'] = otp_expiry.isoformat()
            session['otp_attempts'] = 0
            
            # SIMULATION: Print the code to the terminal (Console)
            # In a real app, this would be: send_sms(user.phone, otp_code)
            print(f"\n[MFA SYSTEM] SENT OTP TO {username}: {otp_code}")
            print(f"[MFA SYSTEM] OTP expires at: {otp_expiry}\n")
            
            # Log successful password verification
            log_access(user.id, f"Login: Password verified, OTP sent", db, AccessLog)
            
            # Redirect to the second step
            return redirect(url_for('verify_otp'))
        else:
            # Increment failed login attempts
            user.failed_login_attempts += 1
            user.last_failed_login = datetime.now()
            db.session.commit()
            
            remaining = app.config['MAX_LOGIN_ATTEMPTS'] - user.failed_login_attempts
            flash(f'Invalid username or password. {remaining} attempts remaining.')
            log_access(user.id, f"Failed login attempt: {username}", db, AccessLog)
            
    # If GET request, just show the HTML form
    return render_template('login.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def verify_otp():
    """
    OTP Verification with expiration and rate limiting
    """
    # Validate session has required data
    if 'otp' not in session or 'pending_user_id' not in session:
        flash('Session expired. Please login again.')
        return redirect(url_for('login'))
    
    # Check if OTP has expired
    if is_otp_expired():
        # Clean up session
        session.pop('otp', None)
        session.pop('pending_user_id', None)
        session.pop('otp_expiry', None)
        session.pop('otp_attempts', None)
        flash('OTP has expired. Please login again.')
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        # Check rate limiting on OTP attempts
        is_locked, lock_message = check_otp_rate_limit()
        if is_locked:
            # Clean up session
            session.pop('otp', None)
            session.pop('pending_user_id', None)
            session.pop('otp_expiry', None)
            session.pop('otp_attempts', None)
            flash(lock_message)
            return redirect(url_for('login'))
        
        user_input = request.form.get('otp')
        real_otp = session.get('otp')
        
        if user_input and int(user_input) == real_otp:
            # 1. GET THE USER ID
            user_id = session['pending_user_id']
            user = User.query.get(user_id)
            
            # 2. LOG THEM IN (Create the session cookie)
            login_user(user, remember=True)
            
            # Log successful login
            log_access(user.id, f"Login: OTP verified successfully", db, AccessLog)
            
            # 3. CLEAN UP
            session.pop('otp', None)
            session.pop('pending_user_id', None)
            session.pop('otp_expiry', None)
            session.pop('otp_attempts', None)
            
            # 4. REDIRECT TO THE TRAFFIC CONTROLLER
            return redirect(url_for('home'))
        else:
            # Increment OTP attempt counter
            session['otp_attempts'] = session.get('otp_attempts', 0) + 1
            remaining = app.config['OTP_MAX_ATTEMPTS'] - session.get('otp_attempts', 0)
            
            # Log failed OTP attempt
            user_id = session.get('pending_user_id')
            if user_id:
                log_access(user_id, f"Failed OTP verification attempt", db, AccessLog)
            
            flash(f'Invalid OTP Code! {remaining} attempts remaining.')
            
    return render_template('otp.html')

@app.route('/logout')
@login_required # Protects this route: Guests cannot logout
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Handles new user sign-ups.
    Enforces 'Access Code' check to prevent unauthorized accounts.
    Enhanced with password and username validation.
    """
    if request.method == 'POST':
        # 1. Get Form Data
        username = request.form.get('username')
        name = request.form.get('name')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role')
        entered_code = request.form.get('access_code')
        
        # 2. Validate username
        is_valid, error = validate_username(username)
        if not is_valid:
            flash(error)
            return redirect(url_for('register'))
        
        # 3. Validate password strength
        is_valid, error = validate_password_strength(password)
        if not is_valid:
            flash(error)
            return redirect(url_for('register'))
        
        # 4. Validate passwords match
        if password != confirm_password:
            flash('Passwords do not match. Please try again.')
            return redirect(url_for('register'))
        
        # 5. Check if username is taken
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose another.')
            return redirect(url_for('register'))
            
        # 6. VERIFY ACCESS CODE (Authorization Requirement)
        # Check if the code entered matches the required code for that Role.
        required_code = REGISTRATION_CODES.get(role)
        
        if entered_code != required_code:
            flash(f"Invalid Access Code for {role}! You are not authorized.")
            return redirect(url_for('register'))
        
        # 7. CREATE ACCOUNT
        # Hash the password (Security Requirement)
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        
        new_user = User(username=username, name=name, password_hash=hashed_pw, role=role)
        db.session.add(new_user)
        db.session.commit()
        
        # Log registration
        log_access(new_user.id, f"User registered: {username} as {role}", db, AccessLog)
        
        flash('Account created successfully! Please login.')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    # Authorization Check: Only Students can upload
    if current_user.role != 'Student':
        flash("Unauthorized: Only students can upload certificates.")
        return redirect(url_for('home'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
            
        file = request.files['file']
        
        # ENHANCED FILE VALIDATION
        is_valid, error = validate_file_upload(
            file, 
            app.config['MAX_FILE_SIZE'],
            app.config['ALLOWED_EXTENSIONS']
        )
        
        if not is_valid:
            flash(error)
            return redirect(request.url)

        if file:
            # 1. Sanitize filename
            safe_filename = sanitize_filename(file.filename)
            
            # 2. Read the raw file bytes
            file_bytes = file.read()
            
            # 3. PERFORM HYBRID ENCRYPTION (AES + RSA)
            enc_data, enc_key, iv = encrypt_data(file_bytes)
            
            # 4. PROPER DIGITAL SIGNATURE (Rubric Criterion 4)
            # Create a cryptographic signature using RSA private key
            signature = create_digital_signature(file_bytes)
            
            # 5. Save to Database
            is_public = request.form.get('is_public') == 'on'  # Checkbox value
            new_cert = Certificate(
                student_id=current_user.id,
                filename=safe_filename,
                encrypted_data=enc_data,
                encrypted_aes_key=enc_key,
                iv=iv,
                digital_signature=signature,
                is_public=is_public
            )
            
            db.session.add(new_cert)
            db.session.commit()
            
            # Log upload action
            log_access(current_user.id, f"Uploaded certificate: {safe_filename}", db, AccessLog)
            
            flash('File uploaded, encrypted, and signed successfully!')
            return redirect(url_for('home'))

    return render_template('upload.html')

# --- ROUTE 1: GENERATE QR CODE IMAGE ---
@app.route('/qr_code/<int:cert_id>')
@login_required
def generate_qr(cert_id):
    """
    Generates a PNG image of the QR code pointing to the verification link.
    Rubric Criterion: Encoding (QR Code / Barcode)
    """
    # 1. Build the verification URL using the local IP for network access
    local_ip = get_local_ip()
    verify_url = f"http://{local_ip}:5000/verify/{cert_id}"
    
    # 2. Create the QR Code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(verify_url)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    
    # 3. Save to a memory buffer (RAM) instead of a file on disk
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    
    return send_file(buf, mimetype='image/png')

# --- ROUTE 2: VERIFY & DECRYPT (The Final Exam) ---
@app.route('/verify/<int:cert_id>', methods=['GET'])
@login_required
def verify_certificate(cert_id):
    """
    Rubric Criterion: Decryption + Digital Signature Verification
    Enhanced authorization logic and proper signature verification
    """
    cert = Certificate.query.get_or_404(cert_id)
    
    # FIXED AUTHORIZATION LOGIC:
    # Allow access if:
    # 1. User is Admin (full access)
    # 2. User is Verifier AND certificate is public
    # 3. User is the owner (Student who uploaded it)
    
    is_admin = current_user.role == 'Admin'
    is_verifier_with_access = current_user.role == 'Verifier' and cert.is_public
    is_owner = current_user.role == 'Student' and cert.student_id == current_user.id
    
    if not (is_admin or is_verifier_with_access or is_owner):
        flash("Access Denied: You do not have permission to verify this document.")
        log_access(current_user.id, f"Denied access to certificate #{cert_id}", db, AccessLog)
        return redirect(url_for('home'))
    
    print(f"Verifying cert {cert_id}, encrypted_data length: {len(cert.encrypted_data)}, iv length: {len(cert.iv)}")
    
    try:
        # A. DECRYPT THE AES KEY (RSA Decryption)
        # We use the University's Private Key to unlock the AES key
        aes_key = private_key.decrypt(
            cert.encrypted_aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        print("AES key decrypted successfully")
        
        # B. DECRYPT THE FILE (AES Decryption)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(cert.iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(cert.encrypted_data) + decryptor.finalize()
        
        # Unpad the data
        unpadder = padding.PKCS7(128).unpadder()
        original_file_bytes = unpadder.update(decrypted_padded) + unpadder.finalize()
        
        print(f"Decryption successful, original length: {len(original_file_bytes)}")
        
        # C. VERIFY DIGITAL SIGNATURE (Integrity Check)
        # Use proper RSA signature verification
        is_valid = verify_digital_signature(original_file_bytes, cert.digital_signature)
        
        if is_valid:
            status = "VALID"
            color = "success" # Green
            message = "The Digital Signature matches. This document is authentic and untampered."
            log_access(current_user.id, f"Verified certificate #{cert_id}: VALID", db, AccessLog)
        else:
            status = "TAMPERED"
            color = "danger" # Red
            message = "❌ WARNING: Digital Signature Mismatch! This file has been modified."
            log_access(current_user.id, f"Verified certificate #{cert_id}: TAMPERED", db, AccessLog)
            
        # In a real app, we might let them download the file. 
        # For the demo, we just show the success message.
        return render_template('verify_result.html', cert=cert, status=status, color=color, message=message)
        
    except Exception as e:
        print(f"Decryption error for cert {cert_id}: {e}")
        log_access(current_user.id, f"Failed to verify certificate #{cert_id}: {str(e)}", db, AccessLog)
        return f"Decryption Failed: {str(e)}. This may occur if the certificate was encrypted with a different key. Try uploading a new certificate."


@app.route('/toggle_public/<int:cert_id>', methods=['POST'])
@login_required
def toggle_public(cert_id):
    cert = Certificate.query.get_or_404(cert_id)
    
    # Only the owner (student) can toggle
    if current_user.role != 'Student' or cert.student_id != current_user.id:
        flash("Access Denied: You can only modify your own files.")
        return redirect(url_for('home'))
    
    cert.is_public = not cert.is_public
    db.session.commit()
    status = "Public" if cert.is_public else "Private"
    
    # Log toggle action
    log_access(current_user.id, f"Toggled certificate #{cert_id} visibility to {status}", db, AccessLog)
    
    flash(f'File status updated to {status}!')
    return redirect(url_for('home'))


@app.route('/delete/<int:cert_id>', methods=['POST'])
@login_required
def delete_certificate(cert_id):
    cert = Certificate.query.get_or_404(cert_id)
    
    # Only the owner (student) can delete
    if current_user.role != 'Student' or cert.student_id != current_user.id:
        flash("Access Denied: You can only delete your own files.")
        return redirect(url_for('home'))
    
    filename = cert.filename
    db.session.delete(cert)
    db.session.commit()
    
    # Log deletion
    log_access(current_user.id, f"Deleted certificate: {filename}", db, AccessLog)
    
    flash('File deleted successfully!')
    return redirect(url_for('home'))


@app.route('/download/<int:cert_id>')
@login_required
def download_certificate(cert_id):
    """Download and decrypt the original file for authorized users."""
    cert = Certificate.query.get_or_404(cert_id)

    # Authorization: only owner, Verifier (if public), or Admin
    is_admin = current_user.role == 'Admin'
    is_verifier_with_access = current_user.role == 'Verifier' and cert.is_public
    is_owner = current_user.role == 'Student' and cert.student_id == current_user.id
    
    if not (is_admin or is_verifier_with_access or is_owner):
        flash("Access Denied: You do not have permission to download this document.")
        return redirect(url_for('home'))

    try:
        aes_key = private_key.decrypt(
            cert.encrypted_aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(cert.iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(cert.encrypted_data) + decryptor.finalize()
        
        # Unpad the data
        unpadder = padding.PKCS7(128).unpadder()
        original_file_bytes = unpadder.update(decrypted_padded) + unpadder.finalize()

        # Log download
        log_access(current_user.id, f"Downloaded certificate #{cert_id}: {cert.filename}", db, AccessLog)

        buf = io.BytesIO(original_file_bytes)
        buf.seek(0)
        return send_file(buf, as_attachment=True, download_name=cert.filename, mimetype='application/octet-stream')

    except Exception as e:
        flash(f'Decryption Failed: {str(e)}')
        return redirect(url_for('home'))

if __name__ == '__main__':
    # Fix: Check for the correct database path (instance/locker.db)
    db_path = os.path.join('instance', 'locker.db')
    if not os.path.exists(db_path):
        create_db()
        
    # Start the server with settings from config
    # Debug mode and host are now configurable via environment variables
    app.run(
        host=app.config['FLASK_HOST'], 
        port=app.config['FLASK_PORT'],
        debug=app.config['DEBUG']
    )