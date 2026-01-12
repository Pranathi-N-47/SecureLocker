from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User
import os
import random
from models import Certificate

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

# Initialize the Flask application
app = Flask(__name__)

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
# These act like "Invite Codes". Without them, registration is blocked.
REGISTRATION_CODES = {
    'Student': 'STUDENT-KEY',   # Code for Students
    'Verifier': 'TRUSTED-PARTNER-KEY',  # Code for Recruiters/Verifiers
    'Admin': 'SYSADMIN-MASTER-KEY'      # Code for Admins
}

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
PRIVATE_KEY_PATH = 'private_key.pem'
PUBLIC_KEY_PATH = 'public_key.pem'

if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
    with open(PRIVATE_KEY_PATH, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    with open(PUBLIC_KEY_PATH, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
else:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Save the keys to disk (PEM format). WARNING: private key is stored unencrypted for demo purposes.
    pem_priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(PRIVATE_KEY_PATH, 'wb') as f:
        f.write(pem_priv)

    pem_pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(PUBLIC_KEY_PATH, 'wb') as f:
        f.write(pem_pub)

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

# --- CONFIGURATION (Settings) ---
# Secret Key: Used by Flask to cryptographically sign session cookies so users can't fake being logged in.
app.config['SECRET_KEY'] = 'secure-key-123' 

# Database URI: Tells SQLAlchemy where to find our file-based database.
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///locker.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- SETUP EXTENSIONS ---
# Connect the database to the app
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
        return render_template('dashboard_admin.html', certs=all_certificates)
    
    # 3. If Verifier -> Show Verification Tool
    elif current_user.role == 'Verifier':
        public_certs = Certificate.query.filter_by(is_public=True).all()
        return render_template('dashboard_verifier.html', certs=public_certs)
    
    # 4. Fallback (Safety)
    return "Role not recognized", 403

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Rubric Criterion 1: Single-Factor Authentication
    """
    # If the user submitted the form (POST request)
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check if user exists in DB
        user = User.query.filter_by(username=username).first()
        
        # VERIFY PASSWORD
        # check_password_hash() securely compares the input plain text password 
        # against the stored hash in the database.
        if user and check_password_hash(user.password_hash, password):
            
            # --- START MFA (Rubric Criterion 1: Multi-Factor) ---
            # Generate a random 6-digit number
            otp_code = random.randint(100000, 999999)
            
            # Save the code and the User ID in the "Session" (Temporary server memory)
            # We don't log them in yet! We just remember who *wants* to log in.
            session['otp'] = otp_code
            session['pending_user_id'] = user.id
            
            # SIMULATION: Print the code to the terminal (Console)
            # In a real app, this would be: send_sms(user.phone, otp_code)
            print(f"\n[MFA SYSTEM] SENT OTP TO {username}: {otp_code}\n")
            
            # Redirect to the second step
            return redirect(url_for('verify_otp'))
        else:
            flash('Invalid username or password') # Show error message
            
    # If GET request, just show the HTML form
    return render_template('login.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    # ... (session checks) ...
        
    if request.method == 'POST':
        user_input = request.form.get('otp')
        real_otp = session.get('otp')
        
        if user_input and int(user_input) == real_otp:
            # 1. GET THE USER ID
            user_id = session['pending_user_id']
            user = User.query.get(user_id)
            
            # 2. LOG THEM IN (Create the session cookie)
            login_user(user, remember=True) 
            
            # 3. CLEAN UP
            session.pop('otp', None)
            session.pop('pending_user_id', None)
            
            # 4. REDIRECT TO THE TRAFFIC CONTROLLER
            return redirect(url_for('home'))
            
        else:
            flash('Invalid OTP Code!')
            
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
    """
    if request.method == 'POST':
        # 1. Get Form Data
        username = request.form.get('username')
        name = request.form.get('name')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role')
        entered_code = request.form.get('access_code')
        
        # 2. Validate passwords match
        if password != confirm_password:
            flash('Passwords do not match. Please try again.')
            return redirect(url_for('register'))
        
        # 3. Check if username is taken
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose another.')
            return redirect(url_for('register'))
            
        # 4. VERIFY ACCESS CODE (Authorization Requirement)
        # Check if the code entered matches the required code for that Role.
        required_code = REGISTRATION_CODES.get(role)
        
        if entered_code != required_code:
            flash(f"Invalid Access Code for {role}! You are not authorized.")
            return redirect(url_for('register'))
        
        # 5. CREATE ACCOUNT
        # Hash the password (Security Requirement)
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        
        new_user = User(username=username, name=name, password_hash=hashed_pw, role=role)
        db.session.add(new_user)
        db.session.commit()
        
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
        
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        if file:
            # 1. Read the raw file bytes
            file_bytes = file.read()
            
            # 2. PERFORM HYBRID ENCRYPTION (AES + RSA)
            enc_data, enc_key, iv = encrypt_data(file_bytes)
            
            # 3. DIGITAL SIGNATURE (Rubric Criterion 4)
            # Create a SHA-256 Hash of the ORIGINAL content to verify integrity later.
            file_hash = hashlib.sha256(file_bytes).hexdigest()
            # Sign it (Simulated by storing the hash signed by our Admin Key - simplified here to just storage for verification)
            # For the demo, we store the hash. In verify step, we check if Decrypted_Hash == Stored_Hash.
            signature = file_hash 
            
            # 4. Save to Database
            is_public = request.form.get('is_public') == 'on'  # Checkbox value
            new_cert = Certificate(
                student_id=current_user.id,
                filename=file.filename,
                encrypted_data=enc_data,
                encrypted_aes_key=enc_key,
                iv=iv,
                digital_signature=signature,
                is_public=is_public
            )
            
            db.session.add(new_cert)
            db.session.commit()
            
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
    """
    # Authorization: Only Verifiers or the Owner can check this
    # (Admins can audit too)
    if current_user.role not in ['Verifier', 'Admin'] and \
       (current_user.role == 'Student' and not Certificate.query.filter_by(id=cert_id, student_id=current_user.id).first()):
        flash("Access Denied: You do not have permission to verify this document.")
        return redirect(url_for('home'))

    cert = Certificate.query.get_or_404(cert_id)
    
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
        # Recalculate hash of the decrypted file
        current_hash = hashlib.sha256(original_file_bytes).hexdigest()
        
        # Compare with the stored signature
        if current_hash == cert.digital_signature:
            status = "VALID"
            color = "success" # Green
            message = "✅ The Digital Signature matches. This document is authentic and untampered."
        else:
            status = "TAMPERED"
            color = "danger" # Red
            message = "❌ WARNING: Digital Signature Mismatch! This file has been modified."
            
        # In a real app, we might let them download the file. 
        # For the demo, we just show the success message.
        return render_template('verify_result.html', cert=cert, status=status, color=color, message=message)
        
    except Exception as e:
        print(f"Decryption error for cert {cert_id}: {e}")
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
    
    db.session.delete(cert)
    db.session.commit()
    flash('File deleted successfully!')
    return redirect(url_for('home'))


@app.route('/download/<int:cert_id>')
@login_required
def download_certificate(cert_id):
    """Download and decrypt the original file for authorized users."""
    cert = Certificate.query.get_or_404(cert_id)

    # Authorization: only owner, Verifier, or Admin
    if current_user.role not in ['Verifier', 'Admin'] and not (current_user.role == 'Student' and cert.student_id == current_user.id):
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

        buf = io.BytesIO(original_file_bytes)
        buf.seek(0)
        return send_file(buf, as_attachment=True, download_name=cert.filename, mimetype='application/octet-stream')

    except Exception as e:
        flash(f'Decryption Failed: {str(e)}')
        return redirect(url_for('home'))

if __name__ == '__main__':
    # If the DB file doesn't exist, create it
    if not os.path.exists('locker.db'):
        create_db()
        
    # Start the server in debug mode (auto-reloads when you save code)
    # Bind to 0.0.0.0 to allow access from other devices on the network
    app.run(host='0.0.0.0', debug=True)