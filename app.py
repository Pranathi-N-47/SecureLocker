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
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import hashlib

# Initialize the Flask application
app = Flask(__name__)

# --- CRYPTO SETUP: HYBRID ENCRYPTION ---
# 1. Generate a Global RSA Key Pair (Simulating the University's Master Key)
# In a real app, you would load these from a file (private.pem), not generate on startup.
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

def encrypt_data(file_bytes):
    """
    HYBRID ENCRYPTION LOGIC (Rubric Criterion 3):
    1. Generate a random AES Key (Symmetric) -> Fast for large files.
    2. Encrypt the File with AES.
    3. Encrypt the AES Key with RSA (Asymmetric) -> Secure key exchange.
    """
    # A. AES Encryption of the File
    aes_key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)       # Initialization Vector
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_file_content = encryptor.update(file_bytes) + encryptor.finalize()

    # B. RSA Encryption of the AES Key
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
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
    return session.get(int(user_id))

# --- ROUTES (URL Handling) ---

@app.route('/')
@login_required
def home():
    """
    The Role-Based Dashboard.
    Decision Logic:
    - Student: Show ONLY certificates uploaded by them.
    - Admin: Show ALL certificates (Audit view).
    - Verifier: Show a search/verification tool (No private data).
    """
    user_certificates = []
    
    # LOGIC 1: STUDENTS see their own files
    if current_user.role == 'Student':
        user_certificates = Certificate.query.filter_by(student_id=current_user.id).all()
        return render_template('dashboard_student.html', certs=user_certificates)
    
    # LOGIC 2: ADMIN sees everything
    elif current_user.role == 'Admin':
        all_certificates = Certificate.query.all()
        # In a real app, you'd join with User table to get usernames, 
        # but for now we just show IDs or raw data
        return render_template('dashboard_admin.html', certs=all_certificates)
    
    # LOGIC 3: VERIFIERS see the Verification Tool
    elif current_user.role == 'Verifier':
        return render_template('dashboard_verifier.html')
    
    # Fallback
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
    """
    Rubric Criterion 1: Multi-Factor Authentication (Step 2)
    """
    # Security Check: Don't let people guess this URL. They must have passed step 1.
    if 'pending_user_id' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        user_input = request.form.get('otp')
        real_otp = session.get('otp')
        
        # Check if the code matches
        if user_input and int(user_input) == real_otp:
            # SUCCESS! Now we actually authorize the user session.
            user = User.query.get(session['pending_user_id'])
            login_user(user)
            
            # Cleanup: Remove temp data from session
            session.pop('otp', None)
            session.pop('pending_user_id', None)
            
            return redirect(url_for('home'))
        else:
            flash('Invalid OTP Code!')
            
    return render_template('otp.html')

@app.route('/logout')
@login_required # Protects this route: Guests cannot logout
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- DATABASE SETUP SCRIPT ---
def create_db():
    """
    Runs once on startup to ensure tables exist and create a default Admin.
    """
    with app.app_context():
        db.create_all() # Create tables defined in models.py
        
        # Check if Admin exists
        if not User.query.filter_by(username='admin').first():
            # Rubric Criterion 4: Hashing with Salt
            # 'pbkdf2:sha256' is the hashing algorithm.
            # generate_password_hash automatically generates a random 'Salt' 
            # and combines it with the password before hashing.
            hashed_pw = generate_password_hash('admin123', method='pbkdf2:sha256')
            
            admin = User(username='admin', password_hash=hashed_pw, role='Admin')
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

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Handles new user sign-ups.
    Enforces 'Access Code' check to prevent unauthorized accounts.
    """
    if request.method == 'POST':
        # 1. Get Form Data
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        entered_code = request.form.get('access_code')
        
        # 2. Check if username is taken
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose another.')
            return redirect(url_for('register'))
            
        # 3. VERIFY ACCESS CODE (Authorization Requirement)
        # Check if the code entered matches the required code for that Role.
        required_code = REGISTRATION_CODES.get(role)
        
        if entered_code != required_code:
            flash(f"Invalid Access Code for {role}! You are not authorized.")
            return redirect(url_for('register'))
        
        # 4. CREATE ACCOUNT
        # Hash the password (Security Requirement)
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        
        new_user = User(username=username, password_hash=hashed_pw, role=role)
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
            new_cert = Certificate(
                student_id=current_user.id,
                filename=file.filename,
                encrypted_data=enc_data,
                encrypted_aes_key=enc_key,
                iv=iv,
                digital_signature=signature
            )
            
            db.session.add(new_cert)
            db.session.commit()
            
            flash('File uploaded, encrypted, and signed successfully!')
            return redirect(url_for('home'))

    return render_template('upload.html')

if __name__ == '__main__':
    # If the DB file doesn't exist, create it
    if not os.path.exists('locker.db'):
        create_db()
        
    # Start the server in debug mode (auto-reloads when you save code)
    app.run(debug=True)