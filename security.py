"""
Security utilities for SecureLocker
Includes validation, sanitization, and security helper functions
"""
import os
import re
from functools import wraps
from flask import request, flash, redirect, url_for, session
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename

def validate_file_upload(file, max_size, allowed_extensions):
    """
    Validate uploaded file for security
    Returns (is_valid, error_message)
    """
    if not file:
        return False, "No file provided"
    
    if file.filename == '':
        return False, "No file selected"
    
    # Check file extension
    filename = file.filename.lower()
    if '.' not in filename:
        return False, "File must have an extension"
    
    ext = filename.rsplit('.', 1)[1]
    if ext not in allowed_extensions:
        allowed = ', '.join(allowed_extensions)
        return False, f"File type not allowed. Allowed types: {allowed}"
    
    # Check file size by reading content
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)  # Reset to beginning
    
    if size > max_size:
        max_mb = max_size / (1024 * 1024)
        return False, f"File too large. Maximum size: {max_mb:.1f}MB"
    
    if size == 0:
        return False, "File is empty"
    
    return True, None

def sanitize_filename(filename):
    """
    Sanitize filename to prevent path traversal and other attacks
    """
    # Use werkzeug's secure_filename as base
    safe_name = secure_filename(filename)
    
    # Additional sanitization
    # Remove any remaining special characters except dots, hyphens, underscores
    safe_name = re.sub(r'[^\w\s.-]', '', safe_name)
    
    # Limit filename length
    if len(safe_name) > 255:
        name, ext = os.path.splitext(safe_name)
        safe_name = name[:250] + ext
    
    return safe_name

def validate_password_strength(password):
    """
    Validate password meets security requirements
    Returns (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    
    # Optional: check for special characters
    # if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
    #     return False, "Password must contain at least one special character"
    
    return True, None

def validate_username(username):
    """
    Validate username format
    Returns (is_valid, error_message)
    """
    if not username or len(username) < 3:
        return False, "Username must be at least 3 characters long"
    
    if len(username) > 50:
        return False, "Username must be less than 50 characters"
    
    # Only allow alphanumeric and underscores
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"
    
    return True, None

def check_rate_limit(user, max_attempts, lockout_duration, attempt_type='login'):
    """
    Check if user has exceeded rate limit
    Returns (is_locked, error_message)
    """
    if not hasattr(user, 'failed_login_attempts') or not hasattr(user, 'last_failed_login'):
        # User model doesn't support rate limiting yet
        return False, None
    
    # Check if user is currently locked out
    if user.last_failed_login:
        time_since_last_attempt = datetime.now() - user.last_failed_login
        if user.failed_login_attempts >= max_attempts:
            if time_since_last_attempt < timedelta(seconds=lockout_duration):
                remaining = lockout_duration - time_since_last_attempt.seconds
                minutes = remaining // 60
                return True, f"Account temporarily locked. Try again in {minutes} minutes."
            else:
                # Lockout period expired, reset counter
                user.failed_login_attempts = 0
    
    return False, None

def check_otp_rate_limit():
    """
    Check if OTP verification has been attempted too many times
    Returns (is_locked, error_message)
    """
    otp_attempts = session.get('otp_attempts', 0)
    max_attempts = 3  # Could also come from config
    
    if otp_attempts >= max_attempts:
        return True, "Too many failed OTP attempts. Please login again."
    
    return False, None

def is_otp_expired():
    """
    Check if the OTP has expired
    Returns True if expired
    """
    otp_expiry = session.get('otp_expiry')
    if not otp_expiry:
        return True
    
    expiry_time = datetime.fromisoformat(otp_expiry)
    return datetime.now() > expiry_time

def log_access(user_id, action, db, AccessLog):
    """
    Log user action for audit trail
    """
    try:
        log_entry = AccessLog(
            user_id=user_id,
            action=action
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        print(f"Failed to log action: {e}")
        # Don't fail the request if logging fails
        db.session.rollback()

def require_role(*roles):
    """
    Decorator to restrict route access to specific roles
    Usage: @require_role('Admin', 'Verifier')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask_login import current_user
            if not current_user.is_authenticated:
                flash("Please login to access this page")
                return redirect(url_for('login'))
            
            if current_user.role not in roles:
                flash("Access Denied: Insufficient permissions")
                return redirect(url_for('home'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator
