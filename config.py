"""
Configuration Management for SecureLocker
Loads settings from environment variables with secure defaults
"""
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Base configuration with security defaults"""
    
    # Flask Core Settings
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-CHANGE-IN-PRODUCTION')
    if SECRET_KEY == 'dev-key-CHANGE-IN-PRODUCTION':
        print("WARNING: Using default SECRET_KEY. Set a secure key in .env file!")
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URI', 'sqlite:///instance/locker.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # RSA Key Management
    RSA_KEY_PASSPHRASE = os.getenv('RSA_KEY_PASSPHRASE', 'dev-passphrase-CHANGE-THIS')
    if RSA_KEY_PASSPHRASE == 'dev-passphrase-CHANGE-THIS':
        print("WARNING: Using default RSA passphrase. Set a secure passphrase in .env file!")
    
    PRIVATE_KEY_PATH = 'private_key.pem'
    PUBLIC_KEY_PATH = 'public_key.pem'
    
    # Access Codes for Registration
    REGISTRATION_CODES = {
        'Student': os.getenv('STUDENT_ACCESS_CODE', 'STUDENT-DEV-KEY'),
        'Verifier': os.getenv('VERIFIER_ACCESS_CODE', 'VERIFIER-DEV-KEY'),
        'Admin': os.getenv('ADMIN_ACCESS_CODE', 'ADMIN-DEV-KEY')
    }
    
    # Security Settings
    OTP_EXPIRATION_SECONDS = int(os.getenv('OTP_EXPIRATION_SECONDS', '300'))  # 5 minutes
    OTP_MAX_ATTEMPTS = int(os.getenv('OTP_MAX_ATTEMPTS', '3'))
    MAX_LOGIN_ATTEMPTS = int(os.getenv('MAX_LOGIN_ATTEMPTS', '5'))
    LOGIN_LOCKOUT_DURATION = int(os.getenv('LOGIN_LOCKOUT_DURATION', '900'))  # 15 minutes
    
    # File Upload Settings
    MAX_FILE_SIZE = int(os.getenv('MAX_FILE_SIZE', '10485760'))  # 10MB default
    ALLOWED_EXTENSIONS = set(os.getenv('ALLOWED_EXTENSIONS', 'pdf,png,jpg,jpeg,doc,docx').split(','))
    
    # Flask Runtime Settings
    DEBUG = os.getenv('DEBUG', 'True').lower() in ('true', '1', 'yes')
    FLASK_HOST = os.getenv('FLASK_HOST', '0.0.0.0')
    FLASK_PORT = int(os.getenv('FLASK_PORT', '5000'))
    
    # Rate Limiting
    RATELIMIT_STORAGE_URL = "memory://"
    RATELIMIT_ENABLED = True

class DevelopmentConfig(Config):
    """Development-specific settings"""
    DEBUG = True

class ProductionConfig(Config):
    """Production-specific settings"""
    DEBUG = False
    # In production, these MUST be set via environment variables
    if Config.SECRET_KEY == 'dev-key-CHANGE-IN-PRODUCTION':
        raise ValueError("SECRET_KEY must be set in production!")
    if Config.RSA_KEY_PASSPHRASE == 'dev-passphrase-CHANGE-THIS':
        raise ValueError("RSA_KEY_PASSPHRASE must be set in production!")

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
