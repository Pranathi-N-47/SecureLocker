"""
Simpler database initialization - just creates tables, doesn't query
"""
from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    # Drop all tables first, then recreate
    db.drop_all()
    print("✓ Dropped old tables")
    
    # Create all tables with new schema
    db.create_all()
    print("✓ Database tables created with new schema")
    
    # Create admin user directly without querying first
    try:
        hashed_pw = generate_password_hash('admin123', method='pbkdf2:sha256')
        admin = User(
            username='admin', 
            name='Administrator', 
            password_hash=hashed_pw, 
            role='Admin',
            failed_login_attempts=0,
            last_failed_login=None
        )
        db.session.add(admin)
        db.session.commit()
        print("✓ Admin user created (username: admin, password: admin123)")
    except Exception as e:
        print(f"Note: {e}")
    
    print("\n✓ Database is ready!")
    print("Access codes from your .env file:")
    import os
    from dotenv import load_dotenv
    load_dotenv()
    print(f"  Student: {os.getenv('STUDENT_ACCESS_CODE')}")
    print(f"  Verifier: {os.getenv('VERIFIER_ACCESS_CODE')}")  
    print(f"  Admin: {os.getenv('ADMIN_ACCESS_CODE')}")
    print("\nYou can now use the app at http://127.0.0.1:5000")
