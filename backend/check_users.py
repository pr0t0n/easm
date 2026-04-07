from app.db.session import SessionLocal
from app.models.models import User

db = SessionLocal()
try:
    users = db.query(User).all()
    if users:
        print("✅ Users in database:")
        for user in users:
            print(f"  - ID: {user.id}, Email: {user.email}")
    else:
        print("❌ No users found in database")
finally:
    db.close()
