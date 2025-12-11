from app import app, db, Admin
import os

def init_db():
    with app.app_context():
        # Create tables
        db.create_all()
        print("✅ Database tables created.")

        # Create initial admin if not exists
        if not Admin.query.first():
            username = os.environ.get('INITIAL_ADMIN_USERNAME', 'admin')
            password = os.environ.get('INITIAL_ADMIN_PASSWORD', 'admin')
            
            admin = Admin(username=username)
            admin.set_password(password)
            admin.is_superadmin = True
            admin.role = 'superadmin'
            
            db.session.add(admin)
            db.session.commit()
            print(f"✅ Initial admin created: {username}")
        else:
            print("ℹ️  Admin already exists.")

if __name__ == "__main__":
    init_db()
