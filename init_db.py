from app import app, db

print("Creating database tables...")
with app.app_context():
    db.create_all()
    print("Tables created successfully.")
