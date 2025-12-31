import os
from app import app, db, Server, SERVER_PASSWORD_PREFIX

def fix_passwords():
    with app.app_context():
        servers = Server.query.all()
        count = 0
        for s in servers:
            if s.password and s.password.startswith(SERVER_PASSWORD_PREFIX):
                print(f"Clearing encrypted password for server: {s.name}")
                s.password = ""
                count += 1
        
        if count > 0:
            db.session.commit()
            print(f"Successfully cleared {count} encrypted passwords. Please re-enter them in the UI.")
        else:
            print("No encrypted passwords found starting with 'enc:'.")

if __name__ == "__main__":
    fix_passwords()
