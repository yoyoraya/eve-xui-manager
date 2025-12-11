from app import app, db
from sqlalchemy import inspect

with app.app_context():
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()
    print('Tables in DB:', tables)
    to_check = ['admins','transactions','payments','faqs','system_settings','client_ownerships','servers','inbounds']
    for t in to_check:
        if t in tables:
            cols = [c['name'] for c in inspector.get_columns(t)]
            print(f"\nColumns in {t}: {cols}")
        else:
            print(f"\nTable {t} not found")
