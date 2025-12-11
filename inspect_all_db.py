from app import app, db
from sqlalchemy import inspect

with app.app_context():
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()
    print('Tables in DB:', tables)
    for t in tables:
        cols = [c['name'] for c in inspector.get_columns(t)]
        print(f"\nColumns in {t}: {cols}")
