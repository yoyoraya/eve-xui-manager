#!/usr/bin/env python3
"""Migrate data from SQLite (instance/servers.db) into PostgreSQL.

Why this exists:
- `setup.sh` historically generated a partial migration script during install.
- After updates, that generated file can drift from the real schema/models.

This script is tracked in the repo and aims to migrate *all* supported tables
with safe upserts for config-like tables (SystemConfig/SystemSetting/SubAppConfig).

Usage (recommended via setup.sh):
  set -a; source .env; set +a; python3 migrate_db.py

Optional args:
  --sqlite PATH            Override SQLite path (defaults to instance/servers.db)
  --no-update-existing     Do not update existing rows (insert-only)
"""

import argparse
import os
import sqlite3
import sys
from datetime import datetime

from sqlalchemy import text

from app import (
    app,
    db,
    Admin,
    Server,
    SubAppConfig,
    FAQ,
    Package,
    SystemConfig,
    SystemSetting,
    BankCard,
    NotificationTemplate,
    RenewTemplate,
    ManualReceipt,
    AutoApprovalWindow,
    Payment,
    Transaction,
    ClientOwnership,
    PanelAPI,
)


def _is_postgres_uri(uri: str) -> bool:
    u = (uri or '').strip().lower()
    return u.startswith('postgresql://') or u.startswith('postgres://')


def _sqlite_default_path() -> str:
    # Use the same location the app historically used
    return os.path.join(app.instance_path, 'servers.db')


def _connect_sqlite(path: str) -> sqlite3.Connection:
    if not os.path.exists(path):
        raise FileNotFoundError(f"SQLite DB not found: {path}")
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def _list_sqlite_tables(conn: sqlite3.Connection) -> set[str]:
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    return {r[0] for r in cur.fetchall()}


def _parse_datetime(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        # Heuristic: seconds vs ms
        try:
            ts = float(value)
            if ts > 10_000_000_000:  # ms
                ts = ts / 1000.0
            return datetime.fromtimestamp(ts)
        except Exception:
            return None
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        # common ISO formats
        try:
            return datetime.fromisoformat(s.replace('Z', '+00:00'))
        except Exception:
            pass
        # fallback: try without timezone
        for fmt in (
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f',
            '%Y-%m-%d',
        ):
            try:
                return datetime.strptime(s, fmt)
            except Exception:
                continue
    return None


def _normalize_row_for_model(row_dict: dict, model) -> dict:
    cols = {c.name: c for c in model.__table__.columns}
    out = {}
    for k, v in row_dict.items():
        if k not in cols:
            continue
        col = cols[k]
        # bool normalization
        try:
            is_bool = col.type.__class__.__name__.lower() == 'boolean'
        except Exception:
            is_bool = False
        if is_bool:
            if isinstance(v, str):
                out[k] = v.strip().lower() in ('1', 'true', 't', 'yes', 'y', 'on')
            else:
                out[k] = bool(v)
            continue

        # datetime normalization
        try:
            is_dt = col.type.__class__.__name__.lower() in ('datetime', 'datetimetime') or 'datetime' in col.type.__class__.__name__.lower()
        except Exception:
            is_dt = False
        if is_dt:
            out[k] = _parse_datetime(v)
            continue

        out[k] = v
    return out


def _fetch_sqlite_rows(conn: sqlite3.Connection, table: str) -> list[dict]:
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM {table}")
    rows = cur.fetchall()
    return [dict(r) for r in rows]


def _get_pk_name(model):
    pks = [c.name for c in model.__table__.columns if getattr(c, 'primary_key', False)]
    if len(pks) == 1:
        return pks[0]
    return None


def _upsert_rows(conn: sqlite3.Connection, table: str, model, *, update_existing: bool, match_field: str | None = None):
    rows = _fetch_sqlite_rows(conn, table)
    if not rows:
        print(f"ℹ️  {table}: 0 rows")
        return

    pk = _get_pk_name(model)
    inserted = 0
    updated = 0
    skipped = 0

    for row in rows:
        data = _normalize_row_for_model(row, model)
        if not data:
            skipped += 1
            continue

        existing = None
        if match_field and data.get(match_field) is not None:
            existing = db.session.query(model).filter(getattr(model, match_field) == data[match_field]).first()
        elif pk and data.get(pk) is not None:
            existing = db.session.get(model, data[pk])

        if existing is None:
            try:
                db.session.add(model(**data))
                inserted += 1
            except Exception:
                db.session.rollback()
                raise
        else:
            if not update_existing:
                skipped += 1
                continue
            try:
                # update all fields except primary key
                for k, v in data.items():
                    if pk and k == pk:
                        continue
                    setattr(existing, k, v)
                updated += 1
            except Exception:
                db.session.rollback()
                raise

    db.session.commit()

    # reset sequence if Postgres and integer id PK exists
    if pk == 'id':
        try:
            max_id = db.session.query(db.func.max(getattr(model, 'id'))).scalar() or 0
            seq = db.session.execute(text("SELECT pg_get_serial_sequence(:t, :c)"), {'t': table, 'c': 'id'}).scalar()
            if seq:
                db.session.execute(text(f"SELECT setval('{seq}', {int(max_id) + 1}, false)"))
                db.session.commit()
        except Exception:
            db.session.rollback()

    print(f"✅ {table}: inserted={inserted} updated={updated} skipped={skipped}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sqlite', dest='sqlite_path', default=None)
    parser.add_argument('--no-update-existing', dest='update_existing', action='store_false', default=True)
    args = parser.parse_args()

    db_uri = app.config.get('SQLALCHEMY_DATABASE_URI')
    if not _is_postgres_uri(db_uri):
        print("❌ Refusing to run: app is not configured for PostgreSQL (check DATABASE_URL).")
        print(f"   SQLALCHEMY_DATABASE_URI={db_uri}")
        return 2

    sqlite_path = args.sqlite_path or os.environ.get('SQLITE_DB_PATH') or _sqlite_default_path()
    print(f"🔎 SQLite source: {sqlite_path}")

    try:
        sqlite_conn = _connect_sqlite(sqlite_path)
    except Exception as e:
        print(f"❌ Cannot open SQLite DB: {e}")
        return 2

    tables = _list_sqlite_tables(sqlite_conn)

    plan = [
        # Core
        ('admins', Admin, None),
        ('servers', Server, None),
        ('panel_apis', PanelAPI, None),

        # Config/content (important to upsert)
        ('system_configs', SystemConfig, 'key'),
        ('system_settings', SystemSetting, 'key'),
        ('sub_app_configs', SubAppConfig, 'app_code'),
        ('faqs', FAQ, None),

        # Business
        ('packages', Package, None),
        ('bank_cards', BankCard, None),
        ('notification_templates', NotificationTemplate, None),
        ('renew_templates', RenewTemplate, None),
        ('auto_approval_windows', AutoApprovalWindow, None),
        ('manual_receipts', ManualReceipt, None),
        ('payments', Payment, None),
        ('transactions', Transaction, None),
        ('client_ownerships', ClientOwnership, None),
    ]

    with app.app_context():
        db.create_all()
        for table, model, match_field in plan:
            if table not in tables:
                print(f"ℹ️  {table}: missing in SQLite, skipping")
                continue
            try:
                _upsert_rows(
                    sqlite_conn,
                    table,
                    model,
                    update_existing=args.update_existing,
                    match_field=match_field,
                )
            except Exception as e:
                print(f"❌ Failed migrating {table}: {e}")
                return 1

    print("\n✨ Migration completed successfully.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
