#!/usr/bin/env python3
"""
Database Migration Script for Eve X-UI Manager
Handles schema updates between versions without data loss.
"""

import sqlite3
import os
import sys

# Path to DB (usually in instance)
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'servers.db')


def _is_postgres_env() -> bool:
    db_url = (os.environ.get('DATABASE_URL') or '').strip().lower()
    return db_url.startswith('postgresql://') or db_url.startswith('postgres://')


def fix_database():
    if not os.path.exists(DB_PATH):
        print(f"❌ Database file not found at: {DB_PATH}")
        print("   Make sure the application has been run to create the database.")
        return False

    print(f"🔧 Connecting to database: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    try:
        # helper
        def column_exists(table, column):
            try:
                c.execute(f"PRAGMA table_info({table})")
                return any(row[1] == column for row in c.fetchall())
            except Exception:
                return False

        # 1) Ensure admin columns
        admin_columns = [
            ('telegram_id', 'VARCHAR(100)'),
            ('discount_percent', 'INTEGER DEFAULT 0'),
            ('custom_cost_per_day', 'INTEGER'),
            ('custom_cost_per_gb', 'INTEGER')
        ]
        c.execute("PRAGMA table_info(admins)")
        for col_name, col_type in admin_columns:
            if not column_exists('admins', col_name):
                try:
                    c.execute(f"ALTER TABLE admins ADD COLUMN {col_name} {col_type}")
                    print(f"✅ Added '{col_name}' to admins table.")
                except Exception as e:
                    print(f"⚠️  Error adding {col_name}: {e}")
            else:
                print(f"ℹ️  '{col_name}' already exists in admins.")

        # 2) Ensure os_type on sub_app_configs
        if not column_exists('sub_app_configs', 'os_type'):
            try:
                c.execute("ALTER TABLE sub_app_configs ADD COLUMN os_type VARCHAR(20) DEFAULT 'android'")
                print("✅ Added 'os_type' to sub_app_configs table.")
            except Exception as e:
                print(f"⚠️  Error adding os_type: {e}")
        else:
            print("ℹ️  'os_type' already exists in sub_app_configs.")

        # 3) Create faqs table if missing
        try:
            c.execute('''
            CREATE TABLE IF NOT EXISTS faqs (
                id INTEGER PRIMARY KEY,
                title VARCHAR(200) NOT NULL,
                content TEXT,
                image_url VARCHAR(500),
                video_url VARCHAR(500),
                platform VARCHAR(20) DEFAULT 'android',
                is_enabled BOOLEAN DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            print("✅ Table 'faqs' checked/created.")
        except Exception as e:
            print(f"⚠️  Error creating faqs table: {e}")

        # 4) Create system_settings table if missing
        try:
            c.execute('''
            CREATE TABLE IF NOT EXISTS system_settings (
                key VARCHAR(50) PRIMARY KEY,
                value TEXT
            )
            ''')
            print("✅ Table 'system_settings' checked/created.")
        except Exception as e:
            print(f"⚠️  Error creating system_settings table: {e}")

        # 4b) Create system_configs table if missing (used for app config like support + channels)
        try:
            c.execute('''
            CREATE TABLE IF NOT EXISTS system_configs (
                key VARCHAR(50) PRIMARY KEY,
                value TEXT
            )
            ''')
            print("✅ Table 'system_configs' checked/created.")
        except Exception as e:
            print(f"⚠️  Error creating system_configs table: {e}")

        # 5) Create payments table if missing
        try:
            c.execute('''
            CREATE TABLE IF NOT EXISTS payments (
                id INTEGER PRIMARY KEY,
                admin_id INTEGER NOT NULL REFERENCES admins(id),
                card_id INTEGER REFERENCES bank_cards(id),
                sender_card VARCHAR(32),
                sender_name VARCHAR(120),
                amount INTEGER NOT NULL,
                payment_date DATETIME NOT NULL,
                client_email VARCHAR(100),
                description TEXT,
                verified BOOLEAN DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            print("✅ Table 'payments' checked/created.")
        except Exception as e:
            print(f"⚠️  Error creating payments table: {e}")

        # 6) Ensure transactions columns
        transaction_columns = [
            ('server_id', 'INTEGER REFERENCES servers(id)'),
            ('card_id', 'INTEGER REFERENCES bank_cards(id)'),
            ('sender_card', 'VARCHAR(32)'),
            ('sender_name', 'VARCHAR(120)'),
            ('client_email', 'VARCHAR(100)'),
            ('category', "VARCHAR(16) NOT NULL DEFAULT 'usage'")
        ]
        for col_name, col_type in transaction_columns:
            if not column_exists('transactions', col_name):
                try:
                    c.execute(f"ALTER TABLE transactions ADD COLUMN {col_name} {col_type}")
                    print(f"✅ Added '{col_name}' to transactions table.")
                except Exception as e:
                    print(f"⚠️  Error adding {col_name}: {e}")
            else:
                print(f"ℹ️  '{col_name}' already exists in transactions.")

        # 7) Create renew_templates table if missing
        try:
            c.execute('''
            CREATE TABLE IF NOT EXISTS renew_templates (
                id INTEGER PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                content TEXT NOT NULL,
                is_active BOOLEAN DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            print("✅ Table 'renew_templates' checked/created.")
        except Exception as e:
            print(f"⚠️  Error creating renew_templates table: {e}")

        conn.commit()
        conn.close()
        print("\n🚀 Database repair completed! You can now restart your app.")
        return True

    except Exception as e:
        print(f"\n❌ Migration error: {e}")
        try:
            conn.rollback()
            conn.close()
        except Exception:
            pass
        return False


if __name__ == "__main__":
    if _is_postgres_env():
        print("ℹ️  DATABASE_URL points to PostgreSQL; skipping SQLite migrations.py")
        sys.exit(0)

    print("\n🔄 Eve X-UI Manager - Database Migration")
    print("=" * 45)
    success = fix_database()
    sys.exit(0 if success else 1)
