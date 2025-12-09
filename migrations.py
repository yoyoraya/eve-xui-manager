#!/usr/bin/env python3
"""
Database Migration Script for Eve X-UI Manager
Handles schema updates between versions without data loss.
"""

import sqlite3
import os
import sys

# مسیر دیتابیس (معمولا در پوشه instance است)
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'servers.db')

def fix_database():
    if not os.path.exists(DB_PATH):
        print(f"❌ Database file not found at: {DB_PATH}")
        print("   Make sure the application has been run to create the database.")
        return False

    print(f"🔧 Connecting to database: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    try:
        # 1. افزودن ستون telegram_id به جدول admins
        try:
            c.execute("ALTER TABLE admins ADD COLUMN telegram_id VARCHAR(100)")
            print("✅ Added 'telegram_id' to admins table.")
        except sqlite3.OperationalError as e:
            if "duplicate column" in str(e).lower():
                print("ℹ️  'telegram_id' already exists in admins.")
            else:
                print(f"⚠️  Error adding telegram_id: {e}")

        # 2. افزودن ستون os_type به جدول sub_app_configs (مشکل اصلی کرش شما)
        try:
            c.execute("ALTER TABLE sub_app_configs ADD COLUMN os_type VARCHAR(20) DEFAULT 'android'")
            print("✅ Added 'os_type' to sub_app_configs table.")
        except sqlite3.OperationalError as e:
            if "duplicate column" in str(e).lower():
                print("ℹ️  'os_type' already exists in sub_app_configs.")
            else:
                print(f"⚠️  Error adding os_type: {e}")

        # 3. ساخت جدول faqs (اگر وجود ندارد)
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

        # 4. ساخت جدول system_settings (اگر وجود ندارد)
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

        # 5. افزودن ستون server_id به جدول transactions
        try:
            c.execute("ALTER TABLE transactions ADD COLUMN server_id INTEGER REFERENCES servers(id)")
            print("✅ Added 'server_id' to transactions table.")
        except sqlite3.OperationalError as e:
            if "duplicate column" in str(e).lower():
                print("ℹ️  'server_id' already exists in transactions.")
            else:
                print(f"⚠️  Error adding server_id: {e}")

        # 6. افزودن ستون card_id به جدول transactions
        try:
            c.execute("ALTER TABLE transactions ADD COLUMN card_id INTEGER REFERENCES bank_cards(id)")
            print("✅ Added 'card_id' to transactions table.")
        except sqlite3.OperationalError as e:
            if "duplicate column" in str(e).lower():
                print("ℹ️  'card_id' already exists in transactions.")
            else:
                print(f"⚠️  Error adding card_id: {e}")

        # 7. افزودن ستون sender_card به جدول transactions
        try:
            c.execute("ALTER TABLE transactions ADD COLUMN sender_card VARCHAR(32)")
            print("✅ Added 'sender_card' to transactions table.")
        except sqlite3.OperationalError as e:
            if "duplicate column" in str(e).lower():
                print("ℹ️  'sender_card' already exists in transactions.")
            else:
                print(f"⚠️  Error adding sender_card: {e}")

        # 8. ساخت جدول payments (پرداخت‌های دریافتی)
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

        conn.commit()
        conn.close()
        print("\n🚀 Database repair completed! You can now restart your app.")
        return True

    except Exception as e:
        print(f"\n❌ Migration error: {e}")
        conn.rollback()
        conn.close()
        return False

if __name__ == "__main__":
    print("\n🔄 Eve X-UI Manager - Database Migration")
    print("=" * 45)
    success = fix_database()
    sys.exit(0 if success else 1)
