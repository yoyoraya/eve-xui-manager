#!/usr/bin/env python3
"""
Database Migration Script for Eve X-UI Manager
Handles schema updates between versions without data loss.
"""

import sqlite3
import os
import sys

# Database path
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'servers.db')

def get_db_connection():
    """Get database connection."""
    if not os.path.exists(DB_PATH):
        print(f"❌ Database not found at {DB_PATH}")
        print("   Run the application first to create the database.")
        return None
    return sqlite3.connect(DB_PATH)

def get_table_columns(conn, table_name):
    """Get list of column names for a table."""
    cursor = conn.execute(f"PRAGMA table_info({table_name})")
    return [row[1] for row in cursor.fetchall()]

def table_exists(conn, table_name):
    """Check if a table exists."""
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", 
        (table_name,)
    )
    return cursor.fetchone() is not None

def migration_v1_3_0(conn):
    """
    Migration for v1.3.0
    - Add 'platform' column to 'faqs' table
    """
    print("📦 Running migration for v1.3.0...")
    
    changes_made = False
    
    # Check if faqs table exists
    if table_exists(conn, 'faqs'):
        columns = get_table_columns(conn, 'faqs')
        
        # Add platform column if missing
        if 'platform' not in columns:
            print("   ➕ Adding 'platform' column to 'faqs' table...")
            conn.execute("ALTER TABLE faqs ADD COLUMN platform VARCHAR(20) DEFAULT 'android'")
            changes_made = True
            print("   ✅ Added 'platform' column")
        else:
            print("   ⏭️  'platform' column already exists in 'faqs'")
    else:
        print("   ⏭️  'faqs' table not found (will be created on first run)")
    
    return changes_made

def run_migrations():
    """Run all pending migrations."""
    print("\n🔄 Eve X-UI Manager - Database Migration")
    print("=" * 45)
    
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        changes_made = False
        
        # Run v1.3.0 migration
        if migration_v1_3_0(conn):
            changes_made = True
        
        # Add future migrations here:
        # if migration_v1_4_0(conn):
        #     changes_made = True
        
        if changes_made:
            conn.commit()
            print("\n✅ Database migration completed successfully!")
        else:
            print("\n✅ Database is already up to date!")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Migration error: {e}")
        conn.rollback()
        return False
        
    finally:
        conn.close()

if __name__ == "__main__":
    success = run_migrations()
    sys.exit(0 if success else 1)
