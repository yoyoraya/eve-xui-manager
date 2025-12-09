
import sqlite3
import os

DB_PATH = 'instance/servers.db'

def add_column():
    if not os.path.exists(DB_PATH):
        print("Database not found.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Check if column exists
        cursor.execute("PRAGMA table_info(sub_app_configs)")
        columns = [info[1] for info in cursor.fetchall()]
        
        if 'os_type' not in columns:
            print("Adding os_type column...")
            cursor.execute("ALTER TABLE sub_app_configs ADD COLUMN os_type TEXT DEFAULT 'android'")
            conn.commit()
            print("Column added successfully.")
        else:
            print("Column os_type already exists.")
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    add_column()
