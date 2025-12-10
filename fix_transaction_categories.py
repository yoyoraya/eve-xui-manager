#!/usr/bin/env python3
"""
Migration script to set category for existing transactions based on type and amount.

Rules:
- type='deposit' or type='payment' or type='receipt' -> category='income' (positive income)
- type='renew' or type='reset_traffic' or type='add_client' -> category='usage' (reseller using credit)
- type='manual_debit' -> category='expense' (negative expense)
- If no type: amount >= 0 -> 'income', amount < 0 -> 'expense'
"""

import os
import sys
import sqlite3

# Get database path
instance_path = os.path.join(os.path.dirname(__file__), 'instance')
db_path = os.path.join(instance_path, 'servers.db')

if not os.path.exists(db_path):
    print(f"❌ Database not found: {db_path}")
    sys.exit(1)

print(f"🔧 Connecting to database: {db_path}")

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

try:
    # Get all transactions without category or with category=NULL or category=''
    cursor.execute("""
        SELECT id, type, amount, category 
        FROM transactions 
        WHERE category IS NULL OR category = '' OR category = 'usage'
    """)
    
    transactions = cursor.fetchall()
    
    if not transactions:
        print("✅ All transactions already have proper categories!")
        conn.close()
        sys.exit(0)
    
    print(f"📊 Found {len(transactions)} transactions to update")
    
    updated = 0
    
    for tx_id, tx_type, amount, current_category in transactions:
        new_category = None
        
        # Determine category based on type
        if tx_type in ['deposit', 'payment', 'receipt', 'manual_receipt']:
            new_category = 'income'  # Real income
        elif tx_type in ['renew', 'reset_traffic', 'add_client']:
            new_category = 'usage'   # Reseller using credit (not real income)
        elif tx_type == 'manual_debit':
            new_category = 'expense'  # Expense/cost
        else:
            # Fallback: based on amount
            if amount >= 0:
                new_category = 'income'
            else:
                new_category = 'expense'
        
        # Update the transaction
        cursor.execute("""
            UPDATE transactions 
            SET category = ? 
            WHERE id = ?
        """, (new_category, tx_id))
        updated += 1
    
    conn.commit()
    print(f"✅ Updated {updated} transactions with proper categories")
    print("🚀 Migration completed successfully!")
    
except Exception as e:
    conn.rollback()
    print(f"❌ Error during migration: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
finally:
    conn.close()
