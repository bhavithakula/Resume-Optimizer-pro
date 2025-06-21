#!/usr/bin/env python3
"""
Database Schema Fix Script
Adds missing columns to optimization_results table
"""

import sqlite3
import os

def fix_database_schema():
    """Add missing columns to the optimization_results table"""
    
    db_path = 'ResumeOptimizerDB.sqlite'
    
    if not os.path.exists(db_path):
        print(f"❌ Database file {db_path} not found!")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check current schema
        cursor.execute("PRAGMA table_info(optimization_results)")
        columns = [col[1] for col in cursor.fetchall()]
        print(f"📋 Current columns in optimization_results: {columns}")
        
        # List of columns that should exist
        required_columns = {
            'improvement_percentage': 'REAL',
            'total_keywords': 'INTEGER', 
            'keyword_density': 'REAL',
            'optimization_version': 'INTEGER DEFAULT 1',
            'processing_time_seconds': 'REAL'
        }
        
        # Add missing columns
        added_columns = []
        for column_name, column_type in required_columns.items():
            if column_name not in columns:
                try:
                    alter_sql = f"ALTER TABLE optimization_results ADD COLUMN {column_name} {column_type}"
                    cursor.execute(alter_sql)
                    added_columns.append(column_name)
                    print(f"✅ Added column: {column_name} ({column_type})")
                except sqlite3.OperationalError as e:
                    print(f"❌ Failed to add column {column_name}: {e}")
        
        if added_columns:
            conn.commit()
            print(f"\n🎉 Successfully added {len(added_columns)} columns: {', '.join(added_columns)}")
        else:
            print("\n✨ All required columns already exist!")
        
        # Show final schema
        cursor.execute("PRAGMA table_info(optimization_results)")
        final_columns = [col[1] for col in cursor.fetchall()]
        print(f"\n📋 Final columns in optimization_results: {final_columns}")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Error fixing database schema: {e}")
        return False

def check_other_tables():
    """Check if other tables need updates based on enhanced_schema.sql"""
    
    db_path = 'ResumeOptimizerDB.sqlite'
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if enhanced tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing_tables = [row[0] for row in cursor.fetchall()]
        
        required_tables = [
            'user_auth', 'user_analytics', 'site_analytics', 'companies',
            'application_timeline', 'download_history', 'system_settings',
            'user_sessions'
        ]
        
        missing_tables = [table for table in required_tables if table not in existing_tables]
        
        if missing_tables:
            print(f"\n⚠️  Missing tables detected: {', '.join(missing_tables)}")
            print("💡 You may want to run the enhanced schema creation script.")
        else:
            print(f"\n✅ All enhanced tables exist: {', '.join(required_tables)}")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Error checking tables: {e}")

if __name__ == "__main__":
    print("🔧 Resume Optimizer Database Schema Fix")
    print("=" * 50)
    
    success = fix_database_schema()
    check_other_tables()
    
    if success:
        print("\n🎯 Database schema has been updated!")
        print("💡 You can now restart your application.")
    else:
        print("\n❌ Failed to update database schema.")
        print("💡 Please check the error messages above.") 