#!/usr/bin/env python3
"""
Database Migration Script
Add has_warning and init_logs fields

Usage:
    python scripts/migrate_add_init_logs.py
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.models.database import get_engine, TABLE_PREFIX
from app.config import get_config


def run_migration():
    """Run the migration to add new fields"""
    engine = get_engine()

    workflow_instance_table = f"{TABLE_PREFIX}workflow_instance"
    workflow_node_instance_table = f"{TABLE_PREFIX}workflow_node_instance"

    print(f"Table prefix: {TABLE_PREFIX}")
    print(f"Workflow instance table: {workflow_instance_table}")
    print(f"Workflow node instance table: {workflow_node_instance_table}")
    print()

    with engine.connect() as conn:
        # 1. Add has_warning column to workflow_instance table
        print(f"Adding has_warning column to {workflow_instance_table}...")
        try:
            conn.execute(text(f"""
                ALTER TABLE {workflow_instance_table}
                ADD COLUMN has_warning TINYINT(1) DEFAULT 0
            """))
            conn.commit()
            print("  Success: has_warning column added")
        except Exception as e:
            if "Duplicate column" in str(e) or "already exists" in str(e).lower():
                print("  Info: has_warning column already exists, skipping")
            else:
                print(f"  Error: {e}")
                raise

        # 2. Add init_logs column to workflow_node_instance table
        print(f"Adding init_logs column to {workflow_node_instance_table}...")
        try:
            conn.execute(text(f"""
                ALTER TABLE {workflow_node_instance_table}
                ADD COLUMN init_logs TEXT
            """))
            conn.commit()
            print("  Success: init_logs column added")
        except Exception as e:
            if "Duplicate column" in str(e) or "already exists" in str(e).lower():
                print("  Info: init_logs column already exists, skipping")
            else:
                print(f"  Error: {e}")
                raise

    print()
    print("Migration completed successfully!")


if __name__ == "__main__":
    try:
        run_migration()
    except Exception as e:
        print(f"Migration failed: {e}")
        sys.exit(1)
