#!/usr/bin/env python3
"""Drop legacy owner/lease columns from secflow_binary_security_task_operation."""

from __future__ import annotations

import argparse

import pymysql


TABLE = "secflow_binary_security_task_operation"
COLUMNS = (
    "owner_instance_id",
    "claim_lease_expires_at",
    "heartbeat_at",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Drop legacy owner/lease columns from secflow_binary_security_task_operation.")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=3306)
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--database", required=True)
    return parser.parse_args()


def fetch_column_names(cursor) -> set[str]:
    cursor.execute(
        """
        SELECT COLUMN_NAME
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s
        """,
        (TABLE,),
    )
    return {row[0] for row in cursor.fetchall()}


def fetch_indexes_by_column(cursor) -> dict[str, set[str]]:
    cursor.execute(
        """
        SELECT COLUMN_NAME, INDEX_NAME
        FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s
        """,
        (TABLE,),
    )
    mapping: dict[str, set[str]] = {}
    for column_name, index_name in cursor.fetchall():
        mapping.setdefault(str(column_name), set()).add(str(index_name))
    return mapping


def main() -> int:
    args = parse_args()
    conn = pymysql.connect(
        host=args.host,
        port=args.port,
        user=args.user,
        password=args.password,
        database=args.database,
        charset="utf8mb4",
        autocommit=False,
    )
    try:
        with conn.cursor() as cursor:
            columns = fetch_column_names(cursor)
            indexes_by_column = fetch_indexes_by_column(cursor)
            for column_name in COLUMNS:
                for index_name in sorted(indexes_by_column.get(column_name, set())):
                    if index_name == "PRIMARY":
                        continue
                    cursor.execute(f"DROP INDEX {index_name} ON {TABLE}")
                if column_name in columns:
                    cursor.execute(f"ALTER TABLE {TABLE} DROP COLUMN {column_name}")
                    columns.remove(column_name)
        conn.commit()
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
