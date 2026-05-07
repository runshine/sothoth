#!/usr/bin/env python3
"""Idempotent schema migration for source task support."""

from __future__ import annotations

import argparse
from typing import Iterable

import pymysql


TASK_TABLE = "secflow_binary_security_task"

ALTERS: list[tuple[str, str, str | None]] = [
    ("dispatcher_instance_id", "ALTER TABLE secflow_binary_security_task ADD COLUMN dispatcher_instance_id VARCHAR(128) NULL", "idx_secflow_binary_security_task_dispatcher_instance_id"),
    ("dispatch_started_at", "ALTER TABLE secflow_binary_security_task ADD COLUMN dispatch_started_at DATETIME NULL", "idx_secflow_binary_security_task_dispatch_started_at"),
    ("task_type", "ALTER TABLE secflow_binary_security_task ADD COLUMN task_type VARCHAR(32) NOT NULL DEFAULT 'binary'", "idx_secflow_binary_security_task_task_type"),
    ("execution_mode", "ALTER TABLE secflow_binary_security_task ADD COLUMN execution_mode VARCHAR(32) NULL", "idx_secflow_binary_security_task_execution_mode"),
    ("target_stage_name", "ALTER TABLE secflow_binary_security_task ADD COLUMN target_stage_name VARCHAR(64) NULL", "idx_secflow_binary_security_task_target_stage_name"),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Add source-task compatible columns to secflow_binary_security_task.")
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
        (TASK_TABLE,),
    )
    return {row[0] for row in cursor.fetchall()}


def fetch_index_names(cursor) -> set[str]:
    cursor.execute(
        """
        SELECT INDEX_NAME
        FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s
        """,
        (TASK_TABLE,),
    )
    return {row[0] for row in cursor.fetchall()}


def ensure_indexes(cursor, existing_columns: Iterable[str], existing_indexes: set[str]) -> None:
    desired = {
        "dispatcher_instance_id": "idx_secflow_binary_security_task_dispatcher_instance_id",
        "dispatch_started_at": "idx_secflow_binary_security_task_dispatch_started_at",
        "task_type": "idx_secflow_binary_security_task_task_type",
        "execution_mode": "idx_secflow_binary_security_task_execution_mode",
        "target_stage_name": "idx_secflow_binary_security_task_target_stage_name",
    }
    for column_name in existing_columns:
        index_name = desired.get(column_name)
        if not index_name or index_name in existing_indexes:
            continue
        cursor.execute(f"CREATE INDEX {index_name} ON {TASK_TABLE} ({column_name})")


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
            for column_name, sql, _ in ALTERS:
                if column_name in columns:
                    continue
                cursor.execute(sql)
                columns.add(column_name)
            indexes = fetch_index_names(cursor)
            ensure_indexes(cursor, columns, indexes)
        conn.commit()
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
