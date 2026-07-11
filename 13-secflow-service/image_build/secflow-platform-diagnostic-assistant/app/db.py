from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .config import get_service_yaml


def _db_path() -> str:
    return get_service_yaml().database.sqlite_path


def init_db() -> None:
    Path(_db_path()).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(_db_path()) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS diagnostic_session (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                agent_session_id TEXT,
                agent_id TEXT,
                session_mode TEXT
            );

            CREATE TABLE IF NOT EXISTS diagnostic_message (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(session_id) REFERENCES diagnostic_session(id)
            );

            CREATE TABLE IF NOT EXISTS diagnostic_execution (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                message_id INTEGER,
                command_text TEXT NOT NULL,
                stdout TEXT NOT NULL,
                stderr TEXT NOT NULL,
                exit_code INTEGER NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                FOREIGN KEY(session_id) REFERENCES diagnostic_session(id),
                FOREIGN KEY(message_id) REFERENCES diagnostic_message(id)
            );

            CREATE TABLE IF NOT EXISTS diagnostic_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                session_id INTEGER,
                action_type TEXT NOT NULL,
                request_text TEXT NOT NULL,
                command_text TEXT,
                result_summary TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS diagnostic_agent_run (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                user_message_id INTEGER,
                assistant_message_id INTEGER,
                agent_id TEXT NOT NULL,
                agent_session_id TEXT,
                upstream_response_id TEXT,
                task_text TEXT NOT NULL,
                final_text TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                finished_at TEXT,
                FOREIGN KEY(session_id) REFERENCES diagnostic_session(id),
                FOREIGN KEY(user_message_id) REFERENCES diagnostic_message(id),
                FOREIGN KEY(assistant_message_id) REFERENCES diagnostic_message(id)
            );

            CREATE TABLE IF NOT EXISTS diagnostic_agent_event (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(run_id) REFERENCES diagnostic_agent_run(id)
            );
            """
        )
        _ensure_column(conn, "diagnostic_session", "agent_session_id", "TEXT")
        _ensure_column(conn, "diagnostic_session", "agent_id", "TEXT")
        _ensure_column(conn, "diagnostic_session", "session_mode", "TEXT")


def _ensure_column(conn: sqlite3.Connection, table_name: str, column_name: str, column_def: str) -> None:
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    existing = {str(row[1]) for row in rows}
    if column_name in existing:
        return
    conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_def}")


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(_db_path())
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
