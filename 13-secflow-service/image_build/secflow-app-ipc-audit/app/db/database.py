from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from app.core.config import get_sqlite_db_path


class Database:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._migration_sql = (
            Path(__file__).resolve().parent / "migrations" / "0001_init.sql"
        ).read_text(encoding="utf-8")

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            version = int(conn.execute("PRAGMA user_version").fetchone()[0])
            if version < 1:
                conn.executescript(self._migration_sql)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(
            self.db_path,
            timeout=5.0,
            isolation_level=None,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute("PRAGMA temp_store = MEMORY")
        try:
            yield conn
        finally:
            conn.close()


_database: Database | None = None


def init_database() -> Database:
    global _database
    if _database is None:
        _database = Database(get_sqlite_db_path())
    _database.initialize()
    return _database


def get_database() -> Database:
    return _database or init_database()

