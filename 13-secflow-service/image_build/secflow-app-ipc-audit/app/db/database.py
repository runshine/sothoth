from __future__ import annotations

import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Literal
from urllib.parse import unquote, urlparse

from app.core.config import get_config

try:
    import pymysql
    from pymysql.cursors import DictCursor
except ImportError:  # pragma: no cover - exercised only in mysql runtime
    pymysql = None
    DictCursor = None

DatabaseBackend = Literal["sqlite", "mysql"]


class DatabaseRow(Mapping[str, Any]):
    def __init__(self, keys: list[str], values: list[Any]) -> None:
        self._keys = tuple(keys)
        self._values = tuple(values)
        self._mapping = dict(zip(self._keys, self._values, strict=False))

    def __getitem__(self, key: object) -> Any:
        if isinstance(key, int):
            return self._values[key]
        return self._mapping[str(key)]

    def __iter__(self) -> Iterator[str]:
        return iter(self._mapping)

    def __len__(self) -> int:
        return len(self._mapping)


class DatabaseCursor:
    def __init__(
        self,
        native_cursor: Any | None,
        *,
        preset_rows: list[DatabaseRow] | None = None,
        rowcount: int = 0,
    ) -> None:
        self._native_cursor = native_cursor
        self._preset_rows = list(preset_rows or [])
        self.rowcount = rowcount

    def fetchone(self) -> DatabaseRow | None:
        if self._preset_rows:
            return self._preset_rows.pop(0)
        if self._native_cursor is None:
            return None
        return self._convert_row(self._native_cursor.fetchone())

    def fetchall(self) -> list[DatabaseRow]:
        if self._preset_rows:
            rows = list(self._preset_rows)
            self._preset_rows.clear()
            return rows
        if self._native_cursor is None:
            return []
        return [self._convert_row(row) for row in self._native_cursor.fetchall() if row is not None]

    def _convert_row(self, row: Any) -> DatabaseRow | None:
        if row is None:
            return None
        if isinstance(row, DatabaseRow):
            return row
        if isinstance(row, sqlite3.Row):
            keys = list(row.keys())
            return DatabaseRow(keys, [row[key] for key in keys])
        if isinstance(row, dict):
            keys = list(row.keys())
            return DatabaseRow(keys, [row[key] for key in keys])
        if isinstance(row, (tuple, list)):
            keys = [item[0] for item in self._native_cursor.description] if self._native_cursor else []
            return DatabaseRow(keys or [str(index) for index in range(len(row))], list(row))
        raise TypeError(f"unsupported database row type: {type(row)!r}")


class DatabaseConnection:
    def __init__(self, backend: DatabaseBackend, native_connection: Any) -> None:
        self.backend = backend
        self._native_connection = native_connection
        self._last_rowcount = 0

    def execute(self, sql: str, params: list[object] | tuple[object, ...] | None = None) -> DatabaseCursor:
        statement = str(sql or "")
        normalized = statement.strip().lower()
        if self.backend == "mysql" and normalized == "select changes()":
            return DatabaseCursor(
                None,
                preset_rows=[DatabaseRow(["changes()"], [self._last_rowcount])],
                rowcount=1,
            )
        actual_sql = statement
        if self.backend == "mysql":
            if normalized == "begin immediate":
                actual_sql = "START TRANSACTION"
            else:
                actual_sql = _replace_qmark_placeholders(statement)
            cursor = self._native_connection.cursor()
            cursor.execute(actual_sql, tuple(params or ()))
            self._last_rowcount = max(int(cursor.rowcount or 0), 0)
            return DatabaseCursor(cursor, rowcount=self._last_rowcount)
        cursor = self._native_connection.execute(actual_sql, tuple(params or ()))
        self._last_rowcount = max(int(cursor.rowcount or 0), 0)
        return DatabaseCursor(cursor, rowcount=self._last_rowcount)

    def executescript(self, script: str) -> None:
        if self.backend == "sqlite":
            self._native_connection.executescript(script)
            return
        for statement in _split_sql_script(script):
            cursor = self._native_connection.cursor()
            cursor.execute(statement)
            cursor.close()

    def commit(self) -> None:
        self._native_connection.commit()

    def rollback(self) -> None:
        self._native_connection.rollback()

    def close(self) -> None:
        self._native_connection.close()


class Database:
    def __init__(self) -> None:
        self.database_url = get_config().database_url
        self.backend, self._settings = _parse_database_url(self.database_url)
        migrations_dir = Path(__file__).resolve().parent / "migrations"
        self._sqlite_migration_sql = (migrations_dir / "0001_init.sql").read_text(encoding="utf-8")
        self._sqlite_dynamic_graph_migration_sql = (migrations_dir / "0002_dynamic_graph.sql").read_text(encoding="utf-8")
        self._sqlite_graph_template_migration_sql = (migrations_dir / "0003_graph_templates.sql").read_text(encoding="utf-8")
        self._mysql_migration_sql = (migrations_dir / "0001_init_mysql.sql").read_text(encoding="utf-8")
        self._mysql_graph_template_migration_sql = (migrations_dir / "0002_graph_templates_mysql.sql").read_text(encoding="utf-8")

    def initialize(self) -> None:
        if self.backend == "sqlite":
            db_path = self.sqlite_path
            db_path.parent.mkdir(parents=True, exist_ok=True)
            with self.connect() as conn:
                version = int(conn.execute("PRAGMA user_version").fetchone()[0])
                if version < 1:
                    conn.executescript(self._sqlite_migration_sql)
                    version = int(conn.execute("PRAGMA user_version").fetchone()[0])
                if version < 2:
                    conn.executescript(self._sqlite_dynamic_graph_migration_sql)
                    version = int(conn.execute("PRAGMA user_version").fetchone()[0])
                if version < 3:
                    conn.executescript(self._sqlite_graph_template_migration_sql)
            return
        with self.connect() as conn:
            if not self._table_exists(conn, "ipc_audit_tasks"):
                conn.executescript(self._mysql_migration_sql)
            self._upgrade_mysql_dynamic_graph_columns(conn)
            conn.executescript(self._mysql_graph_template_migration_sql)

    @property
    def sqlite_path(self) -> Path:
        if self.backend != "sqlite":
            raise ValueError(f"database backend is not sqlite: {self.backend}")
        raw_path = str(self._settings["path"])
        path = Path(raw_path)
        if not path.is_absolute():
            path = Path.cwd() / path
        return path.resolve()

    @contextmanager
    def connect(self) -> Iterator[DatabaseConnection]:
        if self.backend == "sqlite":
            native = sqlite3.connect(
                self.sqlite_path,
                timeout=5.0,
                isolation_level=None,
                check_same_thread=False,
            )
            native.row_factory = sqlite3.Row
            native.execute("PRAGMA journal_mode = WAL")
            native.execute("PRAGMA synchronous = NORMAL")
            native.execute("PRAGMA foreign_keys = ON")
            native.execute("PRAGMA busy_timeout = 5000")
            native.execute("PRAGMA temp_store = MEMORY")
        else:
            if pymysql is None or DictCursor is None:  # pragma: no cover - exercised only in mysql runtime
                raise RuntimeError("pymysql is required for mysql backend")
            native = pymysql.connect(
                host=str(self._settings["host"]),
                port=int(self._settings["port"]),
                user=str(self._settings["username"]),
                password=str(self._settings["password"]),
                database=str(self._settings["name"]),
                charset="utf8mb4",
                autocommit=True,
                connect_timeout=10,
                read_timeout=30,
                write_timeout=30,
                cursorclass=DictCursor,
            )
        wrapper = DatabaseConnection(self.backend, native)
        try:
            yield wrapper
        finally:
            wrapper.close()

    def _table_exists(self, conn: DatabaseConnection, table_name: str) -> bool:
        if self.backend == "sqlite":
            row = conn.execute(
                "select name from sqlite_master where type = 'table' and name = ?",
                (table_name,),
            ).fetchone()
            return row is not None
        row = conn.execute(
            """
            select table_name
            from information_schema.tables
            where table_schema = database() and table_name = ?
            limit 1
            """,
            (table_name,),
        ).fetchone()
        return row is not None

    def _upgrade_mysql_dynamic_graph_columns(self, conn: DatabaseConnection) -> None:
        if self.backend != "mysql":
            return
        statements = [
            "ALTER TABLE ipc_audit_tasks MODIFY COLUMN current_stage VARCHAR(128) NULL",
            "ALTER TABLE ipc_audit_stage_runs MODIFY COLUMN stage_name VARCHAR(128) NOT NULL",
            "ALTER TABLE ipc_audit_task_events MODIFY COLUMN stage_name VARCHAR(128) NULL",
            "ALTER TABLE ipc_audit_artifacts MODIFY COLUMN stage_name VARCHAR(128) NULL",
        ]
        for statement in statements:
            conn.execute(statement)


def _parse_database_url(url: str) -> tuple[DatabaseBackend, dict[str, object]]:
    value = str(url or "").strip()
    if value.startswith("sqlite:///"):
        return "sqlite", {"path": value[len("sqlite:///") :]}
    parsed = urlparse(value)
    if parsed.scheme not in {"mysql", "mysql+pymysql"}:
        raise ValueError(f"unsupported database url: {value}")
    return (
        "mysql",
        {
            "host": parsed.hostname or "localhost",
            "port": int(parsed.port or 3306),
            "username": unquote(parsed.username or "root"),
            "password": unquote(parsed.password or ""),
            "name": unquote(parsed.path.lstrip("/") or "secflow"),
        },
    )


def _replace_qmark_placeholders(sql: str) -> str:
    result: list[str] = []
    in_single = False
    in_double = False
    index = 0
    while index < len(sql):
        ch = sql[index]
        if ch == "'" and not in_double:
            in_single = not in_single
            result.append(ch)
            index += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            result.append(ch)
            index += 1
            continue
        if ch == "?" and not in_single and not in_double:
            result.append("%s")
            index += 1
            continue
        result.append(ch)
        index += 1
    return "".join(result)


def _split_sql_script(script: str) -> list[str]:
    statements: list[str] = []
    current: list[str] = []
    in_single = False
    in_double = False
    for ch in script:
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        if ch == ";" and not in_single and not in_double:
            statement = "".join(current).strip()
            if statement:
                statements.append(statement)
            current = []
            continue
        current.append(ch)
    tail = "".join(current).strip()
    if tail:
        statements.append(tail)
    return statements


_database: Database | None = None


def init_database() -> Database:
    global _database
    if _database is None:
        _database = Database()
    _database.initialize()
    return _database


def get_database() -> Database:
    return _database or init_database()
