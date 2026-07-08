"""Database engine, session, and additive migrations for poc-gen-verify.

Tables are created by `Base.metadata.create_all` on first init (fresh deployment);
the `_MIGRATIONS` list is kept for future additive ALTER columns. Mirrors dvs
`app/db/__init__.py`.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Generator, Literal

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import DBAPIError, InterfaceError, OperationalError
from sqlalchemy.orm import Session, sessionmaker

from .models import Base

logger = logging.getLogger("poc.db")

_engine = None
_SessionLocal = None


@dataclass(frozen=True)
class Migration:
    kind: Literal["column", "index", "table"]
    table_name: str
    name: str
    statement: str


# Fresh tables are created by create_all; this list is for future additive
# columns/indexes on existing deployments. Empty for now.
_MIGRATIONS: list[Migration] = []


def _migration_exists(engine, migration: Migration) -> bool:
    inspector = inspect(engine)
    table_names = inspector.get_table_names()
    if migration.kind == "table":
        return migration.table_name in table_names
    if migration.table_name not in table_names:
        return False
    if migration.kind == "column":
        return migration.name in {col["name"] for col in inspector.get_columns(migration.table_name)}
    return migration.name in {idx["name"] for idx in inspector.get_indexes(migration.table_name)}


def _run_migrations(engine) -> None:
    """Apply additive schema migrations; silently skips already-applied ones."""
    if not _MIGRATIONS:
        return
    with engine.connect() as conn:
        try:
            conn.execute(text("SET SESSION lock_wait_timeout = 5"))
        except Exception:
            conn.rollback()
        try:
            conn.execute(text("SET SESSION innodb_lock_wait_timeout = 5"))
        except Exception:
            conn.rollback()
        for migration in _MIGRATIONS:
            if _migration_exists(engine, migration):
                continue
            try:
                logger.info("Migration begin: %s", migration.statement[:120])
                conn.execute(text(migration.statement))
                conn.commit()
                logger.info("Migration applied: %s.%s", migration.table_name, migration.name)
            except Exception as exc:
                conn.rollback()
                logger.info("Migration skipped: %s (%s)", migration.statement[:120], exc)


def init_db(db_url: str, pool_size: int = 5, max_overflow: int = 10) -> None:
    """Initialize the database engine, create tables, run migrations."""
    global _engine, _SessionLocal
    logger.info("Database engine init begin")
    _engine = create_engine(
        db_url,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_pre_ping=True,
        pool_recycle=3600,
    )
    # Long-running PoC tasks keep objects alive for up to hours while the `poc`
    # CLI (claude + gdb) runs. Keep ORM instances usable after commit.
    _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine, expire_on_commit=False)
    logger.info("Database metadata create_all begin")
    # Concurrent process startup (e.g. worker + scheduler starting together) can
    # race create_all's checkfirst check → a TOCTOU "table already exists" (1050).
    # Retry once: by then the other process has created the table, checkfirst skips.
    for _attempt in range(2):
        try:
            Base.metadata.create_all(bind=_engine)
            break
        except OperationalError as exc:
            if "already exists" in str(exc).lower() and _attempt == 0:
                logger.info("create_all raced (table already exists); retrying")
                continue
            raise
    logger.info("Database metadata create_all done")
    _run_migrations(_engine)
    logger.info("Database initialized")


def is_retryable_db_error(exc: BaseException) -> bool:
    """Return True for transient MySQL/DBAPI disconnect/deadlock errors."""
    if isinstance(exc, (OperationalError, InterfaceError, DBAPIError)):
        t = str(exc).lower()
        return any(tok in t for tok in (
            "2006", "2013", "2014", "1205", "1213",
            "lost connection", "server has gone away", "connection reset",
            "connection refused", "broken pipe", "commands out of sync",
            "deadlock", "lock wait timeout",
        ))
    t = str(exc).lower()
    return any(tok in t for tok in ("lost connection", "server has gone away", "connection reset", "broken pipe"))


def ensure_db() -> None:
    """Init the DB engine/tables now if not already initialized.

    Called by `get_db()` lazily (so the worker/dispatcher processes retry on
    first use even if MySQL was not ready at import time) and by celery_app's
    `_ensure_db` at import. Safe to call repeatedly (no-op once initialized).
    """
    global _engine, _SessionLocal
    if _SessionLocal is not None:
        return
    from app.config import get_service_yaml
    svc = get_service_yaml()
    init_db(svc.database.url, svc.database.pool_size, svc.database.max_overflow)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that provides a DB session (lazy-inits the engine)."""
    if _SessionLocal is None:
        ensure_db()
    if _SessionLocal is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    db: Session = _SessionLocal()
    try:
        yield db
    finally:
        db.close()
