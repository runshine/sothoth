from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Optional

from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine, inspect
from sqlalchemy.dialects.mysql import MEDIUMTEXT
from sqlalchemy.orm import Session, declarative_base, sessionmaker
from sqlalchemy.exc import OperationalError

from app.config import get_config

Base = declarative_base()
_engine = None
_SessionFactory = None


def now_utc() -> datetime:
    return datetime.utcnow()


def _prefix(name: str) -> str:
    return f"{get_config().database.table_prefix}{name}"


def _constraint_suffix(name: str) -> str:
    return hashlib.sha1(name.encode("utf-8", errors="surrogatepass")).hexdigest()[:8]


class ReviewJudgmentRun(Base):
    __tablename__ = _prefix("review_judgment_run")

    id = Column(String(64), primary_key=True)
    project_id = Column(String(64), nullable=False, index=True)
    run_name = Column(String(256), nullable=False)
    work_dir = Column(String(1024), nullable=False)
    session_dir = Column(String(1024), nullable=False)
    vuln_report_file = Column(String(1024), nullable=False)
    status = Column(String(32), nullable=False, default="pending", index=True)
    verdict = Column(String(32))
    severity = Column(String(32))
    confidence = Column(String(32))
    result_json = Column(MEDIUMTEXT)
    error_message = Column(Text)
    created_by = Column(String(64))
    created_at = Column(DateTime, nullable=False, default=now_utc)
    updated_at = Column(DateTime, nullable=False, default=now_utc)


TABLES = [ReviewJudgmentRun]


def get_engine():
    global _engine
    if _engine is not None:
        return _engine
    config = get_config().database
    _engine = create_engine(
        config.sqlalchemy_url,
        pool_size=config.pool_size,
        max_overflow=config.max_overflow,
        pool_timeout=config.pool_timeout,
        pool_pre_ping=True,
        pool_recycle=3600,
    )
    return _engine


def get_session_factory():
    global _SessionFactory
    if _SessionFactory is not None:
        return _SessionFactory
    _SessionFactory = sessionmaker(bind=get_engine())
    return _SessionFactory


def get_session() -> Session:
    return get_session_factory()()


def init_database(lock_timeout_seconds: int = 1, force: bool = False) -> bool:
    engine = get_engine()
    try:
        with engine.connect() as conn:
            conn.exec_driver_sql(f"SET SESSION lock_wait_timeout={int(lock_timeout_seconds)}")
            inspector = inspect(engine)
            existing_tables = set(inspector.get_table_names())
            required_tables = {t.__tablename__ for t in TABLES}
            if not force and existing_tables >= required_tables:
                return True
            Base.metadata.create_all(engine)
            return True
    except OperationalError:
        return False