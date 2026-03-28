"""Database models for config center."""

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text, UniqueConstraint, create_engine
from sqlalchemy.dialects.mysql import JSON as MySQLJSON
from sqlalchemy.orm import Session, declarative_base, sessionmaker
from sqlalchemy.types import JSON

from app.config import get_config


Base = declarative_base()


class LlmProvider(Base):
    __tablename__ = "secflow_config_provider_llm"
    __table_args__ = (
        UniqueConstraint("provider_key", name="uk_config_provider_llm_provider_key"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    provider_key = Column(String(64), nullable=False, index=True)
    display_name = Column(String(128), nullable=False)
    provider_type = Column(String(64), nullable=False)
    enabled = Column(Boolean, nullable=False, default=True)
    is_default = Column(Boolean, nullable=False, default=False)
    api_base = Column(String(512), nullable=False)
    model = Column(String(256), nullable=False)
    api_key = Column(Text, nullable=False)
    organization = Column(String(256), nullable=True)
    api_version = Column(String(128), nullable=True)
    timeout_seconds = Column(Integer, nullable=False, default=60)
    max_tokens = Column(Integer, nullable=True)
    temperature = Column(Float, nullable=True)
    env_bindings = Column(JSON().with_variant(MySQLJSON, "mysql"), nullable=False, default=dict)
    extra_config = Column(JSON().with_variant(MySQLJSON, "mysql"), nullable=False, default=dict)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


_engine = None
_SessionFactory = None


def get_engine():
    global _engine
    if _engine is None:
        config = get_config()
        _engine = create_engine(
            config.database.url,
            pool_size=config.database.pool_size,
            max_overflow=config.database.max_overflow,
            pool_pre_ping=True,
        )
    return _engine


def get_session_factory():
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(autocommit=False, autoflush=False, bind=get_engine())
    return _SessionFactory


def init_database():
    Base.metadata.create_all(bind=get_engine())


def get_db():
    session_local = get_session_factory()
    db = session_local()
    try:
        yield db
    finally:
        db.close()


def get_db_session() -> Session:
    return get_session_factory()()
