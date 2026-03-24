"""Database models for fileserver."""

import os
from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, create_engine
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker

from app.config import get_config


Base = declarative_base()


class FileSubproject(Base):
    __tablename__ = "secflow_fileserver_subproject"
    __table_args__ = (
        UniqueConstraint("project_id", "name", name="uk_fileserver_subproject_project_name"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(String(32), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    created_by = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    directories = relationship("FileDirectory", back_populates="subproject")
    files = relationship("ManagedFile", back_populates="subproject")


class FileDirectory(Base):
    __tablename__ = "secflow_fileserver_directory"
    __table_args__ = (
        UniqueConstraint("subproject_id", "parent_id", "name", name="uk_fileserver_directory_sibling_name"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(String(32), nullable=False, index=True)
    subproject_id = Column(Integer, ForeignKey("secflow_fileserver_subproject.id", ondelete="CASCADE"), nullable=False, index=True)
    parent_id = Column(Integer, ForeignKey("secflow_fileserver_directory.id", ondelete="CASCADE"), nullable=True, index=True)
    name = Column(String(255), nullable=False)
    path_key = Column(String(512), nullable=False, index=True)
    created_by = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    subproject = relationship("FileSubproject", back_populates="directories")
    parent = relationship("FileDirectory", remote_side=[id], backref="children")
    files = relationship("ManagedFile", back_populates="directory")


class ManagedFile(Base):
    __tablename__ = "secflow_fileserver_file"
    __table_args__ = (
        UniqueConstraint("subproject_id", "directory_id", "filename", name="uk_fileserver_file_directory_filename"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(String(32), nullable=False, index=True)
    subproject_id = Column(Integer, ForeignKey("secflow_fileserver_subproject.id", ondelete="CASCADE"), nullable=False, index=True)
    directory_id = Column(Integer, ForeignKey("secflow_fileserver_directory.id", ondelete="SET NULL"), nullable=True, index=True)
    filename = Column(String(255), nullable=False)
    original_filename = Column(String(255), nullable=False)
    content_type = Column(String(255), nullable=True)
    size = Column(BigInteger, nullable=False, default=0)
    sha256 = Column(String(64), nullable=False, index=True)
    storage_key = Column(String(512), nullable=False, unique=True)
    created_by = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    subproject = relationship("FileSubproject", back_populates="files")
    directory = relationship("FileDirectory", back_populates="files")


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


def ensure_storage_dirs():
    config = get_config()
    os.makedirs(config.storage.root_dir, exist_ok=True)
    os.makedirs(config.storage.temp_dir, exist_ok=True)
