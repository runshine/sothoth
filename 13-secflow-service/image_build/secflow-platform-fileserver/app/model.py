"""Database models for fileserver."""

import os
from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, Boolean, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, create_engine, inspect, text
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


class ProjectInputUploadRecord(Base):
    __tablename__ = "secflow_fileserver_project_input_upload"

    upload_id = Column(String(64), primary_key=True)
    project_id = Column(String(32), nullable=False, index=True)
    input_type = Column(String(32), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="pending", index=True)
    display_name = Column(String(255), nullable=True)
    keep_original = Column(Boolean, nullable=False, default=False)
    source_archive_count = Column(Integer, nullable=False, default=0)
    stored_file_count = Column(Integer, nullable=False, default=0)
    stored_total_size_bytes = Column(BigInteger, nullable=False, default=0)
    target_path = Column(String(1024), nullable=False)
    last_error = Column(Text, nullable=True)
    created_by = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    finished_at = Column(DateTime, nullable=True)

    batches = relationship(
        "ProjectInputUploadBatch",
        back_populates="upload",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class ProjectInputUploadBatch(Base):
    __tablename__ = "secflow_fileserver_project_input_upload_batch"

    batch_id = Column(String(64), primary_key=True)
    upload_id = Column(String(64), ForeignKey("secflow_fileserver_project_input_upload.upload_id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="pending", index=True)
    mode = Column(String(32), nullable=False, default="create")
    keep_original = Column(Boolean, nullable=False, default=False)
    submitted_file_count = Column(Integer, nullable=False, default=0)
    processed_file_count = Column(Integer, nullable=False, default=0)
    processed_size_bytes = Column(BigInteger, nullable=False, default=0)
    error_summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    finished_at = Column(DateTime, nullable=True)

    upload = relationship("ProjectInputUploadRecord", back_populates="batches")


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
            pool_timeout=config.database.pool_timeout,
            pool_recycle=config.database.pool_recycle,
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
    _ensure_project_input_upload_columns(get_engine())


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


def _ensure_project_input_upload_columns(engine) -> None:
    table_name = ProjectInputUploadRecord.__tablename__
    columns = {column["name"] for column in inspect(engine).get_columns(table_name)}
    if "display_name" in columns:
        return
    with engine.begin() as connection:
        connection.execute(text(f"ALTER TABLE {table_name} ADD COLUMN display_name VARCHAR(255) NULL"))
