"""
数据库模型模块
"""

from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    String,
    Text,
    Integer,
    JSON,
    create_engine,
    select,
)
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker

from app.config import get_config

Base = declarative_base()


class Project(Base):
    """项目模型 - 用于查询项目的K8S Namespace"""
    __tablename__ = "secflow_project"

    id = Column(String(32), primary_key=True)  # 16位MD5
    name = Column(String(128), nullable=False)
    description = Column(Text)
    owner_id = Column(String(64), nullable=False)
    owner_name = Column(String(128))
    k8s_namespace = Column(String(128))  # 关联的K8S Namespace名称
    status = Column(String(32), default="active")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "owner_id": self.owner_id,
            "owner_name": self.owner_name,
            "k8s_namespace": self.k8s_namespace,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def __repr__(self):
        return f"<Project(id={self.id}, name={self.name})>"


_engine = None
_SessionFactory = None


def get_engine():
    """获取数据库引擎"""
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
    """获取数据库会话工厂"""
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=get_engine()
        )
    return _SessionFactory


def init_database():
    """初始化数据库"""
    engine = get_engine()
    # 注意：不创建表，因为与project服务共享数据库
    # 表结构由project服务创建


def get_db():
    """获取数据库会话"""
    SessionLocal = get_session_factory()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_db_session() -> Session:
    """获取数据库会话（不使用生成器）"""
    SessionLocal = get_session_factory()
    return SessionLocal()


def get_project_by_id(db: Session, project_id: str) -> Optional[Project]:
    """根据ID获取项目"""
    return db.query(Project).filter(
        Project.id == project_id,
        Project.status == "active"
    ).first()


def get_project_namespace(db: Session, project_id: str) -> Optional[str]:
    """
    获取项目关联的K8S Namespace

    Args:
        db: 数据库会话
        project_id: 项目ID

    Returns:
        K8S Namespace名称，如果项目不存在返回None
    """
    project = get_project_by_id(db, project_id)
    if project:
        return project.k8s_namespace
    return None