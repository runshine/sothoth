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
    create_engine,
    select,
)
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker

from app.config import get_config

Base = declarative_base()


class Project(Base):
    """项目模型"""
    __tablename__ = "secflow_project"

    id = Column(String(32), primary_key=True)  # 16位MD5
    name = Column(String(128), nullable=False)
    description = Column(Text)
    owner_id = Column(String(64), nullable=False)  # 所有者用户ID
    owner_name = Column(String(128))  # 所有者名称
    k8s_namespace = Column(String(128))  # 关联的K8S Namespace名称
    status = Column(String(32), default="active")  # active, deleted
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # 关系
    role_binds = relationship("ProjectRoleBind", back_populates="project", lazy="joined")

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


class ProjectRoleBind(Base):
    """项目-角色关联模型"""
    __tablename__ = "secflow_project_role_bind"

    id = Column(String(32), primary_key=True)  # 16位MD5
    project_id = Column(String(32), ForeignKey("secflow_project.id"), nullable=False)
    user_id = Column(String(64), nullable=False)  # 用户ID
    role = Column(String(32), nullable=False)  # 角色：owner, admin, member
    created_at = Column(DateTime, default=datetime.utcnow)

    # 关系
    project = relationship("Project", back_populates="role_binds")

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "id": self.id,
            "project_id": self.project_id,
            "user_id": self.user_id,
            "role": self.role,
            "created_at": self.created_at,
        }

    def __repr__(self):
        return f"<ProjectRoleBind(project_id={self.project_id}, user_id={self.user_id}, role={self.role})>"


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
    Base.metadata.create_all(bind=engine)


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


def get_project_role_binds(db: Session, project_id: str) -> List[ProjectRoleBind]:
    """获取项目的角色绑定列表"""
    return db.query(ProjectRoleBind).filter(
        ProjectRoleBind.project_id == project_id
    ).all()