"""
数据库模型模块
"""

from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    create_engine,
    select,
)
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker

from app.config import get_config

Base = declarative_base()


secflow_user_user_role = Table(
    "secflow_user_user_role",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("secflow_user_users.id"), primary_key=True),
    Column("role_id", Integer, ForeignKey("secflow_user_role.id"), primary_key=True),
)


class Role(Base):
    """用户角色模型。"""
    __tablename__ = "secflow_user_role"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    description = Column(String(500))


class Department(Base):
    """部门模型。"""
    __tablename__ = "secflow_org_department"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(String(500))
    parent_id = Column(Integer, ForeignKey("secflow_org_department.id"), nullable=True)

    parent = relationship("Department", remote_side=[id], backref="children")


class DepartmentMember(Base):
    """部门成员模型。"""
    __tablename__ = "secflow_org_department_member"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    department_id = Column(Integer, ForeignKey("secflow_org_department.id"), nullable=False, index=True)
    role = Column(String(20), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    department = relationship("Department", backref="memberships")


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
    is_public = Column(Boolean, default=False)  # 是否公开，False为私有，True为公开
    department_id = Column(Integer, ForeignKey("secflow_org_department.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # 关系
    role_binds = relationship("ProjectRoleBind", back_populates="project", lazy="joined")
    department = relationship("Department", lazy="joined")

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
            "is_public": self.is_public,
            "department_id": self.department_id,
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
