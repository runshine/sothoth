"""
Code Server Manager - 数据库模型
"""

import enum
import hashlib
import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    Column,
    DateTime,
    String,
    Text,
    Integer,
    Enum as SQLEnum,
    JSON,
    create_engine,
    inspect,
    text,
)
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from app.config import get_config

Base = declarative_base()


class CodeServerStatus(str, enum.Enum):
    """Code Server状态"""
    PENDING = "pending"          # 等待创建
    CREATING = "creating"        # 创建中
    RUNNING = "running"          # 运行中
    STOPPED = "stopped"          # 已停止
    ERROR = "error"              # 错误
    DELETING = "deleting"        # 删除中
    DELETED = "deleted"          # 已删除


class TaskStatus(str, enum.Enum):
    """任务状态"""
    PENDING = "pending"          # 等待执行
    RUNNING = "running"          # 执行中
    COMPLETED = "completed"      # 已完成
    FAILED = "failed"            # 失败
    CANCELLED = "cancelled"      # 已取消


class TaskType(str, enum.Enum):
    """任务类型"""
    CREATE = "create"            # 创建Code Server
    DELETE = "delete"            # 删除Code Server
    RESTART = "restart"          # 重建Code Server


class CodeServer(Base):
    """Code Server实例模型"""
    __tablename__ = "code_servers"

    id = Column(String(32), primary_key=True)
    project_id = Column(String(32), nullable=False, index=True)
    name = Column(String(64), nullable=False)
    namespace = Column(String(128), nullable=False)
    status = Column(String(32), default=CodeServerStatus.PENDING.value)

    # PVC配置 (JSON格式)
    source_pvcs = Column(JSON, default=list)      # 源码PVC列表 [{"pvc_name": "...", "mount_path": "..."}]
    output_pvcs = Column(JSON, default=list)      # 输出PVC列表 [{"pvc_name": "...", "mount_path": "...", "created": true/false}]

    # K8S资源
    deployment_name = Column(String(128))
    service_name = Column(String(128))
    ingress_name = Column(String(128))
    pod_name = Column(String(128))

    # 访问信息
    access_url = Column(String(256))

    # 环境变量配置
    custom_env = Column(JSON, default=dict)          # 自定义环境变量
    code_server_env = Column(JSON, default=dict)     # Code Server镜像环境变量配置
    llm_provider_key = Column(String(128))
    llm_provider_snapshot = Column(JSON, default=dict)
    llm_provider_mapped_env_keys = Column(JSON, default=list)
    llm_file_bindings = Column(JSON, default=list)
    llm_configmap_name = Column(String(128))

    # 元数据
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    deleted_at = Column(DateTime)

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "id": self.id,
            "project_id": self.project_id,
            "name": self.name,
            "namespace": self.namespace,
            "status": self.status,
            "source_pvcs": self.source_pvcs or [],
            "output_pvcs": self.output_pvcs or [],
            "deployment_name": self.deployment_name,
            "service_name": self.service_name,
            "ingress_name": self.ingress_name,
            "pod_name": self.pod_name,
            "access_url": self.access_url,
            "custom_env": self.custom_env or {},
            "code_server_env": self.code_server_env or {},
            "llm_provider_key": self.llm_provider_key,
            "llm_provider_snapshot": self.llm_provider_snapshot or {},
            "llm_provider_mapped_env_keys": self.llm_provider_mapped_env_keys or [],
            "llm_file_bindings": self.llm_file_bindings or [],
            "llm_configmap_name": self.llm_configmap_name,
            "description": self.description,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self):
        return f"<CodeServer(id={self.id}, name={self.name}, status={self.status})>"


class Task(Base):
    """异步任务模型"""
    __tablename__ = "tasks"

    id = Column(String(32), primary_key=True)
    project_id = Column(String(32), nullable=False, index=True)
    type = Column(String(32), nullable=False)  # create, delete, restart
    status = Column(String(32), default=TaskStatus.PENDING.value)

    # 关联的Code Server
    code_server_id = Column(String(32), nullable=True)
    code_server_name = Column(String(64), nullable=True)

    # 任务参数 (JSON格式)
    params = Column(JSON, default=dict)

    # 执行结果
    result = Column(Text)
    error_message = Column(Text)

    # 时间记录
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "id": self.id,
            "project_id": self.project_id,
            "type": self.type,
            "status": self.status,
            "code_server_id": self.code_server_id,
            "code_server_name": self.code_server_name,
            "params": self.params or {},
            "result": self.result,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }

    def __repr__(self):
        return f"<Task(id={self.id}, type={self.type}, status={self.status})>"


_engine = None
_SessionFactory = None


def get_engine():
    """获取数据库引擎"""
    global _engine
    if _engine is None:
        config = get_config()
        engine_kwargs = {
            "pool_pre_ping": True,
            "connect_args": {"check_same_thread": False} if config.database.type == "sqlite" else {}
        }
        # 只有MySQL需要连接池参数
        if config.database.type == "mysql":
            engine_kwargs["pool_size"] = config.database.pool_size
            engine_kwargs["max_overflow"] = config.database.max_overflow
        _engine = create_engine(
            config.database.url,
            **engine_kwargs
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
    _ensure_code_server_columns(engine)


def _ensure_code_server_columns(engine):
    """兼容历史库：补齐新增列。"""
    inspector = inspect(engine)
    columns = {item["name"] for item in inspector.get_columns("code_servers")}

    to_add = []
    if "llm_provider_key" not in columns:
        to_add.append("llm_provider_key VARCHAR(128)")
    if "llm_provider_snapshot" not in columns:
        to_add.append("llm_provider_snapshot JSON")
    if "llm_provider_mapped_env_keys" not in columns:
        to_add.append("llm_provider_mapped_env_keys JSON")
    if "llm_file_bindings" not in columns:
        to_add.append("llm_file_bindings JSON")
    if "llm_configmap_name" not in columns:
        to_add.append("llm_configmap_name VARCHAR(128)")

    if not to_add:
        return

    with engine.begin() as conn:
        for ddl in to_add:
            conn.execute(text(f"ALTER TABLE code_servers ADD COLUMN {ddl}"))


def get_db():
    """获取数据库会话（生成器）"""
    SessionLocal = get_session_factory()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_db_session() -> Session:
    """获取数据库会话（非生成器）"""
    SessionLocal = get_session_factory()
    return SessionLocal()


def generate_id() -> str:
    """生成16位MD5 ID"""
    unique_str = f"{uuid.uuid4()}_{datetime.utcnow().timestamp()}"
    return hashlib.md5(unique_str.encode()).hexdigest()[:16]
