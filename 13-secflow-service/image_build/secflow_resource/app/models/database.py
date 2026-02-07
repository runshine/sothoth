"""Database models for secflow_resource service."""

import os
import yaml
import uuid
from pathlib import Path
from datetime import datetime
from typing import Optional, List
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean,
    Enum as SQLEnum, JSON, create_engine, BigInteger, ForeignKey, Table
)
from sqlalchemy.orm import relationship, DeclarativeBase, sessionmaker
import enum


class Base(DeclarativeBase):
    """Base class for all model."""
    pass


# 资源与项目关联表（多对多关系）
resource_project_association = Table(
    'secflow_resource_project_association',
    Base.metadata,
    Column('resource_id', Integer, ForeignKey('secflow_resource.id'), primary_key=True),
    Column('project_id', String(64), ForeignKey('secflow_project.id'), primary_key=True)
)


def load_db_config():
    """从配置文件加载数据库配置"""
    config_path = os.environ.get(
        "CONFIG_PATH",
        str(Path(__file__).parent.parent.parent / "config.yaml")
    )
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    return config.get("database", {})


# 创建数据库引擎（延迟初始化，用于启动时检查）
engine = None
SessionLocal = None


def init_database_engine():
    """初始化数据库引擎，用于启动时检查"""
    global engine, SessionLocal
    db_config = load_db_config()
    engine = create_engine(
        f"mysql+pymysql://{db_config.get('username', 'root')}:{db_config.get('password', '')}@"
        f"{db_config.get('host', 'localhost')}:{db_config.get('port', 3306)}/{db_config.get('name', 'test')}",
        pool_pre_ping=True,
        pool_size=db_config.get('pool_size', 10),
        max_overflow=db_config.get('max_overflow', 20)
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return engine


def get_db():
    """获取数据库会话"""
    global SessionLocal
    if SessionLocal is None:
        init_database_engine()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_database_connection() -> tuple[bool, str]:
    """测试数据库连接是否正常"""
    try:
        from sqlalchemy import text
        db_config = load_db_config()
        test_engine = create_engine(
            f"mysql+pymysql://{db_config.get('username', 'root')}:{db_config.get('password', '')}@"
            f"{db_config.get('host', 'localhost')}:{db_config.get('port', 3306)}/{db_config.get('name', 'test')}",
            pool_pre_ping=True,
            pool_size=1,
            max_overflow=0
        )
        with test_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        test_engine.dispose()
        return True, "Database connection successful"
    except Exception as e:
        return False, f"Database connection failed: {str(e)}"


class ResourceType(enum.Enum):
    """资源类型枚举（五类资源）。"""
    DOCUMENT = "document"  # 文档资源
    SOFTWARE = "software"  # 软件包资源
    CODE = "code"  # 代码资源
    OTHER = "other"  # 其他资源
    OUTPUT_PVC = "output_pvc"  # 输出PVC资源（用于任务输出存储）


class TaskStatus(enum.Enum):
    """异步任务状态枚举。"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskType(enum.Enum):
    """任务类型枚举。"""
    UPLOAD_EXTRACT = "upload_extract"  # 上传并解压任务
    EXTRACT = "extract"  # 仅解压任务
    DELETE = "delete"  # 删除任务


class ResourceUploadStatus(enum.Enum):
    """资源上传状态枚举。"""
    PENDING = "pending"  # 待处理
    UPLOADING = "uploading"  # 上传中
    EXTRACTING = "extracting"  # 解压中
    COMPLETED = "completed"  # 完成
    FAILED = "failed"  # 失败


class Project(Base):
    """项目模型 - 记录资源关联的项目信息（本地缓存）。

    与 secflow_project 服务保持一致，id 就是 project_id（16位MD5）。
    """
    __tablename__ = "secflow_project"

    id = Column(String(32), primary_key=True, index=True)  # 16位MD5，即 project_id
    name = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    owner_id = Column(String(64), nullable=False)
    owner_name = Column(String(128), nullable=True)
    k8s_namespace = Column(String(128), nullable=True)
    status = Column(String(32), default="active")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # 关联的资源
    resources = relationship("Resource", secondary=resource_project_association, back_populates="projects")


class Resource(Base):
    """资源模型 - 管理软件测试项目的四类资源。

    每次上传创建一个独立的PVC，记录解压后的位置。
    """
    __tablename__ = "secflow_resource"

    id = Column(Integer, primary_key=True, index=True)
    resource_uuid = Column(String(64), unique=True, nullable=False, index=True, default=lambda: str(uuid.uuid4()))

    # 基本信息
    name = Column(String(255), nullable=False, comment="资源名称")
    description = Column(Text, nullable=True, comment="资源描述")
    resource_type = Column(SQLEnum(ResourceType, values_callable=lambda x: [e.value for e in x]), nullable=False, index=True)

    # 关联的项目（多对多）
    projects = relationship("Project", secondary=resource_project_association, back_populates="resources")

    # 原始文件信息
    original_file_name = Column(String(255), nullable=False, comment="原始文件名")
    original_file_size = Column(BigInteger, nullable=False, comment="原始文件大小（字节）")
    original_file_md5 = Column(String(32), nullable=True, comment="原始文件MD5")
    original_file_format = Column(String(32), nullable=True, comment="原始文件格式(zip/tar.gz/etc)")

    # 上传状态
    upload_status = Column(SQLEnum(ResourceUploadStatus, values_callable=lambda x: [e.value for e in x]), default=ResourceUploadStatus.PENDING, comment="上传状态")
    upload_message = Column(Text, nullable=True, comment="上传状态消息")

    # PVC信息（每次上传创建独立的PVC）
    pvc_name = Column(String(255), nullable=True, unique=True, index=True, comment="PVC名称")
    pvc_namespace = Column(String(255), nullable=True, comment="PVC所在namespace（项目namespace）")
    pvc_size = Column(String(16), default="10Gi", comment="PVC大小")

    # 解压路径（压缩包解压后根目录在PVC中的路径）
    extract_path = Column(String(1024), nullable=True, default="/", comment="解压路径（在PVC内）")

    # 元数据
    resource_metadata = Column(JSON, nullable=True, comment="资源元数据")
    created_by = Column(String(64), nullable=True, comment="创建者ID")

    # 时间戳
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # 关联的任务
    tasks = relationship("AsyncTaskLog", back_populates="resource", cascade="all, delete-orphan")


class AsyncTaskLog(Base):
    """异步任务日志模型。

    记录异步任务的完整生命周期，包括资源清理信息。
    """
    __tablename__ = "secflow_resource_async_task_log"

    id = Column(Integer, primary_key=True, index=True)
    task_uuid = Column(String(64), unique=True, nullable=False, index=True, default=lambda: str(uuid.uuid4()))
    task_id = Column(String(64), unique=True, index=True, nullable=False, comment="任务ID（对外展示）")

    # 关联资源
    resource_id = Column(Integer, ForeignKey('secflow_resource.id'), nullable=True, index=True)
    resource = relationship("Resource", back_populates="tasks")

    # 关联项目（用于权限验证）
    project_id = Column(String(64), nullable=True, index=True, comment="关联的项目ID")

    # 任务类型和状态
    task_type = Column(SQLEnum(TaskType, values_callable=lambda x: [e.value for e in x]), nullable=False, comment="任务类型")
    status = Column(SQLEnum(TaskStatus, values_callable=lambda x: [e.value for e in x]), default=TaskStatus.PENDING, comment="任务状态")

    # 进度
    progress = Column(Integer, default=0, comment="进度百分比(0-100)")
    message = Column(Text, nullable=True, comment="状态消息")
    error_message = Column(Text, nullable=True, comment="错误信息")

    # 输入参数
    input_params = Column(JSON, nullable=True, comment="输入参数")

    # 执行结果
    result = Column(JSON, nullable=True, comment="执行结果")

    # Kubernetes资源信息（用于任务失败时清理）
    created_k8s_resources = Column(JSON, nullable=True, default=list,
                                   comment="任务创建的K8S资源列表[{type, name, namespace}]")

    # 时间戳
    started_at = Column(DateTime, nullable=True, comment="开始时间")
    finished_at = Column(DateTime, nullable=True, comment="完成时间")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


def create_tables():
    """创建所有表结构"""
    if engine is None:
        init_database_engine()
    Base.metadata.create_all(bind=engine)


def drop_tables():
    """删除所有表结构"""
    if engine is None:
        init_database_engine()
    Base.metadata.drop_all(bind=engine)