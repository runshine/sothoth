"""
数据库模型定义
"""
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, BigInteger, ForeignKey
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql import func

from config import Config

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(200), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, server_default=func.now())

class Project(Base):
    __tablename__ = "projects"
    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(200), nullable=False, index=True)
    description = Column(Text)
    original_filename = Column(String(500))
    archive_path = Column(String(500))
    extract_path = Column(String(500))
    file_count = Column(Integer, default=0)
    total_size = Column(BigInteger, default=0)
    archive_size = Column(BigInteger, default=0)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    # 项目状态
    status = Column(String(20), default=Config.PROJECT_STATUS_PENDING)  # pending, initializing, ready, error, deleting
    init_log_path = Column(String(500))  # 初始化日志文件路径
    init_error = Column(Text)  # 初始化错误信息
    # PVC相关字段
    pvc_name = Column(String(100), nullable=True)
    pvc_status = Column(String(20), default="pending")  # pending, creating, ready, error
    pvc_size = Column(String(20), default="5Gi")
    file_synced = Column(Boolean, default=False)  # 文件是否已同步到PVC
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())
    initialized_at = Column(DateTime)  # 初始化完成时间
    owner = relationship("User", backref="projects")

class ProjectFile(Base):
    __tablename__ = "project_files"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(String(64), ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    file_path = Column(String(1000), nullable=False)
    file_name = Column(String(300), nullable=False, index=True)
    file_size = Column(BigInteger, default=0)
    file_type = Column(String(50))
    created_at = Column(DateTime, server_default=func.now())
    project = relationship("Project", backref="files")

class CodeServer(Base):
    __tablename__ = "code_servers"
    id = Column(String(64), primary_key=True, index=True)
    project_id = Column(String(64), ForeignKey("projects.id", ondelete="CASCADE"), unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    deployment_name = Column(String(100))
    service_name = Column(String(100))
    service_ip = Column(String(100))
    service_port = Column(Integer)
    access_url = Column(String(500))
    status = Column(String(20), default="pending")  # pending, creating, running, stopped, error, deleting
    pod_name = Column(String(100))
    pod_status = Column(String(50))
    cpu_limit = Column(String(20), default="1000m")
    memory_limit = Column(String(20), default="1024Mi")
    password = Column(String(100))  # 存储访问密码
    created_at = Column(DateTime, server_default=func.now())
    started_at = Column(DateTime)
    stopped_at = Column(DateTime)
    owner = relationship("User", backref="code_servers")
    project = relationship("Project", backref="code_server", uselist=False)

class ProjectTaskLog(Base):
    __tablename__ = "project_task_logs"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(String(64), ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    task_type = Column(String(50), nullable=False)  # init, delete, recreate_pvc
    task_id = Column(String(100), nullable=False, index=True)
    status = Column(String(20), default="running")  # running, completed, failed
    log_path = Column(String(500))  # 日志文件路径
    error_message = Column(Text)
    created_at = Column(DateTime, server_default=func.now())
    completed_at = Column(DateTime)
    project = relationship("Project", backref="task_logs")