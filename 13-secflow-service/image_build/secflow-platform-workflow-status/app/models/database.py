"""
数据库模型模块 - 节点状态管理
"""

from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    Column,
    DateTime,
    String,
    Text,
    Integer,
    JSON,
    create_engine,
    Index,
)
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from app.config import get_config

Base = declarative_base()

# 表名前缀
TABLE_PREFIX = "secflow_node_status_"


class NodeStatusRecord(Base):
    """节点状态记录"""
    __tablename__ = f"{TABLE_PREFIX}record"

    id = Column(String(64), primary_key=True)
    task_id = Column(String(64), nullable=False, index=True)
    node_id = Column(String(64), nullable=False, index=True)
    instance_id = Column(String(64), nullable=False, index=True)
    project_id = Column(String(32), nullable=False, index=True)
    node_type = Column(String(20), nullable=False)  # app/job

    # K8S资源信息
    k8s_resource_name = Column(String(128))
    k8s_resource_type = Column(String(20))  # Deployment/Job

    # 状态信息
    status = Column(String(32), nullable=False, default="Pending")
    started_at = Column(DateTime)
    finished_at = Column(DateTime)
    duration_seconds = Column(Integer)
    message = Column(Text)

    # 日志存储 (JSON格式，包含pod_name、container、logs、fetched_at等)
    init_logs = Column(JSON)        # 初始化日志
    execution_logs = Column(JSON)   # 执行日志
    log_updated_at = Column(DateTime)  # 日志更新时间

    # 扩展信息
    extra_data = Column("metadata", JSON)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # 添加复合索引
    __table_args__ = (
        Index('ix_node_status_record_instance_project', 'instance_id', 'project_id'),
    )

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "id": self.id,
            "task_id": self.task_id,
            "node_id": self.node_id,
            "instance_id": self.instance_id,
            "project_id": self.project_id,
            "node_type": self.node_type,
            "k8s_resource_name": self.k8s_resource_name,
            "k8s_resource_type": self.k8s_resource_type,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": self.duration_seconds,
            "message": self.message,
            "init_logs": self.init_logs or {},
            "execution_logs": self.execution_logs or {},
            "log_updated_at": self.log_updated_at.isoformat() if self.log_updated_at else None,
            "metadata": self.extra_data,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class WorkflowStatusRecord(Base):
    """工作流状态记录"""
    __tablename__ = f"{TABLE_PREFIX}workflow_record"

    id = Column(String(64), primary_key=True)
    instance_id = Column(String(64), nullable=False, index=True)
    project_id = Column(String(32), nullable=False, index=True)

    # 状态信息
    status = Column(String(32), nullable=False, default="Pending")
    started_at = Column(DateTime)
    finished_at = Column(DateTime)
    duration_seconds = Column(Integer)
    message = Column(Text)

    # 节点状态汇总
    total_nodes = Column(Integer, default=0)
    pending_nodes = Column(Integer, default=0)
    not_ready_nodes = Column(Integer, default=0)  # APP节点特有
    ready_nodes = Column(Integer, default=0)       # APP节点特有
    running_nodes = Column(Integer, default=0)
    succeeded_nodes = Column(Integer, default=0)
    failed_nodes = Column(Integer, default=0)
    stopped_nodes = Column(Integer, default=0)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        Index('ix_workflow_status_record_project', 'instance_id', 'project_id'),
    )

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "id": self.id,
            "instance_id": self.instance_id,
            "project_id": self.project_id,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": self.duration_seconds,
            "message": self.message,
            "total_nodes": self.total_nodes,
            "pending_nodes": self.pending_nodes,
            "not_ready_nodes": self.not_ready_nodes,
            "ready_nodes": self.ready_nodes,
            "running_nodes": self.running_nodes,
            "succeeded_nodes": self.succeeded_nodes,
            "failed_nodes": self.failed_nodes,
            "stopped_nodes": self.stopped_nodes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class NodeStatusHistory(Base):
    """节点状态变更历史"""
    __tablename__ = f"{TABLE_PREFIX}history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    node_id = Column(String(64), nullable=False, index=True)
    instance_id = Column(String(64), nullable=False, index=True)
    project_id = Column(String(32), nullable=False, index=True)

    from_status = Column(String(32))
    to_status = Column(String(32), nullable=False)
    reason = Column(Text)
    operator = Column(String(64))  # system/user

    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index('ix_node_status_history_node_project', 'node_id', 'project_id'),
    )

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "id": self.id,
            "node_id": self.node_id,
            "instance_id": self.instance_id,
            "project_id": self.project_id,
            "from_status": self.from_status,
            "to_status": self.to_status,
            "reason": self.reason,
            "operator": self.operator,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# 数据库引擎和会话工厂
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
    """获取数据库会话（生成器模式，用于FastAPI依赖注入）"""
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


# ============ 查询辅助函数 ============

def get_node_status_record(db: Session, node_id: str) -> Optional[NodeStatusRecord]:
    """根据node_id获取节点状态记录"""
    return db.query(NodeStatusRecord).filter(
        NodeStatusRecord.node_id == node_id
    ).order_by(
        NodeStatusRecord.created_at.desc(),
        NodeStatusRecord.id.desc(),
    ).first()


def get_node_status_record_by_task_id(db: Session, task_id: str) -> Optional[NodeStatusRecord]:
    """Get node status record by task_id."""
    return db.query(NodeStatusRecord).filter(
        NodeStatusRecord.task_id == task_id
    ).first()


def get_node_status_by_instance(
    db: Session,
    instance_id: str,
    project_id: str
) -> List[NodeStatusRecord]:
    """获取工作流实例下所有节点状态"""
    return db.query(NodeStatusRecord).filter(
        NodeStatusRecord.instance_id == instance_id,
        NodeStatusRecord.project_id == project_id
    ).order_by(
        NodeStatusRecord.created_at.desc(),
        NodeStatusRecord.id.desc(),
    ).all()


def get_workflow_status_record(db: Session, instance_id: str) -> Optional[WorkflowStatusRecord]:
    """获取工作流状态记录"""
    return db.query(WorkflowStatusRecord).filter(
        WorkflowStatusRecord.instance_id == instance_id
    ).first()


def get_node_status_history(
    db: Session,
    node_id: str,
    project_id: str
) -> List[NodeStatusHistory]:
    """获取节点状态变更历史"""
    return db.query(NodeStatusHistory).filter(
        NodeStatusHistory.node_id == node_id,
        NodeStatusHistory.project_id == project_id
    ).order_by(NodeStatusHistory.created_at.desc()).all()


def get_workflow_status_history(
    db: Session,
    instance_id: str,
    project_id: str
) -> List[NodeStatusHistory]:
    """获取工作流下所有节点的状态变更历史"""
    return db.query(NodeStatusHistory).filter(
        NodeStatusHistory.instance_id == instance_id,
        NodeStatusHistory.project_id == project_id
    ).order_by(NodeStatusHistory.created_at.desc()).all()


def list_workflow_status_records(
    db: Session,
    project_id: str,
    status: Optional[str] = None,
    page: int = 1,
    page_size: int = 20
) -> tuple[List[WorkflowStatusRecord], int]:
    """查询工作流状态记录列表"""
    query = db.query(WorkflowStatusRecord).filter(
        WorkflowStatusRecord.project_id == project_id
    )

    if status:
        query = query.filter(WorkflowStatusRecord.status == status)

    total = query.count()
    items = query.order_by(
        WorkflowStatusRecord.created_at.desc()
    ).offset((page - 1) * page_size).limit(page_size).all()

    return items, total
