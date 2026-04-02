"""
Database models for SecFlow Workflow Service
Table prefix: secflow_platform_workflow_
"""

import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any

from sqlalchemy import (
    Column,
    String,
    Text,
    Integer,
    Boolean,
    DateTime,
    ForeignKey,
    Enum as SQLEnum,
    JSON,
    create_engine,
    Index,
    UniqueConstraint,
    inspect,
    text,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from sqlalchemy.pool import QueuePool

from app.config import get_config

# Create base class for models declarations
Base = declarative_base()

# Get table prefix from configuration
_config = get_config()
TABLE_PREFIX ="secflow_workflow_"


# ============ Enums ============

class TemplateScope:
    """Template scope constants"""
    GLOBAL = "global"
    PROJECT = "project"


class ImagePullPolicy:
    """Image pull policy constants"""
    ALWAYS = "Always"
    IF_NOT_PRESENT = "IfNotPresent"
    NEVER = "Never"


class WorkflowStatus:
    """Workflow instance status based on APP nodes

    Status is determined by APP node statuses only:
    - pending: 所有APP节点都为pending（或没有APP节点）
    - unready: 有APP节点为ready/not_ready/failed/stopped（非全部pending）
    - ready: 所有APP节点都为ready
    """
    PENDING = "pending"    # 所有APP节点都为pending
    UNREADY = "unready"    # 有APP节点为ready/not_ready/failed/stopped
    READY = "ready"        # 所有APP节点都为ready


class NodeStatus:
    """Workflow node instance status

    APP节点状态流转:
    - pending: Pod未运行
    - not_ready: Pod已运行但未就绪
    - ready: Pod全部就绪
    - stopped: 已停止
    - failed: 执行失败

    JOB节点状态流转:
    - pending: 等待执行
    - running: 执行中
    - succeeded: 执行成功
    - failed: 执行失败
    """
    PENDING = "pending"        # APP: Pod未运行; JOB: 等待执行
    NOT_READY = "not_ready"    # APP: Pod已运行但未就绪
    READY = "ready"            # APP: Pod全部就绪
    RUNNING = "running"        # JOB: 执行中
    SUCCEEDED = "succeeded"    # JOB: 执行成功
    FAILED = "failed"          # 执行失败
    STOPPED = "stopped"        # 已停止


class NodeType:
    """Workflow node type"""
    APP = "app"
    JOB = "job"


class TemplateTagCategory:
    TARGET = "target"
    CAPABILITY = "capability"
    REQUIREMENT = "requirement"
    EXECUTION = "execution"
    OUTPUT = "output"


# ============ App Template Model ============

class AppTemplate(Base):
    """Application Deployment Template with multi-container support"""
    __tablename__ = f"{TABLE_PREFIX}app_template"

    id = Column(String(64), primary_key=True)
    name = Column(String(128), nullable=False, index=True)
    description = Column(Text)
    scope = Column(String(20), nullable=False, default=TemplateScope.PROJECT)
    project_id = Column(String(64), index=True)

    # Multi-container configuration
    # Each container has: name, image, command, args, env_vars, volume_mounts,
    # dependency_env_vars, dependency_volume_mounts, health_check, etc.
    containers = Column(JSON, nullable=False)  # List of container configs

    # Deployment-level configuration
    replicas = Column(Integer, default=1)  # Number of replicas
    create_service = Column(Boolean, default=True)
    service_name = Column(String(128))
    service_ports = Column(JSON, nullable=False, default=list)
    service_type = Column(String(32), default="ClusterIP")

    # Audit fields
    created_by = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<AppTemplate(id={self.id}, name={self.name})>"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "scope": self.scope,
            "project_id": self.project_id,
            "containers": self.containers,
            "replicas": self.replicas,
            "create_service": self.create_service,
            "service_name": self.service_name,
            "service_ports": self.service_ports,
            "service_type": self.service_type,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# ============ Job Template Model ============

class JobTemplate(Base):
    """One-time Job Template with multi-container support"""
    __tablename__ = f"{TABLE_PREFIX}job_template"

    id = Column(String(64), primary_key=True)
    name = Column(String(128), nullable=False, index=True)
    description = Column(Text)
    scope = Column(String(20), nullable=False, default=TemplateScope.PROJECT)
    project_id = Column(String(64), index=True)

    # Multi-container configuration
    # Each container has: name, image, command, args, env_vars, volume_mounts,
    # dependency_env_vars, dependency_volume_mounts, etc.
    containers = Column(JSON, nullable=False)  # List of container configs

    # Job-level configuration
    ttl_seconds_after_finished = Column(Integer, default=3600)  # TTL after finished
    backoff_limit = Column(Integer, default=3)  # Backoff limit

    # Audit field
    created_by = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<JobTemplate(id={self.id}, name={self.name})>"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "scope": self.scope,
            "project_id": self.project_id,
            "containers": self.containers,
            "ttl_seconds_after_finished": self.ttl_seconds_after_finished,
            "backoff_limit": self.backoff_limit,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class TemplateTag(Base):
    __tablename__ = f"{TABLE_PREFIX}template_tag"

    id = Column(String(64), primary_key=True)
    tag_key = Column(String(128), nullable=False, unique=True, index=True)
    tag_label = Column(String(128), nullable=False)
    category = Column(String(32), nullable=False, default=TemplateTagCategory.CAPABILITY, index=True)
    description = Column(Text)
    color = Column(String(32), default="slate")
    is_system = Column(Boolean, default=False)
    enabled = Column(Boolean, default=True, index=True)
    sort_order = Column(Integer, default=0)
    created_by = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class TemplateTagBinding(Base):
    __tablename__ = f"{TABLE_PREFIX}template_tag_binding"
    __table_args__ = (
        UniqueConstraint("template_type", "template_id", "tag_id", name=f"uk_{TABLE_PREFIX}template_tag_binding_rel"),
        Index(f"idx_{TABLE_PREFIX}template_tag_binding_template", "template_type", "template_id"),
    )

    id = Column(String(64), primary_key=True)
    template_type = Column(String(32), nullable=False)
    template_id = Column(String(64), nullable=False)
    tag_id = Column(String(64), ForeignKey(f"{TABLE_PREFIX}template_tag.id", ondelete="CASCADE"), nullable=False)
    source = Column(String(32), default="manual")
    created_by = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    tag = relationship("TemplateTag")



# ============ Workflow Instance Model ============

class WorkflowInstance(Base):
    """Workflow Instance (running workflow)

    Nodes configurations are stored directly in the instance (no separate template).
    Each node references an AppTemplate or JobTemplate by template_id.
    """
    __tablename__ = f"{TABLE_PREFIX}workflow_instance"

    id = Column(String(64), primary_key=True)
    name = Column(String(128), nullable=False, index=True)
    description = Column(Text)
    project_id = Column(String(64), nullable=False, index=True)

    # Instance status
    status = Column(String(20), default=WorkflowStatus.PENDING)

    # Run mode: "persistent" or "once"
    # - persistent: workflow keeps running, nodes can be app (Deployment) or job (Job)
    # - once: workflow runs once and finishes
    run_mode = Column(String(20), default="once")

    # Trigger configuration (for persistent mode)
    # Trigger types: "manual", "http"
    trigger_type = Column(String(20), default="manual")
    trigger_enabled = Column(Boolean, default=False)
    trigger_url = Column(String(256))  # Unique trigger endpoint path
    is_active = Column(Boolean, default=True)  # Whether workflow is active (for persistent mode)

    # Workflow instance definition - directly stores node and edge configurations
    # Each node references an AppTemplate or JobTemplate by template_id
    nodes = Column(JSON, nullable=False, default=[])  # Node instance configurations
    edges = Column(JSON, nullable=False, default=[])  # Edge configurations

    # Execution tracking
    run_count = Column(Integer, default=0)  # Number of times workflow has run
    last_run_at = Column(DateTime)  # Last run timestamp
    started_at = Column(DateTime)
    finished_at = Column(DateTime)
    message = Column(Text)
    has_warning = Column(Boolean, default=False)  # Warning flag for resource orphan etc.
    last_sync_at = Column(DateTime)  # Last sync timestamp
    sync_logs = Column(Text)  # Sync logs (recent sync details)

    # Audit field
    created_by = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<WorkflowInstance(id={self.id}, name={self.name}, status={self.status})>"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "project_id": self.project_id,
            "status": self.status,
            "run_mode": self.run_mode,
            "trigger_type": self.trigger_type,
            "trigger_enabled": self.trigger_enabled,
            "trigger_url": self.trigger_url,
            "is_active": self.is_active,
            "nodes": self.nodes,
            "edges": self.edges,
            "run_count": self.run_count,
            "last_run_at": self.last_run_at.isoformat() if self.last_run_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "message": self.message,
            "has_warning": self.has_warning,
            "last_sync_at": self.last_sync_at.isoformat() if self.last_sync_at else None,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# ============ Workflow Node Instance Model ============

class WorkflowNodeInstance(Base):
    """Workflow Node Instance (runtime node)

    Note: node_id is kept for backward compatibility, but is always set to the same value as id.
    The id is auto-generated and serves as the unique identifier for the node.
    """
    __tablename__ = f"{TABLE_PREFIX}workflow_node_instance"

    id = Column(String(64), primary_key=True)
    instance_id = Column(String(64), ForeignKey(f"{TABLE_PREFIX}workflow_instance.id"), nullable=False, index=True)
    node_id = Column(String(64), nullable=False)  # Always same as id, kept for backward compatibility
    node_type = Column(String(20), nullable=False)  # app or job
    template_id = Column(String(64), nullable=False)
    name = Column(String(128), nullable=False)
    status = Column(String(20), default=NodeStatus.PENDING)

    # K8S resource tracking
    k8s_resource_name = Column(String(128))
    k8s_resource_type = Column(String(20))  # Deployment or Job
    service_name = Column(String(128))

    # Ingress configuration (optional, for app type nodes with service)
    ingress_type = Column(String(20))  # nginx or None
    ingress_host = Column(String(256))  # Ingress hostname
    ingress_ip = Column(String(64))  # Ingress IP address

    # Configuration (saved from creation for query and update)
    position = Column(JSON, default={"x": 0.0, "y": 0.0})  # Node position in canvas
    env_vars = Column(JSON, default=[])  # Fixed environment variables (override template)
    volume_mounts = Column(JSON, default=[])  # Fixed volume mounts (override template)
    resources = Column(JSON)  # Resource requirements (override template)

    # Node Dependencies (from edges)
    depends_on = Column(JSON, default=[])  # List of upstream node IDs (nodes this node depends on)
    downstream_node_ids = Column(JSON, default=[])  # List of downstream node IDs (nodes that depend on this node)
    timeout_seconds = Column(Integer)  # Timeout in seconds (excluding image pull time)

    # Input Dependencies (specify source_node_id at instance level)
    input_env_vars = Column(JSON, default=[])
    input_volume_mounts = Column(JSON, default=[])

    # Execution tracking
    started_at = Column(DateTime)
    finished_at = Column(DateTime)
    message = Column(Text)
    init_logs = Column(Text)  # 初始化日志，记录初始化过程中的详细信息

    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<WorkflowNodeInstance(id={self.id}, name={self.name}, status={self.status})>"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "instance_id": self.instance_id,
            "node_id": self.node_id,
            "node_type": self.node_type,
            "template_id": self.template_id,
            "name": self.name,
            "status": self.status,
            "k8s_resource_name": self.k8s_resource_name,
            "k8s_resource_type": self.k8s_resource_type,
            "service_name": self.service_name,
            "ingress_type": self.ingress_type,
            "ingress_host": self.ingress_host,
            "ingress_ip": self.ingress_ip,
            "position": self.position,
            "env_vars": self.env_vars,
            "volume_mounts": self.volume_mounts,
            "resources": self.resources,
            "depends_on": self.depends_on,
            "downstream_node_ids": self.downstream_node_ids,
            "timeout_seconds": self.timeout_seconds,
            "input_env_vars": self.input_env_vars,
            "input_volume_mounts": self.input_volume_mounts,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "message": self.message,
            "init_logs": self.init_logs,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

_engine = None
_session_factory = None


def get_database_url() -> str:
    """Get database connection URL"""
    config = get_config()
    db_config = config.database
    return (
        f"mysql+pymysql://{db_config.username}:{db_config.password}"
        f"@{db_config.host}:{db_config.port}/{db_config.name}"
        f"?charset=utf8mb4"
    )


def init_engine():
    """Initialize database engine"""
    global _engine
    if _engine is None:
        config = get_config()
        db_config = config.database
        _engine = create_engine(
            get_database_url(),
            poolclass=QueuePool,
            pool_size=db_config.pool_size or 10,
            max_overflow=db_config.max_overflow or 20,
            pool_pre_ping=True,
            pool_recycle=3600,
            pool_timeout=30,
            echo=False,
        )
    return _engine


def get_engine():
    """Get database engine"""
    global _engine
    if _engine is None:
        init_engine()
    return _engine


def get_session_factory():
    """Get session factory"""
    global _session_factory
    if _session_factory is None:
        _session_factory = sessionmaker(bind=get_engine(), expire_on_commit=False)
    return _session_factory


def create_table(table_name: str, base=Base):
    """Create a table with the given name (for dynamic table creation)"""
    # This method is kept for compatibility, actual table creation is handled by SQLAlchemy
    pass


def create_tables():
    """Create all database tables"""
    engine = get_engine()
    Base.metadata.create_all(engine)
    _ensure_app_template_columns(engine)
    return True


def _ensure_app_template_columns(engine):
    """Add newly introduced app template columns on existing deployments."""
    inspector = inspect(engine)
    table_name = AppTemplate.__tablename__
    if not inspector.has_table(table_name):
        return

    existing_columns = {column["name"] for column in inspector.get_columns(table_name)}
    statements = []

    if "create_service" not in existing_columns:
        statements.append(f"ALTER TABLE {table_name} ADD COLUMN create_service BOOLEAN DEFAULT 1")
    if "service_name" not in existing_columns:
        statements.append(f"ALTER TABLE {table_name} ADD COLUMN service_name VARCHAR(128)")
    if "service_ports" not in existing_columns:
        statements.append(f"ALTER TABLE {table_name} ADD COLUMN service_ports JSON")
    if "service_type" not in existing_columns:
        statements.append(f"ALTER TABLE {table_name} ADD COLUMN service_type VARCHAR(32) DEFAULT 'ClusterIP'")

    if not statements:
        return

    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def drop_tables():
    """Drop all database tables"""
    engine = get_engine()
    Base.metadata.drop_all(engine)


def generate_id(name: str) -> str:
    """Generate unique ID based on name"""
    # Combine timestamp and UUID to ensure uniqueness
    unique_str = f"{name}-{datetime.utcnow().timestamp()}"
    return uuid.uuid5(uuid.NAMESPACE_DNS, unique_str).hex[:16]


# ============ Workflow Sync Record Model ============

class WorkflowSyncRecord(Base):
    """工作流同步记录 - 记录每次同步操作的时间"""
    __tablename__ = f"{TABLE_PREFIX}workflow_sync_record"

    id = Column(String(64), primary_key=True)
    instance_id = Column(String(64), ForeignKey(f"{TABLE_PREFIX}workflow_instance.id"), nullable=False, index=True)
    sync_at = Column(DateTime, nullable=False)  # 同步时间
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<WorkflowSyncRecord(id={self.id}, instance_id={self.instance_id}, sync_at={self.sync_at})>"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "instance_id": self.instance_id,
            "sync_at": self.sync_at.isoformat() if self.sync_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class WorkflowNodeDomainBinding(Base):
    """节点域名绑定记录。"""
    __tablename__ = f"{TABLE_PREFIX}workflow_node_domain_binding"
    __table_args__ = (
        Index(
            f"idx_{TABLE_PREFIX}wf_node_domain_binding_unique",
            "instance_id",
            "node_instance_id",
            "domain",
            unique=True,
        ),
    )

    id = Column(String(64), primary_key=True)
    instance_id = Column(String(64), ForeignKey(f"{TABLE_PREFIX}workflow_instance.id"), nullable=False, index=True)
    node_instance_id = Column(String(64), nullable=False, index=True)
    node_id = Column(String(64), nullable=False, index=True)
    project_id = Column(String(64), nullable=False, index=True)
    service_name = Column(String(128))
    ingress_name = Column(String(128))
    ingress_type = Column(String(20))
    domain = Column(String(256), nullable=False, index=True)
    ingress_ip = Column(String(64))
    service_port = Column(Integer)
    target_port = Column(Integer)
    binding_status = Column(String(20), default="configured", nullable=False)
    message = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return (
            f"<WorkflowNodeDomainBinding(instance_id={self.instance_id}, "
            f"node_instance_id={self.node_instance_id}, domain={self.domain})>"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "instance_id": self.instance_id,
            "node_instance_id": self.node_instance_id,
            "node_id": self.node_id,
            "project_id": self.project_id,
            "service_name": self.service_name,
            "ingress_name": self.ingress_name,
            "ingress_type": self.ingress_type,
            "domain": self.domain,
            "ingress_ip": self.ingress_ip,
            "service_port": self.service_port,
            "target_port": self.target_port,
            "binding_status": self.binding_status,
            "message": self.message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# ============ Dependency Injection ============

def get_db():
    """FastAPI dependency for database session"""
    session_factory = get_session_factory()
    db = session_factory()
    try:
        yield db
    finally:
        db.close()


def get_db_session():
    """Get a database session (non-FastAPI context)"""
    session_factory = get_session_factory()
    return session_factory()
