"""
数据库模型模块
"""

import json
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy import (
    Column,
    DateTime,
    String,
    Text,
    create_engine,
    inspect,
    text,
)
from sqlalchemy.orm import Session, declarative_base, sessionmaker

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
    # 注意：project表由project服务管理，这里只初始化动态ingress路由表
    ensure_agent_ingress_route_table()


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


def get_agent_ingress_route_table_name() -> str:
    """获取动态Agent Ingress路由表名"""
    prefix = get_config().database.table_prefix
    return f"{prefix}agent_ingress_route"


def ensure_agent_ingress_route_table():
    """确保动态Agent Ingress路由表存在"""
    table_name = get_agent_ingress_route_table_name()
    engine = get_engine()
    create_table_sql = f"""
    CREATE TABLE IF NOT EXISTS {table_name} (
        route_id VARCHAR(64) PRIMARY KEY,
        project_id VARCHAR(64) NOT NULL,
        namespace VARCHAR(128) NOT NULL,
        agent_key VARCHAR(128) NOT NULL,
        target_port INTEGER NOT NULL,
        external_ips TEXT NOT NULL,
        host VARCHAR(255) NOT NULL,
        path VARCHAR(255) NOT NULL,
        ingress_type VARCHAR(64) NOT NULL,
        path_type VARCHAR(32) NOT NULL,
        service_port INTEGER NOT NULL,
        ingress_name VARCHAR(128) NOT NULL,
        service_name VARCHAR(128) NOT NULL,
        tls_enabled INTEGER NOT NULL DEFAULT 0,
        tls_secret_name VARCHAR(255),
        websocket_enabled INTEGER NOT NULL DEFAULT 1,
        status VARCHAR(32) NOT NULL DEFAULT 'creating',
        access_url VARCHAR(1024),
        owner_service VARCHAR(64),
        created_by VARCHAR(128),
        metadata_json TEXT,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        deleted_at DATETIME
    )
    """
    expected_indexes = {
        f"idx_{table_name}_project_agent": ["project_id", "agent_key"],
        f"idx_{table_name}_project_status": ["project_id", "status"],
        f"idx_{table_name}_updated_at": ["updated_at"],
    }

    with engine.connect() as conn:
        conn.execute(text(create_table_sql))
        conn.commit()

    _ensure_agent_ingress_route_indexes(engine, table_name, expected_indexes)


def _ensure_agent_ingress_route_indexes(engine, table_name: str, expected_indexes: Dict[str, List[str]]):
    """为动态路由表补齐缺失索引，避免使用不兼容的 IF NOT EXISTS 语法。"""
    try:
        existing_indexes = {
            index.get("name")
            for index in inspect(engine).get_indexes(table_name)
            if index.get("name")
        }
    except Exception:
        existing_indexes = set()

    with engine.begin() as conn:
        for index_name, columns in expected_indexes.items():
            if index_name in existing_indexes:
                continue
            column_sql = ", ".join(columns)
            conn.execute(
                text(f"CREATE INDEX {index_name} ON {table_name} ({column_sql})")
            )


def _row_to_route_dict(row) -> Dict:
    """数据库行转路由字典"""
    data = dict(row._mapping)
    raw_ips = data.get("external_ips") or "[]"
    raw_meta = data.get("metadata_json") or "{}"
    try:
        data["external_ips"] = json.loads(raw_ips)
    except Exception:
        data["external_ips"] = []
    try:
        data["metadata"] = json.loads(raw_meta)
    except Exception:
        data["metadata"] = {}
    data.pop("metadata_json", None)
    data["tls_enabled"] = bool(data.get("tls_enabled"))
    data["websocket_enabled"] = bool(data.get("websocket_enabled"))
    for dt_key in ("created_at", "updated_at", "deleted_at"):
        value = data.get(dt_key)
        if value is not None and hasattr(value, "isoformat"):
            data[dt_key] = value.isoformat()
    return data


def create_agent_ingress_route(db: Session, route_data: Dict) -> Dict:
    """创建路由记录"""
    table_name = get_agent_ingress_route_table_name()
    route_data = dict(route_data)
    route_data.setdefault("metadata", {})
    route_data.setdefault("status", "creating")
    route_data.setdefault("owner_service", "platform-agent")
    route_data.setdefault("path", "/")
    route_data.setdefault("path_type", "Prefix")
    route_data.setdefault("service_port", 80)
    now = datetime.utcnow()
    route_data["created_at"] = now
    route_data["updated_at"] = now
    insert_sql = text(f"""
        INSERT INTO {table_name}
        (route_id, project_id, namespace, agent_key, target_port, external_ips, host, path, ingress_type, path_type,
         service_port, ingress_name, service_name, tls_enabled, tls_secret_name, websocket_enabled, status, access_url,
         owner_service, created_by, metadata_json, created_at, updated_at, deleted_at)
        VALUES
        (:route_id, :project_id, :namespace, :agent_key, :target_port, :external_ips, :host, :path, :ingress_type, :path_type,
         :service_port, :ingress_name, :service_name, :tls_enabled, :tls_secret_name, :websocket_enabled, :status, :access_url,
         :owner_service, :created_by, :metadata_json, :created_at, :updated_at, NULL)
    """)
    db.execute(insert_sql, {
        "route_id": route_data["route_id"],
        "project_id": route_data["project_id"],
        "namespace": route_data["namespace"],
        "agent_key": route_data["agent_key"],
        "target_port": int(route_data["target_port"]),
        "external_ips": json.dumps(route_data.get("external_ips", []), ensure_ascii=False),
        "host": route_data["host"],
        "path": route_data["path"],
        "ingress_type": route_data["ingress_type"],
        "path_type": route_data["path_type"],
        "service_port": int(route_data["service_port"]),
        "ingress_name": route_data["ingress_name"],
        "service_name": route_data["service_name"],
        "tls_enabled": int(bool(route_data.get("tls_enabled"))),
        "tls_secret_name": route_data.get("tls_secret_name"),
        "websocket_enabled": int(bool(route_data.get("websocket_enabled", True))),
        "status": route_data.get("status", "creating"),
        "access_url": route_data.get("access_url"),
        "owner_service": route_data.get("owner_service"),
        "created_by": route_data.get("created_by"),
        "metadata_json": json.dumps(route_data.get("metadata", {}), ensure_ascii=False),
        "created_at": route_data["created_at"],
        "updated_at": route_data["updated_at"],
    })
    db.commit()
    return get_agent_ingress_route(db, route_data["route_id"])


def update_agent_ingress_route(db: Session, route_id: str, updates: Dict) -> Optional[Dict]:
    """更新路由记录"""
    table_name = get_agent_ingress_route_table_name()
    fields = []
    params = {"route_id": route_id}
    for key, value in updates.items():
        if key == "external_ips":
            fields.append("external_ips = :external_ips")
            params["external_ips"] = json.dumps(value or [], ensure_ascii=False)
        elif key == "metadata":
            fields.append("metadata_json = :metadata_json")
            params["metadata_json"] = json.dumps(value or {}, ensure_ascii=False)
        elif key in {"tls_enabled", "websocket_enabled"}:
            fields.append(f"{key} = :{key}")
            params[key] = int(bool(value))
        elif key in {"project_id", "namespace", "agent_key", "target_port", "host", "path", "ingress_type",
                     "path_type", "service_port", "ingress_name", "service_name", "tls_secret_name", "status",
                     "access_url", "owner_service", "created_by", "deleted_at"}:
            fields.append(f"{key} = :{key}")
            params[key] = value
    fields.append("updated_at = :updated_at")
    params["updated_at"] = datetime.utcnow()
    if not fields:
        return get_agent_ingress_route(db, route_id)
    sql = text(f"UPDATE {table_name} SET {', '.join(fields)} WHERE route_id = :route_id")
    db.execute(sql, params)
    db.commit()
    return get_agent_ingress_route(db, route_id)


def get_agent_ingress_route(db: Session, route_id: str) -> Optional[Dict]:
    """按ID获取路由记录"""
    table_name = get_agent_ingress_route_table_name()
    sql = text(f"SELECT * FROM {table_name} WHERE route_id = :route_id")
    row = db.execute(sql, {"route_id": route_id}).fetchone()
    if not row:
        return None
    return _row_to_route_dict(row)


def get_agent_ingress_route_by_unique_key(
    db: Session,
    project_id: str,
    agent_key: str,
    target_port: int,
    host: str,
    path: str,
) -> Optional[Dict]:
    """按业务唯一键查询路由"""
    table_name = get_agent_ingress_route_table_name()
    sql = text(f"""
        SELECT *
        FROM {table_name}
        WHERE project_id = :project_id
          AND agent_key = :agent_key
          AND target_port = :target_port
          AND host = :host
          AND path = :path
          AND deleted_at IS NULL
        ORDER BY updated_at DESC
        LIMIT 1
    """)
    row = db.execute(sql, {
        "project_id": project_id,
        "agent_key": agent_key,
        "target_port": int(target_port),
        "host": host,
        "path": path,
    }).fetchone()
    if not row:
        return None
    return _row_to_route_dict(row)


def get_agent_ingress_route_by_host_path(
    db: Session,
    project_id: str,
    host: str,
    path: str,
) -> Optional[Dict]:
    """按 host + path 查询现存路由，用于拦截不同端口复用同一路由入口的冲突。"""
    table_name = get_agent_ingress_route_table_name()
    sql = text(f"""
        SELECT *
        FROM {table_name}
        WHERE project_id = :project_id
          AND host = :host
          AND path = :path
          AND deleted_at IS NULL
        ORDER BY updated_at DESC
        LIMIT 1
    """)
    row = db.execute(sql, {
        "project_id": project_id,
        "host": host,
        "path": path,
    }).fetchone()
    if not row:
        return None
    return _row_to_route_dict(row)


def list_agent_ingress_routes(
    db: Session,
    project_id: str,
    agent_key: Optional[str] = None,
    include_deleted: bool = False
) -> Dict:
    """查询路由列表"""
    table_name = get_agent_ingress_route_table_name()
    where_clause = ["project_id = :project_id"]
    params = {"project_id": project_id}
    if agent_key:
        where_clause.append("agent_key = :agent_key")
        params["agent_key"] = agent_key
    if not include_deleted:
        where_clause.append("deleted_at IS NULL")
    sql = text(f"""
        SELECT *
        FROM {table_name}
        WHERE {' AND '.join(where_clause)}
        ORDER BY updated_at DESC
    """)
    rows = db.execute(sql, params).fetchall()
    return {
        "total": len(rows),
        "items": [_row_to_route_dict(row) for row in rows]
    }
