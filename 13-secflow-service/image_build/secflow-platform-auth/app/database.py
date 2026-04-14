"""数据库连接"""

import logging

from sqlalchemy import inspect, text
from sqlalchemy.orm import sessionmaker

from app.db_base import engine, Base

logger = logging.getLogger(__name__)


def _has_column(inspector, table_name: str, column_name: str) -> bool:
    try:
        columns = inspector.get_columns(table_name)
    except Exception:
        return False
    return any(column["name"] == column_name for column in columns)


def _has_index(inspector, table_name: str, index_name: str) -> bool:
    try:
        indexes = inspector.get_indexes(table_name)
    except Exception:
        return False
    return any(index.get("name") == index_name for index in indexes)


def run_auto_migrations():
    """启动时执行轻量级幂等迁移。"""
    inspector = inspect(engine)

    migrations = [
        {
            "name": "add_machine_token_scope",
            "check": lambda: _has_column(inspector, "secflow_user_machine_token", "token_scope"),
            "sql": """
                ALTER TABLE secflow_user_machine_token
                ADD COLUMN token_scope VARCHAR(32) NOT NULL DEFAULT 'global'
            """,
        },
        {
            "name": "add_machine_token_project_id",
            "check": lambda: _has_column(inspector, "secflow_user_machine_token", "project_id"),
            "sql": """
                ALTER TABLE secflow_user_machine_token
                ADD COLUMN project_id VARCHAR(64) NULL
            """,
        },
        {
            "name": "add_machine_token_project_id_index",
            "check": lambda: _has_index(inspector, "secflow_user_machine_token", "ix_secflow_user_machine_token_project_id"),
            "sql": """
                CREATE INDEX ix_secflow_user_machine_token_project_id
                ON secflow_user_machine_token (project_id)
            """,
        },
        {
            "name": "add_user_must_change_password",
            "check": lambda: _has_column(inspector, "secflow_user_users", "must_change_password"),
            "sql": """
                ALTER TABLE secflow_user_users
                ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT FALSE
            """,
        },
    ]

    with engine.begin() as connection:
        for migration in migrations:
            inspector = inspect(connection)
            if migration["check"]():
                continue
            logger.info("[Database] Applying migration: %s", migration["name"])
            connection.execute(text(migration["sql"]))
            logger.info("[Database] Migration applied: %s", migration["name"])


def init_db():
    """初始化数据库，创建所有表"""
    # 导入模型以注册表到 Base.metadata
    from app.model import User, Role, MachineToken  # noqa: F401
    # 在 SQLAlchemy 2.x 中，需要显式确保表都正确注册
    # 直接使用 create_all 会处理 FK 顺序
    with engine.begin() as connection:
        Base.metadata.create_all(bind=connection)
    run_auto_migrations()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """获取数据库会话"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_tables_exist():
    """验证数据库表是否真正存在，不存在则报错"""
    from sqlalchemy import inspect
    from app.db_base import engine

    inspector = inspect(engine)
    existing_tables_names = set(inspector.get_table_names())

    # 需要存在的表名
    required_tables_names = set()
    for table in Base.metadata.sorted_tables:
        required_tables_names.add(table.name)

    missing_tables_names = required_tables_names - existing_tables_names
    if missing_tables_names:
        raise RuntimeError(
            f"[Database] Tables verification failed! "
            f"Missing tables: {', '.join(sorted(missing_tables_names))}. "
            f"Expected: {', '.join(sorted(required_tables_names))}. "
            f"Existing: {', '.join(sorted(existing_tables_names))}"
        )

    return True
