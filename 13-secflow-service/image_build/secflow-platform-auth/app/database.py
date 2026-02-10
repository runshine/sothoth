"""数据库连接"""

from sqlalchemy.orm import sessionmaker
from app.db_base import engine, Base


def init_db():
    """初始化数据库，创建所有表"""
    # 导入模型以注册表到 Base.metadata
    from app.model import User, Role, MachineToken  # noqa: F401
    # 在 SQLAlchemy 2.x 中，需要显式确保表都正确注册
    # 直接使用 create_all 会处理 FK 顺序
    with engine.begin() as connection:
        Base.metadata.create_all(bind=connection)


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