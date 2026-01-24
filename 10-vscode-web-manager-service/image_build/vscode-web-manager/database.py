"""
数据库连接管理
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import QueuePool

from config import Config
from models import Base

# 使用安全的数据库URL
safe_database_url = Config.DATABASE_URL
print(f"使用数据库URL: {safe_database_url}")

engine = create_engine(
    safe_database_url,  # 使用安全的URL
    poolclass=QueuePool,
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,  # 添加连接健康检查
    echo=Config.DEBUG,  # 调试模式下显示SQL
    connect_args={
        'ssl': False,
        'connect_timeout': 10
    } if safe_database_url.startswith("mysql") else {"check_same_thread": False}
)

SessionLocal = sessionmaker(bind=engine)


def get_db():
    """数据库会话依赖注入"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """初始化数据库"""
    try:
        Base.metadata.create_all(bind=engine)
        print("数据库表创建成功")

        # 创建默认管理员
        from utils.auth_utils import pwd_context
        db = SessionLocal()
        try:
            from models import User
            admin = db.query(User).filter(User.username == "admin").first()
            if not admin:
                admin = User(
                    username="admin",
                    email="admin@example.com",
                    password_hash=pwd_context.hash("admin123"),
                    is_admin=True
                )
                db.add(admin)
                db.commit()
                print("创建默认管理员: admin/admin123")
        except Exception as e:
            print(f"创建默认管理员失败: {e}")
            print(f"错误详情: {type(e).__name__}: {str(e)}")
            db.rollback()
        finally:
            db.close()
    except Exception as e:
        print(f"初始化数据库失败: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()  # 打印详细堆栈信息
        exit(255)