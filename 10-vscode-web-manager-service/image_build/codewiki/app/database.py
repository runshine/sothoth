# app/database.py
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base
import os

# 数据库URL
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./data/codewiki.db")

# 创建异步引擎
engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    future=True
)

# 创建异步session工厂
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)


async def get_db():
    """获取数据库会话"""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    """初始化数据库"""
    from app import models

    async with engine.begin() as conn:
        # 创建所有表
        await conn.run_sync(models.Base.metadata.create_all)

    print("Database initialized successfully")