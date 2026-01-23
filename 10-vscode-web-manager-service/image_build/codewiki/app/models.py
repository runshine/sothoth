# app/models.py
from datetime import datetime
from typing import Optional, List, Dict, Any
from sqlalchemy import Column, String, DateTime, Text, JSON, Integer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Task(Base):
    """任务表模型"""
    __tablename__ = "tasks"

    id = Column(String(36), primary_key=True, index=True)
    status = Column(String(20), default="pending")  # pending, running, completed, failed, stopped
    include_patterns = Column(JSON, nullable=True)
    exclude_patterns = Column(JSON, nullable=True)
    folder = Column(String(500), default=".")
    config_overrides = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

    @classmethod
    async def create(cls, db: AsyncSession, **kwargs):
        """创建任务"""
        task = cls(**kwargs)
        db.add(task)
        await db.commit()
        await db.refresh(task)
        return task

    @classmethod
    async def get(cls, db: AsyncSession, task_id: str):
        """获取任务"""
        result = await db.execute(select(cls).where(cls.id == task_id))
        return result.scalar_one_or_none()

    @classmethod
    async def get_all(cls, db: AsyncSession, skip: int = 0, limit: int = 100):
        """获取所有任务"""
        result = await db.execute(
            select(cls)
            .order_by(cls.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()

    @classmethod
    async def update(cls, db: AsyncSession, task_id: str, **kwargs):
        """更新任务"""
        task = await cls.get(db, task_id)
        if task:
            for key, value in kwargs.items():
                setattr(task, key, value)
            task.updated_at = datetime.utcnow()
            await db.commit()
            await db.refresh(task)
        return task

    @classmethod
    async def delete(cls, db: AsyncSession, task_id: str):
        """删除任务"""
        task = await cls.get(db, task_id)
        if task:
            await db.delete(task)
            await db.commit()
            return True
        return False


class Config(Base):
    """配置表模型"""
    __tablename__ = "configs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(100), unique=True, index=True)
    value = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @classmethod
    async def get_all(cls, db: AsyncSession) -> Dict[str, Any]:
        """获取所有配置"""
        result = await db.execute(select(cls))
        configs = result.scalars().all()
        return {config.key: config.value for config in configs}

    @classmethod
    async def set(cls, db: AsyncSession, key: str, value: Any):
        """设置配置"""
        # 检查是否存在
        result = await db.execute(select(cls).where(cls.key == key))
        config = result.scalar_one_or_none()

        if config:
            config.value = str(value) if value is not None else None
        else:
            config = cls(key=key, value=str(value) if value is not None else None)
            db.add(config)

        await db.commit()
        return config

    @classmethod
    async def delete(cls, db: AsyncSession, key: str):
        """删除配置"""
        result = await db.execute(select(cls).where(cls.key == key))
        config = result.scalar_one_or_none()
        if config:
            await db.delete(config)
            await db.commit()
            return True
        return False