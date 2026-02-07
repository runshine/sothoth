"""SQLAlchemy 基础配置 - 定义 engine 和 Base"""

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from app.config import DATABASE_URL

# 创建数据库引擎
engine = create_engine(DATABASE_URL, pool_pre_ping=True)

# 创建基类，所有模型都继承自这个类
Base = declarative_base()
