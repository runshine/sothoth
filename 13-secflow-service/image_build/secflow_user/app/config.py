"""配置文件"""

import os
import yaml
from pathlib import Path

# 查找配置文件
possible_paths = [
    Path(__file__).parent.parent / "config.yaml",  # /app/config.yaml
    Path(__file__).parent / "config.yaml",         # /app/app/config.yaml
    Path.cwd() / "config.yaml",                    # 当前目录
]

config = None
config_file = None

for p in possible_paths:
    if p.exists():
        config_file = p
        with open(p, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
        break

if config is None:
    raise FileNotFoundError("配置文件 config.yaml 不存在")

# 数据库配置
DB_HOST = config.get("database", {}).get("host", "localhost")
DB_PORT = config.get("database", {}).get("port", 3306)
DB_NAME = config.get("database", {}).get("name", "secflow_user")
DB_USER = config.get("database", {}).get("username", "secflow_user")
DB_PASSWORD = config.get("database", {}).get("password", "password")
DB_CHARSET = config.get("database", {}).get("charset", "utf8mb4")

# MySQL连接URL
DATABASE_URL = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset={DB_CHARSET}"