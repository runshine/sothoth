"""配置文件"""

import os
import yaml
from pathlib import Path
from typing import Optional
from pydantic import BaseModel

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


class ProjectServiceConfig(BaseModel):
    """Project服务配置"""
    host: str
    port: int
    project_list_path: str = "/api/project/list"
    project_base_path: str = "/api/project"
    timeout: int = 10

    @property
    def project_list_url(self) -> str:
        """生成项目列表的URL"""
        return f"http://{self.host}:{self.port}{self.project_list_path}"

    @property
    def base_url(self) -> str:
        """生成基础URL"""
        return f"http://{self.host}:{self.port}{self.project_base_path}"

    def get_project_url(self, project_id: str) -> str:
        """生成项目URL"""
        return f"{self.base_url}/{project_id}"

    def get_role_url(self, project_id: str) -> str:
        """生成项目角色管理URL"""
        return f"{self.base_url}/{project_id}/role"


class Config:
    """应用配置"""
    project_service: Optional[ProjectServiceConfig] = None

    def __init__(self):
        # 初始化Project服务配置
        project_config = config.get("project_service", {})
        if project_config:
            self.project_service = ProjectServiceConfig(**project_config)


# 全局配置实例
_config = Config()


def get_config() -> Config:
    """获取配置实例"""
    return _config