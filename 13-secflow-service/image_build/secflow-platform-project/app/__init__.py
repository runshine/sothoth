"""
App包初始化
"""

from app.config import get_config, load_config
from app.model import init_database

__all__ = ["get_config", "load_config", "init_database"]