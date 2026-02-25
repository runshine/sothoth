"""
App package initialization
"""
from app.config import get_config, load_config
from app.models import create_tables

__all__ = ["get_config", "load_config", "create_tables"]
