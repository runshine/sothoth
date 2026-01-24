"""
自定义异常类
"""
from typing import Optional, Dict, Any

class CodeServerError(Exception):
    """Code-Server操作异常"""
    def __init__(self, message: str, details: Optional[Dict] = None, status_code: int = 500):
        self.message = message
        self.details = details or {}
        self.status_code = status_code
        super().__init__(self.message)

class ProjectError(Exception):
    """项目操作异常"""
    def __init__(self, message: str, details: Optional[Dict] = None, status_code: int = 500):
        self.message = message
        self.details = details or {}
        self.status_code = status_code
        super().__init__(self.message)