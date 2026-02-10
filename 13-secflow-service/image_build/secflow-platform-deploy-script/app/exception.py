"""
异常定义模块
"""

from fastapi import Request
from fastapi.responses import JSONResponse


class AppException(Exception):
    """应用异常基类"""

    def __init__(self, message: str, status_code: int = 500, error_code: str = "INTERNAL_ERROR"):
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        super().__init__(message)


class UnauthorizedError(AppException):
    """未授权异常"""
    def __init__(self, message: str = "未授权访问"):
        super().__init__(message, status_code=401, error_code="UNAUTHORIZED")


class ForbiddenError(AppException):
    """禁止访问异常"""
    def __init__(self, message: str = "禁止访问"):
        super().__init__(message, status_code=403, error_code="FORBIDDEN")


class NotFoundError(AppException):
    """资源不存在异常"""
    def __init__(self, resource_type: str, resource_id: str):
        super().__init__(
            message=f"{resource_type}不存在: {resource_id}",
            status_code=404,
            error_code="NOT_FOUND"
        )


class ValidationError(AppException):
    """验证错误异常"""
    def __init__(self, message: str):
        super().__init__(message, status_code=400, error_code="VALIDATION_ERROR")


class ConflictError(AppException):
    """资源冲突异常"""
    def __init__(self, message: str):
        super().__init__(message, status_code=409, error_code="CONFLICT")


def setup_exception_handlers(app):
    """设置全局异常处理器"""

    @app.exception_handler(AppException)
    async def app_exception_handler(request: Request, exc: AppException):
        """处理应用异常"""
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error_code": exc.error_code,
                "message": exc.message,
            }
        )

    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        """处理通用异常"""
        return JSONResponse(
            status_code=500,
            content={
                "error_code": "INTERNAL_ERROR",
                "message": f"内部错误: {str(exc)}",
            }
        )