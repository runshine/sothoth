"""
Code Server Manager - 自定义异常
"""

from fastapi import HTTPException, status
from fastapi.responses import JSONResponse


class AppException(HTTPException):
    """应用基础异常"""
    def __init__(self, status_code: int, detail: str, headers: dict = None):
        super().__init__(status_code=status_code, detail=detail, headers=headers)


class NotFoundError(AppException):
    """资源不存在异常"""
    def __init__(self, resource: str, resource_id: str = None):
        message = f"{resource}不存在"
        if resource_id:
            message = f"{resource}不存在: {resource_id}"
        super().__init__(status_code=status.HTTP_404_NOT_FOUND, detail=message)


class ValidationError(AppException):
    """参数验证异常"""
    def __init__(self, message: str):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=message)


class ConflictError(AppException):
    """资源冲突异常"""
    def __init__(self, message: str):
        super().__init__(status_code=status.HTTP_409_CONFLICT, detail=message)


class InternalError(AppException):
    """内部错误异常"""
    def __init__(self, message: str = "内部服务器错误"):
        super().__init__(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=message)


def setup_exception_handlers(app):
    """设置全局异常处理器"""

    @app.exception_handler(NotFoundError)
    async def not_found_handler(request, exc):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": "Not Found", "detail": exc.detail}
        )

    @app.exception_handler(ValidationError)
    async def validation_error_handler(request, exc):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": "Validation Error", "detail": exc.detail}
        )

    @app.exception_handler(ConflictError)
    async def conflict_error_handler(request, exc):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": "Conflict", "detail": exc.detail}
        )

    @app.exception_handler(InternalError)
    async def internal_error_handler(request, exc):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": "Internal Server Error", "detail": exc.detail}
        )
