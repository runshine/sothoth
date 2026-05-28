"""
异常定义模块
"""

from fastapi import HTTPException, Request


class AppException(HTTPException):
    """应用基础异常"""
    def __init__(self, status_code: int, code: str, message: str, details: dict = None):
        super().__init__(status_code=status_code, detail={
            "code": code,
            "message": message,
            "details": details
        })
        self.code = code
        self.message = message
        self.details = details


class NotFoundError(AppException):
    """资源不存在"""
    def __init__(self, resource: str, identifier: str):
        super().__init__(
            status_code=404,
            code="NOT_FOUND",
            message=f"{resource}不存在: {identifier}"
        )


class ForbiddenError(AppException):
    """无权限访问"""
    def __init__(self, message: str = "无权访问此资源"):
        super().__init__(
            status_code=403,
            code="FORBIDDEN",
            message=message
        )


class UnauthorizedError(AppException):
    """未认证"""
    def __init__(self, message: str = "请先登录"):
        super().__init__(
            status_code=401,
            code="UNAUTHORIZED",
            message=message
        )


class ValidationError(AppException):
    """参数验证错误"""
    def __init__(self, message: str, details: dict = None):
        super().__init__(
            status_code=400,
            code="VALIDATION_ERROR",
            message=message,
            details=details
        )


class ConflictError(AppException):
    """资源冲突"""
    def __init__(self, message: str):
        super().__init__(
            status_code=409,
            code="CONFLICT",
            message=message
        )


class InternalError(AppException):
    """内部错误"""
    def __init__(self, message: str, details: dict = None):
        super().__init__(
            status_code=500,
            code="INTERNAL_ERROR",
            message=message,
            details=details
        )


class DependencyUnavailableError(AppException):
    """依赖服务暂时不可用"""
    def __init__(self, message: str = "依赖服务暂时不可用", details: dict = None):
        super().__init__(
            status_code=502,
            code="DEPENDENCY_UNAVAILABLE",
            message=message,
            details=details
        )


from starlette.responses import JSONResponse


def handle_exception(request: Request, exc: AppException):
    """处理应用异常"""
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.detail
    )


def setup_exception_handlers(app):
    """设置异常处理器"""
    from fastapi import FastAPI
    app.add_exception_handler(AppException, handle_exception)
