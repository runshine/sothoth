"""Application exceptions."""

from fastapi import Request
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse


class AppException(HTTPException):
    def __init__(self, status_code: int, code: str, message: str, details: dict | None = None):
        super().__init__(status_code=status_code, detail={
            "code": code,
            "message": message,
            "details": details,
        })


class ForbiddenError(AppException):
    def __init__(self, message: str = "无权访问此资源"):
        super().__init__(403, "FORBIDDEN", message)


class UnauthorizedError(AppException):
    def __init__(self, message: str = "请先登录"):
        super().__init__(401, "UNAUTHORIZED", message)


class NotFoundError(AppException):
    def __init__(self, resource: str, identifier: str):
        super().__init__(404, "NOT_FOUND", f"{resource}不存在: {identifier}")


class ConflictError(AppException):
    def __init__(self, message: str):
        super().__init__(409, "CONFLICT", message)


class ValidationError(AppException):
    def __init__(self, message: str, details: dict | None = None):
        super().__init__(400, "VALIDATION_ERROR", message, details)


def handle_exception(request: Request, exc: AppException):
    return JSONResponse(status_code=exc.status_code, content=exc.detail)


def setup_exception_handlers(app):
    app.add_exception_handler(AppException, handle_exception)

