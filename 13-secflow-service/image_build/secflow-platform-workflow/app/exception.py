"""
Exception definitions for workflow service
"""

from fastapi import HTTPException, Request
from starlette.responses import JSONResponse


class AppException(HTTPException):
    """Application base exception"""
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
    """Resource not found"""
    def __init__(self, resource: str, identifier: str):
        super().__init__(
            status_code=404,
            code="NOT_FOUND",
            message=f"{resource} not found: {identifier}"
        )


class ForbiddenError(AppException):
    """Permission denied"""
    def __init__(self, message: str = "Access to this resource is forbidden"):
        super().__init__(
            status_code=403,
            code="FORBIDDEN",
            message=message
        )


class UnauthorizedError(AppException):
    """Not authenticated"""
    def __init__(self, message: str = "Please login first"):
        super().__init__(
            status_code=401,
            code="UNAUTHORIZED",
            message=message
        )


class ValidationError(AppException):
    """Parameter validation error"""
    def __init__(self, message: str, details: dict = None):
        super().__init__(
            status_code=400,
            code="VALIDATION_ERROR",
            message=message,
            details=details
        )


class ConflictError(AppException):
    """Resource conflict"""
    def __init__(self, message: str):
        super().__init__(
            status_code=409,
            code="CONFLICT",
            message=message
        )


class InternalError(AppException):
    """Internal error"""
    def __init__(self, message: str, details: dict = None):
        super().__init__(
            status_code=500,
            code="INTERNAL_ERROR",
            message=message,
            details=details
        )


def handle_exception(request: Request, exc: AppException):
    """Handle application exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.detail
    )


def setup_exception_handlers(app):
    """Setup exception handlers"""
    from fastapi import FastAPI
    app.add_exception_handler(AppException, handle_exception)
