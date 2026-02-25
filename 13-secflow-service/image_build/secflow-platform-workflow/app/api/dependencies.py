"""
Common dependencies for API routes
"""
from fastapi import Header
from typing import Optional, Dict
import hashlib
import time

from app.exception import UnauthorizedError
from app.services import get_auth_service, TokenInvalidError
from app.config import get_config


async def get_current_user(authorization: Optional[str] = Header(None)) -> Dict:
    """Get current user from authorization header"""
    config = get_config()

    # If authentication is disabled, return a default system user
    if not config.auth_service.enabled:
        return {
            "id": "system",
            "username": "system",
            "is_active": True,
            "role": ["admin"]
        }

    if not authorization:
        raise UnauthorizedError("Missing Authorization header")

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise UnauthorizedError("Invalid Authorization header format. Expected: Bearer <token>")

    token = parts[1]

    try:
        auth_service = get_auth_service()
        user = await auth_service.validate_token_async(token)
        return user
    except TokenInvalidError:
        raise UnauthorizedError("Token is invalid or expired")


def generate_id(name: str) -> str:
    """Generate a 16-character MD5 ID"""
    unique_str = f"{name}_{time.time()}"
    return hashlib.md5(unique_str.encode()).hexdigest()[:16]
