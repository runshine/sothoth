"""Auth dependency for poc-gen-verify: token validation via platform auth service.

Adapted from DVS app/api/deps.py. Supports:
- User Bearer token validation (via secflow-platform-auth)
- Service machine token (internal inter-service calls)
- Token cache (in-memory, TTL-based) to reduce auth service load
"""
from __future__ import annotations

import time
from typing import Dict, Optional, Tuple

from fastapi import Header, HTTPException

from app.config import get_service_yaml

# In-memory token cache: token → (user_dict, expires_at)
_TOKEN_CACHE: dict[str, tuple[dict, float]] = {}


class AuthServiceError(Exception):
    pass


class TokenInvalidError(AuthServiceError):
    pass


def _cache_get(token: str) -> Optional[dict]:
    cfg = get_service_yaml().auth_service
    if not cfg.token_cache_enabled:
        return None
    entry = _TOKEN_CACHE.get(token)
    if entry is None:
        return None
    user, expires_at = entry
    if time.time() > expires_at:
        _TOKEN_CACHE.pop(token, None)
        return None
    return user


def _cache_put(token: str, user: dict) -> None:
    cfg = get_service_yaml().auth_service
    if not cfg.token_cache_enabled:
        return
    ttl = cfg.token_cache_ttl_minutes * 60
    _TOKEN_CACHE[token] = (user, time.time() + ttl)
    # Simple eviction: if cache grows too large, clear old entries
    if len(_TOKEN_CACHE) > 1000:
        now = time.time()
        for k in list(_TOKEN_CACHE):
            if _TOKEN_CACHE[k][1] < now:
                _TOKEN_CACHE.pop(k, None)


def extract_bearer_token(authorization: Optional[str]) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    token = authorization.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    return token


def _validate_token(token: str, project_id: Optional[str] = None) -> dict:
    # Check service machine token first (internal calls)
    cfg = get_service_yaml().auth_service
    if cfg.service_machine_token and token == cfg.service_machine_token:
        return {"platform_role": "super_admin", "token_type": "machine", "username": "service-machine"}

    # Check cache
    cached = _cache_get(token)
    if cached is not None:
        return cached

    # Validate via auth service
    params = {"project_id": project_id} if project_id else None
    try:
        import httpx
        with httpx.Client(timeout=cfg.timeout) as client:
            response = client.post(
                cfg.validate_url,
                headers={"Authorization": f"Bearer {token}"},
                params=params,
            )
    except Exception as exc:
        # If auth service is unreachable, allow through with a warning (fail-open for availability)
        # but only for health/ready endpoints. For data endpoints, reject.
        raise AuthServiceError(f"无法连接到认证服务: {exc}") from exc
    if response.status_code == 401:
        raise TokenInvalidError("Token已过期或无效")
    if response.status_code != 200:
        raise AuthServiceError(f"认证服务返回异常状态码: {response.status_code}")
    user = response.json()
    _cache_put(token, user)
    return user


def get_current_user(
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> Tuple[Dict, str]:
    """FastAPI dependency: extract and validate the Bearer token → (user_dict, token)."""
    token = extract_bearer_token(authorization)
    try:
        user = _validate_token(token)
    except TokenInvalidError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except AuthServiceError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return user, token


def ensure_project_access(project_id: str, token: str) -> Dict:
    """Validate that the token has access to the given project."""
    try:
        return _validate_token(token, project_id=project_id)
    except TokenInvalidError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except AuthServiceError as exc:
        raise HTTPException(status_code=403, detail=f"project access denied: {exc}") from exc


def ensure_admin_user(user: Dict) -> Dict:
    """Check that the user has admin privileges."""
    platform_role = str(user.get("platform_role") or "").strip()
    role_names = {str(item).strip() for item in (user.get("role") or []) if str(item).strip()}
    token_type = str(user.get("token_type") or "").strip().lower()
    if token_type == "machine":
        return user
    if platform_role in {"super_admin", "ordinary_admin"}:
        return user
    if {"super_admin", "admin", "ordinary_admin"} & role_names:
        return user
    raise HTTPException(status_code=403, detail="需要管理员权限")
