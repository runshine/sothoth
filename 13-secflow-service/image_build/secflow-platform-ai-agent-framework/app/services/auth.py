from __future__ import annotations

from typing import Optional, Tuple

import httpx
from fastapi import HTTPException, status

from app.config import get_config


class AuthService:
    def _service_headers(self) -> dict[str, str]:
        token = get_config().auth_service.service_machine_token
        if not token:
            return {}
        return {"X-Service-Authorization": f"Bearer {token}"}

    async def startup_validate(self) -> None:
        config = get_config().auth_service
        if not config.enabled:
            return
        async with httpx.AsyncClient(timeout=config.timeout) as client:
            await client.get(f"http://{config.host}:{config.port}", headers=self._service_headers())

    async def validate_human_authorization(self, authorization: Optional[str]) -> Tuple[dict, str]:
        config = get_config().auth_service
        if not config.enabled:
            return {"user_id": "test-user", "project_ids": ["default", "project-1"]}, authorization or ""
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer token")
        token = authorization.split(" ", 1)[1]
        async with httpx.AsyncClient(timeout=config.timeout) as client:
            response = await client.post(
                config.human_validate_url,
                headers={"Authorization": f"Bearer {token}", **self._service_headers()},
            )
        if response.status_code != 200:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="human token invalid")
        payload = response.json() if response.text else {}
        return payload, token

    async def validate_machine_authorization(self, authorization: Optional[str]) -> Tuple[dict, str]:
        config = get_config().auth_service
        if not config.enabled:
            return {"token_type": "machine", "project_ids": ["default", "project-1"]}, authorization or ""
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer token")
        token = authorization.split(" ", 1)[1]
        async with httpx.AsyncClient(timeout=config.timeout) as client:
            response = await client.post(
                config.machine_validate_url,
                headers={"Authorization": f"Bearer {token}", **self._service_headers()},
            )
        if response.status_code != 200:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="machine token invalid")
        payload = response.json() if response.text else {}
        return payload, token


_auth_service: AuthService | None = None


def get_auth_service() -> AuthService:
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService()
    return _auth_service
