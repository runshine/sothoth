from __future__ import annotations

from typing import Optional, Tuple

import httpx
from fastapi import HTTPException, status

from app.config import get_config


class AuthService:
    async def validate_human_authorization(self, authorization: Optional[str]) -> Tuple[dict, str]:
        if not authorization:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authorization required")
        async with httpx.AsyncClient(timeout=get_config().auth_service.timeout) as client:
            response = await client.post(
                get_config().auth_service.human_validate_url,
                headers={"Authorization": authorization},
            )
        if response.status_code != 200:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="human token invalid")
        return response.json(), authorization

    async def startup_validate(self) -> None:
        token = get_config().auth_service.service_machine_token
        if not token:
            return
        async with httpx.AsyncClient(timeout=get_config().auth_service.timeout) as client:
            response = await client.post(
                get_config().auth_service.machine_validate_url,
                headers={"Authorization": f"Bearer {token}"},
            )
        if response.status_code != 200:
            raise RuntimeError("machine token invalid")


_auth_service: AuthService | None = None


def get_auth_service() -> AuthService:
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService()
    return _auth_service
