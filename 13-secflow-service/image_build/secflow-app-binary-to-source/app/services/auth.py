"""Auth service integration."""

from typing import Optional

import httpx

from app.config import get_config


class AuthService:
    def __init__(self):
        self.cfg = get_config().auth_service

    async def validate_token(self, token: str) -> Optional[dict]:
        if not self.cfg.enabled:
            return {"id": "anonymous", "username": "anonymous", "token_type": "user"}
        headers = {"Authorization": f"Bearer {token}"}
        try:
            async with httpx.AsyncClient(timeout=self.cfg.timeout) as client:
                response = await client.post(self.cfg.validate_url, headers=headers)
            if response.status_code == 200:
                payload = response.json() if response.content else {}
                payload["token"] = token
                return payload
            return None
        except Exception:
            return None


_auth_service: Optional[AuthService] = None


def get_auth_service() -> AuthService:
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService()
    return _auth_service
