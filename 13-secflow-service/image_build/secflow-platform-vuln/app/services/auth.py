"""Auth service integration."""

from typing import Optional

import httpx


class AuthService:
    def __init__(self, base_url: str, validate_path: str = "/api/auth/validate-token", timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.validate_path = validate_path
        self.timeout = timeout

    async def validate_token(self, token: str) -> Optional[dict]:
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{self.base_url}{self.validate_path}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(url, headers=headers)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None


_auth_service: Optional[AuthService] = None


def init_auth_service(base_url: str, validate_path: str = "/api/auth/validate-token", timeout: int = 10) -> None:
    global _auth_service
    _auth_service = AuthService(base_url=base_url, validate_path=validate_path, timeout=timeout)


def get_auth_service() -> AuthService:
    if _auth_service is None:
        raise RuntimeError("Auth service not initialized")
    return _auth_service
