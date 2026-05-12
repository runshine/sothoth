from __future__ import annotations

from typing import Any

import httpx

from app.config import get_config


class VulnClient:
    async def get_case(self, case_id: str, token: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=get_config().vuln_service.timeout) as client:
            response = await client.get(
                f"{get_config().vuln_service.api_base}/cases/{case_id}",
                headers={"Authorization": token},
            )
        response.raise_for_status()
        return response.json()

    async def list_cases(self, token: str, **params: Any) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=get_config().vuln_service.timeout) as client:
            response = await client.get(
                f"{get_config().vuln_service.api_base}/cases",
                params=params,
                headers={"Authorization": token},
            )
        response.raise_for_status()
        return response.json()

    async def delete_case(self, case_id: str, token: str) -> None:
        async with httpx.AsyncClient(timeout=get_config().vuln_service.timeout) as client:
            response = await client.delete(
                f"{get_config().vuln_service.api_base}/cases/{case_id}",
                headers={"Authorization": token},
            )
        response.raise_for_status()


_client: VulnClient | None = None


def get_vuln_client() -> VulnClient:
    global _client
    if _client is None:
        _client = VulnClient()
    return _client
