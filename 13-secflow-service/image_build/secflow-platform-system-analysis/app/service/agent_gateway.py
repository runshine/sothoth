"""Gateway to secflow-platform-agent service."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import httpx

from app.config import get_config


class AgentGatewayError(Exception):
    pass


class AgentGateway:
    def __init__(self):
        cfg = get_config().agent_service
        self.base_url = cfg.base_url.rstrip("/")
        self.timeout = cfg.timeout

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        token: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], int]:
        url = f"{self.base_url}{path}"
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.request(method, url, params=params, json=json_body, headers=headers)
        except httpx.HTTPError as exc:
            raise AgentGatewayError(str(exc)) from exc

        payload: Dict[str, Any]
        try:
            payload = resp.json() if resp.text else {}
        except Exception:
            payload = {"raw": resp.text}
        return payload, resp.status_code

    async def list_agents(self, project_id: str, token: Optional[str] = None) -> List[Dict[str, Any]]:
        payload, code = await self._request(
            "GET", "/api/agent/agents", params={"project_id": project_id, "page": 1, "per_page": 2000}, token=token
        )
        if code >= 300:
            raise AgentGatewayError(f"list_agents failed: {code} {payload}")
        return payload.get("agents", []) if isinstance(payload.get("agents"), list) else []

    async def list_ai_helpers(self, project_id: str, token: Optional[str] = None) -> List[Dict[str, Any]]:
        payload, code = await self._request("GET", "/api/agent/ai-helpers", params={"project_id": project_id}, token=token)
        if code >= 300:
            raise AgentGatewayError(f"list_ai_helpers failed: {code} {payload}")
        return payload.get("items", []) if isinstance(payload.get("items"), list) else []

    async def get_helper_agents(self, project_id: str, agent_key: str, service_name: str, token: Optional[str] = None) -> List[Dict[str, Any]]:
        path = f"/api/agent/ai-helpers/{quote(agent_key, safe='')}/{quote(service_name, safe='')}/agents"
        payload, code = await self._request("GET", path, params={"project_id": project_id}, token=token)
        if code >= 300:
            raise AgentGatewayError(f"get_helper_agents failed: {code} {payload}")
        return payload.get("items", []) if isinstance(payload.get("items"), list) else []

    async def create_helper_session(
        self,
        project_id: str,
        agent_key: str,
        service_name: str,
        ai_agent_id: str,
        token: Optional[str] = None,
    ) -> Dict[str, Any]:
        path = f"/api/agent/ai-helpers/{quote(agent_key, safe='')}/{quote(service_name, safe='')}/sessions"
        payload, code = await self._request(
            "POST",
            path,
            params={"project_id": project_id},
            json_body={"project_id": project_id, "agent_id": ai_agent_id},
            token=token,
        )
        if code >= 300:
            raise AgentGatewayError(f"create_helper_session failed: {code} {payload}")
        return payload

    async def send_session_message(
        self,
        project_id: str,
        agent_key: str,
        service_name: str,
        session_id: str,
        content: str,
        token: Optional[str] = None,
    ) -> Dict[str, Any]:
        path = (
            f"/api/agent/ai-helpers/{quote(agent_key, safe='')}/{quote(service_name, safe='')}/sessions/"
            f"{quote(session_id, safe='')}/messages"
        )
        payload, code = await self._request(
            "POST",
            path,
            params={"project_id": project_id},
            json_body={"project_id": project_id, "role": "user", "content": content},
            token=token,
        )
        if code >= 300:
            raise AgentGatewayError(f"send_session_message failed: {code} {payload}")
        return payload

    async def delete_session(
        self,
        project_id: str,
        agent_key: str,
        service_name: str,
        session_id: str,
        token: Optional[str] = None,
    ) -> None:
        path = f"/api/agent/ai-helpers/{quote(agent_key, safe='')}/{quote(service_name, safe='')}/sessions/{quote(session_id, safe='')}"
        payload, code = await self._request(
            "DELETE",
            path,
            params={"project_id": project_id},
            json_body={"project_id": project_id},
            token=token,
        )
        if code >= 300 and code != 404:
            raise AgentGatewayError(f"delete_session failed: {code} {payload}")


_gateway: Optional[AgentGateway] = None


def get_agent_gateway() -> AgentGateway:
    global _gateway
    if _gateway is None:
        _gateway = AgentGateway()
    return _gateway

