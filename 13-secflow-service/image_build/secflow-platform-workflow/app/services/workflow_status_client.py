"""
Workflow status service API client.
"""

import logging
from typing import Any, Dict, List, Optional

import httpx

from app.config import get_config

logger = logging.getLogger(__name__)


class WorkflowStatusClient:
    """HTTP client wrapper for secflow-platform-workflow-status."""

    def __init__(self) -> None:
        config = get_config()
        self.status_service_config = config.workflow_status_service
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def client(self) -> httpx.AsyncClient:
        """Return a lazily created async HTTP client."""
        if self._client is None:
            timeout = self.status_service_config.timeout if self.status_service_config else 30
            self._client = httpx.AsyncClient(timeout=timeout)
        return self._client

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _get_base_url(self) -> str:
        """Return the workflow-status base URL."""
        return self.status_service_config.base_url

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Send a JSON request and return the decoded payload."""
        url = f"{self._get_base_url()}{path}"
        response = await self.client.request(method, url, params=params, json=json)
        response.raise_for_status()
        return response.json()

    async def record_node(
        self,
        node_id: str,
        instance_id: str,
        project_id: str,
        node_type: str,
        k8s_resource_name: str,
        k8s_resource_type: Optional[str] = None,
        initial_status: str = "Pending",
        init_logs: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload = {
            "node_id": node_id,
            "instance_id": instance_id,
            "project_id": project_id,
            "node_type": node_type,
            "k8s_resource_name": k8s_resource_name,
            "k8s_resource_type": k8s_resource_type,
            "initial_status": initial_status,
            "init_logs": init_logs,
        }
        return await self._request_json("POST", "/nodes", json=payload)

    async def sync_node_status(
        self,
        node_id: str,
        project_id: str,
        instance_id: str,
        node_type: str,
        k8s_resource_name: str,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        payload = {
            "project_id": project_id,
            "instance_id": instance_id,
            "node_type": node_type,
            "k8s_resource_name": k8s_resource_name,
            "timeout_seconds": timeout_seconds,
        }
        return await self._request_json("POST", f"/nodes/{node_id}/sync", json=payload)

    async def sync_all_nodes(
        self,
        instance_id: str,
        project_id: str,
        nodes: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        payload = {"project_id": project_id, "nodes": nodes}
        return await self._request_json("POST", f"/instances/{instance_id}/sync-all", json=payload)

    async def get_node_status(self, node_id: str, project_id: str) -> Optional[Dict[str, Any]]:
        try:
            data = await self._request_json("GET", f"/nodes/{node_id}", params={"project_id": project_id})
            return data.get("node")
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return None
            raise

    async def get_instance_nodes(self, instance_id: str, project_id: str) -> List[Dict[str, Any]]:
        data = await self._request_json("GET", f"/instances/{instance_id}/nodes", params={"project_id": project_id})
        return data.get("nodes", [])

    async def get_workflow_status(self, instance_id: str, project_id: str) -> Optional[Dict[str, Any]]:
        try:
            data = await self._request_json("GET", f"/instances/{instance_id}", params={"project_id": project_id})
            return data.get("workflow")
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return None
            raise

    async def get_ingress_controllers(self) -> List[Dict[str, Any]]:
        data = await self._request_json("GET", "/infra/ingress-controllers")
        return data.get("items", [])

    async def ensure_namespace(self, project_id: str) -> Dict[str, Any]:
        return await self._request_json("GET", f"/projects/{project_id}/namespace/ensure")

    async def list_project_resources(
        self,
        project_id: str,
        instance_prefix: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = {"instance_prefix": instance_prefix} if instance_prefix else None
        return await self._request_json("GET", f"/projects/{project_id}/resources", params=params)

    async def get_resource_logs(
        self,
        project_id: str,
        resource_type: str,
        resource_name: str,
        *,
        tail_lines: int = 100,
        container: Optional[str] = None,
        previous: bool = False,
    ) -> Dict[str, Any]:
        params = {
            "tail_lines": tail_lines,
            "container": container,
            "previous": previous,
        }
        return await self._request_json(
            "GET",
            f"/projects/{project_id}/resources/{resource_type}/{resource_name}/logs",
            params=params,
        )

    async def initialize_workflow(
        self,
        instance_id: str,
        project_id: str,
        nodes: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        payload = {"project_id": project_id, "nodes": nodes}
        return await self._request_json("POST", f"/instances/{instance_id}/initialize", json=payload)

    async def deinitialize_workflow(
        self,
        instance_id: str,
        project_id: str,
        nodes: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        payload = {"project_id": project_id, "nodes": nodes}
        return await self._request_json("POST", f"/instances/{instance_id}/uninitialize", json=payload)

    async def stop_workflow(
        self,
        instance_id: str,
        project_id: str,
        nodes: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        payload = {"project_id": project_id, "nodes": nodes}
        return await self._request_json("POST", f"/instances/{instance_id}/stop", json=payload)

    async def start_node(
        self,
        node_id: str,
        project_id: str,
        instance_id: str,
        node_type: str,
        k8s_resource_name: Optional[str] = None,
        job_config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        payload = {
            "project_id": project_id,
            "instance_id": instance_id,
            "node_type": node_type,
            "k8s_resource_name": k8s_resource_name,
            "job_config": job_config,
        }
        return await self._request_json("POST", f"/nodes/{node_id}/start", json=payload)

    async def start_monitoring(
        self,
        instance_id: str,
        project_id: str,
        nodes: List[Dict[str, Any]],
        poll_interval: int = 10,
    ) -> Dict[str, Any]:
        payload = {
            "instance_id": instance_id,
            "project_id": project_id,
            "nodes": nodes,
            "poll_interval": poll_interval,
        }
        return await self._request_json("POST", "/monitoring/start", json=payload)

    async def stop_monitoring(self, instance_id: str) -> bool:
        data = await self._request_json("POST", "/monitoring/stop", json={"instance_id": instance_id})
        return bool(data.get("success"))

    async def reset_job_nodes(
        self,
        instance_id: str,
        project_id: str,
        reset_logs: bool = False,
    ) -> Dict[str, Any]:
        payload = {
            "instance_id": instance_id,
            "project_id": project_id,
            "reset_logs": reset_logs,
        }
        return await self._request_json("POST", "/nodes/reset-job", json=payload)


_workflow_status_client: Optional[WorkflowStatusClient] = None


def get_workflow_status_client() -> WorkflowStatusClient:
    """Return the workflow status client singleton."""
    global _workflow_status_client
    if _workflow_status_client is None:
        _workflow_status_client = WorkflowStatusClient()
    return _workflow_status_client
