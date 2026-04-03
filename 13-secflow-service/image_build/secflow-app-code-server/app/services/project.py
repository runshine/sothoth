"""
Code Server Manager - 项目服务客户端
"""

from typing import Any, Dict, Optional

import httpx

from app.config import get_config
from app.exception import InternalError, NotFoundError, ValidationError


class ProjectClient:
    """Project service client (machine token)"""

    def __init__(self):
        cfg = get_config()
        self.project = cfg.project_service
        self.auth = cfg.auth_service
        self._client: Optional[httpx.Client] = None

    def _default_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        machine_token = getattr(self.auth, "service_machine_token", None)
        if machine_token:
            headers["Authorization"] = f"Bearer {machine_token}"
        return headers

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            timeout = self.project.timeout if self.project else 15
            self._client = httpx.Client(timeout=timeout, headers=self._default_headers())
        return self._client

    def _base_url(self) -> str:
        return self.project.base_url.rstrip("/")

    def get_project_namespace(self, project_id: str) -> str:
        if not getattr(self.project, "enabled", True):
            raise InternalError("项目服务未启用")
        project_id = str(project_id or "").strip()
        if not project_id:
            raise ValidationError("project_id 不能为空")

        url = f"{self._base_url()}/{project_id}"
        try:
            resp = self.client.get(url)
            resp.raise_for_status()
            payload: Dict[str, Any] = resp.json() if resp.content else {}
            namespace = str(payload.get("k8s_namespace") or "").strip()
            if namespace:
                return namespace
            # 兜底：与项目服务命名规则保持一致
            return f"secflow-{project_id}".replace("_", "-")
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                raise NotFoundError("项目", project_id)
            raise InternalError("查询项目namespace失败")
        except httpx.HTTPError:
            raise InternalError("项目服务不可用")


_project_client: Optional[ProjectClient] = None


def get_project_client() -> ProjectClient:
    global _project_client
    if _project_client is None:
        _project_client = ProjectClient()
    return _project_client

