"""Project service for validating project existence via secflow_project service."""

import httpx
from typing import Optional
from pydantic import BaseModel


class ProjectInfo(BaseModel):
    """项目信息（来自secflow_project服务）。"""
    id: str
    name: str
    description: Optional[str] = None
    owner_id: str
    owner_name: Optional[str] = None
    status: str
    created_at: str
    updated_at: str
    roles: list = []


class ProjectService:
    """项目服务，用于调用secflow_project验证项目。"""

    def __init__(
        self,
        base_url: str,
        get_project_path: str = "/api/project",
        timeout: int = 10,
        service_machine_token: Optional[str] = None,
    ):
        """
        初始化项目服务。

        Args:
            base_url: secflow_project服务的基础URL
            get_project_path: 获取项目详情路径
            timeout: 请求超时时间（秒）
        """
        self.base_url = base_url.rstrip("/")
        self.get_project_path = get_project_path
        self.timeout = timeout
        self.service_machine_token = service_machine_token

    def _build_headers(self, token: Optional[str]) -> dict:
        if token:
            return {"Authorization": f"Bearer {token}"}
        if self.service_machine_token:
            return {"Authorization": f"Bearer {self.service_machine_token}"}
        return {}

    async def get_project(
        self,
        project_id: str,
        token: Optional[str] = None
    ) -> Optional[ProjectInfo]:
        """
        获取项目信息（验证项目是否存在及权限）。

        Args:
            project_id: 项目ID
            token: 用户Token

        Returns:
            ProjectInfo: 验证成功返回项目信息
            None: 项目不存在或无权限
        """
        url = f"{self.base_url}{self.get_project_path}/{project_id}"
        headers = self._build_headers(token)

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    url,
                    headers=headers,
                    timeout=self.timeout
                )

                if response.status_code == 200:
                    data = response.json()
                    return ProjectInfo(**data)
                elif response.status_code == 404:
                    return None
                else:
                    return None

        except Exception as e:
            print(f"Failed to get project: {e}")
            return None

    async def validate_project_access(
        self,
        project_id: str,
        token: Optional[str] = None
    ) -> tuple[bool, Optional[ProjectInfo]]:
        """
        验证用户对项目的访问权限。

        Args:
            project_id: 项目ID
            token: 用户Token

        Returns:
            tuple: (是否有权限, 项目信息)
        """
        project = await self.get_project(project_id, token)

        if project is None:
            return False, None

        if project.status != "active":
            return False, None

        return True, project

    async def get_project_info(
        self,
        project_id: str,
        token: Optional[str] = None
    ) -> dict:
        """
        获取项目信息（返回字典格式）。

        Args:
            project_id: 项目ID
            token: 用户Token

        Returns:
            dict: 项目信息字典
        """
        project = await self.get_project(project_id, token)
        if project:
            return {
                "id": project.id,
                "name": project.name,
                "description": project.description,
                "owner_id": project.owner_id,
                "owner_name": project.owner_name,
                "status": project.status
            }
        return {
            "id": project_id,
            "name": project_id,
            "status": "active"
        }
_project_service: Optional[ProjectService] = None


def get_project_service() -> ProjectService:
    """获取项目服务实例。"""
    global _project_service
    if _project_service is None:
        raise RuntimeError("Project service not initialized")
    return _project_service


def init_project_service(
    base_url: str,
    get_project_path: str = "/api/project",
    timeout: int = 10,
    service_machine_token: Optional[str] = None,
):
    """初始化项目服务实例。"""
    global _project_service
    _project_service = ProjectService(
        base_url=base_url,
        get_project_path=get_project_path,
        timeout=timeout,
        service_machine_token=service_machine_token,
    )
