"""
项目服务模块 - 用于调用project服务获取项目信息
"""

import logging
from typing import Optional

import httpx

from app.config import get_config

logger = logging.getLogger(__name__)


class ProjectServiceError(Exception):
    """项目服务错误"""
    pass


class ProjectInfo:
    """项目信息"""
    def __init__(self, data: dict):
        self.id = data.get("id")
        self.name = data.get("name")
        self.description = data.get("description")
        self.owner_id = data.get("owner_id")
        self.owner_name = data.get("owner_name")
        self.k8s_namespace = data.get("k8s_namespace")
        self.status = data.get("status")


class ProjectService:
    """项目服务客户端"""

    def __init__(self):
        self.config = get_config().project_service
        self.client = httpx.Client(timeout=self.config.timeout)

    def get_project_url(self, project_id: str) -> str:
        """获取项目详情URL"""
        return f"{self.config.base_url}{self.config.get_project_path}/{project_id}"

    def get_project(self, project_id: str, token: str) -> Optional[ProjectInfo]:
        """
        获取项目信息

        Args:
            project_id: 项目ID
            token: 用户Token

        Returns:
            ProjectInfo: 项目信息
            None: 项目不存在或无权限
        """
        try:
            headers = {"Authorization": f"Bearer {token}"}
            response = self.client.get(
                self.get_project_url(project_id),
                headers=headers
            )

            if response.status_code == 200:
                data = response.json()
                return ProjectInfo(data)
            elif response.status_code == 404:
                return None
            else:
                logger.warning(f"获取项目失败: {response.status_code}")
                return None

        except httpx.TimeoutException:
            logger.error("项目服务请求超时")
            return None
        except httpx.ConnectError as e:
            logger.error(f"无法连接到项目服务: {e}")
            return None

    async def get_project_async(self, project_id: str, token: str) -> Optional[ProjectInfo]:
        """
        异步获取项目信息

        Args:
            project_id: 项目ID
            token: 用户Token

        Returns:
            ProjectInfo: 项目信息
            None: 项目不存在或无权限
        """
        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            try:
                headers = {"Authorization": f"Bearer {token}"}
                response = await client.get(
                    self.get_project_url(project_id),
                    headers=headers
                )

                if response.status_code == 200:
                    data = response.json()
                    return ProjectInfo(data)
                elif response.status_code == 404:
                    return None
                else:
                    logger.warning(f"获取项目失败: {response.status_code}")
                    return None

            except httpx.TimeoutException:
                logger.error("项目服务请求超时")
                return None
            except httpx.ConnectError as e:
                logger.error(f"无法连接到项目服务: {e}")
                return None


# 单例实例
_project_service: Optional[ProjectService] = None


def get_project_service() -> ProjectService:
    """获取项目服务实例"""
    global _project_service
    if _project_service is None:
        _project_service = ProjectService()
    return _project_service