"""
Project服务客户端模块
"""

import logging
from typing import Optional, List, Dict, Any

import httpx

from app.config import get_config

logger = logging.getLogger(__name__)


class ProjectServiceError(Exception):
    """Project服务错误"""
    pass


class ProjectService:
    """Project服务客户端"""

    def __init__(self):
        self.config = get_config().project_service
        if not self.config:
            raise ProjectServiceError("Project服务配置未初始化")

    def _get_headers(self, token: str) -> Dict[str, str]:
        """生成请求头"""
        return {"Authorization": f"Bearer {token}"}

    def _handle_response(self, response: httpx.Response) -> Dict[str, Any]:
        """
        处理响应

        Args:
            response: HTTP响应

        Returns:
            响应数据

        Raises:
            ProjectServiceError: 服务异常
        """
        if response.status_code == 401:
            raise ProjectServiceError("Token无效或已过期")
        if response.status_code == 403:
            raise ProjectServiceError("无权限执行此操作")
        if response.status_code == 404:
            raise ProjectServiceError("资源不存在")
        if response.status_code == 422:
            error_detail = response.json().get("detail", "请求参数错误")
            raise ProjectServiceError(f"请求参数错误: {error_detail}")
        if response.status_code not in [200, 201]:
            error_msg = response.json().get("detail", response.text) if response.text else f"状态码: {response.status_code}"
            raise ProjectServiceError(f"Project服务返回异常: {error_msg}")
        return response.json()

    def get_all_projects(self, token: str) -> List[Dict[str, Any]]:
        """
        获取所有项目列表

        Args:
            token: 认证token

        Returns:
            项目列表

        Raises:
            ProjectServiceError: 服务异常
        """
        try:
            with httpx.Client(timeout=self.config.timeout) as client:
                response = client.get(
                    self.config.project_list_url,
                    headers=self._get_headers(token)
                )
                data = self._handle_response(response)
                return data.get("data", [])

        except httpx.TimeoutException:
            raise ProjectServiceError("Project服务请求超时")
        except httpx.ConnectError as e:
            raise ProjectServiceError(f"无法连接到Project服务: {e}")

    def update_project(
        self,
        token: str,
        project_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        k8s_namespace: Optional[str] = None,
        is_public: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        修改项目信息

        Args:
            token: 认证token
            project_id: 项目ID
            name: 项目名称
            description: 项目描述
            k8s_namespace: K8S Namespace
            is_public: 是否公开

        Returns:
            更新后的项目信息

        Raises:
            ProjectServiceError: 服务异常
        """
        try:
            update_data = {}
            if name is not None:
                update_data["name"] = name
            if description is not None:
                update_data["description"] = description
            if k8s_namespace is not None:
                update_data["k8s_namespace"] = k8s_namespace
            if is_public is not None:
                update_data["is_public"] = is_public

            if not update_data:
                raise ProjectServiceError("没有需要更新的字段")

            with httpx.Client(timeout=self.config.timeout) as client:
                response = client.put(
                    self.config.get_project_url(project_id),
                    headers=self._get_headers(token),
                    json=update_data
                )
                return self._handle_response(response)

        except httpx.TimeoutException:
            raise ProjectServiceError("Project服务请求超时")
        except httpx.ConnectError as e:
            raise ProjectServiceError(f"无法连接到Project服务: {e}")

    def bind_project_role(
        self,
        token: str,
        project_id: str,
        user_id: str,
        role: str
    ) -> Dict[str, Any]:
        """
        为项目绑定用户角色

        Args:
            token: 认证token
            project_id: 项目ID
            user_id: 用户ID
            role: 角色 (owner, admin, member)

        Returns:
            角色绑定信息

        Raises:
            ProjectServiceError: 服务异常
        """
        if role not in ["owner", "admin", "member"]:
            raise ProjectServiceError("角色必须是 owner, admin 或 member")

        try:
            with httpx.Client(timeout=self.config.timeout) as client:
                response = client.post(
                    self.config.get_role_url(project_id),
                    headers=self._get_headers(token),
                    json={"user_id": user_id, "role": role}
                )
                return self._handle_response(response)

        except httpx.TimeoutException:
            raise ProjectServiceError("Project服务请求超时")
        except httpx.ConnectError as e:
            raise ProjectServiceError(f"无法连接到Project服务: {e}")

    def unbind_project_role(
        self,
        token: str,
        project_id: str,
        user_id: str
    ) -> Dict[str, Any]:
        """
        解除项目用户角色绑定

        Args:
            token: 认证token
            project_id: 项目ID
            user_id: 用户ID

        Returns:
            操作结果

        Raises:
            ProjectServiceError: 服务异常
        """
        try:
            with httpx.Client(timeout=self.config.timeout) as client:
                response = client.delete(
                    self.config.get_role_url(project_id),
                    headers=self._get_headers(token),
                    params={"user_id": user_id}
                )
                return self._handle_response(response)

        except httpx.TimeoutException:
            raise ProjectServiceError("Project服务请求超时")
        except httpx.ConnectError as e:
            raise ProjectServiceError(f"无法连接到Project服务: {e}")

    def get_project(
        self,
        token: str,
        project_id: str
    ) -> Dict[str, Any]:
        """
        获取单个项目详情

        Args:
            token: 认证token
            project_id: 项目ID

        Returns:
            项目详情

        Raises:
            ProjectServiceError: 服务异常
        """
        try:
            with httpx.Client(timeout=self.config.timeout) as client:
                response = client.get(
                    self.config.get_project_url(project_id),
                    headers=self._get_headers(token)
                )
                return self._handle_response(response)

        except httpx.TimeoutException:
            raise ProjectServiceError("Project服务请求超时")
        except httpx.ConnectError as e:
            raise ProjectServiceError(f"无法连接到Project服务: {e}")


# 单例实例
_project_service: Optional[ProjectService] = None


def get_project_service() -> ProjectService:
    """获取Project服务实例"""
    global _project_service
    if _project_service is None:
        _project_service = ProjectService()
    return _project_service