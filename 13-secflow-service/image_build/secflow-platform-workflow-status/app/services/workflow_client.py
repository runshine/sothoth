"""
Workflow Service API Client
通过HTTP调用secflow-platform-workflow微服务的API接口（用于回调通知）
"""

import logging
from datetime import datetime
from typing import Optional, Dict, Any

import httpx

from app.config import get_config

logger = logging.getLogger(__name__)


class WorkflowClient:
    """Workflow微服务API客户端"""

    def __init__(self):
        config = get_config()
        self.workflow_service_config = config.workflow_service
        self._async_client: Optional[httpx.AsyncClient] = None

        if self.workflow_service_config:
            logger.info(f"Workflow微服务客户端初始化: {self.workflow_service_config.base_url}")
        else:
            logger.warning("Workflow微服务客户端未配置")

    @property
    def async_client(self) -> httpx.AsyncClient:
        """获取异步HTTP客户端"""
        if self._async_client is None:
            config = get_config()
            timeout = config.workflow_service.timeout if config.workflow_service else 30
            self._async_client = httpx.AsyncClient(timeout=timeout)
        return self._async_client

    def _get_base_url(self) -> str:
        """获取Workflow微服务基础URL"""
        return self.workflow_service_config.base_url

    async def update_node_status(
        self,
        node_id: str,
        instance_id: str,
        status: str,
        message: Optional[str] = None,
        started_at: Optional[datetime] = None,
        finished_at: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        回调更新节点状态

        当 workflow-status 服务检测到节点状态变化时，调用此方法通知 workflow 服务更新本地数据库。

        Args:
            node_id: 节点ID
            instance_id: 工作流实例ID
            status: 新状态 (Pending/Not_ready/Ready/Running/Succeeded/Failed/Stopped)
            message: 状态消息
            started_at: 开始时间
            finished_at: 结束时间

        Returns:
            回调结果字典，包含:
            - success: 是否成功
            - node_id: 节点ID
            - status: 更新后的状态
            - message: 结果消息
        """
        url = f"{self._get_base_url()}/api/workflow/workflow-instances/callback/status"

        payload = {
            "node_id": node_id,
            "instance_id": instance_id,
            "status": status,
        }

        if message is not None:
            payload["message"] = message
        if started_at is not None:
            payload["started_at"] = started_at.isoformat()
        if finished_at is not None:
            payload["finished_at"] = finished_at.isoformat()

        try:
            response = await self.async_client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()

            logger.info(
                f"节点状态回调成功: node_id={node_id}, status={status}, "
                f"response={data.get('message', 'OK')}"
            )
            return data

        except httpx.HTTPStatusError as e:
            logger.error(
                f"节点状态回调失败 (HTTP {e.response.status_code}): "
                f"node_id={node_id}, status={status}, error={e.response.text}"
            )
            return {
                "success": False,
                "node_id": node_id,
                "status": status,
                "message": f"HTTP error {e.response.status_code}: {e.response.text}"
            }
        except httpx.HTTPError as e:
            logger.error(f"节点状态回调失败: node_id={node_id}, status={status}, error={e}")
            return {
                "success": False,
                "node_id": node_id,
                "status": status,
                "message": str(e)
            }
        except Exception as e:
            logger.error(f"节点状态回调异常: node_id={node_id}, status={status}, error={e}")
            return {
                "success": False,
                "node_id": node_id,
                "status": status,
                "message": str(e)
            }

    async def close(self):
        """关闭客户端连接"""
        if self._async_client:
            await self._async_client.aclose()
            self._async_client = None


# 单例实例
_workflow_client: Optional[WorkflowClient] = None


def get_workflow_client() -> WorkflowClient:
    """获取Workflow微服务客户端实例"""
    global _workflow_client
    if _workflow_client is None:
        _workflow_client = WorkflowClient()
    return _workflow_client
