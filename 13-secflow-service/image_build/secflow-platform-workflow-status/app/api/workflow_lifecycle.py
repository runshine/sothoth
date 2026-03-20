"""
工作流生命周期管理API路由
提供工作流实例级别的初始化、反初始化、停止等接口
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Header, Body

from app.config import get_config
from app.exception import NotFoundError, ValidationError, UnauthorizedError, InternalError
from app.services.workflow_lifecycle_service import get_workflow_lifecycle_service
from app.schemas.schemas import (
    WorkflowInitializeRequest,
    WorkflowDeinitializeRequest,
    WorkflowStopRequest,
    WorkflowLifecycleResponse,
    NodeStartRequest,
    NodeStartResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/workflow-status", tags=["工作流生命周期管理"])


# ============ 认证依赖 ============

async def get_current_user(
    authorization: Optional[str] = Header(None),
) -> dict:
    """验证并获取当前用户"""
    config = get_config()

    # 如果认证未启用，返回默认用户
    if not config.auth_service.enabled:
        return {
            "user": {
                "id": "system",
                "username": "system",
                "role": ["admin"]
            }
        }

    if not authorization:
        raise UnauthorizedError("缺少认证令牌")

    # 解析Bearer Token
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise UnauthorizedError("无效的认证格式")

    # TODO: 实际验证Token
    return {
        "user": {
            "id": "system",
            "username": "system",
            "role": ["admin"]
        }
    }


# ============ 工作流生命周期操作 ============

@router.post(
    "/instances/{instance_id}/initialize",
    response_model=WorkflowLifecycleResponse,
    summary="初始化工作流",
    description="为工作流实例创建所有节点的K8S资源"
)
async def initialize_workflow(
    instance_id: str,
    request: WorkflowInitializeRequest = Body(...),
    user: dict = Depends(get_current_user),
):
    """
    初始化工作流实例

    为工作流中的所有节点创建K8S资源：
    - APP节点：创建 Deployment + Service + Ingress(可选)
    - JOB节点：记录状态，延迟到执行时创建Job

    Args:
        instance_id: 工作流实例ID
        request: 初始化请求，包含项目ID和节点配置列表
    """
    try:
        if not request.nodes:
            raise ValidationError("节点列表不能为空")

        lifecycle_service = get_workflow_lifecycle_service()

        # 转换节点配置格式
        nodes = []
        for n in request.nodes:
            node_dict = {
                "node_id": n.node_id,
                "node_type": n.node_type,
                "node_name": n.node_name,
                "deployment_name": n.deployment_name,
                "service_name": n.service_name,
                "ingress_config": n.ingress_config.model_dump() if n.ingress_config else None,
                "containers": n.containers if n.containers else [],
                "volume_mounts": n.volume_mounts,
                "replicas": n.replicas,
                "service_ports": n.service_ports if n.service_ports else [],
                "service_type": n.service_type,
                "job_config": n.job_config.model_dump() if n.job_config else None,
            }
            nodes.append(node_dict)

        result = await lifecycle_service.initialize_workflow(
            instance_id=instance_id,
            project_id=request.project_id,
            nodes=nodes
        )

        return result

    except ValidationError:
        raise
    except Exception as e:
        logger.error(f"初始化工作流失败: {e}")
        raise InternalError(f"初始化工作流失败: {str(e)}")


@router.post(
    "/instances/{instance_id}/uninitialize",
    response_model=WorkflowLifecycleResponse,
    summary="反初始化工作流",
    description="删除工作流实例所有节点的K8S资源"
)
async def uninitialize_workflow(
    instance_id: str,
    request: WorkflowDeinitializeRequest = Body(...),
    user: dict = Depends(get_current_user),
):
    """
    反初始化工作流实例

    删除工作流中所有节点的K8S资源：
    - APP节点：删除 Ingress -> Service -> Deployment
    - JOB节点：删除 Job

    Args:
        instance_id: 工作流实例ID
        request: 反初始化请求，包含项目ID
    """
    try:
        lifecycle_service = get_workflow_lifecycle_service()

        result = await lifecycle_service.deinitialize_workflow(
            instance_id=instance_id,
            project_id=request.project_id,
            nodes=request.nodes
        )

        return result

    except Exception as e:
        logger.error(f"反初始化工作流失败: {e}")
        raise InternalError(f"反初始化工作流失败: {str(e)}")


@router.post(
    "/instances/{instance_id}/stop",
    response_model=WorkflowLifecycleResponse,
    summary="停止工作流",
    description="停止工作流实例并清理所有K8S资源"
)
async def stop_workflow(
    instance_id: str,
    request: WorkflowStopRequest = Body(...),
    user: dict = Depends(get_current_user),
):
    """
    停止工作流实例

    停止所有正在运行的节点并清理资源：
    - APP节点：删除 Ingress -> Service -> Deployment
    - JOB节点：删除 Job

    Args:
        instance_id: 工作流实例ID
        request: 停止请求，包含项目ID
    """
    try:
        lifecycle_service = get_workflow_lifecycle_service()

        result = await lifecycle_service.stop_workflow(
            instance_id=instance_id,
            project_id=request.project_id,
            nodes=request.nodes
        )

        return result

    except Exception as e:
        logger.error(f"停止工作流失败: {e}")
        raise InternalError(f"停止工作流失败: {str(e)}")


# ============ 节点启动操作 ============

@router.post(
    "/nodes/{node_id}/start",
    response_model=NodeStartResponse,
    summary="启动节点",
    description="启动单个节点（JOB节点创建Job，APP节点检查状态）"
)
async def start_node(
    node_id: str,
    request: NodeStartRequest = Body(...),
    user: dict = Depends(get_current_user),
):
    """
    启动单个节点

    APP节点：检查 Deployment 状态
    JOB节点：创建 Job 资源

    Args:
        node_id: 节点ID
        request: 启动请求，包含项目ID、实例ID、节点类型等
    """
    try:
        from app.services.node_lifecycle_service import get_node_lifecycle_service

        lifecycle_service = get_node_lifecycle_service()

        result = await lifecycle_service.start_node(
            node_id=node_id,
            instance_id=request.instance_id,
            project_id=request.project_id,
            node_type=request.node_type,
            k8s_resource_name=request.k8s_resource_name,
            job_config=request.job_config
        )

        return NodeStartResponse(
            success=result.success,
            node_id=result.node_id,
            status=result.status,
            message=result.message,
            k8s_resource_name=result.k8s_resource_name,
            error=result.error
        )

    except Exception as e:
        logger.error(f"启动节点失败: {e}")
        raise InternalError(f"启动节点失败: {str(e)}")
