"""
工作流监控管理API路由
提供监控会话的启动、停止、暂停、恢复等管理接口
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Header, Query, Body

from app.config import get_config
from app.exception import NotFoundError, ValidationError, UnauthorizedError, InternalError
from app.services.workflow_monitor_engine import get_workflow_monitor_engine
from app.services.status_sync_service import get_status_sync_service
from app.schemas.schemas import (
    MonitoringStartRequest,
    MonitoringStartResponse,
    MonitoringStatusResponse,
    MonitoringListResponse,
    MonitoringOperationResponse,
    ResetJobNodesRequest,
    ResetJobNodesResponse,
    ResetNodeStatusRequest,
    ResetNodeStatusResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/workflow-status", tags=["工作流监控管理"])


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


# ============ 监控会话管理 ============

@router.post(
    "/monitoring/start",
    response_model=MonitoringStartResponse,
    summary="启动工作流监控",
    description="为指定工作流实例启动监控会话，后台将定期轮询节点状态"
)
async def start_monitoring(
    request: MonitoringStartRequest = Body(...),
    user: dict = Depends(get_current_user),
):
    """启动工作流监控"""
    try:
        monitor_engine = get_workflow_monitor_engine()

        # 转换节点信息格式
        nodes = [
            {
                "node_id": n.node_id,
                "node_type": n.node_type,
                "k8s_resource_name": n.k8s_resource_name,
                "timeout_seconds": n.timeout_seconds
            }
            for n in request.nodes
        ]

        session_id = await monitor_engine.start_monitoring(
            instance_id=request.instance_id,
            project_id=request.project_id,
            nodes=nodes,
            poll_interval=request.poll_interval
        )

        return MonitoringStartResponse(
            success=True,
            session_id=session_id,
            instance_id=request.instance_id,
            message="监控会话已启动"
        )

    except Exception as e:
        logger.error(f"启动监控失败: {e}")
        raise InternalError(f"启动监控失败: {str(e)}")


@router.post(
    "/monitoring/stop",
    response_model=MonitoringOperationResponse,
    summary="停止工作流监控",
    description="停止指定工作流实例的监控会话"
)
async def stop_monitoring(
    instance_id: str = Body(..., embed=True),
    user: dict = Depends(get_current_user),
):
    """停止工作流监控"""
    try:
        monitor_engine = get_workflow_monitor_engine()
        success = await monitor_engine.stop_monitoring(instance_id)

        if not success:
            raise NotFoundError("监控会话", instance_id)

        return MonitoringOperationResponse(
            success=True,
            instance_id=instance_id,
            message="监控会话已停止"
        )

    except NotFoundError:
        raise
    except Exception as e:
        logger.error(f"停止监控失败: {e}")
        raise InternalError(f"停止监控失败: {str(e)}")


@router.post(
    "/monitoring/pause",
    response_model=MonitoringOperationResponse,
    summary="暂停工作流监控",
    description="暂停指定工作流实例的监控会话"
)
async def pause_monitoring(
    instance_id: str = Body(..., embed=True),
    user: dict = Depends(get_current_user),
):
    """暂停工作流监控"""
    try:
        monitor_engine = get_workflow_monitor_engine()
        success = await monitor_engine.pause_monitoring(instance_id)

        if not success:
            raise NotFoundError("监控会话", instance_id)

        return MonitoringOperationResponse(
            success=True,
            instance_id=instance_id,
            message="监控会话已暂停"
        )

    except NotFoundError:
        raise
    except Exception as e:
        logger.error(f"暂停监控失败: {e}")
        raise InternalError(f"暂停监控失败: {str(e)}")


@router.post(
    "/monitoring/resume",
    response_model=MonitoringOperationResponse,
    summary="恢复工作流监控",
    description="恢复指定工作流实例的监控会话"
)
async def resume_monitoring(
    instance_id: str = Body(..., embed=True),
    user: dict = Depends(get_current_user),
):
    """恢复工作流监控"""
    try:
        monitor_engine = get_workflow_monitor_engine()
        success = await monitor_engine.resume_monitoring(instance_id)

        if not success:
            raise NotFoundError("监控会话", instance_id)

        return MonitoringOperationResponse(
            success=True,
            instance_id=instance_id,
            message="监控会话已恢复"
        )

    except NotFoundError:
        raise
    except Exception as e:
        logger.error(f"恢复监控失败: {e}")
        raise InternalError(f"恢复监控失败: {str(e)}")


@router.get(
    "/monitoring/{instance_id}",
    response_model=MonitoringStatusResponse,
    summary="获取监控状态",
    description="获取指定工作流实例的监控会话状态"
)
async def get_monitoring_status(
    instance_id: str,
    user: dict = Depends(get_current_user),
):
    """获取监控状态"""
    monitor_engine = get_workflow_monitor_engine()
    status = monitor_engine.get_monitor_status(instance_id)

    if not status:
        raise NotFoundError("监控会话", instance_id)

    return MonitoringStatusResponse(**status)


@router.get(
    "/monitoring",
    response_model=MonitoringListResponse,
    summary="获取所有监控会话",
    description="获取当前所有活跃的监控会话列表"
)
async def list_monitoring_sessions(
    user: dict = Depends(get_current_user),
):
    """获取所有监控会话"""
    monitor_engine = get_workflow_monitor_engine()
    sessions = monitor_engine.get_all_sessions()

    return MonitoringListResponse(
        total=len(sessions),
        sessions=[MonitoringStatusResponse(**s) for s in sessions]
    )


# ============ 状态重置 ============

@router.post(
    "/nodes/reset-job",
    response_model=ResetJobNodesResponse,
    summary="重置JOB节点状态",
    description="重置工作流中所有JOB节点状态为Pending，用于重新触发工作流"
)
async def reset_job_nodes(
    request: ResetJobNodesRequest = Body(...),
    user: dict = Depends(get_current_user),
):
    """重置JOB节点状态"""
    try:
        sync_service = get_status_sync_service()
        result = await sync_service.reset_job_nodes_for_instance(
            instance_id=request.instance_id,
            project_id=request.project_id,
            reset_logs=request.reset_logs
        )

        return ResetJobNodesResponse(
            success=True,
            instance_id=result["instance_id"],
            project_id=result["project_id"],
            reset_count=result["reset_count"],
            reset_nodes=result["reset_nodes"]
        )

    except Exception as e:
        logger.error(f"重置JOB节点状态失败: {e}")
        raise InternalError(f"重置JOB节点状态失败: {str(e)}")


@router.post(
    "/nodes/reset",
    response_model=ResetNodeStatusResponse,
    summary="重置单个节点状态",
    description="重置指定节点状态为Pending"
)
async def reset_node_status(
    request: ResetNodeStatusRequest = Body(...),
    user: dict = Depends(get_current_user),
):
    """重置单个节点状态"""
    try:
        sync_service = get_status_sync_service()

        # 先获取当前状态
        stored_logs = await sync_service.get_stored_logs(request.node_id)
        # 通过日志记录获取节点信息（包含old_status）
        # 这里直接调用reset方法
        result = await sync_service.reset_node_status(
            node_id=request.node_id,
            reset_logs=request.reset_logs
        )

        return ResetNodeStatusResponse(
            success=True,
            node_id=request.node_id,
            old_status=None,  # 可以从结果中提取
            new_status="Pending"
        )

    except ValueError as e:
        raise NotFoundError("节点", request.node_id)
    except Exception as e:
        logger.error(f"重置节点状态失败: {e}")
        raise InternalError(f"重置节点状态失败: {str(e)}")
