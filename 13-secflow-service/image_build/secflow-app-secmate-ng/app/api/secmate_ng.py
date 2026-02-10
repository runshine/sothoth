"""
SecMate-NG Manager - API路由
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy.orm import Session, joinedload

from app.config import get_config
from app.exception import NotFoundError, ValidationError, ConflictError
from app.model import (
    get_db, get_db_session, generate_id, SecMateNG, Task,
    SecMateNGStatus, TaskStatus, TaskType
)
from app.schemas import (
    SecMateNGCreateRequest, SecMateNGDeleteRequest, SecMateNGRestartRequest,
    SecMateNGResponse, SecMateNGListResponse, SecMateNGStatusResponse,
    SecMateNGLogsResponse, TaskResponse, TaskListResponse,
    TaskCreatedResponse, SuccessResponse, PVCMount, OutputPVCMount
)
from app.services.k8s import get_k8s_service
from app.services.task_manager import get_task_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/app/secmate-ng", tags=["SecMate-NG Manager"])

# ============ Helper Functions ============

def get_secmate_ng_by_name(db: Session, project_id: str, name: str) -> Optional[SecMateNG]:
    """通过名称获取SecMate-NG"""
    return db.query(SecMateNG).filter(
        SecMateNG.project_id == project_id,
        SecMateNG.name == name,
        SecMateNG.status != SecMateNGStatus.DELETED.value
    ).first()


def get_secmate_ng_realtime_status(server: SecMateNG, k8s_service) -> tuple[str, dict]:
    """
    获取SecMate-NG实时状态

    Returns:
        tuple: (status, extra_info)
    """
    # 获取Deployment状态
    deployment_exists = False
    ready_replicas = 0
    total_replicas = 0
    if server.deployment_name:
        status = k8s_service.get_deployment_status(server.namespace, server.deployment_name)
        if status:
            deployment_exists = True
            ready_replicas = status.get("ready_replicas", 0)
            total_replicas = status.get("replicas", 0)

    # 获取Pod状态
    pod_status = None
    pod_ip = None
    node_name = None
    pod_exists = False
    if server.deployment_name:
        pod_info = k8s_service.get_pod_by_deployment(server.namespace, server.deployment_name)
        if pod_info:
            pod_exists = True
            pod_status = pod_info.get("status")
            pod_ip = pod_info.get("ip")
            node_name = pod_info.get("node_name")

    # 基于Pod和Deployment状态计算实际状态
    actual_status = server.status

    if not deployment_exists and not pod_exists:
        # Deployment和Pod都不存在
        if server.status in [SecMateNGStatus.PENDING.value, SecMateNGStatus.CREATING.value]:
            actual_status = SecMateNGStatus.PENDING.value
        else:
            actual_status = SecMateNGStatus.STOPPED.value
    elif pod_status:
        if ready_replicas > 0 and pod_status == "Running":
            # Pod运行中且Ready
            actual_status = SecMateNGStatus.RUNNING.value
        elif pod_status in ["Pending", "ContainerCreating"]:
            # Pod正在创建中
            actual_status = SecMateNGStatus.CREATING.value
        elif pod_status in ["Error", "Failed", "CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull"]:
            # Pod出错
            actual_status = SecMateNGStatus.ERROR.value
        elif pod_status in ["Succeeded"]:
            # Pod已完成（可能是在Job中）
            actual_status = SecMateNGStatus.STOPPED.value
        elif pod_status == "Running":
            # Pod Running 但 Deployment 未 Ready（正在启动中）
            # 检查是否所有容器都 ready
            if server.deployment_name:
                pod_info_detail = k8s_service.get_pod_by_deployment(server.namespace, server.deployment_name)
                if pod_info_detail:
                    actual_status = SecMateNGStatus.CREATING.value
                else:
                    actual_status = SecMateNGStatus.ERROR.value
            else:
                actual_status = SecMateNGStatus.CREATING.value
        else:
            # 未知状态
            actual_status = SecMateNGStatus.ERROR.value

    extra_info = {
        "pod_status": pod_status,
        "pod_ip": pod_ip,
        "node_name": node_name,
        "ready_replicas": ready_replicas,
        "total_replicas": total_replicas,
    }

    return actual_status, extra_info


def make_secmate_ng_response(server: SecMateNG, realtime_status: str = None) -> SecMateNGResponse:
    """构建SecMate-NG响应"""
    return SecMateNGResponse(
        id=server.id,
        project_id=server.project_id,
        name=server.name,
        namespace=server.namespace,
        status=realtime_status if realtime_status is not None else server.status,
        source_pvcs=server.source_pvcs or [],
        output_pvcs=server.output_pvcs or [],
        deployment_name=server.deployment_name,
        service_name=server.service_name,
        ingress_name=server.ingress_name,
        pod_name=server.pod_name,
        access_url=server.access_url,
        secmate_ng_env=server.secmate_ng_env or {},
        description=server.description,
        created_at=server.created_at.isoformat() if server.created_at else None,
        updated_at=server.updated_at.isoformat() if server.updated_at else None
    )


def make_task_response(task: Task) -> TaskResponse:
    """构建任务响应"""
    return TaskResponse(
        id=task.id,
        project_id=task.project_id,
        type=task.type,
        status=task.status,
        secmate_ng_id=task.secmate_ng_id,
        secmate_ng_name=task.secmate_ng_name,
        params=task.params or {},
        result=task.result,
        error_message=task.error_message,
        created_at=task.created_at.isoformat() if task.created_at else None,
        started_at=task.started_at.isoformat() if task.started_at else None,
        completed_at=task.completed_at.isoformat() if task.completed_at else None
    )


# ============ Health Check ============

@router.get("/health")
async def health_check():
    """
    健康检查接口

    - 检查服务是否正常运行
    - 返回服务状态信息
    """
    return {
        "status": "ok",
        "service": "secmate-ng-manager"
    }


# ============ SecMate-NG CRUD ============

@router.post("/projects/{project_id}/secmate-ngs", response_model=TaskCreatedResponse, status_code=status.HTTP_201_CREATED)
async def create_secmate_ng(
    project_id: str = Path(..., description="项目ID"),
    request: SecMateNGCreateRequest = ...,
    db: Session = Depends(get_db)
):
    """
    创建SecMate-NG实例

    - 异步创建任务
    - 自动创建不存在的输出PVC
    - 自动创建Deployment、Service、Ingress
    """
    k8s_service = get_k8s_service()

    # 检查namespace是否存在
    if not k8s_service.check_namespace_exists(request.namespace):
        raise ValidationError(f"Namespace不存在: {request.namespace}")

    # 检查源码PVC是否存在
    for pvc_info in request.source_pvcs:
        if not k8s_service.check_pvc_exists(request.namespace, pvc_info.pvc_name):
            raise ValidationError(f"源码PVC不存在: {pvc_info.pvc_name}")

    # 检查名称是否已存在
    existing = get_secmate_ng_by_name(db, project_id, request.name)
    if existing:
        raise ConflictError(f"SecMate-NG名称已存在: {request.name}")

    # 创建SecMate-NG记录
    secmate_ng_id = generate_id()
    secmate_ng = SecMateNG(
        id=secmate_ng_id,
        project_id=project_id,
        name=request.name,
        namespace=request.namespace,
        status=SecMateNGStatus.PENDING.value,
        description=request.description,
        source_pvcs=[{"pvc_name": p.pvc_name, "mount_path": p.mount_path} for p in request.source_pvcs],
        output_pvcs=[{
            "pvc_name": p.pvc_name,
            "mount_path": p.mount_path,
            "storage_size": p.storage_size
        } for p in request.output_pvcs],
        custom_env=request.custom_env or {},
        secmate_ng_env=request.secmate_ng_env or {}
    )
    db.add(secmate_ng)
    db.commit()

    # 创建异步任务
    task_manager = get_task_manager()
    params = {
        "secmate_ng_id": secmate_ng_id,
        "namespace": request.namespace,
        "name": request.name,
        "custom_env": request.custom_env,
        "secmate_ng_env": request.secmate_ng_env,
        "image": request.image  # 传递自定义镜像参数
    }
    task = task_manager.create_task(
        project_id=project_id,
        task_type=TaskType.CREATE.value,
        params=params,
        secmate_ng_id=secmate_ng_id,
        secmate_ng_name=request.name
    )

    return TaskCreatedResponse(
        message="SecMate-NG创建任务已提交",
        task_id=task.id,
        task_type=TaskType.CREATE.value
    )


@router.delete("/projects/{project_id}/secmate-ngs", response_model=TaskCreatedResponse)
async def delete_secmate_ng(
    project_id: str = Path(..., description="项目ID"),
    request: SecMateNGDeleteRequest = ...,
    db: Session = Depends(get_db)
):
    """
    删除SecMate-NG实例

    - 需要验证SecMate-NG存在
    - 可选删除输出PVC（默认不删除）
    - 不会删除源码PVC
    """
    # 检查SecMate-NG是否存在
    secmate_ng = get_secmate_ng_by_name(db, project_id, request.name)
    if not secmate_ng:
        raise NotFoundError("SecMate-NG", request.name)

    # 创建异步任务
    task_manager = get_task_manager()
    params = {
        "secmate_ng_id": secmate_ng.id,
        "secmate_ng_name": secmate_ng.name,
        "delete_output_pvcs": request.delete_output_pvcs
    }
    task = task_manager.create_task(
        project_id=project_id,
        task_type=TaskType.DELETE.value,
        params=params,
        secmate_ng_id=secmate_ng.id,
        secmate_ng_name=request.name
    )

    # 更新状态为删除中
    secmate_ng.status = SecMateNGStatus.DELETING.value
    db.commit()

    return TaskCreatedResponse(
        message="SecMate-NG删除任务已提交",
        task_id=task.id,
        task_type=TaskType.DELETE.value
    )


@router.post("/projects/{project_id}/secmate-ngs/restart", response_model=TaskCreatedResponse)
async def restart_secmate_ng(
    project_id: str = Path(..., description="项目ID"),
    request: SecMateNGRestartRequest = ...,
    db: Session = Depends(get_db)
):
    """
    重建SecMate-NG实例

    - 将Deployment副本数调整为0再调整为1
    - 用于重启Pod
    """
    # 检查SecMate-NG是否存在
    secmate_ng = get_secmate_ng_by_name(db, project_id, request.name)
    if not secmate_ng:
        raise NotFoundError("SecMate-NG", request.name)

    if not secmate_ng.deployment_name:
        raise ValidationError("SecMate-NG没有关联的Deployment")

    # 创建异步任务
    task_manager = get_task_manager()
    params = {
        "secmate_ng_id": secmate_ng.id,
        "secmate_ng_name": secmate_ng.name
    }
    task = task_manager.create_task(
        project_id=project_id,
        task_type=TaskType.RESTART.value,
        params=params,
        secmate_ng_id=secmate_ng.id,
        secmate_ng_name=request.name
    )

    return TaskCreatedResponse(
        message="SecMate-NG重建任务已提交",
        task_id=task.id,
        task_type=TaskType.RESTART.value
    )


# ============ SecMate-NG Query ============

@router.get("/projects/{project_id}/secmate-ngs", response_model=SecMateNGListResponse)
async def list_secmate_ngs(
    project_id: str = Path(..., description="项目ID"),
    status: Optional[str] = Query(None, description="按状态过滤"),
    realtime: bool = Query(True, description="是否实时获取Kubernetes状态"),
    db: Session = Depends(get_db)
):
    """查询SecMate-NG列表

    - 默认实时从Kubernetes获取Pod状态
    - 设置 realtime=false 可只查询数据库状态（更快）
    """
    query = db.query(SecMateNG).filter(
        SecMateNG.project_id == project_id,
        SecMateNG.status != SecMateNGStatus.DELETED.value
    )

    if status:
        query = query.filter(SecMateNG.status == status)

    servers = query.all()

    k8s_service = get_k8s_service() if realtime else None

    items = []
    for server in servers:
        realtime_status = None
        if realtime and k8s_service and server.deployment_name:
            try:
                realtime_status, _ = get_secmate_ng_realtime_status(server, k8s_service)
            except Exception as e:
                logger.warning(f"获取SecMate-NG {server.name} 实时状态失败: {e}")
                realtime_status = server.status

        items.append(make_secmate_ng_response(server, realtime_status))

    # 如果按状态过滤，需要在获取实时状态后再过滤
    if status and realtime:
        items = [item for item in items if item.status == status]

    return SecMateNGListResponse(
        total=len(items),
        items=items
    )


@router.get("/projects/{project_id}/secmate-ngs/{name}", response_model=SecMateNGResponse)
async def get_secmate_ng(
    project_id: str = Path(..., description="项目ID"),
    name: str = Path(..., description="SecMate-NG名称"),
    db: Session = Depends(get_db)
):
    """查询单个SecMate-NG"""
    server = get_secmate_ng_by_name(db, project_id, name)
    if not server:
        raise NotFoundError("SecMate-NG", name)

    return make_secmate_ng_response(server)


@router.get("/projects/{project_id}/secmate-ngs/{name}/status", response_model=SecMateNGStatusResponse)
async def get_secmate_ng_status(
    project_id: str = Path(..., description="项目ID"),
    name: str = Path(..., description="SecMate-NG名称"),
    db: Session = Depends(get_db)
):
    """获取SecMate-NG实时状态"""
    server = get_secmate_ng_by_name(db, project_id, name)
    if not server:
        raise NotFoundError("SecMate-NG", name)

    k8s_service = get_k8s_service()

    # 使用辅助函数获取实时状态
    actual_status, extra_info = get_secmate_ng_realtime_status(server, k8s_service)

    return SecMateNGStatusResponse(
        id=server.id,
        name=server.name,
        namespace=server.namespace,
        status=actual_status,
        pod_status=extra_info.get("pod_status"),
        pod_ip=extra_info.get("pod_ip"),
        node_name=extra_info.get("node_name"),
        access_url=server.access_url,
        ready_replicas=extra_info.get("ready_replicas", 0),
        total_replicas=extra_info.get("total_replicas", 0)
    )


@router.get("/projects/{project_id}/secmate-ngs/{name}/logs", response_model=SecMateNGLogsResponse)
async def get_secmate_ng_logs(
    project_id: str = Path(..., description="项目ID"),
    name: str = Path(..., description="SecMate-NG名称"),
    tail_lines: int = Query(100, description="返回行数", ge=1, le=10000),
    container: Optional[str] = Query(None, description="容器名称"),
    db: Session = Depends(get_db)
):
    """获取SecMate-NG运行日志"""
    server = get_secmate_ng_by_name(db, project_id, name)
    if not server:
        raise NotFoundError("SecMate-NG", name)

    if not server.deployment_name:
        raise ValidationError("SecMate-NG没有关联的Deployment")

    k8s_service = get_k8s_service()

    # 实时获取当前运行的Pod（处理Pod重建后的情况）
    pod_info = k8s_service.get_pod_by_deployment(server.namespace, server.deployment_name)
    if not pod_info:
        raise ValidationError("SecMate-NG没有运行中的Pod")

    current_pod_name = pod_info.get("name")
    if not current_pod_name:
        raise ValidationError("无法获取Pod名称")

    logs = k8s_service.get_pod_logs(
        server.namespace, current_pod_name, container=container, tail_lines=tail_lines
    )

    if logs is None:
        raise NotFoundError("Pod日志", current_pod_name)

    # 如果Pod名称有变化，更新数据库
    if server.pod_name != current_pod_name:
        server.pod_name = current_pod_name
        db.commit()

    return SecMateNGLogsResponse(
        secmate_ng_id=server.id,
        secmate_ng_name=server.name,
        namespace=server.namespace,
        pod_name=current_pod_name,
        container=container,
        logs=logs
    )


# ============ Task Management ============

@router.get("/projects/{project_id}/tasks", response_model=TaskListResponse)
async def list_tasks(
    project_id: str = Path(..., description="项目ID"),
    status: Optional[str] = Query(None, description="按状态过滤"),
    task_type: Optional[str] = Query(None, alias="type", description="按类型过滤"),
    db: Session = Depends(get_db)
):
    """查询任务列表"""
    query = db.query(Task).filter(Task.project_id == project_id)

    if status:
        query = query.filter(Task.status == status)
    if task_type:
        query = query.filter(Task.type == task_type)

    tasks = query.order_by(Task.created_at.desc()).all()

    return TaskListResponse(
        total=len(tasks),
        items=[make_task_response(t) for t in tasks]
    )


@router.get("/projects/{project_id}/tasks/{task_id}", response_model=TaskResponse)
async def get_task(
    project_id: str = Path(..., description="项目ID"),
    task_id: str = Path(..., description="任务ID"),
    db: Session = Depends(get_db)
):
    """查询任务详情"""
    task = db.query(Task).filter(
        Task.id == task_id,
        Task.project_id == project_id
    ).first()

    if not task:
        raise NotFoundError("任务", task_id)

    return make_task_response(task)


@router.delete("/projects/{project_id}/tasks/{task_id}", response_model=SuccessResponse)
async def delete_task(
    project_id: str = Path(..., description="项目ID"),
    task_id: str = Path(..., description="任务ID"),
    db: Session = Depends(get_db)
):
    """删除任务"""
    task = db.query(Task).filter(
        Task.id == task_id,
        Task.project_id == project_id
    ).first()

    if not task:
        raise NotFoundError("任务", task_id)

    # 使用任务管理器删除
    task_manager = get_task_manager()
    if not task_manager.delete_task(task_id):
        raise NotFoundError("任务", task_id)

    return SuccessResponse(message=f"任务 {task_id} 已删除", data={"task_id": task_id})
