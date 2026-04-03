"""
Code Server Manager - API路由
"""

import logging
from typing import List, Optional, Set

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy.orm import Session, joinedload

from app.config import get_config
from app.exception import NotFoundError, ValidationError, ConflictError
from app.model import (
    get_db, get_db_session, generate_id, CodeServer, Task,
    CodeServerStatus, TaskStatus, TaskType
)
from app.schemas import (
    CodeServerCreateRequest, CodeServerDeleteRequest, CodeServerRestartRequest,
    CodeServerResponse, CodeServerListResponse, CodeServerStatusResponse,
    CodeServerLogsResponse, CodeServerDeployDefaultsResponse, TaskResponse, TaskListResponse,
    TaskCreatedResponse, SuccessResponse, PVCMount, OutputPVCMount
)
from app.services.k8s import get_k8s_service
from app.services.task_manager import get_task_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/app/code-server", tags=["Code Server Manager"])

# ============ Helper Functions ============


def normalize_llm_provider_keys(llm_provider_key: Optional[str], llm_provider_keys: Optional[List[str]]) -> List[str]:
    raw_items: List[str] = []
    if isinstance(llm_provider_keys, list):
        raw_items.extend([str(item or "").strip() for item in llm_provider_keys])
    single = str(llm_provider_key or "").strip()
    if single:
        raw_items.append(single)
    normalized: List[str] = []
    for item in raw_items:
        if not item:
            continue
        if item not in normalized:
            normalized.append(item)
    return normalized


def get_server_llm_provider_keys(server: CodeServer) -> List[str]:
    provider_keys = server.llm_provider_keys if isinstance(server.llm_provider_keys, list) else []
    if not provider_keys and server.llm_provider_key:
        provider_keys = [server.llm_provider_key]
    return provider_keys


def matches_llm_filters(server: CodeServer, llm_binding: str, requested_provider_keys: Set[str]) -> bool:
    server_provider_keys = get_server_llm_provider_keys(server)
    has_binding = len(server_provider_keys) > 0
    if llm_binding == "bound" and not has_binding:
        return False
    if llm_binding == "unbound" and has_binding:
        return False
    if requested_provider_keys and not any(key in requested_provider_keys for key in server_provider_keys):
        return False
    return True

def get_code_server_by_name(db: Session, project_id: str, name: str) -> Optional[CodeServer]:
    """通过名称获取Code Server"""
    return db.query(CodeServer).filter(
        CodeServer.project_id == project_id,
        CodeServer.name == name,
        CodeServer.status != CodeServerStatus.DELETED.value
    ).first()


def get_code_server_realtime_status(server: CodeServer, k8s_service) -> tuple[str, dict]:
    """
    获取Code Server实时状态

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
        if server.status in [CodeServerStatus.PENDING.value, CodeServerStatus.CREATING.value]:
            actual_status = CodeServerStatus.PENDING.value
        else:
            actual_status = CodeServerStatus.STOPPED.value
    elif pod_status:
        if ready_replicas > 0 and pod_status == "Running":
            # Pod运行中且Ready
            actual_status = CodeServerStatus.RUNNING.value
        elif pod_status in ["Pending", "ContainerCreating"]:
            # Pod正在创建中
            actual_status = CodeServerStatus.CREATING.value
        elif pod_status in ["Error", "Failed", "CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull"]:
            # Pod出错
            actual_status = CodeServerStatus.ERROR.value
        elif pod_status in ["Succeeded"]:
            # Pod已完成（可能是在Job中）
            actual_status = CodeServerStatus.STOPPED.value
        elif pod_status == "Running":
            # Pod Running 但 Deployment 未 Ready（正在启动中）
            # 检查是否所有容器都 ready
            if server.deployment_name:
                pod_info_detail = k8s_service.get_pod_by_deployment(server.namespace, server.deployment_name)
                if pod_info_detail:
                    actual_status = CodeServerStatus.CREATING.value
                else:
                    actual_status = CodeServerStatus.ERROR.value
            else:
                actual_status = CodeServerStatus.CREATING.value
        else:
            # 未知状态
            actual_status = CodeServerStatus.ERROR.value

    extra_info = {
        "pod_status": pod_status,
        "pod_ip": pod_ip,
        "node_name": node_name,
        "ready_replicas": ready_replicas,
        "total_replicas": total_replicas,
    }

    return actual_status, extra_info


def make_code_server_response(server: CodeServer, realtime_status: str = None) -> CodeServerResponse:
    """构建Code Server响应"""
    provider_keys = get_server_llm_provider_keys(server)
    provider_snapshots = server.llm_provider_snapshots if isinstance(server.llm_provider_snapshots, list) else []
    if not provider_snapshots and server.llm_provider_snapshot:
        provider_snapshots = [server.llm_provider_snapshot]
    return CodeServerResponse(
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
        fileserver_mount=server.fileserver_mount or {},
        code_server_env=server.code_server_env or {},
        llm_provider_key=server.llm_provider_key,
        llm_provider_keys=provider_keys,
        llm_provider_snapshot=server.llm_provider_snapshot or {},
        llm_provider_snapshots=provider_snapshots,
        llm_provider_mapped_env_keys=server.llm_provider_mapped_env_keys or [],
        llm_file_bindings=server.llm_file_bindings or [],
        llm_configmap_name=server.llm_configmap_name,
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
        code_server_id=task.code_server_id,
        code_server_name=task.code_server_name,
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
        "service": "code-server-manager"
    }


@router.get("/deploy-defaults", response_model=CodeServerDeployDefaultsResponse)
async def get_deploy_defaults():
    """获取部署审计环境默认配置（镜像 + 预制环境变量）"""
    cfg = get_config().code_server
    preset_env_raw = cfg.env if isinstance(cfg.env, dict) else {}
    preset_env = {str(k): str(v) for k, v in preset_env_raw.items()}
    fs_cfg = get_config().fileserver_mount
    return CodeServerDeployDefaultsResponse(
        default_image=str(cfg.image or ""),
        preset_env=preset_env,
        fileserver_mount_enabled=bool(fs_cfg.enabled),
        fileserver_mount_path=str(fs_cfg.mount_path or "/data/fileserver"),
        fileserver_project_root_prefix=str(fs_cfg.project_root_prefix or "files").strip("/") or "files",
    )


# ============ Code Server CRUD ============

@router.post("/projects/{project_id}/code-servers", response_model=TaskCreatedResponse, status_code=status.HTTP_201_CREATED)
async def create_code_server(
    project_id: str = Path(..., description="项目ID"),
    request: CodeServerCreateRequest = ...,
    db: Session = Depends(get_db)
):
    """
    创建Code Server实例

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
    existing = get_code_server_by_name(db, project_id, request.name)
    if existing:
        raise ConflictError(f"Code Server名称已存在: {request.name}")

    # 创建Code Server记录
    normalized_llm_provider_keys = normalize_llm_provider_keys(request.llm_provider_key, request.llm_provider_keys)
    code_server_id = generate_id()
    code_server = CodeServer(
        id=code_server_id,
        project_id=project_id,
        name=request.name,
        namespace=request.namespace,
        status=CodeServerStatus.PENDING.value,
        description=request.description,
        source_pvcs=[{"pvc_name": p.pvc_name, "mount_path": p.mount_path} for p in request.source_pvcs],
        output_pvcs=[{
            "pvc_name": p.pvc_name,
            "mount_path": p.mount_path,
            "storage_size": p.storage_size
        } for p in request.output_pvcs],
        fileserver_mount={},
        custom_env=request.custom_env or {},
        code_server_env=request.code_server_env or {},
        llm_provider_key=(normalized_llm_provider_keys[-1] if normalized_llm_provider_keys else None),
        llm_provider_keys=normalized_llm_provider_keys
    )
    db.add(code_server)
    db.commit()

    # 创建异步任务
    task_manager = get_task_manager()
    params = {
        "code_server_id": code_server_id,
        "namespace": request.namespace,
        "name": request.name,
        "custom_env": request.custom_env,
        "preset_env": request.preset_env,
        "code_server_env": request.code_server_env,
        "image": request.image,  # 传递自定义镜像参数
        "fileserver_mount_enabled": request.fileserver_mount_enabled,
        "fileserver_mount_path": request.fileserver_mount_path,
        "fileserver_project_subpath": request.fileserver_project_subpath,
        "llm_provider_key": (normalized_llm_provider_keys[-1] if normalized_llm_provider_keys else None),
        "llm_provider_keys": normalized_llm_provider_keys,
        "llm_file_overrides": [{"path": item.path, "content": item.content} for item in (request.llm_file_overrides or [])]
    }
    task = task_manager.create_task(
        project_id=project_id,
        task_type=TaskType.CREATE.value,
        params=params,
        code_server_id=code_server_id,
        code_server_name=request.name
    )

    return TaskCreatedResponse(
        message="Code Server创建任务已提交",
        task_id=task.id,
        task_type=TaskType.CREATE.value
    )


@router.delete("/projects/{project_id}/code-servers", response_model=TaskCreatedResponse)
async def delete_code_server(
    project_id: str = Path(..., description="项目ID"),
    request: CodeServerDeleteRequest = ...,
    db: Session = Depends(get_db)
):
    """
    删除Code Server实例

    - 需要验证Code Server存在
    - 可选删除输出PVC（默认不删除）
    - 不会删除源码PVC
    """
    # 检查Code Server是否存在
    code_server = get_code_server_by_name(db, project_id, request.name)
    if not code_server:
        raise NotFoundError("Code Server", request.name)

    # 创建异步任务
    task_manager = get_task_manager()
    params = {
        "code_server_id": code_server.id,
        "code_server_name": code_server.name,
        "delete_output_pvcs": request.delete_output_pvcs
    }
    task = task_manager.create_task(
        project_id=project_id,
        task_type=TaskType.DELETE.value,
        params=params,
        code_server_id=code_server.id,
        code_server_name=request.name
    )

    # 更新状态为删除中
    code_server.status = CodeServerStatus.DELETING.value
    db.commit()

    return TaskCreatedResponse(
        message="Code Server删除任务已提交",
        task_id=task.id,
        task_type=TaskType.DELETE.value
    )


@router.post("/projects/{project_id}/code-servers/restart", response_model=TaskCreatedResponse)
async def restart_code_server(
    project_id: str = Path(..., description="项目ID"),
    request: CodeServerRestartRequest = ...,
    db: Session = Depends(get_db)
):
    """
    重建Code Server实例

    - 将Deployment副本数调整为0再调整为1
    - 用于重启Pod
    """
    # 检查Code Server是否存在
    code_server = get_code_server_by_name(db, project_id, request.name)
    if not code_server:
        raise NotFoundError("Code Server", request.name)

    if not code_server.deployment_name:
        raise ValidationError("Code Server没有关联的Deployment")

    # 创建异步任务
    task_manager = get_task_manager()
    params = {
        "code_server_id": code_server.id,
        "code_server_name": code_server.name
    }
    task = task_manager.create_task(
        project_id=project_id,
        task_type=TaskType.RESTART.value,
        params=params,
        code_server_id=code_server.id,
        code_server_name=request.name
    )

    return TaskCreatedResponse(
        message="Code Server重建任务已提交",
        task_id=task.id,
        task_type=TaskType.RESTART.value
    )


# ============ Code Server Query ============

@router.get("/projects/{project_id}/code-servers", response_model=CodeServerListResponse)
async def list_code_servers(
    project_id: str = Path(..., description="项目ID"),
    status: Optional[str] = Query(None, description="按状态过滤"),
    llm_binding: str = Query("all", description="LLM 绑定状态过滤: all|bound|unbound"),
    llm_provider_keys: Optional[str] = Query(None, description="按 Provider Key 过滤，逗号分隔，命中任一"),
    realtime: bool = Query(True, description="是否实时获取Kubernetes状态"),
    db: Session = Depends(get_db)
):
    """查询Code Server列表

    - 默认实时从Kubernetes获取Pod状态
    - 设置 realtime=false 可只查询数据库状态（更快）
    """
    llm_binding = str(llm_binding or "all").strip().lower()
    if llm_binding not in {"all", "bound", "unbound"}:
        raise ValidationError("llm_binding 仅支持 all|bound|unbound")

    query = db.query(CodeServer).filter(
        CodeServer.project_id == project_id,
        CodeServer.status != CodeServerStatus.DELETED.value
    )

    if status:
        query = query.filter(CodeServer.status == status)

    servers = query.all()
    requested_provider_keys = {
        item.strip() for item in str(llm_provider_keys or "").split(",") if item.strip()
    }

    k8s_service = get_k8s_service() if realtime else None

    items = []
    for server in servers:
        if not matches_llm_filters(server, llm_binding, requested_provider_keys):
            continue
        realtime_status = None
        if realtime and k8s_service and server.deployment_name:
            try:
                realtime_status, _ = get_code_server_realtime_status(server, k8s_service)
            except Exception as e:
                logger.warning(f"获取Code Server {server.name} 实时状态失败: {e}")
                realtime_status = server.status

        items.append(make_code_server_response(server, realtime_status))

    # 如果按状态过滤，需要在获取实时状态后再过滤
    if status and realtime:
        items = [item for item in items if item.status == status]

    return CodeServerListResponse(
        total=len(items),
        items=items
    )


@router.get("/projects/{project_id}/code-servers/{name}", response_model=CodeServerResponse)
async def get_code_server(
    project_id: str = Path(..., description="项目ID"),
    name: str = Path(..., description="Code Server名称"),
    db: Session = Depends(get_db)
):
    """查询单个Code Server"""
    server = get_code_server_by_name(db, project_id, name)
    if not server:
        raise NotFoundError("Code Server", name)

    return make_code_server_response(server)


@router.get("/projects/{project_id}/code-servers/{name}/status", response_model=CodeServerStatusResponse)
async def get_code_server_status(
    project_id: str = Path(..., description="项目ID"),
    name: str = Path(..., description="Code Server名称"),
    db: Session = Depends(get_db)
):
    """获取Code Server实时状态"""
    server = get_code_server_by_name(db, project_id, name)
    if not server:
        raise NotFoundError("Code Server", name)

    k8s_service = get_k8s_service()

    # 使用辅助函数获取实时状态
    actual_status, extra_info = get_code_server_realtime_status(server, k8s_service)

    return CodeServerStatusResponse(
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


@router.get("/projects/{project_id}/code-servers/{name}/logs", response_model=CodeServerLogsResponse)
async def get_code_server_logs(
    project_id: str = Path(..., description="项目ID"),
    name: str = Path(..., description="Code Server名称"),
    tail_lines: int = Query(100, description="返回行数", ge=1, le=10000),
    container: Optional[str] = Query(None, description="容器名称"),
    db: Session = Depends(get_db)
):
    """获取Code Server运行日志"""
    server = get_code_server_by_name(db, project_id, name)
    if not server:
        raise NotFoundError("Code Server", name)

    if not server.deployment_name:
        raise ValidationError("Code Server没有关联的Deployment")

    k8s_service = get_k8s_service()

    # 实时获取当前运行的Pod（处理Pod重建后的情况）
    pod_info = k8s_service.get_pod_by_deployment(server.namespace, server.deployment_name)
    if not pod_info:
        raise ValidationError("Code Server没有运行中的Pod")

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

    return CodeServerLogsResponse(
        code_server_id=server.id,
        code_server_name=server.name,
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
