"""
Secmate-NG Manager - API路由
"""

import logging
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status, WebSocket, WebSocketDisconnect, Header
from sqlalchemy.orm import Session

from app.config import get_config
from app.exception import NotFoundError, ValidationError, ConflictError, ForbiddenError, UnauthorizedError
from app.model import (
    get_db, get_db_session, generate_id, SecmateNg, Task,
    SecmateNgStatus, TaskStatus, TaskType
)
from app.schemas import (
    SecmateNgCreateRequest, SecmateNgDeleteRequest, SecmateNgRestartRequest,
    SecmateNgResponse, SecmateNgListResponse, SecmateNgStatusResponse,
    SecmateNgEnvConfigResponse,
    SecmateNgLogsResponse, TaskResponse, TaskListResponse,
    TaskCreatedResponse, SuccessResponse, PVCMount, OutputPVCMount
)
from app.services.k8s_api_client import get_k8s_api_client
from app.services.task_manager import get_task_manager
from app.services.auth import get_auth_service, TokenInvalidError, AuthServiceError
from app.utils.health import check_k8s_api_health, check_database_health, check_auth_service_health

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/app/secmate-ng", tags=["Secmate-NG Manager"])


# ============ 辅助函数 ============

import re


def validate_k8s_name(name: str) -> bool:
    """
    验证名称是否符合 K8s DNS 子域名命名规则 (RFC 1123)

    K8s资源名称必须符合以下规则：
    - 最多 253 个字符
    - 只能包含小写字母、数字和 '-'
    - 必须以字母或数字开头和结尾
    - 不能包含连续的 '-'

    Args:
        name: 待验证的名称

    Returns:
        bool: 是否符合命名规范
    """
    if not name or len(name) > 253:
        return False
    # 正则表达式：以字母或数字开头，中间可以有字母数字和连字符，以字母或数字结尾
    pattern = r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'
    return re.match(pattern, name) is not None


SENSITIVE_ENV_KEYWORDS = (
    "key", "token", "secret", "password", "passwd", "pwd",
    "private", "credential", "auth", "access_key", "api_key"
)


def is_sensitive_env_key(key: str) -> bool:
    """判断环境变量名是否敏感"""
    key_lower = key.lower()
    return any(keyword in key_lower for keyword in SENSITIVE_ENV_KEYWORDS)


def mask_sensitive_value(value: Any) -> str:
    """对敏感值做中间脱敏"""
    text = "" if value is None else str(value)
    if len(text) <= 2:
        return "*" * len(text)
    if len(text) <= 6:
        return f"{text[0]}{'*' * (len(text) - 2)}{text[-1]}"
    if len(text) <= 12:
        return f"{text[:2]}{'*' * (len(text) - 4)}{text[-2:]}"
    return f"{text[:4]}{'*' * (len(text) - 8)}{text[-4:]}"


def mask_env_map(env_map: Optional[dict]) -> dict:
    """按 key 对环境变量字典做脱敏"""
    masked = {}
    for key, value in (env_map or {}).items():
        masked[key] = mask_sensitive_value(value) if is_sensitive_env_key(key) else value
    return masked


# ============ 认证依赖 ============

async def get_current_user(
    authorization: Optional[str] = Header(None)
) -> dict:
    """
    获取当前用户（通过Token验证）
    
    Returns:
        用户信息字典，包含token用于后续API调用
    """
    config = get_config()
    
    if not config.auth_service.enabled:
        return {"user_id": "anonymous", "username": "anonymous", "token": None}
    
    if not authorization or not authorization.startswith("Bearer "):
        raise UnauthorizedError("未提供认证Token")
    
    token = authorization.replace("Bearer ", "")
    
    auth_service = get_auth_service()
    try:
        user_info = await auth_service.validate_token_async(token)
        user_info["token"] = token  # 存储token用于API pass-through
        return user_info
    except TokenInvalidError:
        raise ForbiddenError("Token无效或已过期")
    except AuthServiceError as e:
        raise ForbiddenError(f"认证服务异常: {e}")


# ============ Helper Functions ============

def get_secmate_by_name(db: Session, project_id: str, name: str) -> Optional[SecmateNg]:
    """通过名称获取SecmateNg"""
    return db.query(SecmateNg).filter(
        SecmateNg.project_id == project_id,
        SecmateNg.name == name,
        SecmateNg.status != SecmateNgStatus.DELETED.value
    ).first()


def get_secmate_realtime_status(secmate: SecmateNg, k8s_client, user_token: str) -> tuple:
    """
    获取SecmateNg实时状态
    
    Returns:
        tuple: (status, extra_info)
    """
    project_id = secmate.project_id
    
    # 获取Deployment状态
    deployment_exists = False
    ready_replicas = 0
    total_replicas = 0
    if secmate.deployment_name:
        status_info = k8s_client.get_deployment_status(project_id, secmate.deployment_name, user_token)
        if status_info:
            deployment_exists = True
            ready_replicas = status_info.get("ready_replicas", 0)
            total_replicas = status_info.get("replicas", 0)

    # 获取Pod状态
    pod_status = None
    pod_ip = None
    node_name = None
    pod_exists = False
    if secmate.deployment_name:
        pods = k8s_client.get_pods_by_deployment(
            project_id,
            f"app=secmate-ng,secmate-id={secmate.id}",
            user_token
        )
        if pods:
            pod_exists = True
            pod = pods[0]
            pod_status = pod.get("status")
            pod_ip = pod.get("pod_ip")
            node_name = pod.get("node_name")

    # 计算实际状态
    actual_status = secmate.status

    if not deployment_exists and not pod_exists:
        if secmate.status in [SecmateNgStatus.PENDING.value, SecmateNgStatus.CREATING.value]:
            actual_status = SecmateNgStatus.PENDING.value
        else:
            actual_status = SecmateNgStatus.STOPPED.value
    elif pod_status:
        if ready_replicas > 0 and pod_status == "Running":
            actual_status = SecmateNgStatus.RUNNING.value
        elif pod_status in ["Pending", "ContainerCreating"]:
            actual_status = SecmateNgStatus.CREATING.value
        elif pod_status in ["Error", "Failed", "CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull"]:
            actual_status = SecmateNgStatus.ERROR.value
        elif pod_status == "Succeeded":
            actual_status = SecmateNgStatus.STOPPED.value
        elif pod_status == "Running":
            actual_status = SecmateNgStatus.CREATING.value
        else:
            actual_status = SecmateNgStatus.ERROR.value

    extra_info = {
        "pod_status": pod_status,
        "pod_ip": pod_ip,
        "node_name": node_name,
        "ready_replicas": ready_replicas,
        "total_replicas": total_replicas,
    }

    return actual_status, extra_info


def make_secmate_response(secmate: SecmateNg, realtime_status: str = None) -> SecmateNgResponse:
    """构建SecmateNg响应"""
    return SecmateNgResponse(
        id=secmate.id,
        project_id=secmate.project_id,
        name=secmate.name,
        namespace=secmate.namespace,
        status=realtime_status if realtime_status is not None else secmate.status,
        source_pvcs=secmate.source_pvcs or [],
        output_pvcs=secmate.output_pvcs or [],
        deployment_name=secmate.deployment_name,
        service_name=secmate.service_name,
        ingress_name=secmate.ingress_name,
        pod_name=secmate.pod_name,
        access_url=secmate.access_url,
        secmate_env=secmate.secmate_env or {},
        description=secmate.description,
        created_at=secmate.created_at.isoformat() if secmate.created_at else None,
        updated_at=secmate.updated_at.isoformat() if secmate.updated_at else None
    )


def make_task_response(task: Task) -> TaskResponse:
    """构建任务响应"""
    return TaskResponse(
        id=task.id,
        project_id=task.project_id,
        type=task.type,
        status=task.status,
        secmate_id=task.secmate_id,
        secmate_name=task.secmate_name,
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
    """健康检查接口"""
    return {
        "status": "ok",
        "service": "secmate-ng-manager"
    }


@router.get("/ready")
async def readiness_check():
    """
    就绪探针 - 检查关键依赖服务是否可用

    用于Kubernetes就绪探针，检查：
    - 数据库连接
    - K8s API服务
    - 认证服务（如果启用）

    Returns:
        dict: 包含总体就绪状态和各项检查结果
    """
    checks = {
        "database": check_database_health(),
        "k8s_api": check_k8s_api_health(),
        "auth_service": check_auth_service_health()
    }


@router.get("/config/default-env", response_model=SecmateNgEnvConfigResponse)
async def get_default_env_config(
    current_user: dict = Depends(get_current_user)
):
    """获取后端配置文件中的默认环境变量（敏感字段已脱敏）"""
    config = get_config().secmate_ng

    common_env = config.common_env or {}
    default_secmate_env = config.default_secmate_env or {}

    merged_default_env = dict(common_env)
    merged_default_env.update(default_secmate_env)

    return SecmateNgEnvConfigResponse(
        common_env=mask_env_map(common_env),
        default_secmate_env=mask_env_map(default_secmate_env),
        merged_default_env=mask_env_map(merged_default_env)
    )

    all_ready = all(checks.values())

    return {
        "ready": all_ready,
        "checks": checks,
        "service": "secmate-ng-manager"
    }


# ============ SecmateNg CRUD ============

@router.post("/projects/{project_id}/secmate-instances", response_model=TaskCreatedResponse, status_code=status.HTTP_201_CREATED)
async def create_secmate_instance(
    project_id: str = Path(..., description="项目ID"),
    request: SecmateNgCreateRequest = ...,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    创建SecmateNg实例

    - 异步创建任务
    - 自动创建不存在的输出PVC
    - 自动创建Deployment、Service、Ingress
    """
    # 验证名称是否符合 K8s 命名规范
    if not validate_k8s_name(request.name):
        raise ValidationError(
            "名称必须符合Kubernetes命名规范：只能包含小写字母、数字和'-'，"
            "且以字母或数字开头和结尾，最多253个字符"
        )

    user_token = current_user.get("token")
    k8s_client = get_k8s_api_client()

    # 检查源码PVC是否存在
    for pvc_info in request.source_pvcs:
        if not k8s_client.check_pvc_exists(project_id, pvc_info.pvc_name, user_token):
            raise ValidationError(f"源码PVC不存在: {pvc_info.pvc_name}")

    # 检查名称是否已存在
    existing = get_secmate_by_name(db, project_id, request.name)
    if existing:
        raise ConflictError(f"SecmateNg名称已存在: {request.name}")

    # 创建SecmateNg记录
    secmate_id = generate_id()
    config = get_config()
    namespace = f"project-{project_id}"  # 使用project_id作为namespace标识
    
    secmate = SecmateNg(
        id=secmate_id,
        project_id=project_id,
        name=request.name,
        namespace=namespace,
        status=SecmateNgStatus.PENDING.value,
        description=request.description,
        source_pvcs=[{"pvc_name": p.pvc_name, "mount_path": p.mount_path} for p in request.source_pvcs],
        output_pvcs=[{
            "pvc_name": p.pvc_name,
            "mount_path": p.mount_path,
            "storage_size": p.storage_size
        } for p in request.output_pvcs],
        custom_env=request.custom_env or {},
        secmate_env=request.secmate_env or {}
    )
    db.add(secmate)
    db.commit()

    # 创建异步任务，传递user_token
    task_manager = get_task_manager()
    params = {
        "secmate_id": secmate_id,
        "name": request.name,
        "custom_env": request.custom_env,
        "secmate_env": request.secmate_env,
        "image": request.image,
        "user_token": user_token  # 关键：传递token用于K8s API调用
    }
    task = task_manager.create_task(
        project_id=project_id,
        task_type=TaskType.CREATE.value,
        params=params,
        secmate_id=secmate_id,
        secmate_name=request.name
    )

    return TaskCreatedResponse(
        message="SecmateNg创建任务已提交",
        task_id=task.id,
        task_type=TaskType.CREATE.value
    )


@router.delete("/projects/{project_id}/secmate-instances", response_model=TaskCreatedResponse)
async def delete_secmate_instance(
    project_id: str = Path(..., description="项目ID"),
    request: SecmateNgDeleteRequest = ...,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """删除SecmateNg实例"""
    user_token = current_user.get("token")
    
    secmate = get_secmate_by_name(db, project_id, request.name)
    if not secmate:
        raise NotFoundError("SecmateNg", request.name)

    task_manager = get_task_manager()
    params = {
        "secmate_id": secmate.id,
        "secmate_name": secmate.name,
        "delete_output_pvcs": request.delete_output_pvcs,
        "user_token": user_token
    }
    task = task_manager.create_task(
        project_id=project_id,
        task_type=TaskType.DELETE.value,
        params=params,
        secmate_id=secmate.id,
        secmate_name=request.name
    )

    secmate.status = SecmateNgStatus.DELETING.value
    db.commit()

    return TaskCreatedResponse(
        message="SecmateNg删除任务已提交",
        task_id=task.id,
        task_type=TaskType.DELETE.value
    )


@router.post("/projects/{project_id}/secmate-instances/restart", response_model=TaskCreatedResponse)
async def restart_secmate_instance(
    project_id: str = Path(..., description="项目ID"),
    request: SecmateNgRestartRequest = ...,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """重建SecmateNg实例"""
    user_token = current_user.get("token")
    
    secmate = get_secmate_by_name(db, project_id, request.name)
    if not secmate:
        raise NotFoundError("SecmateNg", request.name)

    if not secmate.deployment_name:
        raise ValidationError("SecmateNg没有关联的Deployment")

    task_manager = get_task_manager()
    params = {
        "secmate_id": secmate.id,
        "secmate_name": secmate.name,
        "user_token": user_token
    }
    task = task_manager.create_task(
        project_id=project_id,
        task_type=TaskType.RESTART.value,
        params=params,
        secmate_id=secmate.id,
        secmate_name=request.name
    )

    return TaskCreatedResponse(
        message="SecmateNg重建任务已提交",
        task_id=task.id,
        task_type=TaskType.RESTART.value
    )


# ============ SecmateNg Query ============

@router.get("/projects/{project_id}/secmate-instances", response_model=SecmateNgListResponse)
async def list_secmate_instances(
    project_id: str = Path(..., description="项目ID"),
    status_filter: Optional[str] = Query(None, alias="status", description="按状态过滤"),
    realtime: bool = Query(True, description="是否实时获取Kubernetes状态"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """查询SecmateNg列表"""
    user_token = current_user.get("token")
    
    query = db.query(SecmateNg).filter(
        SecmateNg.project_id == project_id,
        SecmateNg.status != SecmateNgStatus.DELETED.value
    )

    if status_filter:
        query = query.filter(SecmateNg.status == status_filter)

    instances = query.all()

    k8s_client = get_k8s_api_client() if realtime else None

    items = []
    for secmate in instances:
        realtime_status = None
        if realtime and k8s_client and secmate.deployment_name and user_token:
            try:
                realtime_status, _ = get_secmate_realtime_status(secmate, k8s_client, user_token)
            except Exception as e:
                logger.warning(f"获取SecmateNg {secmate.name} 实时状态失败: {e}")
                realtime_status = secmate.status

        items.append(make_secmate_response(secmate, realtime_status))

    if status_filter and realtime:
        items = [item for item in items if item.status == status_filter]

    return SecmateNgListResponse(
        total=len(items),
        items=items
    )


@router.get("/projects/{project_id}/secmate-instances/{name}", response_model=SecmateNgResponse)
async def get_secmate_instance(
    project_id: str = Path(..., description="项目ID"),
    name: str = Path(..., description="SecmateNg名称"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """查询单个SecmateNg"""
    secmate = get_secmate_by_name(db, project_id, name)
    if not secmate:
        raise NotFoundError("SecmateNg", name)

    return make_secmate_response(secmate)


@router.get("/projects/{project_id}/secmate-instances/{name}/status", response_model=SecmateNgStatusResponse)
async def get_secmate_instance_status(
    project_id: str = Path(..., description="项目ID"),
    name: str = Path(..., description="SecmateNg名称"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取SecmateNg实时状态"""
    user_token = current_user.get("token")
    
    secmate = get_secmate_by_name(db, project_id, name)
    if not secmate:
        raise NotFoundError("SecmateNg", name)

    k8s_client = get_k8s_api_client()
    actual_status, extra_info = get_secmate_realtime_status(secmate, k8s_client, user_token)

    return SecmateNgStatusResponse(
        id=secmate.id,
        name=secmate.name,
        namespace=secmate.namespace,
        status=actual_status,
        pod_status=extra_info.get("pod_status"),
        pod_ip=extra_info.get("pod_ip"),
        node_name=extra_info.get("node_name"),
        access_url=secmate.access_url,
        ready_replicas=extra_info.get("ready_replicas", 0),
        total_replicas=extra_info.get("total_replicas", 0)
    )


@router.get("/projects/{project_id}/secmate-instances/{name}/logs", response_model=SecmateNgLogsResponse)
async def get_secmate_instance_logs(
    project_id: str = Path(..., description="项目ID"),
    name: str = Path(..., description="SecmateNg名称"),
    tail_lines: int = Query(100, description="返回行数", ge=1, le=10000),
    container: Optional[str] = Query(None, description="容器名称"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取SecmateNg运行日志"""
    user_token = current_user.get("token")
    
    secmate = get_secmate_by_name(db, project_id, name)
    if not secmate:
        raise NotFoundError("SecmateNg", name)

    if not secmate.deployment_name:
        raise ValidationError("SecmateNg没有关联的Deployment")

    k8s_client = get_k8s_api_client()

    pods = k8s_client.get_pods_by_deployment(
        project_id,
        f"app=secmate-ng,secmate-id={secmate.id}",
        user_token
    )
    if not pods:
        raise ValidationError("SecmateNg没有运行中的Pod")

    current_pod_name = pods[0].get("name")
    if not current_pod_name:
        raise ValidationError("无法获取Pod名称")

    logs = k8s_client.get_pod_logs(
        project_id, current_pod_name, container=container, tail_lines=tail_lines, user_token=user_token
    )

    if secmate.pod_name != current_pod_name:
        secmate.pod_name = current_pod_name
        db.commit()

    return SecmateNgLogsResponse(
        secmate_id=secmate.id,
        secmate_name=secmate.name,
        namespace=secmate.namespace,
        pod_name=current_pod_name,
        container=container,
        logs=logs
    )


# ============ WebSocket Terminal ============

@router.websocket("/ws/projects/{project_id}/secmate-instances/{name}/exec")
async def websocket_terminal(
    websocket: WebSocket,
    project_id: str,
    name: str,
    token: Optional[str] = Query(None)
):
    """
    WebSocket终端 - 连接到SecmateNg实例

    通过secflow-platform-k8s的WebSocket exec接口
    支持心跳保活和自动重连
    """
    import asyncio
    import websockets

    # 验证token
    config = get_config()
    if config.auth_service.enabled:
        if not token:
            await websocket.accept()
            await websocket.send_text("\x1b[31mError: 未提供认证Token\x1b[0m\r\n")
            await websocket.close()
            return

        auth_service = get_auth_service()
        try:
            await auth_service.validate_token_async(token)
        except (TokenInvalidError, AuthServiceError) as e:
            await websocket.accept()
            await websocket.send_text(f"\x1b[31mError: {str(e)}\x1b[0m\r\n")
            await websocket.close()
            return

    # 获取SecmateNg实例
    db = get_db_session()
    try:
        secmate = db.query(SecmateNg).filter(
            SecmateNg.project_id == project_id,
            SecmateNg.name == name,
            SecmateNg.status != SecmateNgStatus.DELETED.value
        ).first()

        if not secmate:
            await websocket.accept()
            await websocket.send_text("\x1b[31mError: SecmateNg实例不存在\x1b[0m\r\n")
            await websocket.close()
            return

        if not secmate.pod_name:
            await websocket.accept()
            await websocket.send_text("\x1b[31mError: 没有关联的Pod\x1b[0m\r\n")
            await websocket.close()
            return

        # 获取K8s API的WebSocket URL
        k8s_client = get_k8s_api_client()
        ws_url = k8s_client.get_websocket_exec_url(project_id, secmate.pod_name, token)

        logger.info(f"[WS Terminal] 连接到K8s API: {ws_url}")

        await websocket.accept()

        # 心跳配置
        HEARTBEAT_INTERVAL = 30  # 秒

        async def send_heartbeat():
            """定期发送心跳保持连接活跃"""
            while True:
                try:
                    await asyncio.sleep(HEARTBEAT_INTERVAL)
                    # 发送空消息作为心跳（或者可以发送特定的ping消息）
                    # 客户端可以选择性地处理或忽略
                    logger.debug("[WS Terminal] 发送心跳")
                except Exception as e:
                    logger.debug(f"[WS Terminal] 心跳任务结束: {e}")
                    break

        # 连接到K8s API的WebSocket（带重试）
        max_retries = 3
        retry_delay = 1

        for attempt in range(max_retries):
            try:
                async with websockets.connect(
                    ws_url,
                    ping_interval=20,  # 每20秒发送ping
                    ping_timeout=10    # 10秒内等待pong响应
                ) as k8s_ws:
                    # 双向转发消息
                    async def forward_to_k8s():
                        try:
                            while True:
                                data = await websocket.receive_text()
                                await k8s_ws.send(data)
                        except WebSocketDisconnect:
                            logger.info("[WS Terminal] 客户端断开连接")
                        except Exception as e:
                            logger.error(f"[WS Terminal] 转发到K8s失败: {e}")

                    async def forward_to_client():
                        try:
                            while True:
                                data = await k8s_ws.recv()
                                await websocket.send_text(data)
                        except Exception as e:
                            logger.error(f"[WS Terminal] 转发到客户端失败: {e}")

                    # 并行执行双向转发和心跳
                    await asyncio.gather(
                        forward_to_k8s(),
                        forward_to_client(),
                        send_heartbeat()
                    )
                    break  # 成功连接并正常结束，退出重试循环

            except Exception as e:
                if attempt < max_retries - 1:
                    logger.warning(f"[WS Terminal] 连接失败，{retry_delay}秒后重试 (尝试 {attempt + 1}/{max_retries}): {e}")
                    await websocket.send_text(f"\x1b[33m警告: 连接中断，{retry_delay}秒后重试...\x1b[0m\r\n")
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2  # 指数退避
                else:
                    logger.error(f"[WS Terminal] K8s WebSocket连接失败，已达最大重试次数: {e}")
                    await websocket.send_text(f"\x1b[31mError: 无法连接到终端 - {str(e)}\x1b[0m\r\n")
                    await websocket.close()

    finally:
        db.close()


# ============ Task Management ============

@router.get("/projects/{project_id}/tasks", response_model=TaskListResponse)
async def list_tasks(
    project_id: str = Path(..., description="项目ID"),
    status_filter: Optional[str] = Query(None, alias="status", description="按状态过滤"),
    task_type: Optional[str] = Query(None, alias="type", description="按类型过滤"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """查询任务列表"""
    query = db.query(Task).filter(Task.project_id == project_id)

    if status_filter:
        query = query.filter(Task.status == status_filter)
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
    current_user: dict = Depends(get_current_user),
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
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """删除任务"""
    task = db.query(Task).filter(
        Task.id == task_id,
        Task.project_id == project_id
    ).first()

    if not task:
        raise NotFoundError("任务", task_id)

    task_manager = get_task_manager()
    if not task_manager.delete_task(task_id):
        raise NotFoundError("任务", task_id)

    return SuccessResponse(message=f"任务 {task_id} 已删除", data={"task_id": task_id})
