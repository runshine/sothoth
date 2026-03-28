"""
K8S资源管理API路由
提供对Kubernetes资源的增删查改接口
"""

import asyncio
import hashlib
import logging
import secrets
import threading
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Header, Query, status, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.config import get_config
from app.exception import NotFoundError, ForbiddenError, ValidationError
from app.models.database import (
    get_project_namespace,
    get_db,
    create_agent_ingress_route,
    update_agent_ingress_route,
    get_agent_ingress_route,
    get_agent_ingress_route_by_host_path,
    get_agent_ingress_route_by_unique_key,
    list_agent_ingress_routes,
)
from app.services.auth import get_auth_service
from app.services.k8s import get_k8s_service
from app.schemas import (
    ErrorResponse,
    SuccessResponse,
    ProjectTLSSyncRequest,
    PodListResponse,
    PodInfo,
    PodLogResponse,
    PodExecRequest,
    PodExecResponse,
    ServiceListResponse,
    ServiceInfo,
    ServiceCreateRequest,
    ServiceUpdateRequest,
    IngressListResponse,
    IngressInfo,
    IngressCreateRequest,
    IngressUpdateRequest,
    IngressSimpleCreateRequest,
    IngressDomainBindingRequest,
    IngressExternalCreateRequest,
    AgentIngressRouteCreateRequest,
    AgentIngressRouteListResponse,
    AgentIngressRouteInfo,
    SecretListResponse,
    SecretInfo,
    SecretCreateRequest,
    SecretUpdateRequest,
    ConfigMapListResponse,
    ConfigMapInfo,
    ConfigMapCreateRequest,
    ConfigMapUpdateRequest,
    DeploymentListResponse,
    DeploymentInfo,
    DeploymentCreateRequest,
    DeploymentUpdateRequest,
    DeploymentScaleRequest,
    StatefulSetListResponse,
    StatefulSetInfo,
    DaemonSetListResponse,
    DaemonSetInfo,
    JobListResponse,
    JobInfo,
    PVCListResponse,
    PVCInfo,
    ProjectResourcesResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/k8s", tags=["K8S资源管理"])


def _normalize_path(path: str) -> str:
    value = (path or "/").strip()
    if not value.startswith("/"):
        value = f"/{value}"
    return value


def _sanitize_name_fragment(value: str) -> str:
    lowered = (value or "").lower()
    cleaned = "".join(ch if ch.isalnum() else "-" for ch in lowered).strip("-")
    if not cleaned:
        return "na"
    return cleaned[:40]


def _random_suffix(length: int = 6) -> str:
    return secrets.token_hex(max(1, length // 2))[:length]


def _build_secure_default_prefix(base: str) -> str:
    sanitized = _sanitize_name_fragment(base)
    return f"{sanitized}-{_random_suffix(6)}"[:40]


def _get_common_domain_suffix() -> Optional[str]:
    conf = get_config().dynamic_ingress
    return conf.common_domain_suffix or conf.default_domain_suffix


def _build_host_by_prefix(project_id: str, host_prefix: str, domain_suffix: Optional[str]) -> Optional[str]:
    if not domain_suffix:
        return None
    prefix = _sanitize_name_fragment(host_prefix)
    project = _sanitize_name_fragment(project_id)
    return f"{prefix}-{project}.{domain_suffix}"


def _resolve_ingress_host(
    project_id: str,
    explicit_host: Optional[str] = None,
    host_prefix: Optional[str] = None,
    default_prefix: Optional[str] = None,
) -> Optional[str]:
    if explicit_host and explicit_host.strip():
        return explicit_host.strip()
    prefix = (host_prefix or default_prefix or "").strip()
    if not prefix:
        return None
    return _build_host_by_prefix(project_id, prefix, _get_common_domain_suffix())


def _build_resource_names(project_id: str, agent_key: str, target_port: int, host: str, path: str) -> tuple[str, str]:
    uniq = hashlib.sha1(f"{project_id}|{agent_key}|{target_port}|{host}|{path}".encode("utf-8")).hexdigest()[:10]
    ingress_name = f"agrt-{_sanitize_name_fragment(agent_key)[:12]}-{target_port}-{uniq}"[:63]
    service_name = f"{ingress_name}-external-svc"
    return ingress_name, service_name


async def get_current_user(
    authorization: Optional[str] = Header(None, description="Bearer Token"),
    db: Session = Depends(get_db)
) -> dict:
    """获取当前用户"""
    config = get_config()

    # 如果认证开关关闭，返回默认用户信息
    if not config.auth_service.enabled:
        return {"user_id": "anonymous", "username": "anonymous", "role": "admin"}

    if not authorization or not authorization.startswith("Bearer "):
        raise ForbiddenError("未提供认证Token")

    token = authorization.replace("Bearer ", "")

    # 调用认证服务验证token
    auth_service = get_auth_service()
    try:
        user_info = await auth_service.validate_token_async(token)
        return user_info
    except Exception as e:
        logger.error(f"Token验证失败: {e}")
        raise ForbiddenError("Token无效或已过期")


async def get_project_and_namespace(
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> tuple:
    """
    获取项目及其K8S Namespace
    通过project_id查询数据库获取namespace，而不是直接使用前端传递的namespace
    """
    # 从数据库查询项目信息
    namespace = get_project_namespace(db, project_id)

    if not namespace:
        raise NotFoundError("项目", project_id)

    return project_id, namespace


def _ensure_namespace_exists(namespace: str) -> None:
    """
    确保目标 namespace 存在。
    对动态 Ingress 等场景做兜底，避免因项目 namespace 尚未落地导致创建失败。
    """
    k8s = get_k8s_service()
    try:
        k8s.get_namespace(namespace)
        return
    except Exception as e:
        msg = str(e).lower()
        if "不存在" in str(e) or "not found" in msg:
            logger.warning(f"namespace 不存在，自动创建: {namespace}")
            k8s.create_namespace(
                namespace,
                labels={
                    "managed-by": "secflow-platform-k8s",
                    "secflow-auto-created": "true",
                },
            )
            return
        raise


# ==================== 健康检查 ====================


@router.get("/health", summary="健康检查")
async def health_check():
    """服务健康检查"""
    return {"status": "healthy"}


@router.get("/ready", summary="就绪检查")
async def readiness_check():
    """服务就绪检查"""
    return {"status": "ready"}


# ==================== Namespace 管理 ====================


@router.get("/namespaces/{namespace_name}", summary="检查Namespace是否存在")
async def check_namespace(
    namespace_name: str,
    current_user: dict = Depends(get_current_user)
):
    """检查Namespace是否存在"""
    k8s = get_k8s_service()
    try:
        namespace = k8s.get_namespace(namespace_name)
        return {
            "exists": True,
            "name": namespace_name,
            "status": namespace.get("status", "Unknown")
        }
    except NotFoundError:
        return {
            "exists": False,
            "name": namespace_name,
            "status": "NotFound"
        }


@router.post("/namespaces/{namespace_name}", response_model=SuccessResponse, summary="创建Namespace")
async def create_namespace(
    namespace_name: str,
    current_user: dict = Depends(get_current_user)
):
    """创建Namespace"""
    k8s = get_k8s_service()
    labels = {"managed-by": "secflow-platform-k8s"}
    result = k8s.create_namespace(namespace_name, labels=labels)
    return SuccessResponse(message="Namespace创建成功", data=result)


@router.delete("/namespaces/{namespace_name}", response_model=SuccessResponse, summary="删除Namespace")
async def delete_namespace(
    namespace_name: str,
    current_user: dict = Depends(get_current_user)
):
    """删除Namespace"""
    k8s = get_k8s_service()
    result = k8s.delete_namespace(namespace_name)
    return SuccessResponse(message="Namespace删除请求已提交", data=result)


@router.get("/projects/{project_id}/namespace", summary="获取项目Namespace信息")
async def get_project_namespace_info(
    project_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取项目Namespace信息"""
    namespace = get_project_namespace(db, project_id)
    if not namespace:
        raise NotFoundError("项目", project_id)

    k8s = get_k8s_service()
    try:
        ns_info = k8s.get_namespace(namespace)
        return {
            "project_id": project_id,
            "namespace": namespace,
            "exists": True,
            "status": ns_info.get("status", "Unknown")
        }
    except NotFoundError:
        return {
            "project_id": project_id,
            "namespace": namespace,
            "exists": False,
            "status": "NotFound"
        }


# ==================== 项目资源概览 ====================


@router.get("/projects/{project_id}/resources", response_model=ProjectResourcesResponse, summary="获取项目资源概览")
async def get_project_resources(
    project_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取项目下所有K8S资源概览"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()

    try:
        pods = k8s.list_pods(namespace)
        services = k8s.list_services(namespace)
        deployments = k8s.list_deployments(namespace)
        statefulsets = k8s.list_statefulsets(namespace)
        daemonsets = k8s.list_daemonsets(namespace)
        jobs = k8s.list_jobs(namespace)
        configmaps = k8s.list_configmaps(namespace)
        secrets = k8s.list_secrets(namespace)
        ingresses = k8s.list_ingresses(namespace)
        pvcs = k8s.list_pvcs(namespace)

        return ProjectResourcesResponse(
            project_id=project_id,
            namespace=namespace,
            pods=len(pods),
            services=len(services),
            deployments=len(deployments),
            statefulsets=len(statefulsets),
            daemonsets=len(daemonsets),
            jobs=len(jobs),
            configmaps=len(configmaps),
            secrets=len(secrets),
            ingresses=len(ingresses),
            pvcs=len(pvcs),
        )
    except Exception as e:
        logger.error(f"获取项目资源概览失败: {e}")
        raise ValidationError(f"获取资源概览失败: {str(e)}")


# ==================== POD 管理 ====================


@router.get("/pods", response_model=PodListResponse, summary="获取Pod列表")
async def list_pods(
    label_selector: Optional[str] = Query(None, description="标签选择器"),
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取Pod列表"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    pods = k8s.list_pods(namespace, label_selector)

    return PodListResponse(total=len(pods), items=pods)


@router.get("/pods/{pod_name}", response_model=PodInfo, summary="获取Pod详情")
async def get_pod(
    pod_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取Pod详情"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    return k8s.get_pod(namespace, pod_name)


@router.post("/pods", response_model=PodInfo, status_code=status.HTTP_201_CREATED, summary="创建Pod")
async def create_pod(
    manifest: dict,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """创建Pod"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    return k8s.create_pod(namespace, manifest)


@router.delete("/pods/{pod_name}", response_model=SuccessResponse, summary="删除Pod")
async def delete_pod(
    pod_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """删除Pod"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    result = k8s.delete_pod(namespace, pod_name)
    return SuccessResponse(message="Pod删除成功", data=result)


@router.get("/pods/{pod_name}/containers", summary="获取Pod容器列表")
async def get_pod_containers(
    pod_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取Pod的容器列表"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    containers = k8s.get_pod_containers(namespace, pod_name)
    return {"pod_name": pod_name, "containers": containers}


@router.get("/pods/{pod_name}/logs", response_model=PodLogResponse, summary="获取Pod日志")
async def get_pod_logs(
    pod_name: str,
    container: Optional[str] = Query(None, description="容器名"),
    tail_lines: int = Query(100, description="日志行数"),
    previous: bool = Query(False, description="是否获取前一个容器的日志"),
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取Pod日志"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    logs = k8s.get_pod_logs(namespace, pod_name, container, tail_lines, previous)
    return PodLogResponse(logs=logs)


@router.get("/pods/{pod_name}/events", summary="获取Pod事件")
async def get_pod_events(
    pod_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取Pod相关事件"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)
    k8s = get_k8s_service()
    events = k8s.get_pod_events(namespace, pod_name)
    return {"pod_name": pod_name, "events": events}


@router.get("/pods/{pod_name}/status", summary="获取Pod详细状态")
async def get_pod_status_detail(
    pod_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取Pod详细状态信息"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)
    k8s = get_k8s_service()
    status = k8s.get_pod_status_detail(namespace, pod_name)
    return status


@router.get("/pods/{pod_name}/metrics", summary="获取Pod资源指标")
async def get_pod_metrics(
    pod_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取Pod资源使用指标（CPU/内存）"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)
    k8s = get_k8s_service()
    metrics = k8s.get_pod_metrics(namespace, pod_name)
    return metrics


@router.post("/pods/{pod_name}/exec", response_model=PodExecResponse, summary="执行Pod命令")
async def exec_pod_command(
    pod_name: str,
    request: PodExecRequest,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """执行一次非交互式 Pod 命令。"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    result = k8s.exec_pod_command(
        namespace=namespace,
        pod_name=pod_name,
        command=request.command,
        container=request.container,
        stdin_data=request.stdin,
        timeout=request.timeout,
        tty=request.tty,
    )
    return PodExecResponse(**result)


# ==================== Service 管理 ====================


@router.get("/services", response_model=ServiceListResponse, summary="获取Service列表")
async def list_services(
    label_selector: Optional[str] = Query(None, description="标签选择器"),
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取Service列表"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    services = k8s.list_services(namespace, label_selector)

    return ServiceListResponse(total=len(services), items=services)


@router.get("/services/{service_name}", response_model=ServiceInfo, summary="获取Service详情")
async def get_service(
    service_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取Service详情"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    return k8s.get_service(namespace, service_name)


@router.post("/services", response_model=ServiceInfo, status_code=status.HTTP_201_CREATED, summary="创建Service")
async def create_service(
    request: ServiceCreateRequest,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """创建Service"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    manifest = {
        "metadata": {
            "name": request.name,
            "namespace": namespace,
        },
        "spec": {
            "type": request.type,
            "selector": request.selector,
            "ports": request.ports,
        }
    }

    k8s = get_k8s_service()
    return k8s.create_service(namespace, manifest)


@router.delete("/services/{service_name}", response_model=SuccessResponse, summary="删除Service")
async def delete_service(
    service_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """删除Service"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    result = k8s.delete_service(namespace, service_name)
    return SuccessResponse(message="Service删除成功", data=result)


@router.get("/services/{service_name}/access", summary="获取Service访问信息")
async def get_service_access(
    service_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取Service访问信息，包括访问URL"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)
    k8s = get_k8s_service()
    access_info = k8s.get_service_access_info(namespace, service_name)
    return access_info


@router.api_route("/services/{service_name}/proxy/{port}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"], summary="代理请求到Service")
async def proxy_service(
    service_name: str,
    port: int,
    path: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
    request: Request = None
):
    """代理HTTP请求到K8S Service"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)
    k8s = get_k8s_service()

    # 获取请求体
    body = None
    if request and request.method in ["POST", "PUT", "PATCH"]:
        body = await request.body()
        body = body.decode('utf-8') if body else None

    # 代理请求
    result = k8s.proxy_service_request(
        namespace=namespace,
        service_name=service_name,
        port=port,
        path=f"/{path}",
        method=request.method if request else "GET",
        body=body,
        headers=dict(request.headers) if request else {}
    )

    return result


# ==================== Ingress 管理 ====================


@router.get("/ingress-controllers", summary="获取可用的Ingress Controller列表")
async def get_ingress_controllers(
    current_user: dict = Depends(get_current_user)
):
    """
    获取集群中可用的Ingress Controller列表

    返回Ingress Controller的名称、外部IP、端口等信息，
    供前端选择使用。用户创建Ingress时可以选择一个Controller，
    并使用其外部IP访问服务。

    无需project_id，因为Ingress Controller是集群级别的资源。
    """
    k8s = get_k8s_service()
    controllers = k8s.get_ingress_controllers()
    return {"total": len(controllers), "items": controllers}


@router.get("/ingresses", response_model=IngressListResponse, summary="获取Ingress列表")
async def list_ingresses(
    label_selector: Optional[str] = Query(None, description="标签选择器"),
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取Ingress列表"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    ingresses = k8s.list_ingresses(namespace, label_selector)

    return IngressListResponse(total=len(ingresses), items=ingresses)


@router.get("/ingresses/{ingress_name}", response_model=IngressInfo, summary="获取Ingress详情")
async def get_ingress(
    ingress_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取Ingress详情"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    return k8s.get_ingress(namespace, ingress_name)


@router.post("/ingresses", response_model=IngressInfo, status_code=status.HTTP_201_CREATED, summary="创建Ingress")
async def create_ingress(
    request: IngressCreateRequest,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """创建Ingress"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    manifest = {
        "metadata": {
            "name": request.name,
            "namespace": namespace,
            "annotations": request.annotation,
        },
        "spec": {
            "ingressClassName": request.ingress_class_name,
            "tls": request.tls,
            "rules": [request.rule],
        }
    }

    k8s = get_k8s_service()
    return k8s.create_ingress(namespace, manifest)


@router.post("/ingresses/simple", response_model=IngressInfo, status_code=status.HTTP_201_CREATED, summary="创建简化版Ingress(工作流服务专用)")
async def create_simple_ingress(
    request: IngressSimpleCreateRequest,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    创建简化版Ingress

    供工作流服务使用，只需提供Service名称、端口和域名即可创建Ingress。
    """
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    resolved_host = _resolve_ingress_host(
        project_id=project_id,
        explicit_host=request.host,
        host_prefix=request.host_prefix,
        default_prefix=request.name
    )
    if not resolved_host:
        raise ValidationError("host 或 host_prefix 必须至少提供一个，且需配置 dynamic_ingress.common_domain_suffix")

    k8s = get_k8s_service()
    return k8s.create_simple_ingress(
        namespace=namespace,
        name=request.name,
        service_name=request.service_name,
        service_port=request.service_port,
        host=resolved_host,
        ingress_type=request.ingress_type,
        ingress_ip=request.ingress_ip,
        path=request.path,
        path_type=request.path_type
    )


@router.post("/ingresses/{ingress_name}/bind-domain", response_model=IngressInfo, summary="绑定Ingress域名")
async def bind_ingress_domain(
    ingress_name: str,
    request: IngressDomainBindingRequest,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    为指定 Ingress 绑定或更新域名。

    供 workflow / workflow-status 微服务调用，统一通过 k8s 微服务完成
    Ingress 域名和选中 Ingress IP 的绑定。
    """
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    return k8s.bind_domain_to_ingress(
        namespace=namespace,
        ingress_name=ingress_name,
        service_name=request.service_name,
        service_port=request.service_port,
        host=request.host,
        ingress_type=request.ingress_type,
        ingress_ip=request.ingress_ip,
        path=request.path,
        path_type=request.path_type,
    )


@router.delete("/ingresses/{ingress_name}", response_model=SuccessResponse, summary="删除Ingress")
async def delete_ingress(
    ingress_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """删除Ingress"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    result = k8s.delete_ingress(namespace, ingress_name)
    return SuccessResponse(message="Ingress删除成功", data=result)


@router.post("/ingresses/external", response_model=dict, status_code=status.HTTP_201_CREATED, summary="创建外部端点Ingress(路由到外部IP:端口)")
async def create_external_ingress(
    request: IngressExternalCreateRequest,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    创建外部端点Ingress

    用于将流量路由到外部IP:端口而非K8s内部Service。
    自动创建Service(无selector)、Endpoints(包含外部IP)和Ingress。
    支持多个外部IP地址实现负载均衡。
    支持NGINX Ingress注解配置（WebSocket、上传大小、超时等）。
    """
    from typing import Dict

    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)
    _ensure_namespace_exists(namespace)

    resolved_host = _resolve_ingress_host(
        project_id=project_id,
        explicit_host=request.host,
        host_prefix=request.host_prefix,
        default_prefix=request.name
    )
    if not resolved_host:
        raise ValidationError("host 或 host_prefix 必须至少提供一个，且需配置 dynamic_ingress.common_domain_suffix")

    k8s = get_k8s_service()
    result = k8s.create_external_ingress(
        namespace=namespace,
        name=request.name,
        external_ips=request.external_ips,
        external_port=request.external_port,
        host=resolved_host,
        path=request.path,
        path_type=request.path_type,
        ingress_type=request.ingress_type,
        service_port=request.service_port,
        tls_enabled=request.tls_enabled,
        tls_secret_name=request.tls_secret_name,
        websocket_enabled=request.websocket_enabled,
        proxy_body_size=request.proxy_body_size,
        proxy_connect_timeout=request.proxy_connect_timeout,
        proxy_send_timeout=request.proxy_send_timeout,
        proxy_read_timeout=request.proxy_read_timeout,
        ssl_redirect=request.ssl_redirect
    )
    result["resolved_host"] = resolved_host
    return result


@router.delete("/ingresses/external/{ingress_name}", response_model=SuccessResponse, summary="删除外部端点Ingress(级联删除)")
async def delete_external_ingress(
    ingress_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    删除外部端点Ingress

    级联删除关联的Service和Endpoints资源。
    """
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    result = k8s.delete_external_ingress(namespace, ingress_name)
    return SuccessResponse(message="外部端点Ingress删除成功", data=result)


# ==================== Agent动态Ingress路由 ====================


@router.get("/agent-ingress-routes", response_model=AgentIngressRouteListResponse, summary="获取Agent动态Ingress路由列表")
async def list_dynamic_agent_ingress_routes(
    project_id: str = Query(..., description="项目ID"),
    agent_key: Optional[str] = Query(None, description="Agent唯一标识"),
    include_deleted: bool = Query(False, description="是否包含已删除记录"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    project_id, _ = await get_project_and_namespace(project_id, current_user, db)
    return list_agent_ingress_routes(db, project_id, agent_key, include_deleted)


@router.post("/agent-ingress-routes", response_model=AgentIngressRouteInfo, status_code=status.HTTP_201_CREATED, summary="创建/更新Agent动态Ingress路由")
async def create_dynamic_agent_ingress_route(
    request: AgentIngressRouteCreateRequest,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)
    _ensure_namespace_exists(namespace)
    conf = get_config().dynamic_ingress
    if not conf.enabled:
        raise ValidationError("动态Ingress功能已关闭")

    target_port = int(request.target_port)
    default_prefix = _build_secure_default_prefix(f"{request.agent_key}-{target_port}")
    host = _resolve_ingress_host(
        project_id=project_id,
        explicit_host=request.host,
        host_prefix=request.host_prefix,
        default_prefix=default_prefix
    )
    if not host:
        raise ValidationError("host 不能为空，且未配置 dynamic_ingress.common_domain_suffix")
    path = _normalize_path(request.path or conf.default_path)
    ingress_type = request.ingress_type or conf.default_ingress_type
    path_type = request.path_type or conf.default_path_type
    # Agent动态转发场景下，若未显式指定service_port，应与target_port保持一致，
    # 否则Ingress会错误回源到默认80端口导致502。
    service_port = int(request.service_port if request.service_port is not None else target_port)
    tls_enabled = bool(conf.default_tls_enabled if request.tls_enabled is None else request.tls_enabled)
    tls_secret_name = request.tls_secret_name if request.tls_secret_name is not None else conf.default_tls_secret_name
    if tls_secret_name == "wildcard-code-server.sothothv2.com-tls":
        # 兼容历史配置，统一切换到当前公共TLS Secret
        tls_secret_name = "wildcard-sothothv2.com-tls"
    if tls_enabled and (not tls_secret_name or not str(tls_secret_name).strip()):
        raise ValidationError("已启用TLS但未配置tls_secret_name，请配置公共TLS Secret名称")
    if tls_enabled:
        try:
            get_k8s_service().get_secret(namespace, tls_secret_name)
        except Exception:
            raise ValidationError(
                f"目标命名空间缺少TLS Secret: {tls_secret_name}，请先在 {namespace} 中创建该公共Secret"
            )
    websocket_enabled = bool(conf.default_websocket_enabled if request.websocket_enabled is None else request.websocket_enabled)
    proxy_body_size = request.proxy_body_size if request.proxy_body_size is not None else conf.default_proxy_body_size
    proxy_connect_timeout = int(request.proxy_connect_timeout if request.proxy_connect_timeout is not None else conf.default_proxy_connect_timeout)
    proxy_send_timeout = int(request.proxy_send_timeout if request.proxy_send_timeout is not None else conf.default_proxy_send_timeout)
    proxy_read_timeout = int(request.proxy_read_timeout if request.proxy_read_timeout is not None else conf.default_proxy_read_timeout)
    if websocket_enabled:
        if request.proxy_send_timeout is None:
            proxy_send_timeout = max(proxy_send_timeout, 3600)
        if request.proxy_read_timeout is None:
            proxy_read_timeout = max(proxy_read_timeout, 3600)
    ssl_redirect = bool(conf.default_ssl_redirect if request.ssl_redirect is None else request.ssl_redirect)
    backend_protocol = str(request.backend_protocol or (request.metadata or {}).get("backend_protocol") or "http").strip().lower()
    if backend_protocol not in {"http", "https"}:
        backend_protocol = "http"

    existing = get_agent_ingress_route_by_unique_key(db, project_id, request.agent_key, target_port, host, path)
    conflicting_route = get_agent_ingress_route_by_host_path(db, project_id, host, path)
    if conflicting_route and (not existing or conflicting_route.get("route_id") != existing.get("route_id")):
        conflict_port = conflicting_route.get("target_port")
        raise ValidationError(
            f"动态路由冲突: {host}{path} 已绑定到端口 {conflict_port}。"
            f" 同一 host + path 不能同时转发到多个端口，请改用不同的 host_prefix 或 path。"
        )
    ext_ips_normalized = sorted(list(dict.fromkeys(request.external_ips)))
    force_recreate = bool(request.force_recreate)
    if existing and not force_recreate:
        same_ips = sorted(existing.get("external_ips") or []) == ext_ips_normalized
        if (
            same_ips
            and existing.get("ingress_type") == ingress_type
            and existing.get("path_type") == path_type
            and int(existing.get("service_port") or 0) == service_port
            and bool(existing.get("tls_enabled")) == tls_enabled
            and (existing.get("tls_secret_name") or "") == (tls_secret_name or "")
            and bool(existing.get("websocket_enabled")) == websocket_enabled
            and existing.get("status") == "ready"
        ):
            return existing

    ingress_name, service_name = _build_resource_names(project_id, request.agent_key, target_port, host, path)
    route_id = existing["route_id"] if existing else uuid.uuid4().hex
    base_route_data = {
        "route_id": route_id,
        "project_id": project_id,
        "namespace": namespace,
        "agent_key": request.agent_key,
        "target_port": target_port,
        "external_ips": ext_ips_normalized,
        "host": host,
        "path": path,
        "ingress_type": ingress_type,
        "path_type": path_type,
        "service_port": service_port,
        "ingress_name": ingress_name,
        "service_name": service_name,
        "tls_enabled": tls_enabled,
        "tls_secret_name": tls_secret_name,
        "backend_protocol": backend_protocol,
        "websocket_enabled": websocket_enabled,
        "owner_service": request.owner_service,
        "created_by": request.created_by or current_user.get("user_id"),
        "metadata": request.metadata or {},
        "status": "creating",
        "access_url": None,
        "deleted_at": None,
    }

    if existing:
        update_agent_ingress_route(db, route_id, base_route_data)
        try:
            get_k8s_service().delete_external_ingress(namespace=namespace, name=existing.get("ingress_name", ingress_name))
        except Exception as e:
            logger.warning(f"重建动态路由前删除旧Ingress失败，继续尝试创建: route_id={route_id}, error={e}")
    else:
        create_agent_ingress_route(db, base_route_data)

    try:
        k8s_result = get_k8s_service().create_external_ingress(
            namespace=namespace,
            name=ingress_name,
            external_ips=ext_ips_normalized,
            external_port=target_port,
            host=host,
            path=path,
            path_type=path_type,
            ingress_type=ingress_type,
            service_port=service_port,
            tls_enabled=tls_enabled,
            tls_secret_name=tls_secret_name,
            backend_protocol=backend_protocol,
            websocket_enabled=websocket_enabled,
            proxy_body_size=proxy_body_size,
            proxy_connect_timeout=proxy_connect_timeout,
            proxy_send_timeout=proxy_send_timeout,
            proxy_read_timeout=proxy_read_timeout,
            ssl_redirect=ssl_redirect,
        )
        access_url = k8s_result.get("access_url")
        update_agent_ingress_route(db, route_id, {
            "status": "ready",
            "access_url": access_url,
            "backend_protocol": backend_protocol,
            "metadata": {
                **(request.metadata or {}),
                "backend_protocol": backend_protocol,
                "k8s_result": {
                    "ingress": k8s_result.get("ingress", {}),
                    "service": k8s_result.get("service", {}),
                    "endpoints": k8s_result.get("endpoints", {}),
                }
            },
        })
        return get_agent_ingress_route(db, route_id)
    except Exception as e:
        update_agent_ingress_route(db, route_id, {
            "status": "error",
            "metadata": {**(request.metadata or {}), "error": str(e)},
        })
        raise ValidationError(f"动态路由创建失败: {e}")


@router.delete("/agent-ingress-routes/{route_id}", response_model=SuccessResponse, summary="删除Agent动态Ingress路由")
async def delete_dynamic_agent_ingress_route(
    route_id: str,
    project_id: str = Query(..., description="项目ID"),
    agent_key: Optional[str] = Query(None, description="Agent唯一标识"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    project_id, _ = await get_project_and_namespace(project_id, current_user, db)
    route = get_agent_ingress_route(db, route_id)
    if not route:
        raise NotFoundError("动态Ingress路由", route_id)
    if route.get("project_id") != project_id:
        raise ForbiddenError("无权访问该项目下的动态Ingress路由")
    if agent_key and route.get("agent_key") != agent_key:
        raise ValidationError(f"路由不属于指定agent: {agent_key}")

    try:
        get_k8s_service().delete_external_ingress(route["namespace"], route["ingress_name"])
    except Exception as e:
        logger.warning(f"删除动态路由对应Ingress失败: route_id={route_id}, error={e}")
    update_agent_ingress_route(db, route_id, {"status": "deleted", "access_url": None, "deleted_at": datetime.utcnow()})
    return SuccessResponse(message="动态Ingress路由删除成功", data=get_agent_ingress_route(db, route_id))


# ==================== Secret 管理 ====================


@router.post("/projects/{project_id}/tls-secret/sync", response_model=SuccessResponse, summary="同步项目TLS Secret")
async def sync_project_tls_secret(
    project_id: str,
    request: ProjectTLSSyncRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    将源命名空间中的 TLS Secret 复制到项目命名空间（已存在则覆盖）。
    """
    _, namespace = await get_project_and_namespace(project_id, current_user, db)
    result = get_k8s_service().sync_tls_secret(
        source_namespace=request.source_namespace,
        source_secret_name=request.source_secret_name,
        target_namespace=namespace,
        target_secret_name=request.target_secret_name,
    )
    return SuccessResponse(message="项目TLS Secret同步成功", data=result)


@router.get("/secrets", response_model=SecretListResponse, summary="获取Secret列表")
async def list_secrets(
    label_selector: Optional[str] = Query(None, description="标签选择器"),
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取Secret列表"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    secrets = k8s.list_secrets(namespace, label_selector)

    return SecretListResponse(total=len(secrets), items=secrets)


@router.get("/secrets/{secret_name}", response_model=SecretInfo, summary="获取Secret详情")
async def get_secret(
    secret_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取Secret详情"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    return k8s.get_secret(namespace, secret_name)


@router.post("/secrets", response_model=SecretInfo, status_code=status.HTTP_201_CREATED, summary="创建Secret")
async def create_secret(
    request: SecretCreateRequest,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """创建Secret"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    manifest = {
        "metadata": {
            "name": request.name,
            "namespace": namespace,
            "labels": request.label,
            "annotations": request.annotation,
        },
        "type": request.type,
        "data": request.data,
    }

    k8s = get_k8s_service()
    return k8s.create_secret(namespace, manifest)


@router.delete("/secrets/{secret_name}", response_model=SuccessResponse, summary="删除Secret")
async def delete_secret(
    secret_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """删除Secret"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    result = k8s.delete_secret(namespace, secret_name)
    return SuccessResponse(message="Secret删除成功", data=result)


# ==================== ConfigMap 管理 ====================


@router.get("/configmaps", response_model=ConfigMapListResponse, summary="获取ConfigMap列表")
async def list_configmaps(
    label_selector: Optional[str] = Query(None, description="标签选择器"),
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取ConfigMap列表"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    configmaps = k8s.list_configmaps(namespace, label_selector)

    return ConfigMapListResponse(total=len(configmaps), items=configmaps)


@router.get("/configmaps/{configmap_name}", response_model=ConfigMapInfo, summary="获取ConfigMap详情")
async def get_configmap(
    configmap_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取ConfigMap详情"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    return k8s.get_configmap(namespace, configmap_name)


@router.post("/configmaps", response_model=ConfigMapInfo, status_code=status.HTTP_201_CREATED, summary="创建ConfigMap")
async def create_configmap(
    request: ConfigMapCreateRequest,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """创建ConfigMap"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    manifest = {
        "metadata": {
            "name": request.name,
            "namespace": namespace,
            "labels": request.label,
            "annotations": request.annotation,
        },
        "data": request.data,
        "binaryData": request.binary_data,
    }

    k8s = get_k8s_service()
    return k8s.create_configmap(namespace, manifest)


@router.delete("/configmaps/{configmap_name}", response_model=SuccessResponse, summary="删除ConfigMap")
async def delete_configmap(
    configmap_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """删除ConfigMap"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    result = k8s.delete_configmap(namespace, configmap_name)
    return SuccessResponse(message="ConfigMap删除成功", data=result)


# ==================== Deployment 管理 ====================


@router.get("/deployments", response_model=DeploymentListResponse, summary="获取Deployment列表")
async def list_deployments(
    label_selector: Optional[str] = Query(None, description="标签选择器"),
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取Deployment列表"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    deployments = k8s.list_deployments(namespace, label_selector)

    return DeploymentListResponse(total=len(deployments), items=deployments)


@router.get("/deployments/{deployment_name}", response_model=DeploymentInfo, summary="获取Deployment详情")
async def get_deployment(
    deployment_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取Deployment详情"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    return k8s.get_deployment(namespace, deployment_name)


@router.post("/deployments", response_model=DeploymentInfo, status_code=status.HTTP_201_CREATED, summary="创建Deployment")
async def create_deployment(
    request: DeploymentCreateRequest,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """创建Deployment"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    manifest = request.manifest
    if "metadata" not in manifest:
        manifest["metadata"] = {}
    manifest["metadata"]["namespace"] = namespace

    k8s = get_k8s_service()
    return k8s.create_deployment(namespace, manifest)


@router.delete("/deployments/{deployment_name}", response_model=SuccessResponse, summary="删除Deployment")
async def delete_deployment(
    deployment_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """删除Deployment"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    result = k8s.delete_deployment(namespace, deployment_name)
    return SuccessResponse(message="Deployment删除成功", data=result)


@router.post("/deployments/{deployment_name}/scale", response_model=DeploymentInfo, summary="扩缩容Deployment")
async def scale_deployment(
    deployment_name: str,
    request: DeploymentScaleRequest,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """扩缩容Deployment"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    result = k8s.scale_deployment(namespace, deployment_name, request.replica)
    return k8s.get_deployment(namespace, deployment_name)


@router.post("/deployments/{deployment_name}/restart", response_model=SuccessResponse, summary="重启Deployment")
async def restart_deployment(
    deployment_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """重启Deployment（触发滚动更新）"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)
    k8s = get_k8s_service()
    result = k8s.restart_deployment(namespace, deployment_name)
    return SuccessResponse(message="Deployment重启已触发", data=result)


# ==================== StatefulSet 管理 ====================


@router.get("/statefulsets", response_model=StatefulSetListResponse, summary="获取StatefulSet列表")
async def list_statefulsets(
    label_selector: Optional[str] = Query(None, description="标签选择器"),
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取StatefulSet列表"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    statefulsets = k8s.list_statefulsets(namespace, label_selector)

    return StatefulSetListResponse(total=len(statefulsets), items=statefulsets)


@router.get("/statefulsets/{statefulset_name}", response_model=StatefulSetInfo, summary="获取StatefulSet详情")
async def get_statefulset(
    statefulset_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取StatefulSet详情"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    return k8s.get_statefulset(namespace, statefulset_name)


@router.post("/statefulsets", response_model=StatefulSetInfo, status_code=status.HTTP_201_CREATED, summary="创建StatefulSet")
async def create_statefulset(
    manifest: dict,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """创建StatefulSet"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    if "metadata" not in manifest:
        manifest["metadata"] = {}
    manifest["metadata"]["namespace"] = namespace

    k8s = get_k8s_service()
    return k8s.create_statefulset(namespace, manifest)


@router.delete("/statefulsets/{statefulset_name}", response_model=SuccessResponse, summary="删除StatefulSet")
async def delete_statefulset(
    statefulset_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """删除StatefulSet"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    result = k8s.delete_statefulset(namespace, statefulset_name)
    return SuccessResponse(message="StatefulSet删除成功", data=result)


# ==================== DaemonSet 管理 ====================


@router.get("/daemonsets", response_model=DaemonSetListResponse, summary="获取DaemonSet列表")
async def list_daemonsets(
    label_selector: Optional[str] = Query(None, description="标签选择器"),
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取DaemonSet列表"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    daemonsets = k8s.list_daemonsets(namespace, label_selector)

    return DaemonSetListResponse(total=len(daemonsets), items=daemonsets)


@router.get("/daemonsets/{daemonset_name}", response_model=DaemonSetInfo, summary="获取DaemonSet详情")
async def get_daemonset(
    daemonset_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取DaemonSet详情"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    return k8s.get_daemonset(namespace, daemonset_name)


@router.post("/daemonsets", response_model=DaemonSetInfo, status_code=status.HTTP_201_CREATED, summary="创建DaemonSet")
async def create_daemonset(
    manifest: dict,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """创建DaemonSet"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    if "metadata" not in manifest:
        manifest["metadata"] = {}
    manifest["metadata"]["namespace"] = namespace

    k8s = get_k8s_service()
    return k8s.create_daemonset(namespace, manifest)


@router.delete("/daemonsets/{daemonset_name}", response_model=SuccessResponse, summary="删除DaemonSet")
async def delete_daemonset(
    daemonset_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """删除DaemonSet"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    result = k8s.delete_daemonset(namespace, daemonset_name)
    return SuccessResponse(message="DaemonSet删除成功", data=result)


# ==================== Job 管理 ====================


@router.get("/jobs", response_model=JobListResponse, summary="获取Job列表")
async def list_jobs(
    label_selector: Optional[str] = Query(None, description="标签选择器"),
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取Job列表"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    jobs = k8s.list_jobs(namespace, label_selector)

    return JobListResponse(total=len(jobs), items=jobs)


@router.get("/jobs/{job_name}", response_model=JobInfo, summary="获取Job详情")
async def get_job(
    job_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取Job详情"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    return k8s.get_job(namespace, job_name)


@router.post("/jobs", response_model=JobInfo, status_code=status.HTTP_201_CREATED, summary="创建Job")
async def create_job(
    manifest: dict,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """创建Job"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    # 处理嵌套的 manifest 结构
    if "manifest" in manifest and "metadata" not in manifest:
        manifest = manifest["manifest"]

    if "metadata" not in manifest:
        manifest["metadata"] = {}
    manifest["metadata"]["namespace"] = namespace

    k8s = get_k8s_service()
    return k8s.create_job(namespace, manifest)


@router.delete("/jobs/{job_name}", response_model=SuccessResponse, summary="删除Job")
async def delete_job(
    job_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """删除Job"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    result = k8s.delete_job(namespace, job_name)
    return SuccessResponse(message="Job删除成功", data=result)


@router.post("/jobs/{job_name}/recreate", response_model=JobInfo, summary="删除并重建Job")
async def recreate_job(
    job_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """删除并重建Job（用于重新执行Job）"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)
    k8s = get_k8s_service()
    result = k8s.recreate_job(namespace, job_name)
    return result


# ==================== PVC 管理 ====================


@router.get("/pvcs", response_model=PVCListResponse, summary="获取PVC列表")
async def list_pvcs(
    label_selector: Optional[str] = Query(None, description="标签选择器"),
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取PVC列表"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    pvcs = k8s.list_pvcs(namespace, label_selector)

    return PVCListResponse(total=len(pvcs), items=pvcs)


@router.get("/pvcs/{pvc_name}", response_model=PVCInfo, summary="获取PVC详情")
async def get_pvc(
    pvc_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """获取PVC详情"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    return k8s.get_pvc(namespace, pvc_name)


@router.get("/pvcs/{pvc_name}/usage", summary="检查PVC使用状态")
async def get_pvc_usage(
    pvc_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """检查PVC是否被Pod/Job使用"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)
    k8s = get_k8s_service()
    return k8s.check_pvc_in_use(namespace, pvc_name)


@router.post("/pvcs", response_model=PVCInfo, status_code=status.HTTP_201_CREATED, summary="创建PVC")
async def create_pvc(
    manifest: dict,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """创建PVC"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    if "metadata" not in manifest:
        manifest["metadata"] = {}
    manifest["metadata"]["namespace"] = namespace

    k8s = get_k8s_service()
    return k8s.create_pvc(namespace, manifest)


@router.delete("/pvcs/{pvc_name}", response_model=SuccessResponse, summary="删除PVC")
async def delete_pvc(
    pvc_name: str,
    project_id: str = Query(..., description="项目ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """删除PVC"""
    project_id, namespace = await get_project_and_namespace(project_id, current_user, db)

    k8s = get_k8s_service()
    result = k8s.delete_pvc(namespace, pvc_name)
    return SuccessResponse(message="PVC删除成功", data=result)


# ==================== WebSocket Exec (类似 kubectl exec -it) ====================


class ConnectionManager:
    """WebSocket连接管理器"""

    def __init__(self):
        self.active_connections: dict = {}

    async def connect(self, websocket: WebSocket, client_id: str):
        """接受WebSocket连接"""
        await websocket.accept()
        self.active_connections[client_id] = websocket

    def disconnect(self, client_id: str):
        """断开WebSocket连接"""
        if client_id in self.active_connections:
            del self.active_connections[client_id]

    async def send_message(self, client_id: str, message: str):
        """发送消息到客户端"""
        if client_id in self.active_connections:
            await self.active_connections[client_id].send_text(message)

    async def send_binary(self, client_id: str, data: bytes):
        """发送二进制数据到客户端"""
        if client_id in self.active_connections:
            await self.active_connections[client_id].send_bytes(data)


# WebSocket连接管理器实例
ws_manager = ConnectionManager()


@router.websocket("/ws/pods/{pod_name}/exec")
async def websocket_exec_pod(
    websocket: WebSocket,
    pod_name: str,
    project_id: str = Query(..., description="项目ID"),
    container: Optional[str] = Query(None, description="容器名"),
    command: Optional[str] = Query("/bin/bash", description="执行的命令"),
    token: Optional[str] = Query(None, description="认证Token")
):
    """
    WebSocket Exec - 类似 kubectl exec -it 的能力
    在Pod中执行新命令并进行实时交互

    使用方式:
    - 连接到 WebSocket 后，通过 stdin 发送命令
    - 从 stdout/stderr 接收输出
    - 发送 "exit" 或关闭连接退出

    Kubernetes Exec协议:
    - 每条消息第一个字节标识数据类型:
      0 = stdin, 1 = stdout, 2 = stderr, 3 = error, 4 = resize
    """
    # ========== 添加入口日志 ==========
    logger.info("=" * 50)
    logger.info(f"[TERMINAL] 收到终端连接请求")
    logger.info(f"[TERMINAL] pod_name: {pod_name}")
    logger.info(f"[TERMINAL] project_id: {project_id}")
    logger.info(f"[TERMINAL] container: {container}")
    logger.info(f"[TERMINAL] command: {command}")
    logger.info(f"[TERMINAL] token: {token[:20] + '...' if token and len(token) > 20 else token}")
    logger.info(f"[TERMINAL] client_host: {websocket.client.host if websocket.client else 'unknown'}")
    logger.info("=" * 50)

    # 验证Token
    # if not token:
    #     logger.warning(f"[TERMINAL] 未提供token，拒绝连接")
    #     await websocket.accept()
    #     await websocket.send_text("\x1b[31mError: 未提供认证Token\x1b[0m\r\n")
    #     await websocket.close()
    #     return
    #
    # try:
    #     logger.info(f"[TERMINAL] 开始验证Token...")
    #     auth_service = get_auth_service()
    #     current_user = auth_service.verify_token(token)
    #     if not current_user:
    #         logger.warning(f"[TERMINAL] Token无效或已过期")
    #         await websocket.accept()
    #         await websocket.send_text("\x1b[31mError: Token无效或已过期\x1b[0m\r\n")
    #         await websocket.close()
    #         return
    #     logger.info(f"[TERMINAL] Token验证成功, user: {current_user.get('username')}")
    # except Exception as e:
    #     logger.error(f"[TERMINAL] Token验证失败: {e}", exc_info=True)
    #     await websocket.accept()
    #     await websocket.send_text(f"\x1b[31mError: Token验证失败 - {str(e)}\x1b[0m\r\n")
    #     await websocket.close()
    #     return

    # 生成客户端ID
    client_id = f"exec_{pod_name}_{id(websocket)}"
    logger.info(f"[TERMINAL] client_id: {client_id}")

    # 验证项目权限
    try:
        logger.info(f"[TERMINAL] 开始获取项目namespace, project_id: {project_id}")
        from app.models.database import get_db_session
        db = get_db_session()
        namespace = get_project_namespace(db, project_id)
        db.close()
        logger.info(f"[TERMINAL] 项目namespace: {namespace}")

        if not namespace:
            logger.warning(f"[TERMINAL] 项目不存在, project_id: {project_id}")
            await websocket.accept()
            await websocket.send_text("\x1b[31mError: 项目不存在\x1b[0m\r\n")
            await websocket.close()
            return
    except Exception as e:
        logger.error(f"[TERMINAL] 获取namespace失败: {e}", exc_info=True)
        await websocket.accept()
        await websocket.send_text(f"\x1b[31mError: {str(e)}\x1b[0m\r\n")
        await websocket.close()
        return

    # 如果未指定容器，自动获取第一个容器的名称
    if not container:
        logger.info(f"[TERMINAL] 未指定容器，正在获取Pod容器列表...")
        try:
            k8s = get_k8s_service()
            pod_info = k8s.get_pod(namespace, pod_name)
            containers_list = pod_info.get("containers", [])
            if containers_list and len(containers_list) > 0:
                container = containers_list[0].get("name")
                logger.info(f"[TERMINAL] 自动获取到容器名称: {container}")
            else:
                logger.warning(f"[TERMINAL] Pod没有容器信息")
        except Exception as e:
            logger.error(f"[TERMINAL] 获取容器列表失败: {e}")

    # 如果仍然没有容器名称，记录警告但继续尝试
    if not container:
        logger.warning(f"[TERMINAL] 未能获取容器名称，将使用默认方式")

    # 尝试多种shell命令
    shell_commands = [
        command.split() if isinstance(command, str) else [command],
        ["/bin/bash"],
        ["/bin/sh"],
        ["/usr/bin/bash"],
        ["/usr/bin/sh"]
    ]

    exec_stream = None
    last_error = None

    logger.info(f"[TERMINAL] 开始创建exec流, namespace: {namespace}, pod: {pod_name}, cmd: {command}")

    for cmd in shell_commands:
        try:
            logger.info(f"[TERMINAL] 尝试使用命令: {cmd}")
            k8s = get_k8s_service()
            exec_stream = k8s.exec_pod_stream(
                namespace=namespace,
                pod_name=pod_name,
                command=cmd,
                container=container,
                stdin=True,
                stdout=True,
                stderr=True,
                tty=True
            )
            logger.info(f"[TERMINAL] 使用shell命令成功: {cmd}")
            break
        except Exception as e:
            last_error = e
            logger.warning(f"[TERMINAL] 尝试命令 {cmd} 失败: {e}")
            continue

    if exec_stream is None:
        logger.error(f"[TERMINAL] 创建exec流失败: {last_error}")
        await websocket.accept()
        await websocket.send_text(f"\x1b[31mError: 无法创建终端连接 - {str(last_error)}\x1b[0m\r\n")
        await websocket.close()
        return

    logger.info(f"[TERMINAL] 准备接受WebSocket连接")
    # 接受连接
    await ws_manager.connect(websocket, client_id)
    logger.info(f"[TERMINAL] WebSocket连接已接受")

    # 获取当前事件循环
    loop = asyncio.get_event_loop()

    # 用于标识连接是否活跃
    active = True

    # 存储终端大小
    terminal_size = {"rows": 24, "cols": 80}

    def parse_k8s_message(data: bytes) -> tuple:
        """
        解析Kubernetes Exec协议消息
        返回: (stream_type, content)
        stream_type: 0=stdin, 1=stdout, 2=stderr, 3=error
        """
        if not data or len(data) < 1:
            return None, None

        stream_type = data[0]
        content = data[1:] if len(data) > 1 else b""
        return stream_type, content

    def read_output_thread():
        """后台线程读取exec输出，使用线程安全的方式发送到WebSocket"""
        nonlocal active
        try:
            while active:
                try:
                    msg = exec_stream.recv()
                    if not msg:
                        break

                    # 解析Kubernetes协议头
                    stream_type, content = parse_k8s_message(msg)
                    if content is None:
                        continue

                    # 只处理stdout(1)和stderr(2)
                    if stream_type in (1, 2):
                        try:
                            decoded = content.decode('utf-8', errors='replace')
                            # 使用线程安全的方式调度协程
                            future = asyncio.run_coroutine_threadsafe(
                                ws_manager.send_message(client_id, decoded),
                                loop
                            )
                            # 等待发送完成（最多1秒）
                            future.result(timeout=1.0)
                        except Exception as e:
                            logger.debug(f"发送消息失败: {e}")
                    elif stream_type == 3:
                        # 错误消息
                        try:
                            error_msg = content.decode('utf-8', errors='replace')
                            future = asyncio.run_coroutine_threadsafe(
                                ws_manager.send_message(client_id, f"\x1b[31m{error_msg}\x1b[0m\r\n"),
                                loop
                            )
                            future.result(timeout=1.0)
                        except:
                            pass

                except Exception as e:
                    err_str = str(e).lower()
                    if "closed" in err_str or "timeout" in err_str or "eof" in err_str:
                        break
                    logger.debug(f"读取输出异常: {e}")
                    continue
        except Exception as e:
            logger.error(f"读取输出线程异常: {e}")
        finally:
            active = False

    # 启动输出读取线程
    reader_thread = threading.Thread(target=read_output_thread, daemon=True)
    reader_thread.start()

    try:
        # 循环处理客户端输入
        logger.info(f"[TERMINAL] 开始主循环，等待客户端消息")
        while active:
            try:
                # 等待客户端消息
                logger.debug(f"[TERMINAL] 等待客户端消息...")
                message = await asyncio.wait_for(
                    websocket.receive(),
                    timeout=60.0
                )
                logger.debug(f"[TERMINAL] 收到消息: {list(message.keys())}")

                # 处理不同类型的消息
                if "text" in message:
                    data = message["text"]
                    logger.debug(f"[TERMINAL] 收到文本消息长度: {len(data)}")

                    # 处理resize消息（JSON格式）
                    if data.startswith('{"resize":'):
                        logger.info(f"[TERMINAL] 收到resize消息")
                        try:
                            import json
                            resize_data = json.loads(data)
                            if "resize" in resize_data:
                                terminal_size["rows"] = resize_data["resize"].get("rows", 24)
                                terminal_size["cols"] = resize_data["resize"].get("cols", 80)
                                logger.info(f"[TERMINAL] Resize终端: rows={terminal_size['rows']}, cols={terminal_size['cols']}")
                                # 尝试resize终端
                                try:
                                    k8s.resize_pod_exec(
                                        namespace=namespace,
                                        pod_name=pod_name,
                                        container=container,
                                        rows=terminal_size["rows"],
                                        cols=terminal_size["cols"]
                                    )
                                except Exception as e:
                                    logger.warning(f"[TERMINAL] Resize终端失败: {e}")
                        except json.JSONDecodeError:
                            pass
                        continue

                    # 发送用户输入到exec流（不自动添加换行，支持原始输入）
                    try:
                        exec_stream.write_stdin(data)
                    except Exception as e:
                        logger.error(f"发送stdin失败: {e}")
                        break

                elif "bytes" in message:
                    # 二进制数据直接发送
                    try:
                        exec_stream.write_stdin(message["bytes"])
                    except Exception as e:
                        logger.error(f"发送二进制stdin失败: {e}")
                        break

            except asyncio.TimeoutError:
                # 超时，继续等待
                continue
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"接收消息异常: {e}")
                break

    except Exception as e:
        logger.error(f"[TERMINAL] WebSocket异常: {e}", exc_info=True)
    finally:
        # 清理资源
        logger.info(f"[TERMINAL] 开始清理资源, client_id: {client_id}")
        active = False
        try:
            exec_stream.close()
            logger.info(f"[TERMINAL] exec_stream已关闭")
        except Exception as e:
            logger.warning(f"[TERMINAL] 关闭exec_stream失败: {e}")

        ws_manager.disconnect(client_id)
        logger.info(f"[TERMINAL] Exec连接已关闭: {client_id}")


@router.websocket("/ws/pods/{pod_name}/attach")
async def websocket_attach_pod(
    websocket: WebSocket,
    pod_name: str,
    project_id: str = Query(..., description="项目ID"),
    container: Optional[str] = Query(None, description="容器名")
):
    """
    WebSocket Attach - 类似 kubectl attach 的能力
    附加到运行中的容器并进行实时交互

    使用方式:
    - 连接到 WebSocket 后可以直接与容器交互
    - 发送 exit 退出
    """
    # 生成客户端ID
    client_id = f"attach_{pod_name}_{id(websocket)}"

    # 验证项目权限
    try:
        from app.models.database import get_db_session
        db = get_db_session()
        namespace = get_project_namespace(db, project_id)
        db.close()

        if not namespace:
            await websocket.send_text("Error: 项目不存在")
            await websocket.close()
            return
    except Exception as e:
        logger.error(f"获取namespace失败: {e}")
        await websocket.send_text(f"Error: {str(e)}")
        await websocket.close()
        return

    # 获取K8S服务并创建attach流
    try:
        k8s = get_k8s_service()
        attach_stream = k8s.attach_pod_stream(
            namespace=namespace,
            pod_name=pod_name,
            container=container,
            stdin=True,
            stdout=True,
            stderr=False,
            tty=True
        )
    except Exception as e:
        logger.error(f"创建attach流失败: {e}")
        await websocket.send_text(f"Error: 创建attach失败 - {str(e)}")
        await websocket.close()
        return

    # 接受连接
    await ws_manager.connect(websocket, client_id)

    active = True

    def read_output_thread():
        """后台线程读取attach输出"""
        nonlocal active
        try:
            while active:
                try:
                    msg = attach_stream.recv()
                    if msg:
                        asyncio.run(ws_manager.send_message(client_id, msg))
                    else:
                        break
                except Exception as e:
                    if "closed" in str(e).lower() or "timeout" in str(e).lower():
                        break
                    logger.debug(f"读取输出异常: {e}")
                    continue
        except Exception as e:
            logger.error(f"读取输出线程异常: {e}")

    # 启动输出读取线程
    reader_thread = threading.Thread(target=read_output_thread, daemon=True)
    reader_thread.start()

    try:
        while active:
            try:
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=60.0
                )

                if data == "exit" or data == "quit":
                    active = False
                    break

                try:
                    attach_stream.send_stdin(data + "\n")
                except Exception as e:
                    logger.error(f"发送stdin失败: {e}")
                    await websocket.send_text(f"Error: 发送失败 - {str(e)}")
                    break

            except asyncio.TimeoutError:
                continue
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"接收消息异常: {e}")
                break

    except Exception as e:
        logger.error(f"WebSocket异常: {e}")
    finally:
        active = False
        try:
            attach_stream.close()
        except:
            pass

        ws_manager.disconnect(client_id)
        logger.info(f"Attach连接关闭: {client_id}")
