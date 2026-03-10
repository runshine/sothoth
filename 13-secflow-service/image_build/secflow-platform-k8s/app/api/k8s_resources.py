"""
K8S资源管理API路由
提供对Kubernetes资源的增删查改接口
"""

import asyncio
import logging
import threading
from typing import Optional

from fastapi import APIRouter, Depends, Header, Query, status, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.config import get_config
from app.exception import NotFoundError, ForbiddenError, ValidationError
from app.models.database import get_project_namespace, get_project_by_id, get_db
from app.services.auth import get_auth_service
from app.services.k8s import get_k8s_service
from app.schemas import (
    ErrorResponse,
    SuccessResponse,
    PodListResponse,
    PodInfo,
    PodLogResponse,
    ServiceListResponse,
    ServiceInfo,
    ServiceCreateRequest,
    ServiceUpdateRequest,
    IngressListResponse,
    IngressInfo,
    IngressCreateRequest,
    IngressUpdateRequest,
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


# ==================== Secret 管理 ====================


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
    command: Optional[str] = Query("/bin/sh", description="执行的命令"),
    token: Optional[str] = Query(None, description="认证Token")
):
    """
    WebSocket Exec - 类似 kubectl exec -it 的能力
    在Pod中执行新命令并进行实时交互

    使用方式:
    - 连接到 WebSocket 后，通过 stdin 发送命令
    - 从 stdout/stderr 接收输出
    - 发送 "exit" 或关闭连接退出
    """
    # 验证Token
    if not token:
        await websocket.accept()
        await websocket.send_text("Error: 未提供认证Token")
        await websocket.close()
        return
    
    try:
        auth_service = get_auth_service()
        current_user = auth_service.verify_token(token)
        if not current_user:
            await websocket.accept()
            await websocket.send_text("Error: Token无效或已过期")
            await websocket.close()
            return
    except Exception as e:
        logger.error(f"Token验证失败: {e}")
        await websocket.accept()
        await websocket.send_text(f"Error: Token验证失败 - {str(e)}")
        await websocket.close()
        return
    
    # 生成客户端ID
    client_id = f"exec_{pod_name}_{id(websocket)}"

    # 验证项目权限
    try:
        # 获取namespace
        from app.models.database import get_db_session
        db = get_db_session()
        namespace = get_project_namespace(db, project_id)
        db.close()

        if not namespace:
            await websocket.accept()
            await websocket.send_text("Error: 项目不存在")
            await websocket.close()
            return
    except Exception as e:
        logger.error(f"获取namespace失败: {e}")
        await websocket.accept()
        await websocket.send_text(f"Error: {str(e)}")
        await websocket.close()
        return

    # 获取K8S服务并创建exec流
    try:
        k8s = get_k8s_service()
        exec_stream = k8s.exec_pod_stream(
            namespace=namespace,
            pod_name=pod_name,
            command=command.split() if isinstance(command, str) else [command],
            container=container,
            stdin=True,
            stdout=True,
            stderr=True,
            tty=True
        )
    except Exception as e:
        logger.error(f"创建exec流失败: {e}")
        await websocket.send_text(f"Error: 创建exec失败 - {str(e)}")
        await websocket.close()
        return

    # 接受连接
    await ws_manager.connect(websocket, client_id)

    # 用于标识连接是否活跃
    active = True

    def read_output_thread():
        """后台线程读取exec输出"""
        nonlocal active
        try:
            while active:
                try:
                    # 读取stdout
                    msg = exec_stream.recv()
                    if msg:
                        asyncio.run(ws_manager.send_message(client_id, msg))
                    else:
                        break
                except Exception as e:
                    # 可能连接已关闭
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
        # 循环处理客户端输入
        while active:
            try:
                # 等待客户端消息（使用超时以便检查连接状态）
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=60.0
                )

                if data == "exit" or data == "quit":
                    # 发送exit命令到容器
                    try:
                        exec_stream.send_stdin("exit\n")
                    except:
                        pass
                    active = False
                    break

                # 发送用户输入到exec流
                try:
                    exec_stream.send_stdin(data + "\n")
                except Exception as e:
                    logger.error(f"发送stdin失败: {e}")
                    await websocket.send_text(f"Error: 发送命令失败 - {str(e)}")
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
        logger.error(f"WebSocket异常: {e}")
    finally:
        # 清理资源
        active = False
        try:
            exec_stream.close()
        except:
            pass

        ws_manager.disconnect(client_id)
        logger.info(f"Exec连接关闭: {client_id}")


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