"""
Workflow instance API routes
Manages workflow execution including creation, running, stopping, deletion, and log retrieval
"""
import asyncio
import logging
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import func, or_

from app.api.dependencies import get_current_user, generate_id
from app.models import (
    get_db, WorkflowInstance, WorkflowNodeInstance,
    WorkflowStatus, NodeStatus, NodeType, AppTemplate, JobTemplate,
    WorkflowSyncRecord, WorkflowNodeDomainBinding, TemplateScope
)
from app.schemas import (
    WorkflowSyncRecordResponse, WorkflowSyncRecordListResponse,
    WorkflowInstanceCreate, WorkflowInstanceUpdate,
    WorkflowInstanceResponse, WorkflowInstanceListResponse,
    WorkflowNodeCreate, WorkflowNodeUpdate, WorkflowNodeInstanceResponse,
    WorkflowEdgesUpdateRequest, WorkflowInstanceInitializeRequest,
    LogQueryRequest, PodLogResponse, SuccessResponse,
    WorkflowInstanceNodeLogEntry, WorkflowInstanceNodeLogListResponse,
    NodeStatusCallbackRequest, NodeStatusCallbackResponse,
    WorkflowNodeIngressBindingRequest, WorkflowNodeDomainBindingResponse,
)
from app.exception import NotFoundError, ForbiddenError, ValidationError, InternalError
from app.services import WorkflowEngine
from app.services.fileserver_client import FileserverClientError, get_fileserver_client
from app.services.workflow_status_client import get_workflow_status_client
from app.config import get_config

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/workflow-instances", tags=["Workflow Instances"])


def get_status_client():
    """Get workflow-status client, fail fast when disabled."""
    config = get_config()
    if not config.workflow_status_service or not config.workflow_status_service.enabled:
        raise InternalError("workflow-status service is required but disabled")
    return get_workflow_status_client()


def _dump_items(items: Optional[List[Any]]) -> List[Dict[str, Any]]:
    dumped: List[Dict[str, Any]] = []
    for item in items or []:
        if hasattr(item, "model_dump"):
            dumped.append(item.model_dump())
        elif hasattr(item, "dict"):
            dumped.append(item.dict())
        else:
            dumped.append(dict(item))
    return dumped


async def resolve_project_file_mounts(
    project_id: str,
    project_file_mounts: Optional[List[Any]],
    token: Optional[str],
) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    if not project_file_mounts:
        return [], []

    config = get_config()
    if not config.fileserver_service.enabled:
        raise InternalError("fileserver service is required but disabled")
    if not token:
        raise ValidationError("Missing user token for project file mount resolution")

    fileserver_client = get_fileserver_client()
    try:
        storage_info = await fileserver_client.get_storage_pvc(token)
    except FileserverClientError as exc:
        raise ValidationError(f"无法获取项目文件存储PVC: {exc}") from exc

    pvc_name = storage_info.get("pvc_name")
    if not pvc_name:
        raise InternalError("fileserver storage pvc_name is empty")

    resolved_mounts: List[Dict[str, Any]] = []
    normalized_mounts: List[Dict[str, Any]] = []

    for raw_mount in project_file_mounts:
        mount = raw_mount.model_dump() if hasattr(raw_mount, "model_dump") else (
            raw_mount.dict() if hasattr(raw_mount, "dict") else dict(raw_mount)
        )
        subproject_id = mount.get("subproject_id")
        directory_id = mount.get("directory_id")
        mount_path = (mount.get("mount_path") or "").strip()
        read_only = bool(mount.get("read_only", True))

        if not subproject_id:
            raise ValidationError("project_file_mounts.subproject_id is required")
        if not mount_path:
            raise ValidationError("project_file_mounts.mount_path is required")

        try:
            if directory_id is not None:
                current = await fileserver_client.get_directory_children(project_id, int(directory_id), token)
                if int(current.get("subproject_id")) != int(subproject_id):
                    raise ValidationError(f"目录 {directory_id} 不属于子项目 {subproject_id}")
                relative_path = (current.get("current_path") or "/").strip("/")
                subproject_name = None
                for crumb in current.get("breadcrumbs") or []:
                    if crumb.get("node_type") == "subproject":
                        subproject_name = crumb.get("name")
                        break
                normalized_mounts.append({
                    "subproject_id": int(subproject_id),
                    "directory_id": int(directory_id),
                    "mount_path": mount_path,
                    "read_only": read_only,
                    "display_path": current.get("current_path") or "/",
                    "subproject_name": subproject_name,
                    "directory_name": current.get("current_name"),
                })
            else:
                current = await fileserver_client.get_subproject_children(project_id, int(subproject_id), token)
                relative_path = ""
                normalized_mounts.append({
                    "subproject_id": int(subproject_id),
                    "directory_id": None,
                    "mount_path": mount_path,
                    "read_only": read_only,
                    "display_path": "/",
                    "subproject_name": current.get("current_name"),
                    "directory_name": None,
                })
        except FileserverClientError as exc:
            raise ValidationError(f"项目文件目录校验失败: {exc}") from exc

        sub_path = f"files/{project_id}/{int(subproject_id)}"
        if relative_path:
            sub_path = f"{sub_path}/{relative_path}"

        resolved_mounts.append({
            "pvc_name": pvc_name,
            "mount_path": mount_path,
            "sub_path": sub_path,
            "read_only": read_only,
        })

    return resolved_mounts, normalized_mounts


async def resolve_requested_volume_mounts(
    project_id: str,
    volume_mounts: Optional[List[Any]],
    project_file_mounts: Optional[List[Any]],
    token: Optional[str],
) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    raw_volume_mounts = _dump_items(volume_mounts)
    resolved_project_mounts, normalized_project_mounts = await resolve_project_file_mounts(
        project_id,
        project_file_mounts,
        token,
    )

    combined_mounts = list(raw_volume_mounts)
    combined_mounts.extend(resolved_project_mounts)

    seen_mount_paths: set[str] = set()
    for mount in combined_mounts:
        mount_path = (mount.get("mount_path") or "").strip()
        if not mount_path:
            raise ValidationError("volume mount mount_path cannot be empty")
        if mount_path in seen_mount_paths:
            raise ValidationError(f"Duplicate mount_path detected: {mount_path}")
        seen_mount_paths.add(mount_path)

    return combined_mounts, raw_volume_mounts, normalized_project_mounts


async def ensure_project_namespace(project_id: str):
    """Ensure project namespace by workflow-status service."""
    result = await get_status_client().ensure_namespace(project_id)
    if not result.get("success"):
        raise InternalError(f"Namespace verification failed: {result.get('message', 'unknown error')}")


def build_lifecycle_nodes(nodes: List[WorkflowNodeInstance], instance: Optional[WorkflowInstance] = None) -> List[Dict[str, Any]]:
    """Build nodes payload for workflow lifecycle APIs."""
    payload: List[Dict[str, Any]] = []
    for node in nodes:
        if not node.k8s_resource_name:
            continue
        node_config = get_instance_node_config(instance, node.id) if instance else {}
        payload.append({
            "node_id": node.node_id,
            "node_type": node.node_type.value if hasattr(node.node_type, "value") else str(node.node_type),
            "k8s_resource_name": node.k8s_resource_name,
            "k8s_resource_type": node.k8s_resource_type,
            "service_name": resolve_runtime_service_name(node, node_config),
            "has_ingress": bool(node.ingress_type),
            "ingress_name": resolve_node_ingress_name(node, node_config),
        })
    return payload


def get_instance_node_config(instance: WorkflowInstance, node_id: str) -> Dict[str, Any]:
    """Get stored node config from instance.nodes."""
    for node_config in (instance.nodes or []):
        if node_config.get("id") == node_id or node_config.get("node_id") == node_id:
            return node_config
    return {}


def build_node_response(node: WorkflowNodeInstance, instance: WorkflowInstance) -> Dict[str, Any]:
    """Build node response merged with stored node config."""
    node_config = get_instance_node_config(instance, node.id)
    node_type_value = node.node_type.value if hasattr(node.node_type, "value") else str(node.node_type)
    create_service = node_config.get("create_service")
    if create_service is None:
        create_service = bool(node.service_name) if node_type_value == "app" else False

    service_name = node_config.get("service_name") or node.service_name
    ingress_type = node_config.get("ingress_type") or node.ingress_type
    ingress_host = node_config.get("ingress_host") or node.ingress_host
    ingress_ip = node_config.get("ingress_ip") or node.ingress_ip
    ingress_name = resolve_node_ingress_name(node, node_config)
    create_ingress = node_config.get("create_ingress")
    if create_ingress is None:
        create_ingress = bool(ingress_type or ingress_host or ingress_ip)

    return {
        "id": node.id,
        "node_id": node.node_id,
        "node_type": node_type_value,
        "template_id": node.template_id,
        "name": node.name,
        "status": node.status,
        "k8s_resource_name": node.k8s_resource_name,
        "k8s_resource_type": node.k8s_resource_type,
        "depends_on": node.depends_on or [],
        "downstream_node_ids": node.downstream_node_ids or [],
        "service_name": service_name,
        "timeout_seconds": node.timeout_seconds,
        "started_at": node.started_at.isoformat() if node.started_at else None,
        "finished_at": node.finished_at.isoformat() if node.finished_at else None,
        "message": node.message,
        "init_logs": node.init_logs,
        "position": node.position or {"x": 0.0, "y": 0.0},
        "env_vars": node.env_vars or [],
        "volume_mounts": node_config.get("volume_mounts", node.volume_mounts or []),
        "project_file_mounts": node_config.get("project_file_mounts", []),
        "resources": node.resources,
        "input_env_vars": node.input_env_vars or [],
        "input_volume_mounts": node.input_volume_mounts or [],
        "create_service": create_service,
        "service_ports": node_config.get("service_ports", []),
        "service_type": node_config.get("service_type"),
        "create_ingress": create_ingress,
        "ingress_type": ingress_type,
        "ingress_host": ingress_host,
        "ingress_ip": ingress_ip,
        "ingress_name": ingress_name,
        "ingress_access_url": node_config.get("ingress_access_url"),
        "ingress_tls_enabled": node_config.get("ingress_tls_enabled"),
        "created_at": node.created_at.isoformat() if node.created_at else None,
    }


def get_primary_service_ports(node_config: Dict[str, Any]) -> tuple[Optional[int], Optional[int]]:
    """Extract the first service port and target port from stored node config."""
    service_ports = node_config.get("service_ports") or []
    if not service_ports:
        return None, None

    first_port = service_ports[0] or {}
    service_port = first_port.get("port")
    target_port = first_port.get("target_port", first_port.get("targetPort", service_port))
    return service_port, target_port


def build_workflow_deployment_name(instance_id: str, node_identifier: str) -> str:
    """Build a stable Deployment name for one workflow node."""
    return f"wf-{instance_id[:8]}-{node_identifier[:8]}"


def build_workflow_service_resource_name(deployment_name: str) -> str:
    """Build the actual K8S Service name from the workflow Deployment name."""
    return f"{deployment_name}-svc"


def build_workflow_ingress_resource_name(service_name: str) -> str:
    """Build the actual K8S Ingress name from the workflow Service name."""
    return f"ing-{service_name}"


def resolve_runtime_service_name(
    node: WorkflowNodeInstance,
    node_config: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """Resolve the actual K8S Service resource name for one node."""
    node_config = node_config or {}
    if node.service_name:
        return node.service_name

    configured_name = node_config.get("k8s_service_name")
    if configured_name:
        return configured_name

    create_service = node_config.get("create_service")
    if create_service is None:
        create_service = node.node_type == NodeType.APP

    if create_service and node.k8s_resource_name:
        return build_workflow_service_resource_name(node.k8s_resource_name)

    return None


def build_workflow_ingress_host_prefix(node_config: Dict[str, Any], service_name: Optional[str]) -> Optional[str]:
    """Build the default workflow ingress host prefix."""
    if node_config.get("ingress_host_prefix"):
        return node_config.get("ingress_host_prefix")
    return None


def resolve_node_ingress_name(node: WorkflowNodeInstance, node_config: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """Resolve the stored ingress name with backward-compatible fallback."""
    node_config = node_config or {}
    ingress_name = node_config.get("ingress_name")
    if ingress_name:
        return ingress_name

    create_ingress = node_config.get("create_ingress")
    if create_ingress is None:
        create_ingress = bool(node.ingress_type or node.ingress_host or node.ingress_ip)

    service_name = resolve_runtime_service_name(node, node_config)
    if service_name and create_ingress:
        return build_workflow_ingress_resource_name(service_name)
    return None


def resolve_ingress_access_url(node_config: Dict[str, Any], host: Optional[str], path: str = "/") -> Optional[str]:
    """Build a fallback ingress access URL from stored config."""
    if node_config.get("ingress_access_url"):
        return node_config.get("ingress_access_url")
    if not host:
        return None
    scheme = "https" if node_config.get("ingress_tls_enabled") else "http"
    normalized_path = path if str(path).startswith("/") else f"/{path}"
    return f"{scheme}://{host}{normalized_path}"


def upsert_node_domain_binding(
    db: Session,
    instance: WorkflowInstance,
    node: WorkflowNodeInstance,
    *,
    domain: str,
    ingress_ip: Optional[str],
    ingress_type: Optional[str],
    service_name: Optional[str],
    service_port: Optional[int],
    target_port: Optional[int],
    binding_status: str,
    ingress_name: Optional[str] = None,
    message: Optional[str] = None,
):
    """Create or update one node domain binding record."""
    if not domain:
        return None

    binding = db.query(WorkflowNodeDomainBinding).filter(
        WorkflowNodeDomainBinding.instance_id == instance.id,
        WorkflowNodeDomainBinding.node_instance_id == node.id,
        WorkflowNodeDomainBinding.domain == domain,
    ).first()

    if not binding:
        binding = WorkflowNodeDomainBinding(
            id=generate_id(f"{instance.id}-{node.id}-{domain}"),
            instance_id=instance.id,
            node_instance_id=node.id,
            node_id=node.node_id,
            project_id=instance.project_id,
            domain=domain,
        )
        db.add(binding)

    binding.service_name = service_name
    binding.ingress_name = ingress_name or (
        build_workflow_ingress_resource_name(service_name) if service_name else None
    )
    binding.ingress_type = ingress_type
    binding.ingress_ip = ingress_ip
    binding.service_port = service_port
    binding.target_port = target_port
    binding.binding_status = binding_status
    binding.message = message
    return binding


def delete_node_domain_bindings(db: Session, instance_id: str, node_instance_id: str):
    """Delete all domain binding records for one node."""
    db.query(WorkflowNodeDomainBinding).filter(
        WorkflowNodeDomainBinding.instance_id == instance_id,
        WorkflowNodeDomainBinding.node_instance_id == node_instance_id,
    ).delete()


# ============ Ingress Controller 处理接口 ============


@router.get("/ingress-controllers", summary="获取可用的Ingress Controller列表")
async def get_ingress_controllers(
    current_user: dict = Depends(get_current_user)
):
    """
    获取集群中可用的Ingress Controller列表

    处理调用k8s服务端接口，返回Ingress Controller的名称、外网IP、端口等信息。
    供前端在创建节点时选择Ingress配置使用。
    """
    status_client = get_status_client()
    controllers = await status_client.get_ingress_controllers()
    return {"total": len(controllers), "items": controllers}


@router.get("/ingress-nginx-ips", summary="获取 Nginx Ingress 可选 IP 列表")
async def get_nginx_ingress_ips(
    current_user: dict = Depends(get_current_user)
):
    """获取 Nginx 类型 Ingress Controller 及其可选外部 IP。"""
    controllers = await get_status_client().get_ingress_controllers()
    nginx_items = [
        item for item in controllers
        if (item.get("ingress_class") == "nginx") or ("nginx" in (item.get("name") or "").lower())
    ]
    return {"total": len(nginx_items), "items": nginx_items}


@router.get("/statistics", summary="获取工作流统计信息")
async def get_workflow_statistics(
    project_id: Optional[str] = Query(None, description="项目ID，不传则统计所有条目"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    获取工作流实例统计信息

    返回:
    - total_instances: 工作流实例总数
    - status_distribution: 各状态实例数量分布
    - templates: 模板统计（应用模板数、任务模板数）
    """
    # 构建基础查询
    base_query = db.query(WorkflowInstance)
    if project_id:
        base_query = base_query.filter(WorkflowInstance.project_id == project_id)

    # 总实例数
    total_instances = base_query.count()

    # 状态分布
    status_distribution = {}
    status_list = [
        WorkflowStatus.PENDING,
        WorkflowStatus.UNREADY,
        WorkflowStatus.READY,
    ]
    for status in status_list:
        count = db.query(func.count(WorkflowInstance.id)).filter(
            WorkflowInstance.status == status
        ).scalar() or 0
        status_distribution[status] = count

    # 模板统计
    app_template_query = db.query(AppTemplate)
    job_template_query = db.query(JobTemplate)
    if project_id:
        app_template_query = app_template_query.filter(
            (AppTemplate.project_id == project_id) | (AppTemplate.scope == TemplateScope.GLOBAL)
        )
        job_template_query = job_template_query.filter(
            (JobTemplate.project_id == project_id) | (JobTemplate.scope == TemplateScope.GLOBAL)
        )

    app_templates = app_template_query.count()
    job_templates = job_template_query.count()

    return {
        "total_instances": total_instances,
        "status_distribution": status_distribution,
        "templates": {
            "app_templates": app_templates,
            "job_templates": job_templates
        }
    }


# ============ 初始化工作流 API ============


@router.post("/{instance_id}/initialize", response_model=WorkflowInstanceResponse)
async def initialize_workflow_instance(
    instance_id: str,
    request: WorkflowInstanceInitializeRequest = WorkflowInstanceInitializeRequest(),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    初始化工作流实例

    对于不同类型的节点，初始化逻辑不同：

    JOB类型节点：
    - 直接上报初始化成功
    - 不创建任何K8S资源（Job在start时创建并执行）

    APP类型节点：
    - 必须在模板中定义Service（create_service=True 且 service_ports不为空）
    - 必须在模板中定义service_name（用于创建Service）
    - 创建对应的Deployment
    - 使用模板中定义的service_name创建Service（不能使用自动生成的名称）
    - 如果模板未定义Service或Service创建失败，则上报初始化失败

    注意:
    - 初始化成功后状态变为INITIALIZED
    - 创建完成后可通过start API启动工作流

    强制初始化(force=True):
    - 如果工作流已经初始化过（状态为INITIALIZED或STOPPED），会先删除已存在的K8S资源
    - 然后重新创建Deployment和Service
    - 用于重新初始化场景

    前置条件:
    - 状态为 PENDING: 正常初始化
    - 状态为 INITIALIZED/STOPPED 且 force=True: 强制重新初始化
    """
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to initialize this instance")

    # 检查状态和强制初始化参数
    # 新状态体系：pending/unready/ready
    force = request.force

    # 检查是否需要强制初始化
    if instance.status not in [WorkflowStatus.PENDING, WorkflowStatus.UNREADY, WorkflowStatus.READY]:
        raise ValidationError(f"Cannot initialize instance in status: {instance.status}")

    if instance.status in [WorkflowStatus.UNREADY, WorkflowStatus.READY] and not force:
        raise ValidationError(
            f"Workflow instance already initialized. Use force=True to re-initialize (this will delete existing resources)"
        )

    status_client = get_status_client()
    await ensure_project_namespace(instance.project_id)

    # 设置状态为unready（初始化中：已开始初始化但未完全就绪）
    instance.status = WorkflowStatus.UNREADY
    instance.message = "Initializing workflow instance..."
    db.commit()

    # 初始化日志收集器
    from datetime import datetime
    init_logs = []
    init_logs.append(f"[{datetime.utcnow().isoformat()}] 开始初始化工作流实例 {instance_id}")
    init_logs.append(f"项目ID: {instance.project_id}")
    init_logs.append(f"强制初始化: {force}")

    # 获取所有节点
    nodes = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.instance_id == instance_id
    ).all()

    if not nodes:
        instance.status = WorkflowStatus.PENDING
        instance.message = "Workflow instance has no nodes to initialize"
        init_logs.append(f"[{datetime.utcnow().isoformat()}] 错误: 工作流没有节点")
        instance.init_logs = "\n".join(init_logs)
        db.commit()
        raise ValidationError("Workflow instance has no nodes to initialize")

    init_logs.append(f"节点总数: {len(nodes)}")

    # 如果强制初始化，先通过 workflow-status 服务删除已有资源
    if force and instance.status in [WorkflowStatus.UNREADY, WorkflowStatus.READY]:
        init_logs.append(f"[{datetime.utcnow().isoformat()}] 强制初始化: 删除已存在的K8S资源")
        logger.info(f"Force initialization cleanup via workflow-status: instance={instance_id}")
        existing_nodes = build_lifecycle_nodes(nodes, instance)
        if existing_nodes:
            cleanup_result = await status_client.deinitialize_workflow(
                instance_id=instance_id,
                project_id=instance.project_id,
                nodes=existing_nodes,
            )
            if not cleanup_result.get("success", False):
                raise InternalError(
                    f"Force cleanup failed: {cleanup_result.get('message') or cleanup_result.get('error', 'unknown error')}"
                )

        for node in nodes:
            node.k8s_resource_name = None
            node.k8s_resource_type = None
            node.service_name = None
            node.ingress_type = None
            node.ingress_host = None
            node.ingress_ip = None
            node.status = NodeStatus.PENDING
            node.message = None
            node_config = get_instance_node_config(instance, node.id)
            node_config["k8s_service_name"] = None
            node_config["ingress_name"] = None
            node_config["ingress_access_url"] = None
            node_config["ingress_tls_enabled"] = None
        db.commit()

    initialized_nodes = []
    errors = []

    # 构建节点配置列表（用于调用workflow-status 服务）
    nodes_info = []
    nodes_to_process = []  # 保存需要处理的节点对象

    for node in nodes:
        # 处理JOB类型节点
        if node.node_type == NodeType.JOB:
            nodes_info.append({
                "node_id": node.node_id,
                "node_type": "job",
                "node_name": node.name,
            })
            nodes_to_process.append(node)
            continue

        # 处理APP类型节点
        # 跳过已经有K8S资源的节点（非强制初始化时）
        if not force and node.k8s_resource_name:
            logger.info(f"Skipping node {node.id}, already has resource {node.k8s_resource_name}")
            initialized_nodes.append(node.id)
            continue

        try:
            # 获取应用模板
            template = db.query(AppTemplate).filter(AppTemplate.id == node.template_id).first()
            if not template:
                error_msg = f"App template {node.template_id} not found for node {node.id}"
                errors.append(error_msg)
                init_logs.append(f"[{datetime.utcnow().isoformat()}] 错误: {error_msg}")
                node.status = NodeStatus.FAILED
                node.message = error_msg
                continue

            # 从节点配置中获取服务相关参数
            node_config = None
            for n in instance.nodes:
                if n.get("id") == node.node_id or n.get("node_id") == node.node_id:
                    node_config = n
                    break

            if not node_config:
                error_msg = f"Node configuration not found for node {node.id}"
                errors.append(error_msg)
                init_logs.append(f"[{datetime.utcnow().isoformat()}] 错误: {error_msg}")
                node.status = NodeStatus.FAILED
                node.message = error_msg
                continue

            # 检查是否创建Service
            create_service = node_config.get("create_service", True)
            display_service_name = None
            service_ports = []

            if create_service:
                display_service_name = node_config.get("service_name")
                if not display_service_name or not display_service_name.strip():
                    error_msg = f"Service display name is required when create_service is True for node {node.id}"
                    errors.append(error_msg)
                    init_logs.append(f"[{datetime.utcnow().isoformat()}] 错误: {error_msg}")
                    node.status = NodeStatus.FAILED
                    node.message = error_msg
                    continue

                service_ports = node_config.get("service_ports", [])
                if not service_ports or len(service_ports) == 0:
                    error_msg = f"Service ports cannot be empty when create_service is True for node {node.id}"
                    errors.append(error_msg)
                    init_logs.append(f"[{datetime.utcnow().isoformat()}] 错误: {error_msg}")
                    node.status = NodeStatus.FAILED
                    node.message = error_msg
                    continue

            # 构建容器配置
            containers = _build_containers_from_template(template, node)

            # 生成Deployment名称
            deployment_name = build_workflow_deployment_name(instance_id, node.node_id)
            runtime_service_name = (
                build_workflow_service_resource_name(deployment_name)
                if create_service else None
            )
            node_config["k8s_service_name"] = runtime_service_name

            # 转换端口格式
            k8s_service_ports = []
            for p in service_ports:
                port_config = {
                    "name": p.get("name", f"port-{p.get('port')}"),
                    "port": p.get("port"),
                    "targetPort": p.get("target_port", p.get("port")),
                    "protocol": p.get("protocol", "TCP")
                }
                k8s_service_ports.append(port_config)

            # 获取service_type
            service_type = node_config.get("service_type", "ClusterIP")
            if hasattr(service_type, "value"):
                service_type = service_type.value

            # 确保replicas至少为1
            replicas = template.replicas if template.replicas and template.replicas > 0 else 1

            # Ingress配置
            create_ingress = node_config.get("create_ingress")
            ingress_type = node_config.get("ingress_type")
            ingress_host = node_config.get("ingress_host")
            ingress_host_prefix = build_workflow_ingress_host_prefix(node_config, runtime_service_name)
            ingress_ip = node_config.get("ingress_ip")

            ingress_config = None
            if create_ingress is None:
                create_ingress = bool(ingress_type or ingress_host or ingress_ip)
            node_config["ingress_name"] = (
                build_workflow_ingress_resource_name(runtime_service_name)
                if create_ingress and runtime_service_name else None
            )
            if create_ingress and ingress_type:
                ingress_config = {
                    "host": ingress_host,
                    "host_prefix": ingress_host_prefix,
                    "ingress_type": ingress_type,
                    "ingress_ip": ingress_ip,
                    "path": node_config.get("ingress_path", "/"),
                    "path_type": node_config.get("ingress_path_type", "Prefix"),
                    "tls_enabled": node_config.get("ingress_tls_enabled"),
                    "tls_secret_name": node_config.get("ingress_tls_secret_name"),
                    "backend_protocol": node_config.get("ingress_backend_protocol"),
                    "websocket_enabled": node_config.get("ingress_websocket_enabled"),
                    "proxy_body_size": node_config.get("ingress_proxy_body_size"),
                    "proxy_connect_timeout": node_config.get("ingress_proxy_connect_timeout"),
                    "proxy_send_timeout": node_config.get("ingress_proxy_send_timeout"),
                    "proxy_read_timeout": node_config.get("ingress_proxy_read_timeout"),
                    "ssl_redirect": node_config.get("ingress_ssl_redirect"),
                }

            node_info = {
                "node_id": node.node_id,
                "node_type": "app",
                "node_name": node.name,
                "deployment_name": deployment_name,
                "service_name": runtime_service_name,
                "ingress_config": ingress_config,
                "containers": containers,
                "volume_mounts": template.volume_mounts if hasattr(template, 'volume_mounts') else None,
                "replicas": replicas,
                "service_ports": k8s_service_ports,
                "service_type": service_type
            }

            nodes_info.append(node_info)
            nodes_to_process.append(node)

            init_logs.append(
                f"[{datetime.utcnow().isoformat()}] 准备初始化节点 {node.name}: "
                f"Deployment={deployment_name}, Service={runtime_service_name}, DisplayName={display_service_name}"
            )

        except Exception as e:
            logger.error(f"Error preparing node {node.id}: {e}")
            error_msg = f"Error preparing node {node.id}: {str(e)}"
            errors.append(error_msg)
            init_logs.append(f"[{datetime.utcnow().isoformat()}] 异常: {error_msg}")
            node.status = NodeStatus.FAILED
            node.message = error_msg

    # 调用 workflow-status 服务初始化工作流
    if nodes_info:
        init_logs.append(f"[{datetime.utcnow().isoformat()}] 调用 workflow-status 服务初始化工作流")
        result = await status_client.initialize_workflow(
            instance_id=instance_id,
            project_id=instance.project_id,
            nodes=nodes_info,
        )

        logger.info(f"initialize_workflow result: {result}")

        if result.get("nodes"):
            for node_result in result.get("nodes", []):
                result_node_id = node_result.get("node_id")
                node = next((n for n in nodes_to_process if n.node_id == result_node_id), None)
                if not node:
                    continue

                if node_result.get("success", False):
                    node.k8s_resource_name = node_result.get("k8s_resource_name")
                    node.k8s_resource_type = "Deployment" if node.node_type == NodeType.APP else "Job"
                    node.service_name = node_result.get("service_name")
                    node_config = get_instance_node_config(instance, node.id)
                    node_config["ingress_name"] = node_result.get("ingress_name") or node_config.get("ingress_name")
                    if node_result.get("ingress_host"):
                        node_config["ingress_host"] = node_result.get("ingress_host")
                    if "ingress_tls_enabled" in node_result:
                        node_config["ingress_tls_enabled"] = node_result.get("ingress_tls_enabled")
                    if node_result.get("ingress_access_url"):
                        node_config["ingress_access_url"] = node_result.get("ingress_access_url")
                    from sqlalchemy.orm.attributes import flag_modified
                    flag_modified(instance, "nodes")
                    configured_create_ingress = node_config.get(
                        "create_ingress",
                        bool(node.ingress_type or node.ingress_host or node.ingress_ip),
                    )
                    configured_host = node_result.get("ingress_host") or node_config.get("ingress_host") or node.ingress_host
                    configured_ip = node_config.get("ingress_ip") or node.ingress_ip
                    configured_type = node_config.get("ingress_type") or node.ingress_type
                    node.ingress_host = configured_host
                    service_port, target_port = get_primary_service_ports(node_config)

                    result_status = str(node_result.get("status", "Pending")).lower()
                    if result_status == "ready":
                        node.status = NodeStatus.READY
                    elif result_status in ["not_ready", "notready"]:
                        node.status = NodeStatus.NOT_READY
                    elif result_status == "running":
                        node.status = NodeStatus.RUNNING
                    elif result_status == "succeeded":
                        node.status = NodeStatus.SUCCEEDED
                    else:
                        node.status = NodeStatus.PENDING

                    node.message = node_result.get("message", "Node initialized successfully")
                    initialized_nodes.append(node.id)
                    if configured_create_ingress and configured_host:
                        upsert_node_domain_binding(
                            db,
                            instance,
                            node,
                            domain=configured_host,
                            ingress_ip=configured_ip,
                            ingress_type=configured_type,
                            service_name=resolve_runtime_service_name(node, node_config),
                            service_port=service_port,
                            target_port=target_port,
                            ingress_name=node_result.get("ingress_name") or resolve_node_ingress_name(node, node_config),
                            binding_status="configured",
                            message="Node initialized with ingress configuration",
                        )
                    init_logs.append(f"[{datetime.utcnow().isoformat()}] 节点 {result_node_id} 初始化成功")
                else:
                    node.status = NodeStatus.FAILED
                    node.message = node_result.get("error", "Node initialization failed")
                    errors.append(f"Node {result_node_id}: {node.message}")
                    init_logs.append(f"[{datetime.utcnow().isoformat()}] 节点 {result_node_id} 初始化失败: {node.message}")

        if not result.get("success", False):
            errors.append(result.get("message", result.get("error", "workflow-status initialization failed")))

        db.commit()

    # 更新工作流状态（根据APP节点状态计算）
    init_logs.append(f"[{datetime.utcnow().isoformat()}] 初始化完成")

    # 获取所有APP节点用于计算工作流状态
    app_nodes = [n for n in nodes if n.node_type == NodeType.APP]

    if errors and not initialized_nodes:
        # 所有节点初始化都失败 - 仍为unready状态
        instance.status = WorkflowStatus.UNREADY
        instance.message = f"Initialization failed: {'; '.join(errors)}"
        init_logs.append(f"结果: 全部失败 - {'; '.join(errors)}")
        logger.error(f"Workflow {instance_id} initialization failed: {errors}")
    elif not app_nodes:
        # 没有APP节点，根据Job节点状态判断
        job_nodes = [n for n in nodes if n.node_type == NodeType.JOB]
        if not job_nodes:
            # 没有任何节点
            instance.status = WorkflowStatus.PENDING
            instance.message = "No nodes in workflow"
            init_logs.append(f"结果: 无节点")
        elif all(n.status == NodeStatus.SUCCEEDED for n in job_nodes):
            # 所有Job节点都执行成功
            instance.status = WorkflowStatus.READY
            instance.message = f"All {len(job_nodes)} JOB nodes succeeded"
            init_logs.append(f"结果: 所有JOB节点执行成功 - {len(job_nodes)} 个")
        elif all(n.status == NodeStatus.PENDING for n in job_nodes):
            # 所有Job节点都在等待
            instance.status = WorkflowStatus.PENDING
            instance.message = f"All {len(job_nodes)} JOB nodes pending"
            init_logs.append(f"结果: 所有JOB节点等待 - {len(job_nodes)} 个")
        else:
            # Job节点正在执行或有失败
            succeeded_count = sum(1 for n in job_nodes if n.status == NodeStatus.SUCCEEDED)
            running_count = sum(1 for n in job_nodes if n.status == NodeStatus.RUNNING)
            failed_count = sum(1 for n in job_nodes if n.status == NodeStatus.FAILED)
            instance.status = WorkflowStatus.PENDING
            instance.message = f"JOB nodes: {succeeded_count} succeeded, {running_count} running, {failed_count} failed"
            init_logs.append(f"结果: JOB节点执行中 - {succeeded_count} 成功, {running_count} 执行中, {failed_count} 失败")
    else:
        # 根据APP节点状态计算工作流状态
        ready_count = sum(1 for n in app_nodes if n.status == NodeStatus.READY)
        pending_count = sum(1 for n in app_nodes if n.status == NodeStatus.PENDING)

        if ready_count == len(app_nodes):
            # 所有APP节点都ready
            instance.status = WorkflowStatus.READY
            instance.message = f"All {len(app_nodes)} APP nodes are ready"
            init_logs.append(f"结果: 全部就绪 - {len(app_nodes)} 个APP节点")
        elif pending_count == len(app_nodes):
            # 所有APP节点都pending
            instance.status = WorkflowStatus.PENDING
            instance.message = f"All {len(app_nodes)} APP nodes are pending"
            init_logs.append(f"结果: 全部等待 - {len(app_nodes)} 个APP节点")
        else:
            # 部分就绪或部分失败
            instance.status = WorkflowStatus.UNREADY
            if errors:
                instance.message = f"Initialization completed with errors: {'; '.join(errors)}"
                init_logs.append(f"结果: 部分成功 - 成功 {len(initialized_nodes)} 个, 失败 {len(errors)} 个")
            else:
                instance.message = f"APP nodes: {ready_count} ready, {pending_count} pending"
                init_logs.append(f"结果: 初始化完成 - {ready_count} 就绪, {pending_count} 等待")
            logger.info(f"Workflow {instance_id} status: UNREADY")

    # 保存初始化日志
    instance.init_logs = "\n".join(init_logs)

    db.commit()
    db.refresh(instance)

    logger.info(f"Initialized workflow instance {instance_id}, initialized {len(initialized_nodes)} nodes, force={force}")
    return build_instance_response(instance, db)


def _build_containers_from_template(template: AppTemplate, node: WorkflowNodeInstance) -> List[Dict[str, Any]]:
    """
    从模板和节点配置构建容器列表
    """
    containers = []

    # 获取模板容器配置
    template_containers = template.containers or []

    for idx, container_config in enumerate(template_containers):
        container = {
            "name": container_config.get("name", f"container-{idx}"),
            "image": container_config.get("image"),
            "image_pull_policy": container_config.get("image_pull_policy", "IfNotPresent"),
            "command": container_config.get("command"),
            "args": container_config.get("args"),
            "env_vars": [],
            "volume_mounts": [],
            "resources": container_config.get("resources"),
            "liveness_probe": container_config.get("liveness_probe"),
            "readiness_probe": container_config.get("readiness_probe"),
            "privileged": container_config.get("privileged", False),
        }

        # 合并模板的环境变量
        template_env_vars = container_config.get("env_vars", [])
        for e in template_env_vars:
            container["env_vars"].append({
                "name": e.get("name"),
                "value": e.get("value", "")
            })

        # 添加节点级别的环境变量覆盖
        node_env_vars = node.env_vars or []
        for e in node_env_vars:
            # 检查是否已存在，如果存在则覆盖
            existing = next((x for x in container["env_vars"] if x["name"] == e.get("name")), None)
            if existing:
                existing["value"] = e.get("value", "")
            else:
                container["env_vars"].append({
                    "name": e.get("name"),
                    "value": e.get("value", "")
                })

        # 合并模板的卷挂载
        template_volume_mounts = container_config.get("volume_mounts", [])
        for vm in template_volume_mounts:
            container["volume_mounts"].append({
                "pvc_name": vm.get("pvc_name"),
                "mount_path": vm.get("mount_path"),
                "sub_path": vm.get("sub_path"),
                "read_only": vm.get("read_only", False)
            })

        # 添加节点级别的卷挂载
        node_volume_mounts = node.volume_mounts or []
        for vm in node_volume_mounts:
            container["volume_mounts"].append({
                "pvc_name": vm.get("pvc_name"),
                "mount_path": vm.get("mount_path"),
                "sub_path": vm.get("sub_path"),
                "read_only": vm.get("read_only", False)
            })

        # 节点级别的资源覆盖
        if node.resources:
            container["resources"] = node.resources

        containers.append(container)

    return containers


def check_instance_permission(instance: WorkflowInstance, user_id: str) -> bool:
    """Check if user has permission to access workflow instance"""
    # Backward compatibility:
    # historical instances were created by service account "system".
    # These instances should be accessible after project-based listing.
    if instance.created_by == user_id:
        return True
    if instance.created_by == "system":
        return True
    return False


def build_instance_response(instance: WorkflowInstance, db: Session) -> Dict[str, Any]:
    """Build workflow instance response dict with nodes from WorkflowNodeInstance table"""
    # Get nodes from WorkflowNodeInstance table (has runtime status)
    node_instances = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.instance_id == instance.id
    ).all()

    # Build nodes list for response
    nodes_data = []
    for node in node_instances:
        nodes_data.append(build_node_response(node, instance))

    return {
        "id": instance.id,
        "name": instance.name,
        "description": instance.description,
        "project_id": instance.project_id,
        "status": instance.status,
        "run_mode": instance.run_mode,
        "trigger_type": instance.trigger_type,
        "trigger_enabled": instance.trigger_enabled,
        "trigger_url": instance.trigger_url,
        "is_active": instance.is_active,
        "run_count": instance.run_count,
        "last_run_at": instance.last_run_at.isoformat() if instance.last_run_at else None,
        "nodes": nodes_data,
        "edges": instance.edges or [],
        "has_warning": instance.has_warning,  # 警告标记
        "last_sync_at": instance.last_sync_at.isoformat() if instance.last_sync_at else None,
        "created_by": instance.created_by,
        "started_at": instance.started_at.isoformat() if instance.started_at else None,
        "finished_at": instance.finished_at.isoformat() if instance.finished_at else None,
        "created_at": instance.created_at.isoformat() if instance.created_at else None,
        "updated_at": instance.updated_at.isoformat() if instance.updated_at else None,
    }


def build_node_relationships(nodes: List[WorkflowNodeInstance], edges: List[Dict]) -> None:
    """
    Build depends_on and downstream_node_ids for all nodes based on edges.

    For each edge (source -> target):
    - target node's depends_on: add source node
    - source node's downstream_node_ids: add target node

    Note: Uses node.id for matching (node_id is same as id for backward compatibility)
    """
    # Initialize empty relationships
    for node in nodes:
        node.depends_on = node.depends_on or []
        node.downstream_node_ids = node.downstream_node_ids or []

    # Build relationships from edges
    for edge in edges:
        source = edge.get("source")
        target = edge.get("target")

        if not source or not target:
            continue

        # Find target node and add source to its depends_on
        for node in nodes:
            if node.id == target or node.node_id == target:  # Support both id and node_id
                if source not in node.depends_on:
                    node.depends_on.append(source)
                break

        # Find source node and add target to its downstream_node_ids
        for node in nodes:
            if node.id == source or node.node_id == source:  # Support both id and node_id
                if target not in node.downstream_node_ids:
                    node.downstream_node_ids.append(target)
                break


@router.post("", response_model=WorkflowInstanceResponse, status_code=status.HTTP_201_CREATED)
async def create_workflow_instance(
    instance_data: WorkflowInstanceCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create workflow instance

    - Can create empty workflow (without nodes) and add nodes later via node API
    - Validates each node's template exists (AppTemplate or JobTemplate) and user has access
    - Creates node instances from provided node configurations
    - Supports run_mode: "once" (run once) or "persistent" (keep running)
    - Supports trigger_type: "manual" or "http"
    - Does not start the workflow automatically
    """
    user_id = str(current_user.get("id", ""))

    # Validate each node's template, check permissions, and validate dependencies (if nodes provided)
    nodes = instance_data.nodes or []
    for node_config_obj in nodes:
        # Convert to dict if it's a Pydantic model
        if hasattr(node_config_obj, 'model_dump'):
            node_config = node_config_obj.model_dump()
        else:
            node_config = node_config_obj.dict()

        template_id = node_config.get("template_id")
        node_type = node_config.get("node_type")

        # Check if template exists and user has access
        if node_type == "app":
            template = db.query(AppTemplate).filter(AppTemplate.id == template_id).first()
            if not template:
                raise NotFoundError("App template", template_id)
            if template.scope != "global" and template.created_by != user_id:
                raise ForbiddenError(f"No permission to use app template {template_id}")
        else:  # job
            template = db.query(JobTemplate).filter(JobTemplate.id == template_id).first()
            if not template:
                raise NotFoundError("Job template", template_id)
            if template.scope != "global" and template.created_by != user_id:
                raise ForbiddenError(f"No permission to use job template {template_id}")

        # Validate template dependencies (env_vars and volume_mounts must satisfy template's requirements)
        # Create a temporary WorkflowNodeCreate object for validation
        node_data = WorkflowNodeCreate(**node_config)
        unsatisfied_dependencies = validate_template_dependencies(template, node_data)
        if unsatisfied_dependencies:
            raise ValidationError(
                f"Template dependency not satisfied for node {node_config.get('node_id')}: {unsatisfied_dependencies}",
                details=unsatisfied_dependencies
            )

    # Generate instance ID
    instance_id = generate_id(instance_data.name)

    # Generate trigger URL for HTTP trigger mode
    trigger_url = None
    trigger_type_val = instance_data.trigger_type.value if hasattr(instance_data.trigger_type, 'value') else instance_data.trigger_type
    if trigger_type_val == "http" and instance_data.trigger_enabled:
        trigger_url = f"/api/workflow/workflow-instances/trigger/{instance_id}"

    # Convert nodes and edges to dict for storage
    nodes_dict = []
    resolved_node_mounts: List[List[Dict[str, Any]]] = []
    for n in nodes:
        if hasattr(n, 'model_dump'):
            node_config = n.model_dump()
        else:
            node_config = n.dict()
        combined_mounts, raw_volume_mounts, normalized_project_mounts = await resolve_requested_volume_mounts(
            instance_data.project_id,
            node_config.get("volume_mounts"),
            node_config.get("project_file_mounts"),
            current_user.get("token"),
        )
        node_config["volume_mounts"] = raw_volume_mounts
        node_config["project_file_mounts"] = normalized_project_mounts
        nodes_dict.append(node_config)
        resolved_node_mounts.append(combined_mounts)

    edges_dict = []
    for e in (instance_data.edges or []):
        if hasattr(e, 'model_dump'):
            edges_dict.append(e.model_dump())
        else:
            edges_dict.append(e.dict())

    # Create instance
    instance = WorkflowInstance(
        id=instance_id,
        name=instance_data.name,
        description=instance_data.description,
        project_id=instance_data.project_id,
        status=WorkflowStatus.PENDING,
        run_mode=instance_data.run_mode.value if hasattr(instance_data.run_mode, 'value') else "once",
        trigger_type=trigger_type_val,
        trigger_enabled=instance_data.trigger_enabled,
        trigger_url=trigger_url,
        is_active=True,
        nodes=nodes_dict,
        edges=edges_dict,
        run_count=0,
        created_by=user_id,
    )

    db.add(instance)
    db.flush()  # Get instance ID

    # Create node instances from provided nodes
    for index, node_config in enumerate(nodes_dict):
        # Generate node ID - this will be both id and node_id
        node_id = generate_id(f"{instance_id}_{node_config.get('name', 'node')}")

        # Get edges that have this node as target to build depends_on
        depends_on = node_config.get("depends_on", [])

        node_instance = WorkflowNodeInstance(
            id=node_id,
            instance_id=instance_id,
            node_id=node_id,  # Same as id
            node_type=NodeType.APP if node_config.get("node_type") == "app" else NodeType.JOB,
            template_id=node_config.get("template_id"),
            name=node_config.get("name", "Unnamed Node"),
            status=NodeStatus.PENDING,
            position=node_config.get("position", {"x": 0.0, "y": 0.0}),
            env_vars=node_config.get("env_vars", []),
            volume_mounts=resolved_node_mounts[index],
            resources=node_config.get("resources"),
            depends_on=depends_on,
            downstream_node_ids=[],  # Initialize empty, will be built after all nodes created
            timeout_seconds=node_config.get("timeout_seconds"),
            input_env_vars=node_config.get("input_env_vars", []),
            input_volume_mounts=node_config.get("input_volume_mounts", []),
            service_name=None,
            ingress_type=node_config.get("ingress_type"),
            ingress_host=node_config.get("ingress_host"),
            ingress_ip=node_config.get("ingress_ip"),
        )
        db.add(node_instance)

        # Update node_config to include the auto-generated id
        node_config["id"] = node_id
        node_config["node_id"] = node_id  # For backward compatibility
        node_config["depends_on"] = depends_on
        node_config["downstream_node_ids"] = []
        node_config["input_env_vars"] = node_config.get("input_env_vars", [])
        node_config["input_volume_mounts"] = node_config.get("input_volume_mounts", [])

    db.commit()

    # Build node relationships (depends_on and downstream_node_ids) from edges
    all_nodes = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.instance_id == instance_id
    ).all()
    if edges_dict and all_nodes:
        build_node_relationships(all_nodes, edges_dict)
        db.commit()

    db.refresh(instance)

    logger.info(f"Created workflow instance {instance_id} by user {user_id}, "
                f"run_mode={instance.run_mode}, trigger_type={instance.trigger_type}, nodes={len(nodes)}")
    return build_instance_response(instance, db)


@router.get("", response_model=WorkflowInstanceListResponse)
async def list_workflow_instances(
    project_id: Optional[str] = Query(None, description="Filter by project ID"),
    status: Optional[str] = Query(None, description="Filter by status"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List workflow instances by selected project."""
    query = db.query(WorkflowInstance)

    # Frontend flow queries instances through project dropdown.
    # If no project is selected, return empty result to avoid cross-project listing.
    if not project_id:
        return WorkflowInstanceListResponse(total=0, items=[])

    query = query.filter(
        WorkflowInstance.project_id == project_id,
        WorkflowInstance.run_mode != "simple_app",
    )
    if status:
        query = query.filter(WorkflowInstance.status == status)

    instances = query.order_by(WorkflowInstance.created_at.desc()).all()

    # Build response items using helper function
    items = [build_instance_response(inst, db) for inst in instances]
    return WorkflowInstanceListResponse(total=len(items), items=items)


@router.get("/{instance_id}", response_model=WorkflowInstanceResponse)
async def get_workflow_instance(
    instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get workflow instance details"""
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)
    if instance.run_mode == "simple_app":
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to access this instance")

    return build_instance_response(instance, db)


@router.put("/{instance_id}", response_model=WorkflowInstanceResponse)
async def update_workflow_instance(
    instance_id: str,
    instance_data: WorkflowInstanceUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update workflow instance

    - Update name, description
    - Enable/disable trigger (for persistent mode)
    - Set active state (for persistent mode)

    Note: 只能在 pending 状态下修改 edges（节点依赖关系），初始化后不允许修改
    """
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to update this instance")

    # 只允许在 pending 状态下修改 edges
    if instance_data.edges is not None and instance.status != WorkflowStatus.PENDING:
        raise ValidationError(f"Cannot update edges in status: {instance.status}. Only pending state allows modification.")

    # 其他字段可以在 pending, unready, ready 状态下修改
    if instance.status not in [WorkflowStatus.PENDING, WorkflowStatus.UNREADY, WorkflowStatus.READY]:
        raise ValidationError(f"Cannot update instance in status: {instance.status}")

    # Update fields
    if instance_data.name is not None:
        instance.name = instance_data.name
    if instance_data.description is not None:
        instance.description = instance_data.description

    # Update edges
    if instance_data.edges is not None:
        edges_list = []
        for e in instance_data.edges:
            if hasattr(e, 'model_dump'):
                edges_list.append(e.model_dump())
            else:
                edges_list.append(e.dict())
        instance.edges = edges_list

    # Handle trigger_enabled update
    if instance_data.trigger_enabled is not None:
        if instance.run_mode != "persistent":
            raise ValidationError("Only persistent mode workflows support trigger")
        instance.trigger_enabled = instance_data.trigger_enabled

    # Handle is_active update
    if instance_data.is_active is not None:
        if instance.run_mode != "persistent":
            raise ValidationError("Only persistent mode workflow support active state")
        instance.is_active = instance_data.is_active

    db.commit()
    db.refresh(instance)

    logger.info(f"Updated workflow instance {instance_id}")
    return build_instance_response(instance, db)


@router.post("/{instance_id}/start", response_model=WorkflowInstanceResponse)
async def start_workflow_instance(
    instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Start workflow instance

    - Uses WorkflowEngine for topological execution with dependency checking
    - Detects and prevents cyclic dependency
    - Concurrently executes ready nodes
    - Handles environment variable and mount dependencies
    """
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to start this instance")

    if instance.status not in [WorkflowStatus.PENDING, WorkflowStatus.UNREADY, WorkflowStatus.READY]:
        raise ValidationError(f"Cannot start instance in status: {instance.status}. Valid states: pending, unready, ready")

    # 如果是从 ready 状态启动（重新执行），重置 JOB 节点状态
    if instance.status == WorkflowStatus.READY:
        await _reset_job_nodes_for_retrigger(instance_id, instance.project_id)

    # Update run count and last run time
    instance.run_count += 1
    from datetime import datetime
    instance.last_run_at = datetime.utcnow()
    db.commit()

    # 使用WorkflowEngine来执行工作流（自动选择K8S客户端模式）
    try:
        from app.models import get_session_factory

        # 为后续操作创建独立的 Session
        bg_session = get_session_factory()()

        engine = WorkflowEngine(instance_id, bg_session)
        await engine.initialize()

        # 将节点记录到状态服务
        await engine._record_nodes_to_status_service()

        # 校验 namespace (via workflow-status proxy)
        await ensure_project_namespace(instance.project_id)

        # Execute workflow (this runs asynchronously with its own session)
        async def run_workflow_with_session():
            try:
                await engine.execute_workflow()
            finally:
                bg_session.close()

        asyncio.create_task(run_workflow_with_session())

        logger.info(f"Started workflow instance {instance_id}")

    except ValueError as e:
        raise ValidationError(str(e))
    except Exception as e:
        logger.error(f"Failed to start workflow {instance_id}: {e}")
        raise InternalError(f"Failed to start workflow: {str(e)}")

    db.refresh(instance)
    return build_instance_response(instance, db)


@router.post("/{instance_id}/sync-status", response_model=WorkflowInstanceResponse)
async def sync_workflow_status(
    instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Sync workflow status from K8S

    - Updates all node statuses from K8S (read-only, no resource creation)
    - Checks for resource consistency between database and K8S cluster:
      - Orphan resources: K8S has resources not recorded in database (resource leak)
      - Missing resources: Database records resources not found in K8S (resource loss)
    - Sets warning flag when inconsistencies are detected
    - Can be called periodically or manually for status synchronization
    - Allowed in any status for manual status synchronization and recovery

    Note: This API only queries K8S resource status, it does NOT create any K8S resources.
    To start workflow execution, use the /start API instead.
    """
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to access this instance")

    # 允许在任何状态下同步状态，以便用户可以手动触发状态同步
    # 这对于异常状态恢复、状态校准等场景非常有用

    from datetime import datetime
    sync_start_time = datetime.utcnow()
    sync_logs = []

    try:
        sync_logs.append(f"[{sync_start_time.isoformat()}] 开始同步工作流状态")

        engine = WorkflowEngine(instance_id, db)
        await engine.initialize()
        await engine.sync_all_nodes_status()

        sync_logs.append(f"工作流状态: {instance.status}, 节点数: {len(engine.nodes)}")

        # 检查资源泄露和状态一致性
        # 1. 检查数据库中记录的资源是否在K8S集群中存在
        # 2. 主动查询集群中与该工作流相关的资源（可能存在资源泄露）
        status_client = get_status_client()

        instance_prefix = f"wf-{instance_id[:8]}-"

        resources = await status_client.list_project_resources(
            project_id=instance.project_id,
            instance_prefix=instance_prefix,
        )
        all_deployments = resources.get("deployments", [])
        all_services = resources.get("services", [])
        all_jobs = resources.get("jobs", [])
        sync_logs.append(
            f"查询K8S资源: Deployments={len(all_deployments)}, Services={len(all_services)}, Jobs={len(all_jobs)}"
        )

        # 筛选出属于该工作流的资源
        workflow_deployments = [d for d in all_deployments if (d.get("name") or "").startswith(instance_prefix)]
        workflow_services = [s for s in all_services if (s.get("name") or "").startswith(instance_prefix)]
        workflow_jobs = [j for j in all_jobs if (j.get("name") or "").startswith(instance_prefix)]

        sync_logs.append(f"工作流相关资源: Deployments={len(workflow_deployments)}, Services={len(workflow_services)}, Jobs={len(workflow_jobs)}")

        # 数据库中记录的资源名称
        db_deployment_names = set()
        db_service_names = set()
        db_job_names = set()
        for node in engine.nodes:
            if node.k8s_resource_name:
                if node.k8s_resource_type == "Deployment":
                    db_deployment_names.add(node.k8s_resource_name)
                elif node.k8s_resource_type == "Job":
                    db_job_names.add(node.k8s_resource_name)
            if node.service_name:
                db_service_names.add(node.service_name)

        # K8S中存在的资源名称
        k8s_deployment_names = set(d.get("name") for d in workflow_deployments)
        k8s_service_names = set(s.get("name") for s in workflow_services)
        k8s_job_names = set(j.get("name") for j in workflow_jobs)

        # 计算差异
        orphan_deployments = list(k8s_deployment_names - db_deployment_names)  # K8S有但数据库没有（资源泄露）
        orphan_services = list(k8s_service_names - db_service_names)  # K8S有但数据库没有（资源泄露）
        orphan_jobs = list(k8s_job_names - db_job_names)  # K8S有但数据库没有（资源泄露）

        missing_deployments = list(db_deployment_names - k8s_deployment_names)  # 数据库有但K8S没有（资源丢失）
        missing_services = list(db_service_names - k8s_service_names)  # 数据库有但K8S没有（资源丢失）
        missing_jobs = list(db_job_names - k8s_job_names)  # 数据库有但K8S没有（资源丢失）

        # 构建警告信息
        warnings = []
        if orphan_deployments:
            warnings.append(f"泄露的Deployment: {orphan_deployments}")
        if orphan_services:
            warnings.append(f"泄露的Service: {orphan_services}")
        if orphan_jobs:
            warnings.append(f"泄露的Job: {orphan_jobs}")
        if missing_deployments:
            warnings.append(f"丢失的Deployment: {missing_deployments}")
        if missing_services:
            warnings.append(f"丢失的Service: {missing_services}")
        if missing_jobs:
            warnings.append(f"丢失的Job: {missing_jobs}")

        sync_end_time = datetime.utcnow()
        sync_duration = (sync_end_time - sync_start_time).total_seconds()

        if warnings:
            warning_msg = f"警告: K8S资源状态不一致 - {'; '.join(warnings)}。建议调用 uninitialize 清理或重新初始化。"
            instance.message = warning_msg
            instance.has_warning = True
            sync_logs.append(f"结果: 发现不一致 - {'; '.join(warnings)}")
            logger.warning(f"Workflow {instance_id}: {warning_msg}")
        elif instance.has_warning:
            # 清除之前的警告标记
            instance.has_warning = False
            instance.message = "状态同步完成，资源状态一致"
            sync_logs.append("结果: 资源状态一致，已清除警告")
        else:
            sync_logs.append("结果: 资源状态一致")

        # 记录同步时间和日志
        instance.last_sync_at = sync_end_time
        sync_logs.append(f"[{sync_end_time.isoformat()}] 同步完成，耗时: {sync_duration:.2f}s")
        instance.sync_logs = "\n".join(sync_logs)

        # 创建同步记录
        sync_record = WorkflowSyncRecord(
            id=generate_id(f"sync_{instance_id}"),
            instance_id=instance_id,
            sync_at=sync_end_time
        )
        db.add(sync_record)

        db.commit()

        # 注意: sync_status 只负责同步状态，不创建任何K8S资源
        # 就绪节点的启动应该由 start API 或 execute_workflow 来处理
        # 这里不再调用 start_node 避免在同步状态时创建资源

    except Exception as e:
        logger.error(f"Error syncing workflow status: {e}")
        sync_logs.append(f"同步失败: {str(e)}")
        instance.sync_logs = "\n".join(sync_logs)
        db.commit()
        raise InternalError(f"Failed to sync status: {str(e)}")

    db.refresh(instance)
    return build_instance_response(instance, db)


@router.get("/{instance_id}/sync-records", response_model=WorkflowSyncRecordListResponse)
async def get_workflow_sync_records(
    instance_id: str,
    limit: int = Query(50, ge=1, le=100, description="Number of records to return"),
    offset: int = Query(0, ge=0, description="Number of records to skip"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    获取工作流实例的同步记录列表

    - 返回指定工作流实例的所有同步时间记录
    - 按同步时间倒序排列
    - 支持分页查询
    """
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to access this instance")

    # 查询同步记录
    query = db.query(WorkflowSyncRecord).filter(
        WorkflowSyncRecord.instance_id == instance_id
    ).order_by(WorkflowSyncRecord.sync_at.desc())

    total = query.count()
    records = query.offset(offset).limit(limit).all()

    return WorkflowSyncRecordListResponse(
        total=total,
        items=[
            WorkflowSyncRecordResponse(
                id=r.id,
                instance_id=r.instance_id,
                sync_at=r.sync_at,
                created_at=r.created_at
            ) for r in records
        ]
    )



@router.post("/{instance_id}/stop", response_model=WorkflowInstanceResponse)
async def stop_workflow_instance(
    instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Stop workflow instance

    - Stops all running K8S resources
    - Can be called from UNREADY or READY state
    - Sets status to PENDING (resources deleted)
    """
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to stop this instance")

    if instance.status not in [WorkflowStatus.UNREADY, WorkflowStatus.READY]:
        raise ValidationError(f"Cannot stop instance in status: {instance.status}. Valid states: unready, ready")

    nodes = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.instance_id == instance_id
    ).all()
    nodes_info = build_lifecycle_nodes(nodes, instance)

    result = await get_status_client().stop_workflow(
        instance_id=instance_id,
        project_id=instance.project_id,
        nodes=nodes_info if nodes_info else None,
    )
    logger.info(f"stop_workflow result: {result}")
    if not result.get("success", False):
        logger.warning(f"stop_workflow returned non-success: {result}")

    # Update local database node status
    nodes = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.instance_id == instance_id
    ).all()

    for node in nodes:
        node.status = NodeStatus.PENDING
        from datetime import datetime
        node.finished_at = datetime.utcnow()
        node.k8s_resource_name = None
        node.k8s_resource_type = None
        node.service_name = None
        node.ingress_type = None
        node_config = get_instance_node_config(instance, node.id)
        node_config["k8s_service_name"] = None
        node_config["ingress_name"] = None
        node_config["ingress_access_url"] = None
        node_config["ingress_tls_enabled"] = None

    # Set status to PENDING after stop (resources deleted)
    instance.status = WorkflowStatus.PENDING
    db.commit()
    db.refresh(instance)

    logger.info(f"Stopped workflow instance {instance_id}")
    return build_instance_response(instance, db)


@router.post("/{instance_id}/uninitialize", response_model=WorkflowInstanceResponse)
async def uninitialize_workflow_instance(
    instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Uninitialize workflow instance

    - Delete all created K8S resources (deployment, service, job)
    - Clear node K8S resource information
    - Reset all node status to PENDING
    - Reset workflow status to PENDING

    Prerequisites:
    - Status is UNREADY or READY

    Usage:
    - Fully reset workflow to initial state
    - Re-deploy after cleaning up all K8S resources
    """
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to uninitialize this instance")

    # Check status - only uninitialize in initialized states
    valid_states = [
        WorkflowStatus.UNREADY,
        WorkflowStatus.READY
    ]
    if instance.status not in valid_states:
        raise ValidationError(
            f"Cannot uninitialize instance in status: {instance.status}. "
            f"Valid states: unready, ready"
        )

    # Get all nodes
    nodes = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.instance_id == instance_id
    ).all()

    deleted_count = 0
    errors = []
    nodes_info = build_lifecycle_nodes(nodes, instance)
    result = await get_status_client().deinitialize_workflow(
        instance_id=instance_id,
        project_id=instance.project_id,
        nodes=nodes_info if nodes_info else None,
    )
    deleted_count = result.get("succeeded_nodes", 0)
    if not result.get("success", False):
        errors.append(result.get("message", result.get("error", "Unknown error")))
    logger.info(f"deinitialize_workflow result: {result}")

    for node in nodes:
        node.k8s_resource_name = None
        node.k8s_resource_type = None
        node.service_name = None
        node.ingress_type = None
        node.ingress_host = None
        node.ingress_ip = None
        node_config = get_instance_node_config(instance, node.id)
        node_config["k8s_service_name"] = None
        node_config["ingress_name"] = None
        node_config["ingress_access_url"] = None
        node_config["ingress_tls_enabled"] = None
        delete_node_domain_bindings(db, instance_id, node.id)
        node.status = NodeStatus.PENDING
        node.started_at = None
        node.finished_at = None
        node.message = None

    # Reset workflow status
    instance.status = WorkflowStatus.PENDING
    instance.started_at = None
    instance.finished_at = None

    if errors:
        instance.message = f"Uninitialize completed with errors: {'; '.join(errors)}"
        logger.warning(f"Uninitialized workflow {instance_id} with errors: {errors}")
    else:
        instance.message = f"Successfully uninitialized, deleted {deleted_count} K8S resources"
        logger.info(f"Uninitialized workflow {instance_id}, deleted {deleted_count} K8S resources")

    db.commit()
    db.refresh(instance)

    return build_instance_response(instance, db)


@router.delete("/{instance_id}", response_model=SuccessResponse)
async def delete_workflow_instance(
    instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Delete workflow instance

    - Stops the workflow if running
    - Deletes all associated K8S resources
    - Removes instance from database
    """
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to delete this instance")

    # Delete K8S resources if initialized (unready or ready)
    if instance.status in [WorkflowStatus.UNREADY, WorkflowStatus.READY]:
        nodes = db.query(WorkflowNodeInstance).filter(
            WorkflowNodeInstance.instance_id == instance_id
        ).all()

        nodes_info = build_lifecycle_nodes(nodes, instance)
        result = await get_status_client().deinitialize_workflow(
            instance_id=instance_id,
            project_id=instance.project_id,
            nodes=nodes_info if nodes_info else None,
        )
        logger.info(f"deinitialize_workflow for delete result: {result}")

    # Delete all sync records first (foreign key constraint requires this)
    db.query(WorkflowSyncRecord).filter(
        WorkflowSyncRecord.instance_id == instance_id
    ).delete()

    # Delete all node instances (foreign key constraint requires this)
    db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.instance_id == instance_id
    ).delete()

    # Delete instance
    db.delete(instance)
    db.commit()

    logger.info(f"Deleted workflow instance {instance_id}")
    return SuccessResponse(message=f"Workflow instance {instance_id} deleted successfully")


@router.get("/{instance_id}/nodes/{node_id}/logs", response_model=PodLogResponse)
async def get_node_logs(
    instance_id: str,
    node_id: str,
    tail_lines: int = Query(100, ge=1, le=10000),
    container: Optional[str] = Query(None),
    previous: bool = Query(False),
    timestamps: bool = Query(True),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get logs for a workflow node

    - For Deployment node: gets logs from the associated pod
    - For Job node: gets logs from the job pod
    """
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to access this instance")

    node = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.id == node_id,
        WorkflowNodeInstance.instance_id == instance_id
    ).first()

    if not node:
        raise NotFoundError("Workflow node", node_id)

    if not node.k8s_resource_name:
        raise ValidationError("Node has not been started yet")

    resource_type = "deployment" if node.k8s_resource_type == "Deployment" else "job"
    log_result = await get_status_client().get_resource_logs(
        project_id=instance.project_id,
        resource_type=resource_type,
        resource_name=node.k8s_resource_name,
        tail_lines=tail_lines,
        container=container,
        previous=previous,
    )
    if log_result.get("error"):
        raise InternalError(f"Failed to retrieve pod logs: {log_result['error']}")

    return PodLogResponse(
        resource_name=node.k8s_resource_name,
        pod_name=log_result.get("pod_name"),
        namespace=log_result.get("namespace"),
        logs=log_result.get("logs", ""),
        container=container,
        previous=previous,
    )


@router.get("/{instance_id}/logs", response_model=WorkflowInstanceNodeLogListResponse)
async def get_workflow_instance_logs(
    instance_id: str,
    node_id: Optional[str] = Query(None, description="Filter by node ID"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Page size"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get stored node log records for one workflow instance."""
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to access this instance")

    nodes = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.instance_id == instance_id
    ).all()

    node_map = {node.id: node.name for node in nodes}
    node_ids = list(node_map.keys())

    if not node_ids:
        return WorkflowInstanceNodeLogListResponse(total=0, page=page, page_size=page_size, items=[])

    if node_id and node_id not in node_map:
        return WorkflowInstanceNodeLogListResponse(total=0, page=page, page_size=page_size, items=[])

    result = await get_status_client().query_instance_node_logs(
        instance_id=instance_id,
        project_id=instance.project_id,
        node_ids=node_ids,
        node_id=node_id,
        page=page,
        page_size=page_size,
    )

    items = []
    for item in result.get("items", []):
        enriched_item = {
            **item,
            "node_name": node_map.get(item.get("node_id")),
        }
        items.append(WorkflowInstanceNodeLogEntry(**enriched_item))

    return WorkflowInstanceNodeLogListResponse(
        total=result.get("total", 0),
        page=result.get("page", page),
        page_size=result.get("page_size", page_size),
        items=items,
    )


@router.get("/{instance_id}/nodes/{node_id}/init-logs")
async def get_node_init_logs(
    instance_id: str,
    node_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get initialization logs of workflow node.
    """
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to access this instance")

    node = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.id == node_id,
        WorkflowNodeInstance.instance_id == instance_id
    ).first()

    if not node:
        raise NotFoundError("Workflow node", node_id)

    return {
        "node_id": node.id,
        "node_name": node.name,
        "status": node.status,
        "message": node.message,
        "init_logs": node.init_logs or "No initialization logs available",
    }


# ============ Trigger Endpoints ============

async def _reset_job_nodes_for_retrigger(instance_id: str, project_id: str):
    """Reset latest JOB status snapshots for legacy re-trigger flows."""
    status_client = get_workflow_status_client()

    try:
        result = await status_client.reset_job_nodes(
            instance_id=instance_id,
            project_id=project_id,
            reset_logs=False,
        )
        logger.info(
            "Reset legacy JOB node snapshots, instance_id=%s, reset_count=%s",
            instance_id,
            result.get("reset_count", 0),
        )
    except Exception as e:
        logger.warning("Failed to reset JOB node status snapshots: %s", e)


def _build_trigger_node_payloads(
    instance: WorkflowInstance,
    db: Session,
) -> tuple[List[WorkflowNodeInstance], List[Dict[str, Any]]]:
    """Build executable node payloads for workflow-status trigger orchestration."""
    nodes = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.instance_id == instance.id
    ).all()

    payloads: List[Dict[str, Any]] = []
    for node in nodes:
        node_config = get_instance_node_config(instance, node.id)
        payload: Dict[str, Any] = {
            "node_id": node.node_id,
            "node_name": node.name,
            "node_type": node.node_type.value if hasattr(node.node_type, "value") else str(node.node_type),
            "depends_on": node.depends_on or [],
            "k8s_resource_name": node.k8s_resource_name,
            "service_name": resolve_runtime_service_name(node, node_config),
            "timeout_seconds": node.timeout_seconds,
        }

        if node.node_type == NodeType.JOB:
            template = db.query(JobTemplate).filter(JobTemplate.id == node.template_id).first()
            if not template:
                raise ValidationError(f"Job template {node.template_id} not found for node {node.node_id}")
            payload["job_config"] = {
                "containers": _build_containers_from_template(template, node),
                "ttl_seconds_after_finished": template.ttl_seconds_after_finished,
                "backoff_limit": template.backoff_limit,
            }

        payloads.append(payload)

    if not payloads:
        raise ValidationError("Workflow instance has no nodes to trigger")

    return nodes, payloads


def _validate_trigger_instance(
    instance: WorkflowInstance,
    *,
    require_http_trigger: bool,
) -> None:
    if instance.status == WorkflowStatus.PENDING:
        raise ValidationError(f"Workflow instance {instance.id} is not initialized. Call initialize first.")

    if instance.run_mode == "persistent" and not instance.is_active:
        raise ValidationError(f"Workflow instance {instance.id} is not active")

    if require_http_trigger:
        if not instance.trigger_enabled:
            raise ValidationError(f"Trigger is not enabled for workflow instance {instance.id}")
        if instance.trigger_type != "http":
            raise ValidationError(f"Workflow instance {instance.id} is not configured for HTTP trigger")


async def _dispatch_workflow_trigger(
    instance: WorkflowInstance,
    db: Session,
) -> SuccessResponse:
    await ensure_project_namespace(instance.project_id)

    node_instances, trigger_nodes = _build_trigger_node_payloads(instance, db)

    from datetime import datetime

    for node in node_instances:
        if node.node_type != NodeType.JOB:
            continue
        node.status = NodeStatus.PENDING
        node.message = "Reset for trigger execution"
        node.started_at = None
        node.finished_at = None
        node.k8s_resource_name = None
        node.k8s_resource_type = "Job"

    instance.run_count += 1
    instance.last_run_at = datetime.utcnow()
    instance.started_at = datetime.utcnow()
    instance.finished_at = None
    instance.status = WorkflowStatus.UNREADY
    instance.message = "Workflow trigger accepted"
    db.commit()

    try:
        result = await get_status_client().trigger_workflow_execution(
            instance_id=instance.id,
            project_id=instance.project_id,
            run_mode=instance.run_mode,
            nodes=trigger_nodes,
            edges=instance.edges or [],
        )
        if not result.get("success", False):
            raise InternalError(result.get("message", "Workflow trigger request rejected by workflow-status"))
    except Exception as e:
        instance.message = f"Trigger dispatch failed: {str(e)}"
        db.commit()
        raise

    logger.info("Triggered workflow instance %s via workflow-status", instance.id)
    return SuccessResponse(message=f"Workflow {instance.id} triggered successfully")


@router.post("/{instance_id}/trigger", response_model=SuccessResponse)
async def trigger_workflow_instance(
    instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Trigger workflow execution from the authenticated UI."""
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to trigger this instance")

    _validate_trigger_instance(instance, require_http_trigger=False)
    return await _dispatch_workflow_trigger(instance, db)


@router.post("/trigger/{instance_id}", response_model=SuccessResponse)
async def trigger_workflow_by_http(
    instance_id: str,
    db: Session = Depends(get_db),
):
    """Trigger workflow execution via public HTTP endpoint."""
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    _validate_trigger_instance(instance, require_http_trigger=True)
    return await _dispatch_workflow_trigger(instance, db)


@router.post("/{instance_id}/activate", response_model=WorkflowInstanceResponse)
async def activate_workflow_instance(
    instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Activate workflow instance (for persistent mode)

    - Makes the workflow instance active to accept trigger
    - Requires workflow to be initialized or stopped
    """
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to activate this instance")

    if instance.run_mode != "persistent":
        raise ValidationError("Only persistent mode workflow can be activated")

    # Workflow must be unready or ready to be activated
    if instance.status not in [WorkflowStatus.UNREADY, WorkflowStatus.READY]:
        raise ValidationError(f"Cannot activate instance in status: {instance.status}. Initialize first.")

    instance.is_active = True
    db.commit()
    db.refresh(instance)

    logger.info(f"Activated workflow instance {instance_id}")
    return build_instance_response(instance, db)


@router.post("/{instance_id}/deactivate", response_model=WorkflowInstanceResponse)
async def deactivate_workflow_instance(
    instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Deactivate workflow instance (for persistent mode)

    - Makes the workflow instance inactive to reject trigger
    - Does not stop running workflow
    """
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to deactivate this instance")

    if instance.run_mode != "persistent":
        raise ValidationError("Only persistent mode workflow can be deactivated")

    instance.is_active = False
    db.commit()
    db.refresh(instance)

    logger.info(f"Deactivated workflow instance {instance_id}")
    return build_instance_response(instance, db)


# ============ Workflow Node Operations ============

@router.post("/{instance_id}/nodes", response_model=WorkflowNodeInstanceResponse, status_code=status.HTTP_201_CREATED)
async def create_workflow_node(
    instance_id: str,
    node_data: WorkflowNodeCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create workflow node

    Adds a node to existing workflow instance.
    Node is instantiated from AppTemplate (app type) or JobTemplate (job type).

    Note:
    - Different nodes have no dependency relationship, no depends_on needed
    - env_vars and volume_mounts are used to satisfy template's dependency requirements
      when instantiating the template
    - Validates whether the provided env_vars and volume_mounts satisfy the template's
      required dependencies. If not satisfied, returns which dependencies conditions are not met.
    """
    # Get workflow instance
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()
    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to add node to this instance")

    # Check workflow is in pending state for adding nodes
    if instance.status != WorkflowStatus.PENDING:
        raise ValidationError(f"Cannot add node to instance in status: {instance.status}. Only pending state allows modification.")

    # Validate template exists and user has access
    node_type_val = node_data.node_type.value if hasattr(node_data.node_type, 'value') else node_data.node_type
    template_id = node_data.template_id

    if node_type_val == "app":
        template = db.query(AppTemplate).filter(AppTemplate.id == template_id).first()
        if not template:
            raise NotFoundError("App template", template_id)
        if template.scope != "global" and template.created_by != user_id:
            raise ForbiddenError(f"No permission to use app template {template_id}")
    else:  # job
        template = db.query(JobTemplate).filter(JobTemplate.id == template_id).first()
        if not template:
            raise NotFoundError("Job template", template_id)
        if template.scope != "global" and template.created_by != user_id:
            raise ForbiddenError(f"No permission to use job template {template_id}")

    # Validate template dependencies (env_vars and volume_mounts must satisfy template's requirements)
    unsatisfied_dependencies = validate_template_dependencies(template, node_data)
    if unsatisfied_dependencies:
        raise ValidationError(
            f"Template dependencies not satisfied: {unsatisfied_dependencies}",
            details=unsatisfied_dependencies
        )

    # Generate node instance ID - this will be both id and node_id
    node_instance_id = generate_id(f"{instance_id}_{node_data.name}")

    # Convert node config to dict
    if hasattr(node_data, 'model_dump'):
        node_config = node_data.model_dump()
    else:
        node_config = node_data.dict()

    resolved_volume_mounts, raw_volume_mounts, normalized_project_mounts = await resolve_requested_volume_mounts(
        instance.project_id,
        node_config.get("volume_mounts"),
        node_config.get("project_file_mounts"),
        current_user.get("token"),
    )
    node_config["volume_mounts"] = raw_volume_mounts
    node_config["project_file_mounts"] = normalized_project_mounts

    # Note: Different nodes have no dependency relationship, depends_on is always empty
    depends_on = []

    # Create node instance
    node_instance = WorkflowNodeInstance(
        id=node_instance_id,
        instance_id=instance_id,
        node_id=node_instance_id,  # Same as id
        node_type=NodeType.APP if node_type_val == "app" else NodeType.JOB,
        template_id=template_id,
        name=node_data.name,
        status=NodeStatus.PENDING,
        position=node_data.position,
        env_vars=[e.model_dump() if hasattr(e, 'model_dump') else e.dict() for e in (node_data.env_vars or [])],
        volume_mounts=resolved_volume_mounts,
        resources=node_data.resources.model_dump() if node_data.resources and hasattr(node_data.resources, 'model_dump') else (node_data.resources.dict() if node_data.resources else None),
        depends_on=depends_on,
        downstream_node_ids=[],  # Will be rebuilt from edges
        timeout_seconds=node_data.timeout_seconds,
        input_env_vars=[],
        input_volume_mounts=[],
        service_name=None,
        # Ingress configuration (for app type nodes)
        ingress_type=getattr(node_data, 'ingress_type', None) if node_type_val == "app" else None,
        ingress_host=getattr(node_data, 'ingress_host', None) if node_type_val == "app" else None,
        ingress_ip=getattr(node_data, 'ingress_ip', None) if node_type_val == "app" else None,
    )
    db.add(node_instance)

    # Add node to instance nodes list
    node_config["status"] = NodeStatus.PENDING
    node_config["id"] = node_instance_id
    node_config["node_id"] = node_instance_id  # For backward compatibility
    node_config["depends_on"] = depends_on
    node_config["downstream_node_ids"] = []
    node_config["input_env_vars"] = []
    node_config["input_volume_mounts"] = []
    existing_nodes = instance.nodes or []
    existing_nodes.append(node_config)
    instance.nodes = existing_nodes

    # Mark nodes field as modified for SQLAlchemy to detect the change
    from sqlalchemy.orm.attributes import flag_modified
    flag_modified(instance, "nodes")

    db.commit()

    # Rebuild node relationships (depends_on and downstream_node_ids) from edges
    all_nodes = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.instance_id == instance_id
    ).all()
    if all_nodes and instance.edges:
        build_node_relationships(all_nodes, instance.edges)
        db.commit()

    db.refresh(node_instance)

    logger.info(f"Created workflow node {node_instance_id} in instance {instance_id}")
    return build_node_response(node_instance, instance)


def validate_template_dependencies(template, node_data: WorkflowNodeCreate) -> List[Dict[str, Any]]:
    """
    Validate whether the provided env_vars and volume_mounts satisfy the template's requirements.

    Returns a list of unsatisfied dependencies details, or empty list if all satisfied.
    """
    unsatisfied = []

    # Get template containers
    template_containers = template.containers or []

    # Get node's env_vars and volume_mounts
    node_env_vars = node_data.env_vars or []
    node_volume_mounts = list(node_data.volume_mounts or [])
    for project_mount in getattr(node_data, "project_file_mounts", []) or []:
        node_volume_mounts.append(project_mount)

    # Convert to dict for easier lookup
    node_env_vars_dict = {e.name: e.value for e in node_env_vars}
    node_volume_mounts_dict = {vm.mount_path: vm for vm in node_volume_mounts}

    # Check each container's dependencies
    for container in template_containers:
        # Check input_env_vars (template requires these env vars from upstream)
        input_env_vars = container.get("input_env_vars", [])
        for req_env in input_env_vars:
            env_name = req_env.get("name")
            # Check if this env var is provided in node's env_vars
            if env_name not in node_env_vars_dict:
                unsatisfied.append({
                    "type": "env_var",
                    "container": container.get("name"),
                    "name": env_name,
                    "message": f"Container '{container.get('name')}' requires env_var '{env_name}' but not provided"
                })

        # Check input_volume_mounts (template requires these mounts from upstream)
        input_volume_mounts = container.get("input_volume_mounts", [])
        for req_mount in input_volume_mounts:
            mount_path = req_mount.get("mount_path")
            # Check if this mount path is provided in node's volume_mounts
            if mount_path not in node_volume_mounts_dict:
                unsatisfied.append({
                    "type": "volume_mount",
                    "container": container.get("name"),
                    "mount_path": mount_path,
                    "message": f"Container '{container.get('name')}' requires volume_mount at '{mount_path}' but not provided"
                })

    return unsatisfied


@router.get("/{instance_id}/nodes", response_model=List[WorkflowNodeInstanceResponse])
async def list_workflow_nodes(
    instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all nodes in a workflow instance"""
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to access this instance")

    nodes = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.instance_id == instance_id
    ).all()

    return [build_node_response(node, instance) for node in nodes]


@router.get("/{instance_id}/nodes/{node_instance_id}", response_model=WorkflowNodeInstanceResponse)
async def get_workflow_node(
    instance_id: str,
    node_instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get workflow node details"""
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to access this instance")

    node = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.id == node_instance_id,
        WorkflowNodeInstance.instance_id == instance_id
    ).first()

    if not node:
        raise NotFoundError("Workflow node", node_instance_id)

    return build_node_response(node, instance)


@router.get("/{instance_id}/nodes/{node_instance_id}/access-info", summary="获取节点访问服务信息")
async def get_workflow_node_access_info(
    instance_id: str,
    node_instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """通过 workflow 微服务获取节点 Service/Ingress 访问信息。"""
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()
    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to access this instance")

    node = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.id == node_instance_id,
        WorkflowNodeInstance.instance_id == instance_id
    ).first()
    if not node:
        raise NotFoundError("Workflow node", node_instance_id)
    node_config = get_instance_node_config(instance, node_instance_id)
    runtime_service_name = resolve_runtime_service_name(node, node_config)
    if not runtime_service_name:
        raise ValidationError("This node has no active K8S service configured")

    access_info = await get_status_client().get_service_access_info(instance.project_id, runtime_service_name)
    access_info.setdefault("ingress_accesses", [])
    access_info.setdefault("access_urls", [])
    domain_bindings = db.query(WorkflowNodeDomainBinding).filter(
        WorkflowNodeDomainBinding.instance_id == instance.id,
        WorkflowNodeDomainBinding.node_instance_id == node.id,
    ).order_by(WorkflowNodeDomainBinding.updated_at.desc()).all()

    configured_ingress = {
        "create_ingress": node_config.get("create_ingress", bool(node.ingress_type or node.ingress_host or node.ingress_ip)),
        "ingress_type": node_config.get("ingress_type") or node.ingress_type,
        "ingress_host": node_config.get("ingress_host") or node.ingress_host,
        "ingress_ip": node_config.get("ingress_ip") or node.ingress_ip,
    }

    fallback_binding = domain_bindings[0] if domain_bindings else None
    fallback_host = (
        (fallback_binding.domain if fallback_binding else None)
        or configured_ingress.get("ingress_host")
    )
    fallback_ip = (
        (fallback_binding.ingress_ip if fallback_binding else None)
        or configured_ingress.get("ingress_ip")
    )
    fallback_type = (
        (fallback_binding.ingress_type if fallback_binding else None)
        or configured_ingress.get("ingress_type")
        or "nginx"
    )

    # If K8s introspection misses the Ingress, fall back to the saved binding record
    # or node config so the UI can still show the expected domain-based access info.
    if configured_ingress.get("create_ingress") and fallback_host and not access_info["ingress_accesses"]:
        host = fallback_host
        ingress_name = (
            (fallback_binding.ingress_name if fallback_binding else None)
            or resolve_node_ingress_name(node, node_config)
        )
        access_url = resolve_ingress_access_url(node_config, host, "/")
        ingress_item = {
            "ingress_name": ingress_name,
            "ingress_class_name": fallback_type,
            "host": host,
            "path": "/",
            "path_type": "Prefix",
            "service_name": runtime_service_name,
            "service_port": fallback_binding.service_port if fallback_binding else None,
            "selected_ip": fallback_ip,
            "url": access_url,
            "source": "binding_record" if fallback_binding else "configured",
        }
        access_info["ingress_accesses"].append(ingress_item)

        if not any(
            (item.get("type") == "Ingress" and item.get("host") == host)
            for item in access_info["access_urls"]
        ):
            access_info["access_urls"].append(
                {
                    "type": "Ingress",
                    "port_name": runtime_service_name,
                    "url": access_url,
                    "host": host,
                    "path": "/",
                    "selected_ip": fallback_ip,
                    "ingress_name": ingress_name,
                    "source": "binding_record" if fallback_binding else "configured",
                }
            )

    access_info["node_id"] = node.id
    access_info["node_name"] = node.name
    access_info["configured_ingress"] = configured_ingress
    access_info["domain_bindings"] = [binding.to_dict() for binding in domain_bindings]
    return access_info


@router.get(
    "/{instance_id}/nodes/{node_instance_id}/domain-bindings",
    response_model=List[WorkflowNodeDomainBindingResponse],
    summary="获取节点域名绑定记录",
)
async def list_workflow_node_domain_bindings(
    instance_id: str,
    node_instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()
    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to access this instance")

    node = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.id == node_instance_id,
        WorkflowNodeInstance.instance_id == instance_id
    ).first()
    if not node:
        raise NotFoundError("Workflow node", node_instance_id)

    records = db.query(WorkflowNodeDomainBinding).filter(
        WorkflowNodeDomainBinding.instance_id == instance_id,
        WorkflowNodeDomainBinding.node_instance_id == node_instance_id,
    ).order_by(WorkflowNodeDomainBinding.updated_at.desc()).all()

    return [WorkflowNodeDomainBindingResponse(**record.to_dict()) for record in records]


@router.post("/{instance_id}/nodes/{node_instance_id}/ingress-binding", response_model=WorkflowNodeInstanceResponse, summary="绑定节点 Ingress 域名")
async def bind_workflow_node_ingress(
    instance_id: str,
    node_instance_id: str,
    request: WorkflowNodeIngressBindingRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """保存节点域名配置，并在已初始化时同步到 k8s 微服务。"""
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()
    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to update this instance")

    node = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.id == node_instance_id,
        WorkflowNodeInstance.instance_id == instance_id
    ).first()
    if not node:
        raise NotFoundError("Workflow node", node_instance_id)
    if node.node_type != NodeType.APP:
        raise ValidationError("Only APP nodes support ingress binding")

    node_config = get_instance_node_config(instance, node_instance_id)
    if not node_config:
        raise NotFoundError("Workflow node config", node_instance_id)

    node_config["create_ingress"] = request.create_ingress
    node_config["ingress_type"] = request.ingress_type
    node_config["ingress_host"] = request.ingress_host
    node_config["ingress_ip"] = request.ingress_ip
    if not request.create_ingress:
        node_config["ingress_name"] = None
        node_config["ingress_access_url"] = None
        node_config["ingress_tls_enabled"] = None
    node.ingress_type = request.ingress_type
    node.ingress_host = request.ingress_host
    node.ingress_ip = request.ingress_ip

    runtime_service_name = resolve_runtime_service_name(node, node_config)
    if node.k8s_resource_name and runtime_service_name:
        service_ports = node_config.get("service_ports") or []
        if not service_ports:
            raise ValidationError("service_ports cannot be empty when binding ingress")
        service_port = service_ports[0].get("port") or service_ports[0].get("target_port")
        ingress_name = resolve_node_ingress_name(node, node_config)
        if not ingress_name:
            raise ValidationError("ingress_name is missing for this initialized node")
        await get_status_client().bind_ingress_domain(
            project_id=instance.project_id,
            ingress_name=ingress_name,
            service_name=runtime_service_name,
            service_port=service_port,
            host=request.ingress_host,
            ingress_type=request.ingress_type,
            ingress_ip=request.ingress_ip,
            path=request.path,
            path_type=request.path_type,
        )
        _, target_port = get_primary_service_ports(node_config)
        upsert_node_domain_binding(
            db,
            instance,
            node,
            domain=request.ingress_host,
            ingress_ip=request.ingress_ip,
            ingress_type=request.ingress_type,
            service_name=runtime_service_name,
            service_port=service_port,
            target_port=target_port,
            ingress_name=ingress_name,
            binding_status="active",
            message="Ingress domain bound successfully",
        )
    else:
        service_port, target_port = get_primary_service_ports(node_config)
        upsert_node_domain_binding(
            db,
            instance,
            node,
            domain=request.ingress_host,
            ingress_ip=request.ingress_ip,
            ingress_type=request.ingress_type,
            service_name=runtime_service_name,
            service_port=service_port,
            target_port=target_port,
            ingress_name=node_config.get("ingress_name"),
            binding_status="configured",
            message="Ingress config saved, waiting for node initialization",
        )

    from sqlalchemy.orm.attributes import flag_modified
    flag_modified(instance, "nodes")
    db.commit()
    db.refresh(node)
    return build_node_response(node, instance)


@router.put("/{instance_id}/nodes/{node_instance_id}", response_model=WorkflowNodeInstanceResponse)
async def update_workflow_node(
    instance_id: str,
    node_instance_id: str,
    node_data: WorkflowNodeUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update workflow node configuration"""
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to update this instance")

    if instance.status != WorkflowStatus.PENDING:
        raise ValidationError(f"Cannot update node in instance status: {instance.status}. Only pending state allows modification.")

    node = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.id == node_instance_id,
        WorkflowNodeInstance.instance_id == instance_id
    ).first()

    if not node:
        raise NotFoundError("Workflow node", node_instance_id)

    current_node_config = get_instance_node_config(instance, node_instance_id)
    effective_volume_mounts = node_data.volume_mounts if node_data.volume_mounts is not None else current_node_config.get("volume_mounts", node.volume_mounts or [])
    effective_project_file_mounts = node_data.project_file_mounts if node_data.project_file_mounts is not None else current_node_config.get("project_file_mounts", [])

    resolved_volume_mounts: Optional[List[Dict[str, Any]]] = None
    raw_volume_mounts: Optional[List[Dict[str, Any]]] = None
    normalized_project_mounts: Optional[List[Dict[str, Any]]] = None
    if node_data.volume_mounts is not None or node_data.project_file_mounts is not None:
        resolved_volume_mounts, raw_volume_mounts, normalized_project_mounts = await resolve_requested_volume_mounts(
            instance.project_id,
            effective_volume_mounts,
            effective_project_file_mounts,
            current_user.get("token"),
        )

    # Update node instance fields
    if node_data.name is not None:
        node.name = node_data.name
    if node_data.position is not None:
        node.position = node_data.position
    if node_data.env_vars is not None:
        node.env_vars = [e.model_dump() if hasattr(e, 'model_dump') else e.dict() for e in node_data.env_vars]
    if resolved_volume_mounts is not None:
        node.volume_mounts = resolved_volume_mounts
    if node_data.resources is not None:
        node.resources = node_data.resources.model_dump() if hasattr(node_data.resources, 'model_dump') else node_data.resources.dict()
    if node_data.input_env_vars is not None:
        node.input_env_vars = [iev.model_dump() if hasattr(iev, 'model_dump') else iev.dict() for iev in node_data.input_env_vars]
    if node_data.input_volume_mounts is not None:
        node.input_volume_mounts = [ivm.model_dump() if hasattr(ivm, 'model_dump') else ivm.dict() for ivm in node_data.input_volume_mounts]
    if node_data.create_service is False:
        node.service_name = None
    if node_data.create_ingress is False:
        node.ingress_type = None
        node.ingress_host = None
        node.ingress_ip = None
    else:
        if node_data.ingress_type is not None:
            node.ingress_type = node_data.ingress_type
        if node_data.ingress_host is not None:
            node.ingress_host = node_data.ingress_host
        if node_data.ingress_ip is not None:
            node.ingress_ip = node_data.ingress_ip

    # Update node in instance nodes list
    existing_nodes = instance.nodes or []
    for existing_node in existing_nodes:
        if existing_node.get("id") == node_instance_id:
            if node_data.name is not None:
                existing_node["name"] = node_data.name
            if node_data.position is not None:
                existing_node["position"] = node_data.position
            if node_data.env_vars is not None:
                existing_node["env_vars"] = [e.model_dump() if hasattr(e, 'model_dump') else e.dict() for e in node_data.env_vars]
            if raw_volume_mounts is not None:
                existing_node["volume_mounts"] = raw_volume_mounts
            if normalized_project_mounts is not None:
                existing_node["project_file_mounts"] = normalized_project_mounts
            if node_data.resources is not None:
                existing_node["resources"] = node_data.resources.model_dump() if hasattr(node_data.resources, 'model_dump') else node_data.resources.dict()
            if node_data.input_env_vars is not None:
                existing_node["input_env_vars"] = [iev.model_dump() if hasattr(iev, 'model_dump') else iev.dict() for iev in node_data.input_env_vars]
            if node_data.input_volume_mounts is not None:
                existing_node["input_volume_mounts"] = [ivm.model_dump() if hasattr(ivm, 'model_dump') else ivm.dict() for ivm in node_data.input_volume_mounts]
            # Update service configuration
            if node_data.create_service is not None:
                existing_node["create_service"] = node_data.create_service
                if node_data.create_service is False:
                    existing_node["service_name"] = None
                    existing_node["k8s_service_name"] = None
                    existing_node["service_ports"] = []
                    existing_node["service_type"] = None
                    existing_node["create_ingress"] = False
                    existing_node["ingress_type"] = None
                    existing_node["ingress_host"] = None
                    existing_node["ingress_ip"] = None
                    existing_node["ingress_name"] = None
                    existing_node["ingress_access_url"] = None
                    existing_node["ingress_tls_enabled"] = None
            if node_data.service_name is not None:
                existing_node["service_name"] = node_data.service_name
            if node_data.service_ports is not None:
                existing_node["service_ports"] = [sp.model_dump() if hasattr(sp, 'model_dump') else sp.dict() for sp in node_data.service_ports]
            if node_data.service_type is not None:
                existing_node["service_type"] = node_data.service_type.value if hasattr(node_data.service_type, 'value') else node_data.service_type
            # Update ingress configuration
            if node_data.create_ingress is not None:
                existing_node["create_ingress"] = node_data.create_ingress
                if node_data.create_ingress is False:
                    existing_node["ingress_type"] = None
                    existing_node["ingress_host"] = None
                    existing_node["ingress_ip"] = None
            if node_data.ingress_type is not None:
                existing_node["ingress_type"] = node_data.ingress_type
            if node_data.ingress_host is not None:
                existing_node["ingress_host"] = node_data.ingress_host
            if node_data.ingress_ip is not None:
                existing_node["ingress_ip"] = node_data.ingress_ip
            break
    instance.nodes = existing_nodes

    # Mark nodes field as modified for SQLAlchemy to detect the change
    from sqlalchemy.orm.attributes import flag_modified
    flag_modified(instance, "nodes")

    latest_node_config = get_instance_node_config(instance, node_instance_id)
    latest_create_ingress = latest_node_config.get(
        "create_ingress",
        bool(node.ingress_type or node.ingress_host or node.ingress_ip),
    )
    latest_domain = latest_node_config.get("ingress_host") or node.ingress_host
    if not latest_create_ingress or not latest_domain:
        delete_node_domain_bindings(db, instance_id, node_instance_id)
    else:
        service_port, target_port = get_primary_service_ports(latest_node_config)
        upsert_node_domain_binding(
            db,
            instance,
            node,
            domain=latest_domain,
            ingress_ip=latest_node_config.get("ingress_ip") or node.ingress_ip,
            ingress_type=latest_node_config.get("ingress_type") or node.ingress_type,
            service_name=resolve_runtime_service_name(node, latest_node_config),
            service_port=service_port,
            target_port=target_port,
            binding_status="configured",
            message="Ingress config saved on workflow node",
        )

    db.commit()
    db.refresh(node)

    logger.info(f"Updated workflow node {node_instance_id} in instance {instance_id}")
    return build_node_response(node, instance)


@router.delete("/{instance_id}/nodes/{node_instance_id}", response_model=SuccessResponse)
async def delete_workflow_node(
    instance_id: str,
    node_instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete workflow node

    Note: Only delete nodes in pending state, not allowed after initialization
    """
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to delete node from this instance")

    if instance.status != WorkflowStatus.PENDING:
        raise ValidationError(f"Cannot delete node from instance in status: {instance.status}. Only pending state allows modification.")

    node = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.id == node_instance_id,
        WorkflowNodeInstance.instance_id == instance_id
    ).first()

    if not node:
        raise NotFoundError("Workflow node", node_instance_id)

    # Remove node from instance nodes list
    existing_nodes = instance.nodes or []
    instance.nodes = [n for n in existing_nodes if n.get("id") != node_instance_id]

    # Mark nodes field as modified for SQLAlchemy to detect the change
    from sqlalchemy.orm.attributes import flag_modified
    flag_modified(instance, "nodes")

    # Delete node instance
    delete_node_domain_bindings(db, instance_id, node_instance_id)
    db.delete(node)
    db.commit()

    # Rebuild node relationships after deletion
    all_nodes = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.instance_id == instance_id
    ).all()
    if all_nodes:
        # Reset and rebuild from edges
        for n in all_nodes:
            n.depends_on = []
            n.downstream_node_ids = []
        if instance.edges:
            build_node_relationships(all_nodes, instance.edges)
            db.commit()

    logger.info(f"Deleted workflow node {node_instance_id} from instance {instance_id}")
    return SuccessResponse(message=f"Workflow node {node_instance_id} deleted successfully")


# ============ Workflow Edge Operations ============

@router.post("/{instance_id}/edges", response_model=WorkflowInstanceResponse)
async def update_workflow_edge(
    instance_id: str,
    edge_data: WorkflowEdgesUpdateRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update workflow edge (add/update/delete)

    - action: "add" - add new edge
    - action: "update" - update existing edge
    - action: "delete" - delete edge
    """
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to update this instance")

    if instance.status != WorkflowStatus.PENDING:
        raise ValidationError(f"Cannot update edges in instance status: {instance.status}. Only pending state allows modification.")

    existing_edges = instance.edges or []
    action = edge_data.action

    if action == "add":
        # Add new edge
        if not edge_data.edge_id or not edge_data.source or not edge_data.target:
            raise ValidationError("edge_id, source, target are required for add action")

        # Validate source and target nodes exist (from WorkflowNodeInstance table)
        existing_nodes = db.query(WorkflowNodeInstance).filter(
            WorkflowNodeInstance.instance_id == instance_id
        ).all()
        node_ids = [n.id for n in existing_nodes]
        if edge_data.source not in node_ids:
            raise ValidationError(f"Source node {edge_data.source} does not exist")
        if edge_data.target not in node_ids:
            raise ValidationError(f"Target node {edge_data.target} does not exist")

        new_edge = {
            "edge_id": edge_data.edge_id,
            "source": edge_data.source,
            "target": edge_data.target,
            "shared_pvc": edge_data.shared_pvc
        }
        existing_edges.append(new_edge)

    elif action == "update":
        # Update existing edge
        if not edge_data.edge_id:
            raise ValidationError("edge_id is required for update action")

        for edge in existing_edges:
            if edge.get("edge_id") == edge_data.edge_id:
                if edge_data.source is not None:
                    edge["source"] = edge_data.source
                if edge_data.target is not None:
                    edge["target"] = edge_data.target
                if edge_data.shared_pvc is not None:
                    edge["shared_pvc"] = edge_data.shared_pvc
                break
        else:
            raise NotFoundError("Workflow edge", edge_data.edge_id)

    elif action == "delete":
        # Delete edge
        if not edge_data.edge_id:
            raise ValidationError("edge_id is required for delete action")

        existing_edges = [e for e in existing_edges if e.get("edge_id") != edge_data.edge_id]
    else:
        raise ValidationError(f"Invalid action: {action}. Valid actions are: add, update, delete")

    instance.edges = existing_edges
    from sqlalchemy.orm.attributes import flag_modified
    flag_modified(instance, "edges")
    db.commit()

    # Rebuild node relationships (depends_on and downstream_node_ids) from updated edges
    all_nodes = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.instance_id == instance_id
    ).all()
    if all_nodes:
        # Reset relationships first
        for node in all_nodes:
            node.depends_on = []
            node.downstream_node_ids = []
        # Rebuild from edges
        build_node_relationships(all_nodes, existing_edges)
        db.commit()

    db.refresh(instance)

    logger.info(f"Updated workflow edges in instance {instance_id}, action: {action}")
    return build_instance_response(instance, db)


# ============ Callback API (for workflow-status service) ============

# Status mapping: workflow-status status -> workflow NodeStatus
STATUS_MAPPING = {
    "pending": NodeStatus.PENDING,
    "Pending": NodeStatus.PENDING,
    "not_ready": NodeStatus.NOT_READY,
    "Not_ready": NodeStatus.NOT_READY,
    "ready": NodeStatus.READY,
    "Ready": NodeStatus.READY,
    "running": NodeStatus.RUNNING,
    "Running": NodeStatus.RUNNING,
    "succeeded": NodeStatus.SUCCEEDED,
    "Succeeded": NodeStatus.SUCCEEDED,
    "failed": NodeStatus.FAILED,
    "Failed": NodeStatus.FAILED,
    "stopped": NodeStatus.STOPPED,
    "Stopped": NodeStatus.STOPPED,
}


@router.post("/callback/status", response_model=NodeStatusCallbackResponse, summary="Receive node status callback")
async def receive_node_status_callback(
    request: NodeStatusCallbackRequest,
    db: Session = Depends(get_db)
):
    """
    Receive node status callback from workflow-status service.

    This endpoint is idempotent: repeated callbacks with the same status
    will not trigger duplicated updates.
    """
    node = db.query(WorkflowNodeInstance).filter(
        or_(
            WorkflowNodeInstance.id == request.node_id,
            WorkflowNodeInstance.node_id == request.node_id,
        )
    ).first()

    if not node:
        logger.warning(f"Callback received for non-existent node: {request.node_id}")
        raise NotFoundError("Workflow node instance", request.node_id)

    if node.instance_id != request.instance_id:
        logger.warning(
            f"Callback instance_id mismatch: node {request.node_id} "
            f"belongs to {node.instance_id}, callback={request.instance_id}"
        )
        raise ValidationError(f"instance_id mismatch: node belongs to {node.instance_id}")

    new_status = STATUS_MAPPING.get(request.status)
    if not new_status:
        logger.warning(f"Unknown status in callback: {request.status}")
        raise ValidationError(f"Unknown status: {request.status}")

    if node.status == new_status:
        return NodeStatusCallbackResponse(
            success=True,
            node_id=request.node_id,
            status=node.status,
            message="Status unchanged (idempotent)"
        )

    old_status = node.status
    node.status = new_status
    if request.started_at:
        node.started_at = request.started_at
    if request.finished_at:
        node.finished_at = request.finished_at
    if request.message:
        node.message = request.message

    # Keep workflow instance status aligned with latest node cache.
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == node.instance_id).first()
    if instance:
        instance_nodes = db.query(WorkflowNodeInstance).filter(
            WorkflowNodeInstance.instance_id == node.instance_id
        ).all()
        app_nodes = [n for n in instance_nodes if n.node_type == NodeType.APP]
        if app_nodes:
            if all(n.status == NodeStatus.READY for n in app_nodes):
                instance.status = WorkflowStatus.READY
            elif all(n.status == NodeStatus.PENDING for n in app_nodes):
                instance.status = WorkflowStatus.PENDING
            else:
                instance.status = WorkflowStatus.UNREADY
        else:
            job_nodes = [n for n in instance_nodes if n.node_type == NodeType.JOB]
            if job_nodes and all(n.status == NodeStatus.SUCCEEDED for n in job_nodes):
                instance.status = WorkflowStatus.READY
            elif job_nodes and all(n.status == NodeStatus.PENDING for n in job_nodes):
                instance.status = WorkflowStatus.PENDING
            else:
                instance.status = WorkflowStatus.UNREADY if job_nodes else WorkflowStatus.PENDING

    db.commit()
    db.refresh(node)

    logger.info(f"Node status updated via callback: {request.node_id} {old_status} -> {new_status}")
    return NodeStatusCallbackResponse(
        success=True,
        node_id=request.node_id,
        status=node.status,
        message=f"Status updated from {old_status} to {new_status}"
    )
