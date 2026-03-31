"""
Single Application Workflow API routes
A simplified workflow for single APP-type node with combined creation
"""
import asyncio
import logging
from datetime import datetime
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.api.dependencies import get_current_user, generate_id
from app.api.workflow_instances import (
    build_workflow_deployment_name,
    build_workflow_service_resource_name,
    get_instance_node_config,
    get_primary_service_ports,
    build_workflow_ingress_host_prefix,
    resolve_ingress_access_url,
    resolve_node_ingress_name,
    resolve_runtime_service_name,
    resolve_requested_volume_mounts,
    upsert_node_domain_binding,
    delete_node_domain_bindings,
)
from app.models import (
    get_db, WorkflowInstance, WorkflowNodeInstance,
    WorkflowStatus, NodeStatus, NodeType, AppTemplate,
    WorkflowSyncRecord, WorkflowNodeDomainBinding
)
from app.schemas import (
    AppWorkflowCreate, AppWorkflowUpdate,
    AppWorkflowResponse, AppWorkflowListResponse,
    AppWorkflowNodeResponse,
    AppWorkflowLlmBindingRequest,
    SuccessResponse,
    WorkflowNodeIngressBindingRequest,
    WorkflowNodeDomainBindingResponse,
)
from app.exception import NotFoundError, ForbiddenError, ValidationError, InternalError
from app.services.configcenter_client import get_configcenter_client
from app.services.workflow_status_client import get_workflow_status_client
from app.config import get_config

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/app-workflows", tags=["App Workflows"])


def get_status_client():
    """Get workflow-status client, fail fast when disabled."""
    config = get_config()
    if not config.workflow_status_service or not config.workflow_status_service.enabled:
        raise InternalError("workflow-status service is required but disabled")
    return get_workflow_status_client()


def check_instance_permission(instance: WorkflowInstance, user_id: str) -> bool:
    """Check if user has permission to access workflow instance"""
    # Backward compatibility:
    # historical instances were created by service account "system".
    # These instances should remain accessible after project-scoped listing.
    if instance.created_by == user_id:
        return True
    if instance.created_by == "system":
        return True
    return False


def get_configcenter_client_or_fail():
    """Get config center client, fail fast when disabled."""
    config = get_config()
    if not config.configcenter_service or not config.configcenter_service.enabled:
        raise InternalError("config center service is required but disabled")
    return get_configcenter_client()


async def resolve_llm_binding(
    binding: Optional[AppWorkflowLlmBindingRequest],
) -> Optional[Dict[str, Any]]:
    """Resolve and validate llm binding payload into a persisted snapshot."""
    if binding is None:
        return None

    if binding.source.value == "config_center":
        provider_key = (binding.provider_key or "").strip()
        provider_detail = await get_configcenter_client_or_fail().get_llm_provider(provider_key)
        return {
            "source": "config_center",
            "provider_key": provider_detail["provider_key"],
            "config": provider_detail,
            "bound_at": datetime.utcnow().isoformat(),
        }

    if binding.config is None:
        raise ValidationError("custom llm config is required")

    config_payload = binding.config.model_dump(mode="json")
    return {
        "source": "custom",
        "provider_key": config_payload["provider_key"],
        "config": config_payload,
        "bound_at": datetime.utcnow().isoformat(),
    }


def build_app_workflow_response(
    instance: WorkflowInstance,
    node: WorkflowNodeInstance,
    template: Optional[AppTemplate] = None
) -> Dict[str, Any]:
    """Build single app workflow response"""
    node_config = get_instance_node_config(instance, node.id)
    display_service_name = node_config.get("service_name") or node.service_name
    ingress_type = node_config.get("ingress_type") or node.ingress_type
    ingress_host = node_config.get("ingress_host") or node.ingress_host
    ingress_ip = node_config.get("ingress_ip") or node.ingress_ip
    ingress_name = resolve_node_ingress_name(node, node_config)
    create_ingress = node_config.get("create_ingress")
    if create_ingress is None:
        create_ingress = bool(ingress_type or ingress_host or ingress_ip)
    create_service = node_config.get("create_service")
    if create_service is None:
        create_service = True
    llm_binding = node_config.get("llm_binding")

    return {
        "id": instance.id,
        "name": instance.name,
        "description": instance.description,
        "project_id": instance.project_id,
        "status": instance.status,
        "workflow_type": "simple_app",
        "node": {
            "id": node.id,
            "name": node.name,
            "node_type": node.node_type,
            "template_id": node.template_id,
            "status": node.status,
            "k8s_resource_name": node.k8s_resource_name,
            "k8s_resource_type": node.k8s_resource_type,
            "service_name": display_service_name,
            "message": node.message,
            "started_at": node.started_at.isoformat() if node.started_at else None,
            "finished_at": node.finished_at.isoformat() if node.finished_at else None,
            "created_at": node.created_at.isoformat() if node.created_at else None,
            "env_vars": node.env_vars or [],
            "volume_mounts": node_config.get("volume_mounts", node.volume_mounts or []),
            "project_file_mounts": node_config.get("project_file_mounts", []),
            "resources": node.resources,
            "timeout_seconds": node.timeout_seconds,
            "create_service": create_service,
            "create_ingress": create_ingress,
            "service_ports": node_config.get("service_ports", []),
            "service_type": node_config.get("service_type"),
            "ingress_type": ingress_type,
            "ingress_host": ingress_host,
            "ingress_ip": ingress_ip,
            "ingress_name": ingress_name,
            "ingress_access_url": node_config.get("ingress_access_url"),
            "ingress_tls_enabled": node_config.get("ingress_tls_enabled"),
            "llm_binding": llm_binding,
            "init_logs": node.init_logs,
        },
        "service_name": display_service_name,
        "service_ports": node_config.get("service_ports", []),
        "service_type": node_config.get("service_type"),
        "replicas": node_config.get("replicas"),
        "env_vars": node.env_vars or [],
        "volume_mounts": node_config.get("volume_mounts", node.volume_mounts or []),
        "project_file_mounts": node_config.get("project_file_mounts", []),
        "resources": node.resources,
        "create_service": create_service,
        "create_ingress": create_ingress,
        "ingress_type": ingress_type,
        "ingress_host": ingress_host,
        "ingress_ip": ingress_ip,
        "ingress_name": ingress_name,
        "ingress_access_url": node_config.get("ingress_access_url"),
        "ingress_tls_enabled": node_config.get("ingress_tls_enabled"),
        "llm_binding": llm_binding,
        "template_id": node.template_id,
        "template_name": template.name if template else None,
        "created_by": instance.created_by,
        "created_at": instance.created_at.isoformat() if instance.created_at else None,
        "updated_at": instance.updated_at.isoformat() if instance.updated_at else None,
        "started_at": instance.started_at.isoformat() if instance.started_at else None,
        "finished_at": instance.finished_at.isoformat() if instance.finished_at else None,
        "message": instance.message,
    }


def build_app_access_info_payload(
    instance: WorkflowInstance,
    node: WorkflowNodeInstance,
    node_config: Dict[str, Any],
    access_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a resilient access-info payload for one app workflow."""
    display_service_name = node_config.get("service_name") or node.service_name
    service_ports = node_config.get("service_ports") or []
    base_payload = access_info or {}
    base_payload.setdefault("name", display_service_name)
    base_payload.setdefault("type", node_config.get("service_type") or "ClusterIP")
    base_payload.setdefault("cluster_ip", None)
    base_payload.setdefault("namespace", f"secflow-{instance.project_id}")
    base_payload.setdefault("ports", [])
    base_payload.setdefault("access_urls", [])
    base_payload.setdefault("ingress_accesses", [])

    if not base_payload["ports"] and service_ports:
        base_payload["ports"] = [
            {
                "name": port.get("name"),
                "protocol": port.get("protocol", "TCP"),
                "port": port.get("port"),
                "target_port": port.get("target_port", port.get("targetPort")),
                "node_port": port.get("node_port"),
            }
            for port in service_ports
        ]

    return base_payload


def get_app_workflow_instance(
    db: Session,
    instance_id: str,
) -> WorkflowInstance:
    instance = db.query(WorkflowInstance).filter(
        WorkflowInstance.id == instance_id,
        WorkflowInstance.run_mode == "simple_app"
    ).first()
    if not instance:
        raise NotFoundError("App workflow", instance_id)
    return instance


def get_app_workflow_node(
    db: Session,
    instance_id: str,
) -> WorkflowNodeInstance:
    node = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.instance_id == instance_id
    ).first()
    if not node:
        raise InternalError(f"Workflow node not found for instance {instance_id}")
    return node


def sync_app_instance_status_from_node(
    instance: WorkflowInstance,
    node: WorkflowNodeInstance,
) -> None:
    """Keep app instance status aligned with node status and resource existence."""
    if not node.k8s_resource_name:
        instance.status = WorkflowStatus.PENDING
        instance.message = "Workflow is pending initialization"
        return

    if node.status == NodeStatus.READY:
        instance.status = WorkflowStatus.READY
        instance.message = "Workflow is ready"
        return

    instance.status = WorkflowStatus.UNREADY
    instance.message = "Workflow is unready"


# ============ Create App Workflow ============

@router.post("", response_model=AppWorkflowResponse, status_code=status.HTTP_201_CREATED)
async def create_app_workflow(
    workflow_data: AppWorkflowCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    创建单应用工作流

    将工作流创建和节点创建合并为一个原子操作。
    必须通过template_id引用已存在的应用模板。

    创建后状态为PENDING，需要调用initialize接口初始化K8S资源。
    """
    user_id = str(current_user.get("id", ""))

    # 1. 验证应用模板存在
    template = db.query(AppTemplate).filter(
        AppTemplate.id == workflow_data.template_id
    ).first()
    if not template:
        raise NotFoundError("App template", workflow_data.template_id)

    # 2. 验证模板权限（global模板所有人可用，project模板同项目或创建者可用）
    if template.scope != "global" and template.created_by != user_id and template.project_id != workflow_data.project_id:
        raise ForbiddenError(f"No permission to use app template {workflow_data.template_id}")

    # 3. 生成工作流ID和节点ID
    instance_id = generate_id(workflow_data.name)
    node_id = generate_id(f"{instance_id}_node")
    llm_binding = await resolve_llm_binding(workflow_data.llm_binding)
    resolved_volume_mounts, raw_volume_mounts, normalized_project_mounts = await resolve_requested_volume_mounts(
        workflow_data.project_id,
        workflow_data.volume_mounts,
        workflow_data.project_file_mounts,
        current_user.get("token"),
    )

    # 4. 构建节点配置
    service_ports_dict = []
    for p in workflow_data.service_ports:
        if hasattr(p, 'model_dump'):
            service_ports_dict.append(p.model_dump())
        else:
            service_ports_dict.append(p.dict())

    node_config = {
        "id": node_id,
        "node_id": node_id,
        "node_type": "app",
        "template_id": workflow_data.template_id,
        "name": f"{workflow_data.name}-node",
        "create_service": True,
        "service_name": workflow_data.service_name,
        "service_ports": service_ports_dict,
        "service_type": workflow_data.service_type.value if hasattr(workflow_data.service_type, 'value') else workflow_data.service_type,
        "env_vars": [e.model_dump() if hasattr(e, 'model_dump') else e.dict() for e in workflow_data.env_vars] if workflow_data.env_vars else [],
        "volume_mounts": raw_volume_mounts,
        "project_file_mounts": normalized_project_mounts,
        "resources": workflow_data.resources.model_dump() if workflow_data.resources and hasattr(workflow_data.resources, 'model_dump') else (workflow_data.resources.dict() if workflow_data.resources else None),
        "replicas": workflow_data.replicas,
        "timeout_seconds": workflow_data.timeout_seconds,
        "create_ingress": workflow_data.create_ingress,
        "ingress_type": workflow_data.ingress_type if workflow_data.create_ingress else None,
        "ingress_host": workflow_data.ingress_host,
        "ingress_ip": workflow_data.ingress_ip,
        "llm_binding": llm_binding,
    }

    # 5. 创建 WorkflowInstance
    instance = WorkflowInstance(
        id=instance_id,
        name=workflow_data.name,
        description=workflow_data.description,
        project_id=workflow_data.project_id,
        status=WorkflowStatus.PENDING,
        run_mode="simple_app",  # 标识单应用工作流
        trigger_type="manual",
        trigger_enabled=False,
        nodes=[node_config],
        edges=[],
        created_by=user_id,
    )
    db.add(instance)
    db.flush()

    # 6. 创建 WorkflowNodeInstance
    node_instance = WorkflowNodeInstance(
        id=node_id,
        instance_id=instance_id,
        node_id=node_id,
        node_type=NodeType.APP,
        template_id=workflow_data.template_id,
        name=f"{workflow_data.name}-node",
        status=NodeStatus.PENDING,
        position={"x": 0.0, "y": 0.0},
        service_name=None,
        env_vars=[e.model_dump() if hasattr(e, 'model_dump') else e.dict() for e in workflow_data.env_vars] if workflow_data.env_vars else [],
        volume_mounts=resolved_volume_mounts,
        resources=workflow_data.resources.model_dump() if workflow_data.resources and hasattr(workflow_data.resources, 'model_dump') else (workflow_data.resources.dict() if workflow_data.resources else None),
        timeout_seconds=workflow_data.timeout_seconds,
        ingress_type=workflow_data.ingress_type if workflow_data.create_ingress else None,
        ingress_host=workflow_data.ingress_host if workflow_data.create_ingress else None,
        ingress_ip=workflow_data.ingress_ip if workflow_data.create_ingress else None,
    )
    db.add(node_instance)
    db.commit()
    db.refresh(instance)

    logger.info(f"Created app workflow {instance_id} by user {user_id}, template={workflow_data.template_id}")
    return build_app_workflow_response(instance, node_instance, template)


# ============ List App Workflows ============

@router.get("", response_model=AppWorkflowListResponse)
async def list_app_workflows(
    project_id: Optional[str] = Query(None, description="按项目ID过滤"),
    status_filter: Optional[str] = Query(None, alias="status", description="按状态过滤"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """查询单应用工作流列表"""
    # 前端通过当前工作项目维度查询应用实例。
    # 未指定项目时返回空集合，避免跨项目拉取。
    if not project_id:
        return AppWorkflowListResponse(total=0, items=[])

    normalized_status_filter = (status_filter or "").strip().lower()
    if normalized_status_filter in {"", "undefined", "null", "all"}:
        normalized_status_filter = ""

    query = db.query(WorkflowInstance).filter(
        WorkflowInstance.project_id == project_id,
        WorkflowInstance.run_mode == "simple_app"  # 只查询单应用工作流
    )

    if normalized_status_filter:
        query = query.filter(WorkflowInstance.status == normalized_status_filter)

    instances = query.order_by(WorkflowInstance.created_at.desc()).all()

    # 构建响应
    items = []
    for inst in instances:
        node = db.query(WorkflowNodeInstance).filter(
            WorkflowNodeInstance.instance_id == inst.id
        ).first()
        if node:
            template = db.query(AppTemplate).filter(
                AppTemplate.id == node.template_id
            ).first()
            items.append(build_app_workflow_response(inst, node, template))

    return AppWorkflowListResponse(total=len(items), items=items)


# ============ LLM Providers ============

@router.get("/llm-providers", summary="获取可绑定的LLM配置列表")
async def list_app_workflow_llm_providers(
    current_user: dict = Depends(get_current_user),
):
    """代理配置中心的已启用 LLM Provider 列表，供应用实例创建时选择。"""
    _ = current_user
    return await get_configcenter_client_or_fail().list_llm_providers()


@router.get("/llm-providers/{provider_key}", summary="获取可绑定的LLM配置详情")
async def get_app_workflow_llm_provider(
    provider_key: str,
    current_user: dict = Depends(get_current_user),
):
    """代理配置中心的单个 LLM Provider 详情。"""
    _ = current_user
    return await get_configcenter_client_or_fail().get_llm_provider(provider_key)


# ============ Ingress Controllers ============

@router.get("/ingress-controllers", summary="获取可用的Ingress Controller列表")
async def get_ingress_controllers(
    current_user: dict = Depends(get_current_user)
):
    """
    获取集群中可用的Ingress Controller列表

    底层调用k8s服务接口，返回Ingress Controller的名称、外网IP、端口等信息。
    供前端在创建应用实例时选择Ingress配置使用。
    """
    controllers = await get_status_client().get_ingress_controllers()
    return {"controllers": controllers}


# ============ Get App Workflow ============

@router.get("/{instance_id}", response_model=AppWorkflowResponse)
async def get_app_workflow(
    instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """查询单应用工作流详情"""
    instance = get_app_workflow_instance(db, instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to access this workflow")

    node = get_app_workflow_node(db, instance_id)

    template = db.query(AppTemplate).filter(
        AppTemplate.id == node.template_id
    ).first()

    return build_app_workflow_response(instance, node, template)


@router.get("/{instance_id}/access-info", summary="获取单应用实例访问服务信息")
async def get_app_workflow_access_info(
    instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """通过 workflow-status 查询单应用实例的 Service/Ingress 访问信息。"""
    instance = get_app_workflow_instance(db, instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to access this workflow")

    node = get_app_workflow_node(db, instance_id)
    node_config = get_instance_node_config(instance, node.id)
    runtime_service_name = resolve_runtime_service_name(node, node_config)
    if not runtime_service_name:
        raise ValidationError("This app workflow has no active K8S service configured")

    access_info: Dict[str, Any]
    try:
        access_info = await get_status_client().get_service_access_info(instance.project_id, runtime_service_name)
    except Exception as exc:
        logger.warning("Failed to query live service access info for app workflow %s: %s", instance_id, exc)
        access_info = {"error": str(exc)}

    access_info = build_app_access_info_payload(instance, node, node_config, access_info)

    domain_bindings = db.query(WorkflowNodeDomainBinding).filter(
        WorkflowNodeDomainBinding.instance_id == instance.id,
        WorkflowNodeDomainBinding.node_instance_id == node.id,
    ).order_by(WorkflowNodeDomainBinding.updated_at.desc()).all()

    configured_ingress = {
        "create_ingress": node_config.get("create_ingress", bool(node.ingress_type or node.ingress_host or node.ingress_ip)),
        "ingress_type": node_config.get("ingress_type") or node.ingress_type,
        "ingress_host": node_config.get("ingress_host") or node.ingress_host,
        "ingress_ip": node_config.get("ingress_ip") or node.ingress_ip,
        "ingress_name": node_config.get("ingress_name"),
        "ingress_access_url": node_config.get("ingress_access_url"),
        "ingress_tls_enabled": node_config.get("ingress_tls_enabled"),
    }

    fallback_binding = domain_bindings[0] if domain_bindings else None
    fallback_host = (fallback_binding.domain if fallback_binding else None) or configured_ingress.get("ingress_host")
    fallback_ip = (fallback_binding.ingress_ip if fallback_binding else None) or configured_ingress.get("ingress_ip")
    fallback_type = (
        (fallback_binding.ingress_type if fallback_binding else None)
        or configured_ingress.get("ingress_type")
        or "nginx"
    )

    if configured_ingress.get("create_ingress") and fallback_host and not access_info["ingress_accesses"]:
        ingress_name = (
            (fallback_binding.ingress_name if fallback_binding else None)
            or configured_ingress.get("ingress_name")
            or resolve_node_ingress_name(node, node_config)
        )
        access_url = resolve_ingress_access_url(node_config, fallback_host, "/")
        ingress_item = {
            "ingress_name": ingress_name,
            "ingress_class_name": fallback_type,
            "host": fallback_host,
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
            (item.get("type") == "Ingress" and item.get("host") == fallback_host)
            for item in access_info["access_urls"]
        ):
            access_info["access_urls"].append(
                {
                    "type": "Ingress",
                    "port_name": runtime_service_name,
                    "url": access_url,
                    "host": fallback_host,
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
    "/{instance_id}/domain-bindings",
    response_model=List[WorkflowNodeDomainBindingResponse],
    summary="获取单应用实例域名绑定记录",
)
async def list_app_workflow_domain_bindings(
    instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    instance = get_app_workflow_instance(db, instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to access this workflow")

    node = get_app_workflow_node(db, instance_id)
    records = db.query(WorkflowNodeDomainBinding).filter(
        WorkflowNodeDomainBinding.instance_id == instance_id,
        WorkflowNodeDomainBinding.node_instance_id == node.id,
    ).order_by(WorkflowNodeDomainBinding.updated_at.desc()).all()

    return [WorkflowNodeDomainBindingResponse(**record.to_dict()) for record in records]


@router.post("/{instance_id}/ingress-binding", response_model=AppWorkflowResponse, summary="绑定单应用实例 Ingress 域名")
async def bind_app_workflow_ingress(
    instance_id: str,
    request: WorkflowNodeIngressBindingRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    instance = get_app_workflow_instance(db, instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to update this workflow")

    node = get_app_workflow_node(db, instance_id)
    node_config = get_instance_node_config(instance, node.id)
    if not node_config:
        raise NotFoundError("Workflow node config", node.id)

    node_config["create_ingress"] = request.create_ingress
    node_config["ingress_type"] = request.ingress_type
    node_config["ingress_host"] = request.ingress_host
    node_config["ingress_ip"] = request.ingress_ip
    node.ingress_type = request.ingress_type if request.create_ingress else None
    node.ingress_host = request.ingress_host if request.create_ingress else None
    node.ingress_ip = request.ingress_ip if request.create_ingress else None

    if not request.create_ingress:
        node_config["ingress_type"] = None
        node_config["ingress_host"] = None
        node_config["ingress_ip"] = None
        node_config["ingress_name"] = None
        node_config["ingress_access_url"] = None
        node_config["ingress_tls_enabled"] = None
        delete_node_domain_bindings(db, instance_id, node.id)
        flag_modified(instance, "nodes")
        db.commit()
        db.refresh(instance)
        template = db.query(AppTemplate).filter(AppTemplate.id == node.template_id).first()
        return build_app_workflow_response(instance, node, template)

    runtime_service_name = resolve_runtime_service_name(node, node_config)
    if node.k8s_resource_name and runtime_service_name:
        service_port, target_port = get_primary_service_ports(node_config)
        if not service_port:
            raise ValidationError("service_ports cannot be empty when binding ingress")
        ingress_name = resolve_node_ingress_name(node, node_config)
        if not ingress_name:
            raise ValidationError("ingress_name is missing for this initialized app workflow")
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

    flag_modified(instance, "nodes")
    db.commit()
    db.refresh(instance)
    template = db.query(AppTemplate).filter(AppTemplate.id == node.template_id).first()
    return build_app_workflow_response(instance, node, template)


# ============ Update App Workflow ============

@router.put("/{instance_id}", response_model=AppWorkflowResponse)
async def update_app_workflow(
    instance_id: str,
    workflow_data: AppWorkflowUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """更新单应用工作流配置"""
    instance = get_app_workflow_instance(db, instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to update this workflow")

    # 只允许在 pending 状态下修改配置
    if instance.status not in [WorkflowStatus.PENDING, WorkflowStatus.UNREADY, WorkflowStatus.READY]:
        raise ValidationError(f"Cannot update workflow in status: {instance.status}")

    node = get_app_workflow_node(db, instance_id)

    # 更新工作流字段
    if workflow_data.name is not None:
        instance.name = workflow_data.name
        node.name = f"{workflow_data.name}-node"
    if workflow_data.description is not None:
        instance.description = workflow_data.description

    # 更新节点配置
    node_config = get_instance_node_config(instance, node.id)
    if not node_config:
        node_config = instance.nodes[0] if instance.nodes else {}

    if workflow_data.service_name is not None:
        node_config["service_name"] = workflow_data.service_name
    if workflow_data.service_ports is not None:
        service_ports_dict = []
        for p in workflow_data.service_ports:
            if hasattr(p, 'model_dump'):
                service_ports_dict.append(p.model_dump())
            else:
                service_ports_dict.append(p.dict())
        node_config["service_ports"] = service_ports_dict
    if workflow_data.service_type is not None:
        node_config["service_type"] = workflow_data.service_type.value if hasattr(workflow_data.service_type, 'value') else workflow_data.service_type
    if workflow_data.env_vars is not None:
        node.env_vars = [e.model_dump() if hasattr(e, 'model_dump') else e.dict() for e in workflow_data.env_vars]
        node_config["env_vars"] = node.env_vars
    effective_volume_mounts = workflow_data.volume_mounts if workflow_data.volume_mounts is not None else node_config.get("volume_mounts", node.volume_mounts or [])
    effective_project_file_mounts = workflow_data.project_file_mounts if workflow_data.project_file_mounts is not None else node_config.get("project_file_mounts", [])
    if workflow_data.volume_mounts is not None or workflow_data.project_file_mounts is not None:
        resolved_volume_mounts, raw_volume_mounts, normalized_project_mounts = await resolve_requested_volume_mounts(
            instance.project_id,
            effective_volume_mounts,
            effective_project_file_mounts,
            current_user.get("token"),
        )
        node.volume_mounts = resolved_volume_mounts
        node_config["volume_mounts"] = raw_volume_mounts
        node_config["project_file_mounts"] = normalized_project_mounts
    if workflow_data.resources is not None:
        node.resources = workflow_data.resources.model_dump() if hasattr(workflow_data.resources, 'model_dump') else workflow_data.resources.dict()
        node_config["resources"] = node.resources
    if workflow_data.replicas is not None:
        node_config["replicas"] = workflow_data.replicas
    if workflow_data.timeout_seconds is not None:
        node.timeout_seconds = workflow_data.timeout_seconds
        node_config["timeout_seconds"] = workflow_data.timeout_seconds
    if workflow_data.llm_binding is not None:
        node_config["llm_binding"] = await resolve_llm_binding(workflow_data.llm_binding)
    if workflow_data.create_ingress is not None:
        node_config["create_ingress"] = workflow_data.create_ingress
        if workflow_data.create_ingress is False:
            node.ingress_type = None
            node.ingress_host = None
            node.ingress_ip = None
            node_config["ingress_type"] = None
            node_config["ingress_host"] = None
            node_config["ingress_ip"] = None
            node_config["ingress_name"] = None
            node_config["ingress_access_url"] = None
            node_config["ingress_tls_enabled"] = None
    if workflow_data.ingress_type is not None:
        node.ingress_type = workflow_data.ingress_type
        node_config["ingress_type"] = workflow_data.ingress_type
    if workflow_data.ingress_host is not None:
        node.ingress_host = workflow_data.ingress_host
        node_config["ingress_host"] = workflow_data.ingress_host
    if workflow_data.ingress_ip is not None:
        node.ingress_ip = workflow_data.ingress_ip
        node_config["ingress_ip"] = workflow_data.ingress_ip
    if any(value is not None for value in (workflow_data.ingress_type, workflow_data.ingress_host, workflow_data.ingress_ip)):
        if node_config.get("create_ingress") is not False:
            node_config["create_ingress"] = bool(node_config.get("ingress_type"))

    latest_create_ingress = node_config.get(
        "create_ingress",
        bool(node.ingress_type or node.ingress_host or node.ingress_ip),
    )
    latest_domain = node_config.get("ingress_host") or node.ingress_host
    if not latest_create_ingress or not latest_domain:
        delete_node_domain_bindings(db, instance_id, node.id)
    else:
        service_port, target_port = get_primary_service_ports(node_config)
        upsert_node_domain_binding(
            db,
            instance,
            node,
            domain=latest_domain,
            ingress_ip=node_config.get("ingress_ip") or node.ingress_ip,
            ingress_type=node_config.get("ingress_type") or node.ingress_type,
            service_name=resolve_runtime_service_name(node, node_config),
            service_port=service_port,
            target_port=target_port,
            ingress_name=node_config.get("ingress_name"),
            binding_status="active" if node.k8s_resource_name else "configured",
            message="Ingress config updated on app workflow",
        )

    # 更新 instance.nodes
    instance.nodes = [node_config]
    flag_modified(instance, "nodes")

    db.commit()
    db.refresh(instance)

    template = db.query(AppTemplate).filter(
        AppTemplate.id == node.template_id
    ).first()

    logger.info(f"Updated app workflow {instance_id}")
    return build_app_workflow_response(instance, node, template)


# ============ Delete App Workflow ============

@router.delete("/{instance_id}", response_model=SuccessResponse)
async def delete_app_workflow(
    instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """删除单应用工作流"""
    instance = get_app_workflow_instance(db, instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to delete this workflow")

    # 删除 K8S 资源（如果已初始化）
    if instance.status in [WorkflowStatus.UNREADY, WorkflowStatus.READY]:
        node = get_app_workflow_node(db, instance_id)
        if node and node.k8s_resource_name:
            result = await get_status_client().deinitialize_workflow(
                instance_id=instance_id,
                project_id=instance.project_id,
                nodes=[{
                    "node_id": node.node_id,
                    "node_type": "app",
                    "k8s_resource_name": node.k8s_resource_name,
                    "k8s_resource_type": node.k8s_resource_type,
                    "service_name": resolve_runtime_service_name(node, get_instance_node_config(instance, node.id)),
                    "has_ingress": bool(node.ingress_type),
                    "ingress_name": resolve_node_ingress_name(node, get_instance_node_config(instance, node.id)),
                }],
            )
            logger.info(f"delete app workflow deinitialize result: {result}")

    # 删除同步记录
    db.query(WorkflowSyncRecord).filter(
        WorkflowSyncRecord.instance_id == instance_id
    ).delete()

    node = get_app_workflow_node(db, instance_id)
    delete_node_domain_bindings(db, instance_id, node.id)

    # 删除节点实例
    db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.instance_id == instance_id
    ).delete()

    # 删除工作流实例
    db.delete(instance)
    db.commit()

    logger.info(f"Deleted app workflow {instance_id}")
    return SuccessResponse(message=f"App workflow {instance_id} deleted successfully")


# ============ Initialize App Workflow ============

@router.post("/{instance_id}/initialize", response_model=AppWorkflowResponse)
async def initialize_app_workflow(
    instance_id: str,
    force: bool = Query(False, description="强制重新初始化"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    初始化单应用工作流

    - 创建 Deployment 和 Service
    - 初始化成功后状态变为 INITIALIZED
    """
    instance = get_app_workflow_instance(db, instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to initialize this workflow")

    if instance.status not in [WorkflowStatus.PENDING, WorkflowStatus.UNREADY, WorkflowStatus.READY]:
        raise ValidationError(f"Cannot initialize workflow in status: {instance.status}")

    if instance.status in [WorkflowStatus.UNREADY, WorkflowStatus.READY] and not force:
        raise ValidationError(
            "Workflow already initialized. Use force=True to re-initialize"
        )

    node = get_app_workflow_node(db, instance_id)

    status_client = get_status_client()
    namespace_result = await status_client.ensure_namespace(instance.project_id)
    if not namespace_result.get("success"):
        raise InternalError(f"Namespace verification failed: {namespace_result.get('message', 'unknown error')}")

    # 设置状态为初始化中
    instance.status = WorkflowStatus.UNREADY
    instance.message = "Initializing workflow..."
    db.commit()

    init_logs = []
    init_logs.append(f"[{datetime.utcnow().isoformat()}] 开始初始化单应用工作流 {instance_id}")

    # 获取应用模板
    template = db.query(AppTemplate).filter(AppTemplate.id == node.template_id).first()
    if not template:
        instance.status = WorkflowStatus.UNREADY
        instance.message = f"App template {node.template_id} not found"
        db.commit()
        raise NotFoundError("App template", node.template_id)

    # 如果强制初始化，先通过 workflow-status 清理已有资源
    if force and node.k8s_resource_name:
        init_logs.append(f"[{datetime.utcnow().isoformat()}] 强制初始化，删除已存在的K8S资源")
        cleanup_result = await status_client.deinitialize_workflow(
            instance_id=instance_id,
            project_id=instance.project_id,
            nodes=[{
                "node_id": node.node_id,
                "node_type": "app",
                "k8s_resource_name": node.k8s_resource_name,
                "k8s_resource_type": node.k8s_resource_type,
                "service_name": resolve_runtime_service_name(node, get_instance_node_config(instance, node.id)),
                "has_ingress": bool(node.ingress_type),
                "ingress_name": resolve_node_ingress_name(node, get_instance_node_config(instance, node.id)),
            }],
        )
        if not cleanup_result.get("success", False):
            raise InternalError(cleanup_result.get("message", cleanup_result.get("error", "force cleanup failed")))

        node.k8s_resource_name = None
        node.k8s_resource_type = None
        node.status = NodeStatus.PENDING
        db.commit()

    try:
        init_logs.append(f"[{datetime.utcnow().isoformat()}] 初始化节点 {node.name}")
        node_config = get_instance_node_config(instance, node.id)
        if not node_config:
            node_config = instance.nodes[0] if instance.nodes else {}
        display_service_name = node_config.get("service_name")
        service_ports = node_config.get("service_ports", [])
        service_type = node_config.get("service_type", "ClusterIP")
        if hasattr(service_type, "value"):
            service_type = service_type.value

        if not display_service_name or not display_service_name.strip():
            raise ValidationError("service_name is required as a display label")
        if not service_ports:
            raise ValidationError("service_ports cannot be empty")

        containers = _build_containers_from_template(template, node)
        replicas = node_config.get("replicas") or template.replicas or 1
        deployment_name = build_workflow_deployment_name(instance_id, node.id)
        runtime_service_name = build_workflow_service_resource_name(deployment_name)
        node_config["k8s_service_name"] = runtime_service_name
        ingress_type = node_config.get("ingress_type")
        ingress_host = node_config.get("ingress_host")
        ingress_host_prefix = build_workflow_ingress_host_prefix(node_config, runtime_service_name)
        ingress_ip = node_config.get("ingress_ip")

        lifecycle_nodes = [{
            "node_id": node.node_id,
            "node_type": "app",
            "node_name": node.name,
            "deployment_name": deployment_name,
            "service_name": runtime_service_name,
            "ingress_config": {
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
            } if ingress_type else None,
            "containers": containers,
            "volume_mounts": template.volume_mounts if hasattr(template, "volume_mounts") else None,
            "replicas": replicas,
            "service_ports": [
                {
                    "name": p.get("name", f"port-{p.get('port')}"),
                    "port": p.get("port"),
                    "targetPort": p.get("target_port", p.get("port")),
                    "protocol": p.get("protocol", "TCP"),
                }
                for p in service_ports
            ],
            "service_type": service_type,
        }]

        if ingress_type:
            node_config["ingress_name"] = resolve_node_ingress_name(node, node_config)

        result = await status_client.initialize_workflow(
            instance_id=instance_id,
            project_id=instance.project_id,
            nodes=lifecycle_nodes,
        )
        logger.info(f"initialize app workflow via workflow-status result: {result}")

        if not result.get("nodes"):
            raise InternalError(result.get("message", result.get("error", "initialize returned empty result")))

        node_result = result["nodes"][0]
        if not node_result.get("success", False):
            raise InternalError(node_result.get("error", result.get("message", "node initialize failed")))

        node.k8s_resource_name = node_result.get("k8s_resource_name")
        node.k8s_resource_type = "Deployment"
        node.service_name = node_result.get("service_name")
        node_config["ingress_name"] = node_result.get("ingress_name") or node_config.get("ingress_name")
        if node_result.get("ingress_host"):
            node_config["ingress_host"] = node_result.get("ingress_host")
        if "ingress_tls_enabled" in node_result:
            node_config["ingress_tls_enabled"] = node_result.get("ingress_tls_enabled")
        if node_result.get("ingress_access_url"):
            node_config["ingress_access_url"] = node_result.get("ingress_access_url")
        flag_modified(instance, "nodes")
        node.ingress_type = ingress_type
        node.ingress_host = node_result.get("ingress_host") or ingress_host
        node.ingress_ip = ingress_ip
        if ingress_type and (node_result.get("ingress_host") or ingress_host):
            service_port, target_port = get_primary_service_ports(node_config)
            upsert_node_domain_binding(
                db,
                instance,
                node,
                domain=node_result.get("ingress_host") or ingress_host,
                ingress_ip=ingress_ip,
                ingress_type=ingress_type,
                service_name=resolve_runtime_service_name(node, node_config),
                service_port=service_port,
                target_port=target_port,
                ingress_name=node_result.get("ingress_name") or node_config.get("ingress_name"),
                binding_status="active",
                message="Ingress bound during initialization",
            )
            flag_modified(instance, "nodes")

        result_status = str(node_result.get("status", "Pending")).lower()
        if result_status == "ready":
            node.status = NodeStatus.READY
        elif result_status in ["not_ready", "notready"]:
            node.status = NodeStatus.NOT_READY
        else:
            node.status = NodeStatus.PENDING

        node.message = node_result.get("message", "App workflow initialized successfully")
        sync_app_instance_status_from_node(instance, node)
        init_logs.append(f"[{datetime.utcnow().isoformat()}] 初始化完成")

    except Exception as e:
        logger.error(f"Error initializing app workflow {instance_id}: {e}")
        init_logs.append(f"  异常: {str(e)}")
        node.status = NodeStatus.FAILED
        node.message = str(e)
        instance.status = WorkflowStatus.UNREADY
        instance.message = f"Initialization failed: {str(e)}"

    # 保存初始化日志
    node.init_logs = "\n".join(init_logs)
    db.commit()
    db.refresh(instance)

    logger.info(f"Initialized app workflow {instance_id}, status={instance.status}")

    template = db.query(AppTemplate).filter(
        AppTemplate.id == node.template_id
    ).first()

    return build_app_workflow_response(instance, node, template)


@router.post("/{instance_id}/uninitialize", response_model=AppWorkflowResponse)
async def uninitialize_app_workflow(
    instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """反初始化单应用工作流并删除已创建的 K8S 资源。"""
    instance = get_app_workflow_instance(db, instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to uninitialize this workflow")

    if instance.status not in [WorkflowStatus.UNREADY, WorkflowStatus.READY]:
        raise ValidationError(
            f"Cannot uninitialize workflow in status: {instance.status}. Valid states: unready, ready"
        )

    node = get_app_workflow_node(db, instance_id)

    deleted_count = 0
    errors = []
    if node.k8s_resource_name:
        result = await get_status_client().deinitialize_workflow(
            instance_id=instance_id,
            project_id=instance.project_id,
            nodes=[{
                "node_id": node.node_id,
                "node_type": "app",
                "k8s_resource_name": node.k8s_resource_name,
                "k8s_resource_type": node.k8s_resource_type,
                "service_name": resolve_runtime_service_name(node, get_instance_node_config(instance, node.id)),
                "has_ingress": bool(node.ingress_type),
                "ingress_name": resolve_node_ingress_name(node, get_instance_node_config(instance, node.id)),
            }],
        )
        deleted_count = result.get("succeeded_nodes", 0)
        if not result.get("success", False):
            errors.append(result.get("message", result.get("error", "Unknown error")))
        logger.info(f"uninitialize app workflow result: {result}")

    node.k8s_resource_name = None
    node.k8s_resource_type = None
    node.service_name = None
    node.status = NodeStatus.PENDING
    node.started_at = None
    node.finished_at = None
    node.message = None
    node_config = get_instance_node_config(instance, node.id)
    node_config["k8s_service_name"] = None
    node_config["ingress_name"] = None
    node_config["ingress_access_url"] = None
    node_config["ingress_tls_enabled"] = None

    delete_node_domain_bindings(db, instance_id, node.id)
    flag_modified(instance, "nodes")

    instance.status = WorkflowStatus.PENDING
    instance.started_at = None
    instance.finished_at = None

    if errors:
        instance.message = f"Uninitialize completed with errors: {'; '.join(errors)}"
        logger.warning(f"Uninitialized app workflow {instance_id} with errors: {errors}")
    else:
        instance.message = f"Successfully uninitialized app workflow, deleted {deleted_count} K8S resources"
        logger.info(f"Uninitialized app workflow {instance_id}, deleted {deleted_count} K8S resources")

    db.commit()
    db.refresh(instance)

    template = db.query(AppTemplate).filter(
        AppTemplate.id == node.template_id
    ).first()

    return build_app_workflow_response(instance, node, template)


def _build_containers_from_template(template: AppTemplate, node: WorkflowNodeInstance) -> List[Dict[str, Any]]:
    """从模板和节点配置构建容器列表"""
    containers = []

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


# ============ Start App Workflow ============

@router.post("/{instance_id}/start", response_model=AppWorkflowResponse)
async def start_app_workflow(
    instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    启动单应用工作流

    - 检查 Deployment 状态
    - 更新工作流状态为 RUNNING
    """
    instance = get_app_workflow_instance(db, instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to start this workflow")

    if instance.status not in [WorkflowStatus.UNREADY, WorkflowStatus.READY]:
        raise ValidationError(f"Cannot start workflow in status: {instance.status}. Valid states: unready, ready")

    node = get_app_workflow_node(db, instance_id)

    # 更新运行计数
    instance.run_count += 1
    instance.last_run_at = datetime.utcnow()

    status_client = get_status_client()

    try:
        if node.k8s_resource_name and node.k8s_resource_type == "Deployment":
            result = await status_client.start_node(
                node_id=node.node_id,
                project_id=instance.project_id,
                instance_id=instance_id,
                node_type="app",
                k8s_resource_name=node.k8s_resource_name,
            )
            if not result.get("success"):
                raise InternalError(result.get("error", "Failed to start app node"))

            result_status = str(result.get("status", "Pending")).lower()
            if result_status == "ready":
                node.status = NodeStatus.READY
                node.message = "Deployment is ready"
            elif result_status in ["not_ready", "notready"]:
                node.status = NodeStatus.NOT_READY
                node.message = "Deployment is starting"
            else:
                node.status = NodeStatus.PENDING
                node.message = "Deployment is pending"

        node.started_at = datetime.utcnow()
        instance.started_at = datetime.utcnow()
        instance.status = WorkflowStatus.READY if node.status == NodeStatus.READY else WorkflowStatus.UNREADY
        instance.message = "Workflow started"

    except Exception as e:
        logger.error(f"Error starting app workflow {instance_id}: {e}")
        instance.status = WorkflowStatus.UNREADY
        instance.message = f"Failed to start: {str(e)}"

    db.commit()
    db.refresh(instance)

    logger.info(f"Started app workflow {instance_id}")

    template = db.query(AppTemplate).filter(
        AppTemplate.id == node.template_id
    ).first()

    return build_app_workflow_response(instance, node, template)


# ============ Stop App Workflow ============

@router.post("/{instance_id}/stop", response_model=AppWorkflowResponse)
async def stop_app_workflow(
    instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """停止单应用工作流"""
    instance = get_app_workflow_instance(db, instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to stop this workflow")

    if instance.status not in [WorkflowStatus.UNREADY, WorkflowStatus.READY]:
        raise ValidationError(f"Cannot stop workflow in status: {instance.status}")

    node = get_app_workflow_node(db, instance_id)

    node_config = get_instance_node_config(instance, node.id)

    if node.k8s_resource_name:
        result = await get_status_client().stop_workflow(
            instance_id=instance_id,
            project_id=instance.project_id,
            nodes=[{
                "node_id": node.node_id,
                "node_type": "app",
                "k8s_resource_name": node.k8s_resource_name,
                "k8s_resource_type": node.k8s_resource_type,
                "service_name": resolve_runtime_service_name(node, node_config),
                "has_ingress": bool(node.ingress_type),
                "ingress_name": resolve_node_ingress_name(node, node_config),
            }],
        )
        logger.info(f"stop app workflow result: {result}")
        if not result.get("success", False):
            node.message = result.get("message", result.get("error", "Stop workflow failed"))

    node.status = NodeStatus.PENDING
    node.k8s_resource_name = None
    node.k8s_resource_type = None
    node.service_name = None
    node.finished_at = datetime.utcnow()
    node.message = "Workflow stopped"
    node_config["k8s_service_name"] = None
    node_config["ingress_name"] = None
    node_config["ingress_access_url"] = None
    node_config["ingress_tls_enabled"] = None

    latest_create_ingress = node_config.get(
        "create_ingress",
        bool(node.ingress_type or node.ingress_host or node.ingress_ip),
    )
    latest_domain = node_config.get("ingress_host") or node.ingress_host
    if not latest_create_ingress or not latest_domain:
        delete_node_domain_bindings(db, instance_id, node.id)
    else:
        service_port, target_port = get_primary_service_ports(node_config)
        upsert_node_domain_binding(
            db,
            instance,
            node,
            domain=latest_domain,
            ingress_ip=node_config.get("ingress_ip") or node.ingress_ip,
            ingress_type=node_config.get("ingress_type") or node.ingress_type,
            service_name=resolve_runtime_service_name(node, node_config),
            service_port=service_port,
            target_port=target_port,
            ingress_name=node_config.get("ingress_name"),
            binding_status="configured",
            message="Ingress config preserved after workflow stop",
        )

    instance.status = WorkflowStatus.PENDING
    instance.finished_at = datetime.utcnow()
    instance.message = "Workflow stopped"
    db.commit()
    db.refresh(instance)

    logger.info(f"Stopped app workflow {instance_id}")

    template = db.query(AppTemplate).filter(
        AppTemplate.id == node.template_id
    ).first()

    return build_app_workflow_response(instance, node, template)


# ============ Sync Status ============

@router.post("/{instance_id}/sync-status", response_model=AppWorkflowResponse)
async def sync_app_workflow_status(
    instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """同步单应用工作流状态"""
    instance = get_app_workflow_instance(db, instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to access this workflow")

    node = get_app_workflow_node(db, instance_id)

    try:
        if node.k8s_resource_name and node.k8s_resource_type == "Deployment":
            sync_result = await get_status_client().sync_node_status(
                node_id=node.node_id,
                project_id=instance.project_id,
                instance_id=instance_id,
                node_type="app",
                k8s_resource_name=node.k8s_resource_name,
                timeout_seconds=node.timeout_seconds,
            )
            status_lower = str(sync_result.get("status", "Pending")).lower()
            if status_lower == "ready":
                node.status = NodeStatus.READY
            elif status_lower in ["not_ready", "notready"]:
                node.status = NodeStatus.NOT_READY
            else:
                node.status = NodeStatus.PENDING
            node.message = sync_result.get("message", node.message)

        # 更新工作流状态
        sync_app_instance_status_from_node(instance, node)

        instance.last_sync_at = datetime.utcnow()

    except Exception as e:
        logger.error(f"Error syncing app workflow status: {e}")
        instance.message = f"Sync failed: {str(e)}"

    db.commit()
    db.refresh(instance)

    logger.info(f"Synced status for app workflow {instance_id}")

    template = db.query(AppTemplate).filter(
        AppTemplate.id == node.template_id
    ).first()

    return build_app_workflow_response(instance, node, template)


# ============ Get Logs ============

@router.get("/{instance_id}/logs")
async def get_app_workflow_logs(
    instance_id: str,
    tail_lines: int = Query(100, ge=1, le=10000),
    container: Optional[str] = Query(None),
    previous: bool = Query(False),
    timestamps: bool = Query(True),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get logs for a single-app workflow instance."""
    instance = get_app_workflow_instance(db, instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to access this workflow")

    node = get_app_workflow_node(db, instance_id)

    if not node.k8s_resource_name:
        raise ValidationError("Workflow has not been initialized yet")

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

    return {
        "workflow_id": instance_id,
        "node_id": node.id,
        "resource_name": node.k8s_resource_name,
        "pod_name": log_result.get("pod_name"),
        "namespace": log_result.get("namespace"),
        "logs": log_result.get("logs", ""),
        "container": container,
        "previous": previous
    }
