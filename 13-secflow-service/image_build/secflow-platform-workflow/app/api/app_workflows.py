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

from app.api.dependencies import get_current_user, generate_id
from app.models import (
    get_db, WorkflowInstance, WorkflowNodeInstance,
    WorkflowStatus, NodeStatus, NodeType, AppTemplate,
    WorkflowSyncRecord
)
from app.schemas import (
    AppWorkflowCreate, AppWorkflowUpdate,
    AppWorkflowResponse, AppWorkflowListResponse,
    AppWorkflowNodeResponse,
    SuccessResponse
)
from app.exception import NotFoundError, ForbiddenError, ValidationError, InternalError
from app.services import WorkflowEngine
from app.services.k8s_service_client import get_k8s_service_client
from app.config import get_config

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/app-workflows", tags=["App Workflows"])


def get_k8s_client():
    """获取K8S微服务客户端"""
    return get_k8s_service_client()


def check_instance_permission(instance: WorkflowInstance, user_id: str) -> bool:
    """Check if user has permission to access workflow instance"""
    return instance.created_by == user_id


def build_app_workflow_response(
    instance: WorkflowInstance,
    node: WorkflowNodeInstance,
    template: Optional[AppTemplate] = None
) -> Dict[str, Any]:
    """Build single app workflow response"""
    node_config = instance.nodes[0] if instance.nodes else {}

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
            "service_name": node.service_name,
            "message": node.message,
            "started_at": node.started_at.isoformat() if node.started_at else None,
            "finished_at": node.finished_at.isoformat() if node.finished_at else None,
            "created_at": node.created_at.isoformat() if node.created_at else None,
            "env_vars": node.env_vars or [],
            "volume_mounts": node.volume_mounts or [],
            "resources": node.resources,
        },
        "service_name": node.service_name,
        "service_ports": node_config.get("service_ports", []),
        "ingress_type": node.ingress_type,
        "ingress_host": node.ingress_host,
        "ingress_ip": node.ingress_ip,
        "template_id": node.template_id,
        "template_name": template.name if template else None,
        "created_by": instance.created_by,
        "created_at": instance.created_at.isoformat() if instance.created_at else None,
        "updated_at": instance.updated_at.isoformat() if instance.updated_at else None,
        "started_at": instance.started_at.isoformat() if instance.started_at else None,
        "finished_at": instance.finished_at.isoformat() if instance.finished_at else None,
        "message": instance.message,
    }


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

    # 2. 验证模板权限（global模板所有人可用，project模板仅创建者可用）
    if template.scope != "global" and template.created_by != user_id:
        raise ForbiddenError(f"No permission to use app template {workflow_data.template_id}")

    # 3. 生成工作流ID和节点ID
    instance_id = generate_id(workflow_data.name)
    node_id = generate_id(f"{instance_id}_node")

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
        "volume_mounts": [v.model_dump() if hasattr(v, 'model_dump') else v.dict() for v in workflow_data.volume_mounts] if workflow_data.volume_mounts else [],
        "resources": workflow_data.resources.model_dump() if workflow_data.resources and hasattr(workflow_data.resources, 'model_dump') else (workflow_data.resources.dict() if workflow_data.resources else None),
        "replicas": workflow_data.replicas,
        "timeout_seconds": workflow_data.timeout_seconds,
        "ingress_type": workflow_data.ingress_type,
        "ingress_host": workflow_data.ingress_host,
        "ingress_ip": workflow_data.ingress_ip,
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
        service_name=workflow_data.service_name,
        env_vars=[e.model_dump() if hasattr(e, 'model_dump') else e.dict() for e in workflow_data.env_vars] if workflow_data.env_vars else [],
        volume_mounts=[v.model_dump() if hasattr(v, 'model_dump') else v.dict() for v in workflow_data.volume_mounts] if workflow_data.volume_mounts else [],
        resources=workflow_data.resources.model_dump() if workflow_data.resources and hasattr(workflow_data.resources, 'model_dump') else (workflow_data.resources.dict() if workflow_data.resources else None),
        timeout_seconds=workflow_data.timeout_seconds,
        ingress_type=workflow_data.ingress_type,
        ingress_host=workflow_data.ingress_host,
        ingress_ip=workflow_data.ingress_ip,
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
    user_id = str(current_user.get("id", ""))

    query = db.query(WorkflowInstance).filter(
        WorkflowInstance.created_by == user_id,
        WorkflowInstance.run_mode == "simple_app"  # 只查询单应用工作流
    )

    if project_id:
        query = query.filter(WorkflowInstance.project_id == project_id)
    if status_filter:
        query = query.filter(WorkflowInstance.status == status_filter)

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


# ============ Ingress Controllers ============

@router.get("/ingress-controllers", summary="获取可用的Ingress Controller列表")
async def get_ingress_controllers(
    current_user: dict = Depends(get_current_user)
):
    """
    获取集群中可用的Ingress Controller列表

    代理调用k8s微服务接口，返回Ingress Controller的名称、外部IP、端口等信息。
    供前端在创建应用实例时选择Ingress配置使用。
    """
    k8s_client = get_k8s_client()
    controllers = k8s_client.get_ingress_controllers()
    return {"controllers": controllers}


# ============ Get App Workflow ============

@router.get("/{instance_id}", response_model=AppWorkflowResponse)
async def get_app_workflow(
    instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """查询单应用工作流详情"""
    instance = db.query(WorkflowInstance).filter(
        WorkflowInstance.id == instance_id,
        WorkflowInstance.run_mode == "simple_app"
    ).first()

    if not instance:
        raise NotFoundError("App workflow", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to access this workflow")

    node = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.instance_id == instance_id
    ).first()

    if not node:
        raise InternalError(f"Workflow node not found for instance {instance_id}")

    template = db.query(AppTemplate).filter(
        AppTemplate.id == node.template_id
    ).first()

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
    instance = db.query(WorkflowInstance).filter(
        WorkflowInstance.id == instance_id,
        WorkflowInstance.run_mode == "simple_app"
    ).first()

    if not instance:
        raise NotFoundError("App workflow", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to update this workflow")

    # 只允许在 pending 状态下修改配置
    if instance.status not in [WorkflowStatus.PENDING, WorkflowStatus.INITIALIZED, WorkflowStatus.STOPPED]:
        raise ValidationError(f"Cannot update workflow in status: {instance.status}")

    node = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.instance_id == instance_id
    ).first()

    if not node:
        raise InternalError(f"Workflow node not found for instance {instance_id}")

    # 更新工作流字段
    if workflow_data.name is not None:
        instance.name = workflow_data.name
        node.name = f"{workflow_data.name}-node"
    if workflow_data.description is not None:
        instance.description = workflow_data.description

    # 更新节点配置
    node_config = instance.nodes[0] if instance.nodes else {}

    if workflow_data.service_name is not None:
        node.service_name = workflow_data.service_name
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
    if workflow_data.volume_mounts is not None:
        node.volume_mounts = [v.model_dump() if hasattr(v, 'model_dump') else v.dict() for v in workflow_data.volume_mounts]
        node_config["volume_mounts"] = node.volume_mounts
    if workflow_data.resources is not None:
        node.resources = workflow_data.resources.model_dump() if hasattr(workflow_data.resources, 'model_dump') else workflow_data.resources.dict()
        node_config["resources"] = node.resources
    if workflow_data.replicas is not None:
        node_config["replicas"] = workflow_data.replicas

    # 更新 instance.nodes
    instance.nodes = [node_config]

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
    instance = db.query(WorkflowInstance).filter(
        WorkflowInstance.id == instance_id,
        WorkflowInstance.run_mode == "simple_app"
    ).first()

    if not instance:
        raise NotFoundError("App workflow", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to delete this workflow")

    # 删除 K8S 资源（如果已初始化）
    if instance.status in [WorkflowStatus.INITIALIZED, WorkflowStatus.RUNNING]:
        k8s_client = get_k8s_client()
        node = db.query(WorkflowNodeInstance).filter(
            WorkflowNodeInstance.instance_id == instance_id
        ).first()

        if node and node.k8s_resource_name:
            try:
                if node.k8s_resource_type == "Deployment":
                    # Delete Ingress if exists
                    if node.ingress_type and node.service_name:
                        try:
                            k8s_client.delete_ingress(instance.project_id, node.service_name)
                            logger.info(f"Deleted Ingress {node.service_name} for node {node.id}")
                        except Exception as e:
                            logger.warning(f"Failed to delete Ingress: {e}")

                    k8s_client.delete_deployment(instance.project_id, node.k8s_resource_name)
                    if node.service_name:
                        k8s_client.delete_service(instance.project_id, node.service_name)
            except Exception as e:
                logger.error(f"Failed to delete K8S resource: {e}")

    # 删除同步记录
    db.query(WorkflowSyncRecord).filter(
        WorkflowSyncRecord.instance_id == instance_id
    ).delete()

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
    instance = db.query(WorkflowInstance).filter(
        WorkflowInstance.id == instance_id,
        WorkflowInstance.run_mode == "simple_app"
    ).first()

    if not instance:
        raise NotFoundError("App workflow", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to initialize this workflow")

    # 检查状态
    if instance.status == WorkflowStatus.INITIALIZING:
        raise ValidationError("Workflow is already initializing, please wait")

    if instance.status == WorkflowStatus.RUNNING:
        raise ValidationError("Cannot initialize running workflow, stop it first")

    if instance.status not in [WorkflowStatus.PENDING, WorkflowStatus.INITIALIZED, WorkflowStatus.STOPPED]:
        raise ValidationError(f"Cannot initialize workflow in status: {instance.status}")

    if instance.status in [WorkflowStatus.INITIALIZED, WorkflowStatus.STOPPED] and not force:
        raise ValidationError(
            "Workflow already initialized. Use force=True to re-initialize"
        )

    node = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.instance_id == instance_id
    ).first()

    if not node:
        raise InternalError(f"Workflow node not found for instance {instance_id}")

    k8s_client = get_k8s_client()

    # 验证 namespace
    namespace_exists, namespace_error = k8s_client.ensure_namespace(instance.project_id)
    if not namespace_exists:
        raise InternalError(f"Namespace verification failed: {namespace_error}")

    # 设置状态为正在初始化
    instance.status = WorkflowStatus.INITIALIZING
    instance.message = "Initializing workflow..."
    db.commit()

    init_logs = []
    init_logs.append(f"[{datetime.utcnow().isoformat()}] 开始初始化单应用工作流 {instance_id}")

    # 获取应用模板
    template = db.query(AppTemplate).filter(AppTemplate.id == node.template_id).first()
    if not template:
        instance.status = WorkflowStatus.FAILED
        instance.message = f"App template {node.template_id} not found"
        db.commit()
        raise NotFoundError("App template", node.template_id)

    # 如果强制初始化，先删除已存在的资源
    if force and node.k8s_resource_name:
        init_logs.append(f"[{datetime.utcnow().isoformat()}] 强制初始化: 删除已存在的K8S资源")
        try:
            if node.k8s_resource_type == "Deployment":
                k8s_client.delete_deployment(instance.project_id, node.k8s_resource_name)
                if node.service_name:
                    k8s_client.delete_service(instance.project_id, node.service_name)
            elif node.k8s_resource_type == "Job":
                k8s_client.delete_job(instance.project_id, node.k8s_resource_name)
        except Exception as e:
            logger.warning(f"Failed to delete existing K8S resource: {e}")

        node.k8s_resource_name = None
        node.k8s_resource_type = None
        node.status = NodeStatus.PENDING
        db.commit()

    try:
        init_logs.append(f"[{datetime.utcnow().isoformat()}] 初始化节点 {node.name}")

        # 获取节点配置
        node_config = instance.nodes[0] if instance.nodes else {}
        service_name = node_config.get("service_name") or node.service_name
        service_ports = node_config.get("service_ports", [])
        service_type = node_config.get("service_type", "ClusterIP")

        # 验证 Service 配置
        if not service_name or not service_name.strip():
            raise ValidationError("service_name is required")

        if not service_ports:
            raise ValidationError("service_ports cannot be empty")

        # 构建容器配置
        containers = _build_containers_from_template(template, node)
        init_logs.append(f"  模板: {template.name}, 容器数: {len(containers)}")

        # 获取副本数（优先使用节点配置，否则使用模板配置）
        replicas = node_config.get("replicas") or template.replicas or 1
        init_logs.append(f"  replicas: {replicas}")

        # 生成 Deployment 名称
        deployment_name = f"wf-{instance_id[:8]}-{node.id[:8]}"
        node.k8s_resource_name = deployment_name
        node.k8s_resource_type = "Deployment"

        # 创建 Deployment
        init_logs.append(f"  创建Deployment: {deployment_name}")
        success, error_msg = k8s_client.create_deployment(
            project_id=instance.project_id,
            name=deployment_name,
            containers=containers,
            ports=service_ports,
            replicas=replicas
        )

        if not success:
            raise InternalError(f"Failed to create Deployment: {error_msg}")

        init_logs.append(f"  成功: 创建Deployment {deployment_name}")

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

        # 创建 Service
        if hasattr(service_type, "value"):
            service_type = service_type.value

        success, error_msg = k8s_client.create_service(
            project_id=instance.project_id,
            name=service_name,
            selector={"app": deployment_name},
            ports=k8s_service_ports,
            service_type=service_type
        )

        if success:
            node.service_name = service_name
            init_logs.append(f"  成功: 创建Service {service_name}")

            # Create Ingress if configured
            ingress_type = node_config.get("ingress_type")
            ingress_host = node_config.get("ingress_host")
            ingress_ip = node_config.get("ingress_ip")

            if ingress_type and ingress_host and service_name:
                ingress_name = service_name  # Same name as service
                service_port = service_ports[0].get("port") if service_ports else 80

                ingress_success, ingress_error = k8s_client.create_ingress(
                    project_id=instance.project_id,
                    name=ingress_name,
                    service_name=service_name,
                    service_port=service_port,
                    host=ingress_host,
                    ingress_type=ingress_type,
                    ingress_ip=ingress_ip
                )

                if ingress_success:
                    node.ingress_type = ingress_type
                    node.ingress_host = ingress_host
                    node.ingress_ip = ingress_ip
                    init_logs.append(f"  成功: 创建Ingress {ingress_name} (host: {ingress_host})")
                else:
                    init_logs.append(f"  警告: 创建Ingress失败 - {ingress_error}")
                    logger.warning(f"Failed to create Ingress for node {node.id}: {ingress_error}")

            # 检查 Deployment 状态
            try:
                deployment_status = k8s_client.get_deployment_status(instance.project_id, deployment_name)
                if deployment_status:
                    ready_replicas = deployment_status.get("ready_replicas", 0) or deployment_status.get("ready_replica", 0)
                    replicas = deployment_status.get("replicas", 0) or deployment_status.get("replica", 0)
                    available_replicas = deployment_status.get("available_replicas", 0) or deployment_status.get("available_replica", 0)

                    init_logs.append(f"  Deployment状态: replicas={replicas}, ready={ready_replicas}, available={available_replicas}")

                    if ready_replicas >= replicas and replicas > 0:
                        node.status = NodeStatus.READY
                        node.message = "Deployment is ready"
                    elif available_replicas > 0 or ready_replicas > 0:
                        node.status = NodeStatus.NOT_READY
                        node.message = "Deployment is running but not ready"
                    else:
                        node.status = NodeStatus.PENDING
                        node.message = "Deployment created, waiting for Pod"
                else:
                    node.status = NodeStatus.PENDING
                    node.message = "App workflow initialized successfully"
            except Exception as status_error:
                logger.warning(f"Failed to get deployment status: {status_error}")
                node.status = NodeStatus.PENDING
                node.message = "App workflow initialized successfully"

            # 更新工作流状态
            instance.status = WorkflowStatus.INITIALIZED
            instance.message = f"Successfully initialized app workflow"
            init_logs.append(f"[{datetime.utcnow().isoformat()}] 初始化完成")

        else:
            # Service 创建失败，删除 Deployment
            error_msg = f"Failed to create Service {service_name}: {error_msg}"
            init_logs.append(f"  错误: {error_msg}")
            try:
                k8s_client.delete_deployment(instance.project_id, deployment_name)
                init_logs.append(f"  清理: 已删除Deployment {deployment_name}")
            except Exception as cleanup_error:
                logger.warning(f"Failed to cleanup Deployment: {cleanup_error}")

            node.status = NodeStatus.FAILED
            node.message = error_msg
            instance.status = WorkflowStatus.FAILED
            instance.message = error_msg

    except Exception as e:
        logger.error(f"Error initializing app workflow {instance_id}: {e}")
        init_logs.append(f"  异常: {str(e)}")
        node.status = NodeStatus.FAILED
        node.message = str(e)
        instance.status = WorkflowStatus.FAILED
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
    instance = db.query(WorkflowInstance).filter(
        WorkflowInstance.id == instance_id,
        WorkflowInstance.run_mode == "simple_app"
    ).first()

    if not instance:
        raise NotFoundError("App workflow", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to start this workflow")

    if instance.status not in [WorkflowStatus.INITIALIZED, WorkflowStatus.STOPPED]:
        raise ValidationError(f"Cannot start workflow in status: {instance.status}. Valid states: initialized, stopped")

    node = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.instance_id == instance_id
    ).first()

    if not node:
        raise InternalError(f"Workflow node not found for instance {instance_id}")

    # 更新运行计数
    instance.run_count += 1
    instance.last_run_at = datetime.utcnow()

    k8s_client = get_k8s_client()

    try:
        # 检查 Deployment 状态
        if node.k8s_resource_name and node.k8s_resource_type == "Deployment":
            deployment_status = k8s_client.get_deployment_status(instance.project_id, node.k8s_resource_name)
            if deployment_status:
                ready_replicas = deployment_status.get("ready_replicas", 0) or deployment_status.get("ready_replica", 0)
                replicas = deployment_status.get("replicas", 0) or deployment_status.get("replica", 0)

                if ready_replicas >= replicas and replicas > 0:
                    node.status = NodeStatus.READY
                    node.message = "Deployment is ready"
                else:
                    node.status = NodeStatus.NOT_READY
                    node.message = "Deployment is starting"

        node.started_at = datetime.utcnow()
        instance.started_at = datetime.utcnow()
        instance.status = WorkflowStatus.RUNNING
        instance.message = "Workflow is running"

    except Exception as e:
        logger.error(f"Error starting app workflow {instance_id}: {e}")
        instance.status = WorkflowStatus.FAILED
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
    instance = db.query(WorkflowInstance).filter(
        WorkflowInstance.id == instance_id,
        WorkflowInstance.run_mode == "simple_app"
    ).first()

    if not instance:
        raise NotFoundError("App workflow", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to stop this workflow")

    if instance.status not in [WorkflowStatus.INITIALIZED, WorkflowStatus.RUNNING]:
        raise ValidationError(f"Cannot stop workflow in status: {instance.status}")

    node = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.instance_id == instance_id
    ).first()

    if not node:
        raise InternalError(f"Workflow node not found for instance {instance_id}")

    k8s_client = get_k8s_client()

    # 删除 K8S 资源
    if node.k8s_resource_name:
        try:
            if node.k8s_resource_type == "Deployment":
                # Delete Ingress if exists
                if node.ingress_type and node.service_name:
                    try:
                        k8s_client.delete_ingress(instance.project_id, node.service_name)
                        logger.info(f"Deleted Ingress {node.service_name} for node {node.id}")
                    except Exception as e:
                        logger.warning(f"Failed to delete Ingress: {e}")

                k8s_client.delete_deployment(instance.project_id, node.k8s_resource_name)
                if node.service_name:
                    k8s_client.delete_service(instance.project_id, node.service_name)
                node.status = NodeStatus.STOPPED
                node.finished_at = datetime.utcnow()

                # Clear Ingress fields
                node.ingress_type = None
                node.ingress_host = None
                node.ingress_ip = None
        except Exception as e:
            logger.error(f"Failed to stop node {node.id}: {e}")
            node.message = str(e)

    instance.status = WorkflowStatus.STOPPED
    instance.finished_at = datetime.utcnow()
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
    instance = db.query(WorkflowInstance).filter(
        WorkflowInstance.id == instance_id,
        WorkflowInstance.run_mode == "simple_app"
    ).first()

    if not instance:
        raise NotFoundError("App workflow", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to access this workflow")

    node = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.instance_id == instance_id
    ).first()

    if not node:
        raise InternalError(f"Workflow node not found for instance {instance_id}")

    k8s_client = get_k8s_client()

    try:
        # 同步节点状态
        if node.k8s_resource_name and node.k8s_resource_type == "Deployment":
            deployment_status = k8s_client.get_deployment_status(instance.project_id, node.k8s_resource_name)
            if deployment_status:
                ready_replicas = deployment_status.get("ready_replicas", 0) or deployment_status.get("ready_replica", 0)
                replicas = deployment_status.get("replicas", 0) or deployment_status.get("replica", 0)
                available_replicas = deployment_status.get("available_replicas", 0) or deployment_status.get("available_replica", 0)

                if ready_replicas >= replicas and replicas > 0:
                    node.status = NodeStatus.READY
                    node.message = "Deployment is ready"
                elif available_replicas > 0 or ready_replicas > 0:
                    node.status = NodeStatus.NOT_READY
                    node.message = "Deployment is running but not ready"
                else:
                    node.status = NodeStatus.PENDING
                    node.message = "Waiting for Pod"

        # 更新工作流状态
        if node.status == NodeStatus.READY and instance.status == WorkflowStatus.RUNNING:
            instance.message = "Workflow is running and ready"

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
    """获取单应用工作流日志"""
    instance = db.query(WorkflowInstance).filter(
        WorkflowInstance.id == instance_id,
        WorkflowInstance.run_mode == "simple_app"
    ).first()

    if not instance:
        raise NotFoundError("App workflow", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to access this workflow")

    node = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.instance_id == instance_id
    ).first()

    if not node:
        raise NotFoundError("Workflow node", f"instance {instance_id}")

    if not node.k8s_resource_name:
        raise ValidationError("Workflow has not been initialized yet")

    k8s_client = get_k8s_client()

    # 获取 Pod
    if node.k8s_resource_type == "Deployment":
        pods = k8s_client.get_deployment_pods(instance.project_id, node.k8s_resource_name)
    else:
        pods = k8s_client.get_job_pods(instance.project_id, node.k8s_resource_name)

    if not pods:
        raise NotFoundError("Pod", f"No pods found for workflow {instance_id}")

    # 获取日志
    pod_name = pods[0]["name"]
    logs = k8s_client.get_pod_logs(
        project_id=instance.project_id,
        pod_name=pod_name,
        container=container,
        tail_lines=tail_lines,
        previous=previous,
        timestamps=timestamps
    )

    if logs is None:
        raise InternalError("Failed to retrieve pod logs")

    return {
        "workflow_id": instance_id,
        "node_id": node.id,
        "resource_name": node.k8s_resource_name,
        "pod_name": pod_name,
        "namespace": k8s_client.get_project_namespace(instance.project_id),
        "logs": logs,
        "container": container,
        "previous": previous
    }
