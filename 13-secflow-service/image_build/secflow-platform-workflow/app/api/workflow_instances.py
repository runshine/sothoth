"""
Workflow instance API routes
Manages workflow execution including creation, running, stopping, deletion, and log retrieval
"""
import asyncio
import logging
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, generate_id
from app.models import (
    get_db, WorkflowInstance, WorkflowNodeInstance,
    WorkflowStatus, NodeStatus, NodeType, AppTemplate, JobTemplate,
    WorkflowSyncRecord
)
from app.schemas import (
    WorkflowSyncRecordResponse, WorkflowSyncRecordListResponse,
    WorkflowInstanceCreate, WorkflowInstanceUpdate,
    WorkflowInstanceResponse, WorkflowInstanceListResponse,
    WorkflowNodeCreate, WorkflowNodeUpdate, WorkflowNodeInstanceResponse,
    WorkflowEdgesUpdateRequest, WorkflowInstanceInitializeRequest,
    LogQueryRequest, PodLogResponse, SuccessResponse
)
from app.exception import NotFoundError, ForbiddenError, ValidationError, InternalError
from app.services import WorkflowEngine
from app.services.k8s_service_client import get_k8s_service_client
from app.config import get_config

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/workflow-instances", tags=["Workflow Instances"])


def get_k8s_client():
    """获取K8S微服务客户端"""
    return get_k8s_service_client()


# ============ Ingress Controller 代理接口 ============


@router.get("/ingress-controllers", summary="获取可用的Ingress Controller列表")
async def get_ingress_controllers(
    current_user: dict = Depends(get_current_user)
):
    """
    获取集群中可用的Ingress Controller列表

    代理调用k8s微服务接口，返回Ingress Controller的名称、外部IP、端口等信息。
    供前端在创建节点时选择Ingress配置使用。
    """
    k8s_client = get_k8s_client()
    controllers = k8s_client.get_ingress_controllers()
    return {"total": len(controllers), "items": controllers}


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

    JOB类型节点:
    - 直接上报初始化成功
    - 不创建任何K8S资源（Job在start时创建并执行）

    APP类型节点:
    - 必须在模板中定义Service（create_service=True 且 service_ports不为空）
    - 必须在模板中定义service_name（用于创建Service）
    - 创建对应的Deployment
    - 使用模板中定义的service_name创建Service（不能使用自动生成的名称）
    - 如果模板未定义Service或Service创建失败，则上报初始化失败

    注意:
    - 初始化成功后状态变为INITIALIZED
    - 创建完成后可通过start API启动工作流

    强制初始化 (force=True):
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
    if instance.status == WorkflowStatus.INITIALIZING:
        raise ValidationError(f"Workflow instance is already initializing, please wait")

    if instance.status == WorkflowStatus.RUNNING:
        raise ValidationError(f"Cannot initialize running instance, stop it first")

    force = request.force

    # 检查是否需要强制初始化
    if instance.status not in [WorkflowStatus.PENDING, WorkflowStatus.INITIALIZED, WorkflowStatus.STOPPED]:
        raise ValidationError(f"Cannot initialize instance in status: {instance.status}")

    if instance.status in [WorkflowStatus.INITIALIZED, WorkflowStatus.STOPPED] and not force:
        raise ValidationError(
            f"Workflow instance already initialized. Use force=True to re-initialize (this will delete existing resources)"
        )

    k8s_client = get_k8s_client()

    # 验证namespace
    namespace_exists, namespace_error = k8s_client.ensure_namespace(instance.project_id)
    if not namespace_exists:
        raise InternalError(f"Namespace验证失败: {namespace_error}")

    # 设置状态为正在初始化
    instance.status = WorkflowStatus.INITIALIZING
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

    # 如果强制初始化，先删除已存在的K8S资源
    if force and instance.status in [WorkflowStatus.INITIALIZED, WorkflowStatus.STOPPED]:
        init_logs.append(f"[{datetime.utcnow().isoformat()}] 强制初始化: 删除已存在的K8S资源")
        logger.info(f"Force initialization: deleting existing K8S resources for instance {instance_id}")
        for node in nodes:
            if node.k8s_resource_name:
                try:
                    if node.k8s_resource_type == "Deployment":
                        k8s_client.delete_deployment(instance.project_id, node.k8s_resource_name)
                        logger.info(f"Deleted Deployment {node.k8s_resource_name} for node {node.id}")
                        init_logs.append(f"  - 删除 Deployment {node.k8s_resource_name}")
                        if node.service_name:
                            k8s_client.delete_service(instance.project_id, node.service_name)
                            logger.info(f"Deleted Service {node.service_name} for node {node.id}")
                            init_logs.append(f"  - 删除 Service {node.service_name}")
                            # 删除关联的 Ingress
                            if node.ingress_type:
                                k8s_client.delete_ingress(instance.project_id, node.service_name)
                                logger.info(f"Deleted Ingress {node.service_name} for node {node.id}")
                                init_logs.append(f"  - 删除 Ingress {node.service_name}")
                    elif node.k8s_resource_type == "Job":
                        k8s_client.delete_job(instance.project_id, node.k8s_resource_name)
                        logger.info(f"Deleted Job {node.k8s_resource_name} for node {node.id}")
                        init_logs.append(f"  - 删除 Job {node.k8s_resource_name}")
                except Exception as e:
                    logger.warning(f"Failed to delete K8S resource {node.k8s_resource_name}: {e}")
                    init_logs.append(f"  - 删除失败 {node.k8s_resource_name}: {e}")
                # 清空节点资源信息
                node.k8s_resource_name = None
                node.k8s_resource_type = None
                node.service_name = None
                node.ingress_type = None
                node.ingress_host = None
                node.ingress_ip = None
                node.status = NodeStatus.PENDING
        db.commit()

    initialized_nodes = []
    errors = []

    for node in nodes:
        # 处理JOB类型节点：直接上报初始化成功
        if node.node_type == NodeType.JOB:
            logger.info(f"JOB node {node.id} initialized successfully (no K8S resources needed)")
            init_logs.append(f"[{datetime.utcnow().isoformat()}] 初始化节点 {node.name} (ID: {node.id})")
            init_logs.append(f"  类型: JOB, 无需创建K8S资源")
            init_logs.append(f"  成功: JOB节点初始化完成")
            node.status = NodeStatus.PENDING
            node.message = "JOB node initialized successfully"
            initialized_nodes.append(node.id)
            continue

        # 处理APP类型节点
        # 跳过已经有K8S资源的节点（非强制初始化时）
        if not force and node.k8s_resource_name:
            logger.info(f"Skipping node {node.id}, already has resource {node.k8s_resource_name}")
            initialized_nodes.append(node.id)
            continue

        try:
            init_logs.append(f"[{datetime.utcnow().isoformat()}] 初始化节点 {node.name} (ID: {node.id})")

            # 获取应用模板
            template = db.query(AppTemplate).filter(AppTemplate.id == node.template_id).first()
            if not template:
                error_msg = f"App template {node.template_id} not found for node {node.id}"
                errors.append(error_msg)
                init_logs.append(f"  错误: {error_msg}")
                continue

            # 从节点配置中获取服务相关参数
            # 查找当前节点在instance.nodes中的配置
            node_config = None
            for n in instance.nodes:
                if n.get("id") == node.node_id or n.get("node_id") == node.node_id:
                    node_config = n
                    break

            if not node_config:
                error_msg = f"Node configuration not found for node {node.id}"
                errors.append(error_msg)
                init_logs.append(f"  错误: {error_msg}")
                node.status = NodeStatus.FAILED
                node.message = error_msg
                continue

            # 检查是否创建Service
            create_service = node_config.get("create_service", True)
            if create_service:
                # 检查service_name
                service_name = node_config.get("service_name")
                if not service_name or not service_name.strip():
                    error_msg = f"Service name is required when create_service is True for node {node.id}"
                    errors.append(error_msg)
                    init_logs.append(f"  错误: {error_msg}")
                    node.status = NodeStatus.FAILED
                    node.message = error_msg
                    continue

                # 检查service_ports
                service_ports = node_config.get("service_ports", [])
                if not service_ports or len(service_ports) == 0:
                    error_msg = f"Service ports cannot be empty when create_service is True for node {node.id}"
                    errors.append(error_msg)
                    init_logs.append(f"  错误: {error_msg}")
                    node.status = NodeStatus.FAILED
                    node.message = error_msg
                    continue

            # 构建容器配置
            containers = _build_containers_from_template(template, node)
            init_logs.append(f"  模板: {template.name}, 容器数: {len(containers)}, replicas: {template.replicas}")

            # 生成Deployment名称
            deployment_name = f"wf-{instance_id[:8]}-{node.node_id[:8]}"
            node.k8s_resource_name = deployment_name
            node.k8s_resource_type = "Deployment"

            # 创建Deployment
            # 使用节点配置中的service_ports（如果需要创建Service的话）
            deployment_ports = service_ports if create_service else []
            # 确保replicas至少为1
            replicas = template.replicas if template.replicas and template.replicas > 0 else 1
            init_logs.append(f"  创建Deployment: {deployment_name}, replicas: {replicas}")
            success, error_msg = k8s_client.create_deployment(
                project_id=instance.project_id,
                name=deployment_name,
                containers=containers,
                ports=deployment_ports,
                replicas=replicas
            )

            if not success:
                errors.append(f"Failed to create Deployment for node {node.id}: {error_msg}")
                init_logs.append(f"  错误: 创建Deployment失败 - {error_msg}")
                node.status = NodeStatus.FAILED
                node.message = f"Failed to create Deployment: {error_msg}"
                continue

            init_logs.append(f"  成功: 创建Deployment {deployment_name}")

            # 转换端口格式: ServicePort schema使用target_port (snake_case)
            # 但create_service期望targetPort (camelCase)
            k8s_service_ports = []
            for p in service_ports:
                port_config = {
                    "name": p.get("name", f"port-{p.get('port')}"),
                    "port": p.get("port"),
                    "targetPort": p.get("target_port", p.get("port")),  # 转换为camelCase
                    "protocol": p.get("protocol", "TCP")
                }
                k8s_service_ports.append(port_config)

            # 获取service_type，默认ClusterIP
            service_type = node_config.get("service_type", "ClusterIP")
            # Convert ServiceType enum to string if needed
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

                # 创建Ingress (如果配置了)
                ingress_type = node_config.get("ingress_type")
                ingress_host = node_config.get("ingress_host")
                ingress_ip = node_config.get("ingress_ip")

                if ingress_type and ingress_host:
                    # Ingress名称与Service名称相同
                    ingress_name = service_name
                    # 获取第一个端口作为Ingress后端端口
                    first_port = service_ports[0].get("port", 80) if service_ports else 80

                    ingress_success, ingress_error = k8s_client.create_ingress(
                        project_id=instance.project_id,
                        name=ingress_name,
                        service_name=service_name,
                        service_port=first_port,
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

                # 检查Deployment状态来确定节点状态
                # PENDING: Pod未运行
                # NOT_READY: Pod已运行但未就绪
                # READY: Pod全部就绪
                try:
                    deployment_status = k8s_client.get_deployment_status(instance.project_id, deployment_name)
                    if deployment_status:
                        ready_replicas = deployment_status.get("ready_replicas", 0) or deployment_status.get("ready_replica", 0)
                        replicas = deployment_status.get("replicas", 0) or deployment_status.get("replica", 0)
                        available_replicas = deployment_status.get("available_replicas", 0) or deployment_status.get("available_replica", 0)

                        init_logs.append(f"  Deployment状态: replicas={replicas}, ready={ready_replicas}, available={available_replicas}")

                        if ready_replicas >= replicas and replicas > 0:
                            # Pod全部就绪
                            node.status = NodeStatus.READY
                            node.message = "Deployment is ready"
                            init_logs.append(f"  节点状态: READY (Pod已就绪)")
                        elif available_replicas > 0 or ready_replicas > 0:
                            # Pod已运行但未全部就绪
                            node.status = NodeStatus.NOT_READY
                            node.message = "Deployment is running but not ready"
                            init_logs.append(f"  节点状态: NOT_READY (Pod运行中但未就绪)")
                        else:
                            # Pod未运行
                            node.status = NodeStatus.PENDING
                            node.message = "Deployment created, waiting for Pod"
                            init_logs.append(f"  节点状态: PENDING (等待Pod启动)")
                    else:
                        # 无法获取状态，默认PENDING
                        node.status = NodeStatus.PENDING
                        node.message = "APP node initialized successfully"
                        init_logs.append(f"  节点状态: PENDING (无法获取Deployment状态)")
                except Exception as status_error:
                    logger.warning(f"Failed to get deployment status: {status_error}")
                    node.status = NodeStatus.PENDING
                    node.message = "APP node initialized successfully"
                    init_logs.append(f"  节点状态: PENDING (获取状态异常: {status_error})")

                initialized_nodes.append(node.id)
                logger.info(f"Initialized node {node.id} with Deployment {deployment_name} and Service {service_name}")
            else:
                # Service创建失败，删除已创建的Deployment，上报初始化失败
                error_msg = f"Failed to create Service {service_name}: {error_msg}"
                errors.append(error_msg)
                init_logs.append(f"  错误: 创建Service失败 - {error_msg}")
                node.status = NodeStatus.FAILED
                node.message = error_msg
                # 尝试清理已创建的Deployment
                try:
                    k8s_client.delete_deployment(instance.project_id, deployment_name)
                    init_logs.append(f"  清理: 已删除Deployment {deployment_name}")
                except Exception as cleanup_error:
                    logger.warning(f"Failed to cleanup Deployment {deployment_name}: {cleanup_error}")
                    init_logs.append(f"  清理失败: 删除Deployment {deployment_name} 失败 - {cleanup_error}")
                continue

        except Exception as e:
            logger.error(f"Error initializing node {node.id}: {e}")
            error_msg = f"Error initializing node {node.id}: {str(e)}"
            errors.append(error_msg)
            init_logs.append(f"  异常: {error_msg}")
            node.status = NodeStatus.FAILED
            node.message = error_msg

    db.commit()

    # 更新工作流状态
    init_logs.append(f"[{datetime.utcnow().isoformat()}] 初始化完成")
    if errors and not initialized_nodes:
        # 所有节点初始化都失败
        instance.status = WorkflowStatus.FAILED
        instance.message = f"Initialization failed: {'; '.join(errors)}"
        init_logs.append(f"结果: 全部失败 - {'; '.join(errors)}")
        logger.error(f"Workflow {instance_id} initialization failed: {errors}")
    elif errors:
        # 部分节点初始化失败，但仍有成功的节点
        instance.status = WorkflowStatus.INITIALIZED
        instance.message = f"Initialization completed with errors: {'; '.join(errors)}"
        init_logs.append(f"结果: 部分成功 - 成功 {len(initialized_nodes)} 个, 失败 {len(errors)} 个")
        logger.warning(f"Workflow {instance_id} initialized with errors: {errors}")
    elif initialized_nodes:
        # 全部成功
        instance.status = WorkflowStatus.INITIALIZED
        action = "re-initialized" if force else "initialized"
        instance.message = f"Successfully {action} {len(initialized_nodes)} app nodes"
        init_logs.append(f"结果: 全部成功 - {len(initialized_nodes)} 个节点")
    else:
        # 没有需要初始化的节点
        instance.status = WorkflowStatus.PENDING
        instance.message = "No app nodes to initialize"
        init_logs.append(f"结果: 无需初始化的节点")

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
    return instance.created_by == user_id


def build_instance_response(instance: WorkflowInstance, db: Session) -> Dict[str, Any]:
    """Build workflow instance response dict with nodes from WorkflowNodeInstance table"""
    # Get nodes from WorkflowNodeInstance table (has runtime status)
    node_instances = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.instance_id == instance.id
    ).all()

    # Build nodes list for response
    nodes_data = []
    for node in node_instances:
        nodes_data.append({
            "id": node.id,
            "node_id": node.node_id,
            "node_type": node.node_type,
            "template_id": node.template_id,
            "name": node.name,
            "status": node.status,
            "k8s_resource_name": node.k8s_resource_name,
            "k8s_resource_type": node.k8s_resource_type,
            "depends_on": node.depends_on or [],
            "downstream_node_ids": node.downstream_node_ids or [],
            "service_name": node.service_name,
            "timeout_seconds": node.timeout_seconds,
            "started_at": node.started_at.isoformat() if node.started_at else None,
            "finished_at": node.finished_at.isoformat() if node.finished_at else None,
            "message": node.message,
            "init_logs": node.init_logs,  # 初始化日志
            "position": node.position or {"x": 0.0, "y": 0.0},
            "env_vars": node.env_vars or [],
            "volume_mounts": node.volume_mounts or [],
            "resources": node.resources,
            "input_env_vars": node.input_env_vars or [],
            "input_volume_mounts": node.input_volume_mounts or [],
            "created_at": node.created_at.isoformat() if node.created_at else None,
        })

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
        "has_warning": instance.has_warning,  # 告警标记
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
        trigger_url = f"/api/workflow/trigger/{instance_id}"

    # Convert nodes and edges to dict for storage
    nodes_dict = []
    for n in nodes:
        if hasattr(n, 'model_dump'):
            nodes_dict.append(n.model_dump())
        else:
            nodes_dict.append(n.dict())

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
    for node_config in nodes_dict:
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
            volume_mounts=node_config.get("volume_mounts", []),
            resources=node_config.get("resources"),
            depends_on=depends_on,
            downstream_node_ids=[],  # Initialize empty, will be built after all nodes created
            timeout_seconds=node_config.get("timeout_seconds"),
            input_env_vars=node_config.get("input_env_vars", []),
            input_volume_mounts=node_config.get("input_volume_mounts", []),
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
    """List workflow instance"""
    user_id = str(current_user.get("id", ""))

    query = db.query(WorkflowInstance).filter(WorkflowInstance.created_by == user_id)

    if project_id:
        query = query.filter(WorkflowInstance.project_id == project_id)
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

    # 其他字段可以在 pending, initialized, stopped 状态下修改
    if instance.status not in [WorkflowStatus.PENDING, WorkflowStatus.INITIALIZED, WorkflowStatus.STOPPED]:
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

    if instance.status not in [WorkflowStatus.PENDING, WorkflowStatus.INITIALIZED, WorkflowStatus.STOPPED]:
        raise ValidationError(f"Cannot start instance in status: {instance.status}. Valid states: pending, initialized, stopped")

    # Update run count and last run time
    instance.run_count += 1
    from datetime import datetime
    instance.last_run_at = datetime.utcnow()
    db.commit()

    # 使用WorkflowEngine来执行工作流（自动选择K8S客户端模式）
    try:
        from app.models import get_session_factory
        
        # 为后台任务创建独立的 Session
        bg_session = get_session_factory()()
        
        engine = WorkflowEngine(instance_id, bg_session)
        await engine.initialize()

        # 验证namespace
        namespace_exists, namespace_error = engine.k8s_client.ensure_namespace(instance.project_id)
        if not namespace_exists:
            bg_session.close()
            raise InternalError(f"Namespace验证失败: {namespace_error}")

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
    # 这对于异常状态恢复、状态校验等场景非常有用

    from datetime import datetime
    sync_start_time = datetime.utcnow()
    sync_logs = []

    try:
        sync_logs.append(f"[{sync_start_time.isoformat()}] 开始同步工作流状态")

        engine = WorkflowEngine(instance_id, db)
        await engine.initialize()
        await engine.sync_all_nodes_status()

        sync_logs.append(f"工作流状态: {instance.status}, 节点数: {len(engine.nodes)}")

        # 检查资源残留和状态一致性
        # 1. 检查数据库中记录的资源是否在K8S集群中存在
        # 2. 主动查询K8S集群中与该工作流相关的资源（可能存在资源泄露）
        k8s_client = get_k8s_client()

        # 获取所有可能与该工作流相关的资源名称前缀
        instance_prefix = f"wf-{instance_id[:8]}-"

        # 主动查询K8S集群中的资源
        try:
            all_deployments = k8s_client.list_deployments(instance.project_id)
            all_services = k8s_client.list_services(instance.project_id)
            all_jobs = k8s_client.list_jobs(instance.project_id)
            sync_logs.append(f"查询K8S资源: Deployments={len(all_deployments)}, Services={len(all_services)}, Jobs={len(all_jobs)}")
        except Exception as e:
            logger.warning(f"Failed to list K8S resources: {e}")
            sync_logs.append(f"查询K8S资源失败: {e}")
            all_deployments = []
            all_services = []
            all_jobs = []

        # 筛选出属于该工作流的资源
        workflow_deployments = [d for d in all_deployments if d.get("name", "").startswith(instance_prefix)]
        workflow_services = [s for s in all_services if s.get("name", "").startswith(instance_prefix)]
        workflow_jobs = [j for j in all_jobs if j.get("name", "").startswith(instance_prefix)]

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

        # 构建告警消息
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
            # 清除之前的告警标记
            instance.has_warning = False
            instance.message = "状态同步完成，资源状态一致"
            sync_logs.append("结果: 资源状态一致，已清除告警")
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
        # 这里不再调用 start_node 来避免在同步状态时创建资源

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
    - Can be called from INITIALIZED or RUNNING state
    - Sets status to STOPPED
    """
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to stop this instance")

    if instance.status not in [WorkflowStatus.INITIALIZED, WorkflowStatus.RUNNING]:
        raise ValidationError(f"Cannot stop instance in status: {instance.status}. Valid states: initialized, running")

    # 获取K8S客户端（自动选择模式）
    config = get_config()
    if config.k8s_service and config.k8s_service.enabled:
        from app.services.k8s_service_client import get_k8s_service_client
        k8s_client = get_k8s_service_client()
    else:
        k8s_client = get_k8s_client()

    # Stop all nodes
    nodes = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.instance_id == instance_id
    ).all()

    for node in nodes:
        if node.k8s_resource_name:
            try:
                if node.k8s_resource_type == "Deployment":
                    k8s_client.delete_deployment(instance.project_id, node.k8s_resource_name)
                    if node.service_name:
                        k8s_client.delete_service(instance.project_id, node.service_name)
                        # 删除关联的 Ingress
                        if node.ingress_type:
                            k8s_client.delete_ingress(instance.project_id, node.service_name)
                elif node.k8s_resource_type == "Job":
                    k8s_client.delete_job(instance.project_id, node.k8s_resource_name)

                node.status = NodeStatus.STOPPED
                from datetime import datetime
                node.finished_at = datetime.utcnow()
            except Exception as e:
                logger.error(f"Failed to stop node {node.id}: {e}")
                node.message = str(e)

    instance.status = WorkflowStatus.STOPPED
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
    反初始化工作流实例

    - 删除所有已创建的 K8S 资源（Deployment、Service、Job）
    - 清空节点的 K8S 资源信息
    - 将所有节点状态重置为 PENDING
    - 将工作流状态重置为 PENDING

    前置条件:
    - 状态为 INITIALIZED、RUNNING、STOPPED、FAILED 或 SUCCEEDED

    用途:
    - 完全重置工作流到初始状态
    - 清理所有 K8S 资源后重新配置
    """
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to uninitialize this instance")

    # 检查状态 - 只能在已初始化或之后的状态下反初始化
    valid_states = [
        WorkflowStatus.INITIALIZED,
        WorkflowStatus.RUNNING,
        WorkflowStatus.STOPPED,
        WorkflowStatus.FAILED,
        WorkflowStatus.SUCCEEDED
    ]
    if instance.status not in valid_states:
        raise ValidationError(
            f"Cannot uninitialize instance in status: {instance.status}. "
            f"Valid states: initialized, running, stopped, failed, succeeded"
        )

    k8s_client = get_k8s_client()

    # 获取所有节点
    nodes = db.query(WorkflowNodeInstance).filter(
        WorkflowNodeInstance.instance_id == instance_id
    ).all()

    deleted_count = 0
    errors = []

    for node in nodes:
        # 删除 K8S 资源 - 每种资源类型独立删除，互不影响
        if node.k8s_resource_name:
            # 删除 Deployment
            if node.k8s_resource_type == "Deployment":
                try:
                    k8s_client.delete_deployment(instance.project_id, node.k8s_resource_name)
                    logger.info(f"Deleted Deployment {node.k8s_resource_name} for node {node.id}")
                    deleted_count += 1
                except Exception as e:
                    error_msg = f"Failed to delete Deployment {node.k8s_resource_name}: {e}"
                    logger.error(error_msg)
                    errors.append(error_msg)

                # 删除可能关联的 Service
                # Service 可能有多个名称:
                # 1. node.service_name (记录的名称)
                # 2. k8s_resource_name (与 deployment 同名)
                # 3. svc-{k8s_resource_name} (旧命名方式)
                possible_service_names = set()
                if node.service_name:
                    possible_service_names.add(node.service_name)
                possible_service_names.add(node.k8s_resource_name)  # 与 deployment 同名
                possible_service_names.add(f"svc-{node.k8s_resource_name}")  # 旧命名方式

                for svc_name in possible_service_names:
                    try:
                        k8s_client.delete_service(instance.project_id, svc_name)
                        logger.info(f"Deleted Service {svc_name} for node {node.id}")
                        deleted_count += 1
                    except Exception as e:
                        # Service 不存在或删除失败，只记录 debug 日志
                        logger.debug(f"Service {svc_name} delete skipped: {e}")

                # 删除关联的 Ingress
                if node.ingress_type and node.service_name:
                    try:
                        k8s_client.delete_ingress(instance.project_id, node.service_name)
                        logger.info(f"Deleted Ingress {node.service_name} for node {node.id}")
                        deleted_count += 1
                    except Exception as e:
                        logger.debug(f"Ingress {node.service_name} delete skipped: {e}")

            # 删除 Job
            elif node.k8s_resource_type == "Job":
                try:
                    k8s_client.delete_job(instance.project_id, node.k8s_resource_name)
                    logger.info(f"Deleted Job {node.k8s_resource_name} for node {node.id}")
                    deleted_count += 1
                except Exception as e:
                    error_msg = f"Failed to delete Job {node.k8s_resource_name}: {e}"
                    logger.error(error_msg)
                    errors.append(error_msg)

        # 清空节点资源信息并重置状态
        node.k8s_resource_name = None
        node.k8s_resource_type = None
        node.service_name = None
        node.ingress_type = None
        node.ingress_host = None
        node.ingress_ip = None
        node.status = NodeStatus.PENDING
        node.started_at = None
        node.finished_at = None
        node.message = None

    # 重置工作流状态
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

    # Delete K8S resources if initialized or running
    if instance.status in [WorkflowStatus.INITIALIZED, WorkflowStatus.RUNNING]:
        k8s_client = get_k8s_client()
        nodes = db.query(WorkflowNodeInstance).filter(
            WorkflowNodeInstance.instance_id == instance_id
        ).all()

        for node in nodes:
            if node.k8s_resource_name:
                try:
                    if node.k8s_resource_type == "Deployment":
                        k8s_client.delete_deployment(instance.project_id, node.k8s_resource_name)
                        if node.service_name:
                            k8s_client.delete_service(instance.project_id, node.service_name)
                            # 删除关联的 Ingress
                            if node.ingress_type:
                                k8s_client.delete_ingress(instance.project_id, node.service_name)
                    elif node.k8s_resource_type == "Job":
                        k8s_client.delete_job(instance.project_id, node.k8s_resource_name)
                except Exception as e:
                    logger.error(f"Failed to delete K8S resource for node {node.id}: {e}")

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

    k8s_client = get_k8s_client()

    # Get pod for the node
    if node.k8s_resource_type == "Deployment":
        pods = k8s_client.get_deployment_pods(instance.project_id, node.k8s_resource_name)
    else:  # Job
        pods = k8s_client.get_job_pods(instance.project_id, node.k8s_resource_name)

    if not pods:
        raise NotFoundError("Pod", f"No pods found for node {node_id}")

    # Get logs from the first pod
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

    return PodLogResponse(
        resource_name=node.k8s_resource_name,
        pod_name=pod_name,
        namespace=k8s_client.get_project_namespace(instance.project_id),
        logs=logs,
        container=container,
        previous=previous
    )


@router.get("/{instance_id}/nodes/{node_id}/init-logs")
async def get_node_init_logs(
    instance_id: str,
    node_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    获取工作流节点的初始化日志

    - 返回节点初始化过程中记录的详细日志
    - 包含初始化时间、创建的资源、错误信息等
    - 用于排查初始化失败的原因
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
        "init_logs": node.init_logs or "暂无初始化日志"
    }


# ============ Trigger Endpoints ============

@router.post("/trigger/{instance_id}", response_model=SuccessResponse)
async def trigger_workflow_by_http(
    instance_id: str,
    db: Session = Depends(get_db)
):
    """
    Trigger workflow execution via HTTP endpoint

    - For persistent mode workflows with HTTP trigger enabled
    - Can be called without authentication (internal use)
    - Returns immediately, workflow runs asynchronously
    - Valid states: initialized (can trigger), running (reject - already running), stopped (need to start first)
    """
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    # Check if trigger is enabled
    if not instance.trigger_enabled:
        raise ValidationError(f"Trigger is not enabled for workflow instance {instance_id}")

    if not instance.is_active:
        raise ValidationError(f"Workflow instance {instance_id} is not active")

    if instance.trigger_type != "http":
        raise ValidationError(f"Workflow instance {instance_id} is not configured for HTTP trigger")

    # Check if workflow can be triggered
    # Valid states: initialized (can trigger), stopped (can trigger)
    if instance.status == WorkflowStatus.RUNNING:
        raise ValidationError(f"Workflow instance {instance_id} is already running")
    if instance.status == WorkflowStatus.PENDING:
        raise ValidationError(f"Workflow instance {instance_id} is not initialized. Call initialize first.")

    # Start workflow
    try:
        from app.models import get_session_factory
        
        # 为后台任务创建独立的 Session
        bg_session = get_session_factory()()
        
        engine = WorkflowEngine(instance_id, bg_session)
        await engine.initialize()

        # Verify namespace exists
        namespace_exists, namespace_error = engine.k8s_client.ensure_namespace(instance.project_id)
        if not namespace_exists:
            bg_session.close()
            raise InternalError(f"Namespace验证失败: {namespace_error}")

        # Update run count and last run time
        instance.run_count += 1
        from datetime import datetime
        instance.last_run_at = datetime.utcnow()

        # Execute workflow asynchronously with its own session
        async def run_workflow_with_session():
            try:
                await engine.execute_workflow()
            finally:
                bg_session.close()
        
        asyncio.create_task(run_workflow_with_session())

        logger.info(f"Triggered workflow instance {instance_id} via HTTP trigger")

    except ValueError as e:
        raise ValidationError(str(e))
    except Exception as e:
        logger.error(f"Failed to trigger workflow {instance_id}: {e}")
        raise InternalError(f"Failed to trigger workflow: {str(e)}")

    db.commit()
    return SuccessResponse(message=f"Workflow {instance_id} triggered successfully")


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

    # Workflow must be initialized or stopped to be activated
    if instance.status not in [WorkflowStatus.INITIALIZED, WorkflowStatus.STOPPED]:
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

    # For app type nodes, ensure service configuration is included
    if node_type_val == "app":
        # These fields are already in the node_config from the Pydantic model
        pass

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
        volume_mounts=[vm.model_dump() if hasattr(vm, 'model_dump') else vm.dict() for vm in (node_data.volume_mounts or [])],
        resources=node_data.resources.model_dump() if node_data.resources and hasattr(node_data.resources, 'model_dump') else (node_data.resources.dict() if node_data.resources else None),
        depends_on=depends_on,
        downstream_node_ids=[],  # Will be rebuilt from edges
        timeout_seconds=node_data.timeout_seconds,
        input_env_vars=[],
        input_volume_mounts=[],
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
    return node_instance


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
    node_volume_mounts = node_data.volume_mounts or []

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

    return nodes


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

    return node


@router.put("/{instance_id}/nodes/{node_instance_id}", response_model=WorkflowNodeInstanceResponse)
async def update_workflow_node(
    instance_id: str,
    node_instance_id: str,
    node_data: WorkflowNodeUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update workflow node configuration

    Note: 只能在 pending 状态下修改节点配置，初始化后不允许修改
    """
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

    # Update node instance fields
    if node_data.name is not None:
        node.name = node_data.name
    if node_data.position is not None:
        node.position = node_data.position
    if node_data.env_vars is not None:
        node.env_vars = [e.model_dump() if hasattr(e, 'model_dump') else e.dict() for e in node_data.env_vars]
    if node_data.volume_mounts is not None:
        node.volume_mounts = [vm.model_dump() if hasattr(vm, 'model_dump') else vm.dict() for vm in node_data.volume_mounts]
    if node_data.resources is not None:
        node.resources = node_data.resources.model_dump() if hasattr(node_data.resources, 'model_dump') else node_data.resources.dict()
    if node_data.input_env_vars is not None:
        node.input_env_vars = [iev.model_dump() if hasattr(iev, 'model_dump') else iev.dict() for iev in node_data.input_env_vars]
    if node_data.input_volume_mounts is not None:
        node.input_volume_mounts = [ivm.model_dump() if hasattr(ivm, 'model_dump') else ivm.dict() for ivm in node_data.input_volume_mounts]

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
            if node_data.volume_mounts is not None:
                existing_node["volume_mounts"] = [vm.model_dump() if hasattr(vm, 'model_dump') else vm.dict() for vm in node_data.volume_mounts]
            if node_data.resources is not None:
                existing_node["resources"] = node_data.resources.model_dump() if hasattr(node_data.resources, 'model_dump') else node_data.resources.dict()
            if node_data.input_env_vars is not None:
                existing_node["input_env_vars"] = [iev.model_dump() if hasattr(iev, 'model_dump') else iev.dict() for iev in node_data.input_env_vars]
            if node_data.input_volume_mounts is not None:
                existing_node["input_volume_mounts"] = [ivm.model_dump() if hasattr(ivm, 'model_dump') else ivm.dict() for ivm in node_data.input_volume_mounts]
            # Update service configuration
            if node_data.create_service is not None:
                existing_node["create_service"] = node_data.create_service
            if node_data.service_name is not None:
                existing_node["service_name"] = node_data.service_name
            if node_data.service_ports is not None:
                existing_node["service_ports"] = [sp.model_dump() if hasattr(sp, 'model_dump') else sp.dict() for sp in node_data.service_ports]
            if node_data.service_type is not None:
                existing_node["service_type"] = node_data.service_type.value if hasattr(node_data.service_type, 'value') else node_data.service_type
            # Update ingress configuration
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

    db.commit()
    db.refresh(node)

    logger.info(f"Updated workflow node {node_instance_id} in instance {instance_id}")
    return node


@router.delete("/{instance_id}/nodes/{node_instance_id}", response_model=SuccessResponse)
async def delete_workflow_node(
    instance_id: str,
    node_instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete workflow node

    Note: 只能在 pending 状态下删除节点，初始化后不允许删除
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

    Note: 只能在 pending 状态下修改边（节点依赖关系），初始化后不允许修改
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