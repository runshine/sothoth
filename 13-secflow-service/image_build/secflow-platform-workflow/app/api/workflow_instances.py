"""
Workflow instance API routes
Manages workflow execution including creation, running, stopping, deletion, and log retrieval
"""
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, generate_id
from app.models import (
    get_db, WorkflowTemplate, WorkflowInstance, WorkflowNodeInstance,
    WorkflowStatus, NodeStatus, NodeType, AppTemplate, JobTemplate
)
from app.schemas import (
    WorkflowInstanceCreate, WorkflowInstanceUpdate,
    WorkflowInstanceResponse, WorkflowInstanceListResponse,
    LogQueryRequest, PodLogResponse, SuccessResponse
)
from app.exception import NotFoundError, ForbiddenError, ValidationError, InternalError
from app.services import get_k8s_client, WorkflowEngine

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/workflow-instances", tags=["Workflow Instances"])


def check_instance_permission(instance: WorkflowInstance, user_id: str) -> bool:
    """Check if user has permission to access workflow instance"""
    return instance.created_by == user_id


@router.post("", response_model=WorkflowInstanceResponse, status_code=status.HTTP_201_CREATED)
async def create_workflow_instance(
    instance_data: WorkflowInstanceCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create workflow instance from template

    - Validates template exists and user has access
    - Creates node instances from template nodes
    - Supports run_mode: "once" (run once) or "persistent" (keep running)
    - Supports trigger_type: "manual" or "http"
    - Does not start the workflow automatically (except for persistent mode with immediate trigger)
    """
    user_id = str(current_user.get("id", ""))

    # Get template
    template = db.query(WorkflowTemplate).filter(
        WorkflowTemplate.id == instance_data.template_id
    ).first()

    if not template:
        raise NotFoundError("Workflow template", instance_data.template_id)

    # Check permission
    if template.scope != "global" and template.created_by != user_id:
        raise ForbiddenError("No permission to use this template")

    # Generate instance ID
    instance_id = generate_id(instance_data.name)

    # Generate trigger URL for HTTP trigger mode
    trigger_url = None
    if instance_data.trigger_type == "http" and instance_data.trigger_enabled:
        trigger_url = f"/api/workflow/triggers/{instance_id}"

    # Create instance
    instance = WorkflowInstance(
        id=instance_id,
        name=instance_data.name,
        description=instance_data.description,
        template_id=instance_data.template_id,
        project_id=instance_data.project_id,
        status=WorkflowStatus.PENDING,
        run_mode=instance_data.run_mode.value if instance_data.run_mode else "once",
        trigger_type=instance_data.trigger_type.value if instance_data.trigger_type else "manual",
        trigger_enabled=instance_data.trigger_enabled,
        trigger_url=trigger_url,
        is_active=True,
        run_count=0,
        created_by=user_id,
    )

    db.add(instance)
    db.flush()  # Get instance ID

    # Create node instances from template nodes
    template_nodes = template.nodes or []
    for node_config in template_nodes:
        node_id = generate_id(f"{instance_id}_{node_config.get('node_id', '')}")

        # Get edges that have this node as target to build depends_on
        depends_on = node_config.get("depends_on", [])
        if not depends_on:
            # Build from edges if depends_on not explicitly set
            template_edges = template.edges or []
            for edge in template_edges:
                if edge.get("target") == node_config.get("node_id"):
                    source_id = edge.get("source")
                    if source_id and source_id not in depends_on:
                        depends_on.append(source_id)

        node_instance = WorkflowNodeInstance(
            id=node_id,
            instance_id=instance_id,
            node_id=node_config.get("node_id"),
            node_type=NodeType.APP if node_config.get("node_type") == "app" else NodeType.JOB,
            template_id=node_config.get("template_id"),
            name=node_config.get("name", "Unnamed Node"),
            status=NodeStatus.PENDING,
            depends_on=depends_on,
            input_env_vars=node_config.get("input_env_vars", []),
            input_volume_mounts=node_config.get("input_volume_mounts", []),
        )
        db.add(node_instance)

    db.commit()
    db.refresh(instance)

    logger.info(f"Created workflow instance {instance_id} from template {template.id} by user {user_id}, "
                f"run_mode={instance.run_mode}, trigger_type={instance.trigger_type}")
    return instance


@router.get("", response_model=WorkflowInstanceListResponse)
async def list_workflow_instances(
    project_id: Optional[str] = Query(None, description="Filter by project ID"),
    status: Optional[str] = Query(None, description="Filter by status"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List workflow instances"""
    user_id = str(current_user.get("id", ""))

    query = db.query(WorkflowInstance).filter(WorkflowInstance.created_by == user_id)

    if project_id:
        query = query.filter(WorkflowInstance.project_id == project_id)
    if status:
        query = query.filter(WorkflowInstance.status == status)

    instances = query.order_by(WorkflowInstance.created_at.desc()).all()

    return WorkflowInstanceListResponse(total=len(instances), items=instances)


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

    return instance


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
    """
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to update this instance")

    # Update fields
    if instance_data.name is not None:
        instance.name = instance_data.name
    if instance_data.description is not None:
        instance.description = instance_data.description

    # Handle trigger_enabled update
    if instance_data.trigger_enabled is not None:
        if instance.run_mode != "persistent":
            raise ValidationError("Only persistent mode workflows support triggers")
        instance.trigger_enabled = instance_data.trigger_enabled

    # Handle is_active update
    if instance_data.is_active is not None:
        if instance.run_mode != "persistent":
            raise ValidationError("Only persistent mode workflows support active state")
        instance.is_active = instance_data.is_active

    db.commit()
    db.refresh(instance)

    logger.info(f"Updated workflow instance {instance_id}")
    return instance


@router.post("/{instance_id}/start", response_model=WorkflowInstanceResponse)
async def start_workflow_instance(
    instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Start workflow instance

    - Uses WorkflowEngine for topological execution with dependency checking
    - Detects and prevents cyclic dependencies
    - Concurrently executes ready nodes
    - Handles environment variable and mount dependencies
    """
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to start this instance")

    if instance.status not in [WorkflowStatus.PENDING, WorkflowStatus.STOPPED]:
        raise ValidationError(f"Cannot start instance in status: {instance.status}")

    k8s_client = get_k8s_client()

    # Verify namespace exists
    if not k8s_client.ensure_namespace(instance.project_id):
        raise InternalError(f"Namespace for project {instance.project_id} does not exist")

    # Use WorkflowEngine to execute workflow
    try:
        engine = WorkflowEngine(instance_id, db, k8s_client)
        await engine.initialize()

        # Execute workflow (this runs asynchronously)
        asyncio.create_task(engine.execute_workflow())

        logger.info(f"Started workflow instance {instance_id}")

    except ValueError as e:
        raise ValidationError(str(e))
    except Exception as e:
        logger.error(f"Failed to start workflow {instance_id}: {e}")
        raise InternalError(f"Failed to start workflow: {str(e)}")

    db.refresh(instance)
    return instance


@router.post("/{instance_id}/sync-status", response_model=WorkflowInstanceResponse)
async def sync_workflow_status(
    instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Sync workflow status from K8S

    - Updates all node statuses from K8S
    - Triggers execution of ready nodes
    - Can be called periodically or manually
    """
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to access this instance")

    if instance.status != WorkflowStatus.RUNNING:
        raise ValidationError(f"Cannot sync instance in status: {instance.status}")

    k8s_client = get_k8s_client()

    try:
        engine = WorkflowEngine(instance_id, db, k8s_client)
        await engine.initialize()
        await engine.sync_all_nodes_status()

        # Check if we have ready nodes to execute
        ready_nodes = engine.get_ready_nodes()
        if ready_nodes:
            for node in ready_nodes:
                asyncio.create_task(engine.start_node(node))

    except Exception as e:
        logger.error(f"Error syncing workflow status: {e}")
        raise InternalError(f"Failed to sync status: {str(e)}")

    db.refresh(instance)
    return instance


@router.post("/{instance_id}/stop", response_model=WorkflowInstanceResponse)
async def stop_workflow_instance(
    instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Stop workflow instance

    - Deletes all K8S resources created for this workflow
    """
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to stop this instance")

    if instance.status != WorkflowStatus.RUNNING:
        raise ValidationError(f"Cannot stop instance in status: {instance.status}")

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
    return instance


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

    # Stop if running
    if instance.status == WorkflowStatus.RUNNING:
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
                    elif node.k8s_resource_type == "Job":
                        k8s_client.delete_job(instance.project_id, node.k8s_resource_name)
                except Exception as e:
                    logger.error(f"Failed to delete K8S resource for node {node.id}: {e}")

    # Delete instance (cascade will delete nodes)
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

    - For Deployment nodes: gets logs from the associated pods
    - For Job nodes: gets logs from the job pods
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

    # Get pods for the node
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


# ============ Trigger Endpoints ============

@router.post("/triggers/{instance_id}", response_model=SuccessResponse)
async def trigger_workflow_by_http(
    instance_id: str,
    db: Session = Depends(get_db)
):
    """
    Trigger workflow execution via HTTP endpoint

    - For persistent mode workflows with HTTP trigger enabled
    - Can be called without authentication (internal use)
    - Returns immediately, workflow runs asynchronously
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

    # Check if workflow can be started
    if instance.status == WorkflowStatus.RUNNING:
        raise ValidationError(f"Workflow instance {instance_id} is already running")

    # Start workflow
    k8s_client = get_k8s_client()

    # Verify namespace exists
    if not k8s_client.ensure_namespace(instance.project_id):
        raise InternalError(f"Namespace for project {instance.project_id} does not exist")

    try:
        engine = WorkflowEngine(instance_id, db, k8s_client)
        await engine.initialize()

        # Update run count and last run time
        instance.run_count += 1
        from datetime import datetime
        instance.last_run_at = datetime.utcnow()

        # Execute workflow asynchronously
        asyncio.create_task(engine.execute_workflow())

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

    - Makes the workflow instance active to accept triggers
    """
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to activate this instance")

    if instance.run_mode != "persistent":
        raise ValidationError("Only persistent mode workflows can be activated")

    instance.is_active = True
    db.commit()
    db.refresh(instance)

    logger.info(f"Activated workflow instance {instance_id}")
    return instance


@router.post("/{instance_id}/deactivate", response_model=WorkflowInstanceResponse)
async def deactivate_workflow_instance(
    instance_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Deactivate workflow instance (for persistent mode)

    - Makes the workflow instance inactive to reject triggers
    - Does not stop running workflow
    """
    instance = db.query(WorkflowInstance).filter(WorkflowInstance.id == instance_id).first()

    if not instance:
        raise NotFoundError("Workflow instance", instance_id)

    user_id = str(current_user.get("id", ""))
    if not check_instance_permission(instance, user_id):
        raise ForbiddenError("No permission to deactivate this instance")

    if instance.run_mode != "persistent":
        raise ValidationError("Only persistent mode workflows can be deactivated")

    instance.is_active = False
    db.commit()
    db.refresh(instance)

    logger.info(f"Deactivated workflow instance {instance_id}")
    return instance
