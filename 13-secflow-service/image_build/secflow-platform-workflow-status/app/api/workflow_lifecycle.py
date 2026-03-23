"""
Workflow lifecycle routes for workflow-status service.
"""

import asyncio
import logging
from typing import Optional

from fastapi import APIRouter, Body, Depends, Header

from app.config import get_config
from app.exception import InternalError, UnauthorizedError, ValidationError
from app.schemas.schemas import (
    NodeStartRequest,
    NodeStartResponse,
    WorkflowDeinitializeRequest,
    WorkflowInitializeRequest,
    WorkflowLifecycleResponse,
    WorkflowStopRequest,
    WorkflowTriggerRequest,
    WorkflowTriggerResponse,
)
from app.services.node_lifecycle_service import get_node_lifecycle_service
from app.services.workflow_execution_service import get_workflow_execution_service
from app.services.workflow_lifecycle_service import get_workflow_lifecycle_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/workflow-status", tags=["Workflow Lifecycle"])


async def get_current_user(
    authorization: Optional[str] = Header(None),
) -> dict:
    """Validate and return current user."""
    config = get_config()
    if not config.auth_service.enabled:
        return {"user": {"id": "system", "username": "system", "role": ["admin"]}}

    if not authorization:
        raise UnauthorizedError("Missing authorization token")

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise UnauthorizedError("Invalid authorization header format")

    # TODO: validate token with auth service.
    return {"user": {"id": "system", "username": "system", "role": ["admin"]}}


@router.post(
    "/instances/{instance_id}/initialize",
    response_model=WorkflowLifecycleResponse,
    summary="Initialize workflow",
    description="Create K8S resources required by workflow nodes.",
)
async def initialize_workflow(
    instance_id: str,
    request: WorkflowInitializeRequest = Body(...),
    user: dict = Depends(get_current_user),
):
    """Initialize a workflow instance."""
    try:
        if not request.nodes:
            raise ValidationError("Node list cannot be empty")

        lifecycle_service = get_workflow_lifecycle_service()
        nodes = []
        for node in request.nodes:
            nodes.append(
                {
                    "node_id": node.node_id,
                    "node_type": node.node_type,
                    "node_name": node.node_name,
                    "deployment_name": node.deployment_name,
                    "service_name": node.service_name,
                    "ingress_config": node.ingress_config.model_dump() if node.ingress_config else None,
                    "containers": node.containers if node.containers else [],
                    "volume_mounts": node.volume_mounts,
                    "replicas": node.replicas,
                    "service_ports": node.service_ports if node.service_ports else [],
                    "service_type": node.service_type,
                    "job_config": node.job_config.model_dump() if node.job_config else None,
                }
            )

        return await lifecycle_service.initialize_workflow(
            instance_id=instance_id,
            project_id=request.project_id,
            nodes=nodes,
        )
    except ValidationError:
        raise
    except Exception as e:
        logger.error("Failed to initialize workflow: %s", e)
        raise InternalError(f"Failed to initialize workflow: {str(e)}")


@router.post(
    "/instances/{instance_id}/uninitialize",
    response_model=WorkflowLifecycleResponse,
    summary="Uninitialize workflow",
    description="Delete K8S resources managed by one workflow instance.",
)
async def uninitialize_workflow(
    instance_id: str,
    request: WorkflowDeinitializeRequest = Body(...),
    user: dict = Depends(get_current_user),
):
    """Uninitialize a workflow instance."""
    try:
        lifecycle_service = get_workflow_lifecycle_service()
        return await lifecycle_service.deinitialize_workflow(
            instance_id=instance_id,
            project_id=request.project_id,
            nodes=request.nodes,
        )
    except Exception as e:
        logger.error("Failed to uninitialize workflow: %s", e)
        raise InternalError(f"Failed to uninitialize workflow: {str(e)}")


@router.post(
    "/instances/{instance_id}/stop",
    response_model=WorkflowLifecycleResponse,
    summary="Stop workflow",
    description="Stop a workflow instance and clean up its running resources.",
)
async def stop_workflow(
    instance_id: str,
    request: WorkflowStopRequest = Body(...),
    user: dict = Depends(get_current_user),
):
    """Stop a workflow instance."""
    try:
        lifecycle_service = get_workflow_lifecycle_service()
        return await lifecycle_service.stop_workflow(
            instance_id=instance_id,
            project_id=request.project_id,
            nodes=request.nodes,
        )
    except Exception as e:
        logger.error("Failed to stop workflow: %s", e)
        raise InternalError(f"Failed to stop workflow: {str(e)}")


@router.post(
    "/instances/{instance_id}/trigger",
    response_model=WorkflowTriggerResponse,
    summary="Trigger workflow execution",
    description="Re-execute workflow instance nodes by DAG topology with parallel branches and retry support.",
)
async def trigger_workflow(
    instance_id: str,
    request: WorkflowTriggerRequest = Body(...),
    user: dict = Depends(get_current_user),
):
    """Trigger workflow execution asynchronously."""
    try:
        execution_service = get_workflow_execution_service()
        if execution_service.is_instance_running(instance_id):
            raise ValidationError(f"Workflow instance {instance_id} is already executing")
        execution_service.validate_execution_plan(
            run_mode=request.run_mode,
            nodes=[node.model_dump() for node in request.nodes],
            edges=request.edges,
        )
        asyncio.create_task(
            execution_service.execute_trigger(
                instance_id=instance_id,
                project_id=request.project_id,
                run_mode=request.run_mode,
                nodes=[node.model_dump() for node in request.nodes],
                edges=request.edges,
            )
        )
        return WorkflowTriggerResponse(
            success=True,
            instance_id=instance_id,
            project_id=request.project_id,
            message="Workflow trigger accepted",
        )
    except ValueError as e:
        raise ValidationError(str(e))
    except Exception as e:
        logger.error("Failed to trigger workflow: %s", e)
        raise InternalError(f"Failed to trigger workflow: {str(e)}")


@router.post(
    "/nodes/{node_id}/start",
    response_model=NodeStartResponse,
    summary="Start node",
    description="Start one node by checking APP readiness or creating a JOB resource.",
)
async def start_node(
    node_id: str,
    request: NodeStartRequest = Body(...),
    user: dict = Depends(get_current_user),
):
    """Start one workflow node."""
    try:
        lifecycle_service = get_node_lifecycle_service()
        result = await lifecycle_service.start_node(
            node_id=node_id,
            instance_id=request.instance_id,
            project_id=request.project_id,
            node_type=request.node_type,
            k8s_resource_name=request.k8s_resource_name,
            job_config=request.job_config,
        )
        return NodeStartResponse(
            success=result.success,
            node_id=result.node_id,
            status=result.status,
            message=result.message,
            k8s_resource_name=result.k8s_resource_name,
            error=result.error,
        )
    except Exception as e:
        logger.error("Failed to start node: %s", e)
        raise InternalError(f"Failed to start node: {str(e)}")
