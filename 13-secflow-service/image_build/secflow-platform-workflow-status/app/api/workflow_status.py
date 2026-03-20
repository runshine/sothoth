"""
Workflow status API routes.
"""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Body, Depends, Header, Query
from sqlalchemy.orm import Session

from app.config import get_config
from app.exception import InternalError, NotFoundError, UnauthorizedError, ValidationError
from app.models.database import (
    get_db,
    get_node_status_by_instance,
    get_node_status_history,
    get_node_status_record,
    get_node_status_record_by_task_id,
    get_workflow_status_history,
    get_workflow_status_record,
    list_workflow_status_records,
)
from app.schemas.schemas import (
    BatchSyncRequest,
    BatchSyncResponse,
    NodeHistoryEntry,
    NodeHistoryResponse,
    NodeInitialRequest,
    NodeInitialResponse,
    NodeListResponse,
    NodeLogResponse,
    NodeStatusInfo,
    NodeStatusResponse,
    NodeTaskCollectRequest,
    NodeTaskCollectResponse,
    NodeSyncRequest,
    NodeSyncResponse,
    NodeUpdateRequest,
    NodeUpdateResponse,
    StatisticsResponse,
    WorkflowHistoryResponse,
    WorkflowStatusInfo,
    WorkflowStatusListResponse,
    WorkflowStatusResponse,
)
from app.services.k8s_client import get_k8s_client
from app.services.status_sync_service import get_status_sync_service
from app.services.workflow_aggregator import get_workflow_aggregator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/workflow-status", tags=["Workflow Status"])


async def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
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


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


@router.get("/ready")
async def readiness_check():
    """Readiness check endpoint."""
    return {"status": "ready"}


@router.get(
    "/infra/ingress-controllers",
    summary="Get ingress controllers",
    description="Proxy ingress controller list from K8S service.",
)
async def list_ingress_controllers(user: dict = Depends(get_current_user)):
    try:
        items = get_k8s_client().get_ingress_controllers()
        return {"total": len(items), "items": items}
    except Exception as e:
        logger.error(f"Failed to list ingress controllers: {e}")
        raise InternalError(f"Failed to list ingress controllers: {str(e)}")


@router.get(
    "/projects/{project_id}/namespace/ensure",
    summary="Ensure project namespace",
    description="Check whether project namespace is available.",
)
async def ensure_project_namespace(project_id: str, user: dict = Depends(get_current_user)):
    try:
        k8s_client = get_k8s_client()
        exists, message = k8s_client.ensure_namespace(project_id)
        return {
            "success": exists,
            "project_id": project_id,
            "namespace": k8s_client.get_project_namespace(project_id),
            "message": message,
        }
    except Exception as e:
        logger.error(f"Failed to ensure namespace: {e}")
        raise InternalError(f"Failed to ensure namespace: {str(e)}")


@router.get(
    "/projects/{project_id}/resources",
    summary="List project resources",
    description="List Deployment/Service/Job resources for project.",
)
async def list_project_resources(
    project_id: str,
    instance_prefix: Optional[str] = Query(None, description="Resource name prefix filter"),
    user: dict = Depends(get_current_user),
):
    try:
        k8s_client = get_k8s_client()
        deployments = k8s_client.list_deployments(project_id)
        services = k8s_client.list_services(project_id)
        jobs = k8s_client.list_jobs(project_id)

        if instance_prefix:
            deployments = [d for d in deployments if (d.get("name") or "").startswith(instance_prefix)]
            services = [s for s in services if (s.get("name") or "").startswith(instance_prefix)]
            jobs = [j for j in jobs if (j.get("name") or "").startswith(instance_prefix)]

        return {
            "project_id": project_id,
            "instance_prefix": instance_prefix,
            "deployments": deployments,
            "services": services,
            "jobs": jobs,
        }
    except Exception as e:
        logger.error(f"Failed to list project resources: {e}")
        raise InternalError(f"Failed to list project resources: {str(e)}")


@router.get(
    "/projects/{project_id}/resources/{resource_type}/{resource_name}/logs",
    summary="Get resource logs",
    description="Get pod logs by deployment/job resource.",
)
async def get_resource_logs(
    project_id: str,
    resource_type: str,
    resource_name: str,
    tail_lines: int = Query(100, ge=1, le=10000, description="Tail lines"),
    container: Optional[str] = Query(None, description="Container name"),
    previous: bool = Query(False, description="Read previous container logs"),
    user: dict = Depends(get_current_user),
):
    try:
        k8s_client = get_k8s_client()
        resource_type_normalized = (resource_type or "").lower()

        if resource_type_normalized in {"deployment", "app"}:
            pods = k8s_client.get_deployment_pods(project_id, resource_name)
        elif resource_type_normalized == "job":
            pods = k8s_client.get_job_pods(project_id, resource_name)
        else:
            raise ValidationError(f"Unsupported resource_type: {resource_type}")

        if not pods:
            raise NotFoundError("Pod", f"No pods found for resource {resource_name}")

        pod_name = pods[0].get("name") or pods[0].get("metadata", {}).get("name")
        if not pod_name:
            raise NotFoundError("Pod", f"Pod name not found for resource {resource_name}")

        logs = k8s_client.get_pod_logs(
            project_id=project_id,
            pod_name=pod_name,
            container=container,
            tail_lines=tail_lines,
            previous=previous,
        )
        if logs is None:
            raise InternalError("Failed to fetch pod logs from K8S service")

        return {
            "resource_name": resource_name,
            "pod_name": pod_name,
            "namespace": k8s_client.get_project_namespace(project_id),
            "logs": logs,
            "container": container,
            "previous": previous,
        }
    except (NotFoundError, ValidationError, InternalError):
        raise
    except Exception as e:
        logger.error(f"Failed to get resource logs: {e}")
        raise InternalError(f"Failed to get resource logs: {str(e)}")


@router.post(
    "/nodes/{node_id}/sync",
    response_model=NodeSyncResponse,
    summary="Sync node status",
    description="Sync a single node status from K8S and persist it.",
)
async def sync_node_status(
    node_id: str,
    request: NodeSyncRequest = Body(...),
    user: dict = Depends(get_current_user),
):
    try:
        result = await get_status_sync_service().sync_node_status(
            node_id=node_id,
            project_id=request.project_id,
            instance_id=request.instance_id,
            node_type=request.node_type,
            k8s_resource_name=request.k8s_resource_name,
            timeout_seconds=request.timeout_seconds,
        )
        return NodeSyncResponse(
            node_id=result["node_id"],
            status=result["status"],
            message=result.get("message"),
            started_at=result.get("started_at"),
            finished_at=result.get("finished_at"),
        )
    except Exception as e:
        logger.error(f"Failed to sync node status: {e}")
        raise InternalError(f"Failed to sync node status: {str(e)}")


@router.post(
    "/instances/{instance_id}/sync-all",
    response_model=BatchSyncResponse,
    summary="Sync all instance nodes",
    description="Sync all nodes in instance and aggregate workflow status.",
)
async def sync_all_nodes(
    instance_id: str,
    request: BatchSyncRequest = Body(...),
    user: dict = Depends(get_current_user),
):
    try:
        nodes = [
            {
                "node_id": n.node_id,
                "node_type": n.node_type,
                "k8s_resource_name": n.k8s_resource_name,
                "timeout_seconds": n.timeout_seconds,
            }
            for n in request.nodes
        ]
        result = await get_status_sync_service().sync_all_nodes(
            instance_id=instance_id,
            project_id=request.project_id,
            nodes=nodes,
        )
        return BatchSyncResponse(
            instance_id=result["instance_id"],
            workflow_status=result["workflow_status"],
            nodes=[NodeStatusInfo(**n) for n in result["nodes"]],
        )
    except Exception as e:
        logger.error(f"Failed to sync all nodes: {e}")
        raise InternalError(f"Failed to sync all nodes: {str(e)}")


@router.post(
    "/nodes",
    response_model=NodeInitialResponse,
    summary="Record initial node status",
    description="Create node status record during initialization.",
)
async def record_node_initial_status(
    request: NodeInitialRequest = Body(...),
    user: dict = Depends(get_current_user),
):
    try:
        result = await get_status_sync_service().record_node_initial_status(
            node_id=request.node_id,
            instance_id=request.instance_id,
            project_id=request.project_id,
            node_type=request.node_type,
            k8s_resource_name=request.k8s_resource_name,
            k8s_resource_type=request.k8s_resource_type,
            initial_status=request.initial_status,
        )
        return NodeInitialResponse(
            success=True,
            node_id=result["node_id"],
            task_id=result["task_id"],
        )
    except Exception as e:
        logger.error(f"Failed to record initial node status: {e}")
        raise InternalError(f"Failed to record initial node status: {str(e)}")


@router.post(
    "/tasks/collect",
    response_model=NodeTaskCollectResponse,
    summary="Create task and collect node status/logs",
    description="Create one node task record for this trigger, sync K8S status, and persist fetched logs.",
)
async def create_task_and_collect(
    request: NodeTaskCollectRequest = Body(...),
    user: dict = Depends(get_current_user),
):
    try:
        result = await get_status_sync_service().create_task_and_collect(
            node_id=request.node_id,
            instance_id=request.instance_id,
            project_id=request.project_id,
            node_type=request.node_type,
            k8s_resource_name=request.k8s_resource_name,
            k8s_resource_type=request.k8s_resource_type,
            timeout_seconds=request.timeout_seconds,
            tail_lines=request.tail_lines,
            container=request.container,
            previous=request.previous,
            initial_status=request.initial_status,
            metadata=request.metadata,
        )
        return NodeTaskCollectResponse(
            task_id=result["task_id"],
            node=NodeStatusInfo(**result["node"]),
            logs=NodeLogResponse(**result["logs"]),
        )
    except Exception as e:
        logger.error(f"Failed to create task and collect: {e}")
        raise InternalError(f"Failed to create task and collect: {str(e)}")


@router.put(
    "/nodes/{node_id}",
    response_model=NodeUpdateResponse,
    summary="Update node status",
    description="Manually update node status.",
)
async def update_node_status(
    node_id: str,
    request: NodeUpdateRequest = Body(...),
    user: dict = Depends(get_current_user),
):
    try:
        result = await get_status_sync_service().update_node_status(
            node_id=node_id,
            status=request.status,
            message=request.message,
        )
        return NodeUpdateResponse(
            success=True,
            node_id=result["node_id"],
            task_id=result.get("task_id"),
            status=result["status"],
        )
    except ValueError:
        raise NotFoundError("Node", node_id)
    except Exception as e:
        logger.error(f"Failed to update node status: {e}")
        raise InternalError(f"Failed to update node status: {str(e)}")


@router.get(
    "/nodes/{node_id}",
    response_model=NodeStatusResponse,
    summary="Get node status",
    description="Get detailed node status.",
)
async def get_node_status(
    node_id: str,
    project_id: str = Query(..., description="Project ID"),
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    record = get_node_status_record(db, node_id)
    if not record:
        raise NotFoundError("Node", node_id)
    return NodeStatusResponse(node=NodeStatusInfo(**record.to_dict()))


@router.get(
    "/tasks/{task_id}",
    response_model=NodeStatusResponse,
    summary="Get task status",
    description="Get the node status record generated for one trigger task.",
)
async def get_task_status(
    task_id: str,
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    record = get_node_status_record_by_task_id(db, task_id)
    if not record:
        raise NotFoundError("Task", task_id)
    return NodeStatusResponse(node=NodeStatusInfo(**record.to_dict()))


@router.get(
    "/instances/{instance_id}/nodes",
    response_model=NodeListResponse,
    summary="List instance nodes",
    description="Get all node statuses in workflow instance.",
)
async def get_instance_nodes(
    instance_id: str,
    project_id: str = Query(..., description="Project ID"),
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    records = get_node_status_by_instance(db, instance_id, project_id)
    return NodeListResponse(total=len(records), nodes=[NodeStatusInfo(**r.to_dict()) for r in records])


@router.get(
    "/nodes/{node_id}/logs",
    response_model=NodeLogResponse,
    summary="Get node logs",
    description="Get execution logs from node pod.",
)
async def get_node_logs(
    node_id: str,
    project_id: str = Query(..., description="Project ID"),
    tail_lines: int = Query(100, ge=1, le=10000, description="Tail lines"),
    container: Optional[str] = Query(None, description="Container name"),
    user: dict = Depends(get_current_user),
):
    try:
        result = await get_status_sync_service().get_node_logs(
            node_id=node_id,
            project_id=project_id,
            tail_lines=tail_lines,
            container=container,
        )
        return NodeLogResponse(**result)
    except ValueError:
        raise NotFoundError("Node", node_id)
    except Exception as e:
        logger.error(f"Failed to get node logs: {e}")
        raise InternalError(f"Failed to get node logs: {str(e)}")


@router.get(
    "/tasks/{task_id}/logs",
    response_model=NodeLogResponse,
    summary="Get task logs",
    description="Get and persist logs for one task-scoped node record.",
)
async def get_task_logs(
    task_id: str,
    project_id: str = Query(..., description="Project ID"),
    tail_lines: int = Query(500, ge=1, le=10000, description="Tail lines"),
    container: Optional[str] = Query(None, description="Container name"),
    previous: bool = Query(False, description="Read previous container logs"),
    user: dict = Depends(get_current_user),
):
    try:
        result = await get_status_sync_service().get_task_logs(
            task_id=task_id,
            project_id=project_id,
            tail_lines=tail_lines,
            container=container,
            previous=previous,
            persist=True,
        )
        return NodeLogResponse(**result)
    except ValueError:
        raise NotFoundError("Task", task_id)
    except Exception as e:
        logger.error(f"Failed to get task logs: {e}")
        raise InternalError(f"Failed to get task logs: {str(e)}")


@router.get(
    "/nodes/{node_id}/history",
    response_model=NodeHistoryResponse,
    summary="Get node history",
    description="Get node status transition history.",
)
async def get_node_history(
    node_id: str,
    project_id: str = Query(..., description="Project ID"),
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    history = get_node_status_history(db, node_id, project_id)
    return NodeHistoryResponse(
        node_id=node_id,
        project_id=project_id,
        history=[NodeHistoryEntry(**h.to_dict()) for h in history],
    )


@router.get(
    "/instances/{instance_id}/history",
    response_model=WorkflowHistoryResponse,
    summary="Get workflow history",
    description="Get workflow status transition history.",
)
async def get_workflow_history(
    instance_id: str,
    project_id: str = Query(..., description="Project ID"),
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    history = get_workflow_status_history(db, instance_id, project_id)
    return WorkflowHistoryResponse(
        instance_id=instance_id,
        project_id=project_id,
        history=[NodeHistoryEntry(**h.to_dict()) for h in history],
    )


@router.get(
    "/instances/{instance_id}",
    response_model=WorkflowStatusResponse,
    summary="Get workflow status",
    description="Get workflow status details.",
)
async def get_workflow_status(
    instance_id: str,
    project_id: str = Query(..., description="Project ID"),
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    record = get_workflow_status_record(db, instance_id)
    if not record:
        raise NotFoundError("Workflow instance", instance_id)
    return WorkflowStatusResponse(workflow=WorkflowStatusInfo(**record.to_dict()))


@router.get(
    "/instances",
    response_model=WorkflowStatusListResponse,
    summary="List workflow statuses",
    description="List workflow status records in project.",
)
async def list_workflow_status(
    project_id: str = Query(..., description="Project ID"),
    status: Optional[str] = Query(None, description="Status filter"),
    page: int = Query(1, ge=1, description="Page index"),
    page_size: int = Query(20, ge=1, le=100, description="Page size"),
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    records, total = list_workflow_status_records(
        db=db,
        project_id=project_id,
        status=status,
        page=page,
        page_size=page_size,
    )
    return WorkflowStatusListResponse(
        total=total,
        page=page,
        page_size=page_size,
        workflows=[WorkflowStatusInfo(**r.to_dict()) for r in records],
    )


@router.get(
    "/statistics",
    response_model=StatisticsResponse,
    summary="Get status statistics",
    description="Get workflow and node status statistics.",
)
async def get_statistics(
    project_id: str = Query(..., description="Project ID"),
    start_time: Optional[datetime] = Query(None, description="Statistics start time"),
    end_time: Optional[datetime] = Query(None, description="Statistics end time"),
    user: dict = Depends(get_current_user),
):
    try:
        result = await get_workflow_aggregator().get_statistics(
            project_id=project_id,
            start_time=start_time,
            end_time=end_time,
        )
        return StatisticsResponse(**result)
    except Exception as e:
        logger.error(f"Failed to get statistics: {e}")
        raise InternalError(f"Failed to get statistics: {str(e)}")


@router.post(
    "/nodes/{node_id}/logs/init",
    summary="Save init logs",
    description="Save node initialization logs.",
)
async def save_init_logs(
    node_id: str,
    logs: str = Body(..., embed=True),
    user: dict = Depends(get_current_user),
):
    try:
        await get_status_sync_service().save_init_logs(node_id=node_id, logs=logs)
        return {"success": True, "node_id": node_id}
    except ValueError:
        raise NotFoundError("Node", node_id)
    except Exception as e:
        logger.error(f"Failed to save init logs: {e}")
        raise InternalError(f"Failed to save init logs: {str(e)}")


@router.post(
    "/nodes/{node_id}/logs/execution",
    summary="Save execution logs",
    description="Save node execution logs.",
)
async def save_execution_logs(
    node_id: str,
    logs: str = Body(..., embed=True),
    user: dict = Depends(get_current_user),
):
    try:
        await get_status_sync_service().save_execution_logs(node_id=node_id, logs=logs)
        return {"success": True, "node_id": node_id}
    except ValueError:
        raise NotFoundError("Node", node_id)
    except Exception as e:
        logger.error(f"Failed to save execution logs: {e}")
        raise InternalError(f"Failed to save execution logs: {str(e)}")


@router.get(
    "/tasks/{task_id}/logs/stored",
    summary="Get stored task logs",
    description="Get stored logs for one task-scoped node record.",
)
async def get_task_stored_logs(
    task_id: str,
    user: dict = Depends(get_current_user),
):
    try:
        return await get_status_sync_service().get_task_stored_logs(task_id=task_id)
    except ValueError:
        raise NotFoundError("Task", task_id)
    except Exception as e:
        logger.error(f"Failed to get task stored logs: {e}")
        raise InternalError(f"Failed to get task stored logs: {str(e)}")


@router.get(
    "/nodes/{node_id}/logs/stored",
    summary="Get stored logs",
    description="Get stored init and execution logs.",
)
async def get_stored_logs(
    node_id: str,
    user: dict = Depends(get_current_user),
):
    try:
        return await get_status_sync_service().get_stored_logs(node_id=node_id)
    except ValueError:
        raise NotFoundError("Node", node_id)
    except Exception as e:
        logger.error(f"Failed to get stored logs: {e}")
        raise InternalError(f"Failed to get stored logs: {str(e)}")
