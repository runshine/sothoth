from __future__ import annotations

from pathlib import Path
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_subject, get_db, get_machine_subject
from app.schemas import (
    HealthResponse,
    SchedulerWorkerResponse,
    SuccessResponse,
    TriggerTaskCreate,
    TriggerTaskResponse,
    WorkflowDefinitionCreate,
    WorkflowDefinitionResponse,
    WorkflowDefinitionUpdate,
    WorkflowDefinitionVersionResponse,
    WorkflowExecutionEventResponse,
    WorkflowExecutionResponse,
)
from app.services.execution_service import get_execution_service
from app.services.scheduler import get_scheduler_service
from app.services.workflow_service import get_workflow_service

router = APIRouter(prefix="/api/ai-agent-framework", tags=["AI Agent Framework"])


@router.get("/health", response_model=HealthResponse)
async def health():
    return get_scheduler_service().health_payload()


@router.get("/ready", response_model=SuccessResponse)
async def ready():
    service = get_workflow_service()
    service.ready_check()
    return SuccessResponse(message="ready")


@router.post("/workflow-definitions", response_model=WorkflowDefinitionResponse, status_code=status.HTTP_201_CREATED)
async def create_workflow_definition(
    payload: WorkflowDefinitionCreate,
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, token = subject
    return get_workflow_service().create_definition(db, payload, principal)


@router.get("/workflow-definitions", response_model=List[WorkflowDefinitionResponse])
async def list_workflow_definitions(
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, token = subject
    return get_workflow_service().list_definitions(db, principal)


@router.get("/workflow-definitions/{definition_id}", response_model=WorkflowDefinitionResponse)
async def get_workflow_definition(definition_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, token = subject
    return get_workflow_service().get_definition(db, definition_id, principal)


@router.put("/workflow-definitions/{definition_id}", response_model=WorkflowDefinitionResponse)
async def update_workflow_definition(
    definition_id: str,
    payload: WorkflowDefinitionUpdate,
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, token = subject
    return get_workflow_service().update_definition(db, definition_id, payload, principal)


@router.delete("/workflow-definitions/{definition_id}", response_model=SuccessResponse)
async def delete_workflow_definition(definition_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, token = subject
    get_workflow_service().delete_definition(db, definition_id, principal)
    return SuccessResponse(message=f"workflow definition {definition_id} deleted")


@router.get("/workflow-definitions/{definition_id}/versions", response_model=List[WorkflowDefinitionVersionResponse])
async def list_definition_versions(definition_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, token = subject
    return get_workflow_service().list_definition_versions(db, definition_id, principal)


@router.get("/workflow-definitions/{definition_id}/versions/{version_no}", response_model=WorkflowDefinitionVersionResponse)
async def get_definition_version(definition_id: str, version_no: int, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, token = subject
    return get_workflow_service().get_definition_version(db, definition_id, version_no, principal)


@router.post("/workflow-definitions/{definition_id}/activate", response_model=WorkflowDefinitionResponse)
async def activate_definition(definition_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, token = subject
    return get_workflow_service().set_definition_active(db, definition_id, principal, True)


@router.post("/workflow-definitions/{definition_id}/deactivate", response_model=WorkflowDefinitionResponse)
async def deactivate_definition(definition_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, token = subject
    return get_workflow_service().set_definition_active(db, definition_id, principal, False)


@router.post("/workflow-definitions/{definition_id}/trigger-tasks", response_model=TriggerTaskResponse, status_code=status.HTTP_201_CREATED)
async def create_trigger_task(
    definition_id: str,
    payload: TriggerTaskCreate,
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, token = subject
    return get_execution_service().create_trigger_task(
        db,
        definition_id,
        payload,
        principal,
        trigger_type="manual",
        authorization_token=token,
    )


@router.post("/trigger/{definition_id}", response_model=TriggerTaskResponse, status_code=status.HTTP_201_CREATED)
async def http_trigger_definition(
    definition_id: str,
    payload: TriggerTaskCreate,
    subject=Depends(get_machine_subject),
    db: Session = Depends(get_db),
):
    principal, token = subject
    return get_execution_service().create_trigger_task(
        db,
        definition_id,
        payload,
        principal,
        trigger_type="http",
        authorization_token=token,
    )


@router.get("/trigger-tasks", response_model=List[TriggerTaskResponse])
async def list_trigger_tasks(subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, token = subject
    return get_execution_service().list_trigger_tasks(db, principal)


@router.get("/trigger-tasks/{trigger_task_id}", response_model=TriggerTaskResponse)
async def get_trigger_task(trigger_task_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, token = subject
    return get_execution_service().get_trigger_task(db, trigger_task_id, principal)


@router.post("/trigger-tasks/{trigger_task_id}/cancel", response_model=SuccessResponse)
async def cancel_trigger_task(trigger_task_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, token = subject
    get_execution_service().cancel_trigger_task(db, trigger_task_id, principal)
    return SuccessResponse(message=f"trigger task {trigger_task_id} cancel requested")


@router.post("/trigger-tasks/{trigger_task_id}/retry", response_model=TriggerTaskResponse, status_code=status.HTTP_201_CREATED)
async def retry_trigger_task(trigger_task_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, token = subject
    return get_execution_service().retry_trigger_task(db, trigger_task_id, principal, authorization_token=token)


@router.get("/executions", response_model=List[WorkflowExecutionResponse])
async def list_executions(subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, token = subject
    return get_execution_service().list_executions(db, principal)


@router.get("/executions/{execution_id}", response_model=WorkflowExecutionResponse)
async def get_execution(execution_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, token = subject
    return get_execution_service().get_execution(db, execution_id, principal)


@router.get("/executions/{execution_id}/events", response_model=List[WorkflowExecutionEventResponse])
async def get_execution_events(execution_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, token = subject
    return get_execution_service().list_execution_events(db, execution_id, principal)


@router.get("/executions/{execution_id}/artifacts", response_model=dict)
async def get_execution_artifacts(execution_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, token = subject
    return get_execution_service().get_execution_artifacts(db, execution_id, principal)


@router.post("/executions/{execution_id}/cancel", response_model=SuccessResponse)
async def cancel_execution(execution_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, token = subject
    get_execution_service().cancel_execution(db, execution_id, principal)
    return SuccessResponse(message=f"execution {execution_id} cancel requested")


@router.get("/scheduler/workers", response_model=List[SchedulerWorkerResponse])
async def list_workers(subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, token = subject
    return get_scheduler_service().list_workers(db)


@router.get("/scheduler/workers/{pod_id}", response_model=SchedulerWorkerResponse)
async def get_worker(pod_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, token = subject
    return get_scheduler_service().get_worker(db, pod_id)


@router.post("/scheduler/workers/{pod_id}/drain", response_model=SuccessResponse)
async def drain_worker(pod_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, token = subject
    get_scheduler_service().set_worker_status(db, pod_id, "draining")
    return SuccessResponse(message=f"worker {pod_id} set to draining")


@router.post("/scheduler/workers/{pod_id}/activate", response_model=SuccessResponse)
async def activate_worker(pod_id: str, subject=Depends(get_current_subject), db: Session = Depends(get_db)):
    principal, token = subject
    get_scheduler_service().set_worker_status(db, pod_id, "active")
    return SuccessResponse(message=f"worker {pod_id} activated")
