"""Case endpoints."""

import json
from uuid import uuid4

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.dependencies import ensure_project_access, get_current_subject
from app.models.database import ActionExecution, Case, CaseEvent, ManualTask, Result, ServiceRegistry, StageHistory, WorkflowRun, get_db
from app.schemas import (
    CaseCreateRequest,
    DecisionRequest,
    ManualTaskCreateRequest,
    ManualTaskStatusUpdateRequest,
    RoutedActionDispatchRequest,
    StageTransitionRequest,
)
from app.services.lifecycle_engine import (
    advance_case_stage,
    auto_orchestrate_case,
    create_case_with_runtime,
    create_manual_task,
    dispatch_routed_actions,
    recommend_actions,
    record_case_decision,
)

router = APIRouter(prefix="/api/vuln/cases", tags=["cases"])


def _case_payload(item: Case) -> dict:
    return {
        "id": item.id,
        "project_id": item.project_id,
        "title": item.title,
        "summary": item.summary,
        "severity": item.severity,
        "confidence": item.confidence,
        "current_stage": item.current_stage,
        "current_status": item.current_status,
        "decision_status": item.decision_status,
        "created_by_type": item.created_by_type,
        "created_by": item.created_by,
        "source_meta": json.loads(item.source_meta_json or "{}"),
        "target_meta": json.loads(item.target_meta_json or "{}"),
        "display_meta": json.loads(item.display_meta_json or "{}"),
        "created_at": item.created_at,
        "updated_at": item.updated_at,
    }


def _manual_task_payload(item: ManualTask) -> dict:
    return {
        "id": item.id,
        "case_id": item.case_id,
        "task_type": item.task_type,
        "status": item.status,
        "assignee": item.assignee,
        "title": item.title,
        "summary": item.summary,
        "context": json.loads(item.context_json or "{}"),
        "due_at": item.due_at,
        "completed_at": item.completed_at,
        "created_at": item.created_at,
    }


@router.post("")
async def create_case(
    request: CaseCreateRequest,
    user_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    _, token = user_and_token
    await ensure_project_access(request.project_id, token)
    item = create_case_with_runtime(db, request)
    return _case_payload(item)


@router.get("")
async def list_cases(
    project_id: str | None = Query(None),
    current_stage: str | None = Query(None),
    user_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    _, token = user_and_token
    if project_id:
        await ensure_project_access(project_id, token)
    query = db.query(Case)
    if project_id:
        query = query.filter(Case.project_id == project_id)
    if current_stage:
        query = query.filter(Case.current_stage == current_stage)
    items = query.order_by(Case.updated_at.desc()).all()
    return {"items": [_case_payload(item) for item in items], "total": len(items)}


@router.get("/{case_id}")
async def get_case(case_id: str, user_and_token: tuple[dict, str] = Depends(get_current_subject), db: Session = Depends(get_db)):
    item = db.query(Case).filter(Case.id == case_id).first()
    if item is None:
        raise HTTPException(status_code=404, detail="case not found")
    _, token = user_and_token
    await ensure_project_access(item.project_id, token)

    workflow_run = None
    if item.active_workflow_run_id:
        workflow_run = db.query(WorkflowRun).filter(WorkflowRun.id == item.active_workflow_run_id).first()

    actions = db.query(ActionExecution).filter(ActionExecution.case_id == case_id).order_by(ActionExecution.created_at.desc()).all()
    results = db.query(Result).filter(Result.case_id == case_id).order_by(Result.created_at.desc()).all()
    manual_tasks = db.query(ManualTask).filter(ManualTask.case_id == case_id).order_by(ManualTask.created_at.desc()).all()

    return {
        **_case_payload(item),
        "workflow_run": {
            "id": workflow_run.id,
            "current_stage": workflow_run.current_stage,
            "run_status": workflow_run.run_status,
            "started_at": workflow_run.started_at,
            "completed_at": workflow_run.completed_at,
        } if workflow_run else None,
        "actions": [
            {
                "id": action.id,
                "stage": action.stage,
                "action_type": action.action_type,
                "target_service_id": action.target_service_id,
                "dispatch_status": action.dispatch_status,
                "execution_status": action.execution_status,
                "result_summary": action.result_summary,
                "created_at": action.created_at,
                "completed_at": action.completed_at,
            }
            for action in actions
        ],
        "results": [
            {
                "id": result.id,
                "action_execution_id": result.action_execution_id,
                "source_service_id": result.source_service_id,
                "result_type": result.result_type,
                "status": result.status,
                "summary": result.summary,
                "confidence": result.confidence,
                "result_meta": json.loads(result.result_meta_json or "{}"),
                "raw_payload": json.loads(result.raw_payload_json or "{}"),
                "artifact_refs": json.loads(result.artifact_refs_json or "[]"),
                "suggested_stage": result.suggested_stage,
                "suggested_decision": result.suggested_decision,
                "created_at": result.created_at,
            }
            for result in results
        ],
        "manual_tasks": [_manual_task_payload(item) for item in manual_tasks],
    }


@router.get("/{case_id}/timeline")
async def get_case_timeline(case_id: str, user_and_token: tuple[dict, str] = Depends(get_current_subject), db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    _, token = user_and_token
    await ensure_project_access(case.project_id, token)

    items: list[dict] = []
    for event in db.query(CaseEvent).filter(CaseEvent.case_id == case_id).all():
        items.append({
            "id": event.id,
            "item_type": "event",
            "created_at": event.created_at,
            "payload": {
                "event_type": event.event_type,
                "summary": event.summary,
                "payload": json.loads(event.payload_json or "{}"),
            },
        })
    for history in db.query(StageHistory).filter(StageHistory.case_id == case_id).all():
        items.append({
            "id": history.id,
            "item_type": "stage_history",
            "created_at": history.created_at,
            "payload": {
                "from_stage": history.from_stage,
                "to_stage": history.to_stage,
                "reason": history.reason,
                "source_type": history.source_type,
                "source_id": history.source_id,
            },
        })
    for result in db.query(Result).filter(Result.case_id == case_id).all():
        items.append({
            "id": result.id,
            "item_type": "result",
            "created_at": result.created_at,
            "payload": {
                "result_type": result.result_type,
                "status": result.status,
                "summary": result.summary,
                "confidence": result.confidence,
                "suggested_stage": result.suggested_stage,
                "suggested_decision": result.suggested_decision,
            },
        })

    items.sort(key=lambda x: x["created_at"])
    return {"items": items, "total": len(items)}


@router.get("/ops/dashboard/overview")
async def get_dashboard_overview(
    project_id: str | None = Query(None),
    user_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    _, token = user_and_token
    if project_id:
        await ensure_project_access(project_id, token)

    case_query = db.query(Case)
    task_query = db.query(ManualTask).join(Case, Case.id == ManualTask.case_id)
    action_query = db.query(ActionExecution).join(Case, Case.id == ActionExecution.case_id)
    result_query = db.query(Result).join(Case, Case.id == Result.case_id)
    service_query = db.query(ServiceRegistry)

    if project_id:
        case_query = case_query.filter(Case.project_id == project_id)
        task_query = task_query.filter(Case.project_id == project_id)
        action_query = action_query.filter(Case.project_id == project_id)
        result_query = result_query.filter(Case.project_id == project_id)

    cases = case_query.all()
    tasks = task_query.all()
    actions = action_query.all()
    results = result_query.all()
    services = service_query.all()

    stage_counts: dict[str, int] = {}
    decision_counts: dict[str, int] = {}
    action_status_counts: dict[str, int] = {}
    result_type_counts: dict[str, int] = {}
    for item in cases:
        stage_counts[item.current_stage] = stage_counts.get(item.current_stage, 0) + 1
        decision_counts[item.decision_status] = decision_counts.get(item.decision_status, 0) + 1
    for item in actions:
        action_status_counts[item.execution_status] = action_status_counts.get(item.execution_status, 0) + 1
    for item in results:
        result_type_counts[item.result_type] = result_type_counts.get(item.result_type, 0) + 1

    recent_cases = sorted(cases, key=lambda item: item.updated_at or datetime.utcnow(), reverse=True)[:5]
    return {
        "project_id": project_id,
        "metrics": {
            "total_cases": len(cases),
            "running_cases": len([item for item in cases if item.current_status == "running"]),
            "waiting_external": len([item for item in cases if item.current_status == "waiting_external"]),
            "manual_tasks_open": len([item for item in tasks if item.status == "open"]),
            "registered_services": len(services),
            "active_services": len([item for item in services if item.status == "active"]),
            "queued_actions": len([item for item in actions if item.execution_status in {"queued", "running"}]),
        },
        "stage_counts": stage_counts,
        "decision_counts": decision_counts,
        "action_status_counts": action_status_counts,
        "result_type_counts": result_type_counts,
        "recent_cases": [_case_payload(item) for item in recent_cases],
    }


@router.get("/ops/manual-tasks")
async def list_manual_tasks(
    project_id: str | None = Query(None),
    status: str | None = Query(None),
    user_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    _, token = user_and_token
    if project_id:
        await ensure_project_access(project_id, token)

    query = db.query(ManualTask).join(Case, Case.id == ManualTask.case_id)
    if project_id:
        query = query.filter(Case.project_id == project_id)
    if status:
        query = query.filter(ManualTask.status == status)
    items = query.order_by(ManualTask.created_at.desc()).all()
    return {"items": [_manual_task_payload(item) for item in items], "total": len(items)}


@router.post("/{case_id}/manual-tasks")
async def create_case_manual_task(
    case_id: str,
    request: ManualTaskCreateRequest,
    user_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    user, token = user_and_token
    case = db.query(Case).filter(Case.id == case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    await ensure_project_access(case.project_id, token)
    item = create_manual_task(db, case, request)
    case.current_status = "waiting_manual"
    db.commit()
    return {
        "status": "ok",
        "task": _manual_task_payload(item),
        "operator": user.get("username"),
    }


@router.post("/{case_id}/manual-tasks/{task_id}/status")
async def update_case_manual_task_status(
    case_id: str,
    task_id: str,
    request: ManualTaskStatusUpdateRequest,
    user_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    user, token = user_and_token
    case = db.query(Case).filter(Case.id == case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    await ensure_project_access(case.project_id, token)
    task = db.query(ManualTask).filter(ManualTask.id == task_id, ManualTask.case_id == case_id).first()
    if task is None:
        raise HTTPException(status_code=404, detail="manual task not found")
    task.status = request.status
    task.completed_at = datetime.utcnow() if request.status in {"done", "completed", "closed"} else None
    db.add(CaseEvent(
        id=uuid4().hex,
        case_id=case.id,
        event_type="manual_task_status_updated",
        summary=f"{task.title}: {request.status}",
        payload_json=json.dumps(
            {
                "task_id": task.id,
                "status": request.status,
                "operator": user.get("username"),
            },
            ensure_ascii=False,
        ),
    ))
    if request.status in {"done", "completed", "closed"}:
        case.current_status = "running"
    db.commit()
    return {"status": "ok", "task": _manual_task_payload(task)}


@router.post("/{case_id}/stage-transition")
async def transition_case_stage(
    case_id: str,
    request: StageTransitionRequest,
    user_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    user, token = user_and_token
    case = db.query(Case).filter(Case.id == case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    await ensure_project_access(case.project_id, token)
    advance_case_stage(db, case, request.to_stage, request.reason or "manual_transition", "human")
    case.current_status = "running"
    db.add(CaseEvent(
        id=uuid4().hex,
        case_id=case.id,
        event_type="manual_stage_transition",
        summary=request.reason or request.to_stage,
        payload_json=json.dumps(
            {
                "to_stage": request.to_stage,
                "reason": request.reason,
                "operator": user.get("username"),
            },
            ensure_ascii=False,
        ),
    ))
    db.commit()
    return {"status": "ok", "case": _case_payload(case)}


@router.post("/{case_id}/decisions")
async def create_case_decision(
    case_id: str,
    request: DecisionRequest,
    user_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    user, token = user_and_token
    case = db.query(Case).filter(Case.id == case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    await ensure_project_access(case.project_id, token)
    record_case_decision(db, case, request.decision_status, request.summary, user.get("username"))
    db.commit()
    return {"status": "ok", "case": _case_payload(case)}


@router.post("/{case_id}/actions/dispatch")
async def dispatch_case_actions(
    case_id: str,
    request: RoutedActionDispatchRequest,
    user_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    _, token = user_and_token
    case = db.query(Case).filter(Case.id == case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    await ensure_project_access(case.project_id, token)
    actions = dispatch_routed_actions(db, case, request)
    db.commit()
    return {
        "status": "ok",
        "count": len(actions),
        "items": [
            {
                "id": item.id,
                "action_type": item.action_type,
                "stage": item.stage,
                "target_service_id": item.target_service_id,
                "dispatch_status": item.dispatch_status,
                "execution_status": item.execution_status,
            }
            for item in actions
        ],
    }


@router.get("/{case_id}/recommended-actions")
async def get_case_recommended_actions(
    case_id: str,
    user_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    _, token = user_and_token
    case = db.query(Case).filter(Case.id == case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    await ensure_project_access(case.project_id, token)
    items = recommend_actions(db, case)
    return {"items": items, "total": len(items)}


@router.post("/{case_id}/orchestrate/auto")
async def auto_orchestrate_case_actions(
    case_id: str,
    user_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    _, token = user_and_token
    case = db.query(Case).filter(Case.id == case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    await ensure_project_access(case.project_id, token)
    actions = auto_orchestrate_case(db, case)
    db.commit()
    return {
        "status": "ok",
        "count": len(actions),
        "items": [
            {
                "id": item.id,
                "action_type": item.action_type,
                "stage": item.stage,
                "target_service_id": item.target_service_id,
                "execution_status": item.execution_status,
            }
            for item in actions
        ],
    }
