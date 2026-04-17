"""Action callback endpoints."""

import json
from datetime import datetime, timedelta
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.dependencies import ensure_project_access, get_current_subject
from app.config import get_config
from app.models.database import ActionExecution, Case, CaseEvent, Result, get_db
from app.schemas import ActionCallbackRequest, ActionControlRequest
from app.services.lifecycle_engine import (
    MAIN_STAGE_TRIAGE,
    MAIN_STAGE_VALIDATION,
    TRIAGE_STATUS_AI_ASSESSING,
    VALIDATION_STATUS_QUEUED,
    get_lifecycle_state,
    set_lifecycle_state,
    apply_action_result,
)

router = APIRouter(prefix="/api/vuln/actions", tags=["actions"])

ACTIVE_EXECUTION_STATUSES = {"queued", "running"}
TERMINAL_EXECUTION_STATUSES = {"succeeded", "failed", "partial", "cancelled"}
CALLBACK_EXECUTION_STATUSES = {"succeeded", "failed", "partial"}


def _is_action_timed_out(action: ActionExecution, *, now: datetime | None = None) -> bool:
    reference_time = now or datetime.utcnow()
    return (
        action.execution_status in ACTIVE_EXECUTION_STATUSES
        and action.timeout_at is not None
        and action.timeout_at < reference_time
    )


def _is_action_timeout_reconciled(action: ActionExecution) -> bool:
    return action.dispatch_status == "timed_out"


def _serialize_queue_item(action: ActionExecution, case: Case, *, now: datetime | None = None) -> dict:
    reference_time = now or datetime.utcnow()
    is_timed_out = _is_action_timed_out(action, now=reference_time) or _is_action_timeout_reconciled(action)
    queue_wait_seconds = None
    if action.started_at:
        queue_wait_seconds = max(0, int((action.started_at - action.created_at).total_seconds()))
    run_duration_anchor = action.completed_at or reference_time
    run_duration_seconds = None
    if action.started_at:
        run_duration_seconds = max(0, int((run_duration_anchor - action.started_at).total_seconds()))
    return {
        "id": action.id,
        "case_id": case.id,
        "case_title": case.title,
        "project_id": case.project_id,
        "stage": action.stage,
        "action_type": action.action_type,
        "target_service_id": action.target_service_id,
        "dispatch_status": action.dispatch_status,
        "execution_status": action.execution_status,
        "result_summary": action.result_summary,
        "retry_count": action.retry_count,
        "max_retry_count": action.max_retry_count,
        "timeout_at": action.timeout_at,
        "created_at": action.created_at,
        "started_at": action.started_at,
        "completed_at": action.completed_at,
        "is_timed_out": is_timed_out,
        "queue_wait_seconds": queue_wait_seconds,
        "run_duration_seconds": run_duration_seconds,
        "can_retry": is_timed_out or action.execution_status in TERMINAL_EXECUTION_STATUSES,
        "can_cancel": action.execution_status in ACTIVE_EXECUTION_STATUSES and not is_timed_out,
    }


def reconcile_timed_out_actions(
    db: Session,
    *,
    project_id: str | None = None,
) -> list[dict]:
    reference_time = datetime.utcnow()
    query = db.query(ActionExecution, Case).join(Case, Case.id == ActionExecution.case_id).filter(
        ActionExecution.execution_status.in_(list(ACTIVE_EXECUTION_STATUSES)),
        ActionExecution.timeout_at.is_not(None),
        ActionExecution.timeout_at < reference_time,
    )
    if project_id:
        query = query.filter(Case.project_id == project_id)

    reconciled: list[dict] = []
    for action, case in query.all():
        summary = action.result_summary or f"action timed out at {action.timeout_at.isoformat()}"
        action.dispatch_status = "timed_out"
        action.execution_status = "failed"
        action.result_summary = summary
        if action.started_at is None:
            action.started_at = action.created_at
        action.completed_at = reference_time
        db.add(Result(
            id=uuid4().hex,
            case_id=case.id,
            action_execution_id=action.id,
            source_service_id=action.target_service_id,
            result_type="timeout",
            status="failed",
            summary=summary,
            confidence=0,
            result_meta_json=json.dumps({"reason": "timeout"}, ensure_ascii=False),
            raw_payload_json=json.dumps({}, ensure_ascii=False),
            artifact_refs_json=json.dumps([], ensure_ascii=False),
            suggested_stage=None,
            suggested_decision=None,
        ))
        apply_action_result(
            db,
            case,
            ActionCallbackRequest(
                source_service_id=action.target_service_id,
                result_type="timeout",
                status="failed",
                summary=summary,
                confidence=0,
                result_meta={"reason": "timeout"},
                raw_payload={},
                artifact_refs=[],
            ),
        )
        db.add(CaseEvent(
            id=uuid4().hex,
            case_id=case.id,
            event_type="action_timed_out",
            summary=summary,
            payload_json=json.dumps(
                {
                    "action_id": action.id,
                    "target_service_id": action.target_service_id,
                    "timeout_at": action.timeout_at.isoformat() if action.timeout_at else None,
                },
                ensure_ascii=False,
            ),
        ))
        reconciled.append({
            "action_id": action.id,
            "case_id": case.id,
            "target_service_id": action.target_service_id,
            "timeout_at": action.timeout_at,
        })
    return reconciled


@router.get("/ops/queue")
async def list_action_queue(
    project_id: str | None = Query(None),
    execution_status: str | None = Query(None),
    stage: str | None = Query(None),
    service_id: str | None = Query(None),
    case_id: str | None = Query(None),
    dispatch_status: str | None = Query(None),
    timeout_only: bool = Query(False),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    user_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    _, token = user_and_token
    query = db.query(ActionExecution, Case).join(Case, Case.id == ActionExecution.case_id)
    if project_id:
        await ensure_project_access(project_id, token)
        query = query.filter(Case.project_id == project_id)
    if case_id:
        query = query.filter(Case.id == case_id)
    if stage:
        query = query.filter(ActionExecution.stage == stage)
    if service_id:
        query = query.filter(ActionExecution.target_service_id == service_id)
    if dispatch_status:
        query = query.filter(ActionExecution.dispatch_status == dispatch_status)
    if execution_status and execution_status != "timed_out":
        query = query.filter(ActionExecution.execution_status == execution_status)
    rows = query.order_by(ActionExecution.created_at.desc()).all()
    reference_time = datetime.utcnow()
    if execution_status == "timed_out":
        rows = [(action, case) for action, case in rows if _is_action_timed_out(action, now=reference_time)]
    elif timeout_only:
        rows = [(action, case) for action, case in rows if _is_action_timed_out(action, now=reference_time)]
    total = len(rows)
    start = (page - 1) * page_size
    paged_rows = rows[start:start + page_size]
    return {
        "items": [_serialize_queue_item(action, case, now=reference_time) for action, case in paged_rows],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.post("/ops/queue/reconcile-timeouts")
async def reconcile_action_queue_timeouts(
    project_id: str | None = Query(None),
    user_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    _, token = user_and_token
    if project_id:
        await ensure_project_access(project_id, token)
    items = reconcile_timed_out_actions(db, project_id=project_id)
    db.commit()
    return {
        "status": "ok",
        "count": len(items),
        "items": items,
    }


@router.post("/{action_id}/callback")
async def action_callback(
    action_id: str,
    request: ActionCallbackRequest,
    user_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    action = db.query(ActionExecution).filter(ActionExecution.id == action_id).first()
    if action is None:
        raise HTTPException(status_code=404, detail="action not found")

    case = db.query(Case).filter(Case.id == action.case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    _, token = user_and_token
    await ensure_project_access(case.project_id, token)

    if action.execution_status in TERMINAL_EXECUTION_STATUSES:
        return {"status": "ok", "action_id": action_id, "duplicate": True}

    action.dispatch_status = "acknowledged"
    action.execution_status = request.status if request.status in CALLBACK_EXECUTION_STATUSES else "succeeded"
    action.result_summary = request.summary
    if action.started_at is None:
        action.started_at = action.created_at
    action.completed_at = datetime.utcnow()

    db.add(Result(
        id=uuid4().hex,
        case_id=case.id,
        action_execution_id=action.id,
        source_service_id=request.source_service_id,
        result_type=request.result_type,
        status=request.status,
        summary=request.summary,
        confidence=request.confidence,
        result_meta_json=json.dumps(request.result_meta, ensure_ascii=False),
        raw_payload_json=json.dumps(request.raw_payload, ensure_ascii=False),
        artifact_refs_json=json.dumps(request.artifact_refs, ensure_ascii=False),
        suggested_stage=request.suggested_stage,
        suggested_decision=request.suggested_decision,
    ))

    apply_action_result(db, case, request)
    db.commit()
    return {"status": "ok", "action_id": action_id}


@router.post("/{action_id}/control")
async def control_action(
    action_id: str,
    request: ActionControlRequest,
    user_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    user, token = user_and_token
    action = db.query(ActionExecution).filter(ActionExecution.id == action_id).first()
    if action is None:
        raise HTTPException(status_code=404, detail="action not found")

    case = db.query(Case).filter(Case.id == action.case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    await ensure_project_access(case.project_id, token)

    operation = request.operation.lower()
    if operation == "retry":
        if action.retry_count >= (action.max_retry_count or 0):
            raise HTTPException(status_code=400, detail="action retry limit reached")
        is_timed_out = _is_action_timed_out(action)
        if not is_timed_out and action.execution_status not in TERMINAL_EXECUTION_STATUSES:
            raise HTTPException(status_code=400, detail="only failed, partial, cancelled, succeeded or timed out actions can be retried")
        action.dispatch_status = "dispatched"
        action.execution_status = "queued"
        action.result_summary = None
        action.completed_at = None
        action.started_at = datetime.utcnow()
        action.retry_count = (action.retry_count or 0) + 1
        action.timeout_at = datetime.utcnow() + timedelta(seconds=get_config().engine.action_timeout_default)
        lifecycle = get_lifecycle_state(case)
        if case.current_stage == MAIN_STAGE_TRIAGE:
            lifecycle["stage_status"] = TRIAGE_STATUS_AI_ASSESSING
        elif case.current_stage == MAIN_STAGE_VALIDATION:
            lifecycle["stage_status"] = VALIDATION_STATUS_QUEUED
        set_lifecycle_state(case, lifecycle)
        case.current_status = lifecycle.get("stage_status", case.current_status)
    elif operation == "cancel":
        if _is_action_timed_out(action):
            raise HTTPException(status_code=400, detail="timed out action should be retried instead of cancelled")
        if action.execution_status not in ACTIVE_EXECUTION_STATUSES:
            raise HTTPException(status_code=400, detail="only queued or running actions can be cancelled")
        action.execution_status = "cancelled"
        action.dispatch_status = "acknowledged"
        action.completed_at = datetime.utcnow()
        action.result_summary = action.result_summary or "action cancelled by operator"
    else:
        raise HTTPException(status_code=400, detail="unsupported operation")

    db.add(CaseEvent(
        id=uuid4().hex,
        case_id=case.id,
        event_type="action_controlled",
        summary=f"{action.action_type} {operation}",
        payload_json=json.dumps(
            {
                "action_id": action.id,
                "operation": operation,
                "operator": user.get("username"),
            },
            ensure_ascii=False,
        ),
    ))
    db.commit()
    return {
        "status": "ok",
        "action": {
            "id": action.id,
            "execution_status": action.execution_status,
            "dispatch_status": action.dispatch_status,
            "retry_count": action.retry_count,
        },
    }


@router.post("/mock-dispatch/{case_id}")
async def mock_dispatch(case_id: str, _: tuple[dict, str] = Depends(get_current_subject), db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")

    cfg = get_config()
    action = ActionExecution(
        id=uuid4().hex,
        case_id=case.id,
        workflow_run_id=case.active_workflow_run_id,
        stage=case.current_stage,
        action_type="manual_triggered_mock",
        dispatch_status="dispatched",
        execution_status="running",
        max_retry_count=cfg.engine.retry_default,
        timeout_at=datetime.utcnow() + timedelta(seconds=cfg.engine.action_timeout_default),
        started_at=datetime.utcnow(),
    )
    db.add(action)
    db.commit()
    return {"status": "ok", "action_id": action.id}
