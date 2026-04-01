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


@router.get("/ops/queue")
async def list_action_queue(
    project_id: str | None = Query(None),
    execution_status: str | None = Query(None),
    user_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    _, token = user_and_token
    query = db.query(ActionExecution, Case).join(Case, Case.id == ActionExecution.case_id)
    if project_id:
        await ensure_project_access(project_id, token)
        query = query.filter(Case.project_id == project_id)
    if execution_status:
        query = query.filter(ActionExecution.execution_status == execution_status)

    rows = query.order_by(ActionExecution.created_at.desc()).all()
    return {
        "items": [
            {
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
                "timeout_at": action.timeout_at,
                "created_at": action.created_at,
                "completed_at": action.completed_at,
            }
            for action, case in rows
        ],
        "total": len(rows),
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

    action.dispatch_status = "acknowledged"
    action.execution_status = request.status if request.status in {"succeeded", "failed", "partial"} else "succeeded"
    action.result_summary = request.summary
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
