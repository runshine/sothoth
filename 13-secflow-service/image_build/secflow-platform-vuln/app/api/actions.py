"""Action callback endpoints."""

import json
from datetime import datetime, timedelta
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_subject
from app.config import get_config
from app.models.database import ActionExecution, Case, Result, get_db
from app.schemas import ActionCallbackRequest
from app.services.lifecycle_engine import apply_action_result

router = APIRouter(prefix="/api/vuln/actions", tags=["actions"])


@router.post("/{action_id}/callback")
async def action_callback(
    action_id: str,
    request: ActionCallbackRequest,
    _: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    action = db.query(ActionExecution).filter(ActionExecution.id == action_id).first()
    if action is None:
        raise HTTPException(status_code=404, detail="action not found")

    case = db.query(Case).filter(Case.id == action.case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")

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
