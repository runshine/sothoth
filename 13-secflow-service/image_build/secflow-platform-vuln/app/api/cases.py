"""Case endpoints."""

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.dependencies import ensure_project_access, get_current_subject
from app.models.database import ActionExecution, Case, CaseEvent, Result, StageHistory, WorkflowRun, get_db
from app.schemas import CaseCreateRequest
from app.services.lifecycle_engine import create_case_with_runtime

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
                "result_type": result.result_type,
                "status": result.status,
                "summary": result.summary,
                "confidence": result.confidence,
                "suggested_stage": result.suggested_stage,
                "suggested_decision": result.suggested_decision,
                "created_at": result.created_at,
            }
            for result in results
        ],
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
