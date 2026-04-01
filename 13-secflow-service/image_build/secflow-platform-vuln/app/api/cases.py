"""Case endpoints."""

import json
from uuid import uuid4

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.dependencies import ensure_project_access, get_current_subject
from app.models.database import ActionExecution, Case, CaseEvent, ManualTask, Result, ServiceRegistry, StageHistory, WorkflowRun, get_db
from app.schemas import (
    CaseCreateRequest,
    DecisionRequest,
    DraftCaseCreateRequest,
    FinishCaseRequest,
    ManualTaskCreateRequest,
    ManualTaskStatusUpdateRequest,
    RoutedActionDispatchRequest,
    SuspicionSubmissionRequest,
    StageTransitionRequest,
    TriageDecisionRequest,
    TriageGateRequest,
    TriageRoundStartRequest,
    ValidationResultRequest,
)
from app.services.lifecycle_engine import (
    FINISHED_REASONS,
    FINISHED_STATUS_DONE,
    MAIN_STAGE_FINISHED,
    MAIN_STAGE_RECEIVE,
    MAIN_STAGE_TRIAGE,
    MAIN_STAGE_VALIDATION,
    TRIAGE_DECISIONS,
    TRIAGE_GATES,
    TRIAGE_STATUS_AWAITING_MANUAL_GATE,
    TRIAGE_STATUS_COMPLETED,
    TRIAGE_STATUS_WAITING,
    VALIDATION_RESULTS,
    VALIDATION_STATUS_COMPLETED,
    VALIDATION_STATUS_QUEUED,
    advance_case_stage,
    auto_orchestrate_case,
    create_case_with_runtime,
    create_manual_task,
    dispatch_routed_actions,
    get_lifecycle_state,
    recommend_actions,
    record_case_decision,
    set_lifecycle_state,
    start_next_triage_round,
    update_triage_gate,
    update_validation_result,
)

router = APIRouter(prefix="/api/vuln/cases", tags=["cases"])


def _case_payload(item: Case) -> dict:
    source_meta = json.loads(item.source_meta_json or "{}")
    subject = json.loads(item.target_meta_json or "{}")
    display_meta = json.loads(item.display_meta_json or "{}")
    lifecycle = get_lifecycle_state(item)
    metadata = display_meta.get("metadata") or {}
    fileserver_root = display_meta.get("fileserver_root") or {}
    return {
        "id": item.id,
        "project_id": item.project_id,
        "title": item.title,
        "summary": item.summary,
        "severity": item.severity,
        "cvss_score": source_meta.get("cvss_score", 0.0),
        "confidence": item.confidence,
        "report_id": source_meta.get("report_id"),
        "state": source_meta.get("state", "suspected"),
        "category": source_meta.get("category"),
        "rule_id": source_meta.get("rule_id"),
        "rule_name": source_meta.get("rule_name"),
        "fingerprint": source_meta.get("fingerprint"),
        "reported_at": source_meta.get("reported_at"),
        "reporter": source_meta.get("reporter") or {},
        "subject": subject,
        "evidence": display_meta.get("evidence") or {},
        "artifacts": display_meta.get("artifacts") or [],
        "metadata": metadata,
        "files_root_path": fileserver_root.get("root_path"),
        "fileserver_root": fileserver_root,
        "current_stage": item.current_stage,
        "current_status": lifecycle.get("stage_status", item.current_status),
        "decision_status": item.decision_status,
        "triage_decision": lifecycle.get("triage_decision"),
        "triage_gate": lifecycle.get("triage_gate"),
        "triage_round": lifecycle.get("triage_round"),
        "triage_history": lifecycle.get("triage_history") or [],
        "validation_result": lifecycle.get("validation_result"),
        "finished_reason": lifecycle.get("finished_reason"),
        "created_by_type": item.created_by_type,
        "created_by": item.created_by,
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


def _validate_stage_transition(
    case: Case,
    to_stage: str,
    *,
    finished_reason: str | None = None,
    summary: str | None = None,
) -> None:
    lifecycle = get_lifecycle_state(case)
    if to_stage not in {MAIN_STAGE_RECEIVE, MAIN_STAGE_TRIAGE, MAIN_STAGE_VALIDATION, MAIN_STAGE_FINISHED}:
        raise HTTPException(status_code=400, detail=f"unsupported stage: {to_stage}")
    if case.current_stage == MAIN_STAGE_FINISHED:
        raise HTTPException(status_code=400, detail="finished stage is terminal and cannot transition")
    if to_stage == case.current_stage:
        raise HTTPException(status_code=400, detail="target stage must be different from current stage")

    if case.current_stage == MAIN_STAGE_RECEIVE and to_stage != MAIN_STAGE_TRIAGE:
        raise HTTPException(status_code=400, detail="receive stage can only transition to triage")
    if case.current_stage == MAIN_STAGE_TRIAGE and to_stage not in {MAIN_STAGE_VALIDATION, MAIN_STAGE_FINISHED}:
        raise HTTPException(status_code=400, detail="triage stage can only transition to validation or finished")
    if case.current_stage == MAIN_STAGE_VALIDATION and to_stage != MAIN_STAGE_FINISHED:
        raise HTTPException(status_code=400, detail="validation stage can only transition to finished")

    if case.current_stage == MAIN_STAGE_TRIAGE and to_stage == MAIN_STAGE_VALIDATION:
        if lifecycle.get("triage_decision") != "issue":
            raise HTTPException(status_code=400, detail="triage_decision must be issue before validation")
        if lifecycle.get("triage_gate") != "approved_to_validation":
            raise HTTPException(status_code=400, detail="triage_gate must be approved_to_validation before validation")

    if to_stage == MAIN_STAGE_FINISHED:
        if case.current_stage not in {MAIN_STAGE_TRIAGE, MAIN_STAGE_VALIDATION}:
            raise HTTPException(status_code=400, detail="only triage or validation stage can be finished manually")
        if finished_reason not in FINISHED_REASONS:
            raise HTTPException(status_code=400, detail="finished_reason is required when transitioning to finished")
        if not (summary or "").strip():
            raise HTTPException(status_code=400, detail="summary is required when transitioning to finished")


def _finish_case(
    db: Session,
    case: Case,
    *,
    finished_reason: str,
    summary: str,
    operator: str | None,
    transition_reason: str,
) -> None:
    _validate_stage_transition(case, MAIN_STAGE_FINISHED, finished_reason=finished_reason, summary=summary)
    advance_case_stage(db, case, MAIN_STAGE_FINISHED, transition_reason, "human")
    lifecycle = get_lifecycle_state(case)
    lifecycle["stage_status"] = FINISHED_STATUS_DONE
    lifecycle["finished_reason"] = finished_reason
    set_lifecycle_state(case, lifecycle)
    case.current_status = lifecycle["stage_status"]
    if finished_reason == "vulnerable":
        case.decision_status = "issue"
    elif finished_reason == "non_vulnerable":
        case.decision_status = "non_issue"
    elif finished_reason in TRIAGE_DECISIONS:
        case.decision_status = finished_reason

    if case.active_workflow_run_id:
        workflow_run = db.query(WorkflowRun).filter(WorkflowRun.id == case.active_workflow_run_id).first()
        if workflow_run:
            workflow_run.run_status = "completed"
            workflow_run.completed_at = datetime.utcnow()

    db.add(CaseEvent(
        id=uuid4().hex,
        case_id=case.id,
        event_type="case_finished",
        summary=summary,
        payload_json=json.dumps(
            {
                "finished_reason": finished_reason,
                "operator": operator,
                "transition_reason": transition_reason,
            },
            ensure_ascii=False,
        ),
    ))


@router.post("")
async def create_case(
    request: SuspicionSubmissionRequest,
    user_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    subject, token = user_and_token
    await ensure_project_access(request.project_id, token)
    creator = subject.get("username") or str(subject.get("id"))
    item = create_case_with_runtime(
        db,
        request.to_case_create_request(created_by_type="human", created_by=creator),
    )
    return _case_payload(item)


@router.post("/draft")
async def create_draft_case(
    request: DraftCaseCreateRequest,
    user_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    subject, token = user_and_token
    await ensure_project_access(request.project_id, token)
    creator = subject.get("username") or str(subject.get("id"))
    item = create_case_with_runtime(
        db,
        request.to_case_create_request(created_by_type="human", created_by=creator),
        initial_status="intake_created",
    )
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


@router.delete("/{case_id}")
async def delete_case(
    case_id: str,
    user_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    item = db.query(Case).filter(Case.id == case_id).first()
    if item is None:
        raise HTTPException(status_code=404, detail="case not found")

    user, token = user_and_token
    await ensure_project_access(item.project_id, token)

    db.query(Result).filter(Result.case_id == case_id).delete()
    db.query(ActionExecution).filter(ActionExecution.case_id == case_id).delete()
    db.query(ManualTask).filter(ManualTask.case_id == case_id).delete()
    db.query(StageHistory).filter(StageHistory.case_id == case_id).delete()
    db.query(CaseEvent).filter(CaseEvent.case_id == case_id).delete()
    db.query(WorkflowRun).filter(WorkflowRun.case_id == case_id).delete()
    db.delete(item)
    db.commit()

    return {
        "status": "ok",
        "deleted_case_id": case_id,
        "deleted_by": user.get("username") or str(user.get("id")),
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
    finished_reason_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    action_status_counts: dict[str, int] = {}
    result_type_counts: dict[str, int] = {}
    for item in cases:
        stage_counts[item.current_stage] = stage_counts.get(item.current_stage, 0) + 1
        decision_counts[item.decision_status] = decision_counts.get(item.decision_status, 0) + 1
        severity_counts[item.severity] = severity_counts.get(item.severity, 0) + 1
        finished_reason = get_lifecycle_state(item).get("finished_reason")
        if item.current_stage == MAIN_STAGE_FINISHED and finished_reason:
            finished_reason_counts[finished_reason] = finished_reason_counts.get(finished_reason, 0) + 1
    for item in actions:
        action_status_counts[item.execution_status] = action_status_counts.get(item.execution_status, 0) + 1
    for item in results:
        result_type_counts[item.result_type] = result_type_counts.get(item.result_type, 0) + 1

    recent_trend: list[dict[str, int | str]] = []
    trend_window = 7
    today = datetime.utcnow().date()
    for offset in range(trend_window - 1, -1, -1):
        day = today - timedelta(days=offset)
        count = len([
            item for item in cases
            if item.created_at and item.created_at.date() == day
        ])
        recent_trend.append({
            "date": day.isoformat(),
            "count": count,
        })

    recent_cases = sorted(cases, key=lambda item: item.updated_at or datetime.utcnow(), reverse=True)[:5]
    return {
        "project_id": project_id,
        "metrics": {
            "total_cases": len(cases),
            "running_cases": len([item for item in cases if item.current_stage in {MAIN_STAGE_RECEIVE, MAIN_STAGE_TRIAGE, MAIN_STAGE_VALIDATION}]),
            "finished_cases": len([item for item in cases if item.current_stage == MAIN_STAGE_FINISHED]),
            "finished_rate": round(
                (len([item for item in cases if item.current_stage == MAIN_STAGE_FINISHED]) / len(cases)) * 100,
                2,
            ) if cases else 0.0,
            "waiting_external": len([item for item in actions if item.execution_status in {"queued", "running"}]),
            "manual_tasks_open": len([item for item in tasks if item.status == "open"]),
            "registered_services": len(services),
            "active_services": len([item for item in services if item.status == "active"]),
            "queued_actions": len([item for item in actions if item.execution_status in {"queued", "running"}]),
        },
        "stage_counts": stage_counts,
        "decision_counts": decision_counts,
        "finished_reason_counts": finished_reason_counts,
        "severity_counts": severity_counts,
        "action_status_counts": action_status_counts,
        "result_type_counts": result_type_counts,
        "recent_trend": recent_trend,
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
    lifecycle = get_lifecycle_state(case)
    case.current_status = lifecycle.get("stage_status", case.current_status)
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
    if request.status in {"done", "completed", "closed"} and case.current_stage == MAIN_STAGE_TRIAGE:
        lifecycle = get_lifecycle_state(case)
        lifecycle["stage_status"] = TRIAGE_STATUS_AWAITING_MANUAL_GATE
        set_lifecycle_state(case, lifecycle)
        case.current_status = lifecycle["stage_status"]
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
    _validate_stage_transition(
        case,
        request.to_stage,
        finished_reason=request.finished_reason,
        summary=request.summary,
    )
    if request.to_stage == MAIN_STAGE_FINISHED:
        _finish_case(
            db,
            case,
            finished_reason=request.finished_reason or "manual_terminated",
            summary=(request.summary or "").strip(),
            operator=user.get("username"),
            transition_reason=request.reason or "manual_transition",
        )
        db.commit()
        return {"status": "ok", "case": _case_payload(case)}

    advance_case_stage(db, case, request.to_stage, request.reason or "manual_transition", "human")
    lifecycle = get_lifecycle_state(case)
    if request.to_stage == MAIN_STAGE_TRIAGE:
        lifecycle["stage_status"] = TRIAGE_STATUS_WAITING
    elif request.to_stage == MAIN_STAGE_VALIDATION:
        lifecycle["stage_status"] = VALIDATION_STATUS_QUEUED
    set_lifecycle_state(case, lifecycle)
    case.current_status = lifecycle["stage_status"]
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


@router.post("/{case_id}/finish")
async def finish_case(
    case_id: str,
    request: FinishCaseRequest,
    user_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    user, token = user_and_token
    case = db.query(Case).filter(Case.id == case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    await ensure_project_access(case.project_id, token)
    _finish_case(
        db,
        case,
        finished_reason=request.finished_reason,
        summary=request.summary.strip(),
        operator=user.get("username"),
        transition_reason="manual_finish",
    )
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
    if case.current_stage != MAIN_STAGE_TRIAGE:
        raise HTTPException(status_code=400, detail="decision is only allowed in triage stage")
    record_case_decision(db, case, request.decision_status, request.summary, user.get("username"))
    db.commit()
    return {"status": "ok", "case": _case_payload(case)}


@router.post("/{case_id}/triage/decision")
async def update_case_triage_decision(
    case_id: str,
    request: TriageDecisionRequest,
    user_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    user, token = user_and_token
    case = db.query(Case).filter(Case.id == case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    await ensure_project_access(case.project_id, token)
    if case.current_stage != MAIN_STAGE_TRIAGE:
        raise HTTPException(status_code=400, detail="triage decision is only allowed in triage stage")
    if request.triage_decision not in TRIAGE_DECISIONS:
        raise HTTPException(status_code=400, detail=f"unsupported triage_decision: {request.triage_decision}")

    record_case_decision(db, case, request.triage_decision, request.summary, user.get("username"))
    db.commit()
    return {"status": "ok", "case": _case_payload(case)}


@router.post("/{case_id}/triage/gate")
async def update_case_triage_gate(
    case_id: str,
    request: TriageGateRequest,
    user_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    user, token = user_and_token
    case = db.query(Case).filter(Case.id == case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    await ensure_project_access(case.project_id, token)
    if case.current_stage != MAIN_STAGE_TRIAGE:
        raise HTTPException(status_code=400, detail="triage gate is only allowed in triage stage")
    if request.triage_gate not in TRIAGE_GATES:
        raise HTTPException(status_code=400, detail=f"unsupported triage_gate: {request.triage_gate}")

    update_triage_gate(
        case,
        request.triage_gate,
        summary=request.summary or f"triage gate -> {request.triage_gate}",
        source_id=user.get("username"),
    )
    db.add(CaseEvent(
        id=uuid4().hex,
        case_id=case.id,
        event_type="triage_gate_updated",
        summary=request.summary or request.triage_gate,
        payload_json=json.dumps(
            {
                "triage_gate": request.triage_gate,
                "operator": user.get("username"),
            },
            ensure_ascii=False,
        ),
    ))
    db.commit()
    return {"status": "ok", "case": _case_payload(case)}


@router.post("/{case_id}/triage/rounds")
async def start_case_next_triage_round(
    case_id: str,
    request: TriageRoundStartRequest,
    user_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    user, token = user_and_token
    case = db.query(Case).filter(Case.id == case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    await ensure_project_access(case.project_id, token)
    if case.current_stage != MAIN_STAGE_TRIAGE:
        raise HTTPException(status_code=400, detail="triage rounds are only allowed in triage stage")

    next_round = start_next_triage_round(case, summary=request.summary)
    db.add(CaseEvent(
        id=uuid4().hex,
        case_id=case.id,
        event_type="triage_round_started",
        summary=request.summary or f"round {next_round}",
        payload_json=json.dumps(
            {
                "triage_round": next_round,
                "operator": user.get("username"),
                "reason": request.summary,
            },
            ensure_ascii=False,
        ),
    ))
    db.commit()
    return {"status": "ok", "case": _case_payload(case)}


@router.post("/{case_id}/validation/result")
async def update_case_validation_result(
    case_id: str,
    request: ValidationResultRequest,
    user_and_token: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    user, token = user_and_token
    case = db.query(Case).filter(Case.id == case_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    await ensure_project_access(case.project_id, token)
    if case.current_stage != MAIN_STAGE_VALIDATION:
        raise HTTPException(status_code=400, detail="validation result is only allowed in validation stage")
    if request.validation_result not in VALIDATION_RESULTS:
        raise HTTPException(status_code=400, detail=f"unsupported validation_result: {request.validation_result}")

    update_validation_result(case, request.validation_result, stage_status=VALIDATION_STATUS_COMPLETED)
    db.add(CaseEvent(
        id=uuid4().hex,
        case_id=case.id,
        event_type="validation_result_updated",
        summary=request.summary or request.validation_result,
        payload_json=json.dumps(
            {
                "validation_result": request.validation_result,
                "operator": user.get("username"),
            },
            ensure_ascii=False,
        ),
    ))
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
    if case.current_stage == MAIN_STAGE_FINISHED:
        raise HTTPException(status_code=400, detail="finished stage does not allow dispatch")
    if request.stage and request.stage != case.current_stage:
        raise HTTPException(status_code=400, detail="stage override is not allowed; use stage-transition first")
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
    if case.current_stage == MAIN_STAGE_FINISHED:
        return {"items": [], "total": 0}
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
    if case.current_stage == MAIN_STAGE_FINISHED:
        raise HTTPException(status_code=400, detail="finished stage does not allow auto orchestration")
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
