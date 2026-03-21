"""Minimal lifecycle engine."""

import json
from uuid import uuid4

from sqlalchemy.orm import Session

from app.config import get_config
from app.models.database import Case, CaseEvent, Result, StageHistory, WorkflowDefinition, WorkflowRun
from app.schemas import ActionCallbackRequest, CaseCreateRequest


def ensure_default_workflow(db: Session) -> WorkflowDefinition:
    cfg = get_config()
    workflow = db.query(WorkflowDefinition).filter(
        WorkflowDefinition.code == cfg.workflow.default_workflow_code
    ).first()
    if workflow is None:
        workflow = WorkflowDefinition(
            id=uuid4().hex,
            code=cfg.workflow.default_workflow_code,
            name="Default Vulnerability Lifecycle",
            version="1.0.0",
            is_default=1,
            status="active",
            trigger_rules_json=json.dumps({}, ensure_ascii=False),
            stage_rules_json=json.dumps({}, ensure_ascii=False),
            transition_rules_json=json.dumps({}, ensure_ascii=False),
        )
        db.add(workflow)
        db.commit()
        db.refresh(workflow)
    return workflow


def create_case_with_runtime(db: Session, request: CaseCreateRequest) -> Case:
    workflow = ensure_default_workflow(db)
    case = Case(
        id=uuid4().hex,
        project_id=request.project_id,
        title=request.title,
        summary=request.summary,
        severity=request.severity,
        confidence=request.confidence,
        current_stage="ingest",
        current_status="running",
        decision_status="unknown",
        workflow_definition_id=workflow.id,
        source_meta_json=json.dumps(request.source_meta, ensure_ascii=False),
        target_meta_json=json.dumps(request.target_meta, ensure_ascii=False),
        display_meta_json=json.dumps(request.display_meta, ensure_ascii=False),
        created_by_type=request.created_by_type,
        created_by=request.created_by,
    )
    db.add(case)
    db.flush()

    workflow_run = WorkflowRun(
        id=uuid4().hex,
        case_id=case.id,
        workflow_definition_id=workflow.id,
        current_stage="ingest",
        run_status="running",
        context_json=json.dumps({}, ensure_ascii=False),
    )
    db.add(workflow_run)
    case.active_workflow_run_id = workflow_run.id

    db.add(CaseEvent(
        id=uuid4().hex,
        case_id=case.id,
        event_type="created",
        summary=request.summary or request.title,
        payload_json=json.dumps(request.model_dump(), ensure_ascii=False),
    ))

    db.add(StageHistory(
        id=uuid4().hex,
        case_id=case.id,
        from_stage=None,
        to_stage="ingest",
        reason="case_created",
        source_type=request.created_by_type,
        source_id=request.created_by,
    ))

    advance_case_stage(db, case, "normalize", "auto_after_ingest")
    db.commit()
    db.refresh(case)
    return case


def advance_case_stage(db: Session, case: Case, to_stage: str, reason: str, source_type: str = "system") -> None:
    old_stage = case.current_stage
    case.current_stage = to_stage
    db.add(StageHistory(
        id=uuid4().hex,
        case_id=case.id,
        from_stage=old_stage,
        to_stage=to_stage,
        reason=reason,
        source_type=source_type,
    ))

    if case.active_workflow_run_id:
        run = db.query(WorkflowRun).filter(WorkflowRun.id == case.active_workflow_run_id).first()
        if run:
            run.current_stage = to_stage


def apply_action_result(db: Session, case: Case, payload: ActionCallbackRequest) -> None:
    if payload.suggested_decision:
        case.decision_status = payload.suggested_decision
    if payload.suggested_stage and payload.suggested_stage != case.current_stage:
        advance_case_stage(db, case, payload.suggested_stage, "external_result_suggestion", "service")
    elif case.current_stage in {"normalize", "route"}:
        advance_case_stage(db, case, "analyze", "result_received_default", "service")
    elif case.current_stage == "analyze":
        advance_case_stage(db, case, "verify", "analysis_completed_default", "service")
    elif case.current_stage == "verify" and payload.result_type in {"poc", "exp"}:
        advance_case_stage(db, case, "prove", "proof_received", "service")
