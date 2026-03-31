"""Minimal lifecycle engine."""

import json
from datetime import datetime, timedelta
from uuid import uuid4

from sqlalchemy.orm import Session

from app.config import get_config
from app.models.database import ActionExecution, Case, CaseEvent, ManualTask, Result, ServiceRegistry, StageHistory, WorkflowDefinition, WorkflowRun
from app.schemas import ActionCallbackRequest, CaseCreateRequest, ManualTaskCreateRequest, RoutedActionDispatchRequest


STAGE_ACTION_CANDIDATES: dict[str, list[str]] = {
    "ingest": ["analysis"],
    "normalize": ["analysis", "ai_analysis", "static_analysis"],
    "route": ["analysis", "ai_analysis", "static_analysis", "reverse_analysis"],
    "analyze": ["analysis", "ai_analysis", "static_analysis", "reverse_analysis"],
    "verify": ["validation", "blackbox_validation", "runtime_validation", "simulation_validation"],
    "prove": ["poc_generation", "exp_generation", "proof_verification"],
    "decide": ["manual_review", "manual_decision"],
    "track": ["feedback", "tool_feedback"],
}

SPECIAL_FILESERVER_SUBPROJECT_NAME = "__vuln_cases__"


def build_case_fileserver_root(case_id: str) -> dict[str, str | None]:
    root_path = f"/{SPECIAL_FILESERVER_SUBPROJECT_NAME}/{case_id}"
    return {
        "root_path": root_path,
        "root_name": case_id,
        "special_subproject_name": SPECIAL_FILESERVER_SUBPROJECT_NAME,
        "special_subproject_id": None,
    }


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


def create_case_with_runtime(db: Session, request: CaseCreateRequest, *, initial_status: str = "running") -> Case:
    workflow = ensure_default_workflow(db)
    source_meta, target_meta, display_meta = request.build_storage_payloads()
    case_id = uuid4().hex
    fileserver_root = build_case_fileserver_root(case_id)
    display_meta["fileserver_root"] = fileserver_root
    case = Case(
        id=case_id,
        project_id=request.project_id,
        title=request.title,
        summary=request.summary,
        severity=request.severity,
        confidence=request.confidence,
        current_stage="ingest",
        current_status=initial_status,
        decision_status="unknown",
        workflow_definition_id=workflow.id,
        source_meta_json=json.dumps(source_meta, ensure_ascii=False),
        target_meta_json=json.dumps(target_meta, ensure_ascii=False),
        display_meta_json=json.dumps(display_meta, ensure_ascii=False),
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
        payload_json=json.dumps(request.model_dump(mode="json"), ensure_ascii=False),
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
    automation_notes: list[str] = []

    if payload.suggested_decision:
        case.decision_status = payload.suggested_decision
        automation_notes.append(f"decision={payload.suggested_decision}")
    if payload.suggested_stage and payload.suggested_stage != case.current_stage:
        advance_case_stage(db, case, payload.suggested_stage, "external_result_suggestion", "service")
        automation_notes.append(f"stage={payload.suggested_stage}")
    elif case.current_stage in {"normalize", "route"}:
        advance_case_stage(db, case, "analyze", "result_received_default", "service")
        automation_notes.append("stage=analyze")
    elif case.current_stage == "analyze":
        advance_case_stage(db, case, "verify", "analysis_completed_default", "service")
        automation_notes.append("stage=verify")
    elif case.current_stage == "verify" and payload.result_type in {"poc", "exp"}:
        advance_case_stage(db, case, "prove", "proof_received", "service")
        automation_notes.append("stage=prove")

    if payload.status == "failed":
        case.current_status = "waiting_manual"
        _ensure_manual_task(
            db,
            case,
            task_type="manual_validation",
            title="外部能力执行失败，请人工介入",
            summary=payload.summary or "外部服务返回失败结果，需要人工确认下一步动作",
            context={
                "source_service_id": payload.source_service_id,
                "result_type": payload.result_type,
                "status": payload.status,
            },
        )
        automation_notes.append("manual_task=failed_result_followup")
    elif payload.confidence < 50 and payload.status in {"succeeded", "partial"}:
        case.current_status = "waiting_manual"
        _ensure_manual_task(
            db,
            case,
            task_type="manual_review",
            title="低置信度结果待人工复核",
            summary=payload.summary or "结果已回传，但置信度较低，需要人工复核",
            context={
                "source_service_id": payload.source_service_id,
                "confidence": payload.confidence,
                "result_type": payload.result_type,
            },
        )
        automation_notes.append("manual_task=low_confidence_review")
    elif payload.result_type in {"poc", "exp"} and payload.status == "succeeded":
        if case.current_stage != "decide":
            advance_case_stage(db, case, "decide", "proof_ready_auto_decide", "system")
            automation_notes.append("stage=decide")
        if case.decision_status == "unknown":
            case.decision_status = "suspected"
            automation_notes.append("decision=suspected")
    elif payload.result_type in {"feedback"} and payload.status == "succeeded":
        if case.current_stage != "track":
            advance_case_stage(db, case, "track", "feedback_completed", "system")
            automation_notes.append("stage=track")

    if payload.suggested_decision in {"confirmed", "false_positive", "accepted_risk"}:
        if case.current_stage != "track":
            advance_case_stage(db, case, "track", "decision_converged_auto_track", "system")
            automation_notes.append("stage=track")
        case.current_status = "running"
    elif case.current_status != "waiting_manual":
        case.current_status = "running"

    if automation_notes:
        db.add(CaseEvent(
            id=uuid4().hex,
            case_id=case.id,
            event_type="automation_rule_applied",
            summary="; ".join(automation_notes),
            payload_json=json.dumps(
                {
                    "notes": automation_notes,
                    "result_type": payload.result_type,
                    "status": payload.status,
                    "confidence": payload.confidence,
                },
                ensure_ascii=False,
            ),
        ))


def create_manual_task(db: Session, case: Case, request: ManualTaskCreateRequest) -> ManualTask:
    task = ManualTask(
        id=uuid4().hex,
        case_id=case.id,
        task_type=request.task_type,
        status="open",
        assignee=request.assignee,
        title=request.title,
        summary=request.summary,
        context_json=json.dumps(request.context, ensure_ascii=False),
        due_at=request.due_at,
    )
    db.add(task)
    db.add(CaseEvent(
        id=uuid4().hex,
        case_id=case.id,
        event_type="manual_task_created",
        summary=request.title,
        payload_json=json.dumps(request.model_dump(mode="json"), ensure_ascii=False),
    ))
    return task


def _ensure_manual_task(
    db: Session,
    case: Case,
    task_type: str,
    title: str,
    summary: str | None,
    context: dict | None = None,
) -> ManualTask:
    existing = db.query(ManualTask).filter(
        ManualTask.case_id == case.id,
        ManualTask.task_type == task_type,
        ManualTask.status.in_(["open", "in_progress"]),
    ).order_by(ManualTask.created_at.desc()).first()
    if existing:
        return existing

    return create_manual_task(
        db,
        case,
        ManualTaskCreateRequest(
            task_type=task_type,
            title=title,
            summary=summary,
            context=context or {},
        ),
    )


def record_case_decision(db: Session, case: Case, decision_status: str, summary: str | None, source_id: str | None) -> None:
    case.decision_status = decision_status
    case.current_status = "waiting_manual" if decision_status == "needs_more_evidence" else "running"
    db.add(CaseEvent(
        id=uuid4().hex,
        case_id=case.id,
        event_type="decision_recorded",
        summary=summary or decision_status,
        payload_json=json.dumps(
            {
                "decision_status": decision_status,
                "summary": summary,
            },
            ensure_ascii=False,
        ),
    ))
    db.add(StageHistory(
        id=uuid4().hex,
        case_id=case.id,
        from_stage=case.current_stage,
        to_stage=case.current_stage,
        reason=f"decision:{decision_status}",
        source_type="human",
        source_id=source_id,
    ))


def _stage_from_action(action_type: str, current_stage: str) -> str:
    mapping = {
        "analysis": "analyze",
        "ai_analysis": "analyze",
        "static_analysis": "analyze",
        "reverse_analysis": "analyze",
        "validation": "verify",
        "blackbox_validation": "verify",
        "runtime_validation": "verify",
        "simulation_validation": "verify",
        "poc_generation": "prove",
        "exp_generation": "prove",
        "proof_verification": "prove",
        "manual_review": "decide",
        "manual_decision": "decide",
        "feedback": "track",
        "tool_feedback": "track",
    }
    return mapping.get(action_type, current_stage)


def dispatch_routed_actions(
    db: Session,
    case: Case,
    request: RoutedActionDispatchRequest | None = None,
) -> list[ActionExecution]:
    cfg = get_config()
    route_request = request or RoutedActionDispatchRequest()
    query = db.query(ServiceRegistry).filter(ServiceRegistry.status == "active")
    if route_request.service_id:
        query = query.filter(ServiceRegistry.service_id == route_request.service_id)
    services = query.all()

    actions: list[ActionExecution] = []
    stage = route_request.stage or case.current_stage
    for service in services:
        for capability in service.capabilities:
            if route_request.action_type and capability.action_type != route_request.action_type:
                continue
            action_stage = _stage_from_action(capability.action_type, stage)
            action = ActionExecution(
                id=uuid4().hex,
                case_id=case.id,
                workflow_run_id=case.active_workflow_run_id,
                stage=action_stage,
                action_type=capability.action_type,
                target_service_id=service.service_id,
                capability_code=capability.capability_code,
                dispatch_status="dispatched",
                execution_status="queued",
                input_meta_json=json.dumps(route_request.input_meta, ensure_ascii=False),
                input_artifact_refs_json=json.dumps(route_request.input_artifact_refs, ensure_ascii=False),
                max_retry_count=cfg.engine.retry_default,
                timeout_at=datetime.utcnow() + timedelta(seconds=capability.timeout_seconds or cfg.engine.action_timeout_default),
                started_at=datetime.utcnow(),
            )
            db.add(action)
            actions.append(action)

    if actions:
        next_stage = _stage_from_action(actions[0].action_type, case.current_stage)
        if next_stage != case.current_stage:
            advance_case_stage(db, case, next_stage, "action_dispatched", "system")
        case.current_status = "waiting_external"
        db.add(CaseEvent(
            id=uuid4().hex,
            case_id=case.id,
            event_type="actions_dispatched",
            summary=f"dispatched {len(actions)} action(s)",
            payload_json=json.dumps(
                {
                    "action_type": route_request.action_type,
                    "service_id": route_request.service_id,
                    "count": len(actions),
                    "targets": [item.target_service_id for item in actions],
                },
                ensure_ascii=False,
            ),
        ))
    return actions


def recommend_actions(db: Session, case: Case) -> list[dict]:
    allowed_types = STAGE_ACTION_CANDIDATES.get(case.current_stage, [])
    if not allowed_types:
        return []

    active_pairs = {
        (item.target_service_id, item.action_type)
        for item in db.query(ActionExecution).filter(
            ActionExecution.case_id == case.id,
            ActionExecution.execution_status.in_(["queued", "running"]),
        ).all()
    }

    recommendations: list[dict] = []
    services = db.query(ServiceRegistry).filter(ServiceRegistry.status == "active").all()
    for service in services:
        for capability in service.capabilities:
            if capability.action_type not in allowed_types:
                continue
            pair = (service.service_id, capability.action_type)
            recommendations.append({
                "service_id": service.service_id,
                "service_name": service.service_name,
                "service_type": service.service_type,
                "capability_code": capability.capability_code,
                "action_type": capability.action_type,
                "priority": capability.priority,
                "recommended_stage": _stage_from_action(capability.action_type, case.current_stage),
                "already_active": pair in active_pairs,
            })

    recommendations.sort(key=lambda item: (item["already_active"], item["priority"], item["service_name"]))
    return recommendations


def auto_orchestrate_case(db: Session, case: Case) -> list[ActionExecution]:
    dispatched: list[ActionExecution] = []
    for item in recommend_actions(db, case):
        if item["already_active"]:
            continue
        dispatched.extend(
            dispatch_routed_actions(
                db,
                case,
                RoutedActionDispatchRequest(
                    action_type=item["action_type"],
                    service_id=item["service_id"],
                    stage=item["recommended_stage"],
                ),
            )
        )
    return dispatched
