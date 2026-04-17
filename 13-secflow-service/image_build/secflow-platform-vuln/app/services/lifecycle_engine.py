"""Minimal lifecycle engine."""

import json
from datetime import datetime, timedelta
from uuid import uuid4

from sqlalchemy.orm import Session

from app.config import get_config
from app.models.database import ActionExecution, Case, CaseEvent, ManualTask, Result, ServiceCapability, ServiceRegistry, StageHistory, WorkflowDefinition, WorkflowRun
from app.schemas import ActionCallbackRequest, CaseCreateRequest, ManualTaskCreateRequest, RoutedActionDispatchRequest


MAIN_STAGE_RECEIVE = "receive"
MAIN_STAGE_TRIAGE = "triage"
MAIN_STAGE_VALIDATION = "validation"
MAIN_STAGE_FINISHED = "finished"

MAIN_STAGES = {MAIN_STAGE_RECEIVE, MAIN_STAGE_TRIAGE, MAIN_STAGE_VALIDATION, MAIN_STAGE_FINISHED}

TRIAGE_DECISIONS = {"issue", "non_issue", "observe"}
TRIAGE_GATES = {"pending", "approved_to_validation", "rejected_to_validation"}
VALIDATION_RESULTS = {"vulnerable", "not_vulnerable", "inconclusive"}
FINISHED_REASONS = {"vulnerable", "non_vulnerable", "inconclusive", "non_issue", "observe", "manual_terminated"}

RECEIVE_STATUS_INTAKE_CREATED = "intake_created"
RECEIVE_STATUS_FILES_COLLECTING = "files_collecting"
RECEIVE_STATUS_READY_FOR_TRIAGE = "ready_for_triage"

TRIAGE_STATUS_WAITING = "waiting"
TRIAGE_STATUS_AI_ASSESSING = "ai_assessing"
TRIAGE_STATUS_MANUAL_ASSESSING = "manual_assessing"
TRIAGE_STATUS_AWAITING_MANUAL_GATE = "awaiting_manual_gate"
TRIAGE_STATUS_COMPLETED = "triage_completed"

VALIDATION_STATUS_QUEUED = "queued"
VALIDATION_STATUS_POC_GENERATING = "poc_generating"
VALIDATION_STATUS_EXP_GENERATING = "exp_generating"
VALIDATION_STATUS_REPRODUCING = "reproducing"
VALIDATION_STATUS_EVIDENCE_COLLECTING = "evidence_collecting"
VALIDATION_STATUS_COMPLETED = "validation_completed"
FINISHED_STATUS_DONE = "finished"

STAGE_ACTION_CANDIDATES: dict[str, list[str]] = {
    MAIN_STAGE_RECEIVE: [],
    MAIN_STAGE_TRIAGE: ["analysis", "ai_analysis", "static_analysis", "reverse_analysis", "manual_review", "manual_decision"],
    MAIN_STAGE_VALIDATION: [
        "validation",
        "blackbox_validation",
        "runtime_validation",
        "simulation_validation",
        "poc_generation",
        "exp_generation",
        "proof_verification",
    ],
    MAIN_STAGE_FINISHED: ["proof_verification"],
}

SPECIAL_FILESERVER_SUBPROJECT_NAME = "__vuln_cases__"


def _load_display_meta(case: Case) -> dict:
    return json.loads(case.display_meta_json or "{}")


def _write_display_meta(case: Case, display_meta: dict) -> None:
    case.display_meta_json = json.dumps(display_meta, ensure_ascii=False)


def get_lifecycle_state(case: Case) -> dict:
    display_meta = _load_display_meta(case)
    lifecycle = dict(display_meta.get("lifecycle") or {})
    lifecycle.setdefault("stage_status", case.current_status or RECEIVE_STATUS_INTAKE_CREATED)
    lifecycle.setdefault("triage_decision", case.decision_status if case.decision_status in TRIAGE_DECISIONS else "observe")
    lifecycle.setdefault("triage_gate", "pending")
    lifecycle.setdefault("triage_round", 1)
    lifecycle.setdefault("triage_history", [])
    lifecycle.setdefault("validation_result", "inconclusive")
    lifecycle.setdefault("finished_reason", None)
    return lifecycle


def set_lifecycle_state(case: Case, lifecycle: dict) -> None:
    display_meta = _load_display_meta(case)
    display_meta["lifecycle"] = lifecycle
    _write_display_meta(case, display_meta)


def append_triage_history(
    case: Case,
    *,
    actor_type: str,
    summary: str | None,
    suggested_decision: str | None,
) -> None:
    lifecycle = get_lifecycle_state(case)
    history = list(lifecycle.get("triage_history") or [])
    history.append(
        {
            "round_no": int(lifecycle.get("triage_round") or 1),
            "actor_type": actor_type,
            "summary": summary,
            "suggested_decision": suggested_decision,
            "created_at": datetime.utcnow().isoformat(),
        }
    )
    lifecycle["triage_history"] = history
    set_lifecycle_state(case, lifecycle)


def generate_case_id() -> str:
    """Generate a sortable case id with report timestamp embedded."""
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    return f"case-{ts}-{uuid4().hex[:10]}"


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


def create_case_with_runtime(db: Session, request: CaseCreateRequest, *, initial_status: str = RECEIVE_STATUS_INTAKE_CREATED) -> Case:
    workflow = ensure_default_workflow(db)
    source_meta, target_meta, display_meta = request.build_storage_payloads()
    case_id = generate_case_id()
    fileserver_root = build_case_fileserver_root(case_id)
    display_meta["fileserver_root"] = fileserver_root
    case = Case(
        id=case_id,
        project_id=request.project_id,
        title=request.title,
        summary=request.summary,
        severity=request.severity,
        confidence=request.confidence,
        current_stage=MAIN_STAGE_RECEIVE,
        current_status=initial_status,
        decision_status="observe",
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
        current_stage=MAIN_STAGE_RECEIVE,
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
        to_stage=MAIN_STAGE_RECEIVE,
        reason="case_created",
        source_type=request.created_by_type,
        source_id=request.created_by,
    ))
    set_lifecycle_state(
        case,
        {
            "stage_status": initial_status,
            "triage_decision": "observe",
            "triage_gate": "pending",
            "triage_round": 1,
            "triage_history": [],
            "validation_result": "inconclusive",
            "finished_reason": None,
        },
    )
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
    if case.current_stage == MAIN_STAGE_FINISHED:
        db.add(CaseEvent(
            id=uuid4().hex,
            case_id=case.id,
            event_type="finished_stage_result_received",
            summary=payload.summary or payload.result_type,
            payload_json=json.dumps(
                {
                    "result_type": payload.result_type,
                    "status": payload.status,
                    "confidence": payload.confidence,
                    "source_service_id": payload.source_service_id,
                    "suggested_stage": payload.suggested_stage,
                    "suggested_decision": payload.suggested_decision,
                },
                ensure_ascii=False,
            ),
        ))
        return

    automation_notes: list[str] = []
    lifecycle = get_lifecycle_state(case)

    if case.current_stage == MAIN_STAGE_TRIAGE:
        suggested = payload.suggested_decision if payload.suggested_decision in TRIAGE_DECISIONS else None
        append_triage_history(
            case,
            actor_type="ai",
            summary=payload.summary,
            suggested_decision=suggested,
        )
        lifecycle = get_lifecycle_state(case)
        lifecycle["stage_status"] = TRIAGE_STATUS_AWAITING_MANUAL_GATE
        if suggested:
            lifecycle["triage_decision"] = suggested
            case.decision_status = suggested
            automation_notes.append(f"triage_decision={suggested}")
        set_lifecycle_state(case, lifecycle)

    if case.current_stage == MAIN_STAGE_VALIDATION:
        lifecycle["stage_status"] = VALIDATION_STATUS_EVIDENCE_COLLECTING
        suggested = payload.suggested_decision if payload.suggested_decision in TRIAGE_DECISIONS else None
        if suggested == "issue":
            lifecycle["validation_result"] = "vulnerable"
        elif suggested == "non_issue":
            lifecycle["validation_result"] = "not_vulnerable"
        elif payload.status in {"failed", "partial"}:
            lifecycle["validation_result"] = "inconclusive"
        set_lifecycle_state(case, lifecycle)
        automation_notes.append(f"validation_result={lifecycle['validation_result']}")

    if payload.status == "failed":
        if case.current_stage == MAIN_STAGE_TRIAGE:
            lifecycle["stage_status"] = TRIAGE_STATUS_MANUAL_ASSESSING
        elif case.current_stage == MAIN_STAGE_VALIDATION:
            lifecycle["stage_status"] = VALIDATION_STATUS_EVIDENCE_COLLECTING
        else:
            lifecycle["stage_status"] = RECEIVE_STATUS_FILES_COLLECTING
        set_lifecycle_state(case, lifecycle)
        case.current_status = lifecycle["stage_status"]
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
        if case.current_stage == MAIN_STAGE_TRIAGE:
            lifecycle["stage_status"] = TRIAGE_STATUS_MANUAL_ASSESSING
        elif case.current_stage == MAIN_STAGE_VALIDATION:
            lifecycle["stage_status"] = VALIDATION_STATUS_EVIDENCE_COLLECTING
        else:
            lifecycle["stage_status"] = RECEIVE_STATUS_FILES_COLLECTING
        set_lifecycle_state(case, lifecycle)
        case.current_status = lifecycle["stage_status"]
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
    else:
        lifecycle = get_lifecycle_state(case)
        case.current_status = lifecycle.get("stage_status", case.current_status)

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
    lifecycle = get_lifecycle_state(case)
    if case.current_stage == MAIN_STAGE_TRIAGE:
        lifecycle["stage_status"] = TRIAGE_STATUS_MANUAL_ASSESSING
        set_lifecycle_state(case, lifecycle)
        case.current_status = TRIAGE_STATUS_MANUAL_ASSESSING
    elif case.current_stage == MAIN_STAGE_VALIDATION:
        lifecycle["stage_status"] = VALIDATION_STATUS_EVIDENCE_COLLECTING
        set_lifecycle_state(case, lifecycle)
        case.current_status = VALIDATION_STATUS_EVIDENCE_COLLECTING
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
    lifecycle = get_lifecycle_state(case)
    mapped = decision_status
    if decision_status in {"confirmed", "suspected"}:
        mapped = "issue"
    elif decision_status in {"false_positive", "accepted_risk"}:
        mapped = "non_issue"
    elif decision_status == "needs_more_evidence":
        mapped = "observe"
    if mapped not in TRIAGE_DECISIONS:
        mapped = "observe"

    lifecycle["triage_decision"] = mapped
    lifecycle["stage_status"] = TRIAGE_STATUS_AWAITING_MANUAL_GATE if mapped == "issue" else TRIAGE_STATUS_COMPLETED
    case.decision_status = mapped
    case.current_status = lifecycle["stage_status"]
    set_lifecycle_state(case, lifecycle)
    append_triage_history(
        case,
        actor_type="human",
        summary=summary,
        suggested_decision=mapped,
    )
    db.add(CaseEvent(
        id=uuid4().hex,
        case_id=case.id,
        event_type="triage_decision_recorded",
        summary=summary or mapped,
        payload_json=json.dumps(
            {
                "triage_decision": mapped,
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


def update_triage_gate(case: Case, triage_gate: str, *, summary: str | None = None, source_id: str | None = None) -> None:
    lifecycle = get_lifecycle_state(case)
    lifecycle["triage_gate"] = triage_gate if triage_gate in TRIAGE_GATES else "pending"
    if lifecycle["triage_gate"] == "approved_to_validation":
        lifecycle["stage_status"] = TRIAGE_STATUS_AWAITING_MANUAL_GATE
    elif lifecycle["triage_gate"] == "rejected_to_validation":
        lifecycle["stage_status"] = TRIAGE_STATUS_COMPLETED
    set_lifecycle_state(case, lifecycle)
    case.current_status = lifecycle["stage_status"]
    if summary or source_id:
        append_triage_history(
            case,
            actor_type="human",
            summary=summary,
            suggested_decision=lifecycle.get("triage_decision"),
        )


def start_next_triage_round(case: Case, *, summary: str | None = None) -> int:
    lifecycle = get_lifecycle_state(case)
    lifecycle["triage_round"] = int(lifecycle.get("triage_round") or 1) + 1
    lifecycle["triage_gate"] = "pending"
    lifecycle["stage_status"] = TRIAGE_STATUS_WAITING
    set_lifecycle_state(case, lifecycle)
    case.current_status = lifecycle["stage_status"]
    if summary:
        append_triage_history(
            case,
            actor_type="human",
            summary=summary,
            suggested_decision=lifecycle.get("triage_decision"),
        )
    return lifecycle["triage_round"]


def update_validation_result(case: Case, validation_result: str, *, stage_status: str | None = None) -> None:
    lifecycle = get_lifecycle_state(case)
    lifecycle["validation_result"] = validation_result if validation_result in VALIDATION_RESULTS else "inconclusive"
    if stage_status:
        lifecycle["stage_status"] = stage_status
    set_lifecycle_state(case, lifecycle)
    case.current_status = lifecycle["stage_status"]


def capability_bind_stage(service: ServiceRegistry, capability: ServiceCapability, default_stage: str) -> str:
    capability_meta = json.loads(capability.meta_json or "{}")
    service_meta = json.loads(service.meta_json or "{}")
    return (
        capability_meta.get("bind_stage")
        or capability_meta.get("lifecycle_stage")
        or service_meta.get("bind_stage")
        or default_stage
    )


def _stage_from_action(action_type: str, current_stage: str) -> str:
    if action_type == "proof_verification" and current_stage == MAIN_STAGE_FINISHED:
        return MAIN_STAGE_FINISHED
    mapping = {
        "analysis": MAIN_STAGE_TRIAGE,
        "ai_analysis": MAIN_STAGE_TRIAGE,
        "static_analysis": MAIN_STAGE_TRIAGE,
        "reverse_analysis": MAIN_STAGE_TRIAGE,
        "manual_review": MAIN_STAGE_TRIAGE,
        "manual_decision": MAIN_STAGE_TRIAGE,
        "validation": MAIN_STAGE_VALIDATION,
        "blackbox_validation": MAIN_STAGE_VALIDATION,
        "runtime_validation": MAIN_STAGE_VALIDATION,
        "simulation_validation": MAIN_STAGE_VALIDATION,
        "poc_generation": MAIN_STAGE_VALIDATION,
        "exp_generation": MAIN_STAGE_VALIDATION,
        "proof_verification": MAIN_STAGE_VALIDATION,
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
    allowed_types = STAGE_ACTION_CANDIDATES.get(stage, [])
    input_meta_json = json.dumps(route_request.input_meta, ensure_ascii=False, sort_keys=True)
    input_artifact_refs_json = json.dumps(route_request.input_artifact_refs, ensure_ascii=False, sort_keys=True)
    for service in services:
        for capability in service.capabilities:
            if capability.action_type not in allowed_types:
                continue
            if route_request.action_type and capability.action_type != route_request.action_type:
                continue
            if capability_bind_stage(service, capability, stage) != stage:
                continue
            active_query = db.query(ActionExecution).filter(
                ActionExecution.case_id == case.id,
                ActionExecution.stage == stage,
                ActionExecution.action_type == capability.action_type,
                ActionExecution.target_service_id == service.service_id,
                ActionExecution.execution_status.in_(["queued", "running"]),
            )
            active_count = active_query.count()
            if active_count > 0:
                duplicate = active_query.filter(
                    ActionExecution.capability_code == capability.capability_code,
                    ActionExecution.input_meta_json == input_meta_json,
                    ActionExecution.input_artifact_refs_json == input_artifact_refs_json,
                ).first()
                if duplicate:
                    continue
            concurrency_limit = max(1, int(capability.concurrency_limit or 1))
            if active_count >= concurrency_limit:
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
                input_meta_json=input_meta_json,
                input_artifact_refs_json=input_artifact_refs_json,
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
        lifecycle = get_lifecycle_state(case)
        if next_stage == MAIN_STAGE_TRIAGE:
            if actions[0].action_type == "manual_review":
                lifecycle["stage_status"] = TRIAGE_STATUS_MANUAL_ASSESSING
            else:
                lifecycle["stage_status"] = TRIAGE_STATUS_AI_ASSESSING
        elif next_stage == MAIN_STAGE_VALIDATION:
            if actions[0].action_type == "poc_generation":
                lifecycle["stage_status"] = VALIDATION_STATUS_POC_GENERATING
            elif actions[0].action_type == "exp_generation":
                lifecycle["stage_status"] = VALIDATION_STATUS_EXP_GENERATING
            elif actions[0].action_type == "proof_verification":
                lifecycle["stage_status"] = VALIDATION_STATUS_REPRODUCING
            else:
                lifecycle["stage_status"] = VALIDATION_STATUS_QUEUED
        set_lifecycle_state(case, lifecycle)
        case.current_status = lifecycle.get("stage_status", case.current_status)
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
            if capability_bind_stage(service, capability, case.current_stage) != case.current_stage:
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
