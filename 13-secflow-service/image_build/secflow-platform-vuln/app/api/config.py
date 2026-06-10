"""Project-scoped engine configuration endpoints."""

import json
from uuid import uuid4

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.dependencies import ensure_project_access, get_current_subject
from app.models.database import EngineProjectConfig, get_db
from app.schemas import VulnEngineProjectConfigResponse, VulnEngineProjectConfigUpdateRequest

router = APIRouter(prefix="/api/vuln/config", tags=["config"])


DEFAULT_VULN_ENGINE_CONFIG: dict = {
    "global": {
        "workflow_code": "default_vuln_lifecycle",
        "auto_orchestrate_new_case": True,
        "max_parallel_actions_per_case": 3,
        "default_action_timeout_seconds": 300,
        "duplicate_window_hours": 24,
        "service_health_grace_seconds": 90,
        "escalation_keywords": ["RCE", "权限提升", "供应链", "认证绕过"],
    },
    "receive": {
        "auto_accept_authenticated_reports": True,
        "intake_require_project_token_auth": False,
        "intake_require_fingerprint": False,
        "intake_dedup_mode": "fingerprint_first",
        "minimum_confidence_for_auto_intake": 40,
        "receive_stage_sla_hours": 4,
        "allowed_reporter_types": ["service", "plugin", "cli", "api", "human"],
    },
    "triage": {
        "auto_dispatch_analysis": True,
        "triage_round_limit": 3,
        "require_manual_gate_for_high_severity": True,
        "auto_promote_confidence_threshold": 75,
        "triage_owner_role": "analysis_lead",
        "analysis_action_types": ["analysis", "tool_feedback"],
    },
    "validation": {
        "auto_dispatch_validation": True,
        "validation_retry_limit": 2,
        "validation_timeout_minutes": 45,
        "allow_parallel_validation": True,
        "require_poc_for_high_severity": True,
        "preferred_validation_channels": ["validation", "poc_generation", "exp_generation"],
    },
    "finished": {
        "auto_finish_on_verdict": False,
        "auto_sync_external_ticket": False,
        "archive_retention_days": 30,
        "reopen_on_new_evidence": True,
        "notify_source_service": True,
        "final_gate_required": True,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _normalize_config(config_value: object) -> dict:
    if not isinstance(config_value, dict):
        return json.loads(json.dumps(DEFAULT_VULN_ENGINE_CONFIG, ensure_ascii=False))
    return _deep_merge(DEFAULT_VULN_ENGINE_CONFIG, config_value)


def _to_response(record: EngineProjectConfig | None, project_id: str) -> VulnEngineProjectConfigResponse:
    raw_config = {}
    if record and record.config_json:
        try:
            raw_config = json.loads(record.config_json)
        except json.JSONDecodeError:
            raw_config = {}
    return VulnEngineProjectConfigResponse(
        project_id=project_id,
        config=_normalize_config(raw_config),
        updated_by=record.updated_by if record else None,
        created_at=record.created_at if record else None,
        updated_at=record.updated_at if record else None,
    )


@router.get("", response_model=VulnEngineProjectConfigResponse)
async def get_project_config(
    project_id: str = Query(...),
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    _, token = subject
    await ensure_project_access(project_id, token)
    record = db.query(EngineProjectConfig).filter(EngineProjectConfig.project_id == project_id).first()
    return _to_response(record, project_id)


@router.put("", response_model=VulnEngineProjectConfigResponse)
async def update_project_config(
    request: VulnEngineProjectConfigUpdateRequest,
    subject=Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    principal, token = subject
    await ensure_project_access(request.project_id, token)
    record = db.query(EngineProjectConfig).filter(EngineProjectConfig.project_id == request.project_id).first()
    if record is None:
        record = EngineProjectConfig(
            id=f"vec-{uuid4().hex[:20]}",
            project_id=request.project_id,
        )
        db.add(record)
    record.config_json = json.dumps(_normalize_config(request.config), ensure_ascii=False)
    record.updated_by = str(principal.get("username") or principal.get("sub") or "")
    db.commit()
    db.refresh(record)
    return _to_response(record, request.project_id)
