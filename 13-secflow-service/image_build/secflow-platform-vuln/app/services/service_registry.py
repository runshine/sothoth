"""Capability service registry manager."""

import json
from datetime import datetime
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.config import get_config
from app.models.database import ServiceCapability, ServiceRegistry
from app.schemas import ServiceRegisterRequest


SERVICE_STATUS_ACTIVE = "active"
SERVICE_STATUS_STALE = "stale"
SERVICE_STATUS_INACTIVE = "inactive"
REPRO_ACTION_TYPES = {"validation", "proof_verification", "poc_generation", "exp_generation"}
REPRO_MODULE_ROLE_BY_ACTION = {
    "validation": {"reproducer", "validator"},
    "poc_generation": {"proof-provider"},
    "exp_generation": {"proof-provider"},
    "proof_verification": {"reporter", "proof-provider"},
}
REPRO_BIND_STAGE_BY_ACTION = {
    "validation": {"validation"},
    "poc_generation": {"validation"},
    "exp_generation": {"validation"},
    "proof_verification": {"validation", "finished"},
}


def _loads_meta(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def _service_status_for(service: ServiceRegistry, *, now: datetime | None = None) -> str:
    reference_time = now or datetime.utcnow()
    timeout_seconds = max(1, int(get_config().service_registry.heartbeat_timeout_seconds or 90))
    elapsed_seconds = max(0, int((reference_time - service.last_heartbeat_at).total_seconds()))
    if service.status == SERVICE_STATUS_INACTIVE:
        return SERVICE_STATUS_INACTIVE
    if elapsed_seconds > timeout_seconds * 3:
        return SERVICE_STATUS_INACTIVE
    if elapsed_seconds > timeout_seconds:
        return SERVICE_STATUS_STALE
    return SERVICE_STATUS_ACTIVE


def reconcile_service_statuses(db: Session, *, service_id: str | None = None) -> list[ServiceRegistry]:
    query = db.query(ServiceRegistry)
    if service_id:
        query = query.filter(ServiceRegistry.service_id == service_id)
    services = query.all()
    changed: list[ServiceRegistry] = []
    reference_time = datetime.utcnow()
    for service in services:
        desired_status = _service_status_for(service, now=reference_time)
        if service.status != desired_status:
            service.status = desired_status
            changed.append(service)
    if changed:
        db.commit()
        for service in changed:
            db.refresh(service)
    return services


def ensure_unique_capabilities(request: ServiceRegisterRequest) -> None:
    seen_codes: set[str] = set()
    seen_pairs: set[tuple[str, str]] = set()
    for item in request.capabilities:
        code = item.capability_code.strip()
        pair = (item.action_type.strip(), code)
        if code in seen_codes:
            raise HTTPException(status_code=400, detail=f"duplicate capability_code: {code}")
        if pair in seen_pairs:
            raise HTTPException(status_code=400, detail=f"duplicate capability mapping: {item.action_type}/{code}")
        seen_codes.add(code)
        seen_pairs.add(pair)


def validate_repro_capability_semantics(request: ServiceRegisterRequest) -> None:
    service_meta = request.meta or {}
    service_module_role = str(service_meta.get("module_role") or "").strip()
    service_bind_stage = str(service_meta.get("bind_stage") or "").strip()
    service_report_channel = str(service_meta.get("report_channel") or "").strip()
    for item in request.capabilities:
        if item.action_type not in REPRO_ACTION_TYPES:
            continue
        capability_meta = item.meta or {}
        module_role = str(capability_meta.get("module_role") or service_module_role).strip()
        bind_stage = str(
            capability_meta.get("bind_stage")
            or capability_meta.get("lifecycle_stage")
            or service_bind_stage
        ).strip()
        report_channel = str(capability_meta.get("report_channel") or service_report_channel).strip()
        allowed_roles = REPRO_MODULE_ROLE_BY_ACTION.get(item.action_type, set())
        allowed_stages = REPRO_BIND_STAGE_BY_ACTION.get(item.action_type, set())

        if module_role and allowed_roles and module_role not in allowed_roles:
            raise HTTPException(
                status_code=400,
                detail=f"action_type {item.action_type} does not support module_role {module_role}",
            )
        if bind_stage and allowed_stages and bind_stage not in allowed_stages:
            raise HTTPException(
                status_code=400,
                detail=f"action_type {item.action_type} does not support bind_stage {bind_stage}",
            )
        if item.action_type == "proof_verification" and bind_stage == "finished" and report_channel and report_channel != "callback":
            raise HTTPException(
                status_code=400,
                detail="finished proof_verification requires callback report_channel",
            )
        if item.action_type == "validation" and service_module_role == "reporter":
            raise HTTPException(
                status_code=400,
                detail="validation action cannot be registered under reporter module_role",
            )


def register_service(db: Session, request: ServiceRegisterRequest) -> ServiceRegistry:
    cfg = get_config()
    ensure_unique_capabilities(request)
    validate_repro_capability_semantics(request)
    service = db.query(ServiceRegistry).filter(ServiceRegistry.service_id == request.service_id).first()
    if service is None:
        if not cfg.service_registry.allow_dynamic_register:
            raise HTTPException(status_code=403, detail="dynamic service register is disabled")
        service = ServiceRegistry(
            id=uuid4().hex,
            service_id=request.service_id,
            service_name=request.service_name,
            service_type=request.service_type,
            endpoint=request.endpoint,
            healthcheck_url=request.healthcheck_url,
            callback_mode=request.callback_mode,
            auth_mode=request.auth_mode,
            version=request.version,
            status=SERVICE_STATUS_ACTIVE,
            meta_json=json.dumps(request.meta, ensure_ascii=False),
        )
        db.add(service)
        db.flush()
    else:
        service.service_name = request.service_name
        service.service_type = request.service_type
        service.endpoint = request.endpoint
        service.healthcheck_url = request.healthcheck_url
        service.callback_mode = request.callback_mode
        service.auth_mode = request.auth_mode
        service.version = request.version
        service.status = SERVICE_STATUS_ACTIVE
        service.meta_json = json.dumps(request.meta, ensure_ascii=False)
        service.last_heartbeat_at = datetime.utcnow()
        db.query(ServiceCapability).filter(ServiceCapability.service_id == service.id).delete()

    for item in request.capabilities:
        db.add(ServiceCapability(
            id=uuid4().hex,
            service_id=service.id,
            capability_code=item.capability_code,
            action_type=item.action_type,
            priority=item.priority,
            timeout_seconds=item.timeout_seconds,
            concurrency_limit=item.concurrency_limit,
            input_schema_meta_json=json.dumps(item.input_schema_meta, ensure_ascii=False),
            output_schema_meta_json=json.dumps(item.output_schema_meta, ensure_ascii=False),
            meta_json=json.dumps(item.meta, ensure_ascii=False),
        ))

    db.commit()
    db.refresh(service)
    return service


def heartbeat_service(db: Session, service_id: str) -> ServiceRegistry | None:
    service = db.query(ServiceRegistry).filter(ServiceRegistry.service_id == service_id).first()
    if service is None:
        return None
    service.last_heartbeat_at = datetime.utcnow()
    service.status = SERVICE_STATUS_ACTIVE
    db.commit()
    db.refresh(service)
    return service


def unregister_service(db: Session, service_id: str) -> ServiceRegistry | None:
    service = db.query(ServiceRegistry).filter(ServiceRegistry.service_id == service_id).first()
    if service is None:
        return None
    meta = json.loads(service.meta_json or "{}")
    meta["unregistered_at"] = datetime.utcnow().isoformat()
    service.meta_json = json.dumps(meta, ensure_ascii=False)
    service.status = SERVICE_STATUS_INACTIVE
    db.commit()
    db.refresh(service)
    return service


def build_repro_service_overview(db: Session) -> dict:
    services = reconcile_service_statuses(db)
    repro_services: list[dict] = []
    coverage = {
        "validation": {"validation": 0, "poc_generation": 0, "exp_generation": 0},
        "finished": {"proof_verification": 0},
    }
    missing_requirements: list[dict[str, str]] = []

    for service in services:
        service_meta = _loads_meta(service.meta_json)
        capabilities: list[dict] = []
        matched_repro = False
        for capability in service.capabilities:
            capability_meta = _loads_meta(capability.meta_json)
            if capability.action_type not in REPRO_ACTION_TYPES:
                continue
            matched_repro = True
            bind_stage = (
                capability_meta.get("bind_stage")
                or capability_meta.get("lifecycle_stage")
                or service_meta.get("bind_stage")
                or "validation"
            )
            module_role = capability_meta.get("module_role") or service_meta.get("module_role")
            report_channel = capability_meta.get("report_channel") or service_meta.get("report_channel")
            capabilities.append(
                {
                    "capability_code": capability.capability_code,
                    "action_type": capability.action_type,
                    "bind_stage": bind_stage,
                    "module_role": module_role,
                    "report_channel": report_channel,
                    "priority": capability.priority,
                    "timeout_seconds": capability.timeout_seconds,
                    "concurrency_limit": capability.concurrency_limit,
                }
            )
            if bind_stage in coverage and capability.action_type in coverage[bind_stage]:
                coverage[bind_stage][capability.action_type] += 1
        if matched_repro:
            repro_services.append(
                {
                    "service_id": service.service_id,
                    "service_name": service.service_name,
                    "service_type": service.service_type,
                    "status": service.status,
                    "endpoint": service.endpoint,
                    "last_heartbeat_at": service.last_heartbeat_at,
                    "meta": service_meta,
                    "capabilities": capabilities,
                }
            )

    for stage, requirements in coverage.items():
        for action_type, count in requirements.items():
            if count == 0:
                missing_requirements.append({"stage": stage, "action_type": action_type})

    return {
        "items": repro_services,
        "total": len(repro_services),
        "coverage": coverage,
        "missing_requirements": missing_requirements,
    }
