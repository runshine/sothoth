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


def register_service(db: Session, request: ServiceRegisterRequest) -> ServiceRegistry:
    cfg = get_config()
    ensure_unique_capabilities(request)
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
