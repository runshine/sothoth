"""Capability service registry manager."""

import json
from datetime import datetime
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models.database import ServiceCapability, ServiceRegistry
from app.schemas import ServiceRegisterRequest


def register_service(db: Session, request: ServiceRegisterRequest) -> ServiceRegistry:
    service = db.query(ServiceRegistry).filter(ServiceRegistry.service_id == request.service_id).first()
    if service is None:
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
            status="active",
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
        service.status = "active"
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
    service.status = "active"
    db.commit()
    db.refresh(service)
    return service
