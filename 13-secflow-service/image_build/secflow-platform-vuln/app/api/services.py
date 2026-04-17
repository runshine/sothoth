"""Service registry endpoints."""

import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_subject
from app.models.database import ServiceRegistry, get_db
from app.schemas import ServiceRegisterRequest
from app.services.service_registry import (
    build_repro_service_overview,
    heartbeat_service,
    reconcile_service_statuses,
    register_service,
    unregister_service,
)

router = APIRouter(prefix="/api/vuln/services", tags=["services"])


def _safe_json_loads(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return {"_raw": raw, "_decode_error": True}
    return value if isinstance(value, dict) else {"value": value}


def _to_response(service: ServiceRegistry) -> dict:
    return {
        "service_id": service.service_id,
        "service_name": service.service_name,
        "service_type": service.service_type,
        "endpoint": service.endpoint,
        "healthcheck_url": service.healthcheck_url,
        "callback_mode": service.callback_mode,
        "auth_mode": service.auth_mode,
        "status": service.status,
        "version": service.version,
        "last_heartbeat_at": service.last_heartbeat_at,
        "meta": _safe_json_loads(service.meta_json),
        "capabilities": [
            {
                "capability_code": item.capability_code,
                "action_type": item.action_type,
                "priority": item.priority,
                "timeout_seconds": item.timeout_seconds,
                "concurrency_limit": item.concurrency_limit,
                "input_schema_meta": _safe_json_loads(item.input_schema_meta_json),
                "output_schema_meta": _safe_json_loads(item.output_schema_meta_json),
                "meta": _safe_json_loads(item.meta_json),
            }
            for item in service.capabilities
        ],
    }


@router.post("/register")
async def register(
    request: ServiceRegisterRequest,
    _: tuple[dict, str] = Depends(get_current_subject),
    db: Session = Depends(get_db),
):
    service = register_service(db, request)
    return {"status": "registered", "service": _to_response(service)}


@router.post("/heartbeat/{service_id}")
async def heartbeat(service_id: str, _: tuple[dict, str] = Depends(get_current_subject), db: Session = Depends(get_db)):
    service = heartbeat_service(db, service_id)
    if service is None:
        raise HTTPException(status_code=404, detail="service not found")
    return {"status": "ok", "service_id": service.service_id, "heartbeat_at": service.last_heartbeat_at}


@router.delete("/unregister/{service_id}")
async def unregister(service_id: str, _: tuple[dict, str] = Depends(get_current_subject), db: Session = Depends(get_db)):
    service = unregister_service(db, service_id)
    if service is None:
        raise HTTPException(status_code=404, detail="service not found")
    return {"status": "ok", "service_id": service_id, "service_status": service.status}


@router.get("")
async def list_services(_: tuple[dict, str] = Depends(get_current_subject), db: Session = Depends(get_db)):
    reconcile_service_statuses(db)
    services = db.query(ServiceRegistry).order_by(ServiceRegistry.updated_at.desc()).all()
    return {"items": [_to_response(service) for service in services], "total": len(services)}


@router.get("/repro/overview")
async def get_repro_service_overview(_: tuple[dict, str] = Depends(get_current_subject), db: Session = Depends(get_db)):
    return build_repro_service_overview(db)


@router.get("/{service_id}")
async def get_service(service_id: str, _: tuple[dict, str] = Depends(get_current_subject), db: Session = Depends(get_db)):
    reconcile_service_statuses(db, service_id=service_id)
    service = db.query(ServiceRegistry).filter(ServiceRegistry.service_id == service_id).first()
    if service is None:
        raise HTTPException(status_code=404, detail="service not found")
    return _to_response(service)
