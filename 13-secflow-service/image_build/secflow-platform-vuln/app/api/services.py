"""Service registry endpoints."""

import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_subject
from app.models.database import ServiceRegistry, get_db
from app.schemas import ServiceRegisterRequest
from app.services.service_registry import heartbeat_service, register_service

router = APIRouter(prefix="/api/vuln/services", tags=["services"])


def _to_response(service: ServiceRegistry) -> dict:
    return {
        "service_id": service.service_id,
        "service_name": service.service_name,
        "service_type": service.service_type,
        "endpoint": service.endpoint,
        "status": service.status,
        "version": service.version,
        "last_heartbeat_at": service.last_heartbeat_at,
        "capabilities": [
            {
                "capability_code": item.capability_code,
                "action_type": item.action_type,
                "priority": item.priority,
                "timeout_seconds": item.timeout_seconds,
                "concurrency_limit": item.concurrency_limit,
                "input_schema_meta": json.loads(item.input_schema_meta_json or "{}"),
                "output_schema_meta": json.loads(item.output_schema_meta_json or "{}"),
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
    service = db.query(ServiceRegistry).filter(ServiceRegistry.service_id == service_id).first()
    if service is None:
        raise HTTPException(status_code=404, detail="service not found")
    db.delete(service)
    db.commit()
    return {"status": "ok", "service_id": service_id}


@router.get("")
async def list_services(_: tuple[dict, str] = Depends(get_current_subject), db: Session = Depends(get_db)):
    services = db.query(ServiceRegistry).order_by(ServiceRegistry.updated_at.desc()).all()
    return {"items": [_to_response(service) for service in services], "total": len(services)}


@router.get("/{service_id}")
async def get_service(service_id: str, _: tuple[dict, str] = Depends(get_current_subject), db: Session = Depends(get_db)):
    service = db.query(ServiceRegistry).filter(ServiceRegistry.service_id == service_id).first()
    if service is None:
        raise HTTPException(status_code=404, detail="service not found")
    return _to_response(service)
