from __future__ import annotations

from fastapi import APIRouter, Depends, Header
from sqlalchemy.orm import Session

from app.model import get_db
from app.schemas import EvolutionConfigPayload, EvolutionConfigResponse
from app.service.auth import get_auth_service
from app.service.task_service import get_task_service

router = APIRouter(prefix="/api/app/binary-evolution", tags=["binary-evolution-config"])


async def get_subject(authorization: str | None = Header(default=None)):
    return await get_auth_service().validate_human_authorization(authorization)


@router.get("/config", response_model=EvolutionConfigResponse)
async def get_config(subject=Depends(get_subject), db: Session = Depends(get_db)):
    _ = subject
    return get_task_service().get_service_config(db)


@router.put("/config", response_model=EvolutionConfigResponse)
async def update_config(payload: EvolutionConfigPayload, subject=Depends(get_subject), db: Session = Depends(get_db)):
    _ = subject
    return get_task_service().save_service_config(db, payload)
