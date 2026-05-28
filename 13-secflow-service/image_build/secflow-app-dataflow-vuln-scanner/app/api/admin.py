from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_or_machine_subject, get_db
from app.schemas import SchedulerWorkerResponse, SuccessResponse
from app.services.scheduler import get_scheduler_service

router = APIRouter(prefix="/api/dataflow-vuln-scanner/admin", tags=["Dataflow Vuln Scanner Admin"])


@router.get("/scheduler/workers", response_model=List[SchedulerWorkerResponse])
async def list_workers(subject=Depends(get_current_or_machine_subject), db: Session = Depends(get_db)):
    return get_scheduler_service().list_workers(db)


@router.get("/scheduler/workers/{pod_id}", response_model=SchedulerWorkerResponse)
async def get_worker(pod_id: str, subject=Depends(get_current_or_machine_subject), db: Session = Depends(get_db)):
    return get_scheduler_service().get_worker(db, pod_id)


@router.post("/scheduler/workers/{pod_id}/drain", response_model=SuccessResponse)
async def drain_worker(pod_id: str, subject=Depends(get_current_or_machine_subject), db: Session = Depends(get_db)):
    get_scheduler_service().set_worker_status(db, pod_id, "draining")
    return SuccessResponse(message=f"worker {pod_id} set to draining")


@router.post("/scheduler/workers/{pod_id}/activate", response_model=SuccessResponse)
async def activate_worker(pod_id: str, subject=Depends(get_current_or_machine_subject), db: Session = Depends(get_db)):
    get_scheduler_service().set_worker_status(db, pod_id, "active")
    return SuccessResponse(message=f"worker {pod_id} activated")
