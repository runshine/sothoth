from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from app.api.dependencies import get_machine_subject
from app.services.scheduler import get_scheduler_service

router = APIRouter(prefix="/api/v1/jobs", tags=["Dataflow Worker Jobs"])


@router.get("")
async def list_jobs(_subject=Depends(get_machine_subject)) -> dict[str, list[dict[str, Any]]]:
    return {"jobs": get_scheduler_service().list_local_jobs()}


@router.post("")
async def create_job(payload: dict[str, Any], _subject=Depends(get_machine_subject)) -> dict[str, Any]:
    return get_scheduler_service().create_local_job(payload)


@router.post("/drain")
async def drain_jobs(payload: dict[str, Any] | None = None, _subject=Depends(get_machine_subject)) -> dict[str, Any]:
    payload = payload or {}
    return get_scheduler_service().drain_local_jobs(
        reason=str(payload.get("reason") or "worker draining"),
        wait_seconds=int(payload.get("wait_seconds") or 45),
    )


@router.get("/{job_id}")
async def get_job(job_id: str, _subject=Depends(get_machine_subject)) -> dict[str, Any]:
    job = get_scheduler_service().get_local_job(job_id)
    if job is None:
        from fastapi import HTTPException, status

        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="job not found")
    return job


@router.post("/{job_id}/cancel")
async def cancel_job(job_id: str, _subject=Depends(get_machine_subject)) -> dict[str, Any]:
    return get_scheduler_service().cancel_local_job(job_id)
