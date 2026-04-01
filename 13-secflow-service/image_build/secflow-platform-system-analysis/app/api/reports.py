"""Report endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import ensure_project_access, get_current_user
from app.model import get_db
from app.schemas import AnalysisReportResponse
from app.service.task_service import get_task_service
from app.service.report_service import get_report_service

router = APIRouter(prefix="/tasks")


@router.get("/{task_id}/report", response_model=AnalysisReportResponse)
async def get_task_report(
    task_id: str,
    user_and_token=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _user, token = user_and_token
    detail = get_task_service().get_task(db, task_id)
    await ensure_project_access(detail.project_id, token)
    return get_report_service().get_report(db, task_id)
