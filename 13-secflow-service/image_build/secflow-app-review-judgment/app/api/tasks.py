from __future__ import annotations

import logging
import uuid
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from app.models.database import ReviewJudgmentRun, get_session
from app.schemas import (
    PaginatedResponse,
    ReviewJudgmentRunCreateRequest,
    ReviewJudgmentRunResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/review-judgment", tags=["Review Judgment Runs"])


@router.post("/runs", response_model=ReviewJudgmentRunResponse, status_code=201)
async def create_run(req: ReviewJudgmentRunCreateRequest) -> ReviewJudgmentRunResponse:
    """创建评审研判运行记录"""
    session = get_session()
    try:
        run = ReviewJudgmentRun(
            id=uuid.uuid4().hex,
            project_id=req.project_id,
            run_name=req.run_name or f"review_{uuid.uuid4().hex[:8]}",
            work_dir=req.work_dir,
            session_dir=req.session_dir,
            vuln_report_file=req.vuln_report_file,
            status="pending",
        )
        session.add(run)
        session.commit()
        session.refresh(run)
        return ReviewJudgmentRunResponse.model_validate(run)
    finally:
        session.close()


@router.get("/runs", response_model=PaginatedResponse)
async def list_runs(
    project_id: str = Query(..., min_length=1),
    status: Optional[str] = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> PaginatedResponse:
    """列出评审研判运行记录"""
    session = get_session()
    try:
        q = session.query(ReviewJudgmentRun).filter(ReviewJudgmentRun.project_id == project_id)
        if status:
            q = q.filter(ReviewJudgmentRun.status == status)
        total = q.count()
        items = q.order_by(ReviewJudgmentRun.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
        return PaginatedResponse(
            items=[ReviewJudgmentRunResponse.model_validate(r).model_dump() for r in items],
            total=total,
            page=page,
            page_size=page_size,
        )
    finally:
        session.close()


@router.get("/runs/{run_id}", response_model=ReviewJudgmentRunResponse)
async def get_run(run_id: str) -> ReviewJudgmentRunResponse:
    """获取评审研判运行详情"""
    session = get_session()
    try:
        run = session.query(ReviewJudgmentRun).filter(ReviewJudgmentRun.id == run_id).first()
        if not run:
            raise HTTPException(status_code=404, detail="run not found")
        return ReviewJudgmentRunResponse.model_validate(run)
    finally:
        session.close()


@router.delete("/runs/{run_id}", status_code=204)
async def delete_run(run_id: str) -> None:
    """删除评审研判运行记录"""
    session = get_session()
    try:
        run = session.query(ReviewJudgmentRun).filter(ReviewJudgmentRun.id == run_id).first()
        if not run:
            raise HTTPException(status_code=404, detail="run not found")
        session.delete(run)
        session.commit()
    finally:
        session.close()