from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    service: Optional[str] = None
    service_id: Optional[str] = None
    service_name: Optional[str] = None
    build_version: Optional[str] = None
    started_at: Optional[float] = None
    updated_at: Optional[float] = None
    shutting_down: bool = False
    startup_phase: str = "booting"
    last_error: Optional[str] = None
    reason: Optional[str] = None
    liveness_ok: bool = False
    readiness_ok: bool = False
    checks: Dict[str, Any] = Field(default_factory=dict)


class SuccessResponse(BaseModel):
    message: str = "ok"


class ReviewJudgmentRunResponse(BaseModel):
    id: str
    project_id: str
    run_name: str
    work_dir: str
    session_dir: str
    vuln_report_file: str
    status: str
    verdict: Optional[str]
    severity: Optional[str]
    confidence: Optional[str]
    result_json: Optional[str]
    error_message: Optional[str]
    created_by: Optional[str]
    created_at: datetime
    updated_at: datetime


class ReviewJudgmentRunCreateRequest(BaseModel):
    project_id: str = Field(..., min_length=1)
    run_name: Optional[str] = None
    work_dir: str = Field(..., min_length=1)
    session_dir: str = Field(..., min_length=1)
    vuln_report_file: str = Field(..., min_length=1)
    model: Optional[str] = None


class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    page_size: int