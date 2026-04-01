"""Report query service."""

from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from app.exception import NotFoundError
from app.model import SystemAnalysisReport
from app.schemas import AnalysisReportResponse


class ReportService:
    def get_report(self, db: Session, task_id: str) -> AnalysisReportResponse:
        row = db.query(SystemAnalysisReport).filter(SystemAnalysisReport.task_id == task_id).first()
        if not row:
            raise NotFoundError("分析报告", task_id)
        return AnalysisReportResponse(
            report_id=row.report_id,
            task_id=row.task_id,
            project_id=row.project_id,
            risk_level=row.risk_level,
            summary_markdown=row.summary_markdown or "",
            summary_json=row.summary_json or {},
            generated_at=row.generated_at,
        )


_report_service: Optional[ReportService] = None


def get_report_service() -> ReportService:
    global _report_service
    if _report_service is None:
        _report_service = ReportService()
    return _report_service

