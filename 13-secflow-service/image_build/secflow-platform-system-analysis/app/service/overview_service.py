"""Overview service."""

from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from app.model import SystemAnalysisTask, SystemAnalysisTaskNode
from app.schemas import AnalysisOverviewResponse, OverviewRiskSummary, OverviewTaskSummary, RecentFindingItem
from app.service.capability_service import CapabilityService, get_capability_service


class OverviewService:
    def __init__(self, capability_service: Optional[CapabilityService] = None):
        self.capability_service = capability_service or get_capability_service()

    async def get_overview(self, db: Session, project_id: str, token: Optional[str] = None) -> AnalysisOverviewResponse:
        capabilities = await self.capability_service.list_capabilities(project_id, token=token)

        total_tasks = (
            db.query(SystemAnalysisTask)
            .filter(SystemAnalysisTask.project_id == project_id, SystemAnalysisTask.is_deleted.is_(False))
            .count()
        )
        last_task = (
            db.query(SystemAnalysisTask)
            .filter(SystemAnalysisTask.project_id == project_id, SystemAnalysisTask.is_deleted.is_(False))
            .order_by(SystemAnalysisTask.created_at.desc())
            .first()
        )
        task_summary = OverviewTaskSummary(
            total_tasks=total_tasks,
            last_task_id=last_task.task_id if last_task else None,
            last_task_status=last_task.status if last_task else None,
            last_task_at=last_task.created_at if last_task else None,
        )

        risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        risk_rows = (
            db.query(SystemAnalysisTaskNode)
            .filter(SystemAnalysisTaskNode.project_id == project_id)
            .order_by(SystemAnalysisTaskNode.updated_at.desc())
            .limit(1000)
            .all()
        )
        for row in risk_rows:
            risk = str(row.risk_level or "unknown")
            if risk in risk_counts:
                risk_counts[risk] += 1

        recent_rows = (
            db.query(SystemAnalysisTaskNode)
            .filter(SystemAnalysisTaskNode.project_id == project_id)
            .order_by(SystemAnalysisTaskNode.updated_at.desc())
            .limit(10)
            .all()
        )
        recent_findings = [
            RecentFindingItem(
                task_id=row.task_id,
                agent_key=row.agent_key,
                risk_level=row.risk_level,
                summary=row.result_summary or (row.error_message or "-"),
            )
            for row in recent_rows
        ]

        return AnalysisOverviewResponse(
            project_id=project_id,
            node_summary=capabilities.summary,
            task_summary=task_summary,
            risk_summary=OverviewRiskSummary(**risk_counts),
            recent_findings=recent_findings,
        )


_overview_service: Optional[OverviewService] = None


def get_overview_service() -> OverviewService:
    global _overview_service
    if _overview_service is None:
        _overview_service = OverviewService()
    return _overview_service

