"""Task orchestration service."""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.config import get_config
from app.exception import NotFoundError, ValidationError
from app.model import SystemAnalysisAuditLog, SystemAnalysisReport, SystemAnalysisTask, SystemAnalysisTaskNode
from app.schemas import (
    AnalysisTaskCreateRequest,
    AnalysisTaskDetailResponse,
    AnalysisTaskListItem,
    AnalysisTaskListResponse,
    AnalysisTaskNodeDetailResponse,
    AnalysisTaskNodeListItem,
    AnalysisTaskNodeListResponse,
    AnalysisTaskResponse,
)
from app.service.agent_gateway import AgentGatewayError, get_agent_gateway
from app.service.capability_service import get_capability_service


class TaskService:
    def __init__(self):
        self.cfg = get_config().service
        self.agent_gateway = get_agent_gateway()
        self.capability_service = get_capability_service()
        self._running_tasks: Dict[str, asyncio.Task] = {}

    async def create_task(self, db: Session, payload: AnalysisTaskCreateRequest, username: str, token: str) -> AnalysisTaskResponse:
        timeout_seconds = min(max(payload.execution_config.timeout_seconds, 30), self.cfg.max_timeout_seconds)
        max_concurrency = min(max(payload.execution_config.max_concurrency, 1), self.cfg.max_concurrency_limit)

        capabilities = await self.capability_service.list_capabilities(payload.project_id, token=token)
        cap_map = {item.agent_key: item for item in capabilities.items}

        task_id = f"sat_{uuid.uuid4().hex[:16]}"
        now = datetime.utcnow()

        task_row = SystemAnalysisTask(
            task_id=task_id,
            project_id=payload.project_id,
            task_name=payload.task_name,
            analysis_type=payload.analysis_type,
            prompt_template_id=payload.prompt_template_id,
            prompt_content=payload.prompt_content,
            status="pending",
            risk_level="unknown",
            total_nodes=len(payload.targets),
            success_nodes=0,
            failed_nodes=0,
            running_nodes=0,
            cancelled_nodes=0,
            execution_config_json={"timeout_seconds": timeout_seconds, "max_concurrency": max_concurrency},
            summary_json={},
            created_by=username,
            created_at=now,
            updated_at=now,
        )
        db.add(task_row)

        for target in payload.targets:
            cap = cap_map.get(target.agent_key)
            if cap is None:
                raise ValidationError(f"节点不存在: {target.agent_key}")
            if not cap.helper_installed or not cap.helper_service_name:
                raise ValidationError(f"节点未部署AI helper: {target.agent_key}")

            agent_ids = {opt.agent_id for opt in cap.available_ai_agents}
            if target.ai_agent_id not in agent_ids:
                raise ValidationError(f"节点 {target.agent_key} 上无AI Agent: {target.ai_agent_id}")

            db.add(
                SystemAnalysisTaskNode(
                    task_id=task_id,
                    project_id=payload.project_id,
                    agent_key=target.agent_key,
                    agent_hostname=cap.agent_hostname,
                    agent_ip=cap.agent_ip,
                    helper_service_name=cap.helper_service_name,
                    ai_agent_id=target.ai_agent_id,
                    status="pending",
                    risk_level="unknown",
                )
            )

        self._append_audit_log(
            db,
            project_id=payload.project_id,
            task_id=task_id,
            action="task_create",
            operator=username,
            request_payload=payload.model_dump(),
            response_payload={"task_id": task_id},
        )
        db.commit()

        self._start_background_execution(task_id, token)
        return AnalysisTaskResponse(task_id=task_id, status="pending")

    def list_tasks(
        self,
        db: Session,
        *,
        project_id: str,
        page: int = 1,
        per_page: int = 20,
        status: Optional[str] = None,
        analysis_type: Optional[str] = None,
        created_by: Optional[str] = None,
        risk_level: Optional[str] = None,
    ) -> AnalysisTaskListResponse:
        query = db.query(SystemAnalysisTask).filter(
            SystemAnalysisTask.project_id == project_id,
            SystemAnalysisTask.is_deleted.is_(False),
        )
        if status:
            query = query.filter(SystemAnalysisTask.status == status)
        if analysis_type:
            query = query.filter(SystemAnalysisTask.analysis_type == analysis_type)
        if created_by:
            query = query.filter(SystemAnalysisTask.created_by == created_by)
        if risk_level:
            query = query.filter(SystemAnalysisTask.risk_level == risk_level)

        total = query.count()
        rows = (
            query.order_by(SystemAnalysisTask.created_at.desc())
            .offset((page - 1) * per_page)
            .limit(per_page)
            .all()
        )
        items = [
            AnalysisTaskListItem(
                task_id=row.task_id,
                project_id=row.project_id,
                task_name=row.task_name,
                analysis_type=row.analysis_type,
                status=row.status,
                risk_level=row.risk_level,
                total_nodes=row.total_nodes,
                success_nodes=row.success_nodes,
                failed_nodes=row.failed_nodes,
                created_by=row.created_by,
                created_at=row.created_at,
                finished_at=row.finished_at,
            )
            for row in rows
        ]
        return AnalysisTaskListResponse(items=items, page=page, per_page=per_page, total=total)

    def get_task(self, db: Session, task_id: str) -> AnalysisTaskDetailResponse:
        row = self._get_task_row(db, task_id)
        return AnalysisTaskDetailResponse(
            task_id=row.task_id,
            project_id=row.project_id,
            task_name=row.task_name,
            analysis_type=row.analysis_type,
            prompt_template_id=row.prompt_template_id,
            prompt_content=row.prompt_content,
            status=row.status,
            risk_level=row.risk_level,
            total_nodes=row.total_nodes,
            success_nodes=row.success_nodes,
            failed_nodes=row.failed_nodes,
            running_nodes=row.running_nodes,
            cancelled_nodes=row.cancelled_nodes,
            execution_config=row.execution_config_json or {},
            summary_json=row.summary_json or {},
            created_by=row.created_by,
            created_at=row.created_at,
            started_at=row.started_at,
            finished_at=row.finished_at,
        )

    def list_task_nodes(self, db: Session, task_id: str) -> AnalysisTaskNodeListResponse:
        self._get_task_row(db, task_id)
        rows = (
            db.query(SystemAnalysisTaskNode)
            .filter(SystemAnalysisTaskNode.task_id == task_id)
            .order_by(SystemAnalysisTaskNode.agent_key.asc())
            .all()
        )
        items = [
            AnalysisTaskNodeListItem(
                agent_key=row.agent_key,
                agent_hostname=row.agent_hostname,
                agent_ip=row.agent_ip,
                helper_service_name=row.helper_service_name,
                helper_session_id=row.helper_session_id,
                ai_agent_id=row.ai_agent_id,
                status=row.status,
                risk_level=row.risk_level,
                result_summary=row.result_summary,
                error_message=row.error_message,
                started_at=row.started_at,
                finished_at=row.finished_at,
            )
            for row in rows
        ]
        return AnalysisTaskNodeListResponse(task_id=task_id, items=items, total=len(items))

    def get_task_node(self, db: Session, task_id: str, agent_key: str) -> AnalysisTaskNodeDetailResponse:
        row = (
            db.query(SystemAnalysisTaskNode)
            .filter(SystemAnalysisTaskNode.task_id == task_id, SystemAnalysisTaskNode.agent_key == agent_key)
            .first()
        )
        if not row:
            raise NotFoundError("任务节点", f"{task_id}:{agent_key}")
        return AnalysisTaskNodeDetailResponse(
            task_id=task_id,
            agent_key=row.agent_key,
            agent_hostname=row.agent_hostname,
            agent_ip=row.agent_ip,
            helper_service_name=row.helper_service_name,
            helper_session_id=row.helper_session_id,
            ai_agent_id=row.ai_agent_id,
            status=row.status,
            risk_level=row.risk_level,
            result_summary=row.result_summary,
            normalized_result_json=row.normalized_result_json or {},
            raw_response_json=row.raw_response_json or {},
            error_message=row.error_message,
            started_at=row.started_at,
            finished_at=row.finished_at,
        )

    async def rerun_task(self, db: Session, task_id: str, username: str, token: str) -> AnalysisTaskResponse:
        old = self._get_task_row(db, task_id)
        nodes = db.query(SystemAnalysisTaskNode).filter(SystemAnalysisTaskNode.task_id == task_id).all()
        targets = [{"agent_key": n.agent_key, "ai_agent_id": n.ai_agent_id} for n in nodes]
        payload = AnalysisTaskCreateRequest(
            project_id=old.project_id,
            task_name=f"{old.task_name}-rerun",
            analysis_type=old.analysis_type,
            prompt_template_id=old.prompt_template_id,
            prompt_content=old.prompt_content,
            execution_config=old.execution_config_json or {},
            targets=targets,
        )
        return await self.create_task(db, payload, username, token)

    def cancel_task(self, db: Session, task_id: str, username: str) -> AnalysisTaskResponse:
        row = self._get_task_row(db, task_id)
        if row.status in {"success", "failed", "partial_success", "cancelled"}:
            return AnalysisTaskResponse(task_id=task_id, status=row.status)

        row.status = "cancelled"
        row.finished_at = datetime.utcnow()
        row.updated_at = datetime.utcnow()
        db.add(row)

        node_rows = db.query(SystemAnalysisTaskNode).filter(SystemAnalysisTaskNode.task_id == task_id).all()
        for node in node_rows:
            if node.status not in {"success", "failed", "cancelled"}:
                node.status = "cancelled"
                node.finished_at = datetime.utcnow()
                db.add(node)

        self._append_audit_log(
            db,
            project_id=row.project_id,
            task_id=task_id,
            action="task_cancel",
            operator=username,
            request_payload={},
            response_payload={"status": "cancelled"},
        )
        db.commit()

        task = self._running_tasks.get(task_id)
        if task and not task.done():
            task.cancel()
        return AnalysisTaskResponse(task_id=task_id, status="cancelled")

    def retry_node(self, db: Session, task_id: str, agent_key: str, username: str) -> AnalysisTaskResponse:
        task_row = self._get_task_row(db, task_id)
        node = (
            db.query(SystemAnalysisTaskNode)
            .filter(SystemAnalysisTaskNode.task_id == task_id, SystemAnalysisTaskNode.agent_key == agent_key)
            .first()
        )
        if not node:
            raise NotFoundError("任务节点", f"{task_id}:{agent_key}")

        node.status = "pending"
        node.error_message = None
        node.raw_response_json = None
        node.normalized_result_json = None
        node.result_summary = None
        node.risk_level = "unknown"
        node.started_at = None
        node.finished_at = None
        node.retry_count = int(node.retry_count or 0) + 1
        db.add(node)

        if task_row.status in {"success", "failed", "partial_success", "cancelled"}:
            task_row.status = "running"
            task_row.finished_at = None
            db.add(task_row)

        self._append_audit_log(
            db,
            project_id=task_row.project_id,
            task_id=task_id,
            action="task_retry_node",
            operator=username,
            request_payload={"agent_key": agent_key},
            response_payload={"status": "pending"},
        )
        db.commit()
        return AnalysisTaskResponse(task_id=task_id, status=task_row.status)

    def get_report_row(self, db: Session, task_id: str) -> Optional[SystemAnalysisReport]:
        return db.query(SystemAnalysisReport).filter(SystemAnalysisReport.task_id == task_id).first()

    def _get_task_row(self, db: Session, task_id: str) -> SystemAnalysisTask:
        row = (
            db.query(SystemAnalysisTask)
            .filter(SystemAnalysisTask.task_id == task_id, SystemAnalysisTask.is_deleted.is_(False))
            .first()
        )
        if not row:
            raise NotFoundError("任务", task_id)
        return row

    def _append_audit_log(
        self,
        db: Session,
        *,
        project_id: Optional[str],
        task_id: Optional[str],
        action: str,
        operator: Optional[str],
        request_payload: Dict[str, Any],
        response_payload: Dict[str, Any],
    ) -> None:
        db.add(
            SystemAnalysisAuditLog(
                project_id=project_id,
                task_id=task_id,
                action=action,
                operator=operator,
                request_json=request_payload,
                response_json=response_payload,
            )
        )

    def _start_background_execution(self, task_id: str, token: str):
        async def _runner():
            await self._execute_task(task_id, token)

        task = asyncio.create_task(_runner())
        self._running_tasks[task_id] = task

        def _cleanup(_: asyncio.Task):
            self._running_tasks.pop(task_id, None)

        task.add_done_callback(_cleanup)

    async def _execute_task(self, task_id: str, token: str):
        from app.model import get_db_session

        db = get_db_session()
        try:
            task_row = self._get_task_row(db, task_id)
            if task_row.status == "cancelled":
                return

            task_row.status = "preparing"
            task_row.started_at = task_row.started_at or datetime.utcnow()
            task_row.updated_at = datetime.utcnow()
            db.add(task_row)
            db.commit()

            node_rows = db.query(SystemAnalysisTaskNode).filter(SystemAnalysisTaskNode.task_id == task_id).all()
            task_row.status = "running"
            task_row.running_nodes = len(node_rows)
            db.add(task_row)
            db.commit()

            max_concurrency = int((task_row.execution_config_json or {}).get("max_concurrency") or 5)
            semaphore = asyncio.Semaphore(max(1, max_concurrency))

            async def _run_node(node_id: int):
                async with semaphore:
                    await self._execute_node(task_id, node_id, token)

            await asyncio.gather(*[_run_node(n.id) for n in node_rows], return_exceptions=True)
            await self._finalize_task(task_id)
        finally:
            db.close()

    async def _execute_node(self, task_id: str, node_id: int, token: str):
        from app.model import get_db_session

        db = get_db_session()
        try:
            task_row = self._get_task_row(db, task_id)
            if task_row.status == "cancelled":
                return

            node = db.query(SystemAnalysisTaskNode).filter(SystemAnalysisTaskNode.id == node_id).first()
            if not node:
                return

            node.status = "session_creating"
            node.started_at = node.started_at or datetime.utcnow()
            node.updated_at = datetime.utcnow()
            db.add(node)
            db.commit()

            session_id = None
            try:
                session_payload = await self.agent_gateway.create_helper_session(
                    node.project_id,
                    node.agent_key,
                    node.helper_service_name,
                    node.ai_agent_id,
                    token=token,
                )
                session_id = str(session_payload.get("session_id") or "").strip()
                if not session_id:
                    raise AgentGatewayError(f"missing session_id: {session_payload}")

                node.helper_session_id = session_id
                node.status = "analyzing"
                db.add(node)
                db.commit()

                response = await self.agent_gateway.send_session_message(
                    node.project_id,
                    node.agent_key,
                    node.helper_service_name,
                    session_id,
                    task_row.prompt_content,
                    token=token,
                )

                normalized, summary, risk_level = self._normalize_response(response)
                node.raw_response_json = response
                node.normalized_result_json = normalized
                node.result_summary = summary
                node.risk_level = risk_level
                node.status = "success"
                node.error_message = None
                node.finished_at = datetime.utcnow()
                node.updated_at = datetime.utcnow()
                db.add(node)
                db.commit()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                node.status = "failed"
                node.error_message = str(exc)
                node.finished_at = datetime.utcnow()
                node.updated_at = datetime.utcnow()
                db.add(node)
                db.commit()
            finally:
                if session_id:
                    try:
                        await self.agent_gateway.delete_session(
                            node.project_id,
                            node.agent_key,
                            node.helper_service_name,
                            session_id,
                            token=token,
                        )
                    except Exception:
                        pass
        finally:
            db.close()

    async def _finalize_task(self, task_id: str):
        from app.model import get_db_session

        db = get_db_session()
        try:
            task_row = self._get_task_row(db, task_id)
            nodes = db.query(SystemAnalysisTaskNode).filter(SystemAnalysisTaskNode.task_id == task_id).all()
            total = len(nodes)
            success = sum(1 for n in nodes if n.status == "success")
            failed = sum(1 for n in nodes if n.status == "failed")
            cancelled = sum(1 for n in nodes if n.status == "cancelled")
            running = sum(1 for n in nodes if n.status in {"pending", "session_creating", "session_created", "analyzing"})

            if task_row.status == "cancelled":
                final_status = "cancelled"
            elif success == total and total > 0:
                final_status = "success"
            elif success > 0 and failed > 0:
                final_status = "partial_success"
            elif failed == total and total > 0:
                final_status = "failed"
            elif cancelled == total and total > 0:
                final_status = "cancelled"
            else:
                final_status = "partial_success" if success > 0 else "failed"

            risk_level = self._aggregate_risk_level([n.risk_level for n in nodes])
            summary_json = {
                "summary": self._build_summary_text(total, success, failed, cancelled),
                "node_counts": {
                    "total": total,
                    "success": success,
                    "failed": failed,
                    "cancelled": cancelled,
                },
            }
            summary_markdown = self._build_report_markdown(task_row, nodes, summary_json)

            task_row.status = final_status
            task_row.risk_level = risk_level
            task_row.total_nodes = total
            task_row.success_nodes = success
            task_row.failed_nodes = failed
            task_row.running_nodes = running
            task_row.cancelled_nodes = cancelled
            task_row.summary_json = summary_json
            task_row.finished_at = datetime.utcnow()
            task_row.updated_at = datetime.utcnow()
            db.add(task_row)

            report = db.query(SystemAnalysisReport).filter(SystemAnalysisReport.task_id == task_id).first()
            if report is None:
                report = SystemAnalysisReport(
                    report_id=f"sar_{uuid.uuid4().hex[:16]}",
                    task_id=task_id,
                    project_id=task_row.project_id,
                    summary_markdown=summary_markdown,
                    summary_json=summary_json,
                    risk_level=risk_level,
                )
            else:
                report.summary_markdown = summary_markdown
                report.summary_json = summary_json
                report.risk_level = risk_level
            db.add(report)
            db.commit()
        finally:
            db.close()

    @staticmethod
    def _normalize_response(response: Dict[str, Any]) -> Tuple[Dict[str, Any], str, str]:
        if not isinstance(response, dict):
            return {"raw": response}, str(response), "unknown"

        response_text = ""
        if isinstance(response.get("response"), dict):
            response_text = str(response["response"].get("content") or "")
        if not response_text:
            response_text = str(response.get("content") or response.get("message") or json.dumps(response, ensure_ascii=False))

        lowered = response_text.lower()
        if "critical" in lowered or "高危" in response_text:
            risk = "critical"
        elif "high" in lowered or "中高" in response_text or "高风险" in response_text:
            risk = "high"
        elif "medium" in lowered or "中风险" in response_text:
            risk = "medium"
        elif "low" in lowered or "低风险" in response_text:
            risk = "low"
        else:
            risk = "unknown"

        normalized = {
            "overall_status": "ok" if risk in {"unknown", "low"} else "warning",
            "risk_level": risk,
            "summary": response_text[:1000],
            "raw": response,
        }
        summary = response_text[:280] if response_text else "分析完成"
        return normalized, summary, risk

    @staticmethod
    def _aggregate_risk_level(values: List[str]) -> str:
        order = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        return max(values or ["unknown"], key=lambda x: order.get(x or "unknown", 0))

    @staticmethod
    def _build_summary_text(total: int, success: int, failed: int, cancelled: int) -> str:
        return f"任务共 {total} 个节点，成功 {success}，失败 {failed}，取消 {cancelled}。"

    @staticmethod
    def _build_report_markdown(task_row: SystemAnalysisTask, nodes: List[SystemAnalysisTaskNode], summary_json: Dict[str, Any]) -> str:
        lines = [
            f"# 系统分析报告 - {task_row.task_name}",
            "",
            f"- 任务ID: `{task_row.task_id}`",
            f"- 项目ID: `{task_row.project_id}`",
            f"- 分析类型: `{task_row.analysis_type}`",
            f"- 任务状态: `{task_row.status}`",
            f"- 风险等级: `{task_row.risk_level}`",
            "",
            "## 执行摘要",
            "",
            summary_json.get("summary") or "",
            "",
            "## 节点结果",
            "",
        ]
        for node in nodes:
            lines.append(
                f"- `{node.agent_key}` / `{node.ai_agent_id}`: status={node.status}, risk={node.risk_level}, summary={node.result_summary or '-'}"
            )
        return "\n".join(lines)


_task_service: Optional[TaskService] = None


def get_task_service() -> TaskService:
    global _task_service
    if _task_service is None:
        _task_service = TaskService()
    return _task_service

