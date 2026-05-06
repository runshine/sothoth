"""Binary Security task orchestration manager."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.config import get_config
from app.exception import NotFoundError, ValidationError
from app.model import (
    STAGE_SEQUENCE,
    BinarySecurityEvent,
    BinarySecurityProjectConfig,
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityTask,
    get_session_factory,
)
from app.schemas import (
    BinarySecurityArtifactsResponse,
    BinarySecurityProjectConfigPayload,
    BinarySecurityProjectConfigResponse,
    BinarySecurityTaskCreate,
    BinarySecurityTaskDetailResponse,
    BinarySecurityTaskEventResponse,
    BinarySecurityTaskListResponse,
    BinarySecurityTaskResponse,
    BinarySecurityTimelineResponse,
    BinarySecurityStageSummary,
    BinarySecurityStageItemResponse,
)
from app.service.binary_to_source import get_binary_to_source_client
from app.service.dataflow_analyse import get_dataflow_analyse_client
from app.service.dataflow_vuln_scanner import get_dataflow_vuln_scanner_client
from app.service.entry_analyse import get_entry_analyse_client
from app.service.fileserver import get_fileserver_client
from app.service.firmware_unpacker import get_firmware_unpacker_client
from app.service.security import app_task_root, ensure_dir, ensure_path_in_project, validate_task_id
from app.service.system_analyse import get_system_analyse_client


def _now() -> datetime:
    return datetime.utcnow()


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value or "").strip("-")
    return cleaned[:120] or uuid.uuid4().hex[:12]


def _read_text(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


def _copytree(src: Path, dst: Path) -> None:
    if not src.exists():
        return
    if src.is_file():
        ensure_dir(dst.parent)
        shutil.copy2(src, dst)
        return
    shutil.copytree(src, dst, dirs_exist_ok=True)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


class TaskManager:
    def __init__(self) -> None:
        self.cfg = get_config()
        self._running = False
        self._loop_task: Optional[asyncio.Task] = None
        self._workers: dict[str, asyncio.Task] = {}
        self._worker_lock = asyncio.Lock()

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._loop_task = asyncio.create_task(self._dispatch_loop(), name="binary-security-dispatcher")

    async def stop(self) -> None:
        self._running = False
        if self._loop_task:
            self._loop_task.cancel()
            try:
                await self._loop_task
            except asyncio.CancelledError:
                pass
        active = list(self._workers.values())
        for task in active:
            task.cancel()
        if active:
            await asyncio.gather(*active, return_exceptions=True)

    def prepare_task_id(self, db: Session, project_id: str) -> str:
        for _ in range(10):
            task_id = uuid.uuid4().hex[:16]
            exists = db.query(BinarySecurityTask.id).filter(
                BinarySecurityTask.project_id == project_id,
                BinarySecurityTask.id == task_id,
            ).first()
            if not exists:
                return task_id
        raise ValidationError("无法生成唯一任务 ID，请重试")

    async def create_task(
        self,
        db: Session,
        *,
        project_id: str,
        payload: BinarySecurityTaskCreate,
        created_by: str,
        authorization_token: str,
    ) -> BinarySecurityTaskResponse:
        task_id = validate_task_id(payload.task_id) if payload.task_id else self.prepare_task_id(db, project_id)
        if db.query(BinarySecurityTask.id).filter(
            BinarySecurityTask.project_id == project_id,
            BinarySecurityTask.id == task_id,
        ).first():
            raise ValidationError("任务 ID 已存在")

        firmware_path = self._resolve_firmware_input(project_id, payload.firmware_input.source, payload.firmware_input.path)
        workspace_root = app_task_root(project_id, task_id)
        output_root = self._resolve_output_root(project_id, task_id, payload.output_root)
        self._init_workspace(workspace_root)

        subproject = await get_fileserver_client().ensure_subproject(project_id, authorization_token, created_by)
        policy = self._merge_policy(db, project_id, payload.policy_overrides.model_dump(exclude_none=True), payload.stage_options)
        task = BinarySecurityTask(
            id=task_id,
            project_id=project_id,
            name=payload.name,
            description=payload.description,
            created_by=created_by,
            status="pending",
            current_stage=STAGE_SEQUENCE[0],
            firmware_name=Path(firmware_path).name,
            firmware_source=payload.firmware_input.source,
            firmware_path=str(firmware_path),
            output_root=str(output_root),
            workspace_root=str(workspace_root),
            fileserver_subproject_id=subproject.get("id"),
            fileserver_subproject_name=subproject.get("name"),
        )
        task.policy = policy
        task.summary = {
            "fileserver_project_path": f"/{subproject.get('name')}/{task_id}" if subproject.get("name") else f"/{task_id}",
            "downstream_task_ids": {},
        }
        task.metrics = {
            "high_risk_module_count": 0,
            "entry_count": 0,
            "vuln_result_count": 0,
        }
        task.stage_summary = {}
        db.add(task)
        db.commit()
        self._record_event(db, task, "task_created", f"创建任务 {task.id}", payload={"firmware_path": str(firmware_path)})
        db.commit()
        db.refresh(task)
        return self._task_response(db, task)

    def list_tasks(self, db: Session, *, project_id: str, status: str | None = None) -> BinarySecurityTaskListResponse:
        query = db.query(BinarySecurityTask).filter(BinarySecurityTask.project_id == project_id)
        if status:
            query = query.filter(BinarySecurityTask.status == status)
        tasks = query.order_by(BinarySecurityTask.created_at.desc()).all()
        return BinarySecurityTaskListResponse(total=len(tasks), items=[self._task_response(db, task) for task in tasks])

    def get_task_detail(self, db: Session, *, project_id: str, task_id: str) -> BinarySecurityTaskDetailResponse:
        task = self._task_or_404(db, project_id, task_id)
        items = db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.task_id == task.id).order_by(
            BinarySecurityStageItem.created_at.asc()
        ).all()
        base = self._task_response(db, task).model_dump()
        return BinarySecurityTaskDetailResponse(
            **base,
            description=task.description,
            output_root=task.output_root,
            workspace_root=task.workspace_root,
            fileserver_subproject_name=task.fileserver_subproject_name,
            policy=task.policy,
            summary=task.summary,
            metrics=task.metrics,
            item_stats=self._item_stats(items),
            stage_items=[self._stage_item_response(item) for item in items],
        )

    def get_timeline(self, db: Session, *, project_id: str, task_id: str) -> BinarySecurityTimelineResponse:
        task = self._task_or_404(db, project_id, task_id)
        events = db.query(BinarySecurityEvent).filter(BinarySecurityEvent.task_id == task.id).order_by(BinarySecurityEvent.created_at.asc()).all()
        return BinarySecurityTimelineResponse(
            task_id=task.id,
            events=[
                BinarySecurityTaskEventResponse(
                    id=event.id,
                    stage_name=event.stage_name,
                    item_id=event.item_id,
                    item_key=event.item_key,
                    level=event.level,
                    event_type=event.event_type,
                    message=event.message,
                    payload=event.payload,
                    created_at=event.created_at,
                )
                for event in events
            ],
        )

    def get_artifacts(self, db: Session, *, project_id: str, task_id: str) -> BinarySecurityArtifactsResponse:
        task = self._task_or_404(db, project_id, task_id)
        root = Path(task.workspace_root)
        files = []
        if root.exists():
            for path in sorted(p for p in root.rglob("*") if p.is_file()):
                files.append({"path": str(path.relative_to(root)), "size": path.stat().st_size})
        return BinarySecurityArtifactsResponse(
            task_id=task.id,
            workspace_root=task.workspace_root,
            output_root=task.output_root,
            fileserver_path=(task.summary or {}).get("fileserver_project_path"),
            files=files,
        )

    async def cancel_task(self, db: Session, *, project_id: str, task_id: str) -> None:
        task = self._task_or_404(db, project_id, task_id)
        if task.status == "cancelled":
            return
        task.status = "cancelled"
        task.finished_at = _now()
        self._record_event(db, task, "task_cancelled", "任务已取消")
        running_items = db.query(BinarySecurityStageItem).filter(
            BinarySecurityStageItem.task_id == task.id,
            BinarySecurityStageItem.status.in_(["pending", "queued", "running"]),
        ).all()
        for item in running_items:
            item.status = "cancelled"
            item.finished_at = _now()
        db.commit()
        token = self._service_token()
        await asyncio.gather(
            *(self._cancel_downstream(item, token) for item in running_items if item.downstream_task_id),
            return_exceptions=True,
        )
        for item in db.query(BinarySecurityStageItem).filter(
            BinarySecurityStageItem.task_id == task.id,
            BinarySecurityStageItem.status.in_(["pending", "queued", "running"]),
        ):
            item.status = "cancelled"
            item.finished_at = item.finished_at or _now()
        db.commit()

    def retry_task(self, db: Session, *, project_id: str, task_id: str) -> None:
        task = self._task_or_404(db, project_id, task_id)
        task.status = "pending"
        task.current_stage = STAGE_SEQUENCE[0]
        task.last_error = None
        task.started_at = None
        task.finished_at = None
        task.summary = {
            **task.summary,
            "downstream_task_ids": {},
        }
        task.metrics = {
            "high_risk_module_count": 0,
            "entry_count": 0,
            "vuln_result_count": 0,
        }
        db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).delete(synchronize_session=False)
        db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.task_id == task.id).delete(synchronize_session=False)
        self._record_event(db, task, "task_retried", "任务已重新排队")
        db.commit()

    def resume_task(self, db: Session, *, project_id: str, task_id: str) -> None:
        task = self._task_or_404(db, project_id, task_id)
        if task.status not in {"failed", "partial_success", "cancelled"}:
            return
        task.current_stage = self._next_incomplete_stage(db, task.id) or STAGE_SEQUENCE[0]
        task.status = "pending"
        task.last_error = None
        task.finished_at = None
        self._record_event(db, task, "task_resumed", f"任务从阶段 {task.current_stage} 继续")
        db.commit()

    def get_project_config(self, db: Session, project_id: str) -> BinarySecurityProjectConfigResponse:
        row = db.query(BinarySecurityProjectConfig).filter(BinarySecurityProjectConfig.project_id == project_id).first()
        config = BinarySecurityProjectConfigPayload(**(row.config if row else {}))
        return BinarySecurityProjectConfigResponse(project_id=project_id, config=config)

    def save_project_config(self, db: Session, project_id: str, payload: BinarySecurityProjectConfigPayload) -> BinarySecurityProjectConfigResponse:
        row = db.query(BinarySecurityProjectConfig).filter(BinarySecurityProjectConfig.project_id == project_id).first()
        if row is None:
            row = BinarySecurityProjectConfig(project_id=project_id)
            db.add(row)
        row.config = payload.model_dump(mode="json")
        db.commit()
        return BinarySecurityProjectConfigResponse(project_id=project_id, config=payload)

    async def _dispatch_loop(self) -> None:
        session_factory = get_session_factory()
        while self._running:
            db = session_factory()
            try:
                pending = (
                    db.query(BinarySecurityTask)
                    .filter(BinarySecurityTask.status == "pending")
                    .order_by(BinarySecurityTask.created_at.asc())
                    .all()
                )
                async with self._worker_lock:
                    active_count = len([task for task in self._workers.values() if not task.done()])
                    slots = max(0, self.cfg.scheduler.task_concurrency - active_count)
                    for task in pending[:slots]:
                        if task.id in self._workers and not self._workers[task.id].done():
                            continue
                        self._workers[task.id] = asyncio.create_task(self._run_task(task.id), name=f"binary-security-{task.id}")
            finally:
                db.close()
            await asyncio.sleep(self.cfg.scheduler.poll_interval_seconds)

    async def _run_task(self, task_id: str) -> None:
        session_factory = get_session_factory()
        db = session_factory()
        try:
            task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == task_id).first()
            if task is None or task.status != "pending":
                return
            if task.started_at is None:
                task.started_at = _now()
            task.status = "running"
            db.commit()
            await self._execute_task(task_id)
        except Exception as exc:
            task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == task_id).first()
            if task:
                task.status = "failed"
                task.last_error = str(exc)
                task.finished_at = _now()
                self._record_event(db, task, "task_failed", f"任务执行失败: {exc}", level="error")
                db.commit()
        finally:
            db.close()

    async def _execute_task(self, task_id: str) -> None:
        session_factory = get_session_factory()
        db = session_factory()
        try:
            task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == task_id).first()
            if not task:
                return
            token = self._service_token()
            start_index = STAGE_SEQUENCE.index(task.current_stage) if task.current_stage in STAGE_SEQUENCE else 0
            for stage_name in STAGE_SEQUENCE[start_index:]:
                db.refresh(task)
                if task.status == "cancelled":
                    return
                if not self._stage_enabled(task, stage_name):
                    stage_run = self._ensure_stage_run(db, task, stage_name)
                    stage_run.status = "skipped"
                    stage_run.started_at = stage_run.started_at or _now()
                    stage_run.finished_at = _now()
                    stage_run.output_summary = {"reason": "disabled_by_stage_options"}
                    stage_run.counts = self._stage_counts(db, stage_run)
                    task.stage_summary = {
                        **task.stage_summary,
                        stage_name: {
                            "status": "skipped",
                            "counts": stage_run.counts,
                            "finished_at": stage_run.finished_at.isoformat(),
                        },
                    }
                    self._record_event(db, task, "stage_skipped", f"阶段跳过: {stage_name}", stage_name=stage_name)
                    db.commit()
                    continue
                task.current_stage = stage_name
                db.commit()
                handler = getattr(self, f"_stage_{stage_name}")
                stage_run = self._ensure_stage_run(db, task, stage_name)
                stage_run.status = "running"
                stage_run.started_at = stage_run.started_at or _now()
                self._record_event(db, task, "stage_started", f"阶段开始: {stage_name}", stage_name=stage_name)
                db.commit()
                status, summary = await handler(db, task, stage_run, token)
                db.refresh(stage_run)
                stage_run.status = status
                stage_run.finished_at = _now()
                stage_run.output_summary = summary
                stage_run.counts = self._stage_counts(db, stage_run)
                if status in {"failed", "partial_success"}:
                    stage_run.last_error = summary.get("error")
                db.commit()
                task.stage_summary = {
                    **task.stage_summary,
                    stage_name: {
                        "status": status,
                        "counts": stage_run.counts,
                        "finished_at": stage_run.finished_at.isoformat() if stage_run.finished_at else None,
                    },
                }
                task.current_stage = stage_name
                if stage_name == "system_analysis":
                    task.metrics = {**task.metrics, "high_risk_module_count": int(summary.get("module_count", 0))}
                elif stage_name == "entry_analysis":
                    task.metrics = {**task.metrics, "entry_count": int(summary.get("entry_count", 0))}
                elif stage_name == "vuln_scan":
                    task.metrics = {**task.metrics, "vuln_result_count": int(summary.get("vuln_result_count", 0))}
                db.commit()
                if status == "failed" and stage_name in {"firmware_unpack", "system_analysis"}:
                    task.status = "failed"
                    task.finished_at = _now()
                    task.last_error = summary.get("error")
                    self._record_event(db, task, "stage_failed", f"关键阶段失败: {stage_name}", level="error", stage_name=stage_name)
                    db.commit()
                    return
            self._finalize_task(db, task)
            db.commit()
        finally:
            db.close()

    def _finalize_task(self, db: Session, task: BinarySecurityTask) -> None:
        if task.status == "cancelled":
            task.finished_at = _now()
            return
        stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
        statuses = [run.status for run in stage_runs]
        vuln_run = next((run for run in stage_runs if run.stage_name == "vuln_scan"), None)
        non_skipped = [status for status in statuses if status != "skipped"]
        if non_skipped and all(status == "success" for status in non_skipped):
            task.status = "success"
        elif vuln_run and vuln_run.status in {"success", "partial_success"}:
            task.status = "partial_success"
        elif any(status in {"failed", "partial_success"} for status in statuses):
            task.status = "partial_success" if any(status == "success" for status in non_skipped) else "failed"
        else:
            task.status = "success"
        task.finished_at = _now()
        self._record_event(db, task, "task_finished", f"任务结束: {task.status}")

    def _resolve_firmware_input(self, project_id: str, source: str, path: str) -> Path:
        if source in {"project_filesystem", "project_path", "project"}:
            return ensure_path_in_project(project_id, path, must_be_file=True)
        if source in {"absolute", "absolute_path"}:
            candidate = Path(path).resolve()
            if not candidate.is_file():
                raise ValidationError(f"固件文件不存在: {path}")
            return candidate
        raise ValidationError(f"不支持的 firmware_input.source: {source}")

    def _resolve_output_root(self, project_id: str, task_id: str, custom_output_root: str | None) -> Path:
        default_root = app_task_root(project_id, task_id) / "summary"
        if not custom_output_root:
            return default_root
        if custom_output_root.startswith("/"):
            candidate = Path(custom_output_root).resolve()
        else:
            candidate = ensure_path_in_project(project_id, custom_output_root)
        ensure_dir(candidate)
        return candidate

    def _init_workspace(self, root: Path) -> None:
        for rel in [
            "input",
            "runtime",
            "artifacts/unpack",
            "artifacts/system-analysis",
            "artifacts/b2s",
            "artifacts/entry",
            "artifacts/dataflow",
            "artifacts/vuln",
            "summary",
            "logs",
        ]:
            ensure_dir(root / rel)

    def _merge_policy(self, db: Session, project_id: str, overrides: dict[str, Any], stage_options: dict[str, Any]) -> dict[str, Any]:
        base = BinarySecurityProjectConfigPayload(
            max_stage_parallelism=self.cfg.runtime_policy.max_stage_parallelism,
            max_retries_per_item=self.cfg.runtime_policy.max_retries_per_item,
            continue_on_item_failure=self.cfg.runtime_policy.continue_on_item_failure,
        ).model_dump(mode="json")
        row = db.query(BinarySecurityProjectConfig).filter(BinarySecurityProjectConfig.project_id == project_id).first()
        if row:
            base.update(row.config)
        if stage_options:
            base["stage_options"] = {
                **base.get("stage_options", {}),
                **{key: value.model_dump(mode="json") for key, value in stage_options.items()},
            }
        base.update({key: value for key, value in overrides.items() if value is not None})
        return base

    def _service_token(self) -> str | None:
        return self.cfg.auth_service.service_machine_token

    def _stage_enabled(self, task: BinarySecurityTask, stage_name: str) -> bool:
        policy = task.policy or {}
        stage_options = policy.get("stage_options", {})
        option = stage_options.get(stage_name)
        if option is None:
            return True
        return bool(option.get("enabled", True))

    def _task_or_404(self, db: Session, project_id: str, task_id: str) -> BinarySecurityTask:
        task = db.query(BinarySecurityTask).filter(
            BinarySecurityTask.project_id == project_id,
            BinarySecurityTask.id == task_id,
        ).first()
        if not task:
            raise NotFoundError("任务不存在")
        return task

    def _ensure_stage_run(self, db: Session, task: BinarySecurityTask, stage_name: str) -> BinarySecurityStageRun:
        stage_run = db.query(BinarySecurityStageRun).filter(
            BinarySecurityStageRun.task_id == task.id,
            BinarySecurityStageRun.stage_name == stage_name,
        ).first()
        if stage_run:
            return stage_run
        stage_run = BinarySecurityStageRun(
            id=f"sr_{uuid.uuid4().hex[:20]}",
            task_id=task.id,
            project_id=task.project_id,
            stage_name=stage_name,
            sequence_no=STAGE_SEQUENCE.index(stage_name) + 1,
            status="pending",
        )
        db.add(stage_run)
        db.flush()
        return stage_run

    def _record_event(
        self,
        db: Session,
        task: BinarySecurityTask,
        event_type: str,
        message: str,
        *,
        level: str = "info",
        stage_name: str | None = None,
        item: BinarySecurityStageItem | None = None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        event = BinarySecurityEvent(
            id=f"evt_{uuid.uuid4().hex[:24]}",
            task_id=task.id,
            project_id=task.project_id,
            stage_name=stage_name,
            item_id=item.id if item else None,
            item_key=item.item_key if item else None,
            level=level,
            event_type=event_type,
            message=message,
        )
        event.payload = payload or {}
        db.add(event)

    def _stage_counts(self, db: Session, stage_run: BinarySecurityStageRun) -> dict[str, int]:
        items = db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.stage_run_id == stage_run.id).all()
        counts = {
            "total_items": len(items),
            "success_items": 0,
            "failed_items": 0,
            "skipped_items": 0,
            "running_items": 0,
            "cancelled_items": 0,
        }
        for item in items:
            key = f"{item.status}_items"
            if key in counts:
                counts[key] += 1
        return counts

    def _task_response(self, db: Session, task: BinarySecurityTask) -> BinarySecurityTaskResponse:
        stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).order_by(BinarySecurityStageRun.sequence_no.asc()).all()
        return BinarySecurityTaskResponse(
            id=task.id,
            project_id=task.project_id,
            name=task.name,
            status=task.status,
            current_stage=task.current_stage,
            firmware_path=task.firmware_path,
            created_by=task.created_by,
            created_at=task.created_at,
            updated_at=task.updated_at,
            started_at=task.started_at,
            finished_at=task.finished_at,
            high_risk_module_count=int((task.metrics or {}).get("high_risk_module_count", 0)),
            entry_count=int((task.metrics or {}).get("entry_count", 0)),
            vuln_result_count=int((task.metrics or {}).get("vuln_result_count", 0)),
            stage_summaries=[
                BinarySecurityStageSummary(
                    stage_name=run.stage_name,
                    sequence_no=run.sequence_no,
                    status=run.status,
                    retry_count=run.retry_count,
                    total_items=int(run.counts.get("total_items", 0)),
                    success_items=int(run.counts.get("success_items", 0)),
                    failed_items=int(run.counts.get("failed_items", 0)),
                    skipped_items=int(run.counts.get("skipped_items", 0)),
                    running_items=int(run.counts.get("running_items", 0)),
                    started_at=run.started_at,
                    finished_at=run.finished_at,
                    last_error=run.last_error,
                )
                for run in stage_runs
            ],
        )

    def _stage_item_response(self, item: BinarySecurityStageItem) -> BinarySecurityStageItemResponse:
        return BinarySecurityStageItemResponse(
            id=item.id,
            stage_name=item.stage_name,
            item_key=item.item_key,
            item_name=item.item_name,
            parent_key=item.parent_key,
            status=item.status,
            retry_count=item.retry_count,
            downstream_service=item.downstream_service,
            downstream_task_id=item.downstream_task_id,
            input_ref=item.input_ref,
            output_ref=item.output_ref,
            result=item.result,
            error_message=item.error_message,
            started_at=item.started_at,
            finished_at=item.finished_at,
        )

    def _item_stats(self, items: list[BinarySecurityStageItem]) -> dict[str, dict[str, int]]:
        stats: dict[str, dict[str, int]] = {}
        for item in items:
            entry = stats.setdefault(item.stage_name, {"total": 0, "success": 0, "failed": 0, "skipped": 0, "running": 0, "cancelled": 0})
            entry["total"] += 1
            if item.status in entry:
                entry[item.status] += 1
        return stats

    def _next_incomplete_stage(self, db: Session, task_id: str) -> str | None:
        stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task_id).all()
        completed = {run.stage_name for run in stage_runs if run.status in {"success", "skipped"}}
        for stage_name in STAGE_SEQUENCE:
            if stage_name not in completed:
                return stage_name
        return None

    async def _cancel_downstream(self, item: BinarySecurityStageItem, token: str | None) -> None:
        try:
            if item.downstream_service == "firmware_unpacker":
                await get_firmware_unpacker_client().cancel_task(item.downstream_task_id, token or "")
            elif item.downstream_service == "binary_to_source":
                result = item.result
                await get_binary_to_source_client().cancel_task(result["project_id"], item.downstream_task_id, token or "")
            elif item.downstream_service == "entry_analyse":
                await get_entry_analyse_client().cancel_task(item.downstream_task_id)
            elif item.downstream_service == "dataflow_analyse":
                await get_dataflow_analyse_client().cancel_task(item.downstream_task_id)
            elif item.downstream_service == "dataflow_vuln_scanner":
                await get_dataflow_vuln_scanner_client().cancel_task(item.downstream_task_id, token or "")
            elif item.downstream_service == "system_analyse":
                await get_system_analyse_client().cancel_task(item.downstream_task_id)
        except Exception:
            pass

    async def _poll_until_terminal(self, fetcher, *, success_statuses: set[str], failure_statuses: set[str], task: BinarySecurityTask, stage_name: str, item: BinarySecurityStageItem | None = None):
        while True:
            payload = await fetcher()
            status = str(payload.get("status") or "").lower()
            if status in success_statuses:
                return "success", payload
            if status in failure_statuses:
                return "failed", payload
            if self._is_task_cancelled(task.id):
                if item and item.downstream_task_id:
                    await self._cancel_downstream(item, self._service_token())
                return "cancelled", payload
            await asyncio.sleep(self.cfg.scheduler.stage_poll_interval_seconds)

    def _is_task_cancelled(self, task_id: str) -> bool:
        session = get_session_factory()()
        try:
            row = session.query(BinarySecurityTask.status).filter(BinarySecurityTask.id == task_id).first()
            return bool(row and row[0] == "cancelled")
        finally:
            session.close()

    async def _stage_firmware_unpack(self, db: Session, task: BinarySecurityTask, stage_run: BinarySecurityStageRun, token: str | None) -> tuple[str, dict[str, Any]]:
        unpack_dir = Path(task.workspace_root) / "artifacts" / "unpack" / "output"
        ensure_dir(unpack_dir)
        item = BinarySecurityStageItem(
            id=f"si_{uuid.uuid4().hex[:20]}",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=stage_run.id,
            stage_name=stage_run.stage_name,
            item_key="firmware",
            item_name=task.firmware_name,
            status="queued",
            downstream_service="firmware_unpacker",
        )
        item.input_ref = {"firmware_path": task.firmware_path}
        item.output_ref = {"output_path": str(unpack_dir)}
        db.add(item)
        db.commit()
        created = await get_firmware_unpacker_client().create_task(task.project_id, task.firmware_path, str(unpack_dir), token or "")
        item.status = "running"
        item.downstream_task_id = created.get("task_id")
        item.started_at = _now()
        item.result = {"project_id": task.project_id}
        db.commit()
        status, payload = await self._poll_until_terminal(
            lambda: get_firmware_unpacker_client().get_task(task.project_id, item.downstream_task_id, token or ""),
            success_statuses={"success"},
            failure_statuses={"failed", "cancelled"},
            task=task,
            stage_name=stage_run.stage_name,
            item=item,
        )
        item.finished_at = _now()
        item.status = "success" if status == "success" else "cancelled" if status == "cancelled" else "failed"
        item.result = {
            "downstream": payload,
            "unpacked_root": str(unpack_dir),
        }
        task.summary = {**task.summary, "unpacked_root": str(unpack_dir), "downstream_task_ids": {**task.summary.get("downstream_task_ids", {}), "firmware_unpack": item.downstream_task_id}}
        db.commit()
        return item.status, {"unpacked_root": str(unpack_dir), "downstream_task_id": item.downstream_task_id, "error": payload.get("error_message")}

    async def _stage_system_analysis(self, db: Session, task: BinarySecurityTask, stage_run: BinarySecurityStageRun, token: str | None) -> tuple[str, dict[str, Any]]:
        unpacked_root = str(task.summary.get("unpacked_root") or "")
        if not unpacked_root:
            return "failed", {"error": "缺少解包目录"}
        created = await get_system_analyse_client().create_task(task.project_id, f"{task.name}-system-analysis", unpacked_root)
        stage_item = BinarySecurityStageItem(
            id=f"si_{uuid.uuid4().hex[:20]}",
            task_id=task.id,
            project_id=task.project_id,
            stage_run_id=stage_run.id,
            stage_name=stage_run.stage_name,
            item_key="system-analysis",
            item_name="system-analysis",
            status="running",
            downstream_service="system_analyse",
            downstream_task_id=created.get("task_id"),
            started_at=_now(),
        )
        stage_item.input_ref = {"input_path": unpacked_root}
        db.add(stage_item)
        db.commit()
        status, payload = await self._poll_until_terminal(
            lambda: get_system_analyse_client().get_task(stage_item.downstream_task_id),
            success_statuses={"passed", "success"},
            failure_statuses={"failed", "error", "cancelled"},
            task=task,
            stage_name=stage_run.stage_name,
            item=stage_item,
        )
        stage_item.finished_at = _now()
        artifact_root = self._materialize_stage_artifact(task, "system-analysis", stage_item.downstream_task_id, payload)
        modules = self._parse_system_analysis_modules(artifact_root)
        stage_item.status = "success" if status == "success" else "cancelled" if status == "cancelled" else "failed"
        stage_item.result = {"downstream": payload, "artifact_root": str(artifact_root), "modules": modules}
        task.summary = {
            **task.summary,
            "system_analysis_root": str(artifact_root),
            "high_risk_modules": modules,
            "downstream_task_ids": {**task.summary.get("downstream_task_ids", {}), "system_analysis": stage_item.downstream_task_id},
        }
        for module in modules:
            child = BinarySecurityStageItem(
                id=f"si_{uuid.uuid4().hex[:20]}",
                task_id=task.id,
                project_id=task.project_id,
                stage_run_id=stage_run.id,
                stage_name=stage_run.stage_name,
                item_key=module["module_key"],
                item_name=module["module_name"],
                parent_key="system-analysis",
                status="success",
            )
            child.input_ref = {"module_dir": module["module_dir"]}
            child.result = module
            db.add(child)
        db.commit()
        if status != "success":
            return "failed", {"error": payload.get("error") or payload.get("error_message"), "artifact_root": str(artifact_root), "module_count": len(modules)}
        if not modules:
            return "failed", {"error": "系统分析未识别出高危模块", "artifact_root": str(artifact_root), "module_count": 0}
        return "success", {"artifact_root": str(artifact_root), "module_count": len(modules)}

    def _parse_system_analysis_modules(self, root: Path) -> list[dict[str, Any]]:
        modules_list = root / "modules.list"
        modules_dir = root / "modules"
        items: list[dict[str, Any]] = []
        names = [line.strip() for line in _read_text(modules_list).splitlines() if line.strip()]
        if not names and modules_dir.is_dir():
            names = [path.name for path in sorted(p for p in modules_dir.iterdir() if p.is_dir())]
        for name in names:
            module_dir = modules_dir / name
            items.append(
                {
                    "module_key": _slug(name),
                    "module_name": name,
                    "module_dir": str(module_dir),
                    "module_report": str(module_dir / "module_report.md"),
                    "files_list": str(module_dir / "files.list"),
                }
            )
        _write_json(root / "high_risk_modules.json", {"items": items})
        return items

    def _materialize_stage_artifact(self, task: BinarySecurityTask, stage_dir: str, downstream_task_id: str | None, payload: dict[str, Any]) -> Path:
        artifact_root = Path(task.workspace_root) / "artifacts" / stage_dir / (downstream_task_id or "unknown")
        ensure_dir(artifact_root)
        candidates: list[Path] = []
        for key in ("artifact_root", "result_root", "workspace_root", "output_path"):
            value = payload.get(key)
            if value:
                raw = Path(str(value))
                if key == "output_path" and downstream_task_id and raw.exists() and raw.is_dir() and not (raw / downstream_task_id).exists():
                    candidates.append(raw)
                else:
                    candidates.append(raw / downstream_task_id if key == "output_path" and downstream_task_id else raw)
        for candidate in candidates:
            if candidate.exists():
                _copytree(candidate, artifact_root)
        return artifact_root

    async def _stage_binary_to_source(self, db: Session, task: BinarySecurityTask, stage_run: BinarySecurityStageRun, token: str | None) -> tuple[str, dict[str, Any]]:
        modules = list(task.summary.get("high_risk_modules") or [])
        if not modules:
            return "failed", {"error": "缺少高危模块列表"}
        results = await self._run_stage_pool(
            task,
            modules,
            int(task.policy.get("max_stage_parallelism") or 1),
            lambda module: self._run_b2s_item(task, stage_run, module, token),
            retries=int(task.policy.get("max_retries_per_item") or 0),
        )
        return self._aggregate_stage_items(db, task, stage_run, results, "b2s_results")

    async def _stage_entry_analysis(self, db: Session, task: BinarySecurityTask, stage_run: BinarySecurityStageRun, token: str | None) -> tuple[str, dict[str, Any]]:
        b2s_success = [
            item.result
            for item in db.query(BinarySecurityStageItem)
            .filter(BinarySecurityStageItem.task_id == task.id, BinarySecurityStageItem.stage_name == "binary_to_source", BinarySecurityStageItem.status == "success")
            .all()
        ]
        if not b2s_success:
            return "failed", {"error": "没有可用于入口分析的反编译结果"}
        results = await self._run_stage_pool(
            task,
            b2s_success,
            int(task.policy.get("max_stage_parallelism") or 1),
            lambda module: self._run_entry_item(task, stage_run, module, token),
            retries=int(task.policy.get("max_retries_per_item") or 0),
        )
        status, summary = self._aggregate_stage_items(db, task, stage_run, results, "entry_results")
        if summary.get("items"):
            task.summary = {**task.summary, "entry_results": summary["items"]}
        return status, summary

    async def _stage_dataflow_analysis(self, db: Session, task: BinarySecurityTask, stage_run: BinarySecurityStageRun, token: str | None) -> tuple[str, dict[str, Any]]:
        entry_results = list(task.summary.get("entry_results") or [])
        entries: list[dict[str, Any]] = []
        for result in entry_results:
            entries.extend(result.get("entries", []))
        if not entries:
            return "failed", {"error": "没有可用于数据流分析的入口"}
        results = await self._run_stage_pool(
            task,
            entries,
            int(task.policy.get("max_stage_parallelism") or 1),
            lambda entry: self._run_dataflow_item(task, stage_run, entry, token),
            retries=int(task.policy.get("max_retries_per_item") or 0),
        )
        status, summary = self._aggregate_stage_items(db, task, stage_run, results, "dataflow_results")
        if summary.get("items"):
            task.summary = {**task.summary, "dataflow_results": summary["items"]}
        return status, summary

    async def _stage_vuln_scan(self, db: Session, task: BinarySecurityTask, stage_run: BinarySecurityStageRun, token: str | None) -> tuple[str, dict[str, Any]]:
        dataflow_results = list(task.summary.get("dataflow_results") or [])
        if not dataflow_results:
            return "failed", {"error": "没有可用于漏洞扫描的数据流结果"}
        results = await self._run_stage_pool(
            task,
            dataflow_results,
            int(task.policy.get("max_stage_parallelism") or 1),
            lambda result: self._run_vuln_item(task, stage_run, result, token),
            retries=int(task.policy.get("max_retries_per_item") or 0),
        )
        return self._aggregate_stage_items(db, task, stage_run, results, "vuln_results")

    async def _run_stage_pool(self, task: BinarySecurityTask, items: list[dict[str, Any]], concurrency: int, runner, retries: int = 0):
        semaphore = asyncio.Semaphore(max(1, concurrency))

        async def wrapped(item: dict[str, Any]):
            async with semaphore:
                if self._is_task_cancelled(task.id):
                    return {"status": "cancelled", "error": "task cancelled", "item": item}
                attempts = 0
                result = await runner(item)
                while result.get("status") == "failed" and attempts < max(0, retries):
                    attempts += 1
                    result = await runner(item)
                    result["attempts"] = attempts + 1
                return result

        return await asyncio.gather(*(wrapped(item) for item in items))

    async def _run_b2s_item(self, task: BinarySecurityTask, stage_run: BinarySecurityStageRun, module: dict[str, Any], token: str | None) -> dict[str, Any]:
        session = get_session_factory()()
        try:
            item = BinarySecurityStageItem(
                id=f"si_{uuid.uuid4().hex[:20]}",
                task_id=task.id,
                project_id=task.project_id,
                stage_run_id=stage_run.id,
                stage_name=stage_run.stage_name,
                item_key=module["module_key"],
                item_name=module["module_name"],
                parent_key=module["module_key"],
                status="running",
                downstream_service="binary_to_source",
                started_at=_now(),
            )
            item.input_ref = module
            session.add(item)
            session.commit()
            elf_path = self._choose_module_binary(module)
            created = await get_binary_to_source_client().create_task(task.project_id, f"{task.name}-{module['module_name']}", elf_path, token or "", module)
            item.downstream_task_id = created.get("id")
            item.result = {"project_id": task.project_id}
            session.commit()
            status, payload = await self._poll_until_terminal(
                lambda: get_binary_to_source_client().get_task(task.project_id, item.downstream_task_id, token or ""),
                success_statuses={"success", "partial_success"},
                failure_statuses={"failed", "cancelled"},
                task=task,
                stage_name=stage_run.stage_name,
                item=item,
            )
            detail = payload
            artifact_root = Path(task.workspace_root) / "artifacts" / "b2s" / module["module_key"]
            ensure_dir(artifact_root)
            generated_files = []
            for child in detail.get("items", []):
                for file_path in child.get("generated_files") or []:
                    src = Path(file_path)
                    if src.exists():
                        target = artifact_root / src.name
                        _copytree(src, target)
                        generated_files.append(str(target))
            result = {
                "module_key": module["module_key"],
                "module_name": module["module_name"],
                "source_dir": str(artifact_root),
                "generated_files": generated_files,
                "downstream": detail,
            }
            item.status = "success" if status == "success" else "cancelled" if status == "cancelled" else "failed"
            item.finished_at = _now()
            item.result = result
            item.output_ref = {"source_dir": str(artifact_root)}
            session.commit()
            return {"status": item.status, "item": result}
        except Exception as exc:
            if "item" in locals():
                item.status = "failed"
                item.error_message = str(exc)
                item.finished_at = _now()
                session.commit()
            return {"status": "failed", "error": str(exc), "item": module}
        finally:
            session.close()

    def _choose_module_binary(self, module: dict[str, Any]) -> str:
        files = [line.strip() for line in _read_text(Path(module["files_list"])).splitlines() if line.strip()]
        module_dir = Path(module["module_dir"])
        unpacked_hint = module.get("unpacked_root")
        unpacked_root = Path(str(unpacked_hint)) if unpacked_hint else (module_dir.parents[1] if len(module_dir.parents) > 1 else module_dir.parent)
        for rel in files:
            candidate = Path(rel)
            candidates = []
            if candidate.is_absolute():
                candidates.append(candidate)
            else:
                candidates.append(module_dir / rel)
                candidates.append(unpacked_root / rel)
                candidates.append(module_dir.parent / rel)
            for resolved in candidates:
                if resolved.exists() and resolved.is_file():
                    return str(resolved.resolve())
                if resolved.parent.exists():
                    matches = sorted(p for p in resolved.parent.rglob(candidate.name) if p.is_file())
                    if matches:
                        return str(matches[0].resolve())
        raise ValidationError(f"模块 {module['module_name']} 未找到可反编译文件")

    async def _run_entry_item(self, task: BinarySecurityTask, stage_run: BinarySecurityStageRun, module: dict[str, Any], token: str | None) -> dict[str, Any]:
        session = get_session_factory()()
        try:
            item = BinarySecurityStageItem(
                id=f"si_{uuid.uuid4().hex[:20]}",
                task_id=task.id,
                project_id=task.project_id,
                stage_run_id=stage_run.id,
                stage_name=stage_run.stage_name,
                item_key=module["module_key"],
                item_name=module["module_name"],
                parent_key=module["module_key"],
                status="running",
                downstream_service="entry_analyse",
                started_at=_now(),
            )
            item.input_ref = module
            session.add(item)
            session.commit()
            created = await get_entry_analyse_client().create_task(task.project_id, f"{task.name}-{module['module_name']}-entry", module["source_dir"])
            item.downstream_task_id = created.get("task_id")
            session.commit()
            status, payload = await self._poll_until_terminal(
                lambda: get_entry_analyse_client().get_task(item.downstream_task_id),
                success_statuses={"passed", "success"},
                failure_statuses={"failed", "error", "cancelled"},
                task=task,
                stage_name=stage_run.stage_name,
                item=item,
            )
            artifact_root = Path(task.workspace_root) / "artifacts" / "entry" / module["module_key"]
            _copytree(self._materialize_stage_artifact(task, "entry", item.downstream_task_id, payload), artifact_root)
            entries = self._parse_entries(artifact_root, module)
            result = {
                "module_key": module["module_key"],
                "module_name": module["module_name"],
                "artifact_root": str(artifact_root),
                "entries": entries,
                "source_dir": module["source_dir"],
                "downstream": payload,
            }
            item.status = "success" if status == "success" else "cancelled" if status == "cancelled" else "failed"
            item.finished_at = _now()
            item.retry_count = max(item.retry_count, 0)
            item.result = result
            item.output_ref = {"artifact_root": str(artifact_root)}
            session.commit()
            return {"status": item.status, "item": result}
        except Exception as exc:
            if "item" in locals():
                item.status = "failed"
                item.error_message = str(exc)
                item.finished_at = _now()
                session.commit()
            return {"status": "failed", "error": str(exc), "item": module}
        finally:
            session.close()

    def _parse_entries(self, artifact_root: Path, module: dict[str, Any]) -> list[dict[str, Any]]:
        json_candidates = [
            artifact_root / "result.json",
            artifact_root / "result_json",
            artifact_root / "entry-list.json",
        ]
        for candidate in json_candidates:
            if candidate.is_file():
                payload = json.loads(_read_text(candidate) or "{}")
                rows = []
                for index, entry in enumerate(payload.get("entries") or payload.get("items") or []):
                    function_name = str(entry.get("function_name") or entry.get("name") or "").strip()
                    if not function_name:
                        continue
                    file_name = str(entry.get("file_name") or entry.get("file") or "").strip()
                    line_no = str(entry.get("line_no") or entry.get("line") or index + 1)
                    rows.append(
                        {
                            "entry_key": _slug(f"{module['module_key']}-{function_name}-{line_no}"),
                            "module_key": module["module_key"],
                            "module_name": module["module_name"],
                            "file_name": file_name,
                            "function_name": function_name,
                            "line_no": line_no,
                            "entry_file": str(candidate),
                            "source_dir": module["source_dir"],
                        }
                    )
                if rows:
                    return rows
        entry_file = artifact_root / "entry-list.md"
        content = _read_text(entry_file)
        rows = []
        for line in content.splitlines():
            parts = [part.strip() for part in line.split("|")]
            if len(parts) >= 7 and parts[1].isdigit():
                file_name = parts[2]
                function_name = parts[3]
                line_no = parts[4]
                if file_name and function_name:
                    rows.append(
                        {
                            "entry_key": _slug(f"{module['module_key']}-{function_name}-{line_no}"),
                            "module_key": module["module_key"],
                            "module_name": module["module_name"],
                            "file_name": file_name,
                            "function_name": function_name,
                            "line_no": line_no,
                            "entry_file": str(entry_file),
                            "source_dir": module["source_dir"],
                        }
                    )
        return rows

    async def _run_dataflow_item(self, task: BinarySecurityTask, stage_run: BinarySecurityStageRun, entry: dict[str, Any], token: str | None) -> dict[str, Any]:
        session = get_session_factory()()
        try:
            item = BinarySecurityStageItem(
                id=f"si_{uuid.uuid4().hex[:20]}",
                task_id=task.id,
                project_id=task.project_id,
                stage_run_id=stage_run.id,
                stage_name=stage_run.stage_name,
                item_key=entry["entry_key"],
                item_name=entry["function_name"],
                parent_key=entry["module_key"],
                status="running",
                downstream_service="dataflow_analyse",
                started_at=_now(),
            )
            item.input_ref = entry
            session.add(item)
            session.commit()
            prompt = f"分析文件 {entry['file_name']} 中函数 {entry['function_name']} 的外部输入数据流"
            created = await get_dataflow_analyse_client().create_task(task.project_id, f"{task.name}-{entry['function_name']}-dfa", entry["source_dir"], prompt)
            item.downstream_task_id = created.get("task_id")
            session.commit()
            status, payload = await self._poll_until_terminal(
                lambda: get_dataflow_analyse_client().get_task(item.downstream_task_id),
                success_statuses={"passed", "success"},
                failure_statuses={"failed", "error", "cancelled"},
                task=task,
                stage_name=stage_run.stage_name,
                item=item,
            )
            artifact_root = Path(task.workspace_root) / "artifacts" / "dataflow" / entry["entry_key"]
            _copytree(self._materialize_stage_artifact(task, "dataflow", item.downstream_task_id, payload), artifact_root)
            data_flow_file = self._find_first(artifact_root, [r"dataflow-.*\.md", r".*result.*\.md", r"report\.md"])
            result = {
                **entry,
                "artifact_root": str(artifact_root),
                "data_flow_file": str(data_flow_file) if data_flow_file else "",
                "downstream": payload,
            }
            item.status = "success" if status == "success" else "cancelled" if status == "cancelled" else "failed"
            item.finished_at = _now()
            item.retry_count = max(item.retry_count, 0)
            item.result = result
            item.output_ref = {"artifact_root": str(artifact_root), "data_flow_file": result["data_flow_file"]}
            session.commit()
            return {"status": item.status, "item": result}
        except Exception as exc:
            if "item" in locals():
                item.status = "failed"
                item.error_message = str(exc)
                item.finished_at = _now()
                session.commit()
            return {"status": "failed", "error": str(exc), "item": entry}
        finally:
            session.close()

    async def _run_vuln_item(self, task: BinarySecurityTask, stage_run: BinarySecurityStageRun, dataflow_result: dict[str, Any], token: str | None) -> dict[str, Any]:
        session = get_session_factory()()
        try:
            item = BinarySecurityStageItem(
                id=f"si_{uuid.uuid4().hex[:20]}",
                task_id=task.id,
                project_id=task.project_id,
                stage_run_id=stage_run.id,
                stage_name=stage_run.stage_name,
                item_key=dataflow_result["entry_key"],
                item_name=dataflow_result["function_name"],
                parent_key=dataflow_result["module_key"],
                status="running",
                downstream_service="dataflow_vuln_scanner",
                started_at=_now(),
            )
            item.input_ref = dataflow_result
            session.add(item)
            session.commit()
            vuln_workspace = Path(task.workspace_root) / "artifacts" / "vuln" / dataflow_result["entry_key"] / "workspace"
            vuln_output = vuln_workspace / "output"
            ensure_dir(vuln_output)
            created = await get_dataflow_vuln_scanner_client().create_task(
                task.project_id,
                f"{task.name}-{dataflow_result['function_name']}-scan",
                token or "",
                dataflow_result["data_flow_file"],
                dataflow_result["source_dir"],
                str(vuln_workspace),
                str(vuln_output),
            )
            item.downstream_task_id = created.get("task_id")
            session.commit()
            status, payload = await self._poll_until_terminal(
                lambda: get_dataflow_vuln_scanner_client().get_task(item.downstream_task_id, token or ""),
                success_statuses={"success", "succeeded", "completed"},
                failure_statuses={"failed", "cancelled"},
                task=task,
                stage_name=stage_run.stage_name,
                item=item,
            )
            artifacts = await get_dataflow_vuln_scanner_client().get_artifacts(item.downstream_task_id, token or "")
            result = {
                **dataflow_result,
                "workspace_root": artifacts.get("workspace_root"),
                "artifact_files": artifacts.get("files", []),
                "downstream": payload,
                "artifacts": artifacts,
            }
            item.status = "success" if status == "success" else "cancelled" if status == "cancelled" else "failed"
            item.finished_at = _now()
            item.retry_count = max(item.retry_count, 0)
            item.result = result
            item.output_ref = {"workspace_root": artifacts.get("workspace_root")}
            session.commit()
            return {"status": item.status, "item": result}
        except Exception as exc:
            if "item" in locals():
                item.status = "failed"
                item.error_message = str(exc)
                item.finished_at = _now()
                session.commit()
            return {"status": "failed", "error": str(exc), "item": dataflow_result}
        finally:
            session.close()

    def _find_first(self, root: Path, patterns: list[str]) -> Path | None:
        if not root.exists():
            return None
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            for pattern in patterns:
                if re.fullmatch(pattern, path.name):
                    return path
        return None

    def _aggregate_stage_items(self, db: Session, task: BinarySecurityTask, stage_run: BinarySecurityStageRun, results: list[dict[str, Any]], summary_key: str) -> tuple[str, dict[str, Any]]:
        success = [result["item"] for result in results if result.get("status") == "success"]
        failed = [result for result in results if result.get("status") == "failed"]
        cancelled = [result for result in results if result.get("status") == "cancelled"]
        if failed and success:
            status = "partial_success"
        elif failed:
            status = "failed"
        elif cancelled and not success:
            status = "cancelled"
        else:
            status = "success"
        summary = {
            "items": success,
            "failed_items": failed,
            "cancelled_items": cancelled,
            "success_count": len(success),
            "failed_count": len(failed),
            "entry_count": len(success) if summary_key == "entry_results" else 0,
            "vuln_result_count": len(success) if summary_key == "vuln_results" else 0,
            "error": failed[0].get("error") if failed else cancelled[0].get("error") if cancelled else None,
        }
        task.summary = {**task.summary, summary_key: success}
        db.commit()
        return status, summary


_task_manager: Optional[TaskManager] = None


def get_task_manager() -> TaskManager:
    global _task_manager
    if _task_manager is None:
        _task_manager = TaskManager()
    return _task_manager
