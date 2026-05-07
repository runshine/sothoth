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

from sqlalchemy import func, or_, text
from sqlalchemy.orm import Session

from app.config import get_config
from app.exception import NotFoundError, ValidationError
from app.model import (
    STAGE_SEQUENCE,
    TASK_STAGE_SEQUENCES,
    TASK_TYPE_BINARY,
    TASK_TYPE_SOURCE,
    BinarySecurityEvent,
    BinarySecurityProjectConfig,
    BinarySecurityServiceConfig,
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityTask,
    get_session_factory,
)
from app.schemas import (
    BinarySecurityArtifactsResponse,
    BinarySecurityInputFile,
    BinarySecurityProjectConfigPayload,
    BinarySecurityProjectConfigResponse,
    BinarySecurityServiceConfigPayload,
    BinarySecurityServiceConfigResponse,
    BinarySecurityStageItemResponse,
    BinarySecurityStageSummary,
    BinarySecurityTaskCreate,
    BinarySecurityTaskDetailResponse,
    BinarySecurityTaskEventResponse,
    BinarySecurityTaskListResponse,
    BinarySecurityTaskResponse,
    BinarySecurityTimelineResponse,
    BinarySecurityUploadCompletePayload,
)
from app.service.binary_to_source import get_binary_to_source_client
from app.service.dataflow_analyse import get_dataflow_analyse_client
from app.service.dataflow_vuln_scanner import get_dataflow_vuln_scanner_client
from app.service.entry_analyse import get_entry_analyse_client
from app.service.fileserver import get_fileserver_client
from app.service.firmware_unpacker import get_firmware_unpacker_client
from app.service.security import app_task_root, ensure_dir, validate_task_id
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


STAGE_RETRY_ALLOWED_STATUSES = {"success", "failed", "partial_success", "cancelled"}
STAGE_RETRY_BLOCKED_TASK_STATUSES = {"pending", "dispatching", "running", "pending_upload", "uploading", "ready_to_start"}
STAGE_SUMMARY_RESULT_KEYS = {
    "firmware_unpack": ["firmware_unpack_results"],
    "system_analysis": ["system_analysis_results", "high_risk_modules"],
    "binary_to_source": ["b2s_results"],
    "entry_analysis": ["entry_results"],
    "dataflow_analysis": ["dataflow_results"],
    "vuln_scan": ["vuln_results"],
}
STAGE_METRIC_RESETTERS = {
    "firmware_unpack": {"unpacked_firmware_count": 0, "failed_firmware_count": 0},
    "system_analysis": {"high_risk_module_count": 0},
    "entry_analysis": {"entry_count": 0},
    "vuln_scan": {"vuln_result_count": 0},
}
SOURCE_TASK_INPUT_KEY = "source_project"


class TaskManager:
    def __init__(self) -> None:
        self.cfg = get_config()
        self.instance_id = os.environ.get("POD_NAME") or os.environ.get("HOSTNAME") or f"binary-security-{uuid.uuid4().hex[:12]}"
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

    def _task_type(self, task: BinarySecurityTask | str | None) -> str:
        raw = task if isinstance(task, str) else getattr(task, "task_type", None)
        return raw if raw in TASK_STAGE_SEQUENCES else TASK_TYPE_BINARY

    def _stage_sequence_for_task(self, task: BinarySecurityTask | str | None) -> list[str]:
        return list(TASK_STAGE_SEQUENCES[self._task_type(task)])

    def _validate_task_type(self, task_type: str | None) -> str:
        normalized = str(task_type or TASK_TYPE_BINARY).strip().lower()
        if normalized not in TASK_STAGE_SEQUENCES:
            raise ValidationError(f"不支持的任务类型: {task_type}")
        return normalized

    async def create_task(
        self,
        db: Session,
        *,
        project_id: str,
        payload: BinarySecurityTaskCreate,
        created_by: str,
        authorization_token: str,
    ) -> BinarySecurityTaskDetailResponse:
        task_id = validate_task_id(payload.task_id) if payload.task_id else self.prepare_task_id(db, project_id)
        task_type = self._validate_task_type(payload.task_type)
        if db.query(BinarySecurityTask.id).filter(
            BinarySecurityTask.project_id == project_id,
            BinarySecurityTask.id == task_id,
        ).first():
            raise ValidationError("任务 ID 已存在")
        input_files = self._normalize_input_files(payload.input_files, task_type=task_type)
        workspace_root = app_task_root(project_id, task_id)
        output_root = self._resolve_output_root(workspace_root, payload.output_root)
        input_dir = workspace_root / "input"
        run_dir = workspace_root / "run"
        self._init_workspace(workspace_root)
        await self._ensure_task_directories(project_id, task_id, authorization_token)
        metadata_path = input_dir / "task-metadata.json"
        policy = self._merge_policy(db, project_id, payload.policy_overrides.model_dump(exclude_none=True), payload.stage_options)

        task = BinarySecurityTask(
            id=task_id,
            project_id=project_id,
            task_type=task_type,
            name=payload.name,
            description=payload.description,
            created_by=created_by,
            status="pending_upload",
            current_stage=None,
            firmware_name=f"{len(input_files)} files",
            firmware_source="project_filesystem",
            firmware_path=self._fileserver_task_path(task_id, "input"),
            output_root=str(output_root),
            workspace_root=str(workspace_root),
        )
        task.policy = policy
        task.summary = {
            "fileserver_project_path": self._fileserver_task_path(task_id),
            "task_root_path": str(workspace_root),
            "input_dir": self._fileserver_task_path(task_id, "input"),
            "output_dir": self._fileserver_task_path(task_id, "output"),
            "run_dir": self._fileserver_task_path(task_id, "run"),
            "input_manifest_path": f"{self._fileserver_task_path(task_id, 'input')}/task-metadata.json",
            "input_files": input_files,
            "input_kind": "source_tree" if task_type == TASK_TYPE_SOURCE else "firmware_files",
            "downstream_task_ids": {},
        }
        task.metrics = {
            "high_risk_module_count": 0,
            "entry_count": 0,
            "vuln_result_count": 0,
            "input_file_count": len(input_files),
            "uploaded_file_count": 0,
            "input_total_bytes": int(sum(int(item.get("size") or 0) for item in input_files)),
            "firmware_item_count": len(input_files),
            "unpacked_firmware_count": 0,
            "failed_firmware_count": 0,
        }
        task.stage_summary = {}
        db.add(task)
        db.commit()
        self._write_task_metadata(task, metadata_path, status="pending_upload")
        self._record_event(db, task, "task_created", f"创建任务 {task.id}", payload={"input_files": input_files})
        self._record_event(db, task, "task_upload_pending", "任务创建完成，等待上传文件")
        db.commit()
        return self.get_task_detail(db, project_id=project_id, task_id=task.id)

    async def complete_uploads(
        self,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        payload: BinarySecurityUploadCompletePayload,
        updated_by: str,
        authorization_token: str,
    ) -> BinarySecurityTaskDetailResponse:
        del updated_by, authorization_token
        task = self._task_or_404(db, project_id, task_id)
        if task.status not in {"pending_upload", "uploading", "ready_to_start"}:
            raise ValidationError(f"当前状态不允许确认上传完成: {task.status}")
        input_dir = Path(task.workspace_root) / "input"
        declared = self._normalize_input_files(
            payload.files or [BinarySecurityInputFile(**item) for item in task.summary.get("input_files") or []],
            task_type=self._task_type(task),
        )
        self._record_event(db, task, "task_upload_started", "开始校验上传文件")
        actual_files = []
        total_bytes = 0
        for file_info in declared:
            filename = str(file_info["filename"])
            relative_path = str(file_info.get("relative_path") or filename).strip().replace("\\", "/")
            local_path = input_dir / relative_path
            if not local_path.is_file():
                raise ValidationError(f"上传文件缺失: {relative_path}")
            stat = local_path.stat()
            total_bytes += stat.st_size
            actual_files.append(
                {
                    **file_info,
                    "size": stat.st_size,
                    "uploaded": True,
                    "path": f"{task.summary.get('input_dir')}/{relative_path}",
                }
            )
        task.status = "ready_to_start"
        task.dispatcher_instance_id = None
        task.dispatch_started_at = None
        task.summary = {
            **task.summary,
            "input_files": actual_files,
        }
        task.metrics = {
            **task.metrics,
            "input_file_count": len(actual_files),
            "uploaded_file_count": len(actual_files),
            "input_total_bytes": total_bytes,
            "firmware_item_count": len(actual_files),
        }
        self._write_task_metadata(task, input_dir / "task-metadata.json", status="ready_to_start")
        self._record_event(db, task, "task_upload_completed", "输入文件上传完成", payload={"uploaded_files": len(actual_files)})
        self._record_event(db, task, "task_ready_to_start", "任务已就绪，准备自动启动")
        db.commit()
        return self.start_task(db, project_id=project_id, task_id=task_id)

    def start_task(self, db: Session, *, project_id: str, task_id: str) -> BinarySecurityTaskDetailResponse:
        task = self._task_or_404(db, project_id, task_id)
        if task.status not in {"ready_to_start", "failed", "partial_success"}:
            if task.status in {"pending", "running"}:
                return self.get_task_detail(db, project_id=project_id, task_id=task_id)
            raise ValidationError(f"当前状态不允许启动任务: {task.status}")
        input_files = task.summary.get("input_files") or []
        if not input_files:
            raise ValidationError("没有可用的输入文件")
        task.status = "pending"
        task.current_stage = self._stage_sequence_for_task(task)[0]
        task.execution_mode = None
        task.target_stage_name = None
        task.last_error = None
        task.dispatcher_instance_id = None
        task.dispatch_started_at = None
        task.started_at = None
        task.finished_at = None
        task.summary = {
            **task.summary,
            "stale_stages": [],
            "stale_reason": None,
            "stale_from_stage": None,
            "stage_retry_context": {},
        }
        self._write_task_metadata(task, Path(task.workspace_root) / "input" / "task-metadata.json", status="pending")
        self._record_event(db, task, "task_start_requested", "任务已进入调度队列")
        if self._task_type(task) == TASK_TYPE_BINARY:
            self._record_event(db, task, "firmware_items_initialized", f"已初始化 {len(input_files)} 个固件输入")
        else:
            self._record_event(db, task, "source_tree_initialized", f"已初始化源码工程输入，共 {len(input_files)} 个文件")
        db.commit()
        return self.get_task_detail(db, project_id=project_id, task_id=task_id)

    def list_tasks(self, db: Session, *, project_id: str, status: str | None = None, task_type: str | None = None) -> BinarySecurityTaskListResponse:
        query = db.query(BinarySecurityTask).filter(BinarySecurityTask.project_id == project_id)
        if status:
            query = query.filter(BinarySecurityTask.status == status)
        if task_type:
            normalized_task_type = self._validate_task_type(task_type)
            if normalized_task_type == TASK_TYPE_BINARY:
                query = query.filter(
                    or_(
                        BinarySecurityTask.task_type == TASK_TYPE_BINARY,
                        BinarySecurityTask.task_type.is_(None),
                    )
                )
            else:
                query = query.filter(BinarySecurityTask.task_type == normalized_task_type)
        tasks = query.order_by(BinarySecurityTask.created_at.desc()).all()
        queue_info = self._build_queue_info(db, project_id=project_id)
        service_config = self._load_service_config(db)
        return BinarySecurityTaskListResponse(
            total=len(tasks),
            running_count=queue_info["running_count"],
            queued_count=queue_info["queued_count"],
            max_concurrent_tasks=service_config.max_concurrent_tasks,
            items=[self._task_response(db, task, queue_info=queue_info) for task in tasks],
        )

    def get_task_detail(self, db: Session, *, project_id: str, task_id: str) -> BinarySecurityTaskDetailResponse:
        task = self._task_or_404(db, project_id, task_id)
        items = db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.task_id == task.id).order_by(
            BinarySecurityStageItem.created_at.asc()
        ).all()
        queue_info = self._build_queue_info(db, project_id=project_id)
        base = self._task_response(db, task, queue_info=queue_info).model_dump()
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
        task.dispatcher_instance_id = None
        task.dispatch_started_at = None
        task.finished_at = _now()
        self._record_event(db, task, "task_cancelled", "任务已取消")
        running_items = db.query(BinarySecurityStageItem).filter(
            BinarySecurityStageItem.task_id == task.id,
            BinarySecurityStageItem.status.in_(["pending", "queued", "running"]),
        ).all()
        for item in running_items:
            item.status = "cancelled"
            item.finished_at = _now()
        self._write_task_metadata(task, Path(task.workspace_root) / "input" / "task-metadata.json", status="cancelled")
        db.commit()
        token = self._service_token()
        await asyncio.gather(
            *(self._cancel_downstream(item, token) for item in running_items if item.downstream_task_id),
            return_exceptions=True,
        )

    def retry_task(self, db: Session, *, project_id: str, task_id: str) -> None:
        task = self._task_or_404(db, project_id, task_id)
        if task.status in {"pending_upload", "uploading"}:
            return
        input_files = task.summary.get("input_files") or []
        task.status = "pending"
        task.current_stage = self._stage_sequence_for_task(task)[0]
        task.execution_mode = None
        task.target_stage_name = None
        task.last_error = None
        task.dispatcher_instance_id = None
        task.dispatch_started_at = None
        task.started_at = None
        task.finished_at = None
        task.summary = {
            **task.summary,
            "downstream_task_ids": {},
            "firmware_unpack_results": [],
            "system_analysis_results": [],
            "high_risk_modules": [],
            "b2s_results": [],
            "entry_results": [],
            "dataflow_results": [],
            "vuln_results": [],
            "stale_stages": [],
            "stale_reason": None,
            "stale_from_stage": None,
            "stage_retry_context": {},
        }
        task.metrics = {
            **task.metrics,
            "high_risk_module_count": 0,
            "entry_count": 0,
            "vuln_result_count": 0,
            "firmware_item_count": len(input_files),
            "unpacked_firmware_count": 0,
            "failed_firmware_count": 0,
        }
        db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).delete(synchronize_session=False)
        db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.task_id == task.id).delete(synchronize_session=False)
        self._write_task_metadata(task, Path(task.workspace_root) / "input" / "task-metadata.json", status="pending")
        self._record_event(db, task, "task_retried", "任务已重置并重新进入调度队列")
        db.commit()

    def retry_stage(self, db: Session, *, project_id: str, task_id: str, stage_name: str) -> None:
        task = self._task_or_404(db, project_id, task_id)
        stage_sequence = self._stage_sequence_for_task(task)
        if stage_name not in stage_sequence:
            raise ValidationError(f"无效阶段: {stage_name}")
        if task.status in STAGE_RETRY_BLOCKED_TASK_STATUSES:
            raise ValidationError(f"当前任务状态不允许阶段重试: {task.status}")
        stage_run = db.query(BinarySecurityStageRun).filter(
            BinarySecurityStageRun.task_id == task.id,
            BinarySecurityStageRun.stage_name == stage_name,
        ).first()
        if not stage_run:
            raise ValidationError("目标阶段尚未执行，不能重试")
        if stage_run.status not in STAGE_RETRY_ALLOWED_STATUSES:
            raise ValidationError(f"当前阶段状态不允许重试: {stage_run.status}")

        previous_items = db.query(BinarySecurityStageItem).filter(
            BinarySecurityStageItem.task_id == task.id,
            BinarySecurityStageItem.stage_name == stage_name,
        ).all()
        previous_snapshot = {
            item.item_key: {
                "id": item.id,
                "item_key": item.item_key,
                "item_name": item.item_name,
                "parent_key": item.parent_key,
                "status": item.status,
                "downstream_service": item.downstream_service,
                "downstream_task_id": item.downstream_task_id,
                "input_ref": item.input_ref,
                "output_ref": item.output_ref,
                "payload": item.payload,
                "result": item.result,
                "error_message": item.error_message,
            }
            for item in previous_items
        }
        downstream_stale = stage_sequence[stage_sequence.index(stage_name) + 1 :]
        summary = dict(task.summary or {})
        stage_retry_context = dict(summary.get("stage_retry_context") or {})
        stage_retry_context[stage_name] = previous_snapshot
        for summary_key in STAGE_SUMMARY_RESULT_KEYS.get(stage_name, []):
            summary.pop(summary_key, None)
        summary["stage_retry_context"] = stage_retry_context
        summary["stale_reason"] = "upstream_stage_retried"
        summary["stale_from_stage"] = stage_name
        summary["stale_stages"] = downstream_stale
        task.summary = summary

        metrics = dict(task.metrics or {})
        metrics.update(STAGE_METRIC_RESETTERS.get(stage_name, {}))
        task.metrics = metrics
        stage_summary = dict(task.stage_summary or {})
        stage_summary.pop(stage_name, None)
        task.stage_summary = stage_summary

        db.query(BinarySecurityStageItem).filter(
            BinarySecurityStageItem.task_id == task.id,
            BinarySecurityStageItem.stage_name == stage_name,
        ).delete(synchronize_session=False)
        stage_run.status = "pending"
        stage_run.retry_count = int(stage_run.retry_count or 0) + 1
        stage_run.started_at = None
        stage_run.finished_at = None
        stage_run.last_error = None
        stage_run.input_snapshot = {}
        stage_run.output_summary = {}
        stage_run.counts = {}
        stage_run.downstream_refs = {}

        task.execution_mode = "stage_retry"
        task.target_stage_name = stage_name
        task.status = "pending"
        task.current_stage = stage_name
        task.last_error = None
        task.dispatcher_instance_id = None
        task.dispatch_started_at = None
        task.finished_at = None
        self._write_task_metadata(task, Path(task.workspace_root) / "input" / "task-metadata.json", status="pending")
        self._record_event(
            db,
            task,
            "stage_retry_requested",
            f"请求重试阶段: {stage_name}",
            stage_name=stage_name,
            payload={"downstream_stale": downstream_stale},
        )
        if downstream_stale:
            self._record_event(
                db,
                task,
                "downstream_marked_stale",
                f"阶段 {stage_name} 之后的结果已标记过期",
                stage_name=stage_name,
                level="warning",
                payload={"stale_stages": downstream_stale},
            )
        db.commit()

    def resume_task(self, db: Session, *, project_id: str, task_id: str) -> None:
        task = self._task_or_404(db, project_id, task_id)
        if task.status == "ready_to_start":
            self.start_task(db, project_id=project_id, task_id=task_id)
            return
        if task.status not in {"failed", "partial_success", "cancelled"}:
            return
        task.current_stage = self._next_incomplete_stage(db, task) or self._stage_sequence_for_task(task)[0]
        task.status = "pending"
        task.execution_mode = None
        task.target_stage_name = None
        task.last_error = None
        task.dispatcher_instance_id = None
        task.dispatch_started_at = None
        task.finished_at = None
        self._write_task_metadata(task, Path(task.workspace_root) / "input" / "task-metadata.json", status="pending")
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

    def get_service_config(self, db: Session) -> BinarySecurityServiceConfigResponse:
        return BinarySecurityServiceConfigResponse(config=self._load_service_config(db))

    def save_service_config(self, db: Session, payload: BinarySecurityServiceConfigPayload) -> BinarySecurityServiceConfigResponse:
        row = db.query(BinarySecurityServiceConfig).filter(BinarySecurityServiceConfig.config_key == "global").first()
        if row is None:
            row = BinarySecurityServiceConfig(config_key="global")
            db.add(row)
        row.config = payload.model_dump(mode="json")
        db.commit()
        return BinarySecurityServiceConfigResponse(config=payload)

    async def _dispatch_loop(self) -> None:
        session_factory = get_session_factory()
        while self._running:
            db = session_factory()
            try:
                claimed_ids = self._dispatch_once(db)
                if claimed_ids:
                    async with self._worker_lock:
                        for task_id in claimed_ids:
                            if task_id in self._workers and not self._workers[task_id].done():
                                continue
                            self._workers[task_id] = asyncio.create_task(self._run_task(task_id), name=f"binary-security-{task_id}")
            finally:
                db.close()
            await asyncio.sleep(self.cfg.scheduler.poll_interval_seconds)

    def _dispatch_once(self, db: Session) -> list[str]:
        lock_name = "secflow_binary_security_dispatch_lock"
        locked = bool(db.execute(text("SELECT GET_LOCK(:name, :timeout)"), {"name": lock_name, "timeout": 1}).scalar())
        if not locked:
            db.rollback()
            return []
        try:
            stale_reclaimed = self._reclaim_stale_dispatching_locked(db)
            service_config = self._load_service_config(db)
            active_count = self._active_dispatch_count(db)
            slots = max(0, service_config.max_concurrent_tasks - active_count)
            claimed_ids = self._claim_pending_tasks(db, slots)
            if stale_reclaimed and not claimed_ids:
                db.commit()
            return claimed_ids
        finally:
            db.execute(text("SELECT RELEASE_LOCK(:name)"), {"name": lock_name})
            db.commit()

    async def _run_task(self, task_id: str) -> None:
        session_factory = get_session_factory()
        db = session_factory()
        try:
            task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == task_id).first()
            if (
                task is None
                or task.status != "dispatching"
                or task.dispatcher_instance_id != self.instance_id
            ):
                return
            if task.started_at is None:
                task.started_at = _now()
            task.dispatch_started_at = task.dispatch_started_at or _now()
            task.status = "running"
            self._record_event(
                db,
                task,
                "task_dispatched",
                f"任务由实例 {self.instance_id} 启动执行",
                payload={"dispatcher_instance_id": self.instance_id},
            )
            db.commit()
            await self._execute_task(task_id)
        except Exception as exc:
            task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == task_id).first()
            if task:
                task.status = "failed"
                task.last_error = str(exc)
                task.dispatcher_instance_id = None
                task.dispatch_started_at = None
                task.finished_at = _now()
                self._record_event(db, task, "task_failed", f"任务执行失败: {exc}", level="error")
                db.commit()
        finally:
            async with self._worker_lock:
                self._workers.pop(task_id, None)
            db.close()

    async def _execute_task(self, task_id: str) -> None:
        session_factory = get_session_factory()
        db = session_factory()
        try:
            task = db.query(BinarySecurityTask).filter(BinarySecurityTask.id == task_id).first()
            if not task:
                return
            token = self._service_token()
            stage_sequence = self._stage_sequence_for_task(task)
            start_index = stage_sequence.index(task.current_stage) if task.current_stage in stage_sequence else 0
            stage_retry_mode = task.execution_mode == "stage_retry" and bool(task.target_stage_name)
            target_stage_name = task.target_stage_name if stage_retry_mode else None
            for stage_name in stage_sequence[start_index:]:
                if stage_retry_mode and stage_name != target_stage_name:
                    continue
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
                if stage_retry_mode:
                    self._record_event(db, task, "stage_retry_started", f"阶段开始重试: {stage_name}", stage_name=stage_name)
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
                if stage_name == "firmware_unpack":
                    task.metrics = {
                        **task.metrics,
                        "unpacked_firmware_count": int(summary.get("success_count", 0)),
                        "failed_firmware_count": int(summary.get("failed_count", 0)),
                    }
                elif stage_name == "system_analysis":
                    task.metrics = {**task.metrics, "high_risk_module_count": int(summary.get("module_count", 0))}
                elif stage_name == "entry_analysis":
                    task.metrics = {**task.metrics, "entry_count": int(summary.get("entry_count", 0))}
                elif stage_name == "vuln_scan":
                    task.metrics = {**task.metrics, "vuln_result_count": int(summary.get("vuln_result_count", 0))}
                db.commit()
                if stage_retry_mode:
                    self._record_event(
                        db,
                        task,
                        "stage_retry_finished",
                        f"阶段重试完成: {stage_name}",
                        stage_name=stage_name,
                        payload={"status": status},
                    )
                    break
                if status == "failed":
                    task.last_error = summary.get("error")
                    self._record_event(db, task, "stage_failed", f"阶段失败，停止后续推进: {stage_name}", level="error", stage_name=stage_name)
                    db.commit()
                    break
            if stage_retry_mode:
                task.execution_mode = None
                task.target_stage_name = None
                summary = dict(task.summary or {})
                summary.pop("stage_retry_context", None)
                task.summary = summary
            self._finalize_task(db, task)
            self._write_task_metadata(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
            db.commit()
        finally:
            db.close()

    def _load_service_config(self, db: Session) -> BinarySecurityServiceConfigPayload:
        row = db.query(BinarySecurityServiceConfig).filter(BinarySecurityServiceConfig.config_key == "global").first()
        raw = row.config if row else {}
        return BinarySecurityServiceConfigPayload(**raw)

    def _active_dispatch_count(self, db: Session) -> int:
        return int(
            db.query(func.count(BinarySecurityTask.id))
            .filter(BinarySecurityTask.status.in_(["dispatching", "running"]))
            .scalar()
            or 0
        )

    def _claim_pending_tasks(self, db: Session, slots: int) -> list[str]:
        if slots <= 0:
            return []
        candidates = (
            db.query(BinarySecurityTask.id)
            .filter(BinarySecurityTask.status == "pending")
            .order_by(BinarySecurityTask.created_at.asc(), BinarySecurityTask.id.asc())
            .limit(slots)
            .all()
        )
        claimed: list[str] = []
        dispatch_started_at = _now()
        for row in candidates:
            task_id = row[0]
            updated = (
                db.query(BinarySecurityTask)
                .filter(
                    BinarySecurityTask.id == task_id,
                    BinarySecurityTask.status == "pending",
                )
                .update(
                    {
                        BinarySecurityTask.status: "dispatching",
                        BinarySecurityTask.dispatcher_instance_id: self.instance_id,
                        BinarySecurityTask.dispatch_started_at: dispatch_started_at,
                        BinarySecurityTask.updated_at: dispatch_started_at,
                    },
                    synchronize_session=False,
                )
            )
            if updated:
                claimed.append(task_id)
        if claimed:
            db.flush()
        return claimed

    def _reclaim_stale_dispatching_locked(self, db: Session) -> bool:
        service_config = self._load_service_config(db)
        cutoff = _now().timestamp() - service_config.dispatch_timeout_seconds
        stale_rows = (
            db.query(BinarySecurityTask)
            .filter(
                BinarySecurityTask.status == "dispatching",
                BinarySecurityTask.dispatch_started_at.isnot(None),
            )
            .all()
        )
        if not stale_rows:
            return False
        local_workers = {
            task_id for task_id, worker in self._workers.items()
            if not worker.done()
        }
        reclaimed = False
        for task in stale_rows:
            if task.id in local_workers:
                continue
            if not task.dispatch_started_at or task.dispatch_started_at.timestamp() >= cutoff:
                continue
            task.status = "pending"
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            task.last_error = None
            self._record_event(
                db,
                task,
                "dispatch_reclaimed",
                "调度超时，任务已回收并重新进入队列",
                level="warning",
            )
            reclaimed = True
        if reclaimed:
            db.flush()
        return reclaimed

    def _build_queue_info(self, db: Session, *, project_id: str) -> dict[str, Any]:
        running_count = int(
            db.query(func.count(BinarySecurityTask.id))
            .filter(
                BinarySecurityTask.status.in_(["dispatching", "running"]),
            )
            .scalar()
            or 0
        )
        queued_rows = (
            db.query(BinarySecurityTask.id)
            .filter(
                BinarySecurityTask.status == "pending",
            )
            .order_by(BinarySecurityTask.created_at.asc(), BinarySecurityTask.id.asc())
            .all()
        )
        pending_positions = {row[0]: index + 1 for index, row in enumerate(queued_rows)}
        return {
            "running_count": running_count,
            "queued_count": len(queued_rows),
            "pending_positions": pending_positions,
        }

    def _finalize_task(self, db: Session, task: BinarySecurityTask) -> None:
        if task.status == "cancelled":
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            task.finished_at = _now()
            return
        stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
        statuses = [run.status for run in stage_runs]
        vuln_run = next((run for run in stage_runs if run.stage_name == "vuln_scan"), None)
        non_skipped = [status for status in statuses if status != "skipped"]
        if non_skipped and all(status == "success" for status in non_skipped):
            task.status = "success"
        elif vuln_run and vuln_run.status in {"success", "partial_success"}:
            task.status = "partial_success" if any(status in {"failed", "partial_success"} for status in statuses) else "success"
        elif any(status in {"failed", "partial_success"} for status in statuses):
            task.status = "partial_success" if any(status == "success" for status in non_skipped) else "failed"
        else:
            task.status = "success"
        stale_stages = list((task.summary or {}).get("stale_stages") or [])
        if stale_stages and task.status == "success":
            task.status = "partial_success"
        task.dispatcher_instance_id = None
        task.dispatch_started_at = None
        task.finished_at = _now()
        self._record_event(db, task, "task_finished", f"任务结束: {task.status}")

    def _resolve_output_root(self, workspace_root: Path, custom_output_root: str | None) -> Path:
        if custom_output_root:
            candidate = Path(custom_output_root).resolve()
            return ensure_dir(candidate)
        return ensure_dir(workspace_root / "output")

    def _init_workspace(self, root: Path) -> None:
        for rel in ["input", "output", "run", "logs"]:
            ensure_dir(root / rel)

    async def _ensure_task_directories(self, project_id: str, task_id: str, authorization_token: str) -> None:
        client = get_fileserver_client()
        await client.ensure_project_directory(project_id, "app", authorization_token)
        await client.ensure_project_directory(project_id, "app/secflow-app-binary-security", authorization_token)
        await client.ensure_project_directory(project_id, f"app/secflow-app-binary-security/{task_id}", authorization_token)
        for name in ("input", "output", "run"):
            await client.ensure_project_directory(project_id, f"app/secflow-app-binary-security/{task_id}/{name}", authorization_token)

    def _write_task_metadata(self, task: BinarySecurityTask, metadata_path: Path, *, status: str) -> None:
        _write_json(
            metadata_path,
            {
                "task_id": task.id,
                "project_id": task.project_id,
                "task_type": self._task_type(task),
                "name": task.name,
                "description": task.description,
                "created_by": task.created_by,
                "created_at": task.created_at.isoformat() if task.created_at else None,
                "status": status,
                "input_files": task.summary.get("input_files", []),
                "input_kind": task.summary.get("input_kind"),
                "policy": task.policy,
                "stage_options": task.policy.get("stage_options", {}),
                "paths": {
                    "task_root": task.summary.get("task_root_path"),
                    "input_dir": task.summary.get("input_dir"),
                    "output_dir": task.summary.get("output_dir"),
                    "run_dir": task.summary.get("run_dir"),
                },
            },
        )

    def _normalize_input_files(self, files: list[BinarySecurityInputFile | dict[str, Any]], *, task_type: str) -> list[dict[str, Any]]:
        rows = []
        seen_names: set[str] = set()
        seen_paths: set[str] = set()
        seen_keys: set[str] = set()
        for index, raw in enumerate(files):
            item = raw.model_dump(mode="json") if isinstance(raw, BinarySecurityInputFile) else dict(raw)
            filename = str(item.get("filename") or "").strip()
            if not filename:
                raise ValidationError("上传文件名不能为空")
            if "/" in filename or "\\" in filename:
                raise ValidationError(f"文件名不合法: {filename}")
            relative_path_raw = str(item.get("relative_path") or "").strip().replace("\\", "/").strip("/")
            if relative_path_raw:
                path_parts = [part for part in relative_path_raw.split("/") if part]
                if any(part in {".", ".."} for part in path_parts):
                    raise ValidationError(f"相对路径不合法: {relative_path_raw}")
                effective_path = "/".join(path_parts)
                if Path(effective_path).name != filename:
                    effective_path = "/".join([part for part in path_parts[:-1]] + [filename]) if path_parts else filename
            else:
                effective_path = filename
            if task_type == TASK_TYPE_SOURCE:
                if effective_path in seen_paths:
                    raise ValidationError(f"存在重复相对路径: {effective_path}")
                seen_paths.add(effective_path)
            else:
                if filename in seen_names:
                    raise ValidationError(f"存在重复文件名: {filename}")
                seen_names.add(filename)
            firmware_key = _slug(filename)
            if firmware_key in seen_keys:
                firmware_key = _slug(f"{index + 1}-{filename}")
            seen_keys.add(firmware_key)
            rows.append(
                {
                    "filename": filename,
                    "size": int(item.get("size") or 0),
                    "content_type": item.get("content_type"),
                    "relative_path": effective_path,
                    "metadata": item.get("metadata") or {},
                    "firmware_key": firmware_key,
                    "firmware_name": Path(filename).stem or filename,
                }
            )
        if not rows:
            raise ValidationError("至少需要上传一个输入文件")
        return rows

    def _merge_policy(self, db: Session, project_id: str, overrides: dict[str, Any], stage_options: dict[str, Any]) -> dict[str, Any]:
        stage_parallelism = {stage: self.cfg.runtime_policy.max_stage_parallelism for stage in STAGE_SEQUENCE}
        base = BinarySecurityProjectConfigPayload(
            max_stage_parallelism=self.cfg.runtime_policy.max_stage_parallelism,
            max_retries_per_item=self.cfg.runtime_policy.max_retries_per_item,
            continue_on_item_failure=self.cfg.runtime_policy.continue_on_item_failure,
            stage_parallelism=stage_parallelism,
        ).model_dump(mode="json")
        row = db.query(BinarySecurityProjectConfig).filter(BinarySecurityProjectConfig.project_id == project_id).first()
        if row:
            base.update(row.config)
        if stage_options:
            base["stage_options"] = {
                **base.get("stage_options", {}),
                **{key: value.model_dump(mode="json") for key, value in stage_options.items()},
            }
        if overrides.get("max_stage_parallelism") is not None:
            stage_value = int(overrides["max_stage_parallelism"])
            base["max_stage_parallelism"] = stage_value
            base["stage_parallelism"] = {stage: stage_value for stage in STAGE_SEQUENCE}
        if overrides.get("stage_parallelism"):
            merged = {**base.get("stage_parallelism", {})}
            for stage_name, value in (overrides.get("stage_parallelism") or {}).items():
                if stage_name in STAGE_SEQUENCE and value is not None:
                    merged[stage_name] = int(value)
            base["stage_parallelism"] = merged
        if overrides.get("max_retries_per_item") is not None:
            base["max_retries_per_item"] = int(overrides["max_retries_per_item"])
        if overrides.get("continue_on_item_failure") is not None:
            base["continue_on_item_failure"] = bool(overrides["continue_on_item_failure"])
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

    def _stage_parallelism(self, task: BinarySecurityTask, stage_name: str) -> int:
        policy = task.policy or {}
        stage_parallelism = policy.get("stage_parallelism") or {}
        if stage_name in stage_parallelism:
            return max(1, int(stage_parallelism[stage_name]))
        return max(1, int(policy.get("max_stage_parallelism") or 1))

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
            sequence_no=self._stage_sequence_for_task(task).index(stage_name) + 1,
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

    def _task_response(self, db: Session, task: BinarySecurityTask, queue_info: dict[str, Any] | None = None) -> BinarySecurityTaskResponse:
        stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).order_by(BinarySecurityStageRun.sequence_no.asc()).all()
        metrics = task.metrics or {}
        queue_info = queue_info or {"pending_positions": {}}
        queue_position = queue_info.get("pending_positions", {}).get(task.id)
        stage_sequence = self._stage_sequence_for_task(task)
        return BinarySecurityTaskResponse(
            id=task.id,
            project_id=task.project_id,
            task_type=self._task_type(task),
            name=task.name,
            status=task.status,
            current_stage=task.current_stage,
            firmware_path=task.firmware_path,
            stage_sequence=stage_sequence,
            is_queued=task.status == "pending",
            queue_position=queue_position,
            dispatcher_instance_id=task.dispatcher_instance_id,
            created_by=task.created_by,
            created_at=task.created_at,
            updated_at=task.updated_at,
            started_at=task.started_at,
            finished_at=task.finished_at,
            high_risk_module_count=int(metrics.get("high_risk_module_count", 0)),
            entry_count=int(metrics.get("entry_count", 0)),
            vuln_result_count=int(metrics.get("vuln_result_count", 0)),
            firmware_item_count=int(metrics.get("firmware_item_count", 0)),
            unpacked_firmware_count=int(metrics.get("unpacked_firmware_count", 0)),
            failed_firmware_count=int(metrics.get("failed_firmware_count", 0)),
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
                if run.stage_name in stage_sequence
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

    def _next_incomplete_stage(self, db: Session, task: BinarySecurityTask) -> str | None:
        stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
        completed = {run.stage_name for run in stage_runs if run.status in {"success", "skipped"}}
        for stage_name in self._stage_sequence_for_task(task):
            if stage_name not in completed:
                return stage_name
        return None

    def _retry_snapshot_for_item(self, task: BinarySecurityTask, stage_name: str, item_key: str) -> dict[str, Any] | None:
        summary = task.summary or {}
        stage_context = (summary.get("stage_retry_context") or {}).get(stage_name) or {}
        snapshot = stage_context.get(item_key)
        return dict(snapshot) if isinstance(snapshot, dict) else None

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

    async def _poll_until_terminal(self, fetcher, *, success_statuses: set[str], failure_statuses: set[str], task: BinarySecurityTask, item: BinarySecurityStageItem | None = None):
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
        input_files = list(task.summary.get("input_files") or [])
        if not input_files:
            return "failed", {"error": "缺少输入文件"}
        results = await self._run_stage_pool(
            task,
            input_files,
            self._stage_parallelism(task, stage_run.stage_name),
            lambda input_file: self._run_firmware_item(task, stage_run, input_file, token),
            retries=int(task.policy.get("max_retries_per_item") or 0),
        )
        status, summary = self._aggregate_stage_items(db, task, results, "firmware_unpack_results")
        return status, summary

    async def _run_firmware_item(self, task: BinarySecurityTask, stage_run: BinarySecurityStageRun, input_file: dict[str, Any], token: str | None) -> dict[str, Any]:
        session = get_session_factory()()
        try:
            firmware_key = input_file["firmware_key"]
            input_path = Path(task.workspace_root) / "input" / input_file["filename"]
            output_dir = Path(task.output_root) / firmware_key / "unpack"
            ensure_dir(output_dir)
            retry_snapshot = self._retry_snapshot_for_item(task, stage_run.stage_name, firmware_key)
            item = BinarySecurityStageItem(
                id=f"si_{uuid.uuid4().hex[:20]}",
                task_id=task.id,
                project_id=task.project_id,
                stage_run_id=stage_run.id,
                stage_name=stage_run.stage_name,
                item_key=firmware_key,
                item_name=input_file["filename"],
                parent_key=firmware_key,
                status="queued",
                downstream_service="firmware_unpacker",
            )
            item.input_ref = {"filename": input_file["filename"], "path": str(input_path)}
            item.output_ref = {"output_path": str(output_dir)}
            session.add(item)
            session.commit()
            created = None
            previous_task_id = retry_snapshot.get("downstream_task_id") if retry_snapshot else None
            if previous_task_id:
                try:
                    created = await get_firmware_unpacker_client().retry_task(previous_task_id, token or "")
                except Exception:
                    try:
                        await get_firmware_unpacker_client().delete_task(previous_task_id, token or "")
                    except Exception:
                        pass
            if created is None:
                created = await get_firmware_unpacker_client().create_task(task.project_id, str(input_path), str(output_dir), token or "")
            item.status = "running"
            item.downstream_task_id = created.get("task_id") or previous_task_id
            item.started_at = _now()
            item.result = {"project_id": task.project_id}
            session.commit()
            status, payload = await self._poll_until_terminal(
                lambda: get_firmware_unpacker_client().get_task(task.project_id, item.downstream_task_id, token or ""),
                success_statuses={"success"},
                failure_statuses={"failed", "cancelled"},
                task=task,
                item=item,
            )
            item.finished_at = _now()
            item.status = "success" if status == "success" else "cancelled" if status == "cancelled" else "failed"
            result = {
                **input_file,
                "input_path": str(input_path),
                "unpacked_root": str(output_dir),
                "downstream": payload,
            }
            item.result = result
            item.output_ref = {"unpacked_root": str(output_dir)}
            session.commit()
            return {"status": item.status, "item": result, "error": payload.get("error") or payload.get("error_message")}
        except Exception as exc:
            if "item" in locals():
                item.status = "failed"
                item.error_message = str(exc)
                item.finished_at = _now()
                session.commit()
            return {"status": "failed", "error": str(exc), "item": input_file}
        finally:
            session.close()

    async def _stage_system_analysis(self, db: Session, task: BinarySecurityTask, stage_run: BinarySecurityStageRun, token: str | None) -> tuple[str, dict[str, Any]]:
        del token
        system_inputs = self._system_analysis_inputs(task)
        if not system_inputs:
            return "failed", {"error": "缺少可用于系统分析的输入"}
        results = await self._run_stage_pool(
            task,
            system_inputs,
            self._stage_parallelism(task, stage_run.stage_name),
            lambda analysis_input: self._run_system_analysis_item(task, stage_run, analysis_input),
            retries=int(task.policy.get("max_retries_per_item") or 0),
        )
        success = [result["item"] for result in results if result.get("status") == "success"]
        failed = [result for result in results if result.get("status") == "failed"]
        all_modules = []
        for result in success:
            all_modules.extend(result.get("modules", []))
        task.summary = {
            **task.summary,
            "system_analysis_results": success,
            "high_risk_modules": all_modules,
        }
        db.commit()
        status = "success"
        if failed and success:
            status = "partial_success"
        elif failed:
            status = "failed"
        return status, {
            "items": success,
            "failed_items": failed,
            "success_count": len(success),
            "failed_count": len(failed),
            "module_count": len(all_modules),
            "error": failed[0].get("error") if failed else None,
        }

    def _system_analysis_inputs(self, task: BinarySecurityTask) -> list[dict[str, Any]]:
        if self._task_type(task) == TASK_TYPE_SOURCE:
            input_dir = Path(task.workspace_root) / "input"
            if not input_dir.exists():
                return []
            return [
                {
                    "firmware_key": SOURCE_TASK_INPUT_KEY,
                    "firmware_name": task.name,
                    "filename": "source-project",
                    "unpacked_root": str(input_dir),
                    "source_root": str(input_dir),
                    "task_type": TASK_TYPE_SOURCE,
                }
            ]
        return list(task.summary.get("firmware_unpack_results") or [])

    async def _run_system_analysis_item(self, task: BinarySecurityTask, stage_run: BinarySecurityStageRun, firmware: dict[str, Any]) -> dict[str, Any]:
        session = get_session_factory()()
        try:
            retry_snapshot = self._retry_snapshot_for_item(task, stage_run.stage_name, firmware["firmware_key"])
            item = BinarySecurityStageItem(
                id=f"si_{uuid.uuid4().hex[:20]}",
                task_id=task.id,
                project_id=task.project_id,
                stage_run_id=stage_run.id,
                stage_name=stage_run.stage_name,
                item_key=firmware["firmware_key"],
                item_name=firmware["filename"],
                parent_key=firmware["firmware_key"],
                status="running",
                downstream_service="system_analyse",
                started_at=_now(),
            )
            item.input_ref = {"input_path": firmware["unpacked_root"], "firmware_key": firmware["firmware_key"]}
            session.add(item)
            session.commit()
            created = None
            previous_task_id = retry_snapshot.get("downstream_task_id") if retry_snapshot else None
            if previous_task_id:
                try:
                    created = await get_system_analyse_client().restart_task(previous_task_id)
                except Exception:
                    try:
                        await get_system_analyse_client().cancel_task(previous_task_id)
                    except Exception:
                        pass
            if created is None:
                created = await get_system_analyse_client().create_task(
                    task.project_id,
                    f"{task.name}-{firmware['firmware_name']}-system-analysis",
                    firmware["unpacked_root"],
                )
            item.downstream_task_id = created.get("task_id") or previous_task_id
            session.commit()
            status, payload = await self._poll_until_terminal(
                lambda: get_system_analyse_client().get_task(item.downstream_task_id),
                success_statuses={"passed", "success"},
                failure_statuses={"failed", "error", "cancelled"},
                task=task,
                item=item,
            )
            artifact_root = Path(task.output_root) / firmware["firmware_key"] / "system-analysis"
            materialized = self._materialize_stage_artifact(artifact_root, item.downstream_task_id, payload)
            modules = self._parse_system_analysis_modules(materialized, firmware)
            item.finished_at = _now()
            item.status = "success" if status == "success" else "cancelled" if status == "cancelled" else "failed"
            result = {
                **firmware,
                "artifact_root": str(materialized),
                "modules": modules,
                "downstream": payload,
            }
            item.result = result
            item.output_ref = {"artifact_root": str(materialized)}
            session.commit()
            return {"status": item.status, "item": result, "error": payload.get("error") or payload.get("error_message")}
        except Exception as exc:
            if "item" in locals():
                item.status = "failed"
                item.error_message = str(exc)
                item.finished_at = _now()
                session.commit()
            return {"status": "failed", "error": str(exc), "item": firmware}
        finally:
            session.close()

    def _parse_system_analysis_modules(self, root: Path, firmware: dict[str, Any]) -> list[dict[str, Any]]:
        modules_list = root / "modules.list"
        modules_dir = root / "modules"
        items: list[dict[str, Any]] = []
        names = [line.strip() for line in _read_text(modules_list).splitlines() if line.strip()]
        if not names and modules_dir.is_dir():
            names = [path.name for path in sorted(p for p in modules_dir.iterdir() if p.is_dir())]
        if not names and self._task_type(firmware.get("task_type")) == TASK_TYPE_SOURCE:
            names = ["source-project"]
        for name in names:
            module_dir = modules_dir / name
            source_dir = module_dir if module_dir.is_dir() else Path(str(firmware.get("source_root") or firmware.get("unpacked_root") or root))
            module_key = _slug(f"{firmware['firmware_key']}-{name}")
            items.append(
                {
                    "firmware_key": firmware["firmware_key"],
                    "firmware_name": firmware["firmware_name"],
                    "filename": firmware["filename"],
                    "unpacked_root": firmware["unpacked_root"],
                    "source_root": firmware.get("source_root") or firmware.get("unpacked_root"),
                    "task_type": firmware.get("task_type", TASK_TYPE_BINARY),
                    "module_key": module_key,
                    "module_name": name,
                    "module_dir": str(module_dir),
                    "source_dir": str(source_dir),
                    "module_report": str(module_dir / "module_report.md"),
                    "files_list": str(module_dir / "files.list"),
                }
            )
        _write_json(root / "high_risk_modules.json", {"items": items})
        return items

    def _materialize_stage_artifact(self, artifact_root: Path, downstream_task_id: str | None, payload: dict[str, Any]) -> Path:
        ensure_dir(artifact_root)
        candidates: list[Path] = []
        for key in ("artifact_root", "result_root", "workspace_root", "output_path"):
            value = payload.get(key)
            if not value:
                continue
            raw = Path(str(value))
            if key == "output_path" and downstream_task_id and raw.exists() and (raw / downstream_task_id).exists():
                candidates.append(raw / downstream_task_id)
            else:
                candidates.append(raw)
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
            self._stage_parallelism(task, stage_run.stage_name),
            lambda module: self._run_b2s_item(task, stage_run, module, token),
            retries=int(task.policy.get("max_retries_per_item") or 0),
        )
        return self._aggregate_stage_items(db, task, results, "b2s_results")

    async def _stage_entry_analysis(self, db: Session, task: BinarySecurityTask, stage_run: BinarySecurityStageRun, token: str | None) -> tuple[str, dict[str, Any]]:
        b2s_success = self._entry_analysis_inputs(task)
        if not b2s_success:
            return "failed", {"error": "没有可用于入口分析的源码模块"}
        results = await self._run_stage_pool(
            task,
            b2s_success,
            self._stage_parallelism(task, stage_run.stage_name),
            lambda module: self._run_entry_item(task, stage_run, module, token),
            retries=int(task.policy.get("max_retries_per_item") or 0),
        )
        status, summary = self._aggregate_stage_items(db, task, results, "entry_results")
        summary["entry_count"] = sum(len(item.get("entries") or []) for item in summary.get("items", []))
        return status, summary

    def _entry_analysis_inputs(self, task: BinarySecurityTask) -> list[dict[str, Any]]:
        if self._task_type(task) == TASK_TYPE_SOURCE:
            return list(task.summary.get("high_risk_modules") or [])
        return list(task.summary.get("b2s_results") or [])

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
            self._stage_parallelism(task, stage_run.stage_name),
            lambda entry: self._run_dataflow_item(task, stage_run, entry, token),
            retries=int(task.policy.get("max_retries_per_item") or 0),
        )
        return self._aggregate_stage_items(db, task, results, "dataflow_results")

    async def _stage_vuln_scan(self, db: Session, task: BinarySecurityTask, stage_run: BinarySecurityStageRun, token: str | None) -> tuple[str, dict[str, Any]]:
        dataflow_results = list(task.summary.get("dataflow_results") or [])
        if not dataflow_results:
            return "failed", {"error": "没有可用于漏洞扫描的数据流结果"}
        results = await self._run_stage_pool(
            task,
            dataflow_results,
            self._stage_parallelism(task, stage_run.stage_name),
            lambda result: self._run_vuln_item(task, stage_run, result, token),
            retries=int(task.policy.get("max_retries_per_item") or 0),
        )
        status, summary = self._aggregate_stage_items(db, task, results, "vuln_results")
        summary["vuln_result_count"] = len(summary.get("items", []))
        return status, summary

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
            retry_snapshot = self._retry_snapshot_for_item(task, stage_run.stage_name, module["module_key"])
            item = BinarySecurityStageItem(
                id=f"si_{uuid.uuid4().hex[:20]}",
                task_id=task.id,
                project_id=task.project_id,
                stage_run_id=stage_run.id,
                stage_name=stage_run.stage_name,
                item_key=module["module_key"],
                item_name=module["module_name"],
                parent_key=module["firmware_key"],
                status="running",
                downstream_service="binary_to_source",
                started_at=_now(),
            )
            item.input_ref = module
            session.add(item)
            session.commit()
            elf_path = self._choose_module_binary(module)
            created = None
            previous_task_id = retry_snapshot.get("downstream_task_id") if retry_snapshot else None
            if previous_task_id:
                try:
                    created = await get_binary_to_source_client().retry_task(task.project_id, previous_task_id, token or "")
                except Exception:
                    try:
                        await get_binary_to_source_client().terminate_task(task.project_id, previous_task_id, token or "")
                    except Exception:
                        pass
            if created is None:
                created = await get_binary_to_source_client().create_task(
                    task.project_id,
                    f"{task.name}-{module['module_name']}",
                    elf_path,
                    token or "",
                    module,
                )
            item.downstream_task_id = created.get("id") or previous_task_id
            item.result = {"project_id": task.project_id}
            session.commit()
            status, payload = await self._poll_until_terminal(
                lambda: get_binary_to_source_client().get_task(task.project_id, item.downstream_task_id, token or ""),
                success_statuses={"success", "partial_success"},
                failure_statuses={"failed", "cancelled"},
                task=task,
                item=item,
            )
            artifact_root = Path(task.output_root) / module["firmware_key"] / "b2s" / module["module_key"]
            ensure_dir(artifact_root)
            generated_files = []
            for child in payload.get("items", []):
                for file_path in child.get("generated_files") or []:
                    src = Path(file_path)
                    if src.exists():
                        target = artifact_root / src.name
                        _copytree(src, target)
                        generated_files.append(str(target))
            result = {
                **module,
                "source_dir": str(artifact_root),
                "generated_files": generated_files,
                "downstream": payload,
            }
            item.status = "success" if status == "success" else "cancelled" if status == "cancelled" else "failed"
            item.finished_at = _now()
            item.result = result
            item.output_ref = {"source_dir": str(artifact_root)}
            session.commit()
            return {"status": item.status, "item": result, "error": payload.get("error") or payload.get("error_message")}
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
        unpacked_root = Path(str(module["unpacked_root"]))
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
        del token
        session = get_session_factory()()
        try:
            retry_snapshot = self._retry_snapshot_for_item(task, stage_run.stage_name, module["module_key"])
            item = BinarySecurityStageItem(
                id=f"si_{uuid.uuid4().hex[:20]}",
                task_id=task.id,
                project_id=task.project_id,
                stage_run_id=stage_run.id,
                stage_name=stage_run.stage_name,
                item_key=module["module_key"],
                item_name=module["module_name"],
                parent_key=module["firmware_key"],
                status="running",
                downstream_service="entry_analyse",
                started_at=_now(),
            )
            item.input_ref = module
            session.add(item)
            session.commit()
            created = None
            previous_task_id = retry_snapshot.get("downstream_task_id") if retry_snapshot else None
            if previous_task_id:
                try:
                    created = await get_entry_analyse_client().restart_task(previous_task_id)
                except Exception:
                    try:
                        await get_entry_analyse_client().cancel_task(previous_task_id)
                    except Exception:
                        pass
            if created is None:
                created = await get_entry_analyse_client().create_task(
                    task.project_id,
                    f"{task.name}-{module['module_name']}-entry",
                    module["source_dir"],
                )
            item.downstream_task_id = created.get("task_id") or previous_task_id
            session.commit()
            status, payload = await self._poll_until_terminal(
                lambda: get_entry_analyse_client().get_task(item.downstream_task_id),
                success_statuses={"passed", "success"},
                failure_statuses={"failed", "error", "cancelled"},
                task=task,
                item=item,
            )
            artifact_root = Path(task.output_root) / module["firmware_key"] / "entry" / module["module_key"]
            materialized = self._materialize_stage_artifact(artifact_root, item.downstream_task_id, payload)
            entries = self._parse_entries(materialized, module)
            result = {
                **module,
                "artifact_root": str(materialized),
                "entries": entries,
                "source_dir": module["source_dir"],
                "downstream": payload,
            }
            item.status = "success" if status == "success" else "cancelled" if status == "cancelled" else "failed"
            item.finished_at = _now()
            item.result = result
            item.output_ref = {"artifact_root": str(materialized)}
            session.commit()
            return {"status": item.status, "item": result, "error": payload.get("error") or payload.get("error_message")}
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
                            "firmware_key": module["firmware_key"],
                            "firmware_name": module["firmware_name"],
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
                            "firmware_key": module["firmware_key"],
                            "firmware_name": module["firmware_name"],
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
        del token
        session = get_session_factory()()
        try:
            retry_snapshot = self._retry_snapshot_for_item(task, stage_run.stage_name, entry["entry_key"])
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
            created = None
            previous_task_id = retry_snapshot.get("downstream_task_id") if retry_snapshot else None
            if previous_task_id:
                try:
                    created = await get_dataflow_analyse_client().restart_task(previous_task_id)
                except Exception:
                    try:
                        await get_dataflow_analyse_client().cancel_task(previous_task_id)
                    except Exception:
                        pass
            if created is None:
                created = await get_dataflow_analyse_client().create_task(
                    task.project_id,
                    f"{task.name}-{entry['function_name']}-dfa",
                    entry["source_dir"],
                    prompt,
                )
            item.downstream_task_id = created.get("task_id") or previous_task_id
            session.commit()
            status, payload = await self._poll_until_terminal(
                lambda: get_dataflow_analyse_client().get_task(item.downstream_task_id),
                success_statuses={"passed", "success"},
                failure_statuses={"failed", "error", "cancelled"},
                task=task,
                item=item,
            )
            artifact_root = Path(task.output_root) / entry["firmware_key"] / "dataflow" / entry["entry_key"]
            materialized = self._materialize_stage_artifact(artifact_root, item.downstream_task_id, payload)
            data_flow_file = self._find_first(materialized, [r"dataflow-.*\.md", r".*result.*\.md", r"report\.md"])
            result = {
                **entry,
                "artifact_root": str(materialized),
                "data_flow_file": str(data_flow_file) if data_flow_file else "",
                "downstream": payload,
            }
            item.status = "success" if status == "success" else "cancelled" if status == "cancelled" else "failed"
            item.finished_at = _now()
            item.result = result
            item.output_ref = {"artifact_root": str(materialized), "data_flow_file": result["data_flow_file"]}
            session.commit()
            return {"status": item.status, "item": result, "error": payload.get("error") or payload.get("error_message")}
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
            retry_snapshot = self._retry_snapshot_for_item(task, stage_run.stage_name, dataflow_result["entry_key"])
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
            vuln_workspace = Path(task.output_root) / dataflow_result["firmware_key"] / "vuln" / dataflow_result["entry_key"] / "workspace"
            vuln_output = vuln_workspace / "output"
            ensure_dir(vuln_output)
            created = None
            previous_task_id = retry_snapshot.get("downstream_task_id") if retry_snapshot else None
            if previous_task_id:
                try:
                    created = await get_dataflow_vuln_scanner_client().retry_task(previous_task_id, token or "")
                except Exception:
                    try:
                        await get_dataflow_vuln_scanner_client().cancel_task(previous_task_id, token or "")
                    except Exception:
                        pass
            if created is None:
                created = await get_dataflow_vuln_scanner_client().create_task(
                    task.project_id,
                    f"{task.name}-{dataflow_result['function_name']}-scan",
                    token or "",
                    dataflow_result["data_flow_file"],
                    dataflow_result["source_dir"],
                    str(vuln_workspace),
                    str(vuln_output),
                )
            item.downstream_task_id = created.get("task_id") or previous_task_id
            session.commit()
            status, payload = await self._poll_until_terminal(
                lambda: get_dataflow_vuln_scanner_client().get_task(item.downstream_task_id, token or ""),
                success_statuses={"success", "succeeded", "completed"},
                failure_statuses={"failed", "cancelled"},
                task=task,
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
            item.result = result
            item.output_ref = {"workspace_root": artifacts.get("workspace_root")}
            session.commit()
            return {"status": item.status, "item": result, "error": payload.get("error") or payload.get("error_message")}
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

    def _aggregate_stage_items(self, db: Session, task: BinarySecurityTask, results: list[dict[str, Any]], summary_key: str) -> tuple[str, dict[str, Any]]:
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
            "entry_count": 0,
            "vuln_result_count": 0,
            "error": failed[0].get("error") if failed else cancelled[0].get("error") if cancelled else None,
        }
        task.summary = {**task.summary, summary_key: success}
        db.commit()
        return status, summary

    def _fileserver_task_path(self, task_id: str, suffix: str | None = None) -> str:
        base = f"/app/secflow-app-binary-security/{task_id}"
        if suffix:
            return f"{base}/{suffix.strip('/')}"
        return base


_task_manager: Optional[TaskManager] = None


def get_task_manager() -> TaskManager:
    global _task_manager
    if _task_manager is None:
        _task_manager = TaskManager()
    return _task_manager
