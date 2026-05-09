"""Binary Security task orchestration manager."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tarfile
import uuid
import zipfile
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
    BinarySecurityActionResponse,
    BinarySecurityArtifactsResponse,
    BinarySecurityInputFile,
    BinarySecurityModuleSelectionResponse,
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
from app.time_utils import now_local


def _now() -> datetime:
    return now_local()


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


def _path_has_content(path: Path) -> bool:
    if path.is_file():
        return True
    if not path.is_dir():
        return False
    return any(path.iterdir())


def _count_files(path: Path) -> int:
    if path.is_file():
        return 1
    if not path.is_dir():
        return 0
    return sum(1 for child in path.rglob("*") if child.is_file())


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _is_within_path(base: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def _dedupe_paths(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    unique: list[Path] = []
    for path in paths:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique


def _downstream_origin_payload(task: BinarySecurityTask, item: BinarySecurityStageItem) -> dict[str, Any]:
    return {
        "task_origin_type": "binary_security",
        "parent_project_id": task.project_id,
        "parent_task_id": task.id,
        "parent_task_type": task.task_type,
        "parent_stage_name": item.stage_name,
        "parent_stage_item_id": item.id,
        "parent_stage_item_key": item.item_key,
    }


def _normalize_module_risk_levels(values: list[str] | None) -> list[str]:
    ordered: list[str] = []
    for value in values or []:
        normalized = str(value or "").strip()
        if normalized in ALLOWED_MODULE_RISK_LEVELS and normalized not in ordered:
            ordered.append(normalized)
    return ordered or ["高"]


STAGE_RETRY_ALLOWED_STATUSES = {"success", "failed", "partial_success", "cancelled"}
STAGE_RETRY_BLOCKED_TASK_STATUSES = {"pending", "dispatching", "running", "pending_upload", "uploading", "ready_to_start"}
TASK_STATUS_PENDING_MODULE_CONFIRMATION = "pending_module_confirmation"
MODULE_SELECTION_MODE_AUTO = "auto"
MODULE_SELECTION_MODE_MANUAL_CONFIRM = "manual_confirm"
ALLOWED_MODULE_RISK_LEVELS = ("高", "中", "低")
STAGE_SUMMARY_RESULT_KEYS = {
    "firmware_unpack": ["firmware_unpack_results"],
    "system_analysis": ["system_analysis_results", "high_risk_modules", "system_analysis_modules", "candidate_modules", "selected_modules"],
    "binary_to_source": ["b2s_results"],
    "entry_analysis": ["entry_results"],
    "dataflow_analysis": ["dataflow_results"],
    "vuln_scan": ["vuln_results"],
}
STAGE_METRIC_RESETTERS = {
    "firmware_unpack": {"unpacked_firmware_count": 0, "failed_firmware_count": 0},
    "system_analysis": {
        "high_risk_module_count": 0,
        "medium_risk_module_count": 0,
        "low_risk_module_count": 0,
        "candidate_module_count": 0,
        "selected_module_count": 0,
    },
    "entry_analysis": {"entry_count": 0},
    "vuln_scan": {"vuln_result_count": 0},
}
STAGE_RETRY_ENDPOINTS = {
    "firmware_unpack": ("firmware_unpacker", "retry"),
    "system_analysis": ("system_analyse", "restart"),
    "binary_to_source": ("binary_to_source", "retry"),
    "entry_analysis": ("entry_analyse", "restart"),
    "dataflow_analysis": ("dataflow_analyse", "restart"),
    "vuln_scan": ("dataflow_vuln_scanner", "retry"),
}
SOURCE_TASK_INPUT_KEY = "source_project"
SERVICE_OUTPUT_FOLDERS = {
    "firmware_unpacker": "firmware-unpacker",
    "system_analyse": "system-analyse",
    "binary_to_source": "binary-to-source",
    "entry_analyse": "entry-analyse",
    "dataflow_analyse": "dataflow-analyse",
    "dataflow_vuln_scanner": "dataflow-vuln-scanner",
}
DOWNSTREAM_APP_ROOTS = {
    "firmware_unpacker": "secflow-app-firmware-unpacker",
    "system_analyse": "secflow-app-system-analyse",
    "binary_to_source": "secflow-app-binary-to-source",
    "entry_analyse": "secflow-app-entry-analyse",
    "dataflow_analyse": "secflow-app-dataflow-analyse",
    "dataflow_vuln_scanner": "secflow-app-dataflow-vuln-scanner",
}
SOURCE_ARCHIVE_FORMATS = (
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
)


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
            "temp_upload_dir": self._fileserver_task_path(task_id, "run/upload-tmp") if task_type == TASK_TYPE_SOURCE else None,
            "input_manifest_path": f"{self._fileserver_task_path(task_id, 'input')}/task-metadata.json",
            "input_files": input_files,
            "input_kind": "source_archives" if task_type == TASK_TYPE_SOURCE else "firmware_files",
            "downstream_task_ids": {},
            "system_analysis_modules": [],
            "candidate_modules": [],
            "selected_modules": [],
        }
        task.metrics = {
            "high_risk_module_count": 0,
            "medium_risk_module_count": 0,
            "low_risk_module_count": 0,
            "candidate_module_count": 0,
            "selected_module_count": 0,
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
        declared = self._normalize_input_files(
            payload.files or [BinarySecurityInputFile(**item) for item in task.summary.get("input_files") or []],
            task_type=self._task_type(task),
        )
        input_dir = Path(task.workspace_root) / "input"
        self._record_event(db, task, "task_upload_started", "开始校验上传文件")
        if self._task_type(task) == TASK_TYPE_SOURCE:
            actual_files, total_bytes, extracted_count = await self._materialize_source_archives(task, declared)
            self._record_event(
                db,
                task,
                "source_archives_extracted",
                "源码压缩包已解压到任务输入目录",
                payload={"archive_count": len(actual_files), "extracted_file_count": extracted_count},
            )
        else:
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

    def get_module_selection(self, db: Session, *, project_id: str, task_id: str) -> BinarySecurityModuleSelectionResponse:
        task = self._task_or_404(db, project_id, task_id)
        summary = task.summary or {}
        return BinarySecurityModuleSelectionResponse(
            task_id=task.id,
            status=task.status,
            selection_mode=self._module_selection_mode(task),
            risk_levels=self._module_risk_levels(task),
            requires_confirmation=task.status == TASK_STATUS_PENDING_MODULE_CONFIRMATION,
            system_analysis_modules=list(summary.get("system_analysis_modules") or []),
            candidate_modules=list(summary.get("candidate_modules") or []),
            selected_modules=list(summary.get("selected_modules") or []),
        )

    def confirm_module_selection(
        self,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        selected_module_keys: list[str],
    ) -> BinarySecurityTaskDetailResponse:
        task = self._task_or_404(db, project_id, task_id)
        if task.status != TASK_STATUS_PENDING_MODULE_CONFIRMATION:
            raise ValidationError("当前任务不处于等待模块确认状态")
        summary = dict(task.summary or {})
        candidate_modules = list(summary.get("candidate_modules") or [])
        if not candidate_modules:
            raise ValidationError("当前任务没有可确认的候选模块")
        requested = [str(key or "").strip() for key in selected_module_keys if str(key or "").strip()]
        if not requested:
            raise ValidationError("至少选择 1 个模块")
        candidate_map = {str(module.get("module_key") or ""): dict(module) for module in candidate_modules if str(module.get("module_key") or "").strip()}
        invalid = [key for key in requested if key not in candidate_map]
        if invalid:
            raise ValidationError(f"存在不属于候选集合的模块: {invalid[0]}")
        selected = self._mark_selected_modules([candidate_map[key] for key in requested], selected_by=MODULE_SELECTION_MODE_MANUAL_CONFIRM)
        summary["selected_modules"] = selected
        summary["high_risk_modules"] = selected
        task.summary = summary
        task.metrics = {
            **task.metrics,
            "selected_module_count": len(selected),
        }
        current_stage = str(task.current_stage or "").strip()
        task.status = "pending"
        next_stage = self._next_incomplete_stage(db, task)
        if next_stage == current_stage or not next_stage:
            stage_sequence = self._stage_sequence_for_task(task)
            if current_stage in stage_sequence:
                current_index = stage_sequence.index(current_stage)
                if current_index + 1 < len(stage_sequence):
                    next_stage = stage_sequence[current_index + 1]
        task.current_stage = next_stage or self._stage_sequence_for_task(task)[0]
        task.last_error = None
        task.dispatcher_instance_id = None
        task.dispatch_started_at = None
        task.finished_at = None
        self._record_event(
            db,
            task,
            "module_selection_confirmed",
            f"已确认 {len(selected)} 个模块，任务继续执行",
            stage_name="system_analysis",
            payload={"selected_module_keys": requested},
        )
        db.commit()
        return self.get_task_detail(db, project_id=project_id, task_id=task_id)

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

    async def cancel_task(self, db: Session, *, project_id: str, task_id: str) -> BinarySecurityActionResponse:
        task = self._task_or_404(db, project_id, task_id)
        if task.status == "cancelled":
            return BinarySecurityActionResponse(task_id=task_id, message="任务已取消")
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
        return BinarySecurityActionResponse(
            task_id=task_id,
            message="任务已取消",
            cancelled_downstream_count=len([item for item in running_items if item.downstream_task_id]),
            cleanup_status="cancelled",
        )

    async def delete_task(self, db: Session, *, project_id: str, task_id: str) -> BinarySecurityActionResponse:
        task = self._task_or_404(db, project_id, task_id)
        task.status = "cancelled"
        task.dispatcher_instance_id = None
        task.dispatch_started_at = None
        task.finished_at = task.finished_at or _now()
        self._record_event(db, task, "task_delete_requested", "任务删除已请求")
        items = db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.task_id == task.id).all()
        downstream_refs = self._collect_downstream_refs(task, items)
        for item in items:
            if item.status in {"pending", "queued", "running"}:
                item.status = "cancelled"
                item.finished_at = _now()
        self._write_task_metadata(task, Path(task.workspace_root) / "input" / "task-metadata.json", status="cancelled")
        db.commit()

        await self._cancel_local_worker(task.id)
        token = self._service_token()
        cancelled_count = await self._cancel_downstream_refs(db, task, downstream_refs, token)
        deleted_count = await self._delete_downstream_refs(db, task, downstream_refs, token)
        cleanup_status = await self._cleanup_task_workspace(task, token)

        db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.task_id == task.id).delete(synchronize_session=False)
        db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).delete(synchronize_session=False)
        db.query(BinarySecurityEvent).filter(BinarySecurityEvent.task_id == task.id).delete(synchronize_session=False)
        db.delete(task)
        db.commit()
        return BinarySecurityActionResponse(
            task_id=task_id,
            message="任务及下游资源已删除",
            cancelled_downstream_count=cancelled_count,
            deleted_downstream_count=deleted_count,
            cleanup_status=cleanup_status,
        )

    def continue_task(self, db: Session, *, project_id: str, task_id: str) -> str:
        task = self._task_or_404(db, project_id, task_id)
        if task.status in {"pending_upload", "uploading", "ready_to_start"}:
            raise ValidationError(f"当前任务状态不允许继续: {task.status}")
        if task.status in {"pending", "dispatching", "running"}:
            raise ValidationError(f"当前任务正在执行或排队中，不能手动继续: {task.status}")
        if task.status == TASK_STATUS_PENDING_MODULE_CONFIRMATION:
            raise ValidationError("当前任务等待模块确认，请先确认模块后继续")

        stage_sequence = self._stage_sequence_for_task(task)
        stage_runs = {
            row.stage_name: row
            for row in db.query(BinarySecurityStageRun).filter(
                BinarySecurityStageRun.task_id == task.id,
            ).all()
        }
        target_stage = stage_sequence[0]
        last_success_stage: str | None = None
        for stage_name in stage_sequence:
            run = stage_runs.get(stage_name)
            if run and run.status in {"success", "skipped"}:
                last_success_stage = stage_name
                continue
            target_stage = stage_name
            break
        else:
            raise ValidationError("当前任务所有阶段都已成功，没有可继续的后续阶段")

        target_index = stage_sequence.index(target_stage)
        affected_stages = stage_sequence[target_index:]
        self._clear_stage_outputs_from(task, target_stage, mark_stale=False)
        db.query(BinarySecurityStageItem).filter(
            BinarySecurityStageItem.task_id == task.id,
            BinarySecurityStageItem.stage_name.in_(affected_stages),
        ).delete(synchronize_session=False)
        for stage_name in affected_stages:
            stage_run = stage_runs.get(stage_name)
            if stage_run:
                self._reset_stage_run_for_retry(stage_run, increment_retry=False)

        task.status = "pending"
        task.current_stage = target_stage
        task.execution_mode = None
        task.target_stage_name = None
        task.last_error = None
        task.dispatcher_instance_id = None
        task.dispatch_started_at = None
        task.finished_at = None
        self._write_task_metadata(task, Path(task.workspace_root) / "input" / "task-metadata.json", status="pending")
        self._record_event(
            db,
            task,
            "task_continue_requested",
            f"手动继续任务，将从阶段 {target_stage} 开始推进",
            stage_name=target_stage,
            payload={
                "target_stage": target_stage,
                "last_success_stage": last_success_stage,
                "cleared_stages": affected_stages,
            },
        )
        db.commit()
        return target_stage

    def retry_task(self, db: Session, *, project_id: str, task_id: str) -> None:
        task = self._task_or_404(db, project_id, task_id)
        supported, reason, stage_name = self._task_retry_support(db, task)
        if not supported or not stage_name:
            raise ValidationError(reason or "当前任务不支持安全重试")
        stage_sequence = self._stage_sequence_for_task(task)
        task.status = "pending"
        task.current_stage = stage_name
        task.execution_mode = "task_retry"
        task.target_stage_name = stage_name
        task.last_error = None
        task.dispatcher_instance_id = None
        task.dispatch_started_at = None
        task.finished_at = None
        self._clear_stage_outputs_from(task, stage_name)
        for current_stage in stage_sequence[stage_sequence.index(stage_name):]:
            stage_run = db.query(BinarySecurityStageRun).filter(
                BinarySecurityStageRun.task_id == task.id,
                BinarySecurityStageRun.stage_name == current_stage,
            ).first()
            if stage_run:
                self._reset_stage_run_for_retry(stage_run, increment_retry=current_stage == stage_name)
        self._write_task_metadata(task, Path(task.workspace_root) / "input" / "task-metadata.json", status="pending")
        self._record_event(
            db,
            task,
            "task_retried",
            f"任务将从阶段 {stage_name} 继续安全重试",
            stage_name=stage_name,
            payload={"target_stage": stage_name, "stale_stages": stage_sequence[stage_sequence.index(stage_name) + 1:]},
        )
        db.commit()

    def retry_stage(self, db: Session, *, project_id: str, task_id: str, stage_name: str) -> None:
        task = self._task_or_404(db, project_id, task_id)
        stage_sequence = self._stage_sequence_for_task(task)
        if stage_name not in stage_sequence:
            raise ValidationError(f"无效阶段: {stage_name}")
        supported, reason = self._stage_retry_support(db, task, stage_name)
        if not supported:
            raise ValidationError(reason or f"阶段 {stage_name} 不支持安全重试")
        stage_run = db.query(BinarySecurityStageRun).filter(
            BinarySecurityStageRun.task_id == task.id,
            BinarySecurityStageRun.stage_name == stage_name,
        ).first()
        if not stage_run:
            raise ValidationError("目标阶段尚未执行，不能重试")
        downstream_stale = stage_sequence[stage_sequence.index(stage_name) + 1 :]
        self._clear_stage_outputs_from(task, stage_name)
        self._reset_stage_run_for_retry(stage_run, increment_retry=True)

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

    async def sync_downstream_status(
        self,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        stage_name: str | None = None,
        item_id: str | None = None,
        force: bool = False,
        token: str | None = None,
    ) -> BinarySecurityActionResponse:
        task = self._task_or_404(db, project_id, task_id)
        query = db.query(BinarySecurityStageItem).filter(BinarySecurityStageItem.task_id == task.id)
        if stage_name:
            if stage_name not in self._stage_sequence_for_task(task):
                raise ValidationError(f"无效阶段: {stage_name}")
            query = query.filter(BinarySecurityStageItem.stage_name == stage_name)
        if item_id:
            query = query.filter(BinarySecurityStageItem.id == item_id)
        items = query.order_by(BinarySecurityStageItem.created_at.asc()).all()
        if item_id and not items:
            raise NotFoundError("阶段子任务不存在")

        self._record_event(
            db,
            task,
            "downstream_status_sync_requested",
            "请求同步下游子任务状态",
            stage_name=stage_name,
            payload={"stage_name": stage_name, "item_id": item_id, "force": force},
        )
        db.commit()

        synced_count = 0
        skipped_count = 0
        failed_count = 0
        touched_stages: set[str] = set()
        auth_token = token or self._service_token()
        for item in items:
            if not item.downstream_service or not item.downstream_task_id:
                skipped_count += 1
                self._record_event(
                    db,
                    task,
                    "downstream_status_sync_skipped",
                    "跳过同步：子任务缺少下游服务或任务ID",
                    level="warning",
                    stage_name=item.stage_name,
                    item=item,
                )
                continue
            before_status = item.status
            try:
                payload = await self._fetch_downstream_task_payload(task, item, auth_token)
                downstream_status = str(payload.get("status") or "").lower()
                mapped_status = self._map_downstream_status(downstream_status)
                if not mapped_status:
                    skipped_count += 1
                    self._record_event(
                        db,
                        task,
                        "downstream_status_sync_skipped",
                        f"跳过同步：无法识别下游状态 {downstream_status or '-'}",
                        level="warning",
                        stage_name=item.stage_name,
                        item=item,
                        payload={
                            "downstream_service": item.downstream_service,
                            "downstream_task_id": item.downstream_task_id,
                            "downstream_status": downstream_status,
                        },
                    )
                    continue
                if force or mapped_status != before_status:
                    item.status = mapped_status
                    item.error_message = None if mapped_status in {"queued", "running", "success"} else (
                        payload.get("error") or payload.get("error_message") or payload.get("message") or item.error_message
                    )
                    if mapped_status in {"queued", "running"}:
                        item.finished_at = None
                        item.started_at = item.started_at or _now()
                    else:
                        item.finished_at = item.finished_at or _now()
                    item.result = {
                        **(item.result or {}),
                        "downstream": self._lightweight_downstream_payload(payload),
                        "downstream_status_synced_at": _now().isoformat(),
                    }
                    touched_stages.add(item.stage_name)
                    synced_count += 1
                else:
                    skipped_count += 1
                if force or mapped_status in {"success", "partial_success", "failed", "cancelled"}:
                    archived_dir = self._archive_downstream_output(
                        db,
                        task,
                        item,
                        semantic_key=item.item_key,
                        payload=payload,
                    )
                    if archived_dir:
                        item.output_ref = {
                            **(item.output_ref or {}),
                            "archive_root": str(archived_dir),
                        }
                        item.result = {
                            **(item.result or {}),
                            "archive_root": str(archived_dir),
                        }
                    if mapped_status in {"success", "partial_success"}:
                        await self._refresh_terminal_item_result_from_downstream(
                            task,
                            item,
                            payload,
                            mapped_status=mapped_status,
                            archived_dir=archived_dir,
                        )
                self._record_event(
                    db,
                    task,
                    "downstream_status_synced" if (force or mapped_status != before_status) else "downstream_status_sync_skipped",
                    "下游子任务状态已同步" if (force or mapped_status != before_status) else "下游子任务状态一致，无需同步",
                    stage_name=item.stage_name,
                    item=item,
                    payload={
                        "downstream_service": item.downstream_service,
                        "downstream_task_id": item.downstream_task_id,
                        "before_status": before_status,
                        "downstream_status": downstream_status,
                        "after_status": mapped_status,
                    },
                )
            except Exception as exc:
                failed_count += 1
                self._record_event(
                    db,
                    task,
                    "downstream_status_sync_failed",
                    f"同步下游子任务状态失败: {exc}",
                    level="warning",
                    stage_name=item.stage_name,
                    item=item,
                    payload={
                        "downstream_service": item.downstream_service,
                        "downstream_task_id": item.downstream_task_id,
                        "error": str(exc),
                    },
                )
        for current_stage in touched_stages:
            if current_stage == "system_analysis":
                self._refresh_system_analysis_stage_from_synced_items(db, task)
            else:
                self._refresh_stage_run_from_items(db, task, current_stage)
        if touched_stages:
            self._refresh_task_status_after_sync(db, task)
            self._write_task_metadata(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
        db.commit()
        return BinarySecurityActionResponse(
            task_id=task.id,
            message=f"下游状态同步完成：更新 {synced_count} 个，跳过 {skipped_count} 个，失败 {failed_count} 个",
            synced_downstream_count=synced_count,
            skipped_downstream_count=skipped_count,
            failed_downstream_count=failed_count,
        )

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
            stale_reclaimed = self._reclaim_stale_running_locked(db) or stale_reclaimed
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
            task_retry_mode = task.execution_mode == "task_retry" and bool(task.target_stage_name)
            target_stage_name = task.target_stage_name if (stage_retry_mode or task_retry_mode) else None
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
                elif task_retry_mode and self._stage_items(db, task.id, stage_name):
                    self._record_event(db, task, "stage_retry_started", f"阶段开始安全续跑: {stage_name}", stage_name=stage_name)
                self._record_event(db, task, "stage_started", f"阶段开始: {stage_name}", stage_name=stage_name)
                db.commit()
                retry_existing = False
                if stage_retry_mode and stage_name == target_stage_name:
                    retry_existing = True
                elif task_retry_mode and self._stage_items(db, task.id, stage_name):
                    retry_existing = True
                status, summary = await handler(db, task, stage_run, token, retry_existing)
                db.refresh(stage_run)
                stage_run.status = "waiting_confirmation" if task.status == TASK_STATUS_PENDING_MODULE_CONFIRMATION else status
                stage_run.finished_at = _now()
                stage_run.output_summary = summary
                stage_run.counts = self._stage_counts(db, stage_run)
                if status in {"failed", "partial_success"}:
                    stage_run.last_error = summary.get("error")
                db.commit()
                task.stage_summary = {
                    **task.stage_summary,
                    stage_name: {
                        "status": stage_run.status,
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
                    task.metrics = {
                        **task.metrics,
                        "high_risk_module_count": int(summary.get("high_risk_module_count", 0)),
                        "medium_risk_module_count": int(summary.get("medium_risk_module_count", 0)),
                        "low_risk_module_count": int(summary.get("low_risk_module_count", 0)),
                        "candidate_module_count": int(summary.get("candidate_module_count", 0)),
                        "selected_module_count": int(summary.get("selected_module_count", 0)),
                    }
                elif stage_name == "entry_analysis":
                    task.metrics = {**task.metrics, "entry_count": int(summary.get("entry_count", 0))}
                elif stage_name == "vuln_scan":
                    task.metrics = {**task.metrics, "vuln_result_count": int(summary.get("vuln_result_count", 0))}
                db.commit()
                if task.status == TASK_STATUS_PENDING_MODULE_CONFIRMATION:
                    self._write_task_metadata(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
                    db.commit()
                    return
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
            if stage_retry_mode or task_retry_mode:
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

    def _reclaim_stale_running_locked(self, db: Session) -> bool:
        service_config = self._load_service_config(db)
        timeout_seconds = max(int(service_config.dispatch_timeout_seconds) * 3, 300)
        cutoff = _now().timestamp() - timeout_seconds
        stale_rows = (
            db.query(BinarySecurityTask)
            .filter(
                BinarySecurityTask.status == "running",
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
            heartbeat_at = task.updated_at or task.dispatch_started_at
            if not heartbeat_at or heartbeat_at.timestamp() >= cutoff:
                continue
            stage_name = task.current_stage or self._stage_sequence_for_task(task)[0]
            stage_run = db.query(BinarySecurityStageRun).filter(
                BinarySecurityStageRun.task_id == task.id,
                BinarySecurityStageRun.stage_name == stage_name,
            ).first()
            if stage_run:
                stage_run.status = "failed"
                stage_run.finished_at = _now()
                stage_run.last_error = "任务执行实例心跳超时，运行状态已回收"
                stage_run.output_summary = {
                    **(stage_run.output_summary or {}),
                    "error": stage_run.last_error,
                    "reclaimed": True,
                }
                running_items = db.query(BinarySecurityStageItem).filter(
                    BinarySecurityStageItem.task_id == task.id,
                    BinarySecurityStageItem.stage_name == stage_name,
                    BinarySecurityStageItem.status.in_(["pending", "queued", "running"]),
                ).all()
                for item in running_items:
                    item.status = "failed"
                    item.finished_at = _now()
                    item.error_message = item.error_message or stage_run.last_error
                stage_run.counts = self._stage_counts(db, stage_run)
            task.status = "failed"
            task.last_error = "任务执行实例心跳超时，运行状态已回收"
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            task.finished_at = _now()
            self._record_event(
                db,
                task,
                "running_reclaimed",
                "运行实例心跳超时，任务已回收并标记失败",
                level="error",
                stage_name=stage_name,
                payload={"stage_name": stage_name},
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
        if task.status == TASK_STATUS_PENDING_MODULE_CONFIRMATION:
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            return
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
        await client.ensure_project_directory(project_id, f"app/secflow-app-binary-security/{task_id}/run/upload-tmp", authorization_token)

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
                    "temp_upload_dir": task.summary.get("temp_upload_dir"),
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
                effective_path = filename
                if filename in seen_names:
                    raise ValidationError(f"存在重复文件名: {filename}")
                seen_names.add(filename)
                if not self._is_supported_source_archive(filename):
                    raise ValidationError(f"源码扫描仅支持常见压缩文件: {filename}")
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

    def _is_supported_source_archive(self, filename: str) -> bool:
        lowered = str(filename or "").strip().lower()
        return any(lowered.endswith(ext) for ext in SOURCE_ARCHIVE_FORMATS)

    def _source_temp_upload_root(self, task: BinarySecurityTask) -> Path:
        return ensure_dir(Path(task.workspace_root) / "run" / "upload-tmp")

    def _safe_extract_archive(self, archive_path: Path, target_dir: Path) -> int:
        ensure_dir(target_dir)
        extracted = 0
        if zipfile.is_zipfile(archive_path):
            with zipfile.ZipFile(archive_path) as archive:
                for member in archive.infolist():
                    member_name = member.filename.replace("\\", "/").strip("/")
                    if not member_name:
                        continue
                    target_path = target_dir / member_name
                    if not _is_within_path(target_dir, target_path):
                        raise ValidationError(f"压缩包包含非法路径: {member.filename}")
                    archive.extract(member, target_dir)
                    if not member.is_dir():
                        extracted += 1
            return extracted
        if tarfile.is_tarfile(archive_path):
            with tarfile.open(archive_path, "r:*") as archive:
                for member in archive.getmembers():
                    member_name = member.name.replace("\\", "/").strip("/")
                    if not member_name:
                        continue
                    target_path = target_dir / member_name
                    if not _is_within_path(target_dir, target_path):
                        raise ValidationError(f"压缩包包含非法路径: {member.name}")
                archive.extractall(target_dir)
                extracted = sum(1 for member in archive.getmembers() if member.isfile())
            return extracted
        raise ValidationError(f"不支持的源码压缩文件格式: {archive_path.name}")

    async def _wait_for_uploaded_file(self, path: Path, *, timeout_seconds: int = 10, interval_seconds: int = 1) -> bool:
        attempts = max(1, timeout_seconds // max(1, interval_seconds)) + 1
        for attempt in range(attempts):
            if path.is_file():
                return True
            if attempt < attempts - 1:
                await asyncio.sleep(interval_seconds)
        return path.is_file()

    async def _materialize_source_archives(self, task: BinarySecurityTask, declared: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int, int]:
        input_dir = ensure_dir(Path(task.workspace_root) / "input")
        temp_dir = self._source_temp_upload_root(task)
        actual_files: list[dict[str, Any]] = []
        total_bytes = 0
        extracted_count = 0
        for file_info in declared:
            filename = str(file_info["filename"])
            temp_path = temp_dir / filename
            if not await self._wait_for_uploaded_file(temp_path, timeout_seconds=10, interval_seconds=1):
                raise ValidationError(f"上传文件缺失: {filename}")
            stat = temp_path.stat()
            total_bytes += stat.st_size
            extracted_count += self._safe_extract_archive(temp_path, input_dir)
            temp_path.unlink(missing_ok=True)
            actual_files.append(
                {
                    **file_info,
                    "size": stat.st_size,
                    "uploaded": True,
                    "path": str(task.summary.get("input_dir") or self._fileserver_task_path(task.id, "input")),
                    "temp_path": f"{task.summary.get('temp_upload_dir')}/{filename}" if task.summary.get("temp_upload_dir") else None,
                    "extracted": True,
                }
            )
        if extracted_count <= 0:
            raise ValidationError("源码压缩包解压后没有得到任何文件")
        shutil.rmtree(temp_dir, ignore_errors=True)
        ensure_dir(temp_dir)
        return actual_files, total_bytes, extracted_count

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
        selection_mode = str(overrides.get("module_selection_mode") or base.get("module_selection_mode") or MODULE_SELECTION_MODE_AUTO).strip()
        if selection_mode not in {MODULE_SELECTION_MODE_AUTO, MODULE_SELECTION_MODE_MANUAL_CONFIRM}:
            selection_mode = MODULE_SELECTION_MODE_AUTO
        base["module_selection_mode"] = selection_mode
        base["module_risk_levels"] = _normalize_module_risk_levels(overrides.get("module_risk_levels") or base.get("module_risk_levels"))
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

    def _module_selection_mode(self, task: BinarySecurityTask) -> str:
        mode = str((task.policy or {}).get("module_selection_mode") or MODULE_SELECTION_MODE_AUTO).strip()
        if mode not in {MODULE_SELECTION_MODE_AUTO, MODULE_SELECTION_MODE_MANUAL_CONFIRM}:
            return MODULE_SELECTION_MODE_AUTO
        return mode

    def _module_risk_levels(self, task: BinarySecurityTask) -> list[str]:
        return _normalize_module_risk_levels((task.policy or {}).get("module_risk_levels"))

    def _mark_selected_modules(self, modules: list[dict[str, Any]], *, selected_by: str, selected_at: str | None = None) -> list[dict[str, Any]]:
        timestamp = selected_at or _now().isoformat()
        return [
            {
                **module,
                "selected_by": selected_by,
                "selected_at": timestamp,
            }
            for module in modules
        ]

    def _filter_candidate_modules(self, modules: list[dict[str, Any]], risk_levels: list[str]) -> list[dict[str, Any]]:
        allowed = set(_normalize_module_risk_levels(risk_levels))
        return [dict(module) for module in modules if str(module.get("risk_level") or "").strip() in allowed]

    def _module_metrics(self, modules: list[dict[str, Any]], candidate_modules: list[dict[str, Any]], selected_modules: list[dict[str, Any]]) -> dict[str, int]:
        return {
            "high_risk_module_count": sum(1 for module in modules if str(module.get("risk_level") or "").strip() == "高"),
            "medium_risk_module_count": sum(1 for module in modules if str(module.get("risk_level") or "").strip() == "中"),
            "low_risk_module_count": sum(1 for module in modules if str(module.get("risk_level") or "").strip() == "低"),
            "candidate_module_count": len(candidate_modules),
            "selected_module_count": len(selected_modules),
        }

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
            elif item.status in {"pending", "queued", "dispatching"}:
                counts["running_items"] += 1
        return counts

    def _task_response(self, db: Session, task: BinarySecurityTask, queue_info: dict[str, Any] | None = None) -> BinarySecurityTaskResponse:
        stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).order_by(BinarySecurityStageRun.sequence_no.asc()).all()
        metrics = task.metrics or {}
        queue_info = queue_info or {"pending_positions": {}}
        queue_position = queue_info.get("pending_positions", {}).get(task.id)
        stage_sequence = self._stage_sequence_for_task(task)
        task_retry_supported, task_retry_reason, _ = self._task_retry_support(db, task)
        stage_retry_support = {
            run.stage_name: self._stage_retry_support(db, task, run.stage_name)
            for run in stage_runs
            if run.stage_name in stage_sequence
        }
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
            medium_risk_module_count=int(metrics.get("medium_risk_module_count", 0)),
            low_risk_module_count=int(metrics.get("low_risk_module_count", 0)),
            candidate_module_count=int(metrics.get("candidate_module_count", 0)),
            selected_module_count=int(metrics.get("selected_module_count", 0)),
            selected_risk_levels=_normalize_module_risk_levels((task.policy or {}).get("module_risk_levels")),
            module_selection_mode=self._module_selection_mode(task),
            entry_count=int(metrics.get("entry_count", 0)),
            vuln_result_count=int(metrics.get("vuln_result_count", 0)),
            firmware_item_count=int(metrics.get("firmware_item_count", 0)),
            unpacked_firmware_count=int(metrics.get("unpacked_firmware_count", 0)),
            failed_firmware_count=int(metrics.get("failed_firmware_count", 0)),
            task_retry_supported=task_retry_supported,
            task_retry_reason=task_retry_reason,
            stage_summaries=[
                BinarySecurityStageSummary(
                    stage_name=run.stage_name,
                    sequence_no=run.sequence_no,
                    status=run.status,
                    retry_count=run.retry_count,
                    retry_supported=stage_retry_support.get(run.stage_name, (False, None))[0],
                    retry_reason=stage_retry_support.get(run.stage_name, (False, None))[1],
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
        completed = {run.stage_name for run in stage_runs if run.status in {"success", "skipped", "waiting_confirmation"}}
        for stage_name in self._stage_sequence_for_task(task):
            if stage_name not in completed:
                return stage_name
        return None

    def _retry_snapshot_for_item(self, task: BinarySecurityTask, stage_name: str, item_key: str) -> dict[str, Any] | None:
        summary = task.summary or {}
        stage_context = (summary.get("stage_retry_context") or {}).get(stage_name) or {}
        snapshot = stage_context.get(item_key)
        return dict(snapshot) if isinstance(snapshot, dict) else None

    def _stage_result_keys(self, stage_name: str) -> list[str]:
        return list(STAGE_SUMMARY_RESULT_KEYS.get(stage_name, []))

    def _stage_expected_service(self, stage_name: str) -> str | None:
        mapping = STAGE_RETRY_ENDPOINTS.get(stage_name)
        return mapping[0] if mapping else None

    async def _fetch_downstream_task_payload(self, task: BinarySecurityTask, item: BinarySecurityStageItem, token: str) -> dict[str, Any]:
        task_id = str(item.downstream_task_id or "").strip()
        if not task_id:
            raise ValidationError("缺少下游任务ID")
        if item.downstream_service == "firmware_unpacker":
            return await get_firmware_unpacker_client().get_task(task.project_id, task_id, token or "")
        if item.downstream_service == "system_analyse":
            return await get_system_analyse_client().get_task(task_id)
        if item.downstream_service == "binary_to_source":
            project_id = (item.result or {}).get("project_id") or task.project_id
            return await get_binary_to_source_client().get_task(project_id, task_id, token or "")
        if item.downstream_service == "entry_analyse":
            return await get_entry_analyse_client().get_task(task_id)
        if item.downstream_service == "dataflow_analyse":
            return await get_dataflow_analyse_client().get_task(task_id)
        if item.downstream_service == "dataflow_vuln_scanner":
            return await get_dataflow_vuln_scanner_client().get_task(task_id, token or "")
        raise ValidationError(f"未知下游服务: {item.downstream_service}")

    async def _refresh_terminal_item_result_from_downstream(
        self,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        payload: dict[str, Any],
        *,
        mapped_status: str,
        archived_dir: Path | None,
    ) -> None:
        if item.stage_name != "system_analysis" or item.downstream_service != "system_analyse":
            return
        if mapped_status != "success":
            return
        result_payload: dict[str, Any] = {}
        try:
            result_payload = await get_system_analyse_client().get_task_result(str(item.downstream_task_id))
        except Exception:
            result_payload = {}
        firmware = self._system_analysis_input_for_item(task, item)
        artifact_root = archived_dir or self._service_output_dir(
            task,
            item.downstream_service or item.stage_name,
            item.item_key,
            item.downstream_task_id,
        )
        modules = self._parse_system_analysis_modules(artifact_root, firmware, result_payload)
        item.result = {
            **self._lightweight_system_analysis_input(firmware),
            "artifact_root": str(artifact_root),
            "archive_root": str(artifact_root),
            "modules": self._lightweight_modules_for_storage(modules),
            "module_count": len(modules),
            "downstream": self._lightweight_downstream_payload(payload),
            "system_analysis_result": self._lightweight_system_analysis_result(result_payload),
            "downstream_status_synced_at": _now().isoformat(),
        }
        item.output_ref = {
            **(item.output_ref or {}),
            "artifact_root": str(artifact_root),
            "archive_root": str(artifact_root),
        }

    def _system_analysis_input_for_item(self, task: BinarySecurityTask, item: BinarySecurityStageItem) -> dict[str, Any]:
        for candidate in self._system_analysis_inputs(task):
            if str(candidate.get("firmware_key") or "") == str(item.item_key or ""):
                return dict(candidate)
        input_ref = dict(item.input_ref or {})
        return {
            "firmware_key": str(item.item_key or input_ref.get("firmware_key") or SOURCE_TASK_INPUT_KEY),
            "firmware_name": str(item.item_name or task.name),
            "filename": str(item.item_name or input_ref.get("filename") or item.item_key or "source-project"),
            "unpacked_root": str(input_ref.get("input_path") or input_ref.get("unpacked_root") or Path(task.workspace_root) / "input"),
            "source_root": str(input_ref.get("source_root") or input_ref.get("input_path") or Path(task.workspace_root) / "input"),
            "task_type": self._task_type(task),
        }

    def _map_downstream_status(self, status: str) -> str | None:
        normalized = (status or "").lower()
        if normalized in {"pending", "queued", "created", "dispatching", "ready", "ready_to_start"}:
            return "queued"
        if normalized in {"running", "processing", "in_progress", "cancelling", "started"}:
            return "running"
        if normalized in {"success", "passed", "completed", "complete", "done"}:
            return "success"
        if normalized == "partial_success":
            return "partial_success"
        if normalized in {"failed", "error", "failure"}:
            return "failed"
        if normalized in {"cancelled", "canceled"}:
            return "cancelled"
        return None

    def _aggregate_item_statuses(self, statuses: list[str]) -> str:
        if not statuses:
            return "pending"
        active = {"pending", "queued", "running", "dispatching"}
        if any(status in active for status in statuses):
            return "running"
        if all(status == "success" for status in statuses):
            return "success"
        if any(status == "success" for status in statuses) and any(status in {"failed", "cancelled", "partial_success"} for status in statuses):
            return "partial_success"
        if all(status == "cancelled" for status in statuses):
            return "cancelled"
        if any(status in {"failed", "partial_success"} for status in statuses):
            return "failed"
        return statuses[0]

    def _refresh_stage_run_from_items(self, db: Session, task: BinarySecurityTask, stage_name: str) -> None:
        stage_run = db.query(BinarySecurityStageRun).filter(
            BinarySecurityStageRun.task_id == task.id,
            BinarySecurityStageRun.stage_name == stage_name,
        ).first()
        if not stage_run:
            return
        items = self._stage_items(db, task.id, stage_name)
        status = self._aggregate_item_statuses([item.status for item in items])
        stage_run.status = status
        stage_run.counts = self._stage_counts(db, stage_run)
        stage_run.last_error = next((item.error_message for item in items if item.status == "failed" and item.error_message), None)
        stage_run.output_summary = {
            **(stage_run.output_summary or {}),
            "status_synced": True,
            "sync_status": status,
            **stage_run.counts,
        }
        if status in {"running", "pending", "queued"}:
            stage_run.finished_at = None
            stage_run.started_at = stage_run.started_at or _now()
        else:
            stage_run.finished_at = stage_run.finished_at or _now()
        if stage_name == "firmware_unpack":
            task.metrics = {
                **(task.metrics or {}),
                "unpacked_firmware_count": int(stage_run.counts.get("success_items", 0)),
                "failed_firmware_count": int(stage_run.counts.get("failed_items", 0)),
            }

    def _refresh_system_analysis_stage_from_synced_items(self, db: Session, task: BinarySecurityTask) -> None:
        stage_run = db.query(BinarySecurityStageRun).filter(
            BinarySecurityStageRun.task_id == task.id,
            BinarySecurityStageRun.stage_name == "system_analysis",
        ).first()
        if not stage_run:
            return
        items = self._stage_items(db, task.id, "system_analysis")
        success = []
        failed = [
            {"status": item.status, "error": item.error_message, "item_key": item.item_key}
            for item in items
            if item.status in {"failed", "cancelled"}
        ]
        all_modules: list[dict[str, Any]] = []
        for item in items:
            if item.status != "success":
                continue
            result = dict(item.result or {})
            item_modules = self._system_analysis_modules_from_item(task, item)
            all_modules.extend(item_modules)
            success.append({**result, "modules": self._lightweight_modules_for_storage(item_modules), "module_count": len(item_modules)})
        status = self._aggregate_item_statuses([item.status for item in items])
        candidate_modules = self._filter_candidate_modules(all_modules, self._module_risk_levels(task))
        selected_modules: list[dict[str, Any]] = []
        if status in {"success", "partial_success"} and candidate_modules:
            if self._module_selection_mode(task) == MODULE_SELECTION_MODE_AUTO:
                selected_modules = self._mark_selected_modules(candidate_modules, selected_by=MODULE_SELECTION_MODE_AUTO)
            else:
                task.status = TASK_STATUS_PENDING_MODULE_CONFIRMATION
                self._record_event(
                    db,
                    task,
                    "module_selection_required",
                    "系统分析已同步完成，等待人工确认模块",
                    stage_name="system_analysis",
                    payload={"candidate_module_count": len(candidate_modules)},
                )
        if status in {"success", "partial_success"} and not candidate_modules:
            status = "failed"
            failed = failed or [{"status": "failed", "error": "没有匹配所选风险等级的模块"}]
        summary = dict(task.summary or {})
        summary.update(
            {
                "system_analysis_results": self._lightweight_system_analysis_items(success),
                "system_analysis_modules": self._lightweight_modules_for_storage(all_modules),
                "system_analysis_module_count": len(all_modules),
                "candidate_modules": candidate_modules,
                "selected_modules": selected_modules,
                "high_risk_modules": selected_modules,
            }
        )
        task.summary = summary
        task.metrics = {
            **(task.metrics or {}),
            **self._module_metrics(all_modules, candidate_modules, selected_modules),
        }
        stage_run.status = "waiting_confirmation" if task.status == TASK_STATUS_PENDING_MODULE_CONFIRMATION else status
        stage_run.finished_at = None if stage_run.status in {"running", "pending", "queued"} else (stage_run.finished_at or _now())
        stage_run.started_at = stage_run.started_at or _now()
        stage_run.counts = self._stage_counts(db, stage_run)
        stage_run.last_error = failed[0].get("error") if failed and status == "failed" else None
        stage_run.output_summary = {
            "items": success,
            "failed_items": failed,
            "success_count": len(success),
            "failed_count": len(failed),
            "module_count": len(all_modules),
            "high_risk_module_count": sum(1 for module in all_modules if str(module.get("risk_level") or "").strip() == "高"),
            "medium_risk_module_count": sum(1 for module in all_modules if str(module.get("risk_level") or "").strip() == "中"),
            "low_risk_module_count": sum(1 for module in all_modules if str(module.get("risk_level") or "").strip() == "低"),
            "candidate_module_count": len(candidate_modules),
            "selected_module_count": len(selected_modules),
            "status_synced": True,
            "sync_status": stage_run.status,
            "error": stage_run.last_error,
            **stage_run.counts,
        }

    def _refresh_task_status_after_sync(self, db: Session, task: BinarySecurityTask) -> None:
        if task.status == TASK_STATUS_PENDING_MODULE_CONFIRMATION:
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            task.finished_at = None
            return
        stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
        statuses = [run.status for run in stage_runs if run.status != "skipped"]
        if any(status in {"running", "dispatching"} for status in statuses):
            task.status = "running"
            task.finished_at = None
            task.last_error = None
            return
        stage_retry_mode = task.execution_mode == "stage_retry" and bool(task.target_stage_name)
        task_retry_mode = task.execution_mode == "task_retry" and bool(task.target_stage_name)
        if stage_retry_mode:
            task.execution_mode = None
            task.target_stage_name = None
            summary = dict(task.summary or {})
            summary.pop("stage_retry_context", None)
            task.summary = summary
            self._finalize_task(db, task)
            return
        next_stage = self._next_incomplete_stage(db, task)
        next_stage_run = next((run for run in stage_runs if run.stage_name == next_stage), None)
        next_stage_status = next_stage_run.status if next_stage_run else "pending"
        if next_stage and next_stage_status in {"pending", "queued"} and not task_retry_mode:
            task.status = "pending"
            task.current_stage = next_stage
            task.finished_at = None
            task.dispatcher_instance_id = None
            task.dispatch_started_at = None
            task.last_error = None
            summary = dict(task.summary or {})
            if summary.get("stale_from_stage") and next_stage in set(summary.get("stale_stages") or []):
                summary["stale_stages"] = []
                summary["stale_reason"] = None
                summary["stale_from_stage"] = None
                task.summary = summary
            self._record_event(
                db,
                task,
                "task_requeued_after_downstream_sync",
                f"下游状态同步完成，任务继续进入阶段: {next_stage}",
                stage_name=next_stage,
            )
            return
        self._finalize_task(db, task)

    def _stage_items(self, db: Session, task_id: str, stage_name: str) -> list[BinarySecurityStageItem]:
        return db.query(BinarySecurityStageItem).filter(
            BinarySecurityStageItem.task_id == task_id,
            BinarySecurityStageItem.stage_name == stage_name,
        ).order_by(BinarySecurityStageItem.created_at.asc()).all()

    def _stage_item_identity(self, item_key: str, parent_key: str | None) -> str:
        return f"{item_key}::{parent_key or ''}"

    def _find_stage_item(
        self,
        db: Session,
        *,
        task_id: str,
        stage_name: str,
        item_key: str,
        parent_key: str | None,
    ) -> BinarySecurityStageItem | None:
        items = db.query(BinarySecurityStageItem).filter(
            BinarySecurityStageItem.task_id == task_id,
            BinarySecurityStageItem.stage_name == stage_name,
            BinarySecurityStageItem.item_key == item_key,
        ).order_by(BinarySecurityStageItem.created_at.asc()).all()
        matches = [item for item in items if (item.parent_key or None) == (parent_key or None)]
        if len(matches) > 1:
            raise ValidationError(f"阶段 {stage_name} 存在重复历史 item，无法安全重试: {item_key}")
        return matches[0] if matches else None

    def _upsert_stage_item(
        self,
        db: Session,
        *,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        stage_name: str,
        item_key: str,
        item_name: str | None,
        parent_key: str | None,
        downstream_service: str,
        input_ref: dict[str, Any],
        output_ref: dict[str, Any] | None = None,
        retrying: bool,
        running_status: str = "running",
    ) -> BinarySecurityStageItem:
        item = self._find_stage_item(
            db,
            task_id=task.id,
            stage_name=stage_name,
            item_key=item_key,
            parent_key=parent_key,
        )
        if item is None:
            if retrying:
                raise ValidationError(f"缺少历史阶段项，无法安全重试: {stage_name}:{item_key}")
            item = BinarySecurityStageItem(
                id=f"si_{uuid.uuid4().hex[:20]}",
                task_id=task.id,
                project_id=task.project_id,
                stage_run_id=stage_run.id,
                stage_name=stage_name,
                item_key=item_key,
                item_name=item_name,
                parent_key=parent_key,
                status=running_status,
                downstream_service=downstream_service,
                started_at=_now(),
            )
            db.add(item)
        else:
            item.stage_run_id = stage_run.id
            item.item_name = item_name
            item.parent_key = parent_key
            item.status = running_status
            item.downstream_service = downstream_service
            item.error_message = None
            item.finished_at = None
            item.started_at = _now()
            item.payload = {}
            item.result = {}
            if retrying:
                item.retry_count = int(item.retry_count or 0) + 1
        item.input_ref = input_ref
        if output_ref is not None:
            item.output_ref = output_ref
        db.flush()
        return item

    def _invoke_existing_downstream_retry(
        self,
        stage_name: str,
        *,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        token: str | None,
    ):
        downstream_task_id = str(item.downstream_task_id or "").strip()
        if not downstream_task_id:
            raise ValidationError("缺少下游任务ID，无法安全重试")
        expected_service = self._stage_expected_service(stage_name)
        if expected_service and item.downstream_service != expected_service:
            raise ValidationError(
                f"下游服务不匹配，无法安全重试: 期望 {expected_service}，实际 {item.downstream_service or '-'}"
            )
        if stage_name == "firmware_unpack":
            return get_firmware_unpacker_client().retry_task(downstream_task_id, token or "")
        if stage_name == "system_analysis":
            return get_system_analyse_client().restart_task(downstream_task_id)
        if stage_name == "binary_to_source":
            return get_binary_to_source_client().retry_task(task.project_id, downstream_task_id, token or "")
        if stage_name == "entry_analysis":
            return get_entry_analyse_client().restart_task(downstream_task_id)
        if stage_name == "dataflow_analysis":
            return get_dataflow_analyse_client().restart_task(downstream_task_id)
        if stage_name == "vuln_scan":
            return get_dataflow_vuln_scanner_client().retry_task(downstream_task_id, token or "")
        raise ValidationError(f"阶段 {stage_name} 未配置安全重试接口")

    def _has_retryable_downstream_task(self, item: BinarySecurityStageItem) -> bool:
        return bool(str(item.downstream_task_id or "").strip())

    def _stage_retry_support(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_name: str,
        *,
        require_stage_run: bool = True,
    ) -> tuple[bool, str | None]:
        if stage_name not in self._stage_sequence_for_task(task):
            return False, f"无效阶段: {stage_name}"
        mapping = STAGE_RETRY_ENDPOINTS.get(stage_name)
        if not mapping:
            return False, f"阶段 {stage_name} 未配置安全重试接口"
        if task.status in STAGE_RETRY_BLOCKED_TASK_STATUSES:
            return False, f"当前任务状态不允许重试: {task.status}"
        stage_run = db.query(BinarySecurityStageRun).filter(
            BinarySecurityStageRun.task_id == task.id,
            BinarySecurityStageRun.stage_name == stage_name,
        ).first()
        if require_stage_run and not stage_run:
            return False, "目标阶段尚未执行，不能重试"
        if stage_run and stage_run.status not in STAGE_RETRY_ALLOWED_STATUSES:
            return False, f"当前阶段状态不允许重试: {stage_run.status}"
        items = self._stage_items(db, task.id, stage_name)
        if not items:
            return False, "阶段没有历史子任务，无法安全重试"
        seen: set[str] = set()
        expected_service = mapping[0]
        for item in items:
            logical_key = self._stage_item_identity(item.item_key, item.parent_key)
            if logical_key in seen:
                return False, f"阶段 {stage_name} 存在重复历史 item，无法安全重试: {item.item_key}"
            seen.add(logical_key)
            if item.downstream_service and item.downstream_service != expected_service:
                return False, (
                    f"阶段 {stage_name} 下游服务不匹配，期望 {expected_service}，实际 {item.downstream_service or '-'}"
                )
        return True, None

    def _first_retry_stage_name(self, db: Session, task: BinarySecurityTask) -> str | None:
        stage_runs = {
            row.stage_name: row
            for row in db.query(BinarySecurityStageRun).filter(
                BinarySecurityStageRun.task_id == task.id,
            ).all()
        }
        for stage_name in self._stage_sequence_for_task(task):
            run = stage_runs.get(stage_name)
            if not run:
                return None
            if run.status not in {"success", "skipped", "waiting_confirmation"}:
                return stage_name
        return None

    def _task_retry_support(self, db: Session, task: BinarySecurityTask) -> tuple[bool, str | None, str | None]:
        if task.status in {"pending_upload", "uploading"}:
            return False, "当前任务仍在上传输入，不能重试", None
        stage_name = self._first_retry_stage_name(db, task)
        if not stage_name:
            return False, "当前任务没有可安全重试的失败阶段", None
        supported, reason = self._stage_retry_support(db, task, stage_name)
        if not supported:
            return False, f"阶段 {stage_name} 不支持安全重试: {reason}", stage_name
        return True, None, stage_name

    def _clear_stage_outputs_from(self, task: BinarySecurityTask, stage_name: str, *, mark_stale: bool = True) -> None:
        summary = dict(task.summary or {})
        metrics = dict(task.metrics or {})
        stage_summary = dict(task.stage_summary or {})
        stage_sequence = self._stage_sequence_for_task(task)
        if stage_name not in stage_sequence:
            return
        affected = stage_sequence[stage_sequence.index(stage_name):]
        for current_stage in affected:
            for summary_key in self._stage_result_keys(current_stage):
                summary.pop(summary_key, None)
            stage_summary.pop(current_stage, None)
            metrics.update(STAGE_METRIC_RESETTERS.get(current_stage, {}))
        if mark_stale:
            summary["stale_reason"] = "upstream_stage_retried"
            summary["stale_from_stage"] = stage_name
            summary["stale_stages"] = stage_sequence[stage_sequence.index(stage_name) + 1:]
        else:
            summary.pop("stale_reason", None)
            summary.pop("stale_from_stage", None)
            summary.pop("stale_stages", None)
        task.summary = summary
        task.metrics = metrics
        task.stage_summary = stage_summary

    def _reset_stage_run_for_retry(self, stage_run: BinarySecurityStageRun, *, increment_retry: bool) -> None:
        stage_run.status = "pending"
        if increment_retry:
            stage_run.retry_count = int(stage_run.retry_count or 0) + 1
        stage_run.started_at = None
        stage_run.finished_at = None
        stage_run.last_error = None
        stage_run.input_snapshot = {}
        stage_run.output_summary = {}
        stage_run.counts = {}
        stage_run.downstream_refs = {}

    async def _cancel_downstream(self, item: BinarySecurityStageItem, token: str | None) -> None:
        try:
            if item.downstream_service == "firmware_unpacker":
                await get_firmware_unpacker_client().cancel_task(item.downstream_task_id, token or "")
            elif item.downstream_service == "binary_to_source":
                result = item.result
                await get_binary_to_source_client().cancel_task(result.get("project_id") or item.project_id, item.downstream_task_id, token or "")
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

    def _collect_downstream_refs(self, task: BinarySecurityTask, items: list[BinarySecurityStageItem]) -> list[dict[str, str]]:
        refs: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for item in items:
            if not item.downstream_service or not item.downstream_task_id:
                continue
            key = (item.downstream_service, item.downstream_task_id)
            if key in seen:
                continue
            seen.add(key)
            refs.append(
                {
                    "service": item.downstream_service,
                    "task_id": item.downstream_task_id,
                    "project_id": task.project_id,
                    "stage_name": item.stage_name,
                }
            )
        return refs

    async def _cancel_local_worker(self, task_id: str) -> None:
        async with self._worker_lock:
            worker = self._workers.get(task_id)
        if worker and not worker.done():
            worker.cancel()
            await asyncio.gather(worker, return_exceptions=True)

    async def _cancel_downstream_refs(self, db: Session, task: BinarySecurityTask, refs: list[dict[str, str]], token: str | None) -> int:
        async def do_cancel(ref: dict[str, str]) -> bool:
            self._record_event(
                db,
                task,
                "downstream_cancel_requested",
                f"请求取消下游任务: {ref['service']}:{ref['task_id']}",
                stage_name=ref.get("stage_name"),
                payload=ref,
            )
            try:
                if ref["service"] == "firmware_unpacker":
                    await get_firmware_unpacker_client().cancel_task(ref["task_id"], token or "")
                elif ref["service"] == "system_analyse":
                    await get_system_analyse_client().cancel_task(ref["task_id"])
                elif ref["service"] == "binary_to_source":
                    await get_binary_to_source_client().cancel_task(ref["project_id"], ref["task_id"], token or "")
                elif ref["service"] == "entry_analyse":
                    await get_entry_analyse_client().cancel_task(ref["task_id"])
                elif ref["service"] == "dataflow_analyse":
                    await get_dataflow_analyse_client().cancel_task(ref["task_id"])
                elif ref["service"] == "dataflow_vuln_scanner":
                    await get_dataflow_vuln_scanner_client().cancel_task(ref["task_id"], token or "")
                return True
            except Exception as exc:
                self._record_event(
                    db,
                    task,
                    "downstream_cancel_failed",
                    f"下游取消失败: {ref['service']}:{ref['task_id']} - {exc}",
                    stage_name=ref.get("stage_name"),
                    level="warning",
                    payload={**ref, "error": str(exc)},
                )
                return False

        results = await asyncio.gather(*(do_cancel(ref) for ref in refs), return_exceptions=False)
        db.commit()
        return sum(1 for ok in results if ok)

    async def _delete_downstream_refs(self, db: Session, task: BinarySecurityTask, refs: list[dict[str, str]], token: str | None) -> int:
        async def do_delete(ref: dict[str, str]) -> bool:
            self._record_event(
                db,
                task,
                "downstream_delete_requested",
                f"请求删除下游任务: {ref['service']}:{ref['task_id']}",
                stage_name=ref.get("stage_name"),
                payload=ref,
            )
            try:
                if ref["service"] == "firmware_unpacker":
                    await get_firmware_unpacker_client().delete_task(ref["task_id"], token or "")
                elif ref["service"] == "system_analyse":
                    await get_system_analyse_client().delete_task(ref["task_id"])
                elif ref["service"] == "binary_to_source":
                    await get_binary_to_source_client().delete_task(ref["project_id"], ref["task_id"], token or "")
                elif ref["service"] == "entry_analyse":
                    await get_entry_analyse_client().delete_task(ref["task_id"])
                elif ref["service"] == "dataflow_analyse":
                    await get_dataflow_analyse_client().delete_task(ref["task_id"])
                elif ref["service"] == "dataflow_vuln_scanner":
                    await get_dataflow_vuln_scanner_client().delete_task(ref["task_id"], token or "")
                return True
            except Exception as exc:
                self._record_event(
                    db,
                    task,
                    "downstream_delete_failed",
                    f"下游删除失败: {ref['service']}:{ref['task_id']} - {exc}",
                    stage_name=ref.get("stage_name"),
                    level="warning",
                    payload={**ref, "error": str(exc)},
                )
                return False

        results = await asyncio.gather(*(do_delete(ref) for ref in refs), return_exceptions=False)
        db.commit()
        return sum(1 for ok in results if ok)

    async def _cleanup_task_workspace(self, task: BinarySecurityTask, token: str | None) -> str:
        relative_path = f"app/secflow-app-binary-security/{task.id}"
        workspace_root = Path(task.workspace_root)
        client = get_fileserver_client()
        cleanup_status = "deleted"
        try:
            await client.delete_project_path(task.project_id, relative_path, token, recursive=True)
        except Exception:
            cleanup_status = "fallback"
        try:
            shutil.rmtree(workspace_root, ignore_errors=True)
        except Exception:
            cleanup_status = "partial_failed"
        return cleanup_status

    async def _poll_until_terminal(self, fetcher, *, success_statuses: set[str], failure_statuses: set[str], task: BinarySecurityTask, item: BinarySecurityStageItem | None = None):
        while True:
            self._touch_task_heartbeat(task.id)
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

    def _touch_task_heartbeat(self, task_id: str) -> None:
        session = get_session_factory()()
        try:
            now = _now()
            session.query(BinarySecurityTask).filter(
                BinarySecurityTask.id == task_id,
                BinarySecurityTask.status == "running",
            ).update({BinarySecurityTask.updated_at: now}, synchronize_session=False)
            session.commit()
        finally:
            session.close()

    def _is_task_cancelled(self, task_id: str) -> bool:
        session = get_session_factory()()
        try:
            row = session.query(BinarySecurityTask.status).filter(BinarySecurityTask.id == task_id).first()
            return row is None or bool(row and row[0] == "cancelled")
        finally:
            session.close()

    async def _stage_firmware_unpack(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        token: str | None,
        retry_existing: bool = False,
    ) -> tuple[str, dict[str, Any]]:
        input_files = list(task.summary.get("input_files") or [])
        if not input_files:
            return "failed", {"error": "缺少输入文件"}
        results = await self._run_stage_pool(
            task,
            input_files,
            self._stage_parallelism(task, stage_run.stage_name),
            lambda input_file, retrying=False: self._run_firmware_item(task, stage_run, input_file, token, retrying),
            retries=int(task.policy.get("max_retries_per_item") or 0),
            initial_retry=retry_existing,
        )
        status, summary = self._aggregate_stage_items(db, task, results, "firmware_unpack_results")
        return status, summary

    async def _run_firmware_item(
        self,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        input_file: dict[str, Any],
        token: str | None,
        retrying: bool = False,
    ) -> dict[str, Any]:
        session = get_session_factory()()
        try:
            firmware_key = input_file["firmware_key"]
            input_path = Path(task.workspace_root) / "input" / input_file["filename"]
            output_dir = ensure_dir(Path(task.workspace_root) / "run" / "firmware-unpacker" / firmware_key)
            item = self._upsert_stage_item(
                session,
                task=task,
                stage_run=stage_run,
                stage_name=stage_run.stage_name,
                item_key=firmware_key,
                item_name=input_file["filename"],
                parent_key=firmware_key,
                downstream_service="firmware_unpacker",
                input_ref={"filename": input_file["filename"], "path": str(input_path)},
                output_ref={"output_path": str(output_dir)},
                retrying=retrying,
                running_status="queued",
            )
            session.commit()
            if retrying and self._has_retryable_downstream_task(item):
                created = await self._invoke_existing_downstream_retry(stage_run.stage_name, task=task, item=item, token=token)
            else:
                created = await get_firmware_unpacker_client().create_task(
                    task.project_id,
                    str(input_path),
                    str(output_dir),
                    token or "",
                    _downstream_origin_payload(task, item),
                )
            item.status = "running"
            item.downstream_task_id = created.get("task_id") or item.downstream_task_id
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
            archived_dir = self._archive_downstream_output(
                session,
                task,
                item,
                semantic_key=firmware_key,
                payload=payload,
                extra_paths=[output_dir],
            )
            result = {
                **input_file,
                "input_path": str(input_path),
                "unpacked_root": str(archived_dir or output_dir),
                "downstream": payload,
            }
            item.result = result
            item.output_ref = {
                "runtime_output_path": str(output_dir),
                "archive_root": str(archived_dir) if archived_dir else None,
                "unpacked_root": str(archived_dir or output_dir),
            }
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

    async def _stage_system_analysis(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        token: str | None,
        retry_existing: bool = False,
    ) -> tuple[str, dict[str, Any]]:
        del token
        system_inputs = self._system_analysis_inputs(task)
        if not system_inputs:
            return "failed", {"error": "缺少可用于系统分析的输入"}
        results = await self._run_stage_pool(
            task,
            system_inputs,
            self._stage_parallelism(task, stage_run.stage_name),
            lambda analysis_input, retrying=False: self._run_system_analysis_item(task, stage_run, analysis_input, retrying),
            retries=int(task.policy.get("max_retries_per_item") or 0),
            initial_retry=retry_existing,
        )
        success = [result["item"] for result in results if result.get("status") == "success"]
        failed = [result for result in results if result.get("status") == "failed"]
        all_modules: list[dict[str, Any]] = []
        for result in success:
            all_modules.extend(result.get("modules", []))
        candidate_modules = self._filter_candidate_modules(all_modules, self._module_risk_levels(task))
        if not candidate_modules:
            task.summary = {
                **task.summary,
                "system_analysis_results": self._lightweight_system_analysis_items(success),
                "system_analysis_modules": self._lightweight_modules_for_storage(all_modules),
                "system_analysis_module_count": len(all_modules),
                "candidate_modules": [],
                "selected_modules": [],
                "high_risk_modules": [],
            }
            task.metrics = {
                **task.metrics,
                **self._module_metrics(all_modules, [], []),
            }
            db.commit()
            return "failed", {
                "items": success,
                "failed_items": failed,
                "success_count": len(success),
                "failed_count": len(failed),
                "module_count": len(all_modules),
                "high_risk_module_count": sum(1 for module in all_modules if str(module.get("risk_level") or "").strip() == "高"),
                "medium_risk_module_count": sum(1 for module in all_modules if str(module.get("risk_level") or "").strip() == "中"),
                "low_risk_module_count": sum(1 for module in all_modules if str(module.get("risk_level") or "").strip() == "低"),
                "candidate_module_count": 0,
                "selected_module_count": 0,
                "error": failed[0].get("error") if failed else "没有匹配所选风险等级的模块",
            }
        selection_mode = self._module_selection_mode(task)
        selected_modules = self._mark_selected_modules(candidate_modules, selected_by=MODULE_SELECTION_MODE_AUTO) if selection_mode == MODULE_SELECTION_MODE_AUTO else []
        task.summary = {
            **task.summary,
            "system_analysis_results": self._lightweight_system_analysis_items(success),
            "system_analysis_modules": self._lightweight_modules_for_storage(all_modules),
            "system_analysis_module_count": len(all_modules),
            "candidate_modules": candidate_modules,
            "selected_modules": selected_modules,
            "high_risk_modules": selected_modules,
        }
        task.metrics = {
            **task.metrics,
            **self._module_metrics(all_modules, candidate_modules, selected_modules),
        }
        db.commit()
        status = "success"
        if failed and success:
            status = "partial_success"
        elif failed:
            status = "failed"
        if status in {"success", "partial_success"} and selection_mode == MODULE_SELECTION_MODE_MANUAL_CONFIRM:
            task.status = TASK_STATUS_PENDING_MODULE_CONFIRMATION
            self._record_event(
                db,
                task,
                "module_selection_required",
                "系统分析已完成，等待人工确认模块",
                stage_name=stage_run.stage_name,
                payload={"candidate_module_count": len(candidate_modules)},
            )
            db.commit()
        return status, {
            "items": success,
            "failed_items": failed,
            "success_count": len(success),
            "failed_count": len(failed),
            "module_count": len(all_modules),
            "high_risk_module_count": sum(1 for module in all_modules if str(module.get("risk_level") or "").strip() == "高"),
            "medium_risk_module_count": sum(1 for module in all_modules if str(module.get("risk_level") or "").strip() == "中"),
            "low_risk_module_count": sum(1 for module in all_modules if str(module.get("risk_level") or "").strip() == "低"),
            "candidate_module_count": len(candidate_modules),
            "selected_module_count": len(selected_modules),
            "requires_confirmation": selection_mode == MODULE_SELECTION_MODE_MANUAL_CONFIRM,
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

    async def _run_system_analysis_item(
        self,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        firmware: dict[str, Any],
        retrying: bool = False,
    ) -> dict[str, Any]:
        session = get_session_factory()()
        try:
            item = self._upsert_stage_item(
                session,
                task=task,
                stage_run=stage_run,
                stage_name=stage_run.stage_name,
                item_key=firmware["firmware_key"],
                item_name=firmware["filename"],
                parent_key=firmware["firmware_key"],
                downstream_service="system_analyse",
                input_ref={
                    "input_path": firmware["unpacked_root"],
                    "firmware_key": firmware["firmware_key"],
                    "task_type": self._task_type(task),
                    "analysis_mode": self._task_type(task),
                },
                retrying=retrying,
            )
            session.commit()
            if retrying and self._has_retryable_downstream_task(item):
                created = await self._invoke_existing_downstream_retry(stage_run.stage_name, task=task, item=item, token=None)
            else:
                created = await get_system_analyse_client().create_task(
                    task.project_id,
                    f"{task.name}-{firmware['firmware_name']}-system-analysis",
                    firmware["unpacked_root"],
                    _downstream_origin_payload(task, item),
                    analysis_mode=self._task_type(task),
                )
            item.downstream_task_id = created.get("task_id") or item.downstream_task_id
            session.commit()
            status, payload = await self._poll_until_terminal(
                lambda: get_system_analyse_client().get_task(item.downstream_task_id),
                success_statuses={"passed", "success"},
                failure_statuses={"failed", "error", "cancelled"},
                task=task,
                item=item,
            )
            result_payload = {}
            if status == "success":
                try:
                    result_payload = await get_system_analyse_client().get_task_result(item.downstream_task_id)
                except Exception:
                    result_payload = {}
            artifact_root = self._service_output_dir(task, item.downstream_service or stage_run.stage_name, firmware["firmware_key"], item.downstream_task_id)
            materialized = self._materialize_stage_artifact(
                artifact_root,
                item.downstream_task_id,
                {**payload, **({"result": result_payload} if result_payload else {})},
                db=session,
                task=task,
                item=item,
            )
            modules = self._parse_system_analysis_modules(materialized, firmware, result_payload)
            item.finished_at = _now()
            item.status = "success" if status == "success" else "cancelled" if status == "cancelled" else "failed"
            result = {
                **self._lightweight_system_analysis_input(firmware),
                "artifact_root": str(materialized),
                "archive_root": str(materialized),
                "modules": self._lightweight_modules_for_storage(modules),
                "module_count": len(modules),
                "downstream": self._lightweight_downstream_payload(payload),
                "system_analysis_result": self._lightweight_system_analysis_result(result_payload),
            }
            item.result = result
            item.output_ref = {"artifact_root": str(materialized), "archive_root": str(materialized)}
            session.commit()
            return {"status": item.status, "item": {**result, "modules": modules}, "error": payload.get("error") or payload.get("error_message")}
        except Exception as exc:
            if "item" in locals():
                session.rollback()
                item = session.merge(item)
                item.status = "failed"
                item.error_message = str(exc)
                item.finished_at = _now()
                item.result = {
                    **self._lightweight_system_analysis_input(firmware),
                    "error": str(exc),
                    "downstream_task_id": item.downstream_task_id,
                }
                session.commit()
            return {"status": "failed", "error": str(exc), "item": firmware}
        finally:
            session.close()

    def _lightweight_system_analysis_input(self, firmware: dict[str, Any]) -> dict[str, Any]:
        return {
            "firmware_key": firmware.get("firmware_key"),
            "firmware_name": firmware.get("firmware_name"),
            "filename": firmware.get("filename"),
            "unpacked_root": firmware.get("unpacked_root"),
            "source_root": firmware.get("source_root") or firmware.get("unpacked_root"),
            "task_type": firmware.get("task_type", TASK_TYPE_BINARY),
        }

    def _lightweight_downstream_payload(self, payload: dict[str, Any] | None) -> dict[str, Any]:
        payload = payload or {}
        keys = [
            "task_id",
            "id",
            "project_id",
            "status",
            "error",
            "error_message",
            "message",
            "output_path",
            "workspace_root",
            "created_at",
            "updated_at",
            "started_at",
            "finished_at",
        ]
        return {key: payload.get(key) for key in keys if payload.get(key) is not None}

    def _lightweight_system_analysis_result(self, result_payload: dict[str, Any] | None) -> dict[str, Any]:
        payload = result_payload or {}
        raw_summary = dict(payload.get("summary") or {})
        summary = {
            key: value
            for key, value in raw_summary.items()
            if isinstance(value, (int, float, bool)) or (isinstance(value, str) and len(value) <= 500)
        }
        modules = self._lightweight_modules_for_storage(list(payload.get("modules") or []))
        return {
            "available": payload.get("available"),
            "status": payload.get("status"),
            "output_root": payload.get("output_root"),
            "final_report_path": payload.get("final_report_path"),
            "modules_list_path": payload.get("modules_list_path"),
            "summary": summary,
            "module_count": len(modules),
            "modules": modules,
            "warnings": payload.get("warnings") or [],
        }

    def _lightweight_system_analysis_items(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        rows = []
        for item in items:
            row = dict(item)
            row["modules"] = self._lightweight_modules_for_storage(list(row.get("modules") or []))
            if "system_analysis_result" in row:
                row["system_analysis_result"] = self._lightweight_system_analysis_result(row.get("system_analysis_result") or {})
            rows.append(row)
        return rows

    def _lightweight_modules_for_storage(self, modules: list[dict[str, Any]], *, limit: int = 20) -> list[dict[str, Any]]:
        rows = []
        for module in modules[:limit]:
            rows.append(
                {
                    "module_key": module.get("module_key"),
                    "module_name": module.get("module_name"),
                    "rank": module.get("rank"),
                    "risk_level": module.get("risk_level"),
                    "risk_score": module.get("risk_score"),
                    "file_count": module.get("file_count"),
                    "source_dir": module.get("source_dir"),
                    "module_dir": module.get("module_dir") or module.get("module_dir_path"),
                    "module_report": module.get("module_report") or module.get("module_report_path"),
                    "files_list": module.get("files_list") or module.get("files_list_path"),
                }
            )
        return rows

    def _system_analysis_modules_from_item(self, task: BinarySecurityTask, item: BinarySecurityStageItem) -> list[dict[str, Any]]:
        result = dict(item.result or {})
        artifact_root = Path(str((item.output_ref or {}).get("archive_root") or result.get("archive_root") or result.get("artifact_root") or ""))
        modules_file = artifact_root / "system_analysis_modules.json"
        if modules_file.is_file():
            try:
                payload = json.loads(_read_text(modules_file) or "{}")
                rows = payload.get("items") or []
                if isinstance(rows, list):
                    return [dict(row) for row in rows if isinstance(row, dict)]
            except Exception:
                pass
        modules = result.get("modules") or []
        return [dict(row) for row in modules if isinstance(row, dict)]

    def _parse_system_analysis_modules(self, root: Path, firmware: dict[str, Any], result_payload: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        result_payload = result_payload or {}
        modules_list = root / "modules.list"
        modules_dir = root / "modules"
        items: list[dict[str, Any]] = []
        result_modules = list(result_payload.get("modules") or [])
        if result_modules:
            for module in sorted(result_modules, key=lambda item: int(item.get("rank") or 0)):
                name = str(module.get("module_name") or "").strip()
                if not name:
                    continue
                module_dir = Path(str(module.get("module_dir_path") or (modules_dir / name)))
                files_list = Path(str(module.get("files_list_path") or (module_dir / "files.list")))
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
                        "module_report": str(module.get("module_report_path") or (module_dir / "module_report.md")),
                        "files_list": str(files_list),
                        "risk_level": str(module.get("risk_level") or "").strip(),
                        "risk_score": int(module.get("risk_score") or 0),
                        "rank": int(module.get("rank") or 0),
                        "selected_by": None,
                        "selected_at": None,
                    }
                )
            _write_json(root / "system_analysis_modules.json", {"items": items})
            _write_json(root / "high_risk_modules.json", {"items": items})
            return items
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
                    "risk_level": "",
                    "risk_score": 0,
                    "rank": len(items) + 1,
                    "selected_by": None,
                    "selected_at": None,
                }
            )
        _write_json(root / "system_analysis_modules.json", {"items": items})
        _write_json(root / "high_risk_modules.json", {"items": items})
        return items

    def _service_output_dir(
        self,
        task: BinarySecurityTask,
        downstream_service: str,
        semantic_key: str,
        downstream_task_id: str | None,
    ) -> Path:
        return ensure_dir(self._service_output_path(task, downstream_service, semantic_key, downstream_task_id))

    def _service_output_path(
        self,
        task: BinarySecurityTask,
        downstream_service: str,
        semantic_key: str,
        downstream_task_id: str | None,
    ) -> Path:
        service_folder = SERVICE_OUTPUT_FOLDERS.get(downstream_service, downstream_service.replace("_", "-"))
        suffix = downstream_task_id or "unknown-task"
        dirname = f"{semantic_key}__{suffix}"
        return Path(task.output_root) / service_folder / dirname

    def _downstream_standard_output_sources(
        self,
        task: BinarySecurityTask,
        downstream_service: str | None,
        downstream_task_id: str | None,
    ) -> list[Path]:
        if not downstream_service or not downstream_task_id:
            return []
        app_root = DOWNSTREAM_APP_ROOTS.get(downstream_service)
        if not app_root:
            return []
        project_app_root = Path(task.workspace_root).parent.parent
        task_root = project_app_root / app_root / downstream_task_id
        return [task_root / "output", task_root]

    def _payload_output_candidates(
        self,
        payload: dict[str, Any] | None,
        *,
        downstream_task_id: str | None = None,
    ) -> list[Path]:
        candidates: list[Path] = []
        if not isinstance(payload, dict):
            return candidates
        for key in (
            "output_path",
            "output_root",
            "artifact_root",
            "artifacts_root",
            "result_root",
            "workspace_root",
            "work_dir",
            "task_root",
        ):
            value = payload.get(key)
            if not value:
                continue
            raw = Path(str(value))
            if key in {"output_path", "output_root"} and downstream_task_id:
                candidates.extend([raw / downstream_task_id / "output", raw / downstream_task_id])
            if key in {"workspace_root", "work_dir", "task_root"}:
                candidates.append(raw / "output")
            candidates.append(raw)
        for key in ("result", "artifacts", "artifact", "data"):
            nested = payload.get(key)
            if isinstance(nested, dict):
                candidates.extend(self._payload_output_candidates(nested, downstream_task_id=downstream_task_id))
        return candidates

    def _resolve_downstream_output_sources(
        self,
        payload: dict[str, Any] | None,
        *,
        downstream_task_id: str | None = None,
        extra_paths: list[str | Path] | None = None,
        task: BinarySecurityTask | None = None,
        downstream_service: str | None = None,
    ) -> list[Path]:
        candidates: list[Path] = []
        candidates.extend(self._payload_output_candidates(payload, downstream_task_id=downstream_task_id))
        if task is not None:
            candidates.extend(self._downstream_standard_output_sources(task, downstream_service, downstream_task_id))
        for value in extra_paths or []:
            if not value:
                continue
            raw = Path(str(value))
            if raw.is_file():
                candidates.append(raw.parent)
            else:
                candidates.append(raw)
        normalized: list[Path] = []
        for candidate in candidates:
            if candidate.name == "output":
                normalized.append(candidate)
                continue
            if candidate.is_dir() and (candidate / "output").exists():
                normalized.append(candidate / "output")
                continue
            normalized.append(candidate)
        return _dedupe_paths(normalized)

    def _archive_downstream_output(
        self,
        db: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        *,
        semantic_key: str,
        payload: dict[str, Any] | None = None,
        extra_paths: list[str | Path] | None = None,
    ) -> Path | None:
        target_dir = self._service_output_path(task, item.downstream_service or item.stage_name, semantic_key, item.downstream_task_id)
        sources = self._resolve_downstream_output_sources(
            payload,
            downstream_task_id=item.downstream_task_id,
            extra_paths=extra_paths,
            task=task,
            downstream_service=item.downstream_service,
        )
        existing_sources = [
            source
            for source in sources
            if source.exists()
            and _path_has_content(source)
            and source.resolve() != target_dir.resolve()
            and not _is_within_path(target_dir, source)
        ]
        if not existing_sources:
            self._record_event(
                db,
                task,
                "downstream_output_copy_skipped",
                f"下游阶段产物不存在，跳过归档: {item.downstream_service or item.stage_name}",
                stage_name=item.stage_name,
                item=item,
                level="warning",
                payload={
                    "target_dir": str(target_dir),
                    "sources": [str(path) for path in sources],
                },
            )
            return None
        try:
            ensure_dir(target_dir)
            for source in existing_sources:
                _copytree(source, target_dir)
        except Exception as exc:
            self._record_event(
                db,
                task,
                "downstream_output_copy_failed",
                f"下游阶段产物归档失败: {exc}",
                stage_name=item.stage_name,
                item=item,
                level="error",
                payload={
                    "target_dir": str(target_dir),
                    "sources": [str(path) for path in existing_sources],
                    "error": str(exc),
                },
            )
            return None
        self._record_event(
            db,
            task,
            "downstream_output_copied",
            f"下游阶段产物已归档: {item.downstream_service or item.stage_name}",
            stage_name=item.stage_name,
            item=item,
            payload={
                "target_dir": str(target_dir),
                "sources": [str(path) for path in existing_sources],
                "copied_file_count": _count_files(target_dir),
            },
        )
        return target_dir

    def _materialize_stage_artifact(
        self,
        artifact_root: Path,
        downstream_task_id: str | None,
        payload: dict[str, Any],
        *,
        db: Session | None = None,
        task: BinarySecurityTask | None = None,
        item: BinarySecurityStageItem | None = None,
    ) -> Path:
        existing_candidates = [
            candidate
            for candidate in self._resolve_downstream_output_sources(
                payload,
                downstream_task_id=downstream_task_id,
                task=task,
                downstream_service=item.downstream_service if item else None,
            )
            if candidate.exists()
            and _path_has_content(candidate)
            and candidate.resolve() != artifact_root.resolve()
            and not _is_within_path(artifact_root, candidate)
        ]
        if not existing_candidates:
            if db and task and item:
                self._record_event(
                    db,
                    task,
                    "downstream_output_copy_skipped",
                    f"下游阶段产物不存在，跳过归档: {item.downstream_service or item.stage_name}",
                    stage_name=item.stage_name,
                    item=item,
                    level="warning",
                    payload={"target_dir": str(artifact_root)},
                )
            ensure_dir(artifact_root)
            return artifact_root
        try:
            ensure_dir(artifact_root)
            for candidate in existing_candidates:
                _copytree(candidate, artifact_root)
        except Exception as exc:
            if db and task and item:
                self._record_event(
                    db,
                    task,
                    "downstream_output_copy_failed",
                    f"下游阶段产物归档失败: {exc}",
                    stage_name=item.stage_name,
                    item=item,
                    level="error",
                    payload={
                        "target_dir": str(artifact_root),
                        "sources": [str(path) for path in existing_candidates],
                        "error": str(exc),
                    },
                )
            return artifact_root
        if db and task and item:
            self._record_event(
                db,
                task,
                "downstream_output_copied",
                f"下游阶段产物已归档: {item.downstream_service or item.stage_name}",
                stage_name=item.stage_name,
                item=item,
                payload={
                    "target_dir": str(artifact_root),
                    "sources": [str(path) for path in existing_candidates],
                    "copied_file_count": _count_files(artifact_root),
                },
            )
        return artifact_root

    async def _stage_binary_to_source(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        token: str | None,
        retry_existing: bool = False,
    ) -> tuple[str, dict[str, Any]]:
        modules = list(task.summary.get("selected_modules") or [])
        if not modules:
            return "failed", {"error": "缺少已选模块列表"}
        results = await self._run_stage_pool(
            task,
            modules,
            self._stage_parallelism(task, stage_run.stage_name),
            lambda module, retrying=False: self._run_b2s_item(task, stage_run, module, token, retrying),
            retries=int(task.policy.get("max_retries_per_item") or 0),
            initial_retry=retry_existing,
        )
        return self._aggregate_stage_items(db, task, results, "b2s_results")

    async def _stage_entry_analysis(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        token: str | None,
        retry_existing: bool = False,
    ) -> tuple[str, dict[str, Any]]:
        b2s_success = self._entry_analysis_inputs(task)
        if not b2s_success:
            return "failed", {"error": "没有可用于入口分析的源码模块"}
        results = await self._run_stage_pool(
            task,
            b2s_success,
            self._stage_parallelism(task, stage_run.stage_name),
            lambda module, retrying=False: self._run_entry_item(task, stage_run, module, token, retrying),
            retries=int(task.policy.get("max_retries_per_item") or 0),
            initial_retry=retry_existing,
        )
        status, summary = self._aggregate_stage_items(db, task, results, "entry_results")
        summary["entry_count"] = sum(len(item.get("entries") or []) for item in summary.get("items", []))
        return status, summary

    def _entry_analysis_inputs(self, task: BinarySecurityTask) -> list[dict[str, Any]]:
        if self._task_type(task) == TASK_TYPE_SOURCE:
            return list(task.summary.get("selected_modules") or [])
        return list(task.summary.get("b2s_results") or [])

    async def _stage_dataflow_analysis(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        token: str | None,
        retry_existing: bool = False,
    ) -> tuple[str, dict[str, Any]]:
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
            lambda entry, retrying=False: self._run_dataflow_item(task, stage_run, entry, token, retrying),
            retries=int(task.policy.get("max_retries_per_item") or 0),
            initial_retry=retry_existing,
        )
        return self._aggregate_stage_items(db, task, results, "dataflow_results")

    async def _stage_vuln_scan(
        self,
        db: Session,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        token: str | None,
        retry_existing: bool = False,
    ) -> tuple[str, dict[str, Any]]:
        dataflow_results = list(task.summary.get("dataflow_results") or [])
        if not dataflow_results:
            return "failed", {"error": "没有可用于漏洞扫描的数据流结果"}
        results = await self._run_stage_pool(
            task,
            dataflow_results,
            self._stage_parallelism(task, stage_run.stage_name),
            lambda result, retrying=False: self._run_vuln_item(task, stage_run, result, token, retrying),
            retries=int(task.policy.get("max_retries_per_item") or 0),
            initial_retry=retry_existing,
        )
        status, summary = self._aggregate_stage_items(db, task, results, "vuln_results")
        summary["vuln_result_count"] = len(summary.get("items", []))
        return status, summary

    async def _run_stage_pool(
        self,
        task: BinarySecurityTask,
        items: list[dict[str, Any]],
        concurrency: int,
        runner,
        retries: int = 0,
        initial_retry: bool = False,
    ):
        semaphore = asyncio.Semaphore(max(1, concurrency))

        async def wrapped(item: dict[str, Any]):
            async with semaphore:
                if self._is_task_cancelled(task.id):
                    return {"status": "cancelled", "error": "task cancelled", "item": item}
                attempts = 0
                result = await runner(item, initial_retry)
                while result.get("status") == "failed" and attempts < max(0, retries):
                    attempts += 1
                    result = await runner(item, True)
                    result["attempts"] = attempts + 1
                return result

        return await asyncio.gather(*(wrapped(item) for item in items))

    async def _run_b2s_item(
        self,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        module: dict[str, Any],
        token: str | None,
        retrying: bool = False,
    ) -> dict[str, Any]:
        session = get_session_factory()()
        try:
            item = self._upsert_stage_item(
                session,
                task=task,
                stage_run=stage_run,
                stage_name=stage_run.stage_name,
                item_key=module["module_key"],
                item_name=module["module_name"],
                parent_key=module["firmware_key"],
                downstream_service="binary_to_source",
                input_ref=module,
                retrying=retrying,
            )
            session.commit()
            elf_path = self._choose_module_binary(module)
            if retrying and self._has_retryable_downstream_task(item):
                created = await self._invoke_existing_downstream_retry(stage_run.stage_name, task=task, item=item, token=token)
            else:
                created = await get_binary_to_source_client().create_task(
                    task.project_id,
                    f"{task.name}-{module['module_name']}",
                    elf_path,
                    token or "",
                    module,
                    _downstream_origin_payload(task, item),
                )
            item.downstream_task_id = created.get("id") or item.downstream_task_id
            item.result = {"project_id": task.project_id}
            session.commit()
            status, payload = await self._poll_until_terminal(
                lambda: get_binary_to_source_client().get_task(task.project_id, item.downstream_task_id, token or ""),
                success_statuses={"success", "partial_success"},
                failure_statuses={"failed", "cancelled"},
                task=task,
                item=item,
            )
            artifact_root = self._service_output_dir(task, item.downstream_service or stage_run.stage_name, module["module_key"], item.downstream_task_id)
            generated_files = []
            extra_paths: list[str] = []
            for child in payload.get("items", []):
                if child.get("output_dir"):
                    extra_paths.append(child["output_dir"])
                for file_path in child.get("generated_files") or []:
                    src = Path(file_path)
                    if src.exists():
                        target = artifact_root / src.name
                        _copytree(src, target)
                        generated_files.append(str(target))
                        extra_paths.append(str(src.parent))
            archived_dir = self._archive_downstream_output(
                session,
                task,
                item,
                semantic_key=module["module_key"],
                payload=payload,
                extra_paths=extra_paths,
            )
            result = {
                **module,
                "source_dir": str(archived_dir or artifact_root),
                "generated_files": generated_files,
                "downstream": payload,
            }
            item.status = "success" if status == "success" else "cancelled" if status == "cancelled" else "failed"
            item.finished_at = _now()
            item.result = result
            item.output_ref = {
                "archive_root": str(archived_dir or artifact_root),
                "source_dir": str(archived_dir or artifact_root),
            }
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

    async def _run_entry_item(
        self,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        module: dict[str, Any],
        token: str | None,
        retrying: bool = False,
    ) -> dict[str, Any]:
        del token
        session = get_session_factory()()
        try:
            item = self._upsert_stage_item(
                session,
                task=task,
                stage_run=stage_run,
                stage_name=stage_run.stage_name,
                item_key=module["module_key"],
                item_name=module["module_name"],
                parent_key=module["firmware_key"],
                downstream_service="entry_analyse",
                input_ref=module,
                retrying=retrying,
            )
            session.commit()
            if retrying and self._has_retryable_downstream_task(item):
                created = await self._invoke_existing_downstream_retry(stage_run.stage_name, task=task, item=item, token=None)
            else:
                created = await get_entry_analyse_client().create_task(
                    task.project_id,
                    f"{task.name}-{module['module_name']}-entry",
                    module["source_dir"],
                    module["module_name"],
                    module.get("source_root") or module.get("unpacked_root") or module["source_dir"],
                    _downstream_origin_payload(task, item),
                )
            item.downstream_task_id = created.get("task_id") or item.downstream_task_id
            session.commit()
            status, payload = await self._poll_until_terminal(
                lambda: get_entry_analyse_client().get_task(item.downstream_task_id),
                success_statuses={"passed", "success"},
                failure_statuses={"failed", "error", "cancelled"},
                task=task,
                item=item,
            )
            artifact_root = self._service_output_dir(task, item.downstream_service or stage_run.stage_name, module["module_key"], item.downstream_task_id)
            materialized = self._materialize_stage_artifact(
                artifact_root,
                item.downstream_task_id,
                payload,
                db=session,
                task=task,
                item=item,
            )
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
            item.output_ref = {"artifact_root": str(materialized), "archive_root": str(materialized)}
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
                            "firmware_key": module.get("firmware_key") or "",
                            "firmware_name": module.get("firmware_name") or "",
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
            if parts and not parts[0]:
                parts = parts[1:]
            if parts and not parts[-1]:
                parts = parts[:-1]
            if len(parts) >= 7 and parts[1].isdigit():
                file_name = parts[2]
                function_name = parts[3]
                line_no = parts[4]
                if file_name and function_name:
                    rows.append(
                        {
                            "entry_key": _slug(f"{module['module_key']}-{function_name}-{line_no}"),
                            "firmware_key": module.get("firmware_key") or "",
                            "firmware_name": module.get("firmware_name") or "",
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

    async def _run_dataflow_item(
        self,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        entry: dict[str, Any],
        token: str | None,
        retrying: bool = False,
    ) -> dict[str, Any]:
        del token
        session = get_session_factory()()
        try:
            item = self._upsert_stage_item(
                session,
                task=task,
                stage_run=stage_run,
                stage_name=stage_run.stage_name,
                item_key=entry["entry_key"],
                item_name=entry["function_name"],
                parent_key=entry["module_key"],
                downstream_service="dataflow_analyse",
                input_ref=entry,
                retrying=retrying,
            )
            session.commit()
            prompt = f"分析文件 {entry['file_name']} 中函数 {entry['function_name']} 的外部输入数据流"
            if retrying and self._has_retryable_downstream_task(item):
                created = await self._invoke_existing_downstream_retry(stage_run.stage_name, task=task, item=item, token=None)
            else:
                created = await get_dataflow_analyse_client().create_task(
                    task.project_id,
                    f"{task.name}-{entry['function_name']}-dfa",
                    entry["source_dir"],
                    prompt,
                    _downstream_origin_payload(task, item),
                )
            item.downstream_task_id = created.get("task_id") or item.downstream_task_id
            session.commit()
            status, payload = await self._poll_until_terminal(
                lambda: get_dataflow_analyse_client().get_task(item.downstream_task_id),
                success_statuses={"passed", "success"},
                failure_statuses={"failed", "error", "cancelled"},
                task=task,
                item=item,
            )
            artifact_root = self._service_output_dir(task, item.downstream_service or stage_run.stage_name, entry["entry_key"], item.downstream_task_id)
            materialized = self._materialize_stage_artifact(
                artifact_root,
                item.downstream_task_id,
                payload,
                db=session,
                task=task,
                item=item,
            )
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
            item.output_ref = {"artifact_root": str(materialized), "archive_root": str(materialized), "data_flow_file": result["data_flow_file"]}
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

    async def _run_vuln_item(
        self,
        task: BinarySecurityTask,
        stage_run: BinarySecurityStageRun,
        dataflow_result: dict[str, Any],
        token: str | None,
        retrying: bool = False,
    ) -> dict[str, Any]:
        session = get_session_factory()()
        try:
            item = self._upsert_stage_item(
                session,
                task=task,
                stage_run=stage_run,
                stage_name=stage_run.stage_name,
                item_key=dataflow_result["entry_key"],
                item_name=dataflow_result["function_name"],
                parent_key=dataflow_result["module_key"],
                downstream_service="dataflow_vuln_scanner",
                input_ref=dataflow_result,
                retrying=retrying,
            )
            session.commit()
            vuln_workspace = ensure_dir(Path(task.workspace_root) / "run" / "dataflow-vuln-scanner" / dataflow_result["entry_key"] / "workspace")
            vuln_output = vuln_workspace / "output"
            ensure_dir(vuln_output)
            if retrying and self._has_retryable_downstream_task(item):
                created = await self._invoke_existing_downstream_retry(stage_run.stage_name, task=task, item=item, token=token)
            else:
                created = await get_dataflow_vuln_scanner_client().create_task(
                    task.project_id,
                    f"{task.name}-{dataflow_result['function_name']}-scan",
                    token or "",
                    dataflow_result["data_flow_file"],
                    dataflow_result["source_dir"],
                    str(vuln_workspace),
                    str(vuln_output),
                    _downstream_origin_payload(task, item),
                )
            item.downstream_task_id = created.get("task_id") or item.downstream_task_id
            session.commit()
            status, payload = await self._poll_until_terminal(
                lambda: get_dataflow_vuln_scanner_client().get_task(item.downstream_task_id, token or ""),
                success_statuses={"success", "succeeded", "completed"},
                failure_statuses={"failed", "cancelled"},
                task=task,
                item=item,
            )
            artifacts = await get_dataflow_vuln_scanner_client().get_artifacts(item.downstream_task_id, token or "")
            archived_dir = self._archive_downstream_output(
                session,
                task,
                item,
                semantic_key=dataflow_result["entry_key"],
                payload={"workspace_root": artifacts.get("workspace_root")},
            )
            result = {
                **dataflow_result,
                "workspace_root": artifacts.get("workspace_root"),
                "artifact_files": artifacts.get("files", []),
                "archive_root": str(archived_dir) if archived_dir else None,
                "downstream": payload,
                "artifacts": artifacts,
            }
            item.status = "success" if status == "success" else "cancelled" if status == "cancelled" else "failed"
            item.finished_at = _now()
            item.result = result
            item.output_ref = {
                "workspace_root": artifacts.get("workspace_root"),
                "archive_root": str(archived_dir) if archived_dir else None,
            }
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
        failed = [self._lightweight_stage_failure(result) for result in results if result.get("status") == "failed"]
        cancelled = [self._lightweight_stage_failure(result) for result in results if result.get("status") == "cancelled"]
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

    def _lightweight_stage_failure(self, result: dict[str, Any]) -> dict[str, Any]:
        item = result.get("item") or {}
        if not isinstance(item, dict):
            item = {}
        error = str(result.get("error") or "")[:1000]
        return {
            "status": result.get("status"),
            "error": error,
            "item": {
                "firmware_key": item.get("firmware_key"),
                "firmware_name": item.get("firmware_name"),
                "module_key": item.get("module_key"),
                "module_name": item.get("module_name"),
                "entry_key": item.get("entry_key"),
                "function_name": item.get("function_name"),
                "file_name": item.get("file_name"),
                "line_no": item.get("line_no"),
                "source_dir": item.get("source_dir"),
            },
        }

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
