from __future__ import annotations

import asyncio
import errno
import json
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.exception import ValidationError
from app.model import (
    BinarySecurityArchiveJob,
    BinarySecurityEvent,
    BinarySecurityStageItem,
    BinarySecurityStageRun,
    BinarySecurityStateEvent,
    BinarySecurityTask,
    build_archive_job_dedupe_key,
    normalize_stage_name,
)
from app.service.security import ensure_dir

from . import shared as task_shared

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager


class TaskResultServiceMixin:
    _SYNC_RESULT_ROOT_KEYS = (
        "sync_status",
        "downstream_status",
        "downstream_status_synced_at",
        "last_sync_attempt_at",
        "last_sync_success_at",
        "last_sync_error_at",
        "last_sync_error_message",
        "last_sync_error_type",
        "last_sync_result",
        "consecutive_sync_error_count",
        "sync_error_budget_exhausted",
        "next_sync_retry_at",
        "sync_observation",
    )

    def _normalize_result_payload_value(self: TaskManager, value: Any) -> Any:
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, datetime):
            return task_shared._isoformat_or_none(value)
        if isinstance(value, dict):
            return {str(key): self._normalize_result_payload_value(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._normalize_result_payload_value(item) for item in value]
        if isinstance(value, tuple):
            return [self._normalize_result_payload_value(item) for item in value]
        if isinstance(value, set):
            return [self._normalize_result_payload_value(item) for item in sorted(value, key=lambda item: str(item))]
        return value

    def _merge_result_with_preserved_sync_fields(
        self: TaskManager,
        item: BinarySecurityStageItem,
        result: dict[str, Any] | None,
    ) -> dict[str, Any]:
        merged = self._normalize_result_payload_value(dict(result or {}))
        existing = self._normalize_result_payload_value(dict(getattr(item, "result", None) or {}))
        if not existing:
            return merged
        for key in self._SYNC_RESULT_ROOT_KEYS:
            if key not in merged and key in existing:
                merged[key] = existing[key]
        if "downstream" not in merged and "downstream" in existing:
            merged["downstream"] = existing["downstream"]
        return merged

    def _build_binary_module_summary(
        self: TaskManager,
        task: BinarySecurityTask,
        input_files: list[dict[str, Any]],
    ) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        input_dir = Path(str(task.summary.get("input_dir") or Path(task.workspace_root) / "input"))
        module_input = dict(task.summary.get("module_input") or {})
        module_name = str(module_input.get("module_name") or task.name or "module").strip() or "module"
        module_key = task_shared._slug(module_name)
        firmware_key = task_manager_module.MODULE_TASK_INPUT_KEY
        files_list_path = input_dir / "module-files.list"
        rel_paths = [str(item.get("relative_path") or item.get("filename") or "").strip().replace("\\", "/") for item in input_files]
        files_list_path.write_text("\n".join(path for path in rel_paths if path) + ("\n" if rel_paths else ""), encoding="utf-8")
        selected_at = task_shared._now().isoformat()
        module = {
            "module_key": module_key,
            "module_name": module_name,
            "task_type": task_manager_module.TASK_TYPE_BINARY_MODULE,
            "firmware_key": firmware_key,
            "firmware_name": module_name,
            "source_dir": str(input_dir),
            "module_dir": str(input_dir),
            "files_list": str(files_list_path),
            "unpacked_root": str(input_dir),
            "source_root": str(input_dir),
            "file_count": len(input_files),
            "risk_level": "高",
            "risk_source": "manual_input",
            "selected_by": "manual_input",
            "selected_at": selected_at,
        }
        return {
            "module_input": {
                **module_input,
                "module_name": module_name,
                "module_key": module_key,
                "file_count": len(input_files),
            },
            "selected_modules": [module],
            "candidate_modules": [module],
            "system_analysis_modules": [module],
            "high_risk_modules": [module],
            "system_analysis_bypassed": True,
        }

    def _build_binary_module_restart_summary(
        self: TaskManager,
        task: BinarySecurityTask,
        input_files: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return {
            "downstream_task_ids": {},
            **self._build_binary_module_summary(task, input_files),
        }

    def _reset_task_for_hard_restart(self: TaskManager, task: BinarySecurityTask) -> None:
        from app.service import task_manager as task_manager_module

        input_files = [dict(item) for item in (task.summary or {}).get("input_files") or []]
        task.execution_epoch = int(getattr(task, "execution_epoch", 0) or 0) + 1
        task.execution_mode = None
        task.target_stage_name = None
        task.last_error = None
        task.finished_at = None
        task.started_at = None
        task.current_stage = self._stage_sequence_for_task(task)[0]
        self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION)
        task.tail_reconcile_state = "idle"
        self._invalidate_task_execution(task)
        task.summary = self._base_task_summary(task, input_files=input_files)
        task.metrics = self._base_task_metrics(task, input_files=input_files)
        task.stage_summary = {}
        task.cleanup_snapshot = {}
        if (
            self._task_type(task) == task_manager_module.TASK_TYPE_BINARY_MODULE
            and not list((task.summary or {}).get("selected_modules") or [])
        ):
            raise ValidationError("binary_module 硬重启后缺少已选模块上下文")

    def _delete_task_summary_file(self: TaskManager, task: BinarySecurityTask) -> None:
        from app.service import task_manager as task_manager_module

        summary_path = Path(task.workspace_root) / task_manager_module.BinarySecurityTask.SUMMARY_FILENAME
        try:
            if summary_path.exists():
                summary_path.unlink()
        except Exception:
            pass

    def _clear_stage_output_artifacts(self: TaskManager, task: BinarySecurityTask, stage_names: list[str]) -> None:
        from app.service import task_manager as task_manager_module

        output_root = Path(str(task.output_root or "")).resolve()
        if not output_root.exists():
            return
        services: set[str] = set()
        for stage_name in stage_names:
            for downstream_service in task_manager_module.STAGE_OUTPUT_SERVICES.get(stage_name, []):
                services.add(downstream_service)
        for downstream_service in services:
            folder_names = [
                task_manager_module.SERVICE_OUTPUT_FOLDERS.get(downstream_service, downstream_service.replace("_", "-")),
                *task_manager_module.LEGACY_SERVICE_OUTPUT_FOLDERS.get(downstream_service, ()),
            ]
            for folder in folder_names:
                target = output_root / folder
                if target.exists():
                    try:
                        shutil.rmtree(target, ignore_errors=True)
                    except OSError as exc:
                        if exc.errno != errno.ESTALE:
                            raise

    def _clear_single_stage_outputs(self: TaskManager, task: BinarySecurityTask, stage_name: str) -> None:
        from app.service import task_manager as task_manager_module

        summary = dict(task.summary or {})
        metrics = dict(task.metrics or {})
        stage_summary = dict(task.stage_summary or {})
        for summary_key in self._stage_result_keys(stage_name):
            summary.pop(summary_key, None)
        stage_summary.pop(stage_name, None)
        metrics.update(task_manager_module.STAGE_METRIC_RESETTERS.get(stage_name, {}))
        task.summary = summary
        task.metrics = metrics
        task.stage_summary = stage_summary
        self._clear_stage_output_artifacts(task, [stage_name])

    def _clear_single_stage_runtime_state(self: TaskManager, task: BinarySecurityTask, stage_name: str) -> None:
        from app.service import task_manager as task_manager_module

        summary = dict(task.summary or {})
        metrics = dict(task.metrics or {})
        stage_summary = dict(task.stage_summary or {})
        for summary_key in self._stage_result_keys(stage_name):
            summary.pop(summary_key, None)
        stage_summary.pop(stage_name, None)
        metrics.update(task_manager_module.STAGE_METRIC_RESETTERS.get(stage_name, {}))
        task.summary = summary
        task.metrics = metrics
        task.stage_summary = stage_summary

    async def _cleanup_task_workspace(self: TaskManager, task: BinarySecurityTask, token: str | None) -> str:
        from app.service import task_manager as task_manager_module

        workspace_root = task_manager_module.Path(task.workspace_root)
        client = task_manager_module.get_fileserver_client()
        cleanup_status = "deleted"
        check_paths = [
            workspace_root,
            workspace_root / "input",
            workspace_root / "run",
            workspace_root / "input" / "task-metadata.json",
        ]
        try:
            await client.delete_project_path(task.project_id, str(workspace_root), token, recursive=True)
        except Exception:
            cleanup_status = "fallback"
        try:
            await task_manager_module.asyncio.to_thread(shutil.rmtree, workspace_root, True)
        except Exception:
            cleanup_status = "partial_failed"
        recreated = False
        if any(path.exists() for path in check_paths):
            cleanup_status = "partial_failed"
            for _attempt in range(6):
                await task_manager_module.asyncio.sleep(5)
                if not any(path.exists() for path in check_paths):
                    cleanup_status = "deleted" if cleanup_status != "fallback" else "fallback"
                    break
                recreated = True
            else:
                cleanup_status = "recreated_during_delete" if recreated else "partial_failed"
        return cleanup_status

    def _delete_task_event_payload_dirs(self: TaskManager, task: BinarySecurityTask) -> None:
        root = Path(task.workspace_root)
        for folder_name in ("state-event-payloads", "timeline-event-payloads"):
            target = root / folder_name
            if not target.exists():
                continue
            try:
                shutil.rmtree(target, ignore_errors=True)
            except OSError as exc:
                if exc.errno != errno.ESTALE:
                    raise

    def _delete_stage_run_rows(self: TaskManager, db: Session, task_id: str) -> int:
        deleted = int(
            db.query(BinarySecurityStageRun)
            .filter(BinarySecurityStageRun.task_id == task_id)
            .delete(synchronize_session=False)
            or 0
        )
        if hasattr(db, "stage_runs") and isinstance(getattr(db, "stage_runs"), list):
            db.stage_runs = [row for row in db.stage_runs if str(getattr(row, "task_id", "") or "").strip() != task_id]
        return deleted

    def _delete_task_timeline_rows(self: TaskManager, db: Session, task_id: str) -> int:
        deleted = int(
            db.query(BinarySecurityEvent)
            .filter(BinarySecurityEvent.task_id == task_id)
            .delete(synchronize_session=False)
            or 0
        )
        if hasattr(db, "events") and isinstance(getattr(db, "events"), list):
            db.events = [row for row in db.events if str(getattr(row, "task_id", "") or "").strip() != task_id]
        return deleted

    def _delete_timeline_rows_for_stages(self: TaskManager, db: Session, task_id: str, stage_names: list[str]) -> int:
        normalized = [str(stage_name or "").strip() for stage_name in stage_names if str(stage_name or "").strip()]
        if not normalized:
            return 0
        preserved_event_types = {
            "stage_retry_full_cleanup_started",
            "stage_retry_full_cleanup_finished",
            "child_task_cancel_requested",
            "child_task_cancel_succeeded",
            "child_task_cancel_failed",
            "child_task_inactive_check_requested",
            "child_task_inactive_check_succeeded",
            "child_task_inactive_check_blocked",
            "child_task_delete_requested",
            "child_task_delete_succeeded",
            "child_task_delete_verified_absent",
            "child_task_delete_failed_but_ignored",
            "child_task_delete_failed_blocking",
        }
        candidate_rows = (
            db.query(BinarySecurityEvent)
            .filter(
                BinarySecurityEvent.task_id == task_id,
                BinarySecurityEvent.stage_name.in_(normalized),
            )
            .all()
        )
        removable_ids = [
            str(getattr(row, "id", "") or "").strip()
            for row in candidate_rows
            if str(getattr(row, "operation_id", "") or "").strip() == ""
            or str(getattr(row, "event_type", "") or "").strip() not in preserved_event_types
        ]
        if not removable_ids:
            return 0
        deleted = int(
            db.query(BinarySecurityEvent)
            .filter(BinarySecurityEvent.id.in_(removable_ids))
            .delete(synchronize_session=False)
            or 0
        )
        if hasattr(db, "events") and isinstance(getattr(db, "events"), list):
            removable = set(removable_ids)
            db.events = [
                row for row in db.events
                if str(getattr(row, "id", "") or "").strip() not in removable
            ]
        return deleted

    def _delete_task_state_event_rows(self: TaskManager, db: Session, task_id: str) -> int:
        deleted = int(
            db.query(BinarySecurityStateEvent)
            .filter(BinarySecurityStateEvent.task_id == task_id)
            .delete(synchronize_session=False)
            or 0
        )
        if hasattr(db, "state_events") and isinstance(getattr(db, "state_events"), list):
            db.state_events = [row for row in db.state_events if str(getattr(row, "task_id", "") or "").strip() != task_id]
        return deleted

    def _delete_state_event_rows_for_stages(self: TaskManager, db: Session, task_id: str, stage_names: list[str]) -> int:
        normalized = [str(stage_name or "").strip() for stage_name in stage_names if str(stage_name or "").strip()]
        if not normalized:
            return 0
        deleted = int(
            db.query(BinarySecurityStateEvent)
            .filter(
                BinarySecurityStateEvent.task_id == task_id,
                BinarySecurityStateEvent.stage_name.in_(normalized),
            )
            .delete(synchronize_session=False)
            or 0
        )
        if hasattr(db, "state_events") and isinstance(getattr(db, "state_events"), list):
            allowed = set(normalized)
            db.state_events = [
                row for row in db.state_events
                if not (
                    str(getattr(row, "task_id", "") or "").strip() == task_id
                    and str(getattr(row, "stage_name", "") or "").strip() in allowed
                )
            ]
        return deleted

    def _delete_workspace_runtime_children(self: TaskManager, task: BinarySecurityTask) -> None:
        from app.service import task_manager as task_manager_module

        workspace_root = Path(task.workspace_root)
        input_dir = workspace_root / "input"
        keep_files = {"task-metadata.json"}
        keep_all_input_children = self._task_type(task) == task_manager_module.TASK_TYPE_BINARY_MODULE
        if input_dir.exists() and not keep_all_input_children:
            for child in input_dir.iterdir():
                if child.name in keep_files:
                    continue
                if child.is_dir():
                    shutil.rmtree(child, ignore_errors=True)
                else:
                    child.unlink(missing_ok=True)
        for folder_name in ("output", "run", "logs"):
            target = workspace_root / folder_name
            if target.exists():
                shutil.rmtree(target, ignore_errors=True)
            ensure_dir(target)
        ensure_dir(workspace_root / "run" / "upload-tmp")

    def _validate_hard_restart_cleanup(self: TaskManager, db: Session, task: BinarySecurityTask) -> dict[str, int]:
        if all(hasattr(db, attr) for attr in ("stage_items", "stage_runs", "archive_jobs", "events", "state_events")):
            checks = {
                "stage_item_count": len([row for row in db.stage_items if str(getattr(row, "task_id", "") or "").strip() == task.id]),
                "stage_run_count": len([row for row in db.stage_runs if str(getattr(row, "task_id", "") or "").strip() == task.id]),
                "archive_job_count": len([row for row in db.archive_jobs if str(getattr(row, "task_id", "") or "").strip() == task.id]),
                "timeline_event_count": len([row for row in db.events if str(getattr(row, "task_id", "") or "").strip() == task.id]),
                "state_event_count": len([row for row in db.state_events if str(getattr(row, "task_id", "") or "").strip() == task.id]),
            }
        else:
            checks = {
                "stage_item_count": int(db.query(func.count(BinarySecurityStageItem.id)).filter(BinarySecurityStageItem.task_id == task.id).scalar() or 0),
                "stage_run_count": int(db.query(func.count(BinarySecurityStageRun.id)).filter(BinarySecurityStageRun.task_id == task.id).scalar() or 0),
                "archive_job_count": int(db.query(func.count(BinarySecurityArchiveJob.id)).filter(BinarySecurityArchiveJob.task_id == task.id).scalar() or 0),
                "timeline_event_count": int(db.query(func.count(BinarySecurityEvent.id)).filter(BinarySecurityEvent.task_id == task.id).scalar() or 0),
                "state_event_count": int(db.query(func.count(BinarySecurityStateEvent.id)).filter(BinarySecurityStateEvent.task_id == task.id).scalar() or 0),
            }
        blocking_keys = {
            "stage_item_count",
            "stage_run_count",
            "archive_job_count",
            "state_event_count",
        }
        non_zero = {key: value for key, value in checks.items() if key in blocking_keys and int(value or 0) > 0}
        if non_zero:
            raise ValidationError(f"硬重启清理未完成，仍有残留: {non_zero}")
        return checks

    def _lightweight_downstream_payload(self: TaskManager, payload: dict[str, Any] | None) -> dict[str, Any]:
        payload = payload or {}
        keys = [
            "task_id",
            "id",
            "project_id",
            "status",
            "cancel_phase",
            "cancel_requested",
            "cancel_acknowledged",
            "cancel_process_cleanup_done",
            "cancel_finalized",
            "cancel_requested_at",
            "cancel_acknowledged_at",
            "cancel_process_cleanup_at",
            "cancel_finalized_at",
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
        compact: dict[str, Any] = {}
        for key in keys:
            value = payload.get(key)
            if value is None:
                continue
            compact[key] = self._normalize_result_payload_value(value)
        return compact

    def _archive_job_downstream_payload(self: TaskManager, payload: dict[str, Any] | None) -> dict[str, Any]:
        def _compact_payload_dict(source: dict[str, Any] | None) -> dict[str, Any]:
            data = source or {}
            compact = {
                key: data.get(key)
                for key in (
                    "id",
                    "task_id",
                    "status",
                    "result_status",
                    "message",
                    "error",
                    "error_message",
                    "output_root",
                    "work_dir",
                    "task_root",
                )
                if data.get(key) not in (None, "", [], {})
            }
            return compact

        compact = _compact_payload_dict(payload)
        payload = payload or {}
        for key in ("result", "artifacts", "artifact", "data"):
            nested = payload.get(key)
            if not isinstance(nested, dict):
                continue
            nested_compact = _compact_payload_dict(nested)
            if nested_compact:
                compact[key] = nested_compact
        return compact

    @staticmethod
    def _archive_job_payload_size(payload: dict[str, Any] | None) -> int:
        try:
            return len(json.dumps(payload or {}, ensure_ascii=False))
        except Exception:
            return 0

    def _trim_archive_job_payload_for_storage(
        self: TaskManager,
        payload: dict[str, Any] | None,
        *,
        max_bytes: int = 16 * 1024,
    ) -> dict[str, Any]:
        compact = dict(payload or {})
        if self._archive_job_payload_size(compact) <= max_bytes:
            return compact
        downstream_payload = dict(compact.get("downstream_payload") or {})
        if downstream_payload:
            trimmed_downstream = {
                key: downstream_payload.get(key)
                for key in ("status", "error", "error_message", "task_id", "id", "output_root")
                if downstream_payload.get(key) not in (None, "", [], {})
            }
            compact["downstream_payload"] = trimmed_downstream
        if self._archive_job_payload_size(compact) <= max_bytes:
            return compact
        for key in ("extra_paths", "archive_source_paths"):
            values = compact.get(key)
            if isinstance(values, list) and len(values) > 3:
                compact[key] = values[:3]
        if self._archive_job_payload_size(compact) <= max_bytes:
            return compact
        fallback = {
            key: compact.get(key)
            for key in (
                "mapped_status",
                "before_status",
                "force",
                "bound_downstream_task_id",
                "archive_source_primary_path",
            )
            if compact.get(key) not in (None, "", [], {})
        }
        if compact.get("downstream_payload"):
            fallback["downstream_payload"] = compact.get("downstream_payload")
        return fallback

    def _build_archive_job_payload(
        self: TaskManager,
        *,
        mapped_status: str,
        before_status: str | None,
        force: bool,
        payload: dict[str, Any] | None,
        bound_downstream_task_id: str | None = None,
        extra_paths: list[str | Path] | None = None,
        previous_payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        preserved = dict(previous_payload or {})
        preserved.pop("archive_copy_stats", None)
        payload_for_storage = {
            **preserved,
            "mapped_status": mapped_status,
            "before_status": before_status,
            "force": force,
            "bound_downstream_task_id": str(bound_downstream_task_id or "").strip() or None,
            "downstream_payload": self._archive_job_downstream_payload(payload),
            "extra_paths": [str(path) for path in (extra_paths or [])],
        }
        return self._trim_archive_job_payload_for_storage(payload_for_storage)

    def _with_archive_source_payload(
        self: TaskManager,
        payload: dict[str, Any] | None,
        *,
        archive_source_paths: list[str] | None,
    ) -> dict[str, Any]:
        next_payload = dict(payload or {})
        normalized = [str(path).strip() for path in list(archive_source_paths or []) if str(path).strip()]
        next_payload["archive_source_paths"] = normalized
        next_payload["archive_source_primary_path"] = normalized[0] if normalized else None
        return next_payload

    def _archive_job_payload_requires_refresh(
        self: TaskManager,
        job: BinarySecurityArchiveJob,
        *,
        next_payload: dict[str, Any],
    ) -> bool:
        current_payload = dict(job.payload or {})
        current_downstream = dict(current_payload.get("downstream_payload") or {})
        next_downstream = dict(next_payload.get("downstream_payload") or {})
        current_extra_paths = [str(path) for path in (current_payload.get("extra_paths") or [])]
        next_extra_paths = [str(path) for path in (next_payload.get("extra_paths") or [])]
        return (
            str(current_payload.get("mapped_status") or "").strip() != str(next_payload.get("mapped_status") or "").strip()
            or str(current_payload.get("bound_downstream_task_id") or "").strip() != str(next_payload.get("bound_downstream_task_id") or "").strip()
            or current_downstream != next_downstream
            or current_extra_paths != next_extra_paths
        )

    def _lightweight_artifacts_payload(self: TaskManager, payload: dict[str, Any] | None) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        payload = payload or {}
        files = payload.get("files") or []
        return {
            key: value
            for key, value in {
                "workspace_root": payload.get("workspace_root"),
                "output_root": payload.get("output_root"),
                "task_root": payload.get("task_root"),
                "status": payload.get("status"),
                "file_count": len(files) if isinstance(files, list) else 0,
                "files_preview": files[: task_manager_module.DB_ARTIFACT_PREVIEW_LIMIT] if isinstance(files, list) else [],
            }.items()
            if value not in (None, "")
        }

    def _stage_item_result_path(
        self: TaskManager,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
    ) -> Path | None:
        workspace_root = str(getattr(task, "workspace_root", "") or "").strip()
        item_id = str(getattr(item, "id", "") or "").strip()
        if not workspace_root or not item_id:
            return None
        return Path(workspace_root) / "run" / "stage-items" / item_id / "result.json"

    def _result_payload_needs_externalization(
        self: TaskManager,
        stage_name: str,
        result: dict[str, Any],
    ) -> bool:
        normalized_stage = normalize_stage_name(stage_name)
        if normalized_stage in {"system_analysis", "entry_analysis", "dataflow_vuln_scan", "binary_to_source"}:
            if any(key in result for key in ("entries", "modules", "artifact_files", "system_analysis_result")):
                return True
        try:
            payload_size = len(json.dumps(result, ensure_ascii=False))
        except Exception:
            return False
        return payload_size >= 16 * 1024

    def _load_stage_item_result_payload(self: TaskManager, item: BinarySecurityStageItem) -> dict[str, Any]:
        result = dict(item.result or {})
        result_path = str(result.get("result_path") or "").strip()
        if not result_path:
            return result
        try:
            loaded = task_shared._read_json(Path(result_path))
        except Exception:
            return {
                **result,
                "missing_externalized_result": True,
            }
        if not isinstance(loaded, dict):
            return result
        merged = dict(loaded)
        for key, value in result.items():
            merged.setdefault(key, value)
        return merged

    def _merge_stage_item_result_fields(
        self: TaskManager,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        *,
        stage_name: str,
        updates: dict[str, Any] | None,
    ) -> dict[str, Any]:
        merged = {
            **self._load_stage_item_result_payload(item),
            **dict(updates or {}),
        }
        return self._persist_stage_item_result(
            task,
            item,
            stage_name=stage_name,
            result=merged,
        )

    def _persist_stage_item_result(
        self: TaskManager,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        *,
        stage_name: str,
        result: dict[str, Any] | None,
        preserve_sync_fields: bool = False,
    ) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        if preserve_sync_fields:
            full_result = self._merge_result_with_preserved_sync_fields(item, result)
        else:
            full_result = self._normalize_result_payload_value(dict(result or {}))
        compact = self._compact_result_for_storage(stage_name, full_result)
        if not self._result_payload_needs_externalization(stage_name, full_result):
            item.result = compact
            return compact
        path = self._stage_item_result_path(task, item)
        if path is None:
            item.result = compact
            return compact
        try:
            task_shared._write_json(path, full_result)
            item.result = {
                **compact,
                "result_path": str(path),
            }
            return dict(item.result or {})
        except OSError:
            fallback_root = (
                Path(tempfile.gettempdir())
                / "secflow-binary-security"
                / "stage-items"
                / str(task.id or "unknown")
                / str(item.id or "unknown")
            )
            fallback_path = fallback_root / "result.json"
            task_shared._write_json(fallback_path, full_result)
            item.result = {
                **compact,
                "result_path": str(fallback_path),
            }
            return dict(item.result or {})

    def _service_output_dir(
        self: TaskManager,
        task: BinarySecurityTask,
        downstream_service: str,
        semantic_key: str,
        downstream_task_id: str | None,
    ) -> Path:
        return ensure_dir(self._service_output_path(task, downstream_service, semantic_key, downstream_task_id))

    def _service_output_path(
        self: TaskManager,
        task: BinarySecurityTask,
        downstream_service: str,
        semantic_key: str,
        downstream_task_id: str | None,
    ) -> Path:
        from app.service import task_manager as task_manager_module

        if not str(task.output_root or "").strip():
            raise ValidationError("任务输出目录不存在")
        service_folder = task_manager_module.SERVICE_OUTPUT_FOLDERS.get(
            downstream_service,
            downstream_service.replace("_", "-"),
        )
        suffix = downstream_task_id or "unknown-task"
        dirname = f"{semantic_key}__{suffix}"
        return Path(task.output_root) / service_folder / dirname

    def _downstream_standard_output_sources(
        self: TaskManager,
        task: BinarySecurityTask,
        downstream_service: str | None,
        downstream_task_id: str | None,
    ) -> list[Path]:
        from app.service import task_manager as task_manager_module

        if not downstream_service or not downstream_task_id:
            return []
        app_root = task_manager_module.DOWNSTREAM_APP_ROOTS.get(downstream_service)
        if not app_root:
            return []
        project_app_root = Path(task.workspace_root).parent.parent
        task_root = project_app_root / app_root / downstream_task_id
        return [task_root / "output", task_root]

    def _payload_output_candidates(
        self: TaskManager,
        payload: dict[str, Any] | None,
        *,
        downstream_task_id: str | None = None,
    ) -> list[Path]:
        from app.service import task_manager as task_manager_module

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
            "final_report_path",
            "modules_list_path",
            "result_file",
            "result_file_path",
            "run_result_path",
            "run_report_path",
            "functions_list_path",
            "index_path",
            "sessions_root",
        ):
            value = payload.get(key)
            if not value:
                continue
            if key == "output_root" and value is None:
                continue
            raw = Path(str(value))
            if raw.suffix:
                candidates.extend([raw.parent, raw.parent / "output"])
            if key in {"output_path", "output_root"} and downstream_task_id:
                if raw.name == "output" and task_shared._path_matches_task_id(raw, downstream_task_id):
                    candidates.append(raw)
                else:
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
        self: TaskManager,
        payload: dict[str, Any] | None,
        *,
        downstream_task_id: str | None = None,
        extra_paths: list[str | Path] | None = None,
        task: BinarySecurityTask | None = None,
        downstream_service: str | None = None,
    ) -> list[Path]:
        from app.service import task_manager as task_manager_module

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
        return task_shared._dedupe_paths(normalized)

    def _archive_downstream_output(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        item: BinarySecurityStageItem,
        *,
        semantic_key: str,
        bound_downstream_task_id: str | None = None,
        payload: dict[str, Any] | None = None,
        extra_paths: list[str | Path] | None = None,
    ):
        from app.service import task_manager as task_manager_module

        downstream_task_id = str(bound_downstream_task_id or item.downstream_task_id or "").strip()
        if not downstream_task_id:
            return task_manager_module._ArchiveOutputResult(status="source_not_ready", target_dir=None, source_candidates=[])
        if not str(task.output_root or "").strip():
            return task_manager_module._ArchiveOutputResult(status="source_not_ready", target_dir=None, source_candidates=[])
        target_dir = self._service_output_path(task, item.downstream_service or item.stage_name, semantic_key, downstream_task_id)
        sources = self._resolve_downstream_output_sources(
            payload,
            downstream_task_id=downstream_task_id,
            extra_paths=extra_paths,
            task=task,
            downstream_service=item.downstream_service,
        )
        existing_sources = [
            source
            for source in sources
            if source.exists()
            and task_shared._path_has_content(source)
            and source.resolve() != target_dir.resolve()
            and not task_shared._is_within_path(target_dir, source)
        ]
        existing_sources = task_shared._prefer_specific_paths(existing_sources, downstream_task_id=downstream_task_id)
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
                    "bound_downstream_task_id": downstream_task_id,
                },
            )
            return task_manager_module._ArchiveOutputResult(
                status="source_not_ready",
                target_dir=None,
                source_candidates=[str(path) for path in sources],
            )
        if target_dir.exists() or target_dir.is_symlink():
            if target_dir.is_dir() and not target_dir.is_symlink():
                shutil.rmtree(target_dir, ignore_errors=True)
            else:
                target_dir.unlink(missing_ok=True)
        ensure_dir(target_dir)
        copy_stats = {
            "copied_files": 0,
            "copied_dirs": 0,
            "copied_symlinks": 0,
            "skipped_errors": 0,
            "errors": [],
            "error_truncated": False,
        }
        for source in existing_sources:
            skip_path = (
                (lambda candidate, root: task_shared._should_skip_b2s_archive_path(candidate, source_root=root))
                if item.downstream_service == "binary_to_source" or item.stage_name == "binary_to_source"
                else None
            )
            current_stats = task_shared._copytree_best_effort(source, target_dir, skip_path=skip_path)
            copy_stats["copied_files"] += int(current_stats.get("copied_files") or 0)
            copy_stats["copied_dirs"] += int(current_stats.get("copied_dirs") or 0)
            copy_stats["copied_symlinks"] += int(current_stats.get("copied_symlinks") or 0)
            copy_stats["skipped_errors"] += int(current_stats.get("skipped_errors") or 0)
            remaining = max(0, 200 - len(copy_stats["errors"]))
            copy_stats["errors"].extend(list(current_stats.get("errors") or [])[:remaining])
            if int(current_stats.get("skipped_errors") or 0) > len(current_stats.get("errors") or []):
                copy_stats["error_truncated"] = True
        if copy_stats["skipped_errors"]:
            self._record_event(
                db,
                task,
                "downstream_output_copy_partial",
                f"下游阶段产物已尽力归档，跳过 {copy_stats['skipped_errors']} 个错误文件",
                stage_name=item.stage_name,
                item=item,
                level="warning",
                payload={
                    "target_dir": str(target_dir),
                    "sources": [str(path) for path in existing_sources],
                    "copy_stats": copy_stats,
                    "bound_downstream_task_id": downstream_task_id,
                },
            )
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
                "copied_file_count": task_shared._count_files(target_dir),
                "copy_stats": copy_stats,
                "bound_downstream_task_id": downstream_task_id,
            },
        )
        job_dedupe_key = build_archive_job_dedupe_key(item.id, downstream_task_id)
        archive_job = (
            db.query(BinarySecurityArchiveJob)
            .filter(
                BinarySecurityArchiveJob.task_id == task.id,
                BinarySecurityArchiveJob.stage_name == item.stage_name,
                BinarySecurityArchiveJob.job_dedupe_key == job_dedupe_key,
            )
            .order_by(BinarySecurityArchiveJob.created_at.desc())
            .first()
        )
        if archive_job is not None:
            archive_job.payload = self._with_archive_source_payload(
                archive_job.payload,
                archive_source_paths=[str(path) for path in existing_sources],
            )
        self._merge_stage_item_output_ref(item, archive_copy_stats=copy_stats)
        return task_manager_module._ArchiveOutputResult(
            status="archived",
            target_dir=target_dir,
            source_candidates=[str(path) for path in existing_sources],
        )

    def _materialize_stage_artifact(
        self: TaskManager,
        artifact_root: Path,
        downstream_task_id: str | None,
        payload: dict[str, Any],
        *,
        db: Session | None = None,
        task: BinarySecurityTask | None = None,
        item: BinarySecurityStageItem | None = None,
    ) -> Path:
        from app.service import task_manager as task_manager_module

        del db
        candidates = [
            candidate
            for candidate in self._resolve_downstream_output_sources(
                payload,
                downstream_task_id=downstream_task_id,
                task=task,
                downstream_service=item.downstream_service if item else None,
            )
            if candidate.exists()
            and task_shared._path_has_content(candidate)
            and candidate.resolve() != artifact_root.resolve()
            and not task_shared._is_within_path(artifact_root, candidate)
        ]
        return candidates[0] if candidates else artifact_root
