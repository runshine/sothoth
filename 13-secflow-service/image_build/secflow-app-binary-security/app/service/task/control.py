from __future__ import annotations

import asyncio
import json
import shutil
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sqlalchemy.orm import Session

from app.exception import NotFoundError, ValidationError
from app.model import BinarySecurityProjectConfig, BinarySecurityServiceConfig, BinarySecurityTaskOperation
from app.schemas import (
    BinarySecurityActionResponse,
    BinarySecurityGlobalConfigPayload,
    BinarySecurityGlobalConfigResponse,
    BinarySecurityInputFile,
    BinarySecurityModuleSelectionResponse,
    BinarySecurityProjectConfigPayload,
    BinarySecurityProjectConfigResponse,
    BinarySecurityTaskCreate,
    BinarySecurityTaskPolicyUpdatePayload,
    BinarySecurityTaskDetailResponse,
    BinarySecurityTaskRuntimePolicyUpdatePayload,
)

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager


class TaskControlServiceMixin:
    def _global_config_defaults(self: TaskManager) -> dict[str, Any]:
        project_defaults = self._project_config_defaults(task_type="binary")
        return {
            "max_concurrent_tasks": 20,
            "dispatch_timeout_seconds": 60,
            "lease_timeout_seconds": 90,
            **project_defaults,
        }

    def _latest_project_config_row(self: TaskManager, db: Session) -> BinarySecurityProjectConfig | None:
        return (
            db.query(BinarySecurityProjectConfig)
            .order_by(BinarySecurityProjectConfig.updated_at.desc(), BinarySecurityProjectConfig.id.desc())
            .first()
        )

    def _ensure_global_service_config_row(self: TaskManager, db: Session) -> BinarySecurityServiceConfig | None:
        row = (
            db.query(BinarySecurityServiceConfig)
            .filter(BinarySecurityServiceConfig.config_key == "global")
            .first()
        )
        if row is not None:
            return row
        legacy_row = self._latest_project_config_row(db)
        if legacy_row is None:
            return None
        migrated = BinarySecurityServiceConfig(config_key="global")
        migrated.config = dict(legacy_row.config or {})
        db.add(migrated)
        db.commit()
        db.refresh(migrated)
        return migrated

    def _task_input_dir(self: TaskManager, task) -> Path:
        summary_path = Path(str((task.summary or {}).get("input_dir") or "")).expanduser()
        if str(summary_path) and summary_path.exists():
            return summary_path
        return Path(task.workspace_root) / "input"

    def _task_temp_upload_dir(self: TaskManager, task) -> Path:
        summary_path = Path(str((task.summary or {}).get("temp_upload_dir") or "")).expanduser()
        if str(summary_path) and summary_path.exists():
            return summary_path
        return Path(task.workspace_root) / "run" / "upload-tmp"

    def _normalize_input_files(self: TaskManager, files, *, task_type: str) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        seen_relative_paths: set[str] = set()
        saw_archive = False
        saw_tree = False
        for current in list(files or []):
            row = current.model_dump(exclude_none=True) if hasattr(current, "model_dump") else dict(current or {})
            filename = str(row.get("filename") or "").strip()
            if not filename:
                raise ValidationError("上传文件缺少文件名")
            raw_relative_path = str(row.get("relative_path") or "").strip().replace("\\", "/")
            lowered = filename.lower()
            is_archive = lowered.endswith((".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz"))
            relative_path = str((raw_relative_path if (task_type != "source" or not is_archive) else filename) or filename).strip().replace("\\", "/")
            if not relative_path:
                raise ValidationError("上传文件缺少相对路径")
            if relative_path in seen_relative_paths:
                raise ValidationError("存在重复路径")
            seen_relative_paths.add(relative_path)
            normalized = {**row, "filename": filename, "relative_path": relative_path}
            if task_type == "source":
                if raw_relative_path and not is_archive:
                    saw_tree = True
                else:
                    if not is_archive:
                        raise ValidationError("源码任务仅支持常见压缩文件")
                    saw_archive = True
            rows.append(normalized)
        if task_type == "source" and saw_archive and saw_tree:
            raise ValidationError("不能混合目录文件和压缩包")
        return rows

    def _source_input_kind(self: TaskManager, input_files: list[dict[str, Any]]) -> str:
        if any(str(item.get("relative_path") or item.get("filename") or "").strip() != str(item.get("filename") or "").strip() for item in list(input_files or [])):
            return "source_tree_files"
        return "source_archives"

    def _check_storage_free_space(self: TaskManager, *, required_bytes: int) -> None:
        del required_bytes
        return None

    def _validate_uploaded_archive_size(self: TaskManager, filename: str, size_bytes: int, *, source_task: bool) -> None:
        max_upload = int(getattr(self.cfg.storage, "max_upload_file_bytes", 0) or 0)
        max_source_archive = int(getattr(self.cfg.storage, "max_source_archive_bytes", 0) or 0)
        limit = max_source_archive if source_task and max_source_archive > 0 else max_upload
        if limit > 0 and int(size_bytes or 0) > limit:
            raise ValidationError(f"上传文件过大: {filename}")

    def _safe_extract_archive(self: TaskManager, archive_path: Path, target_dir: Path) -> int:
        extracted_count = 0
        with zipfile.ZipFile(archive_path) as archive:
            for member in archive.infolist():
                member_name = str(member.filename or "").strip()
                if not member_name or member_name.startswith("/") or ".." in Path(member_name).parts:
                    raise ValidationError("压缩包包含非法路径")
                archive.extract(member, path=target_dir)
                if not member.is_dir():
                    extracted_count += 1
        return extracted_count

    async def _materialize_source_archives(
        self: TaskManager,
        task,
        declared: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], int, int]:
        input_dir = self._task_input_dir(task)
        temp_dir = self._task_temp_upload_dir(task)
        extracted_count = 0
        total_bytes = 0
        actual_files: list[dict[str, Any]] = []
        for file_info in declared:
            filename = str(file_info.get("filename") or "").strip()
            relative_path = str(file_info.get("relative_path") or filename).strip().replace("\\", "/")
            archive_path = temp_dir / relative_path
            if not await asyncio.to_thread(archive_path.is_file):
                raise ValidationError(f"上传文件缺失: {relative_path}")
            stat = await asyncio.to_thread(archive_path.stat)
            self._validate_uploaded_archive_size(filename, stat.st_size, source_task=True)
            self._check_storage_free_space(required_bytes=stat.st_size)
            extracted_count += await asyncio.to_thread(self._safe_extract_archive, archive_path, input_dir)
            total_bytes += int(stat.st_size or 0)
            await asyncio.to_thread(archive_path.unlink)
            actual_files.append(
                {
                    **file_info,
                    "size": stat.st_size,
                    "uploaded": True,
                    "path": f"{(task.summary or {}).get('input_dir')}/{relative_path}",
                }
            )
        return actual_files, total_bytes, extracted_count

    async def _materialize_source_tree_files(
        self: TaskManager,
        task,
        declared: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], int]:
        input_dir = self._task_input_dir(task)
        total_bytes = 0
        actual_files: list[dict[str, Any]] = []
        for file_info in declared:
            filename = str(file_info.get("filename") or "").strip()
            relative_path = str(file_info.get("relative_path") or filename).strip().replace("\\", "/")
            local_path = input_dir / relative_path
            if not await asyncio.to_thread(local_path.is_file):
                raise ValidationError(f"上传文件缺失: {relative_path}")
            stat = await asyncio.to_thread(local_path.stat)
            self._check_storage_free_space(required_bytes=stat.st_size)
            total_bytes += int(stat.st_size or 0)
            actual_files.append(
                {
                    **file_info,
                    "size": stat.st_size,
                    "uploaded": True,
                    "path": f"{(task.summary or {}).get('input_dir')}/{relative_path}",
                }
            )
        return actual_files, total_bytes

    async def _init_workspace_async(self: TaskManager, workspace_root: Path) -> None:
        await asyncio.to_thread(workspace_root.mkdir, parents=True, exist_ok=True)
        await asyncio.to_thread((workspace_root / "input").mkdir, parents=True, exist_ok=True)
        await asyncio.to_thread((workspace_root / "run").mkdir, parents=True, exist_ok=True)

    async def _ensure_task_directories(self: TaskManager, project_id: str, task_id: str, authorization_token: str) -> None:
        del project_id, task_id, authorization_token
        return None

    def _resolve_output_root(self: TaskManager, workspace_root: Path, output_root: str | None) -> Path:
        return Path(output_root) if output_root else workspace_root / "output"

    def _normalize_partial_success_stage_advancement_for_task_type(
        self: TaskManager,
        values: dict[str, Any] | None,
        *,
        task_type: str,
    ) -> dict[str, bool]:
        allowed = set(self._stage_sequence_for_task(task_type))
        legacy_aliases = {
            "dataflow_analysis": "entry_analysis",
            "vuln_scan": "dataflow_vuln_scan",
        }
        normalized: dict[str, bool] = {}
        for stage_name, enabled in dict(values or {}).items():
            current = legacy_aliases.get(str(stage_name or "").strip(), str(stage_name or "").strip())
            if not current:
                continue
            if current not in allowed:
                continue
            normalized[current] = bool(enabled)
        return normalized

    def _validate_and_normalize_partial_success_stage_advancement_overrides(
        self: TaskManager,
        values: dict[str, Any] | None,
        *,
        task_type: str,
    ) -> dict[str, bool]:
        return self._normalize_partial_success_stage_advancement_for_task_type(values, task_type=task_type)

    def _project_config_defaults(self: TaskManager, *, task_type: str) -> dict[str, Any]:
        stage_names = self._stage_sequence_for_task(task_type)
        defaults = {
            "pipeline_profile": "default",
            "pipeline_mode": "barrier",
            "max_stage_parallelism": 4,
            "max_retries_per_item": 2,
            "continue_on_item_failure": True,
            "stage_parallelism": {stage_name: 4 for stage_name in stage_names},
            "stage_options": {},
            "module_selection_mode": "auto",
            "module_risk_levels": ["高"],
        }
        defaults["partial_success_stage_advancement"] = {
            stage_name: False for stage_name in stage_names if stage_name in {"binary_to_source", "entry_analysis", "dataflow_vuln_scan"}
        }
        return defaults

    def _merge_policy(self: TaskManager, db: Session, project_id: str, overrides: dict[str, Any], stage_options: dict[str, Any]) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        task_type = self._validate_task_type(overrides.get("task_type"))
        policy = self._project_config_defaults(task_type=task_type)
        row = db.query(BinarySecurityProjectConfig).filter(BinarySecurityProjectConfig.project_id == project_id).first()
        project_config = dict(getattr(row, "config", {}) or {})
        if project_config:
            policy.update({k: v for k, v in project_config.items() if k != "partial_success_stage_advancement"})
            if "partial_success_stage_advancement" in project_config:
                policy["partial_success_stage_advancement"] = self._normalize_partial_success_stage_advancement_for_task_type(
                    project_config.get("partial_success_stage_advancement"),
                    task_type=task_type,
                )
        if stage_options:
            policy["stage_options"] = {
                **dict(policy.get("stage_options") or {}),
                **{
                    str(name): option.model_dump(exclude_none=True) if hasattr(option, "model_dump") else dict(option or {})
                    for name, option in dict(stage_options or {}).items()
                },
            }
        override_payload = dict(overrides or {})
        if "pipeline_profile" in override_payload:
            policy["pipeline_profile"] = self._validate_pipeline_profile(task_type, override_payload.get("pipeline_profile"))
        else:
            policy["pipeline_profile"] = self._validate_pipeline_profile(task_type, policy.get("pipeline_profile"))
        if "pipeline_mode" in override_payload:
            policy["pipeline_mode"] = task_manager_module._normalize_pipeline_mode(override_payload.get("pipeline_mode"))
        else:
            policy["pipeline_mode"] = task_manager_module._normalize_pipeline_mode(policy.get("pipeline_mode"))
        if override_payload.get("partial_success_stage_advancement") is not None:
            merged_partial = dict(policy.get("partial_success_stage_advancement") or {})
            merged_partial.update(
                self._normalize_partial_success_stage_advancement_for_task_type(
                    override_payload.get("partial_success_stage_advancement"),
                    task_type=task_type,
                )
            )
            policy["partial_success_stage_advancement"] = merged_partial
        if override_payload.get("stage_parallelism"):
            merged_parallelism = dict(policy.get("stage_parallelism") or {})
            for stage_name, value in dict(override_payload.get("stage_parallelism") or {}).items():
                merged_parallelism[str(stage_name)] = int(value)
            policy["stage_parallelism"] = merged_parallelism
            if merged_parallelism:
                policy["max_stage_parallelism"] = max(int(value) for value in merged_parallelism.values())
        for key in ("max_stage_parallelism", "max_retries_per_item", "continue_on_item_failure", "module_selection_mode", "entry_selection_mode"):
            if override_payload.get(key) is not None:
                policy[key] = override_payload.get(key)
        if override_payload.get("module_risk_levels") is not None:
            policy["module_risk_levels"] = task_manager_module._normalize_module_risk_levels(override_payload.get("module_risk_levels"))
        if "knowledge_graph_entries_url" in override_payload:
            value = str(override_payload.get("knowledge_graph_entries_url") or "").strip()
            policy["knowledge_graph_entries_url"] = value or None
        if policy.get("pipeline_profile") == task_manager_module.PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN:
            policy["entry_selection_mode"] = "auto"
        return policy

    def save_project_config(
        self: TaskManager,
        db: Session,
        project_id: str,
        payload: BinarySecurityProjectConfigPayload,
    ) -> BinarySecurityProjectConfigResponse:
        row = db.query(BinarySecurityProjectConfig).filter(BinarySecurityProjectConfig.project_id == project_id).first()
        if row is None:
            row = BinarySecurityProjectConfig(project_id=project_id)
            db.add(row)
        config = payload.model_dump()
        config["pipeline_mode"] = self._normalize_policy_update_payload(
            type("TaskLike", (), {"policy": {}, "task_type": "binary"})(),
            BinarySecurityTaskPolicyUpdatePayload(pipeline_mode=config.get("pipeline_mode")),
        )["pipeline_mode"]
        row.config = config
        return BinarySecurityProjectConfigResponse(project_id=project_id, config=BinarySecurityProjectConfigPayload(**config))

    def get_project_config(self: TaskManager, db: Session, project_id: str) -> BinarySecurityProjectConfigResponse:
        row = db.query(BinarySecurityProjectConfig).filter(BinarySecurityProjectConfig.project_id == project_id).first()
        config = dict(getattr(row, "config", {}) or {})
        config["pipeline_mode"] = self._normalize_policy_update_payload(
            type("TaskLike", (), {"policy": {}, "task_type": "binary"})(),
            BinarySecurityTaskPolicyUpdatePayload(pipeline_mode=config.get("pipeline_mode")),
        ).get("pipeline_mode", "barrier")
        if "partial_success_stage_advancement" in config:
            defaults = self._project_config_defaults(task_type="binary")["partial_success_stage_advancement"]
            current = dict(config.get("partial_success_stage_advancement") or {})
            config["partial_success_stage_advancement"] = {
                stage_name: bool(current.get(stage_name, default_value))
                for stage_name, default_value in defaults.items()
            }
        payload = BinarySecurityProjectConfigPayload(**{**BinarySecurityProjectConfigPayload().model_dump(), **config})
        return BinarySecurityProjectConfigResponse(project_id=project_id, config=payload)

    def get_config(self: TaskManager, db: Session) -> BinarySecurityGlobalConfigResponse:
        row = self._ensure_global_service_config_row(db)
        config = {**self._global_config_defaults()}
        if row is not None and row.config:
            config.update(dict(row.config or {}))
        config["pipeline_mode"] = self._normalize_policy_update_payload(
            type("TaskLike", (), {"policy": {}, "task_type": "binary"})(),
            BinarySecurityTaskPolicyUpdatePayload(pipeline_mode=config.get("pipeline_mode")),
        ).get("pipeline_mode", "barrier")
        if "partial_success_stage_advancement" in config:
            defaults = self._project_config_defaults(task_type="binary")["partial_success_stage_advancement"]
            current = dict(config.get("partial_success_stage_advancement") or {})
            config["partial_success_stage_advancement"] = {
                stage_name: bool(current.get(stage_name, default_value))
                for stage_name, default_value in defaults.items()
            }
        payload = BinarySecurityGlobalConfigPayload(**{**BinarySecurityGlobalConfigPayload().model_dump(), **config})
        return BinarySecurityGlobalConfigResponse(config=payload)

    def save_config(self: TaskManager, db: Session, payload: BinarySecurityGlobalConfigPayload) -> BinarySecurityGlobalConfigResponse:
        row = (
            db.query(BinarySecurityServiceConfig)
            .filter(BinarySecurityServiceConfig.config_key == "global")
            .first()
        )
        if row is None:
            row = BinarySecurityServiceConfig(config_key="global")
            db.add(row)
        config = payload.model_dump()
        config["pipeline_mode"] = self._normalize_policy_update_payload(
            type("TaskLike", (), {"policy": {}, "task_type": "binary"})(),
            BinarySecurityTaskPolicyUpdatePayload(pipeline_mode=config.get("pipeline_mode")),
        )["pipeline_mode"]
        row.config = config
        db.commit()
        db.refresh(row)
        return BinarySecurityGlobalConfigResponse(
            config=BinarySecurityGlobalConfigPayload(**{**BinarySecurityGlobalConfigPayload().model_dump(), **config})
        )

    def get_module_selection(
        self: TaskManager,
        db: Session,
        *,
        project_id: str,
        task_id: str,
    ) -> BinarySecurityModuleSelectionResponse:
        from app.service import task_manager as task_manager_module

        task = self._task_or_404(db, project_id, task_id)
        summary = task.summary if isinstance(task.summary, dict) else {}
        return task_manager_module.BinarySecurityModuleSelectionResponse(
            task_id=task.id,
            status=task.status,
            selection_mode=self._module_selection_mode(task),
            risk_levels=self._module_selection_candidate_levels(task),
            requires_confirmation=task.status == task_manager_module.TASK_STATUS_PENDING_MODULE_CONFIRMATION,
            system_analysis_modules=list(summary.get("system_analysis_modules") or []),
            candidate_modules=list(summary.get("candidate_modules") or []),
            selected_modules=list(summary.get("selected_modules") or []),
        )

    def _policy_stage_names(self: TaskManager, task) -> set[str]:
        return set(self._stage_sequence_for_task(task))

    def _normalize_policy_update_payload(self: TaskManager, task, payload: BinarySecurityTaskPolicyUpdatePayload) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        current = dict(task.policy or {})
        stage_names = self._policy_stage_names(task)
        updated = json.loads(json.dumps(current))
        if payload.pipeline_mode is not None:
            updated["pipeline_mode"] = task_manager_module._normalize_pipeline_mode(payload.pipeline_mode)
        if payload.max_retries_per_item is not None:
            updated["max_retries_per_item"] = int(payload.max_retries_per_item)
        if payload.continue_on_item_failure is not None:
            updated["continue_on_item_failure"] = bool(payload.continue_on_item_failure)
        if payload.module_selection_mode is not None:
            updated["module_selection_mode"] = str(payload.module_selection_mode or "").strip() or "auto"
        if payload.module_risk_levels is not None:
            updated["module_risk_levels"] = task_manager_module._normalize_module_risk_levels(list(payload.module_risk_levels or []))
        stage_options = dict(updated.get("stage_options") or {})
        for stage_name, option in dict(payload.stage_options or {}).items():
            normalized_stage = str(stage_name or "").strip()
            if normalized_stage not in stage_names:
                raise ValidationError("阶段不属于当前任务流程")
            stage_options[normalized_stage] = option.model_dump(exclude_none=True) if hasattr(option, "model_dump") else dict(option or {})
        if stage_options:
            updated["stage_options"] = stage_options
        partial_success = dict(updated.get("partial_success_stage_advancement") or {})
        for stage_name, enabled in dict(payload.partial_success_stage_advancement or {}).items():
            normalized_stage = str(stage_name or "").strip()
            if normalized_stage not in stage_names:
                raise ValidationError(f"阶段不属于当前任务流程: {normalized_stage}")
            partial_success[normalized_stage] = bool(enabled)
        if partial_success:
            updated["partial_success_stage_advancement"] = partial_success
        stage_parallelism = dict(updated.get("stage_parallelism") or {})
        for stage_name, parallelism in dict(payload.stage_parallelism or {}).items():
            normalized_stage = str(stage_name or "").strip()
            if normalized_stage not in stage_names:
                raise ValidationError("阶段不属于当前任务流程")
            try:
                value = int(parallelism)
            except Exception as exc:
                raise ValidationError("并发必须是 1 到 32 之间的整数") from exc
            if value < 1 or value > 32:
                raise ValidationError("并发必须是 1 到 32 之间的整数")
            stage_parallelism[normalized_stage] = value
        if stage_parallelism:
            updated["stage_parallelism"] = stage_parallelism
            updated["max_stage_parallelism"] = max(int(value) for value in stage_parallelism.values())
        return updated

    def update_task_policy(
        self: TaskManager,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        payload: BinarySecurityTaskPolicyUpdatePayload,
    ) -> BinarySecurityTaskDetailResponse:
        task = self._task_or_404(db, project_id, task_id)
        supported, reason = self._task_policy_update_support(task, db)
        if not supported:
            raise ValidationError(reason or "不允许修改任务策略")
        before = json.loads(json.dumps(dict(task.policy or {})))
        after = self._normalize_policy_update_payload(task, payload)
        event = self._enqueue_state_event(
            db,
            task=task,
            task_id=task.id,
            project_id=task.project_id,
            event_type="manual_policy_update_requested",
            idempotency_key=f"manual_policy_update_requested:{task.id}:{hash(json.dumps(after, sort_keys=True, ensure_ascii=False))}",
            payload={
                "mode": "policy",
                "before": before,
                "after": after,
                "effective_scope": "future_stages_only",
            },
        )
        if event is not None:
            task.updated_at = getattr(task, "updated_at", None)
        return self.get_task_detail(db, project_id=project_id, task_id=task_id)

    def update_task_runtime_policy(
        self: TaskManager,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        payload: BinarySecurityTaskRuntimePolicyUpdatePayload,
    ) -> BinarySecurityTaskDetailResponse:
        task = self._task_or_404(db, project_id, task_id)
        supported, reason = self._task_runtime_policy_update_support(task, db)
        if not supported:
            raise ValidationError(reason or "不允许运行时修改任务策略")
        current_version = int(getattr(task, "runtime_override_version", 0) or 0)
        expected_version = int(getattr(payload, "expected_version", 0) or 0)
        if expected_version != current_version:
            raise ValidationError("运行时策略版本不匹配")
        before = self._task_runtime_override(task)
        after = json.loads(json.dumps(before))
        if payload.stage_parallelism:
            normalized_stage_parallelism: dict[str, int] = {}
            for stage_name, parallelism in dict(payload.stage_parallelism or {}).items():
                normalized_stage = str(stage_name or "").strip()
                if normalized_stage not in self._policy_stage_names(task):
                    raise ValidationError("阶段不属于当前任务流程")
                value = int(parallelism)
                if value < 1 or value > 32:
                    raise ValidationError("并发必须是 1 到 32 之间的整数")
                normalized_stage_parallelism[normalized_stage] = value
            after["stage_parallelism"] = normalized_stage_parallelism
        if payload.dispatch_throttle:
            after["dispatch_throttle"] = json.loads(json.dumps(dict(payload.dispatch_throttle or {})))
        if payload.max_retries_per_item is not None:
            after["max_retries_per_item"] = int(payload.max_retries_per_item)
        if payload.continue_on_item_failure is not None:
            after["continue_on_item_failure"] = bool(payload.continue_on_item_failure)
        if payload.tail_reconcile_poll_interval_seconds is not None:
            after["tail_reconcile_poll_interval_seconds"] = int(payload.tail_reconcile_poll_interval_seconds)
        self._enqueue_state_event(
            db,
            task=task,
            task_id=task.id,
            project_id=task.project_id,
            event_type="manual_policy_update_requested",
            idempotency_key=f"manual_runtime_policy_update_requested:{task.id}:{current_version + 1}",
            payload={
                "mode": "runtime_override",
                "before": before,
                "after": after,
                "effective_scope": "tail_claim_immediate",
                "updated_by": str(payload.updated_by or "").strip() or None,
            },
        )
        return self.get_task_detail(db, project_id=project_id, task_id=task_id)

    def confirm_entry_selection(
        self: TaskManager,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        selected_entry_keys: list[str],
    ) -> BinarySecurityTaskDetailResponse:
        from app.service import task_manager as task_manager_module

        task = self._task_or_404(db, project_id, task_id)
        if self._entry_selection_mode(task) != task_manager_module.ENTRY_SELECTION_MODE_MANUAL_CONFIRM:
            raise ValidationError("当前任务不需要手动确认入口")
        candidate_entries = self._entry_candidates(task)
        selected_keys = [str(key or "").strip() for key in list(selected_entry_keys or []) if str(key or "").strip()]
        selected_key_set = set(selected_keys)
        selected_entries = [
            dict(entry)
            for entry in candidate_entries
            if str(entry.get("entry_key") or "").strip() in selected_key_set
        ]
        confirmed_at = task_manager_module._now().isoformat()
        summary = dict(task.summary or {})
        summary["entry_selection"] = {
            **self._entry_selection_snapshot(task),
            "mode": task_manager_module.ENTRY_SELECTION_MODE_MANUAL_CONFIRM,
            "status": "confirmed",
            "candidate_entries": candidate_entries,
            "selected_entry_keys": selected_keys,
            "selected_entries": self._mark_selected_entries(selected_entries, selected_by=task_manager_module.ENTRY_SELECTION_MODE_MANUAL_CONFIRM, selected_at=confirmed_at),
            "confirmed_at": confirmed_at,
        }
        task.summary = summary
        metrics = dict(getattr(task, "metrics", {}) or {})
        metrics.update(self._entry_selection_metrics(task))
        task.metrics = metrics
        task.status = "pending"
        task.current_stage = "entry_analysis"
        self._record_event(
            db,
            task,
            "entry_selection_confirmed",
            "入口选择已确认，任务将继续执行后续阶段",
            stage_name="entry_analysis",
            payload={"selected_entry_keys": selected_keys},
        )
        self._write_task_metadata(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
        return self.get_task_detail(db, project_id=project_id, task_id=task_id)

    def confirm_module_selection(
        self: TaskManager,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        selected_module_keys: list[str],
    ) -> BinarySecurityTaskDetailResponse:
        from app.service import task_manager as task_manager_module

        task = self._task_or_404(db, project_id, task_id)
        if self._module_selection_mode(task) != task_manager_module.MODULE_SELECTION_MODE_MANUAL_CONFIRM:
            raise ValidationError("当前任务不需要手动确认模块")
        candidates = [dict(item) for item in (task.summary.get("candidate_modules") or []) if isinstance(item, dict)]
        selected_keys = [str(key or "").strip() for key in list(selected_module_keys or []) if str(key or "").strip()]
        selected_key_set = set(selected_keys)
        selected_modules = [
            {
                **module,
                "selected_by": task_manager_module.MODULE_SELECTION_MODE_MANUAL_CONFIRM,
                "selected_at": task_manager_module._now().isoformat(),
            }
            for module in candidates
            if str(module.get("module_key") or "").strip() in selected_key_set
        ]
        task.summary = {
            **dict(task.summary or {}),
            "selected_modules": selected_modules,
        }
        task.metrics = {
            **dict(task.metrics or {}),
            **self._module_metrics(candidates, candidates, selected_modules),
        }
        task.status = "pending"
        task.current_stage = "entry_analysis"
        self._record_event(
            db,
            task,
            "module_selection_confirmed",
            "模块选择已确认，任务将继续执行后续阶段",
            stage_name="system_analysis",
            payload={"selected_module_keys": selected_keys},
        )
        self._write_task_metadata(task, Path(task.workspace_root) / "input" / "task-metadata.json", status=task.status)
        return self.get_task_detail(db, project_id=project_id, task_id=task_id)

    async def create_task(
        self: TaskManager,
        db: Session,
        *,
        project_id: str,
        payload: BinarySecurityTaskCreate,
        created_by: str,
        authorization_token: str,
    ) -> BinarySecurityTaskDetailResponse:
        from app.service import task_manager as task_manager_module

        task_id = (
            task_manager_module.validate_task_id(payload.task_id)
            if payload.task_id
            else self.prepare_task_id(db, project_id)
        )
        task_type = self._validate_task_type(payload.task_type)
        pipeline_profile = self._validate_pipeline_profile(
            task_type,
            payload.policy_overrides.pipeline_profile,
        )
        if db.query(task_manager_module.BinarySecurityTask.id).filter(
            task_manager_module.BinarySecurityTask.project_id == project_id,
            task_manager_module.BinarySecurityTask.id == task_id,
        ).first():
            raise ValidationError("任务 ID 已存在")
        self._validate_and_normalize_partial_success_stage_advancement_overrides(
            payload.policy_overrides.partial_success_stage_advancement,
            task_type=task_type,
        )
        module_name = str(payload.module_name or "").strip()
        if task_type == task_manager_module.TASK_TYPE_BINARY_MODULE and not module_name:
            raise ValidationError("二进制模块任务必须填写模块名")
        input_files = self._normalize_input_files(payload.input_files, task_type=task_type)
        workspace_root = task_manager_module.app_task_root(project_id, task_id)
        output_root = self._resolve_output_root(workspace_root, payload.output_root)
        input_dir = workspace_root / "input"
        run_dir = workspace_root / "run"
        await self._init_workspace_async(workspace_root)
        await self._ensure_task_directories(project_id, task_id, authorization_token)
        metadata_path = input_dir / "task-metadata.json"
        policy_overrides = payload.policy_overrides.model_dump(exclude_none=True)
        policy_overrides["task_type"] = task_type
        policy_overrides["pipeline_profile"] = pipeline_profile
        policy = self._merge_policy(db, project_id, policy_overrides, payload.stage_options)

        task = task_manager_module.BinarySecurityTask(
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
            firmware_path=str(input_dir),
            output_root=str(output_root),
            workspace_root=str(workspace_root),
            task_key_source=str(payload.task_key_source or "").strip() or None,
            root_task_key_id=str(payload.root_task_key_id or "").strip() or None,
            root_task_key_name=str(payload.root_task_key_name or "").strip() or None,
            root_task_key_prefix=str(payload.root_task_key_prefix or "").strip() or None,
            execution_epoch=0,
            runtime_phase=task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION,
        )
        task.policy = policy
        task.summary = {
            "fileserver_project_path": str(workspace_root),
            "task_root_path": str(workspace_root),
            "input_dir": str(input_dir),
            "output_dir": str(output_root),
            "run_dir": str(run_dir),
            "temp_upload_dir": str(run_dir / "upload-tmp") if task_type == task_manager_module.TASK_TYPE_SOURCE else None,
            "input_manifest_path": str(metadata_path),
            "input_files": input_files,
            "input_kind": (
                self._source_input_kind(input_files)
                if task_type == task_manager_module.TASK_TYPE_SOURCE
                else "module_elf_files"
                if task_type == task_manager_module.TASK_TYPE_BINARY_MODULE
                else "firmware_files"
            ),
            "module_input": {
                "module_name": module_name,
                "file_count": len(input_files),
            } if task_type == task_manager_module.TASK_TYPE_BINARY_MODULE else None,
            "system_analysis_bypassed": task_type == task_manager_module.TASK_TYPE_BINARY_MODULE,
            "downstream_task_ids": {},
            "system_analysis_modules": [],
            "candidate_modules": [],
            "selected_modules": [],
            "knowledge_graph_entry_results": [],
            "runtime_task_keys": {
                "root_task_key_secret": str(payload.root_task_key_secret or "").strip() or None,
                "root_task_key_id": str(payload.root_task_key_id or "").strip() or None,
                "root_task_key_name": str(payload.root_task_key_name or "").strip() or None,
                "root_task_key_prefix": str(payload.root_task_key_prefix or "").strip() or None,
                "task_key_source": str(payload.task_key_source or "").strip() or None,
            },
            "pipeline_profile": pipeline_profile,
        }
        task.metrics = {
            "high_risk_module_count": 0,
            "medium_risk_module_count": 0,
            "low_risk_module_count": 0,
            "candidate_module_count": 0,
            "selected_module_count": 0,
            "knowledge_graph_raw_entry_count": 0,
            "knowledge_graph_selected_entry_count": 0,
            "knowledge_graph_filtered_out_count": 0,
            "candidate_entry_count": 0,
            "selected_entry_count": 0,
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
        task.cleanup_snapshot = {}
        db.add(task)
        db.commit()
        await self._write_task_metadata_async(task, metadata_path, status="pending_upload")
        self._record_event(db, task, "task_created", f"创建任务 {task.id}", payload={"input_files": input_files})
        self._record_event(db, task, "task_upload_pending", "任务创建完成，等待上传文件")
        task_manager_module.observe_task_lifecycle("created", status=task.status, task_type=self._task_type(task))
        db.commit()
        return self.get_task_detail(db, project_id=project_id, task_id=task.id)

    async def cancel_task(self: TaskManager, db: Session, *, project_id: str, task_id: str) -> BinarySecurityActionResponse:
        from app.service import task_manager as task_manager_module

        task = self._task_or_404(db, project_id, task_id)
        active_cancel_operation = self._active_operation(db, task.id)
        if active_cancel_operation is not None and str(active_cancel_operation.operation_type or "").strip() == task_manager_module.TASK_ACTION_CANCEL:
            task_manager_module.observe_task_operation("cancel", "already_queued")
            return BinarySecurityActionResponse(
                task_id=task_id,
                operation_id=active_cancel_operation.id,
                accepted=True,
                action="cancel",
                status="accepted",
                message="任务取消已受理，后台正在停止执行并清理下游任务",
                task_status_after_accept=task_manager_module.TASK_STATUS_CANCELLING,
            )
        if task.status == "cancelled":
            active_item_count = db.query(task_manager_module.BinarySecurityStageItem).filter(
                task_manager_module.BinarySecurityStageItem.task_id == task.id,
                task_manager_module.BinarySecurityStageItem.status.in_(["pending", "queued", "running", "dispatching"]),
            ).count()
            active_stage_count = db.query(task_manager_module.BinarySecurityStageRun).filter(
                task_manager_module.BinarySecurityStageRun.task_id == task.id,
                task_manager_module.BinarySecurityStageRun.status.in_(["pending", "dispatching", "queued", "running"]),
            ).count()
            if active_item_count <= 0 and active_stage_count <= 0:
                task_manager_module.observe_task_operation("cancel", "already_cancelled")
                return BinarySecurityActionResponse(task_id=task_id, message="任务已取消")
        operation = self._queue_task_operation(
            db,
            task,
            operation_type=task_manager_module.TASK_ACTION_CANCEL,
            target_stage=task.current_stage,
            requested_by=task.created_by,
            request_payload={"current_stage": task.current_stage},
            accepted_event_type="task_cancel_accepted",
            accepted_message="任务取消已受理，后台正在停止执行并清理下游任务",
        )
        task.status = task_manager_module.TASK_STATUS_CANCELLING
        task.finished_at = None
        task.last_error = None
        task.current_operation_id = operation.id
        db.commit()
        task_manager_module.observe_task_operation("cancel", "accepted")
        return BinarySecurityActionResponse(
            task_id=task_id,
            operation_id=operation.id,
            accepted=True,
            action="cancel",
            status="accepted",
            message="任务取消已受理，后台正在停止执行并清理下游任务",
            task_status_after_accept=task_manager_module.TASK_STATUS_CANCELLING,
        )

    async def delete_task(
        self: TaskManager,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        force: bool = False,
    ) -> BinarySecurityActionResponse:
        from app.service import task_manager as task_manager_module

        task = self._task_or_404(db, project_id, task_id)
        active_delete_operation = self._active_operation(db, task.id)
        if active_delete_operation is not None and str(active_delete_operation.operation_type or "").strip() == task_manager_module.TASK_ACTION_DELETE:
            task_manager_module.observe_task_operation("delete", "already_queued")
            return BinarySecurityActionResponse(
                task_id=task_id,
                operation_id=active_delete_operation.id,
                accepted=True,
                action="delete",
                status="accepted",
                message="任务删除已受理，后台正在清理任务及下游资源",
                task_status_after_accept=task.status,
            )
        operation = self._queue_task_operation(
            db,
            task,
            operation_type=task_manager_module.TASK_ACTION_DELETE,
            target_stage=task.current_stage,
            requested_by=task.created_by,
            request_payload={
                "current_stage": task.current_stage,
                "force": bool(force),
                "force_delete": bool(force),
            },
            accepted_event_type="task_delete_accepted",
            accepted_message="任务删除已受理，后台正在清理任务及下游资源",
        )
        task.current_operation_id = operation.id
        db.commit()
        task_manager_module.observe_task_operation("delete", "accepted")
        return BinarySecurityActionResponse(
            task_id=task_id,
            operation_id=operation.id,
            accepted=True,
            action="delete",
            status="accepted",
            message="任务删除已受理，后台正在清理任务及下游资源",
            task_status_after_accept=task.status,
        )

    async def continue_task(self: TaskManager, db: Session, *, project_id: str, task_id: str) -> BinarySecurityTaskOperation:
        from app.service import task_manager as task_manager_module

        task = self._task_or_404(db, project_id, task_id)
        supported, reason, target_stage = self._task_continue_support(db, task)
        if not supported:
            task_manager_module.observe_task_operation("continue", "rejected")
            raise ValidationError(reason or "当前任务不可继续")
        if not target_stage:
            task_manager_module.observe_task_operation("continue", "rejected")
            raise ValidationError("当前任务未找到可继续的阶段")
        operation = self._queue_task_operation(
            db,
            task,
            operation_type=task_manager_module.TASK_ACTION_CONTINUE,
            target_stage=target_stage,
            requested_by=task.created_by,
            request_payload={"target_stage": target_stage},
            accepted_event_type="task_continue_accepted",
            accepted_message=f"继续任务已受理，后台正在准备从阶段 {target_stage} 继续",
        )
        task_manager_module.observe_task_operation("continue", "accepted")
        return operation

    def retry_task(self: TaskManager, db: Session, *, project_id: str, task_id: str) -> BinarySecurityTaskOperation:
        from app.service import task_manager as task_manager_module

        task = self._task_or_404(db, project_id, task_id)
        supported, reason, stage_name = self._task_retry_support(db, task)
        if not supported or not stage_name:
            task_manager_module.observe_task_operation("retry", "rejected")
            task_manager_module.observe_task_error("retry", stage=str(task.current_stage or "none"), result="rejected")
            raise ValidationError(reason or "当前任务不支持安全重试")
        first_stage = self._stage_sequence_for_task(task)[0]
        operation = self._queue_task_operation(
            db,
            task,
            operation_type=task_manager_module.TASK_ACTION_RETRY,
            target_stage=first_stage,
            requested_by=task.created_by,
            request_payload={"target_stage": first_stage},
            accepted_event_type="task_retry_accepted",
            accepted_message=f"清空并从头开始已受理，后台正在准备从阶段 {first_stage} 重新排队",
        )
        task_manager_module.observe_task_operation("retry", "accepted")
        task_manager_module.observe_task_error("retry", stage=first_stage, result="accepted")
        return operation

    def retry_failed_items(self: TaskManager, db: Session, *, project_id: str, task_id: str) -> BinarySecurityTaskOperation:
        from app.service import task_manager as task_manager_module

        task = self._task_or_404(db, project_id, task_id)
        supported, reason, stage_name, items = self._task_retry_failed_items_support(db, task)
        if not supported or not stage_name:
            continue_supported, continue_reason, continue_stage = self._task_continue_support(db, task)
            if not continue_supported or not continue_stage:
                task_manager_module.observe_task_operation(task_manager_module.TASK_ACTION_RETRY_FAILED_ITEMS, "rejected")
                raise ValidationError(reason or continue_reason or "当前任务不支持重试失败项")
            operation = self._queue_task_operation(
                db,
                task,
                operation_type=task_manager_module.TASK_ACTION_CONTINUE,
                target_stage=continue_stage,
                requested_by=task.created_by,
                request_payload={"target_stage": continue_stage, "fallback_from": task_manager_module.TASK_ACTION_RETRY_FAILED_ITEMS},
                accepted_event_type="task_retry_failed_items_continue_accepted",
                accepted_message=f"当前没有失败项，已自动转为继续推进，后台将从阶段 {continue_stage} 重新排队",
            )
            task_manager_module.observe_task_operation(task_manager_module.TASK_ACTION_RETRY_FAILED_ITEMS, "accepted")
            return operation
        item_keys = sorted({self._stage_item_identity(item.item_key, item.parent_key) for item in items})
        self._set_retry_plan(
            task,
            {
                "target_stage": stage_name,
                "mode": task_manager_module.TASK_ACTION_RETRY_FAILED_ITEMS,
                "retry_item_keys": item_keys,
                "preserve_success_items": True,
                "archive_mode": "linked_failed_items",
                "cleared_business_stages": [],
                "cleared_archive_stages": [],
            },
        )
        operation = self._queue_task_operation(
            db,
            task,
            operation_type=task_manager_module.TASK_ACTION_RETRY_FAILED_ITEMS,
            target_stage=stage_name,
            requested_by=task.created_by,
            request_payload={"target_stage": stage_name, "retry_item_keys": item_keys, "retry_item_count": len(item_keys)},
            accepted_event_type="task_retry_failed_items_accepted",
            accepted_message=f"重试失败项已受理，后台正在准备从阶段 {stage_name} 重新排队",
        )
        task_manager_module.observe_task_operation(task_manager_module.TASK_ACTION_RETRY_FAILED_ITEMS, "accepted")
        return operation

    def retry_stage(self: TaskManager, db: Session, *, project_id: str, task_id: str, stage_name: str) -> None:
        self.retry_stage_full(db, project_id=project_id, task_id=task_id, stage_name=stage_name)

    def retry_stage_failed_items(
        self: TaskManager,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        stage_name: str,
    ) -> BinarySecurityTaskOperation:
        from app.service import task_manager as task_manager_module

        task = self._task_or_404(db, project_id, task_id)
        supported, reason, items = self._stage_retry_failed_items_support(db, task, stage_name)
        if not supported:
            continue_supported, continue_reason, continue_stage = self._task_continue_support(db, task)
            if not continue_supported or not continue_stage:
                raise ValidationError(reason or continue_reason or f"阶段 {stage_name} 不支持重试失败项")
            operation = self._queue_task_operation(
                db,
                task,
                operation_type=task_manager_module.TASK_ACTION_CONTINUE,
                target_stage=continue_stage,
                requested_by=task.created_by,
                request_payload={"target_stage": continue_stage, "requested_stage": stage_name},
                accepted_event_type="stage_retry_failed_items_continue_accepted",
                accepted_message=f"阶段 {stage_name} 当前没有失败项，已自动转为继续推进，后台将从阶段 {continue_stage} 重新排队",
            )
            return operation
        item_keys = sorted({self._stage_item_identity(item.item_key, item.parent_key) for item in items})
        self._set_retry_plan(
            task,
            {
                "target_stage": stage_name,
                "mode": task_manager_module.TASK_ACTION_RETRY_STAGE_FAILED_ITEMS,
                "retry_item_keys": item_keys,
                "preserve_success_items": True,
                "archive_mode": "linked_failed_items",
                "cleared_business_stages": [],
                "cleared_archive_stages": [],
            },
        )
        operation = self._queue_task_operation(
            db,
            task,
            operation_type=task_manager_module.TASK_ACTION_RETRY_STAGE_FAILED_ITEMS,
            target_stage=stage_name,
            requested_by=task.created_by,
            request_payload={"target_stage": stage_name, "retry_item_keys": item_keys, "retry_item_count": len(item_keys)},
            accepted_event_type="stage_retry_failed_items_accepted",
            accepted_message=f"阶段 {stage_name} 的失败项重试已受理，后台正在准备重新排队",
        )
        return operation

    def retry_stage_full(self: TaskManager, db: Session, *, project_id: str, task_id: str, stage_name: str) -> BinarySecurityTaskOperation:
        from app.service import task_manager as task_manager_module

        task = self._task_or_404(db, project_id, task_id)
        supported, reason = self._stage_retry_support(db, task, stage_name)
        if not supported:
            raise ValidationError(reason or f"阶段 {stage_name} 不支持完全重试")
        task.execution_mode = task_manager_module.TASK_ACTION_RETRY_STAGE_FULL
        task.target_stage_name = stage_name
        task.current_stage = stage_name
        self._set_retry_plan(
            task,
            {
                "target_stage": stage_name,
                "mode": task_manager_module.TASK_ACTION_RETRY_STAGE_FULL,
                "retry_item_keys": [],
                "preserve_success_items": False,
                "archive_mode": "linked_full",
                "cleared_business_stages": [],
                "cleared_archive_stages": [],
            },
        )
        operation = self._queue_task_operation(
            db,
            task,
            operation_type=task_manager_module.TASK_ACTION_RETRY_STAGE_FULL,
            target_stage=stage_name,
            requested_by=task.created_by,
            request_payload={"target_stage": stage_name},
            accepted_event_type="stage_retry_full_accepted",
            accepted_message=f"阶段 {stage_name} 的完全重试已受理，后台正在清理旧子任务并重建输入",
        )
        return operation

    def retry_stage_archive(self: TaskManager, db: Session, *, project_id: str, task_id: str, stage_name: str) -> BinarySecurityTaskOperation:
        return self.retry_stage_archive_failed_items(db, project_id=project_id, task_id=task_id, stage_name=stage_name)

    def retry_stage_archive_failed_items(
        self: TaskManager,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        stage_name: str,
    ) -> BinarySecurityTaskOperation:
        from app.service import task_manager as task_manager_module

        task = self._task_or_404(db, project_id, task_id)
        stage_sequence = self._stage_sequence_for_task(task)
        if stage_name not in stage_sequence:
            task_manager_module.observe_archive_action("retry_stage", "rejected")
            raise ValidationError(f"无效阶段: {stage_name}")
        supported, reason, jobs = self._archive_retry_support(db, task, stage_name, ignore_operation_lock=True)
        if not supported:
            task_manager_module.observe_archive_action("retry_stage", "rejected")
            raise ValidationError(reason or f"阶段 {stage_name} 暂无可重试的归档任务")
        operation = self._queue_task_operation(
            db,
            task,
            operation_type=task_manager_module.TASK_ACTION_RETRY_ARCHIVE_FAILED_ITEMS,
            target_stage=stage_name,
            requested_by=task.created_by,
            request_payload={"target_stage": stage_name, "retryable_job_ids": [job.id for job in jobs]},
            accepted_event_type="archive_stage_retry_accepted",
            accepted_message=f"阶段 {stage_name} 的归档失败项重试已受理，后台正在重新排队归档任务",
        )
        task_manager_module.observe_archive_action("retry_stage", "accepted")
        return operation

    def retry_stage_archive_full(
        self: TaskManager,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        stage_name: str,
    ) -> BinarySecurityTaskOperation:
        from app.service import task_manager as task_manager_module

        task = self._task_or_404(db, project_id, task_id)
        supported, reason, jobs, stage_items = self._archive_full_retry_support(db, task, stage_name, ignore_operation_lock=True)
        if not supported:
            task_manager_module.observe_archive_action("retry_stage_full", "rejected")
            raise ValidationError(reason or f"阶段 {stage_name} 暂无可完全重试的归档任务")
        operation = self._queue_task_operation(
            db,
            task,
            operation_type=task_manager_module.TASK_ACTION_RETRY_ARCHIVE_FULL,
            target_stage=stage_name,
            requested_by=task.created_by,
            request_payload={
                "target_stage": stage_name,
                "existing_job_ids": [job.id for job in jobs],
                "stage_item_ids": [item.id for item in stage_items],
            },
            accepted_event_type="archive_stage_full_retry_accepted",
            accepted_message=f"阶段 {stage_name} 的归档全量重试已受理，后台正在清空并重建归档任务",
        )
        task_manager_module.observe_archive_action("retry_stage_full", "accepted")
        return operation

    def retry_archive_job(self: TaskManager, db: Session, *, project_id: str, task_id: str, archive_job_id: str) -> str:
        from app.service import task_manager as task_manager_module

        task = self._task_or_404(db, project_id, task_id)
        job = db.query(task_manager_module.BinarySecurityArchiveJob).filter(
            task_manager_module.BinarySecurityArchiveJob.task_id == task.id,
            task_manager_module.BinarySecurityArchiveJob.id == archive_job_id,
        ).first()
        if job is None:
            task_manager_module.observe_archive_action("retry_job", "rejected")
            raise NotFoundError("归档任务不存在")
        supported, reason = self._archive_job_retry_support(db, task, job, ignore_operation_lock=True)
        if not supported:
            task_manager_module.observe_archive_action("retry_job", "rejected")
            raise ValidationError(reason or "当前归档任务不可重试")
        self._requeue_archive_jobs(
            db,
            task,
            [job],
            stage_name=job.stage_name,
            event_type="archive_job_retry_requested",
            event_message="归档任务已重新排队",
        )
        self._mark_task_waiting_for_archive_retry(db, task, job.stage_name)
        db.commit()
        task_manager_module.observe_archive_action("retry_job", "accepted")
        return job.stage_name
