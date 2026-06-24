from __future__ import annotations

import asyncio
import json
import shutil
import zipfile
import os
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
    BinarySecurityTaskPolicyConfigPayload,
    BinarySecurityTaskPolicyConfigResponse,
    BinarySecurityTaskCreate,
    BinarySecurityTaskPolicyUpdatePayload,
    BinarySecurityTaskDetailResponse,
    BinarySecurityTaskRuntimePolicyUpdatePayload,
)

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager


class TaskControlServiceMixin:
    def _active_delete_operation(self: TaskManager, db: Session, task_id: str):
        from app.service import task_manager as task_manager_module

        active_operation = self._active_operation(db, task_id)
        if active_operation is not None and str(active_operation.operation_type or "").strip() == task_manager_module.TASK_ACTION_DELETE:
            return active_operation
        return None

    def _task_workspace_root(self: TaskManager, task) -> Path:
        return Path(str(task.workspace_root or "")).expanduser()

    def _task_summary_dir(self: TaskManager, task, key: str, fallback: Path) -> Path:
        summary_value = str((task.summary or {}).get(key) or "").strip()
        workspace_root = self._task_workspace_root(task)
        if summary_value:
            candidate = Path(summary_value).expanduser()
            try:
                resolved = candidate.resolve(strict=False)
                workspace_resolved = workspace_root.resolve(strict=False)
                if resolved == workspace_resolved or workspace_resolved in resolved.parents:
                    return resolved
            except Exception:
                pass
        return fallback

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
        fallback = self._task_workspace_root(task) / "input"
        return self._task_summary_dir(task, "input_dir", fallback)

    def _task_temp_upload_dir(self: TaskManager, task) -> Path:
        fallback = self._task_workspace_root(task) / "run" / "upload-tmp"
        return self._task_summary_dir(task, "temp_upload_dir", fallback)

    def _normalize_input_files(self: TaskManager, files, *, task_type: str) -> list[dict[str, Any]]:
        from app.service import task_manager as task_manager_module

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
            if task_type == "binary":
                firmware_key = str(normalized.get("firmware_key") or "").strip()
                if not firmware_key:
                    firmware_key = task_manager_module._slug(Path(filename).stem or filename)
                normalized["firmware_key"] = firmware_key
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

    def _common_path_root(self: TaskManager, paths: list[Path]) -> Path:
        if not paths:
            raise ValidationError("输入文件列表不能为空")
        try:
            root = Path(os.path.commonpath([str(path) for path in paths]))
        except ValueError as exc:
            raise ValidationError("输入文件路径必须位于同一文件系统根下") from exc
        return root

    def _summarize_path_input(
        self: TaskManager,
        *,
        task_type: str,
        input_file_path: str | None,
        input_dir_path: str | None,
        input_file_paths: list[str] | None,
    ) -> dict[str, Any] | None:
        file_path = str(input_file_path or "").strip()
        dir_path = str(input_dir_path or "").strip()
        file_paths = [str(item or "").strip() for item in list(input_file_paths or []) if str(item or "").strip()]
        if not file_path and not dir_path and not file_paths:
            return None
        if task_type == "binary":
            if not file_path:
                raise ValidationError("binary 任务必须提供 input_file_path")
            path = Path(file_path).expanduser()
            if not path.is_file():
                raise ValidationError(f"输入文件不存在或不是文件: {path}")
            stat = path.stat()
            return {
                "mode": "path",
                "input_files": [
                    {
                        "filename": path.name,
                        "firmware_key": path.stem or path.name,
                        "relative_path": path.name,
                        "size": stat.st_size,
                        "uploaded": True,
                        "path": str(path),
                    }
                ],
                "input_kind": "firmware_files",
                "firmware_path": str(path),
                "summary_updates": {
                    "input_mode": "shared_path",
                    "input_file_path": str(path),
                    "input_dir_path": None,
                    "input_file_paths": [],
                    "input_dir": str(path.parent),
                },
                "metrics": {
                    "input_total_bytes": int(stat.st_size or 0),
                },
            }
        if task_type == "source":
            if not dir_path:
                raise ValidationError("source 任务必须提供 input_dir_path")
            root = Path(dir_path).expanduser()
            if not root.is_dir():
                raise ValidationError(f"输入目录不存在或不是目录: {root}")
            rows: list[dict[str, Any]] = []
            total_bytes = 0
            for child in sorted(root.rglob("*")):
                if not child.is_file():
                    continue
                rel = child.relative_to(root).as_posix()
                stat = child.stat()
                total_bytes += int(stat.st_size or 0)
                rows.append(
                    {
                        "filename": child.name,
                        "relative_path": rel,
                        "size": stat.st_size,
                        "uploaded": True,
                        "path": str(child),
                    }
                )
            if not rows:
                raise ValidationError("任务输入目录中没有可用文件")
            return {
                "mode": "path",
                "input_files": rows,
                "input_kind": "source_tree_files",
                "firmware_path": str(root),
                "summary_updates": {
                    "input_mode": "shared_path",
                    "input_file_path": None,
                    "input_dir_path": str(root),
                    "input_file_paths": [],
                    "input_dir": str(root),
                    "source_root": str(root),
                },
                "metrics": {
                    "input_total_bytes": total_bytes,
                },
            }
        if task_type == "binary_module":
            if not file_paths:
                raise ValidationError("binary_module 任务必须提供非空 input_file_paths")
            normalized_paths = [Path(item).expanduser() for item in file_paths]
            for path in normalized_paths:
                if not path.is_file():
                    raise ValidationError(f"输入模块文件不存在或不是文件: {path}")
            root = self._common_path_root(normalized_paths)
            if root.is_file():
                root = root.parent
            rows = []
            total_bytes = 0
            seen_relative_paths: set[str] = set()
            for path in normalized_paths:
                rel = path.relative_to(root).as_posix()
                if rel in seen_relative_paths:
                    raise ValidationError("存在重复模块输入路径")
                seen_relative_paths.add(rel)
                stat = path.stat()
                total_bytes += int(stat.st_size or 0)
                rows.append(
                    {
                        "filename": path.name,
                        "relative_path": rel,
                        "size": stat.st_size,
                        "uploaded": True,
                        "path": str(path),
                    }
                )
            return {
                "mode": "path",
                "input_files": rows,
                "input_kind": "module_elf_files",
                "firmware_path": str(root),
                "summary_updates": {
                    "input_mode": "shared_path",
                    "input_file_path": None,
                    "input_dir_path": None,
                    "input_file_paths": [str(path) for path in normalized_paths],
                    "input_dir": str(root),
                    "module_input_root_path": str(root),
                    "source_root": str(root),
                },
                "metrics": {
                    "input_total_bytes": total_bytes,
                },
            }
        raise ValidationError(f"不支持的任务类型: {task_type}")

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
        temp_dir = self._task_temp_upload_dir(task)
        await asyncio.to_thread(input_dir.mkdir, parents=True, exist_ok=True)
        await asyncio.to_thread(temp_dir.mkdir, parents=True, exist_ok=True)
        total_bytes = 0
        actual_files: list[dict[str, Any]] = []
        for file_info in declared:
            filename = str(file_info.get("filename") or "").strip()
            relative_path = str(file_info.get("relative_path") or filename).strip().replace("\\", "/")
            local_path = input_dir / relative_path
            temp_path = temp_dir / relative_path
            if not await asyncio.to_thread(local_path.is_file):
                if not await asyncio.to_thread(temp_path.is_file):
                    raise ValidationError(f"上传文件缺失: {relative_path}")
                await asyncio.to_thread(local_path.parent.mkdir, parents=True, exist_ok=True)
                await asyncio.to_thread(temp_path.replace, local_path)
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
        await asyncio.to_thread((workspace_root / "run" / "upload-tmp").mkdir, parents=True, exist_ok=True)

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
            "pipeline_mode": "mixed_streaming",
            "max_stage_parallelism": 5,
            "max_retries_per_item": 2,
            "continue_on_item_failure": True,
            "stage_parallelism": {stage_name: 5 for stage_name in stage_names},
            "stage_options": {},
            "module_selection_mode": "auto",
            "module_risk_levels": ["高"],
        }
        defaults["partial_success_stage_advancement"] = {
            stage_name: True for stage_name in stage_names if stage_name in {"binary_to_source", "entry_analysis", "dataflow_vuln_scan"}
        }
        return defaults

    def _global_task_policy_config(self: TaskManager, db: Session, *, task_type: str) -> dict[str, Any]:
        policy = self._project_config_defaults(task_type=task_type)
        row = self._ensure_global_service_config_row(db)
        config = dict(getattr(row, "config", {}) or {}) if row is not None else {}
        if config:
            policy.update({k: v for k, v in config.items() if k != "partial_success_stage_advancement"})
            if "partial_success_stage_advancement" in config:
                policy["partial_success_stage_advancement"] = self._normalize_partial_success_stage_advancement_for_task_type(
                    config.get("partial_success_stage_advancement"),
                    task_type=task_type,
                )
        return policy

    def _merge_policy(self: TaskManager, db: Session, project_id: str, overrides: dict[str, Any], stage_options: dict[str, Any]) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        del project_id
        task_type = self._validate_task_type(overrides.get("task_type"))
        policy = self._global_task_policy_config(db, task_type=task_type)
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
        for key in (
            "knowledge_graph_upload_id",
            "knowledge_graph_db_name",
            "knowledge_graph_status_filter",
            "knowledge_graph_kind",
        ):
            if key in override_payload:
                value = str(override_payload.get(key) or "").strip()
                policy[key] = value or None
        if "knowledge_graph_module" in override_payload:
            value = override_payload.get("knowledge_graph_module")
            policy["knowledge_graph_module"] = None if value is None else str(value)
        if "knowledge_graph_include_excluded" in override_payload:
            include_excluded = override_payload.get("knowledge_graph_include_excluded")
            policy["knowledge_graph_include_excluded"] = None if include_excluded is None else bool(include_excluded)
        if policy.get("pipeline_profile") == task_manager_module.PIPELINE_PROFILE_KG_SOURCE_VULN_SCAN:
            policy["entry_selection_mode"] = "auto"
        return policy

    def save_task_policy_config(
        self: TaskManager,
        db: Session,
        payload: BinarySecurityTaskPolicyConfigPayload,
    ) -> BinarySecurityTaskPolicyConfigResponse:
        response = self.save_config(db, BinarySecurityGlobalConfigPayload(**payload.model_dump()))
        return BinarySecurityTaskPolicyConfigResponse(
            project_id="global",
            config=BinarySecurityTaskPolicyConfigPayload(**response.config.model_dump()),
        )

    def get_task_policy_config(self: TaskManager, db: Session) -> BinarySecurityTaskPolicyConfigResponse:
        response = self.get_config(db)
        return BinarySecurityTaskPolicyConfigResponse(
            project_id="global",
            config=BinarySecurityTaskPolicyConfigPayload(**response.config.model_dump()),
        )

    def save_project_config(
        self: TaskManager,
        db: Session,
        project_id: str,
        payload: BinarySecurityProjectConfigPayload,
    ) -> BinarySecurityProjectConfigResponse:
        del project_id
        response = self.save_task_policy_config(
            db,
            BinarySecurityTaskPolicyConfigPayload(**payload.model_dump()),
        )
        return BinarySecurityProjectConfigResponse(
            project_id="global",
            config=BinarySecurityProjectConfigPayload(**response.config.model_dump()),
        )

    def get_project_config(self: TaskManager, db: Session, project_id: str) -> BinarySecurityProjectConfigResponse:
        del project_id
        response = self.get_task_policy_config(db)
        return BinarySecurityProjectConfigResponse(
            project_id="global",
            config=BinarySecurityProjectConfigPayload(**response.config.model_dump()),
        )

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
        self._apply_task_status_only_update(
            db,
            task,
            status="pending",
            reason="入口选择确认完成，任务恢复待执行",
            source="task_control",
            stage_name="entry_analysis",
            finished_at=None,
            last_error=None,
        )
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
        self._apply_task_status_only_update(
            db,
            task,
            status="pending",
            reason="模块选择确认完成，任务恢复待执行",
            source="task_control",
            stage_name="entry_analysis",
            finished_at=None,
            last_error=None,
        )
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
        path_input = self._summarize_path_input(
            task_type=task_type,
            input_file_path=payload.input_file_path,
            input_dir_path=payload.input_dir_path,
            input_file_paths=payload.input_file_paths,
        )
        input_files = (
            [dict(item) for item in path_input["input_files"]]
            if path_input is not None
            else self._normalize_input_files(payload.input_files, task_type=task_type)
        )
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

        input_kind = (
            path_input["input_kind"]
            if path_input is not None
            else self._source_input_kind(input_files)
            if task_type == task_manager_module.TASK_TYPE_SOURCE
            else "module_elf_files"
            if task_type == task_manager_module.TASK_TYPE_BINARY_MODULE
            else "firmware_files"
        )
        task_status = "pending" if path_input is not None else "pending_upload"
        firmware_path = (
            str(path_input["firmware_path"])
            if path_input is not None
            else str(input_dir)
        )
        initial_stage_name = self._stage_sequence_for_task(task_type)[0]
        task = task_manager_module.BinarySecurityTask(
            id=task_id,
            project_id=project_id,
            task_type=task_type,
            name=payload.name,
            description=payload.description,
            schedule_user_task_id=str(payload.schedule_user_task_id or "").strip() or None,
            created_by=created_by,
            status=task_status,
            current_stage=initial_stage_name if path_input is not None else None,
            firmware_name=f"{len(input_files)} files",
            firmware_source="project_filesystem",
            firmware_path=firmware_path,
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
            "input_kind": input_kind,
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
            **(path_input["summary_updates"] if path_input is not None else {"input_mode": "uploaded_files", "input_file_path": None, "input_dir_path": None, "input_file_paths": []}),
        }
        if task_type == task_manager_module.TASK_TYPE_BINARY_MODULE:
            task.summary = {
                **task.summary,
                **self._build_binary_module_summary(task, input_files),
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
            "uploaded_file_count": len(input_files) if path_input is not None else 0,
            "input_total_bytes": int(path_input["metrics"]["input_total_bytes"] if path_input is not None else sum(int(item.get("size") or 0) for item in input_files)),
            "firmware_item_count": len(input_files),
            "unpacked_firmware_count": 0,
            "failed_firmware_count": 0,
        }
        if task_type == task_manager_module.TASK_TYPE_BINARY_MODULE:
            task.metrics = {
                **task.metrics,
                "selected_module_count": 1,
                "candidate_module_count": 1,
            }
        task.stage_summary = {}
        task.cleanup_snapshot = {}
        db.add(task)
        db.commit()
        await self._write_task_metadata_async(task, metadata_path, status=task_status)
        self._record_event(db, task, "task_created", f"创建任务 {task.id}", payload={"input_files": input_files})
        if path_input is not None:
            self._record_event(db, task, "task_start_requested", "共享路径输入校验完成，任务已自动进入调度队列")
            if task_type == task_manager_module.TASK_TYPE_BINARY:
                self._record_event(db, task, "firmware_items_initialized", f"已初始化 {len(input_files)} 个固件输入")
            else:
                self._record_event(db, task, "source_tree_initialized", f"已初始化源码工程输入，共 {len(input_files)} 个文件")
        else:
            self._record_event(db, task, "task_upload_pending", "任务创建完成，等待上传文件")
        task_manager_module.observe_task_lifecycle("created", status=task.status, task_type=self._task_type(task))
        db.commit()
        if path_input is not None:
            self._enqueue_task(task.id)
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
        self._set_task_status(
            db,
            task,
            task_manager_module.TASK_STATUS_CANCELLING,
            reason="收到取消请求",
            source="task_control",
            stage_name=task.current_stage,
        )
        task.finished_at = None
        task.last_error = None
        task.current_operation_id = operation.id
        db.commit()
        wakeup_requested = await self._request_local_worker_control_wakeup(
            task.id,
            task_manager_module.TASK_ACTION_CANCEL,
            operation_id=operation.id,
            wait_for_runner=False,
        )
        if wakeup_requested:
            self._record_event(
                db,
                task,
                "local_owner_control_wakeup_requested",
                "已通知当前 owner 原地处理取消控制操作",
                stage_name=task.current_stage,
                payload={
                    "operation_id": operation.id,
                    "operation_type": task_manager_module.TASK_ACTION_CANCEL,
                    "dispatcher_instance_id": str(getattr(task, "dispatcher_instance_id", "") or "").strip() or None,
                },
            )
            db.commit()
        self._enqueue_task(task.id)
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
        requested_by: str | None = None,
        request_source: str = "api",
        request_token_type: str | None = None,
        request_machine_code: str | None = None,
    ) -> BinarySecurityActionResponse:
        from app.service import task_manager as task_manager_module

        task = self._task_or_404(db, project_id, task_id)
        normalized_requested_by = str(requested_by or getattr(task, "created_by", None) or "").strip() or None
        normalized_request_source = str(request_source or "api").strip() or "api"
        normalized_token_type = str(request_token_type or "").strip() or None
        normalized_machine_code = str(request_machine_code or "").strip() or None
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
            requested_by=normalized_requested_by,
            request_payload={
                "current_stage": task.current_stage,
                "force": bool(force),
                "force_delete": bool(force),
                "requested_by": normalized_requested_by,
                "request_token_type": normalized_token_type,
                "request_machine_code": normalized_machine_code,
                "request_source": normalized_request_source,
            },
            accepted_event_type="task_delete_accepted",
            accepted_message="任务删除已受理，后台正在清理任务及下游资源",
        )
        operation.request_source = normalized_request_source
        task.current_operation_id = operation.id
        db.commit()
        wakeup_requested = await self._request_local_worker_control_wakeup(
            task.id,
            task_manager_module.TASK_ACTION_DELETE,
            operation_id=operation.id,
            wait_for_runner=False,
        )
        if wakeup_requested:
            self._record_event(
                db,
                task,
                "local_owner_control_wakeup_requested",
                "已通知当前 owner 原地处理删除控制操作",
                stage_name=task.current_stage,
                payload={
                    "operation_id": operation.id,
                    "operation_type": task_manager_module.TASK_ACTION_DELETE,
                    "dispatcher_instance_id": str(getattr(task, "dispatcher_instance_id", "") or "").strip() or None,
                },
            )
            db.commit()
        self._enqueue_task(task.id)
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

    async def force_reset_task_to_pending(
        self: TaskManager,
        db: Session,
        *,
        project_id: str,
        task_id: str,
        requested_by: str | None = None,
    ) -> BinarySecurityActionResponse:
        from app.service import task_manager as task_manager_module

        task = self._task_or_404(db, project_id, task_id)
        previous_status = str(getattr(task, "status", "") or "").strip()
        normalized_requested_by = str(requested_by or getattr(task, "created_by", None) or "").strip() or None
        if previous_status.lower() in {"success", "cancelled"}:
            task_manager_module.observe_task_operation("force_reset", "rejected")
            raise ValidationError(f"当前任务状态不支持强制重置: {task.status}")
        active_operations = (
            db.query(task_manager_module.BinarySecurityTaskOperation)
            .filter(task_manager_module.BinarySecurityTaskOperation.task_id == task.id)
            .all()
        )
        reset_at = task_manager_module._now()
        for candidate in active_operations:
            operation_status = str(getattr(candidate, "status", "") or "").strip().lower()
            if operation_status in task_manager_module.TASK_OPERATION_TERMINAL_STATUSES:
                continue
            if str(getattr(candidate, "operation_type", "") or "").strip() == "force_reset_to_pending":
                task_manager_module.observe_task_operation("force_reset", "already_queued")
                return BinarySecurityActionResponse(
                    task_id=task_id,
                    operation_id=candidate.id,
                    accepted=True,
                    action="force_reset_to_pending",
                    status="accepted",
                    message="任务强制重置已受理，后台将等待当前 owner 或租约过期后处理",
                    task_status_after_accept=task.status,
                )
            candidate.status = "superseded"
            candidate.finished_at = reset_at
            candidate.superseded_by_operation_id = None
            operation_payload = dict(self._operation_result_data(candidate) or {})
            operation_payload["force_reset"] = {
                "requested": True,
                "requested_by": normalized_requested_by,
                "reset_at": reset_at.isoformat(),
                "task_status_after": str(getattr(task, "status", "") or "").strip(),
            }
            self._persist_operation_result_payload(
                candidate,
                operation_payload,
                workspace_root=task.workspace_root,
            )
            self._record_operation_event(
                db,
                task,
                candidate,
                "operation_force_reset_superseded",
                "人工强制重置请求已受理，原后台操作已转为 superseded",
                level="warning",
                stage_name=candidate.target_stage,
                payload={
                    "source": "manual_force_reset_request",
                    "requested_by": normalized_requested_by,
                    "task_status_after": str(getattr(task, "status", "") or "").strip(),
                },
            )
        operation = self._queue_task_operation(
            db,
            task,
            operation_type="force_reset_to_pending",
            target_stage=task.current_stage,
            requested_by=normalized_requested_by,
            request_payload={
                "current_stage": task.current_stage,
                "requested_by": normalized_requested_by,
                "previous_status": previous_status,
            },
            accepted_event_type="task_force_reset_to_pending_accepted",
            accepted_message="任务强制重置已受理，后台将等待当前 owner 或租约过期后处理",
        )
        await self._request_local_worker_cancel(task.id, wait_for_runner=False)
        task_manager_module.observe_task_operation("force_reset", "accepted")
        return BinarySecurityActionResponse(
            task_id=task_id,
            operation_id=operation.id,
            accepted=True,
            action="force_reset_to_pending",
            status="accepted",
            message="任务强制重置已受理，后台将等待当前 owner 或租约过期后处理",
            task_status_after_accept=task.status,
        )

    async def _apply_force_reset_to_pending_now(
        self: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        *,
        requested_by: str | None = None,
        operation: BinarySecurityTaskOperation | None = None,
    ) -> dict[str, Any]:
        from app.service import task_manager as task_manager_module

        previous_status = str(getattr(task, "status", "") or "").strip()
        active_operations = (
            db.query(task_manager_module.BinarySecurityTaskOperation)
            .filter(task_manager_module.BinarySecurityTaskOperation.task_id == task.id)
            .all()
        )
        reset_at = task_manager_module._now()
        current_operation_id = str(getattr(task, "current_operation_id", "") or "").strip() or None
        current_operation_type: str | None = None
        superseded_operation_count = 0
        executing_operation_id = str(getattr(operation, "id", "") or "").strip() or None
        for candidate in active_operations:
            operation_status = str(getattr(candidate, "status", "") or "").strip().lower()
            if operation_status in task_manager_module.TASK_OPERATION_TERMINAL_STATUSES:
                continue
            candidate_id = str(getattr(candidate, "id", "") or "").strip() or None
            if executing_operation_id and candidate_id == executing_operation_id:
                current_operation_type = str(getattr(candidate, "operation_type", "") or "").strip() or None
                continue
            if current_operation_id and candidate_id == current_operation_id:
                current_operation_type = str(getattr(candidate, "operation_type", "") or "").strip() or None
            candidate.status = "superseded"
            candidate.finished_at = reset_at
            candidate.superseded_by_operation_id = executing_operation_id
            operation_payload = dict(self._operation_result_data(candidate) or {})
            operation_payload["force_reset"] = {
                "requested": True,
                "requested_by": str(requested_by or "").strip() or None,
                "reset_at": reset_at.isoformat(),
                "task_status_after": "pending",
            }
            self._persist_operation_result_payload(
                candidate,
                operation_payload,
                workspace_root=task.workspace_root,
            )
            self._record_operation_event(
                db,
                task,
                candidate,
                "operation_force_reset_superseded",
                "人工强制重置任务状态，已终止当前后台操作",
                level="warning",
                stage_name=candidate.target_stage,
                payload={
                    "source": "manual_force_reset",
                    "requested_by": str(requested_by or "").strip() or None,
                    "task_status_after": "pending",
                    "superseded_by_operation_id": executing_operation_id,
                },
            )
            superseded_operation_count += 1

        self._set_task_runtime_workset(task, {})
        task.summary = self._clear_failure_fields_from_summary(dict(getattr(task, "summary", None) or {}))
        self._set_task_status(
            db,
            task,
            "pending",
            reason="人工强制重置任务为待调度",
            source="task_control",
            stage_name=task.current_stage,
        )
        task.last_error = None
        task.finished_at = None
        task.current_operation_id = None
        task.execution_mode = None
        task.tail_reconcile_state = "idle"
        self._set_task_runtime_phase(task, task_manager_module.TASK_RUNTIME_PHASE_OWNED_EXECUTION)
        self._invalidate_task_execution(task)
        self._clear_runtime_lease(db, task.id)
        self._release_tail_reconcile_owner(task.id)
        self._clear_task_abnormal_reason_snapshot(db, task)
        self._record_event(
            db,
            task,
            "task_force_reset_to_pending",
            "任务已被人工强制重置为待调度",
            level="warning",
            stage_name=task.current_stage,
            payload={
                "source": "manual_force_reset",
                "requested_by": str(requested_by or "").strip() or None,
                "previous_status": previous_status,
                "previous_current_operation_id": current_operation_id,
                "previous_operation_type": current_operation_type,
                "superseded_operation_count": superseded_operation_count,
                "task_status_after": "pending",
                "executed_via_operation_id": executing_operation_id,
            },
        )
        self._enqueue_task(task.id)
        return {
            "previous_status": previous_status,
            "previous_current_operation_id": current_operation_id,
            "previous_operation_type": current_operation_type,
            "superseded_operation_count": superseded_operation_count,
        }

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
        task.current_operation_id = operation.id
        db.commit()
        self._request_local_worker_control_wakeup_nowait(
            task.id,
            task_manager_module.TASK_ACTION_CONTINUE,
            operation_id=operation.id,
        )
        self._enqueue_task(task.id)
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
        task.current_operation_id = operation.id
        db.commit()
        self._request_local_worker_control_wakeup_nowait(
            task.id,
            task_manager_module.TASK_ACTION_RETRY,
            operation_id=operation.id,
        )
        self._enqueue_task(task.id)
        task_manager_module.observe_task_operation("retry", "accepted")
        task_manager_module.observe_task_error("retry", stage=first_stage, result="accepted")
        return operation

    def retry_failed_items(self: TaskManager, db: Session, *, project_id: str, task_id: str) -> BinarySecurityTaskOperation:
        from app.service import task_manager as task_manager_module

        task = self._task_or_404(db, project_id, task_id)
        supported, reason, stage_name, items = self._task_retry_failed_items_support(db, task)
        if supported and stage_name and not items:
            operation = self._queue_task_operation(
                db,
                task,
                operation_type=task_manager_module.TASK_ACTION_RETRY_ARCHIVE_FULL,
                target_stage=stage_name,
                requested_by=task.created_by,
                request_payload={
                    "target_stage": stage_name,
                    "fallback_from": task_manager_module.TASK_ACTION_RETRY_FAILED_ITEMS,
                    "upgrade_reason": "archive_pending_full_retry",
                },
                accepted_event_type="task_retry_failed_items_archive_full_accepted",
                accepted_message=f"检测到阶段 {stage_name} 的归档仍在处理中，已自动升级为阶段归档完全重试",
            )
            task.current_operation_id = operation.id
            db.commit()
            self._request_local_worker_control_wakeup_nowait(
                task.id,
                task_manager_module.TASK_ACTION_RETRY_ARCHIVE_FULL,
                operation_id=operation.id,
            )
            self._enqueue_task(task.id)
            task_manager_module.observe_task_operation(task_manager_module.TASK_ACTION_RETRY_FAILED_ITEMS, "accepted")
            return operation
        if not supported or not stage_name:
            archive_stage_name, archive_reason = self._archive_pending_full_retry_stage(db, task)
            if archive_stage_name:
                operation = self._queue_task_operation(
                    db,
                    task,
                    operation_type=task_manager_module.TASK_ACTION_RETRY_ARCHIVE_FULL,
                    target_stage=archive_stage_name,
                    requested_by=task.created_by,
                    request_payload={
                        "target_stage": archive_stage_name,
                        "fallback_from": task_manager_module.TASK_ACTION_RETRY_FAILED_ITEMS,
                        "upgrade_reason": "archive_pending_full_retry",
                    },
                    accepted_event_type="task_retry_failed_items_archive_full_accepted",
                    accepted_message=f"检测到阶段 {archive_stage_name} 的归档仍在处理中，已自动升级为阶段归档完全重试",
                )
                task.current_operation_id = operation.id
                db.commit()
                self._request_local_worker_control_wakeup_nowait(
                    task.id,
                    task_manager_module.TASK_ACTION_RETRY_ARCHIVE_FULL,
                    operation_id=operation.id,
                )
                self._enqueue_task(task.id)
                task_manager_module.observe_task_operation(task_manager_module.TASK_ACTION_RETRY_FAILED_ITEMS, "accepted")
                return operation
            continue_supported, continue_reason, continue_stage = self._task_continue_support(db, task)
            if not continue_supported or not continue_stage:
                task_manager_module.observe_task_operation(task_manager_module.TASK_ACTION_RETRY_FAILED_ITEMS, "rejected")
                raise ValidationError(archive_reason or reason or continue_reason or "当前任务不支持重试失败项")
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
            task.current_operation_id = operation.id
            db.commit()
            self._request_local_worker_control_wakeup_nowait(
                task.id,
                task_manager_module.TASK_ACTION_CONTINUE,
                operation_id=operation.id,
            )
            self._enqueue_task(task.id)
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
        task.current_operation_id = operation.id
        db.commit()
        self._request_local_worker_control_wakeup_nowait(
            task.id,
            task_manager_module.TASK_ACTION_RETRY_FAILED_ITEMS,
            operation_id=operation.id,
        )
        self._enqueue_task(task.id)
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
        if supported and not items:
            operation = self._queue_task_operation(
                db,
                task,
                operation_type=task_manager_module.TASK_ACTION_RETRY_ARCHIVE_FULL,
                target_stage=stage_name,
                requested_by=task.created_by,
                request_payload={
                    "target_stage": stage_name,
                    "requested_stage": stage_name,
                    "fallback_from": task_manager_module.TASK_ACTION_RETRY_STAGE_FAILED_ITEMS,
                    "upgrade_reason": "archive_pending_full_retry",
                },
                accepted_event_type="stage_retry_failed_items_archive_full_accepted",
                accepted_message=f"阶段 {stage_name} 的归档仍在处理中，已自动升级为阶段归档完全重试",
            )
            task.current_operation_id = operation.id
            db.commit()
            self._request_local_worker_control_wakeup_nowait(
                task.id,
                task_manager_module.TASK_ACTION_RETRY_ARCHIVE_FULL,
                operation_id=operation.id,
            )
            self._enqueue_task(task.id)
            return operation
        if not supported:
            archive_stage_name, archive_reason = self._archive_pending_full_retry_stage(db, task, stage_name)
            if archive_stage_name:
                operation = self._queue_task_operation(
                    db,
                    task,
                    operation_type=task_manager_module.TASK_ACTION_RETRY_ARCHIVE_FULL,
                    target_stage=archive_stage_name,
                    requested_by=task.created_by,
                    request_payload={
                        "target_stage": archive_stage_name,
                        "requested_stage": stage_name,
                        "fallback_from": task_manager_module.TASK_ACTION_RETRY_STAGE_FAILED_ITEMS,
                        "upgrade_reason": "archive_pending_full_retry",
                    },
                    accepted_event_type="stage_retry_failed_items_archive_full_accepted",
                    accepted_message=f"阶段 {archive_stage_name} 的归档仍在处理中，已自动升级为阶段归档完全重试",
                )
                task.current_operation_id = operation.id
                db.commit()
                self._request_local_worker_control_wakeup_nowait(
                    task.id,
                    task_manager_module.TASK_ACTION_RETRY_ARCHIVE_FULL,
                    operation_id=operation.id,
                )
                self._enqueue_task(task.id)
                return operation
            continue_supported, continue_reason, continue_stage = self._task_continue_support(db, task)
            if not continue_supported or not continue_stage:
                raise ValidationError(archive_reason or reason or continue_reason or f"阶段 {stage_name} 不支持重试失败项")
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
            task.current_operation_id = operation.id
            db.commit()
            self._request_local_worker_control_wakeup_nowait(
                task.id,
                task_manager_module.TASK_ACTION_CONTINUE,
                operation_id=operation.id,
            )
            self._enqueue_task(task.id)
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
        task.current_operation_id = operation.id
        db.commit()
        self._request_local_worker_control_wakeup_nowait(
            task.id,
            task_manager_module.TASK_ACTION_RETRY_STAGE_FAILED_ITEMS,
            operation_id=operation.id,
        )
        self._enqueue_task(task.id)
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
        task.current_operation_id = operation.id
        db.commit()
        self._request_local_worker_control_wakeup_nowait(
            task.id,
            task_manager_module.TASK_ACTION_RETRY_STAGE_FULL,
            operation_id=operation.id,
        )
        self._enqueue_task(task.id)
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
        task.current_operation_id = operation.id
        db.commit()
        self._request_local_worker_control_wakeup_nowait(
            task.id,
            task_manager_module.TASK_ACTION_RETRY_ARCHIVE_FAILED_ITEMS,
            operation_id=operation.id,
        )
        self._enqueue_task(task.id)
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
        task.current_operation_id = operation.id
        db.commit()
        self._request_local_worker_control_wakeup_nowait(
            task.id,
            task_manager_module.TASK_ACTION_RETRY_ARCHIVE_FULL,
            operation_id=operation.id,
        )
        self._enqueue_task(task.id)
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
