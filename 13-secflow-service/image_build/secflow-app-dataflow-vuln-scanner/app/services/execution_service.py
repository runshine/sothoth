from __future__ import annotations

import asyncio
import os
import posixpath
import shutil
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.artifacts.io import abs_path, ensure_dir, sanitize_name, write_json, write_task_manifest, write_text
from app.config import get_config
from app.models.contracts import TaskItem, TaskManifest
from app.models.database import (
    HistoryRun,
    HistoryRunCycle,
    HistoryRunFile,
    HistoryRunGlobalReview,
    HistoryRunRemovedResult,
    HistoryRunResult,
    HistoryRunResultReview,
    HistoryRunSession,
    TriggerTask,
    WorkflowDefinition,
    WorkflowDefinitionVersion,
    WorkflowExecution,
    WorkflowExecutionEvent,
    get_db_session,
)
from app.pi_vuln_core.runner import build_runtime_framework_config, run_framework_config
from app.pi_vuln_core.utils.logger import attach_log_file, detach_log_file
from app.pi_vuln_core.utils.win_compat import ensure_event_loop_policy
from app.schemas import (
    ArtifactRef,
    ScanTaskArtifactsResponse,
    ScanTaskArtifactFileResponse,
    ScanTaskAttemptResponse,
    ScanTaskCreateRequest,
    ScanTaskDetailResponse,
    ScanTaskEventResponse,
    ScanTaskResponse,
    TriggerTaskCreate,
    TriggerTaskInputTask,
    TriggerTaskResponse,
    WorkflowExecutionEventResponse,
    WorkflowExecutionResponse,
)
from app.services.fileserver_client import get_fileserver_client
from app.services.history_run_service import get_history_run_service
from app.services.pi_vuln_adapter import (
    DbExecutionObserver,
    DbExecutionRecorder,
    build_core_tasks,
    write_final_task_manifest,
)
from app.services.workflow_service import get_workflow_service


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:20]}"


def _principal_id(principal: dict) -> str:
    return principal.get("user_id") or principal.get("subject") or principal.get("client_id") or "system"


def _project_ids(principal: dict) -> set[str]:
    return set(principal.get("project_ids") or [])


def _command_display(args: list[str]) -> str:
    return " ".join(shlex.quote(str(item)) for item in args)


class ExecutionService:
    def _ensure_project_access(self, principal: dict, project_id: str) -> None:
        project_ids = _project_ids(principal)
        if project_ids and project_id not in project_ids:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="project access denied")

    def _definition_or_404(self, db: Session, definition_id: str) -> WorkflowDefinition:
        definition = db.get(WorkflowDefinition, definition_id)
        if definition is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="workflow definition not found")
        return definition

    def _definition_version_or_404(self, db: Session, version_id: str | None) -> WorkflowDefinitionVersion:
        if not version_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="workflow definition version not found")
        version = db.get(WorkflowDefinitionVersion, version_id)
        if version is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="workflow definition version not found")
        return version

    def _trigger_or_404(self, db: Session, trigger_task_id: str) -> TriggerTask:
        trigger = db.get(TriggerTask, trigger_task_id)
        if trigger is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="trigger task not found")
        return trigger

    def _execution_or_404(self, db: Session, execution_id: str) -> WorkflowExecution:
        execution = db.get(WorkflowExecution, execution_id)
        if execution is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="execution not found")
        return execution

    def _latest_execution_for_trigger(self, db: Session, trigger_id: str) -> WorkflowExecution | None:
        return (
            db.query(WorkflowExecution)
            .filter(WorkflowExecution.trigger_task_id == trigger_id)
            .order_by(WorkflowExecution.attempt_no.desc(), WorkflowExecution.created_at.desc())
            .first()
        )

    def _list_executions_for_trigger(self, db: Session, trigger_id: str) -> list[WorkflowExecution]:
        return (
            db.query(WorkflowExecution)
            .filter(WorkflowExecution.trigger_task_id == trigger_id)
            .order_by(WorkflowExecution.attempt_no.asc(), WorkflowExecution.created_at.asc())
            .all()
        )

    def _trigger_response(self, model: TriggerTask) -> TriggerTaskResponse:
        return TriggerTaskResponse.model_validate(model, from_attributes=True)

    def _execution_response(self, model: WorkflowExecution) -> WorkflowExecutionResponse:
        return WorkflowExecutionResponse.model_validate(model, from_attributes=True)

    def _event_response(self, model: WorkflowExecutionEvent) -> WorkflowExecutionEventResponse:
        return WorkflowExecutionEventResponse.model_validate(model, from_attributes=True)

    def _scan_task_response(self, db: Session, trigger: TriggerTask) -> ScanTaskResponse:
        latest_execution = self._latest_execution_for_trigger(db, trigger.id)
        if trigger.workflow_definition_version_id:
            version = self._definition_version_or_404(db, trigger.workflow_definition_version_id)
        else:
            version = get_workflow_service().get_profile_version_model(db, trigger.workflow_definition_id)
        return ScanTaskResponse(
            task_id=trigger.id,
            project_id=trigger.project_id,
            profile_id=trigger.profile_id or trigger.workflow_definition_id,
            profile_version=version.version_no,
            status=trigger.status,
            latest_attempt_no=latest_execution.attempt_no if latest_execution else 0,
            retry_count=trigger.retry_count,
            max_retry_count=trigger.max_retry_count,
            priority=trigger.priority,
            created_by=trigger.submitted_by,
            created_at=trigger.created_at,
            started_at=trigger.started_at,
            finished_at=trigger.finished_at,
            message=trigger.message,
            latest_execution_id=trigger.latest_execution_id,
        )

    def _scan_task_detail(self, db: Session, trigger: TriggerTask) -> ScanTaskDetailResponse:
        response = self._scan_task_response(db, trigger)
        manifest = TaskManifest.model_validate(trigger.input_tasks_json)
        first_task = manifest.tasks[0] if manifest.tasks else None
        task_markdown = ""
        artifact_refs: list[ArtifactRef] = []
        runtime_overrides: dict[str, Any] = {}
        task_metadata: dict[str, Any] = {}
        title = first_task.title if first_task else trigger.id
        if first_task:
            try:
                task_markdown = Path(first_task.task_md_path).read_text(encoding="utf-8")
            except FileNotFoundError:
                task_markdown = ""
            task_metadata = dict(first_task.metadata or {})
            for item in task_metadata.get("artifact_refs") or []:
                if isinstance(item, dict):
                    artifact_refs.append(ArtifactRef.model_validate(item))
            runtime_overrides = dict(task_metadata.get("runtime_overrides") or {})
        attempts = []
        history_service = get_history_run_service()
        for item in self._list_executions_for_trigger(db, trigger.id):
            history_run = history_service.get_history_run_by_execution(db, item) if item.workspace_root else None
            attempts.append(self._attempt_response(item, history_run_id=history_run.id if history_run else None))
        return ScanTaskDetailResponse(
            **response.model_dump(),
            title=title,
            task_markdown=task_markdown,
            artifact_refs=artifact_refs,
            runtime_overrides=runtime_overrides,
            task_metadata=task_metadata,
            attempts=attempts,
        )

    def _attempt_response(self, execution: WorkflowExecution, history_run_id: str | None = None) -> ScanTaskAttemptResponse:
        return ScanTaskAttemptResponse(
            execution_id=execution.id,
            task_id=execution.trigger_task_id,
            attempt_no=execution.attempt_no,
            status=execution.status,
            history_run_id=history_run_id,
            owner_pod_id=execution.owner_pod_id,
            lease_expires_at=execution.lease_expires_at,
            started_at=execution.started_at,
            finished_at=execution.finished_at,
            recovery_reason=execution.recovery_reason,
            message=execution.message,
            workspace_root=execution.workspace_root,
            output_manifest_path=execution.output_manifest_path,
            output_task_count=execution.output_task_count,
            created_at=execution.created_at,
            updated_at=execution.updated_at,
        )

    def _build_workspace_root(self, execution_id: str, definition: WorkflowDefinition) -> Path:
        base_dir = definition.workspace_base_dir or get_config().service.workspace_base_dir
        return ensure_dir(Path(base_dir) / execution_id)

    def _copy_uploaded_inputs_to_task_dir(self, *, task_input_dir: Path, metadata: Dict[str, Any]) -> List[Dict[str, str]]:
        uploads = metadata.get("task_input_uploads")
        if not isinstance(uploads, list) or not uploads:
            return []
        copied: List[Dict[str, str]] = []
        data_mount_path = Path(get_config().fileserver_service.data_mount_path)
        assets_dir = ensure_dir(task_input_dir / get_config().service.default_artifact_subdir)

        for item in uploads:
            if not isinstance(item, dict):
                continue
            storage_key = str(item.get("storage_key") or "").strip()
            if not storage_key:
                continue
            relative_path_raw = str(item.get("relative_path") or item.get("filename") or "").strip()
            if not relative_path_raw:
                continue
            relative_path = Path(relative_path_raw)
            if relative_path.is_absolute() or ".." in relative_path.parts:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"invalid uploaded relative path: {relative_path_raw}",
                )
            storage_path = Path(storage_key)
            if storage_path.is_absolute() or ".." in storage_path.parts:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"invalid uploaded storage key: {storage_key}",
                )
            source_path = data_mount_path / storage_path
            if not source_path.exists() or not source_path.is_file():
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"uploaded file not found in pvc: {storage_key}",
                )
            target_path = assets_dir / relative_path
            ensure_dir(target_path.parent)
            shutil.copy2(source_path, target_path)
            copied.append(
                {
                    "relative_path": relative_path.as_posix(),
                    "target_path": abs_path(target_path),
                    "source_storage_key": storage_key,
                }
            )
        if copied:
            write_json(task_input_dir / "uploaded_assets_manifest.json", {"items": copied})
        return copied

    def _normalize_project_path(self, raw_path: str) -> str:
        raw = str(raw_path or "").strip() or "/"
        if any(part == ".." for part in raw.split("/")):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="project path escapes project root")
        normalized = posixpath.normpath(raw)
        if not normalized.startswith("/"):
            normalized = f"/{normalized}"
        if normalized.startswith("/../") or normalized == "/..":
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="project path escapes project root")
        return normalized

    def _ensure_path_within(self, *, path: Path, root: Path, label: str) -> Path:
        resolved = path.resolve()
        root_resolved = root.resolve()
        try:
            resolved.relative_to(root_resolved)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{label} escapes allowed root") from exc
        return resolved

    def _project_files_root(self, project_id: str) -> Path:
        config = get_config()
        data_mount_path = Path(config.fileserver_service.data_mount_path).resolve()
        project_root = data_mount_path / config.fileserver_service.project_files_dirname / sanitize_name(project_id)
        return self._ensure_path_within(path=project_root, root=data_mount_path, label="project_root")

    def _build_project_filesystem_entry(self, *, project_root: Path, candidate: Path) -> dict[str, Any]:
        resolved = self._ensure_path_within(path=candidate, root=project_root, label="project filesystem path")
        stat = resolved.stat()
        relative = resolved.relative_to(project_root).as_posix()
        depth = 0 if not relative else len(relative.split("/"))
        is_dir = resolved.is_dir()
        node_type = "file"
        if is_dir:
            node_type = "subproject" if depth == 1 else "directory"
        has_children = False
        if is_dir:
            try:
                next(resolved.iterdir())
                has_children = True
            except StopIteration:
                has_children = False
        return {
            "node_type": node_type,
            "name": resolved.name,
            "path": f"/{relative}" if relative else "/",
            "content_type": None,
            "size": stat.st_size if resolved.is_file() else None,
            "updated_at": datetime.utcfromtimestamp(stat.st_mtime).isoformat() + "Z",
            "has_children": has_children,
            "special_badge": None,
        }

    def _list_project_filesystem_entries(self, *, project_root: Path, current_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        directories: list[dict[str, Any]] = []
        files: list[dict[str, Any]] = []
        if not current_dir.exists():
            return directories, files
        for child in sorted(current_dir.iterdir(), key=lambda item: (not item.is_dir(), item.name.lower())):
            entry = self._build_project_filesystem_entry(project_root=project_root, candidate=child)
            if entry["node_type"] == "file":
                files.append(entry)
            else:
                directories.append(entry)
        return directories, files

    def get_project_filesystem_root(self, principal: dict, project_id: str) -> dict[str, Any]:
        self._ensure_project_access(principal, project_id)
        project_root = self._project_files_root(project_id)
        directories, files = self._list_project_filesystem_entries(project_root=project_root, current_dir=project_root)
        items = directories + files
        return {
            "project_id": project_id,
            "root_name": project_id,
            "total": len(items),
            "items": items,
        }

    def get_project_filesystem_children(self, principal: dict, project_id: str, path: str) -> dict[str, Any]:
        self._ensure_project_access(principal, project_id)
        project_root = self._project_files_root(project_id)
        normalized = self._normalize_project_path(path)
        current_dir = project_root if normalized == "/" else self._ensure_path_within(
            path=project_root / normalized.lstrip("/"),
            root=project_root,
            label="project filesystem path",
        )
        if not current_dir.exists():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"path not found: {normalized}")
        if not current_dir.is_dir():
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="path must be a directory")

        directories, files = self._list_project_filesystem_entries(project_root=project_root, current_dir=current_dir)
        breadcrumbs = [{"node_type": "project", "name": project_id, "path": "/"}]
        if normalized != "/":
            parts = [part for part in normalized.split("/") if part]
            assembled: list[str] = []
            for index, part in enumerate(parts):
                assembled.append(part)
                breadcrumbs.append(
                    {
                        "node_type": "subproject" if index == 0 else "directory",
                        "name": part,
                        "path": f"/{'/'.join(assembled)}",
                    }
                )

        return {
            "project_id": project_id,
            "current_path": normalized,
            "current_name": project_id if normalized == "/" else current_dir.name,
            "breadcrumbs": breadcrumbs,
            "directories": directories,
            "files": files,
        }

    def _resolve_dataflow_input_ref(self, *, project_id: str, ref: dict[str, Any], expected: str) -> Path:
        source = str(ref.get("source") or "project_filesystem").strip()
        data_mount_path = Path(get_config().fileserver_service.data_mount_path)
        if source in {"project_filesystem", "project_path", "project"}:
            project_root = self._project_files_root(project_id)
            normalized = self._normalize_project_path(str(ref.get("path") or ""))
            candidate = project_root / normalized.lstrip("/")
            resolved = self._ensure_path_within(path=candidate, root=project_root, label=expected)
        elif source in {"fileserver_storage", "storage_key", "managed_file"}:
            storage_key = str(ref.get("storage_key") or ref.get("path") or "").strip()
            if not storage_key:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{expected} storage_key is required")
            storage_path = Path(storage_key)
            if storage_path.is_absolute() or ".." in storage_path.parts:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"invalid {expected} storage_key")
            resolved = self._ensure_path_within(path=data_mount_path / storage_path, root=data_mount_path, label=expected)
        elif source in {"absolute", "absolute_path", "local_path"}:
            raw = str(ref.get("path") or "").strip()
            if not raw:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{expected} path is required")
            candidate = Path(raw)
            if not candidate.is_absolute():
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{expected} absolute path is required")
            resolved = candidate.resolve()
        else:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"unsupported {expected} source: {source}")
        if not resolved.exists():
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{expected} not found: {resolved}")
        return resolved

    def _copy_ref_to_target(self, *, source_path: Path, target_path: Path, expected: str) -> None:
        if expected == "file":
            if not source_path.is_file():
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"expected file but got: {source_path}")
            ensure_dir(target_path.parent)
            shutil.copy2(source_path, target_path)
            return
        if not source_path.is_dir():
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"expected directory but got: {source_path}")
        ensure_dir(target_path)
        shutil.copytree(source_path, target_path, dirs_exist_ok=True)

    def _resolve_custom_execution_paths(
        self,
        *,
        project_id: str,
        metadata: Dict[str, Any],
        execution_id: str,
    ) -> tuple[Path | None, Path | None]:
        request = metadata.get("dataflow_scan_request")
        if not isinstance(request, dict):
            return None, None

        workspace_ref = request.get("workspace_dir")
        output_ref = request.get("output_dir")
        if workspace_ref is None and output_ref is None:
            return None, None
        if workspace_ref is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="workspace_dir is required when output_dir is provided",
            )
        if not isinstance(workspace_ref, dict):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="workspace_dir must be a valid directory ref")
        if output_ref is not None and not isinstance(output_ref, dict):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="output_dir must be a valid directory ref")

        workspace_base = self._resolve_dataflow_input_ref(project_id=project_id, ref=workspace_ref, expected="workspace_dir")
        if not workspace_base.is_dir():
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"expected directory but got: {workspace_base}")

        workspace_base = workspace_base.resolve()
        output_relative = Path("output")
        if output_ref is not None:
            output_base = self._resolve_dataflow_input_ref(project_id=project_id, ref=output_ref, expected="output_dir")
            if not output_base.is_dir():
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"expected directory but got: {output_base}")
            output_base = output_base.resolve()
            try:
                output_relative = output_base.relative_to(workspace_base)
            except ValueError as exc:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="output_dir must be inside workspace_dir",
                ) from exc

        workspace_root = ensure_dir(workspace_base / sanitize_name(execution_id))
        output_dir = ensure_dir(workspace_root / output_relative)
        return workspace_root, output_dir

    def _default_dataflow_cli_runs_root(self, project_id: str) -> Path:
        config = get_config()
        return (
            Path(config.fileserver_service.data_mount_path)
            / config.fileserver_service.project_files_dirname
            / sanitize_name(project_id)
            / config.fileserver_service.aiwf_subproject_name
            / "runs"
        ).resolve()

    def _resolve_dataflow_cli_runs_root(self, *, project_id: str, request: dict[str, Any]) -> Path:
        workspace_ref = request.get("workspace_dir")
        if workspace_ref is None:
            return ensure_dir(self._default_dataflow_cli_runs_root(project_id)).resolve()
        if not isinstance(workspace_ref, dict):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="workspace_dir must be a valid directory ref")
        runs_root = self._resolve_dataflow_input_ref(project_id=project_id, ref=workspace_ref, expected="workspace_dir")
        if not runs_root.is_dir():
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"expected directory but got: {runs_root}")
        return runs_root.resolve()

    def _build_dataflow_cli_run_name(self, *, data_flow_path: Path, runs_root: Path, execution_id: str, requested_run_name: str | None = None) -> str:
        requested = str(requested_run_name or "").strip()
        if requested:
            base_name = sanitize_name(requested)
        else:
            base_name = f"{sanitize_name(data_flow_path.stem)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        run_name = base_name or f"dataflow_vuln_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        if not (runs_root / run_name).exists():
            return run_name
        fallback = f"{run_name}_{sanitize_name(execution_id)[-8:]}"
        if not (runs_root / fallback).exists():
            return fallback
        return f"{fallback}_{uuid.uuid4().hex[:6]}"

    def _build_dataflow_cli_plan(
        self,
        *,
        project_id: str,
        request: dict[str, Any],
        execution_id: str,
    ) -> dict[str, Any]:
        data_flow_ref = request.get("data_flow")
        source_dir_ref = request.get("source_dir")
        if not isinstance(data_flow_ref, dict) or not isinstance(source_dir_ref, dict):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="dataflow scan request is incomplete")
        if request.get("output_dir") is not None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="output_dir is not supported by run_vuln_scan.py launcher; choose workspace_dir/runs root instead",
            )
        data_flow_path = self._resolve_dataflow_input_ref(project_id=project_id, ref=data_flow_ref, expected="data_flow")
        if not data_flow_path.is_file():
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"expected file but got: {data_flow_path}")
        source_dir_path = self._resolve_dataflow_input_ref(project_id=project_id, ref=source_dir_ref, expected="source_dir")
        if not source_dir_path.is_dir():
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"expected directory but got: {source_dir_path}")
        runs_root = self._resolve_dataflow_cli_runs_root(project_id=project_id, request=request)
        options = request.get("options") if isinstance(request.get("options"), dict) else {}
        run_name = self._build_dataflow_cli_run_name(
            data_flow_path=data_flow_path,
            runs_root=runs_root,
            execution_id=execution_id,
            requested_run_name=options.get("run_name"),
        )
        run_dir = runs_root / run_name
        task_md_path = run_dir / "input" / "task.md"
        return {
            "launcher": "run_vuln_scan.py",
            "run_name": run_name,
            "runs_root": abs_path(runs_root),
            "run_dir": abs_path(run_dir),
            "task_md_path": abs_path(task_md_path),
            "data_flow_file": abs_path(data_flow_path),
            "source_dir": abs_path(source_dir_path),
        }

    def _write_dataflow_cli_task_preview(self, plan: dict[str, Any]) -> None:
        from run_vuln_scan import generate_task_md

        run_dir = Path(plan["run_dir"])
        task_md_path = Path(plan["task_md_path"])
        ensure_dir(task_md_path.parent)
        write_text(
            task_md_path,
            generate_task_md(plan["data_flow_file"], plan["source_dir"]).strip() + "\n",
        )
        ensure_dir(run_dir / "output")

    def _dataflow_cli_config_requires_file(self, *, request: dict[str, Any], runtime_overrides: dict[str, Any]) -> bool:
        if runtime_overrides:
            return True
        for key in ("worker_timeout", "advisor_timeout"):
            if request.get(key) is not None:
                return True
        return False

    def _build_dataflow_cli_argv(
        self,
        *,
        plan: dict[str, Any],
        config_payload: dict[str, Any],
        request: dict[str, Any],
        compiled_config: dict[str, Any],
        runtime_overrides: dict[str, Any],
    ) -> tuple[list[str], str | None]:
        argv = [
            "--data-flow",
            plan["data_flow_file"],
            "--source-dir",
            plan["source_dir"],
            "--runs-root",
            plan["runs_root"],
            "--run-name",
            plan["run_name"],
        ]
        temp_config_path: str | None = None
        if self._dataflow_cli_config_requires_file(request=request, runtime_overrides=runtime_overrides):
            fd, temp_config_path = tempfile.mkstemp(prefix="secflow-dataflow-cli-", suffix=".json")
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json_payload = compiled_config or {}
                import json

                json.dump(json_payload, handle, ensure_ascii=False, indent=2)
            argv.extend(["--config", temp_config_path])
            return argv, temp_config_path

        model = str(config_payload.get("model") or request.get("model") or "").strip()
        thinking = str(config_payload.get("thinking") or request.get("thinking") or "high").strip() or "high"
        review_profile = str(config_payload.get("review_profile") or request.get("review_profile") or "balanced").strip() or "balanced"
        max_cycles = int(config_payload.get("max_review_cycles") or request.get("max_review_cycles") or 0)
        result_review_concurrency = int(config_payload.get("result_review_concurrency") or request.get("result_review_concurrency") or 3)
        if model:
            argv.extend(["--model", model])
        if thinking:
            argv.extend(["--thinking", thinking])
        if max_cycles > 0:
            argv.extend(["--max-cycles", str(max_cycles)])
        argv.extend(["--result-review-concurrency", str(max(result_review_concurrency, 1))])
        argv.extend(["--review-profile", review_profile])
        return argv, temp_config_path

    def _is_dataflow_cli_task_metadata(self, metadata: dict[str, Any]) -> bool:
        request = metadata.get("dataflow_scan_request")
        return isinstance(request, dict) and request.get("launcher") == "run_vuln_scan.py"

    def _update_trigger_cli_task(
        self,
        *,
        trigger: TriggerTask,
        metadata: dict[str, Any],
        task_md_path: str,
    ) -> None:
        manifest = TaskManifest.model_validate(trigger.input_tasks_json)
        if not manifest.tasks:
            return
        task = manifest.tasks[0]
        task.metadata = metadata
        task.task_md_path = task_md_path
        trigger.input_tasks_json = TaskManifest(tasks=[task, *manifest.tasks[1:]]).model_dump(mode="json")

    def _materialize_dataflow_scan_inputs(self, *, task_input_dir: Path, metadata: Dict[str, Any]) -> tuple[str | None, Dict[str, Any]]:
        request = metadata.get("dataflow_scan_request")
        if not isinstance(request, dict):
            return None, {}
        project_id = str(request.get("project_id") or "").strip()
        data_flow_ref = request.get("data_flow")
        source_dir_ref = request.get("source_dir")
        workspace_ref = request.get("workspace_dir")
        output_ref = request.get("output_dir")
        if not project_id or not isinstance(data_flow_ref, dict) or not isinstance(source_dir_ref, dict):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="dataflow scan request is incomplete")

        source_data_flow = self._resolve_dataflow_input_ref(project_id=project_id, ref=data_flow_ref, expected="data_flow")
        source_source_dir = self._resolve_dataflow_input_ref(project_id=project_id, ref=source_dir_ref, expected="source_dir")
        workspace_base = None
        output_base = None
        if workspace_ref is not None:
            if not isinstance(workspace_ref, dict):
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="workspace_dir ref is invalid")
            workspace_base = self._resolve_dataflow_input_ref(project_id=project_id, ref=workspace_ref, expected="workspace_dir")
            if not workspace_base.is_dir():
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"expected directory but got: {workspace_base}")
        if output_ref is not None:
            if not isinstance(output_ref, dict):
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="output_dir ref is invalid")
            output_base = self._resolve_dataflow_input_ref(project_id=project_id, ref=output_ref, expected="output_dir")
            if not output_base.is_dir():
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"expected directory but got: {output_base}")
        if workspace_base is not None and output_base is not None:
            self._ensure_path_within(path=output_base, root=workspace_base, label="output_dir")
        effective_output_base = output_base
        if workspace_base is not None and effective_output_base is None:
            effective_output_base = workspace_base / "output"
        scan_input_dir = ensure_dir(task_input_dir / "dataflow_scan")
        data_flow_name = sanitize_name(str(data_flow_ref.get("filename") or source_data_flow.name or "data_flow.md"))
        data_flow_target = scan_input_dir / "data_flow" / data_flow_name
        source_target = scan_input_dir / "source"
        self._copy_ref_to_target(source_path=source_data_flow, target_path=data_flow_target, expected="file")
        self._copy_ref_to_target(source_path=source_source_dir, target_path=source_target, expected="directory")

        from run_vuln_scan import generate_task_md

        generated_markdown = generate_task_md(abs_path(data_flow_target), abs_path(source_target))
        materialized = {
            "data_flow_file": abs_path(data_flow_target),
            "source_dir": abs_path(source_target),
            "original_data_flow": data_flow_ref,
            "original_source_dir": source_dir_ref,
            "options": request.get("options") or {},
        }
        if workspace_base is not None:
            materialized["workspace_dir"] = abs_path(workspace_base)
            materialized["original_workspace_dir"] = workspace_ref
        if effective_output_base is not None:
            materialized["output_dir"] = abs_path(effective_output_base)
        if output_base is not None:
            materialized["original_output_dir"] = output_ref
        elif workspace_base is not None:
            materialized["output_dir_mode"] = "auto_workspace_output"
        write_json(scan_input_dir / "input_manifest.json", materialized)
        return generated_markdown, materialized

    def _normalize_trigger_tasks(
        self,
        *,
        input_tasks: List[TriggerTaskInputTask],
        workspace_root: Path,
        entry_input_task_type: str,
    ) -> List[TaskItem]:
        task_inputs_root = ensure_dir(workspace_root / "trigger_inputs")
        normalized: List[TaskItem] = []
        if not input_tasks:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="input_tasks must not be empty")
        for index, raw_task in enumerate(input_tasks, start=1):
            provided_task_type = (raw_task.task_type or "").strip()
            if provided_task_type and provided_task_type != entry_input_task_type:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=(
                        f"task {raw_task.task_id or index} task_type '{provided_task_type}' "
                        f"does not match entry_input_task_type '{entry_input_task_type}'"
                    ),
                )
            task_id = raw_task.task_id or _new_id(f"task{index}")
            task_slug = sanitize_name(task_id)
            task_dir = ensure_dir(task_inputs_root / task_slug)
            input_dir = ensure_dir(task_dir / "input")
            metadata = dict(raw_task.metadata or {})
            markdown = raw_task.task_markdown
            if markdown is None and raw_task.task_md_path:
                markdown = Path(raw_task.task_md_path).read_text(encoding="utf-8")
            generated_markdown, materialized_inputs = self._materialize_dataflow_scan_inputs(
                task_input_dir=input_dir,
                metadata=metadata,
            )
            if generated_markdown:
                markdown = generated_markdown
                metadata["dataflow_scan_materialized"] = materialized_inputs
            if markdown is None:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"task {task_id} missing task_markdown",
                )
            task_md_path = write_text(input_dir / "task.md", markdown.strip() + "\n")
            copied_inputs = self._copy_uploaded_inputs_to_task_dir(task_input_dir=input_dir, metadata=metadata)
            write_json(
                input_dir / "task.json",
                {
                    "task_id": task_id,
                    "task_type": entry_input_task_type,
                    "title": raw_task.title,
                    "metadata": metadata,
                    "upstream_refs": raw_task.upstream_refs,
                    "copied_input_files": copied_inputs,
                },
            )
            normalized.append(
                TaskItem(
                    task_id=task_id,
                    task_type=entry_input_task_type,
                    title=raw_task.title,
                    task_md_path=abs_path(task_md_path),
                    metadata=metadata,
                    upstream_refs=list(raw_task.upstream_refs),
                )
            )
        return normalized

    def _prepare_single_task_entry_file(self, *, workspace_root: Path, manifest: TaskManifest) -> str | None:
        if len(manifest.tasks) != 1:
            return None
        task = manifest.tasks[0]
        markdown_path = str(task.task_md_path or "").strip()
        if not markdown_path:
            return None
        try:
            markdown = Path(markdown_path).read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        if not markdown.strip():
            return None
        task_file = write_text(workspace_root / "input" / "task.md", markdown.strip() + "\n")
        return abs_path(task_file)

    def _build_project_workspace_root(
        self,
        *,
        definition: WorkflowDefinition,
        trigger_id: str,
        execution_id: str,
        authorization_token: str | None,
        created_by: str,
    ) -> Path:
        subproject = get_fileserver_client().ensure_subproject(
            project_id=definition.project_id,
            authorization_token=authorization_token,
            created_by=created_by,
        )
        base_root = Path(subproject["root_dir"])
        return ensure_dir(
            base_root
            / "scan-profiles"
            / sanitize_name(definition.id)
            / "tasks"
            / sanitize_name(trigger_id)
            / "executions"
            / sanitize_name(execution_id)
        )

    def _artifact_uploads_from_refs(self, artifact_refs: list[ArtifactRef]) -> list[dict[str, Any]]:
        return [
            {
                "storage_key": item.storage_key,
                "relative_path": item.relative_path,
                "filename": item.filename,
                "metadata": item.metadata,
            }
            for item in artifact_refs
        ]

    def _input_tasks_from_manifest(self, manifest: TaskManifest) -> list[TriggerTaskInputTask]:
        items: list[TriggerTaskInputTask] = []
        for item in manifest.tasks:
            items.append(
                TriggerTaskInputTask(
                    task_id=item.task_id,
                    task_type=item.task_type,
                    title=item.title,
                    task_md_path=item.task_md_path,
                    metadata=dict(item.metadata),
                    upstream_refs=list(item.upstream_refs),
                )
            )
        return items

    def _set_terminal_state(
        self,
        db: Session,
        *,
        execution: WorkflowExecution,
        trigger: TriggerTask,
        execution_status: str,
        message: str,
        output_manifest_path: str | None = None,
        output_task_count: int = 0,
    ) -> None:
        now = datetime.utcnow()
        execution.status = execution_status
        execution.message = message
        execution.finished_at = now
        execution.output_manifest_path = output_manifest_path
        execution.output_task_count = output_task_count
        execution.lease_expires_at = now
        execution.current_stage_id = None
        trigger.status = execution_status
        trigger.message = message
        trigger.finished_at = now
        if trigger.started_at is None:
            trigger.started_at = execution.started_at or now
        db.add(execution)
        db.add(trigger)

    def _create_execution_attempt(
        self,
        db: Session,
        *,
        trigger: TriggerTask,
        definition: WorkflowDefinition,
        definition_version: WorkflowDefinitionVersion,
        actor: str,
        authorization_token: str | None,
        recovery_reason: str | None = None,
    ) -> WorkflowExecution:
        compiled_config = definition_version.compiled_config_json or definition_version.definition_json or definition.definition_json
        validated_definition = get_workflow_service().validate_definition_payload(compiled_config)
        next_attempt_no = (
            db.query(WorkflowExecution)
            .filter(WorkflowExecution.trigger_task_id == trigger.id)
            .count()
        ) + 1
        execution_id = _new_id("exec")
        manifest = TaskManifest.model_validate(trigger.input_tasks_json)
        raw_input_tasks = self._input_tasks_from_manifest(manifest)
        primary_metadata = dict(raw_input_tasks[0].metadata or {}) if raw_input_tasks else {}
        workspace_root, _ = self._resolve_custom_execution_paths(
            project_id=definition.project_id,
            metadata=primary_metadata,
            execution_id=execution_id,
        )
        if workspace_root is None:
            workspace_root = self._build_project_workspace_root(
                definition=definition,
                trigger_id=trigger.id,
                execution_id=execution_id,
                authorization_token=authorization_token,
                created_by=actor,
            )
        normalized_tasks = self._normalize_trigger_tasks(
            input_tasks=raw_input_tasks,
            workspace_root=workspace_root,
            entry_input_task_type=validated_definition.resolve_entry_input_task_type(),
        )
        input_manifest_path = write_task_manifest(workspace_root / "input" / "tasks.json", normalized_tasks)
        write_json(
            workspace_root / "execution_meta.json",
            {
                "workflow_definition_id": definition.id,
                "workflow_definition_version_id": definition_version.id,
                "project_id": definition.project_id,
                "trigger_id": trigger.id,
                "execution_id": execution_id,
                "attempt_no": next_attempt_no,
                "trigger_type": trigger.trigger_type,
                "entry_input_task_type": validated_definition.resolve_entry_input_task_type(),
                "workspace_root": abs_path(workspace_root),
                "input_manifest_path": abs_path(input_manifest_path),
                "recovery_reason": recovery_reason,
            },
        )
        trigger.input_tasks_json = TaskManifest(tasks=normalized_tasks).model_dump(mode="json")
        trigger.status = "pending"
        trigger.latest_execution_id = execution_id
        trigger.workflow_definition_version_id = definition_version.id
        trigger.profile_id = definition.id
        trigger.finished_at = None
        trigger.message = "pending dispatch" if not recovery_reason else f"pending dispatch: {recovery_reason}"
        execution = WorkflowExecution(
            id=execution_id,
            trigger_task_id=trigger.id,
            workflow_definition_id=definition.id,
            workflow_definition_version_id=definition_version.id,
            project_id=definition.project_id,
            attempt_no=next_attempt_no,
            status="pending",
            recovery_reason=recovery_reason,
            workspace_root=abs_path(workspace_root),
            message="pending dispatch" if not recovery_reason else f"pending dispatch: {recovery_reason}",
        )
        db.add(trigger)
        db.add(execution)
        db.flush()
        return execution

    def _create_task_record(
        self,
        db: Session,
        *,
        definition: WorkflowDefinition,
        definition_version: WorkflowDefinitionVersion,
        input_tasks: List[TriggerTaskInputTask],
        priority: int,
        trigger_type: str,
        actor: str,
        authorization_token: str | None,
    ) -> tuple[TriggerTask, WorkflowExecution]:
        trigger = TriggerTask(
            id=_new_id("tt"),
            workflow_definition_id=definition.id,
            workflow_definition_version_id=definition_version.id,
            profile_id=definition.id,
            project_id=definition.project_id,
            trigger_type=trigger_type,
            input_tasks_json=TaskManifest(tasks=[]).model_dump(mode="json"),
            priority=priority,
            status="pending",
            submitted_by=actor,
            retry_count=0,
            max_retry_count=definition.max_retry_count,
            latest_execution_id=None,
            message="pending dispatch",
        )
        db.add(trigger)
        db.flush()
        compiled_config = definition_version.compiled_config_json or definition_version.definition_json or definition.definition_json
        validated_definition = get_workflow_service().validate_definition_payload(compiled_config)
        workspace_root = self._build_project_workspace_root(
            definition=definition,
            trigger_id=trigger.id,
            execution_id="bootstrap",
            authorization_token=authorization_token,
            created_by=actor,
        ).parent / "bootstrap"
        normalized_tasks = self._normalize_trigger_tasks(
            input_tasks=input_tasks,
            workspace_root=workspace_root,
            entry_input_task_type=validated_definition.resolve_entry_input_task_type(),
        )
        trigger.input_tasks_json = TaskManifest(tasks=normalized_tasks).model_dump(mode="json")
        db.add(trigger)
        execution = self._create_execution_attempt(
            db,
            trigger=trigger,
            definition=definition,
            definition_version=definition_version,
            actor=actor,
            authorization_token=authorization_token,
        )
        return trigger, execution

    def _create_dataflow_cli_execution_attempt(
        self,
        db: Session,
        *,
        trigger: TriggerTask,
        definition: WorkflowDefinition,
        definition_version: WorkflowDefinitionVersion,
        actor: str,
        recovery_reason: str | None = None,
    ) -> WorkflowExecution:
        manifest = TaskManifest.model_validate(trigger.input_tasks_json)
        if not manifest.tasks:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="input_tasks must not be empty")
        task = manifest.tasks[0]
        metadata = dict(task.metadata or {})
        request = metadata.get("dataflow_scan_request")
        if not isinstance(request, dict):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="dataflow scan request is incomplete")
        execution_id = _new_id("exec")
        next_attempt_no = (
            db.query(WorkflowExecution)
            .filter(WorkflowExecution.trigger_task_id == trigger.id)
            .count()
        ) + 1
        plan = self._build_dataflow_cli_plan(
            project_id=definition.project_id,
            request=request,
            execution_id=execution_id,
        )
        metadata["dataflow_cli"] = plan
        self._write_dataflow_cli_task_preview(plan)
        task.task_md_path = plan["task_md_path"]
        task.metadata = metadata
        trigger.input_tasks_json = TaskManifest(tasks=[task, *manifest.tasks[1:]]).model_dump(mode="json")
        trigger.status = "pending"
        trigger.latest_execution_id = execution_id
        trigger.workflow_definition_version_id = definition_version.id
        trigger.profile_id = definition.id
        trigger.finished_at = None
        trigger.message = "pending dispatch" if not recovery_reason else f"pending dispatch: {recovery_reason}"
        execution = WorkflowExecution(
            id=execution_id,
            trigger_task_id=trigger.id,
            workflow_definition_id=definition.id,
            workflow_definition_version_id=definition_version.id,
            project_id=definition.project_id,
            attempt_no=next_attempt_no,
            status="pending",
            recovery_reason=recovery_reason,
            workspace_root=plan["run_dir"],
            message="pending dispatch" if not recovery_reason else f"pending dispatch: {recovery_reason}",
        )
        db.add(trigger)
        db.add(execution)
        db.flush()
        return execution

    def _create_dataflow_cli_task_record(
        self,
        db: Session,
        *,
        definition: WorkflowDefinition,
        definition_version: WorkflowDefinitionVersion,
        payload: ScanTaskCreateRequest,
        metadata: dict[str, Any],
        priority: int,
        actor: str,
    ) -> tuple[TriggerTask, WorkflowExecution]:
        trigger = TriggerTask(
            id=_new_id("tt"),
            workflow_definition_id=definition.id,
            workflow_definition_version_id=definition_version.id,
            profile_id=definition.id,
            project_id=definition.project_id,
            trigger_type="manual",
            input_tasks_json=TaskManifest(tasks=[]).model_dump(mode="json"),
            priority=priority,
            status="pending",
            submitted_by=actor,
            retry_count=0,
            max_retry_count=definition.max_retry_count,
            latest_execution_id=None,
            message="pending dispatch",
        )
        db.add(trigger)
        db.flush()
        trigger.input_tasks_json = TaskManifest(
            tasks=[
                TaskItem(
                    task_id=_new_id("task"),
                    task_type="dataflow_vuln_scan_cli",
                    title=payload.title,
                    task_md_path=abs_path(self._default_dataflow_cli_runs_root(definition.project_id) / "_pending" / trigger.id / "task.md"),
                    metadata=metadata,
                    upstream_refs=[],
                )
            ]
        ).model_dump(mode="json")
        execution = self._create_dataflow_cli_execution_attempt(
            db,
            trigger=trigger,
            definition=definition,
            definition_version=definition_version,
            actor=actor,
        )
        return trigger, execution

    def create_scan_task(
        self,
        db: Session,
        payload: ScanTaskCreateRequest,
        principal: dict,
        *,
        authorization_token: str | None = None,
    ) -> ScanTaskResponse:
        self._ensure_project_access(principal, payload.project_id)
        workflow_service = get_workflow_service()
        definition = (
            workflow_service.get_or_create_default_profile_model(db, payload.project_id, principal)
            if not payload.profile_id
            else workflow_service._get_definition_or_404(db, payload.profile_id)
        )
        self._ensure_project_access(principal, definition.project_id)
        actor = _principal_id(principal)
        config_payload_overrides = {
            "model": payload.model,
            "thinking": payload.thinking,
            "review_profile": payload.review_profile,
            "max_review_cycles": payload.max_review_cycles,
            "worker_timeout": payload.worker_timeout,
            "advisor_timeout": payload.advisor_timeout,
            "result_review_concurrency": payload.result_review_concurrency,
        }
        if payload.provider and payload.model and "/" not in payload.model:
            config_payload_overrides["model"] = f"{payload.provider}/{payload.model}"
        definition_version = workflow_service.build_task_bound_version(
            db,
            definition=definition,
            principal=principal,
            runtime_overrides=payload.runtime_overrides,
            config_payload_overrides={key: value for key, value in config_payload_overrides.items() if value is not None},
        )
        metadata = {
            "artifact_refs": [item.model_dump(mode="json") for item in payload.artifact_refs],
            "task_input_uploads": self._artifact_uploads_from_refs(payload.artifact_refs),
            "runtime_overrides": payload.runtime_overrides,
            "task_title": payload.title,
        }
        if payload.data_flow and payload.source_dir:
            metadata["dataflow_scan_request"] = {
                "launcher": "run_vuln_scan.py",
                "project_id": payload.project_id,
                "workspace_dir": payload.workspace_dir.model_dump(mode="json") if payload.workspace_dir else None,
                "data_flow": payload.data_flow.model_dump(mode="json"),
                "source_dir": payload.source_dir.model_dump(mode="json"),
                "output_dir": payload.output_dir.model_dump(mode="json") if payload.output_dir else None,
                "model": payload.model,
                "provider": payload.provider,
                "thinking": payload.thinking,
                "review_profile": payload.review_profile,
                "max_review_cycles": payload.max_review_cycles,
                "worker_timeout": payload.worker_timeout,
                "advisor_timeout": payload.advisor_timeout,
                "result_review_concurrency": payload.result_review_concurrency,
                "options": payload.scan_options,
            }
        if payload.data_flow and payload.source_dir:
            trigger, _ = self._create_dataflow_cli_task_record(
                db,
                definition=definition,
                definition_version=definition_version,
                payload=payload,
                metadata=metadata,
                priority=payload.priority if payload.priority is not None else definition.priority_default,
                actor=actor,
            )
        else:
            trigger, _ = self._create_task_record(
                db,
                definition=definition,
                definition_version=definition_version,
                input_tasks=[
                    TriggerTaskInputTask(
                        task_id=_new_id("task"),
                        title=payload.title,
                        task_markdown=payload.task_markdown,
                        metadata=metadata,
                        upstream_refs=[],
                    )
                ],
                priority=payload.priority if payload.priority is not None else definition.priority_default,
                trigger_type="manual",
                actor=actor,
                authorization_token=authorization_token,
            )
        db.commit()
        db.refresh(trigger)
        latest_execution = self._latest_execution_for_trigger(db, trigger.id)
        if latest_execution is not None:
            self.record_event(
                db,
                execution_id=latest_execution.id,
                event_type="execution_queued",
                message="task queued",
                payload_json={"task_id": trigger.id, "attempt_no": latest_execution.attempt_no},
            )
        return self._scan_task_response(db, trigger)

    def list_scan_tasks(
        self,
        db: Session,
        principal: dict,
        *,
        project_id: str | None = None,
        status_filter: str | None = None,
        profile_id: str | None = None,
    ) -> List[ScanTaskResponse]:
        project_ids = _project_ids(principal)
        query = db.query(TriggerTask).order_by(TriggerTask.created_at.desc())
        if project_id:
            self._ensure_project_access(principal, project_id)
            query = query.filter(TriggerTask.project_id == project_id)
        elif project_ids:
            query = query.filter(TriggerTask.project_id.in_(project_ids))
        if status_filter:
            query = query.filter(TriggerTask.status == status_filter)
        if profile_id:
            query = query.filter(TriggerTask.profile_id == profile_id)
        return [self._scan_task_response(db, item) for item in query.all()]

    def get_scan_task(self, db: Session, task_id: str, principal: dict) -> ScanTaskDetailResponse:
        trigger = self._trigger_or_404(db, task_id)
        self._ensure_project_access(principal, trigger.project_id)
        return self._scan_task_detail(db, trigger)

    def list_scan_task_attempts(self, db: Session, task_id: str, principal: dict) -> List[ScanTaskAttemptResponse]:
        trigger = self._trigger_or_404(db, task_id)
        self._ensure_project_access(principal, trigger.project_id)
        history_service = get_history_run_service()
        responses: list[ScanTaskAttemptResponse] = []
        for item in self._list_executions_for_trigger(db, task_id):
            history_run = history_service.get_history_run_by_execution(db, item) if item.workspace_root else None
            responses.append(self._attempt_response(item, history_run_id=history_run.id if history_run else None))
        return responses

    def list_scan_task_events(self, db: Session, task_id: str, principal: dict) -> List[ScanTaskEventResponse]:
        trigger = self._trigger_or_404(db, task_id)
        self._ensure_project_access(principal, trigger.project_id)
        executions = self._list_executions_for_trigger(db, task_id)
        attempt_by_execution = {item.id: item.attempt_no for item in executions}
        events = (
            db.query(WorkflowExecutionEvent)
            .filter(WorkflowExecutionEvent.execution_id.in_(list(attempt_by_execution.keys()) or [""]))
            .order_by(WorkflowExecutionEvent.created_at.asc())
            .all()
        )
        return [
            ScanTaskEventResponse(
                event_id=item.id,
                execution_id=item.execution_id,
                attempt_no=attempt_by_execution.get(item.execution_id, 0),
                event_type=item.event_type,
                stage_id=item.stage_id,
                round_no=item.round_no,
                level=item.level,
                message=item.message,
                payload_json=item.payload_json or {},
                created_at=item.created_at,
            )
            for item in events
        ]

    def get_scan_task_artifacts(self, db: Session, task_id: str, principal: dict) -> ScanTaskArtifactsResponse:
        trigger = self._trigger_or_404(db, task_id)
        self._ensure_project_access(principal, trigger.project_id)
        latest_execution = self._latest_execution_for_trigger(db, task_id)
        files: list[ScanTaskArtifactFileResponse] = []
        workspace_root = Path(latest_execution.workspace_root) if latest_execution and latest_execution.workspace_root else None
        if workspace_root and workspace_root.exists():
            for path in sorted(p for p in workspace_root.rglob("*") if p.is_file()):
                files.append(
                    ScanTaskArtifactFileResponse(
                        path=str(path.relative_to(workspace_root)),
                        size=path.stat().st_size,
                    )
                )
        return ScanTaskArtifactsResponse(
            task_id=task_id,
            execution_id=latest_execution.id if latest_execution else None,
            workspace_root=latest_execution.workspace_root if latest_execution else None,
            output_manifest_path=latest_execution.output_manifest_path if latest_execution else None,
            files=files,
        )

    def _execution_for_task_or_404(self, db: Session, task_id: str, execution_id: str, principal: dict) -> WorkflowExecution:
        trigger = self._trigger_or_404(db, task_id)
        self._ensure_project_access(principal, trigger.project_id)
        execution = self._execution_or_404(db, execution_id)
        if execution.trigger_task_id != task_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="run not found for task")
        return execution

    def list_scan_task_runs(self, db: Session, task_id: str, principal: dict) -> list[dict[str, Any]]:
        trigger = self._trigger_or_404(db, task_id)
        self._ensure_project_access(principal, trigger.project_id)
        history_service = get_history_run_service()
        runs: list[dict[str, Any]] = []
        for execution in self._list_executions_for_trigger(db, task_id):
            history_run = history_service.get_history_run_by_execution(db, execution) if execution.workspace_root else None
            summary = history_service.get_history_run_summary(db, history_run) if history_run else {}
            attempt = self._attempt_response(execution, history_run_id=history_run.id if history_run else None).model_dump(mode="json")
            runs.append({**attempt, "run_summary": summary})
        return runs

    def get_scan_task_run(self, db: Session, task_id: str, execution_id: str, principal: dict) -> dict[str, Any]:
        execution = self._execution_for_task_or_404(db, task_id, execution_id, principal)
        history_service = get_history_run_service()
        history_run = history_service.get_history_run_by_execution(db, execution) if execution.workspace_root else None
        if not execution.workspace_root:
            return {"execution": self._attempt_response(execution, history_run_id=history_run.id if history_run else None).model_dump(mode="json"), "detail": None}
        return {
            "execution": self._attempt_response(execution, history_run_id=history_run.id if history_run else None).model_dump(mode="json"),
            "detail": history_service.get_history_run_detail(db, history_run) if history_run else None,
        }

    def get_scan_task_run_cycle(self, db: Session, task_id: str, execution_id: str, cycle: int, principal: dict) -> dict[str, Any]:
        execution = self._execution_for_task_or_404(db, task_id, execution_id, principal)
        history_run = get_history_run_service().get_history_run_by_execution(db, execution) if execution.workspace_root else None
        if history_run is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="run workspace not found")
        return get_history_run_service().get_history_run_cycle(db, history_run, cycle)

    def list_scan_task_run_sessions(self, db: Session, task_id: str, execution_id: str, principal: dict) -> list[dict[str, Any]]:
        execution = self._execution_for_task_or_404(db, task_id, execution_id, principal)
        history_run = get_history_run_service().get_history_run_by_execution(db, execution) if execution.workspace_root else None
        return get_history_run_service().list_history_run_sessions(db, history_run) if history_run else []

    def list_scan_task_run_files(self, db: Session, task_id: str, execution_id: str, principal: dict, limit: int = 1200) -> list[dict[str, Any]]:
        execution = self._execution_for_task_or_404(db, task_id, execution_id, principal)
        history_run = get_history_run_service().get_history_run_by_execution(db, execution) if execution.workspace_root else None
        if history_run is None:
            return []
        return get_history_run_service().list_history_run_files(db, history_run, limit=limit)

    def get_scan_task_run_file(self, db: Session, task_id: str, execution_id: str, principal: dict, path: str) -> dict[str, Any]:
        execution = self._execution_for_task_or_404(db, task_id, execution_id, principal)
        history_run = get_history_run_service().get_history_run_by_execution(db, execution) if execution.workspace_root else None
        if history_run is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="run workspace not found")
        return get_history_run_service().get_history_run_file(db, history_run, path)

    def get_scan_task_run_session_file(self, db: Session, task_id: str, execution_id: str, principal: dict, path: str) -> dict[str, Any]:
        execution = self._execution_for_task_or_404(db, task_id, execution_id, principal)
        history_run = get_history_run_service().get_history_run_by_execution(db, execution) if execution.workspace_root else None
        if history_run is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="run workspace not found")
        return get_history_run_service().get_history_run_session_file(db, history_run, path)

    def get_scan_task_run_log(self, db: Session, task_id: str, execution_id: str, principal: dict, lines: int = 300) -> dict[str, Any]:
        execution = self._execution_for_task_or_404(db, task_id, execution_id, principal)
        history_run = get_history_run_service().get_history_run_by_execution(db, execution) if execution.workspace_root else None
        if history_run is None:
            return {"content": "(no workspace)"}
        return get_history_run_service().get_history_run_log(db, history_run, lines=lines)

    def _history_run_or_404(self, db: Session, history_run_id: str, principal: dict) -> Any:
        history_run = get_history_run_service()._history_run_or_404(db, history_run_id)
        self._ensure_project_access(principal, history_run.project_id)
        return history_run

    def list_history_runs(self, db: Session, principal: dict, *, project_id: str) -> list[dict[str, Any]]:
        self._ensure_project_access(principal, project_id)
        return get_history_run_service().list_history_runs(db, project_id)

    def resolve_history_run(self, db: Session, principal: dict, *, project_id: str, run_name: str, root_path: str) -> dict[str, Any]:
        self._ensure_project_access(principal, project_id)
        history_run = get_history_run_service().resolve_history_run(db, project_id=project_id, run_name=run_name, root_path=root_path)
        return {
            "history_run_id": history_run.id,
            "project_id": history_run.project_id,
            "run_name": history_run.run_name,
            "root_path": str(Path(history_run.run_root_path).resolve().parent),
            "source_type": history_run.source_type,
            "linked_task_id": history_run.linked_task_id,
            "linked_execution_id": history_run.linked_execution_id,
        }

    def get_history_run(self, db: Session, history_run_id: str, principal: dict) -> dict[str, Any]:
        history_run = self._history_run_or_404(db, history_run_id, principal)
        return get_history_run_service().get_history_run_detail(db, history_run)

    def get_history_run_cycle(self, db: Session, history_run_id: str, cycle: int, principal: dict) -> dict[str, Any]:
        history_run = self._history_run_or_404(db, history_run_id, principal)
        return get_history_run_service().get_history_run_cycle(db, history_run, cycle)

    def list_history_run_sessions(self, db: Session, history_run_id: str, principal: dict) -> list[dict[str, Any]]:
        history_run = self._history_run_or_404(db, history_run_id, principal)
        return get_history_run_service().list_history_run_sessions(db, history_run)

    def list_history_run_files(self, db: Session, history_run_id: str, principal: dict, limit: int = 1200) -> list[dict[str, Any]]:
        history_run = self._history_run_or_404(db, history_run_id, principal)
        return get_history_run_service().list_history_run_files(db, history_run, limit=limit)

    def get_history_run_file(self, db: Session, history_run_id: str, principal: dict, path: str) -> dict[str, Any]:
        history_run = self._history_run_or_404(db, history_run_id, principal)
        return get_history_run_service().get_history_run_file(db, history_run, path)

    def get_history_run_session_file(self, db: Session, history_run_id: str, principal: dict, path: str) -> dict[str, Any]:
        history_run = self._history_run_or_404(db, history_run_id, principal)
        return get_history_run_service().get_history_run_session_file(db, history_run, path)

    def get_history_run_log(self, db: Session, history_run_id: str, principal: dict, lines: int = 300) -> dict[str, Any]:
        history_run = self._history_run_or_404(db, history_run_id, principal)
        return get_history_run_service().get_history_run_log(db, history_run, lines=lines)

    def cancel_scan_task(self, db: Session, task_id: str, principal: dict) -> ScanTaskResponse:
        trigger = self._trigger_or_404(db, task_id)
        self._ensure_project_access(principal, trigger.project_id)
        latest_execution = self._latest_execution_for_trigger(db, trigger.id)
        now = datetime.utcnow()
        if trigger.status == "pending":
            trigger.status = "cancelled"
            trigger.finished_at = now
            trigger.message = "cancelled before dispatch"
            if latest_execution is not None and latest_execution.status == "pending":
                latest_execution.status = "cancelled"
                latest_execution.finished_at = now
                latest_execution.message = "cancelled before dispatch"
                db.add(latest_execution)
        elif trigger.status in {"running", "cancel_requested"}:
            trigger.status = "cancel_requested"
            trigger.message = "cancel requested"
            if latest_execution is not None and latest_execution.status == "running":
                latest_execution.status = "cancel_requested"
                latest_execution.message = "cancel requested"
                db.add(latest_execution)
        else:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="task is not cancelable")
        db.add(trigger)
        db.commit()
        db.refresh(trigger)
        return self._scan_task_response(db, trigger)

    def delete_scan_task(self, db: Session, task_id: str, principal: dict) -> dict[str, Any]:
        trigger = self._trigger_or_404(db, task_id)
        self._ensure_project_access(principal, trigger.project_id)
        if trigger.status in {"pending", "running", "cancel_requested"}:
            try:
                self.cancel_scan_task(db, task_id, principal)
                trigger = self._trigger_or_404(db, task_id)
            except Exception:
                db.rollback()
                trigger = self._trigger_or_404(db, task_id)

        executions = self._list_executions_for_trigger(db, trigger.id)
        history_run_ids: set[str] = set()
        workspace_roots: set[str] = set()
        for execution in executions:
            if execution.workspace_root:
                workspace_roots.add(execution.workspace_root)
            history_run = get_history_run_service().get_history_run_by_execution(db, execution) if execution.workspace_root else None
            if history_run:
                history_run_ids.add(history_run.id)
                if history_run.run_root_path:
                    workspace_roots.add(history_run.run_root_path)

        if history_run_ids:
            db.query(HistoryRunFile).filter(HistoryRunFile.history_run_id.in_(list(history_run_ids))).delete(synchronize_session=False)
            db.query(HistoryRunSession).filter(HistoryRunSession.history_run_id.in_(list(history_run_ids))).delete(synchronize_session=False)
            db.query(HistoryRunRemovedResult).filter(HistoryRunRemovedResult.history_run_id.in_(list(history_run_ids))).delete(synchronize_session=False)
            db.query(HistoryRunResultReview).filter(HistoryRunResultReview.history_run_id.in_(list(history_run_ids))).delete(synchronize_session=False)
            db.query(HistoryRunResult).filter(HistoryRunResult.history_run_id.in_(list(history_run_ids))).delete(synchronize_session=False)
            db.query(HistoryRunGlobalReview).filter(HistoryRunGlobalReview.history_run_id.in_(list(history_run_ids))).delete(synchronize_session=False)
            db.query(HistoryRunCycle).filter(HistoryRunCycle.history_run_id.in_(list(history_run_ids))).delete(synchronize_session=False)
            db.query(HistoryRun).filter(HistoryRun.id.in_(list(history_run_ids))).delete(synchronize_session=False)

        execution_ids = [execution.id for execution in executions]
        if execution_ids:
            db.query(WorkflowExecutionEvent).filter(WorkflowExecutionEvent.execution_id.in_(execution_ids)).delete(synchronize_session=False)
            db.query(WorkflowExecution).filter(WorkflowExecution.id.in_(execution_ids)).delete(synchronize_session=False)
        db.delete(trigger)
        db.commit()

        for path in workspace_roots:
            if path:
                shutil.rmtree(path, ignore_errors=True)
        return {"success": True, "message": "task deleted"}

    def _create_retry_attempt_for_task(
        self,
        db: Session,
        *,
        trigger: TriggerTask,
        principal: dict,
        authorization_token: str | None,
        recovery_reason: str,
        increment_retry_count: bool,
    ) -> ScanTaskResponse:
        definition = self._definition_or_404(db, trigger.workflow_definition_id)
        version = self._definition_version_or_404(db, trigger.workflow_definition_version_id)
        actor = _principal_id(principal)
        if increment_retry_count:
            trigger.retry_count += 1
        manifest = TaskManifest.model_validate(trigger.input_tasks_json)
        metadata = dict(manifest.tasks[0].metadata or {}) if manifest.tasks else {}
        if self._is_dataflow_cli_task_metadata(metadata):
            execution = self._create_dataflow_cli_execution_attempt(
                db,
                trigger=trigger,
                definition=definition,
                definition_version=version,
                actor=actor,
                recovery_reason=recovery_reason,
            )
        else:
            execution = self._create_execution_attempt(
                db,
                trigger=trigger,
                definition=definition,
                definition_version=version,
                actor=actor,
                authorization_token=authorization_token,
                recovery_reason=recovery_reason,
            )
        db.commit()
        db.refresh(trigger)
        self.record_event(
            db,
            execution_id=execution.id,
            event_type="execution_requeued",
            message=recovery_reason,
            payload_json={"task_id": trigger.id, "attempt_no": execution.attempt_no},
        )
        return self._scan_task_response(db, trigger)

    def retry_scan_task(self, db: Session, task_id: str, principal: dict, *, authorization_token: str | None = None) -> ScanTaskResponse:
        trigger = self._trigger_or_404(db, task_id)
        self._ensure_project_access(principal, trigger.project_id)
        if trigger.status not in {"failed", "cancelled"}:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="task is not retryable")
        return self._create_retry_attempt_for_task(
            db,
            trigger=trigger,
            principal=principal,
            authorization_token=authorization_token,
            recovery_reason="manual retry requested",
            increment_retry_count=False,
        )

    def requeue_scan_task(self, db: Session, task_id: str, principal: dict, *, authorization_token: str | None = None) -> ScanTaskResponse:
        trigger = self._trigger_or_404(db, task_id)
        self._ensure_project_access(principal, trigger.project_id)
        latest_execution = self._latest_execution_for_trigger(db, trigger.id)
        if latest_execution is None or latest_execution.status not in {"orphaned", "failed", "cancelled"}:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="task is not requeueable")
        return self._create_retry_attempt_for_task(
            db,
            trigger=trigger,
            principal=principal,
            authorization_token=authorization_token,
            recovery_reason="manual requeue requested",
            increment_retry_count=False,
        )

    def update_scan_task_priority(self, db: Session, task_id: str, principal: dict, priority: int) -> ScanTaskResponse:
        trigger = self._trigger_or_404(db, task_id)
        self._ensure_project_access(principal, trigger.project_id)
        if trigger.status in {"succeeded", "failed", "cancelled"}:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="finished task priority cannot be updated")
        trigger.priority = priority
        trigger.message = f"priority updated to {priority}"
        db.add(trigger)
        db.commit()
        db.refresh(trigger)
        return self._scan_task_response(db, trigger)

    def create_trigger_task(
        self,
        db: Session,
        definition_id: str,
        payload: TriggerTaskCreate,
        principal: dict,
        *,
        trigger_type: str,
        authorization_token: str | None = None,
    ) -> TriggerTaskResponse:
        definition = self._definition_or_404(db, definition_id)
        self._ensure_project_access(principal, definition.project_id)
        if not definition.enabled:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="workflow definition is disabled")
        if trigger_type == "http":
            if definition.trigger_type != "http" or not definition.trigger_enabled or not definition.is_active:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="workflow definition http trigger is unavailable")
        actor = _principal_id(principal)
        version = get_workflow_service().get_profile_version_model(db, definition.id)
        trigger, execution = self._create_task_record(
            db,
            definition=definition,
            definition_version=version,
            input_tasks=payload.input_tasks,
            priority=payload.priority if payload.priority is not None else definition.priority_default,
            trigger_type=trigger_type,
            actor=actor,
            authorization_token=authorization_token,
        )
        db.commit()
        db.refresh(trigger)
        self.record_event(
            db,
            execution_id=execution.id,
            event_type="execution_queued",
            message="legacy trigger task queued",
            payload_json={"task_id": trigger.id, "attempt_no": execution.attempt_no},
        )
        return self._trigger_response(trigger)

    def list_trigger_tasks(self, db: Session, principal: dict) -> List[TriggerTaskResponse]:
        project_ids = _project_ids(principal)
        query = db.query(TriggerTask).order_by(TriggerTask.created_at.desc())
        if project_ids:
            query = query.filter(TriggerTask.project_id.in_(project_ids))
        return [self._trigger_response(item) for item in query.all()]

    def get_trigger_task(self, db: Session, trigger_task_id: str, principal: dict) -> TriggerTaskResponse:
        trigger = self._trigger_or_404(db, trigger_task_id)
        self._ensure_project_access(principal, trigger.project_id)
        return self._trigger_response(trigger)

    def cancel_trigger_task(self, db: Session, trigger_task_id: str, principal: dict) -> None:
        self.cancel_scan_task(db, trigger_task_id, principal)

    def retry_trigger_task(
        self,
        db: Session,
        trigger_task_id: str,
        principal: dict,
        *,
        authorization_token: str | None = None,
    ) -> TriggerTaskResponse:
        trigger = self._trigger_or_404(db, trigger_task_id)
        self._ensure_project_access(principal, trigger.project_id)
        definition = self._definition_or_404(db, trigger.workflow_definition_id)
        payload = TriggerTaskCreate(
            input_tasks=self._input_tasks_from_manifest(TaskManifest.model_validate(trigger.input_tasks_json)),
            priority=trigger.priority,
        )
        return self.create_trigger_task(
            db,
            definition.id,
            payload,
            principal,
            trigger_type=trigger.trigger_type,
            authorization_token=authorization_token,
        )

    def list_executions(self, db: Session, principal: dict) -> List[WorkflowExecutionResponse]:
        project_ids = _project_ids(principal)
        query = db.query(WorkflowExecution).order_by(WorkflowExecution.created_at.desc())
        if project_ids:
            query = query.filter(WorkflowExecution.project_id.in_(project_ids))
        return [self._execution_response(item) for item in query.all()]

    def get_execution(self, db: Session, execution_id: str, principal: dict) -> WorkflowExecutionResponse:
        execution = self._execution_or_404(db, execution_id)
        self._ensure_project_access(principal, execution.project_id)
        return self._execution_response(execution)

    def list_execution_events(self, db: Session, execution_id: str, principal: dict) -> List[WorkflowExecutionEventResponse]:
        execution = self._execution_or_404(db, execution_id)
        self._ensure_project_access(principal, execution.project_id)
        events = (
            db.query(WorkflowExecutionEvent)
            .filter(WorkflowExecutionEvent.execution_id == execution.id)
            .order_by(WorkflowExecutionEvent.created_at.asc())
            .all()
        )
        return [self._event_response(item) for item in events]

    def get_execution_artifacts(self, db: Session, execution_id: str, principal: dict) -> Dict[str, Any]:
        execution = self._execution_or_404(db, execution_id)
        self._ensure_project_access(principal, execution.project_id)
        files: List[Dict[str, Any]] = []
        workspace_root = Path(execution.workspace_root) if execution.workspace_root else None
        if workspace_root and workspace_root.exists():
            for path in sorted(p for p in workspace_root.rglob("*") if p.is_file()):
                files.append({"path": str(path.relative_to(workspace_root)), "size": path.stat().st_size})
        return {
            "execution_id": execution.id,
            "workspace_root": execution.workspace_root,
            "output_manifest_path": execution.output_manifest_path,
            "files": files,
        }

    def cancel_execution(self, db: Session, execution_id: str, principal: dict) -> None:
        execution = self._execution_or_404(db, execution_id)
        self._ensure_project_access(principal, execution.project_id)
        self.cancel_scan_task(db, execution.trigger_task_id, principal)

    def record_event(
        self,
        db: Session,
        *,
        execution_id: str,
        event_type: str,
        message: str,
        stage_id: str | None = None,
        round_no: int | None = None,
        level: str = "info",
        payload_json: dict[str, Any] | None = None,
    ) -> WorkflowExecutionEvent:
        event = WorkflowExecutionEvent(
            id=_new_id("evt"),
            execution_id=execution_id,
            event_type=event_type,
            stage_id=stage_id,
            round_no=round_no,
            level=level,
            message=message,
            payload_json=payload_json or {},
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event

    def auto_requeue_orphaned_execution(self, db: Session, execution_id: str, *, reason: str) -> bool:
        execution = self._execution_or_404(db, execution_id)
        trigger = self._trigger_or_404(db, execution.trigger_task_id)
        if execution.status != "orphaned":
            execution.status = "orphaned"
            execution.message = reason
            execution.finished_at = datetime.utcnow()
            db.add(execution)
        if trigger.retry_count >= trigger.max_retry_count:
            trigger.status = "failed"
            trigger.finished_at = datetime.utcnow()
            trigger.message = "max auto retry reached after orphaned execution"
            db.add(trigger)
            db.commit()
            self.record_event(
                db,
                execution_id=execution.id,
                event_type="execution_orphaned",
                message=reason,
                level="warning",
            )
            return False
        system_principal = {"subject": "scheduler"}
        self._create_retry_attempt_for_task(
            db,
            trigger=trigger,
            principal=system_principal,
            authorization_token=None,
            recovery_reason=reason,
            increment_retry_count=True,
        )
        self.record_event(
            db,
            execution_id=execution.id,
            event_type="execution_orphaned",
            message=reason,
            level="warning",
        )
        return True

    def _invoke_run_vuln_scan_cli(
        self,
        *,
        argv: list[str],
        db: Session,
        execution: WorkflowExecution,
        trigger: TriggerTask,
    ) -> int:
        if os.environ.get("SECFLOW_DATAFLOW_CLI_IN_PROCESS") == "1":
            import run_vuln_scan

            try:
                run_vuln_scan.main(argv)
                return 0
            except SystemExit as exc:
                code = exc.code
                if code is None:
                    return 0
                if isinstance(code, int):
                    return code
                return 1

        script_path = Path(__file__).resolve().parents[2] / "run_vuln_scan.py"
        cmd = [sys.executable, str(script_path), *argv]
        process = subprocess.Popen(cmd, cwd=str(script_path.parent))
        try:
            while process.poll() is None:
                time.sleep(max(1, int(get_config().service.execution_cancel_check_interval_seconds)))
                db.expire(execution)
                db.expire(trigger)
                if execution.status == "cancel_requested" or trigger.status == "cancel_requested":
                    process.send_signal(signal.SIGINT)
                    try:
                        return process.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        process.terminate()
                        try:
                            return process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            return process.wait()
            return int(process.returncode or 0)
        finally:
            if process.poll() is None:
                process.terminate()

    def _run_claimed_dataflow_cli_execution(
        self,
        *,
        db: Session,
        execution: WorkflowExecution,
        trigger: TriggerTask,
        definition: WorkflowDefinition,
        version: WorkflowDefinitionVersion,
        metadata: dict[str, Any],
    ) -> None:
        launcher_mode = "run_vuln_scan_cli"
        request = metadata.get("dataflow_scan_request")
        plan = metadata.get("dataflow_cli")
        if not isinstance(request, dict) or not isinstance(plan, dict):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="dataflow CLI task metadata is incomplete")
        run_dir = Path(plan["run_dir"])
        self._write_dataflow_cli_task_preview(plan)
        execution.workspace_root = abs_path(run_dir)
        execution.message = "run_vuln_scan.py running"
        if execution.started_at is None:
            execution.started_at = datetime.utcnow()
        if trigger.started_at is None:
            trigger.started_at = execution.started_at
        trigger.status = "running"
        trigger.message = "run_vuln_scan.py running"
        db.add(execution)
        db.add(trigger)
        db.commit()

        runtime_overrides = dict(metadata.get("runtime_overrides") or {})
        config_payload = version.config_payload_json or definition.config_payload_json or {}
        compiled_config = version.compiled_config_json or version.definition_json or definition.definition_json
        temp_config_path: str | None = None
        argv: list[str] = []
        try:
            argv, temp_config_path = self._build_dataflow_cli_argv(
                plan=plan,
                config_payload=config_payload,
                request=request,
                compiled_config=compiled_config,
                runtime_overrides=runtime_overrides,
            )
            command = [sys.executable, str(Path(__file__).resolve().parents[2] / "run_vuln_scan.py"), *argv]
            metadata["dataflow_cli"] = {
                **plan,
                "argv": argv,
                "command": command,
                "command_display": _command_display(command),
                "launch_mode": launcher_mode,
            }
            self._update_trigger_cli_task(trigger=trigger, metadata=metadata, task_md_path=plan["task_md_path"])
            db.add(trigger)
            db.commit()
            get_history_run_service().sync_execution_run(db, execution)
            db.commit()
            self.record_event(
                db,
                execution_id=execution.id,
                event_type="execution_started",
                message="run_vuln_scan.py started",
                payload_json={
                    "workspace_root": abs_path(run_dir),
                    "owner_pod_id": execution.owner_pod_id,
                    "launch_mode": launcher_mode,
                    "command": command,
                    "command_display": _command_display(command),
                    "run_name": plan["run_name"],
                    "runs_root": plan["runs_root"],
                },
            )
            exit_code = self._invoke_run_vuln_scan_cli(
                argv=argv,
                db=db,
                execution=execution,
                trigger=trigger,
            )
            db.refresh(execution)
            db.refresh(trigger)
            history_run = get_history_run_service().sync_execution_run(db, execution)
            output_summary = run_dir / "output" / "execution_summary.json"
            output_manifest = run_dir / "output" / "tasks.json"
            output_manifest_path = output_manifest if output_manifest.is_file() else output_summary if output_summary.is_file() else None
            if exit_code == 0:
                terminal_status = "succeeded"
                message = "run_vuln_scan.py completed"
            elif exit_code == 130 or execution.status == "cancel_requested" or trigger.status == "cancel_requested":
                terminal_status = "cancelled"
                message = "run_vuln_scan.py cancelled"
            else:
                terminal_status = "failed"
                message = f"run_vuln_scan.py failed with exit code {exit_code}"
            self._set_terminal_state(
                db,
                execution=execution,
                trigger=trigger,
                execution_status=terminal_status,
                message=message,
                output_manifest_path=abs_path(output_manifest_path) if output_manifest_path else None,
                output_task_count=int(history_run.result_count if history_run else 0),
            )
            db.commit()
            get_history_run_service().sync_execution_run(db, execution)
            db.commit()
            event_type = "execution_finished"
            if terminal_status == "cancelled":
                event_type = "execution_cancelled"
            elif terminal_status != "succeeded":
                event_type = "execution_failed"
            self.record_event(
                db,
                execution_id=execution.id,
                event_type=event_type,
                message=message,
                level="info" if terminal_status == "succeeded" else "warning",
                payload_json={
                    "status": execution.status,
                    "exit_code": exit_code,
                    "launch_mode": launcher_mode,
                    "run_dir": abs_path(run_dir),
                    "output_manifest_path": execution.output_manifest_path,
                    "output_task_count": execution.output_task_count,
                },
            )
        finally:
            if temp_config_path:
                try:
                    Path(temp_config_path).unlink(missing_ok=True)
                except OSError:
                    pass

    def run_claimed_execution(self, execution_id: str) -> None:
        db = get_db_session()
        execution: WorkflowExecution | None = None
        trigger: TriggerTask | None = None
        launcher_mode = "rest_service"
        try:
            execution = self._execution_or_404(db, execution_id)
            trigger = self._trigger_or_404(db, execution.trigger_task_id)
            definition = self._definition_or_404(db, execution.workflow_definition_id)
            version = self._definition_version_or_404(db, execution.workflow_definition_version_id or trigger.workflow_definition_version_id)
            service_manifest = TaskManifest.model_validate(trigger.input_tasks_json)
            task_metadata = dict(service_manifest.tasks[0].metadata or {}) if service_manifest.tasks else {}
            if self._is_dataflow_cli_task_metadata(task_metadata):
                self._run_claimed_dataflow_cli_execution(
                    db=db,
                    execution=execution,
                    trigger=trigger,
                    definition=definition,
                    version=version,
                    metadata=task_metadata,
                )
                return
            compiled_config = version.compiled_config_json or version.definition_json or definition.definition_json
            workspace_root = Path(execution.workspace_root) if execution.workspace_root else self._build_workspace_root(execution.id, definition)
            input_manifest_path = workspace_root / "input" / "tasks.json"
            if not input_manifest_path.exists():
                input_manifest_path = write_task_manifest(input_manifest_path, TaskManifest.model_validate(trigger.input_tasks_json).tasks)

            execution.workspace_root = abs_path(workspace_root)
            execution.message = "execution running"
            if execution.started_at is None:
                execution.started_at = datetime.utcnow()
            if trigger.started_at is None:
                trigger.started_at = execution.started_at
            trigger.status = "running"
            trigger.message = "execution running"
            db.add(execution)
            db.add(trigger)
            db.commit()
            custom_workspace_root, custom_output_dir = self._resolve_custom_execution_paths(
                project_id=definition.project_id,
                metadata=task_metadata,
                execution_id=execution.id,
            )
            if custom_workspace_root is not None:
                workspace_root = custom_workspace_root
                execution.workspace_root = abs_path(workspace_root)
                db.add(execution)
                db.commit()
            single_task_entry_file = self._prepare_single_task_entry_file(
                workspace_root=workspace_root,
                manifest=service_manifest,
            )
            entry_task_file = single_task_entry_file or service_manifest.tasks[0].task_md_path
            launcher_mode = "rest_service_cli" if single_task_entry_file else "rest_service"
            runtime_config = build_runtime_framework_config(
                compiled_config,
                workspace_root=abs_path(workspace_root),
                execution_id=execution.id,
                input_task_file=entry_task_file,
                input_task_id=service_manifest.tasks[0].task_id,
                output_dir=abs_path(custom_output_dir or (workspace_root / "output")),
                summary_file=abs_path((custom_output_dir or (workspace_root / "output")) / "execution_summary.json"),
                runtime_mode=launcher_mode,
            )
            write_json(workspace_root / "config.json", runtime_config.model_dump(mode="json"))
            write_json(
                workspace_root / "_meta" / "run_timestamps.json",
                {
                    "started_at": datetime.utcnow().isoformat(),
                    "status": "running",
                    "last_mode": launcher_mode,
                    "last_updated_at": datetime.utcnow().isoformat(),
                },
            )
            get_history_run_service().sync_execution_run(db, execution)
            db.commit()
            log_path = attach_log_file(abs_path(workspace_root / "run.log"))
            self.record_event(
                db,
                execution_id=execution.id,
                event_type="execution_started",
                message="execution claimed and started",
                payload_json={
                    "workspace_root": str(workspace_root),
                    "owner_pod_id": execution.owner_pod_id,
                    "launch_mode": launcher_mode,
                    "entry_task_file": entry_task_file,
                    "log_path": log_path,
                },
            )
            observer = DbExecutionObserver(execution.id)
            recorder = DbExecutionRecorder(abs_path(workspace_root), execution.id)
            ensure_event_loop_policy()
            try:
                artifacts = asyncio.run(
                    run_framework_config(
                        runtime_config,
                        initial_tasks=None if single_task_entry_file else build_core_tasks(service_manifest),
                        observer=observer,
                        recorder=recorder,
                    )
                )
            finally:
                detach_log_file()
            output_manifest_path = write_final_task_manifest(
                workspace_root=workspace_root,
                final_tasks=artifacts.result.final_tasks,
                final_output_task_type=runtime_config.resolve_final_output_task_type(),
            )

            db.refresh(execution)
            db.refresh(trigger)
            self._set_terminal_state(
                db,
                execution=execution,
                trigger=trigger,
                execution_status="succeeded" if artifacts.result.success else "failed",
                message="execution completed" if artifacts.result.success else (artifacts.result.error or "execution failed"),
                output_manifest_path=abs_path(output_manifest_path),
                output_task_count=len(artifacts.result.final_tasks),
            )
            db.commit()
            write_json(
                workspace_root / "_meta" / "run_timestamps.json",
                {
                    "started_at": (execution.started_at or trigger.started_at or datetime.utcnow()).isoformat(),
                    "finished_at": datetime.utcnow().isoformat(),
                    "status": execution.status,
                    "exit_code": 0 if artifacts.result.success else 1,
                    "last_mode": launcher_mode,
                    "last_updated_at": datetime.utcnow().isoformat(),
                },
            )
            get_history_run_service().sync_execution_run(db, execution)
            db.commit()
            self.record_event(
                db,
                execution_id=execution.id,
                event_type="execution_finished",
                message="execution finished",
                payload_json={
                    "status": execution.status,
                    "output_manifest_path": execution.output_manifest_path,
                    "output_task_count": execution.output_task_count,
                    "launch_mode": launcher_mode,
                },
            )
        except Exception as exc:
            from app.pi_vuln_core.observer import ExecutionCancelledError

            if isinstance(exc, ExecutionCancelledError):
                if execution is None or trigger is None:
                    return
                db.refresh(execution)
                db.refresh(trigger)
                self._set_terminal_state(db, execution=execution, trigger=trigger, execution_status="cancelled", message=str(exc))
                db.commit()
                workspace_root = Path(execution.workspace_root) if execution.workspace_root else None
                if workspace_root:
                    write_json(
                        workspace_root / "_meta" / "run_timestamps.json",
                        {
                            "started_at": (execution.started_at or trigger.started_at or datetime.utcnow()).isoformat(),
                            "finished_at": datetime.utcnow().isoformat(),
                            "status": "cancelled",
                            "exit_code": 130,
                            "last_mode": launcher_mode,
                            "last_updated_at": datetime.utcnow().isoformat(),
                        },
                    )
                    get_history_run_service().sync_execution_run(db, execution)
                    db.commit()
                self.record_event(
                    db,
                    execution_id=execution.id,
                    event_type="execution_cancelled",
                    message=str(exc),
                    level="warning",
                )
                return
            if execution is None or trigger is None:
                raise
            db.refresh(execution)
            db.refresh(trigger)
            self._set_terminal_state(db, execution=execution, trigger=trigger, execution_status="failed", message=str(exc))
            db.commit()
            workspace_root = Path(execution.workspace_root) if execution.workspace_root else None
            if workspace_root:
                write_json(
                    workspace_root / "_meta" / "run_timestamps.json",
                    {
                        "started_at": (execution.started_at or trigger.started_at or datetime.utcnow()).isoformat(),
                        "finished_at": datetime.utcnow().isoformat(),
                        "status": "failed",
                        "exit_code": 1,
                        "last_mode": launcher_mode,
                        "last_updated_at": datetime.utcnow().isoformat(),
                    },
                )
                get_history_run_service().sync_execution_run(db, execution)
                db.commit()
            self.record_event(
                db,
                execution_id=execution.id,
                event_type="execution_failed",
                message=str(exc),
                level="error",
            )
            raise
        finally:
            db.close()


_execution_service: ExecutionService | None = None


def get_execution_service() -> ExecutionService:
    global _execution_service
    if _execution_service is None:
        _execution_service = ExecutionService()
    return _execution_service
