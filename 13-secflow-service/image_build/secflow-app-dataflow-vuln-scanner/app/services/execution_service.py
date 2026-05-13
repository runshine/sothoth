from __future__ import annotations

import asyncio
import copy
import json
import logging
import os
import posixpath
import re
import shutil
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi.encoders import jsonable_encoder
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.artifacts.io import abs_path, ensure_dir, sanitize_name, write_json, write_task_manifest, write_text
from app.config import get_config
from app.models.contracts import TaskItem, TaskManifest
from app.models.database import (
    RunIndex,
    RunIndexCycle,
    RunIndexFile,
    RunIndexGlobalReview,
    RunIndexRemovedResult,
    RunIndexResult,
    RunIndexResultReview,
    RunIndexSession,
    TriggerTask,
    WorkflowDefinition,
    WorkflowDefinitionVersion,
    WorkflowExecution,
    WorkflowExecutionEvent,
    get_db_session,
)
from app.pi_vuln_core.review.profile import apply_profile_runtime_policy_to_config
from app.pi_vuln_core.runner import build_runtime_framework_config, run_framework_config
from app.pi_vuln_core.utils.logger import attach_log_file, detach_log_file
from app.pi_vuln_core.utils.win_compat import ensure_event_loop_policy
from app.schemas import (
    ArtifactRef,
    CreateEvolutionTaskRequest,
    DataflowAgentStateDirResponse,
    DataflowInputRef,
    ReplayReadyResponse,
    RunRetryRequest,
    ScanTaskAttemptResponse,
    ScanTaskCreateRequest,
    ScanTaskDetailResponse,
    ScanTaskResponse,
    TriggerTaskInputTask,
)
from app.services.fileserver_client import get_fileserver_client
from app.services.llm_provider_sync import sync_providers_to_pi
from app.services.run_index_service import (
    _load_externalized_json_payload,
    _load_externalized_mapping_payload,
    get_run_index_service,
)
from app.services.pi_vuln_adapter import (
    DbExecutionObserver,
    DbExecutionRecorder,
    build_core_tasks,
    write_final_task_manifest,
)
from app.services.vuln_reporter import get_task_vuln_report_status, get_vuln_report_service
from app.services.workflow_service import get_workflow_service
from app.time_utils import UTC_PLUS_8, isoformat_local, now_local


logger = logging.getLogger("dataflow_vuln.execution")

_TASK_PURPOSE_LABELS = {
    "normal": "正常任务",
    "evolution": "进化任务",
}


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:20]}"


def _sanitize_dataflow_run_name(value: str) -> str:
    cleaned = re.sub(r"\s+", "-", str(value or "").strip())
    cleaned = re.sub(r"[\\/:\0]+", "-", cleaned)
    cleaned = re.sub(r"[^\w.-]+", "-", cleaned, flags=re.UNICODE).strip("-.")
    if cleaned in {"", ".", ".."}:
        return "item"
    return cleaned


def _principal_id(principal: dict) -> str:
    return principal.get("user_id") or principal.get("subject") or principal.get("client_id") or "system"


def _project_ids(principal: dict) -> set[str]:
    return set(principal.get("project_ids") or [])


_ACTIVE_RUN_INDEX_STATUSES = {"pending", "queued", "running", "cancel_requested", "delete_requested"}
_QUEUE_RUN_INDEX_STATUSES = {"pending", "queued"}
_RETRYABLE_RUN_INDEX_STATUSES = {
    "cancelled",
    "failed",
    "interrupted",
    "stopped",
    "review_error",
    "review_plateau",
    "summary_incomplete",
    "runtime_output_limit",
    "runtime_timeout",
    "blocked_context_window",
    "blocked_quota",
    "provider_rate_limited",
    "model_contract_violation",
    "blocked_external_source",
    "error",
}


def _command_display(args: list[str]) -> str:
    return " ".join(shlex.quote(str(item)) for item in args)


class ExecutionService:
    def __init__(self) -> None:
        self._process_lock = threading.RLock()
        self._active_cli_processes: dict[str, subprocess.Popen] = {}

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

    def _trigger_title(self, trigger: TriggerTask) -> str:
        try:
            manifest = TaskManifest.model_validate(trigger.input_tasks_json)
        except Exception:
            return trigger.id
        first_task = manifest.tasks[0] if manifest.tasks else None
        return str(first_task.title or trigger.id) if first_task else trigger.id

    def _trigger_task_metadata(self, trigger: TriggerTask | None) -> dict[str, Any]:
        if trigger is None:
            return {}
        try:
            manifest = TaskManifest.model_validate(trigger.input_tasks_json)
        except Exception:
            return {}
        first_task = manifest.tasks[0] if manifest.tasks else None
        return dict(first_task.metadata or {}) if first_task else {}

    def _normalize_task_purpose(self, value: str | None) -> str:
        normalized = str(value or "").strip().lower()
        return normalized if normalized in {"normal", "evolution"} else "normal"

    def _task_derivation_metadata(self, metadata: dict[str, Any] | None) -> dict[str, Any]:
        payload = metadata.get("derivation") if isinstance(metadata, dict) else None
        return dict(payload) if isinstance(payload, dict) else {}

    def _task_effective_profile_id(self, trigger: TriggerTask) -> str:
        return str(trigger.profile_id or trigger.workflow_definition_id or "").strip()

    def _source_run_index_for_trigger(self, db: Session, trigger: TriggerTask, execution: WorkflowExecution | None) -> RunIndex | None:
        if execution is not None:
            run_index = self._ensure_run_index_for_execution(db, execution, trigger)
            if run_index is not None:
                return run_index
        return (
            db.query(RunIndex)
            .filter(RunIndex.linked_task_id == trigger.id)
            .order_by(RunIndex.started_at.desc(), RunIndex.created_at.desc())
            .first()
        )

    def _default_evolution_title(self, source_title: str) -> str:
        title = f"Evolution of {str(source_title or '').strip()}".strip()
        title = title[:128].rstrip()
        return title or "Evolution Task"

    def _input_ref_or_none(self, value: Any, *, label: str) -> DataflowInputRef | None:
        if value is None:
            return None
        if not isinstance(value, dict):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{label} ref is invalid")
        try:
            return DataflowInputRef.model_validate(value)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{label} ref is invalid") from exc

    def _artifact_refs_from_metadata(self, metadata: dict[str, Any]) -> list[ArtifactRef]:
        items: list[ArtifactRef] = []
        for item in metadata.get("artifact_refs") or []:
            if not isinstance(item, dict):
                continue
            try:
                items.append(ArtifactRef.model_validate(item))
            except Exception as exc:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="artifact_refs in source task metadata is invalid") from exc
        return items

    def _merged_scan_options_for_evolution(self, source_request: dict[str, Any], payload: CreateEvolutionTaskRequest) -> dict[str, Any]:
        merged = dict(source_request.get("options") or {})
        merged.pop("run_name", None)
        merged.update(dict(payload.scan_options or {}))
        return merged

    def _build_evolution_create_payload(
        self,
        *,
        db: Session,
        source_trigger: TriggerTask,
        source_execution: WorkflowExecution | None,
        payload: CreateEvolutionTaskRequest,
    ) -> tuple[ScanTaskCreateRequest, dict[str, Any]]:
        task_metadata = self._trigger_task_metadata(source_trigger)
        if self._normalize_task_purpose(getattr(source_trigger, "task_purpose", None) or task_metadata.get("task_purpose")) != "normal":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="only normal tasks can create evolution tasks")
        if not self._is_dataflow_cli_task_metadata(task_metadata):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="source task is not a run_vuln_scan.py launcher task")
        source_request = task_metadata.get("dataflow_scan_request") if isinstance(task_metadata.get("dataflow_scan_request"), dict) else {}
        if not isinstance(source_request.get("data_flow"), dict) or not isinstance(source_request.get("source_dir"), dict):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="source task is missing reusable data_flow/source_dir inputs")

        if source_trigger.workflow_definition_version_id:
            version = self._definition_version_or_404(db, source_trigger.workflow_definition_version_id)
        else:
            version = get_workflow_service().get_profile_version_model(db, source_trigger.workflow_definition_id)
        source_config_payload = dict(version.config_payload_json or {})
        source_run_index = self._source_run_index_for_trigger(db, source_trigger, source_execution)
        source_run_id = source_run_index.id if source_run_index is not None else None
        source_title = self._trigger_title(source_trigger)
        source_profile_id = self._task_effective_profile_id(source_trigger)
        source_origin_type = str(source_trigger.task_origin_type or task_metadata.get("task_origin_type") or "manual").strip() or "manual"
        source_runtime_overrides = dict(task_metadata.get("runtime_overrides") or {})
        merged_runtime_overrides = {**source_runtime_overrides, **dict(payload.runtime_overrides or {})}
        derivation = {
            "kind": "evolution_replay",
            "source_task_id": source_trigger.id,
            "source_execution_id": source_execution.id if source_execution is not None else None,
            "source_run_id": source_run_id,
            "source_task_purpose": "normal",
            "evolution_task_id": payload.evolution_task_id,
            "evolution_round": payload.evolution_round,
            "evolution_source_task_id": payload.evolution_source_task_id or source_trigger.id,
            "evolution_source_execution_id": payload.evolution_source_execution_id or (source_execution.id if source_execution is not None else None),
        }

        create_payload = ScanTaskCreateRequest(
            project_id=source_trigger.project_id,
            profile_id=payload.profile_id or source_profile_id,
            title=(payload.title.strip() if isinstance(payload.title, str) else "") or self._default_evolution_title(source_title),
            workspace_dir=self._input_ref_or_none(source_request.get("workspace_dir"), label="workspace_dir"),
            data_flow=self._input_ref_or_none(source_request.get("data_flow"), label="data_flow"),
            source_dir=self._input_ref_or_none(source_request.get("source_dir"), label="source_dir"),
            output_dir=self._input_ref_or_none(source_request.get("output_dir"), label="output_dir"),
            model=payload.model if payload.model is not None else source_request.get("model") or source_config_payload.get("model"),
            provider=payload.provider if payload.provider is not None else source_request.get("provider"),
            review_profile=payload.review_profile if payload.review_profile is not None else source_request.get("review_profile") or source_config_payload.get("review_profile"),
            max_review_cycles=payload.max_review_cycles if payload.max_review_cycles is not None else source_request.get("max_review_cycles") or source_config_payload.get("max_review_cycles"),
            agent_run_timeout_seconds=payload.agent_run_timeout_seconds if payload.agent_run_timeout_seconds is not None else source_request.get("agent_run_timeout_seconds") if source_request.get("agent_run_timeout_seconds") is not None else source_config_payload.get("agent_run_timeout_seconds"),
            agent_timeout_retry_enabled=payload.agent_timeout_retry_enabled if payload.agent_timeout_retry_enabled is not None else source_request.get("agent_timeout_retry_enabled") if source_request.get("agent_timeout_retry_enabled") is not None else source_config_payload.get("agent_timeout_retry_enabled"),
            agent_timeout_max_retries=payload.agent_timeout_max_retries if payload.agent_timeout_max_retries is not None else source_request.get("agent_timeout_max_retries") if source_request.get("agent_timeout_max_retries") is not None else source_config_payload.get("agent_timeout_max_retries"),
            worker_timeout=source_request.get("worker_timeout") if source_request.get("worker_timeout") is not None else source_config_payload.get("worker_timeout"),
            advisor_timeout=source_request.get("advisor_timeout") if source_request.get("advisor_timeout") is not None else source_config_payload.get("advisor_timeout"),
            timeout_max_retries=payload.timeout_max_retries if payload.timeout_max_retries is not None else source_request.get("timeout_max_retries") if source_request.get("timeout_max_retries") is not None else source_config_payload.get("timeout_max_retries"),
            timeout_retry_interval_seconds=payload.timeout_retry_interval_seconds if payload.timeout_retry_interval_seconds is not None else source_request.get("timeout_retry_interval_seconds") if source_request.get("timeout_retry_interval_seconds") is not None else source_config_payload.get("timeout_retry_interval_seconds"),
            result_review_concurrency=payload.result_review_concurrency if payload.result_review_concurrency is not None else source_request.get("result_review_concurrency") if source_request.get("result_review_concurrency") is not None else source_config_payload.get("result_review_concurrency"),
            scan_options=self._merged_scan_options_for_evolution(source_request, payload),
            artifact_refs=self._artifact_refs_from_metadata(task_metadata),
            priority=payload.priority if payload.priority is not None else source_trigger.priority,
            runtime_overrides=merged_runtime_overrides,
            task_purpose="evolution",
            agent_state_roots=dict(payload.agent_state_roots or {}),
            task_origin_type=source_origin_type,
            auto_report_vulnerabilities=bool(task_metadata.get("auto_report_vulnerabilities", True)) if payload.auto_report_vulnerabilities is None else bool(payload.auto_report_vulnerabilities),
        )
        return create_payload, {"derivation": derivation}

    def _agent_ids_from_compiled_config(self, compiled_config: dict[str, Any] | None) -> list[str]:
        agent_ids: list[str] = []
        for agent in (compiled_config or {}).get("agents") or []:
            if not isinstance(agent, dict):
                continue
            agent_id = str(agent.get("id") or "").strip()
            if agent_id and agent_id not in agent_ids:
                agent_ids.append(agent_id)
        return agent_ids

    def _default_agent_state_root(self, *, project_id: str, agent_id: str) -> Path:
        config = get_config()
        return (
            self._project_files_root(project_id)
            / sanitize_name(config.fileserver_service.dataflow_subproject_name)
            / "agent-state"
            / "shared"
            / sanitize_name(agent_id)
        )

    def _resolve_directory_ref(
        self,
        *,
        project_id: str,
        ref: dict[str, Any],
        expected: str,
        require_exists: bool,
    ) -> Path:
        source = str(ref.get("source") or "project_filesystem").strip()
        if source in {"project_filesystem", "project_path", "project"}:
            project_root = self._project_files_root(project_id)
            normalized = self._normalize_project_path(str(ref.get("path") or ""))
            resolved = self._ensure_path_within(path=project_root / normalized.lstrip("/"), root=project_root, label=expected)
        elif source in {"fileserver_storage", "storage_key", "managed_file"}:
            storage_key = str(ref.get("storage_key") or ref.get("path") or "").strip()
            if not storage_key:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{expected} storage_key is required")
            resolved = self._resolve_project_storage_key(project_id=project_id, storage_key=storage_key, label=expected)
        elif source in {"absolute", "absolute_path", "local_path"}:
            if not get_config().service.allow_absolute_input_refs:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{expected} absolute_path input is disabled")
            raw = str(ref.get("path") or "").strip()
            if not raw:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{expected} path is required")
            candidate = Path(raw)
            if not candidate.is_absolute():
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{expected} absolute path is required")
            resolved = self._ensure_path_within(path=candidate, root=self._project_files_root(project_id), label=expected)
        else:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"unsupported {expected} source: {source}")
        if require_exists and not resolved.exists():
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{expected} not found: {resolved}")
        if resolved.exists() and not resolved.is_dir():
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{expected} must be a directory: {resolved}")
        return resolved

    def _agent_state_dirs_from_metadata(
        self,
        *,
        project_id: str,
        compiled_config: dict[str, Any] | None,
        metadata: dict[str, Any] | None,
    ) -> dict[str, dict[str, str]]:
        metadata = metadata or {}
        configured_roots = metadata.get("agent_state_roots") if isinstance(metadata.get("agent_state_roots"), dict) else {}
        response: dict[str, dict[str, str]] = {}
        for agent_id in self._agent_ids_from_compiled_config(compiled_config):
            root_path: Path
            source = "shared_default"
            root_payload = configured_roots.get(agent_id) if isinstance(configured_roots.get(agent_id), dict) else {}
            root_ref = root_payload.get("root_dir") if isinstance(root_payload.get("root_dir"), dict) else None
            if root_ref is not None:
                root_path = self._resolve_directory_ref(
                    project_id=project_id,
                    ref=root_ref,
                    expected=f"{agent_id} root_dir",
                    require_exists=False,
                )
                source = "task_override"
            else:
                root_path = self._default_agent_state_root(project_id=project_id, agent_id=agent_id)
            response[agent_id] = {
                "agent_id": agent_id,
                "root_dir": abs_path(root_path),
                "skills_dir": abs_path(root_path / "skills"),
                "memory_dir": abs_path(root_path / "memory"),
                "source": source,
            }
        return response

    def _ensure_agent_state_dirs(self, agent_state_dirs: dict[str, dict[str, str]]) -> None:
        for item in agent_state_dirs.values():
            root_dir = ensure_dir(item["root_dir"])
            skills_dir = ensure_dir(item["skills_dir"])
            memory_dir = ensure_dir(item["memory_dir"])
            home_skills = root_dir / "skills"
            home_memory = root_dir / "memory"
            if home_skills != skills_dir:
                ensure_dir(home_skills)
            if home_memory != memory_dir:
                ensure_dir(home_memory)

    def _apply_agent_state_dirs_to_compiled_config(
        self,
        *,
        compiled_config: dict[str, Any],
        agent_state_dirs: dict[str, dict[str, str]],
    ) -> dict[str, Any]:
        payload = copy.deepcopy(compiled_config or {})
        for agent in payload.get("agents") or []:
            if not isinstance(agent, dict):
                continue
            agent_id = str(agent.get("id") or "").strip()
            state_dirs = agent_state_dirs.get(agent_id)
            if not state_dirs:
                continue
            runtime_config = agent.setdefault("runtime_config", {})
            env_payload = runtime_config.setdefault("env", {})
            env_payload["PI_CODING_AGENT_DIR"] = state_dirs["root_dir"]
            env_payload["SECFLOW_PI_AGENT_HOME"] = state_dirs["root_dir"]
            env_payload["SECFLOW_PI_SKILLS_DIR"] = state_dirs["skills_dir"]
            env_payload["SECFLOW_PI_MEMORY_DIR"] = state_dirs["memory_dir"]
            runtime_config["agent_home_dir"] = state_dirs["root_dir"]
            runtime_config["skills_dir"] = state_dirs["skills_dir"]
            runtime_config["memory_dir"] = state_dirs["memory_dir"]
        return payload

    def _trigger_uses_run_directory(self, trigger: TriggerTask | None) -> bool:
        metadata = self._trigger_task_metadata(trigger)
        return (
            self._is_dataflow_cli_task_metadata(metadata)
            or isinstance(metadata.get("run_adoption"), dict)
            or isinstance(metadata.get("run_retry"), dict)
        )

    def _planned_run_root_for_trigger(self, trigger: TriggerTask | None) -> Path | None:
        metadata = self._trigger_task_metadata(trigger)
        plan = metadata.get("dataflow_cli") if isinstance(metadata.get("dataflow_cli"), dict) else {}
        raw_run_dir = str(plan.get("run_dir") or "").strip()
        if not raw_run_dir:
            request = metadata.get("dataflow_scan_request") if isinstance(metadata.get("dataflow_scan_request"), dict) else {}
            raw_run_dir = str(request.get("resume_run_dir") or "").strip()
        if not raw_run_dir:
            return None
        candidate = Path(raw_run_dir)
        if not candidate.is_absolute():
            return None
        try:
            project_id = trigger.project_id if trigger is not None else ""
            return self._ensure_path_within(path=candidate, root=self._project_files_root(project_id), label="run_dir")
        except Exception:
            return None

    def _run_root_for_execution_or_trigger(
        self,
        execution: WorkflowExecution | None,
        trigger: TriggerTask | None = None,
    ) -> Path | None:
        if execution is not None and execution.workspace_root:
            return Path(execution.workspace_root).resolve()
        return self._planned_run_root_for_trigger(trigger)

    def _run_locator_for_execution(self, execution: WorkflowExecution | None, trigger: TriggerTask | None = None) -> dict[str, str | None]:
        run_root = self._run_root_for_execution_or_trigger(execution, trigger)
        if run_root is None:
            return {"run_name": None, "runs_root": None, "run_path": None}
        return {
            "run_name": run_root.name,
            "runs_root": str(run_root.parent),
            "run_path": str(run_root),
        }

    def _latest_run_summary_for_execution(self, db: Session, execution: WorkflowExecution | None, trigger: TriggerTask | None = None) -> dict[str, Any]:
        if execution is None:
            return {}
        try:
            run_index = get_run_index_service().get_run_index_by_execution(db, execution) if execution.workspace_root else None
            if run_index is None:
                run_index = self._ensure_run_index_for_execution(db, execution, trigger)
            if run_index is None:
                return {}
            return get_run_index_service().get_run_summary(db, run_index)
        except Exception:
            db.rollback()
            return {}

    def _ensure_run_index_for_execution(
        self,
        db: Session,
        execution: WorkflowExecution | None,
        trigger: TriggerTask | None = None,
    ) -> RunIndex | None:
        if execution is None:
            return None
        run_root = self._run_root_for_execution_or_trigger(execution, trigger)
        if run_root is None:
            return None
        if not execution.workspace_root:
            execution.workspace_root = abs_path(run_root)
            db.add(execution)
            db.flush()
        if not run_root.is_dir() and trigger is not None and self._trigger_uses_run_directory(trigger):
            metadata = self._trigger_task_metadata(trigger)
            plan = metadata.get("dataflow_cli") if isinstance(metadata.get("dataflow_cli"), dict) else {}
            planned_run_dir = str(plan.get("run_dir") or "").strip()
            if planned_run_dir:
                try:
                    if Path(planned_run_dir).resolve() == run_root.resolve():
                        self._write_dataflow_cli_task_preview(plan)
                except Exception:
                    # Resolver paths should be best-effort; the caller will
                    # still return 404 if the run directory cannot be prepared.
                    pass
        if not run_root.is_dir():
            return None
        return get_run_index_service().sync_run_path(
            db,
            project_id=execution.project_id,
            run_root=run_root,
            source_type="execution_workspace",
            linked_execution=execution,
            linked_task=trigger or db.get(TriggerTask, execution.trigger_task_id),
            profile_id=(trigger.profile_id if trigger else None),
        )

    def _scan_task_response(self, db: Session, trigger: TriggerTask, *, include_run_summary: bool = True) -> ScanTaskResponse:
        latest_execution = self._latest_execution_for_trigger(db, trigger.id)
        if trigger.workflow_definition_version_id:
            version = self._definition_version_or_404(db, trigger.workflow_definition_version_id)
        else:
            version = get_workflow_service().get_profile_version_model(db, trigger.workflow_definition_id)
        compiled_config = version.compiled_config_json or version.definition_json or {}
        task_metadata = self._trigger_task_metadata(trigger)
        task_origin_type = str(trigger.task_origin_type or "").strip() or "manual"
        task_purpose = self._normalize_task_purpose(getattr(trigger, "task_purpose", None) or task_metadata.get("task_purpose"))
        derivation = self._task_derivation_metadata(task_metadata)
        parent_task_type = str(trigger.parent_task_type or "").strip() or None
        origin_label = (
            "二进制安全-源码扫描"
            if task_origin_type == "binary_security" and parent_task_type == "source"
            else "二进制安全-二进制类扫描"
            if task_origin_type == "binary_security"
            else "手动任务"
        )
        def _version_review_profile() -> str:
            version_config = version.compiled_config_json or version.definition_json or {}
            for workflow in ((version_config.get("workflows") or {}).get("atomic") or []):
                if not isinstance(workflow, dict):
                    continue
                engine = workflow.get("engine")
                if isinstance(engine, dict) and (engine.get("review_profile") or workflow.get("id") == "vuln_scan"):
                    return str(engine.get("review_profile") or "")
            return ""

        run_locator = self._run_locator_for_execution(latest_execution, trigger)
        if include_run_summary:
            run_summary = self._latest_run_summary_for_execution(db, latest_execution, trigger)
        else:
            run_summary = {}
            if latest_execution is not None:
                lightweight_run_index = (
                    db.query(RunIndex)
                    .filter(RunIndex.linked_execution_id == latest_execution.id)
                    .first()
                )
                if lightweight_run_index is None:
                    lightweight_run_index = (
                        db.query(RunIndex)
                        .filter(RunIndex.linked_task_id == trigger.id)
                        .order_by(RunIndex.started_at.desc(), RunIndex.created_at.desc())
                        .first()
                    )
                if lightweight_run_index is not None:
                    config_json = _load_externalized_mapping_payload(
                        lightweight_run_index.run_root_path,
                        lightweight_run_index.config_json,
                    )
                    review_profile = str(config_json.get("review_profile") or "")
                    for workflow in ((config_json.get("workflows") or {}).get("atomic") or []):
                        if not isinstance(workflow, dict):
                            continue
                        engine = workflow.get("engine")
                        if isinstance(engine, dict) and (engine.get("review_profile") or workflow.get("id") == "vuln_scan"):
                            review_profile = str(engine.get("review_profile") or "")
                            break
                    if not review_profile:
                        review_profile = _version_review_profile()
                    run_summary.update({
                        "run_id": lightweight_run_index.id,
                        "status": lightweight_run_index.status,
                        "model": lightweight_run_index.model,
                        "provider": lightweight_run_index.provider,
                        "thinking": lightweight_run_index.thinking,
                        "max_cycles": lightweight_run_index.max_cycles,
                        "cycles_used": lightweight_run_index.cycles_used,
                        "result_count": lightweight_run_index.result_count,
                        "passed_count": lightweight_run_index.passed_count,
                        "failed_count": lightweight_run_index.failed_count,
                        "workflow_mode": lightweight_run_index.workflow_mode,
                        "review_profile": review_profile,
                        "process_state": self._run_process_state(
                            db,
                            lightweight_run_index,
                            trigger=trigger,
                            execution=latest_execution,
                        ),
                    })
        if run_summary and "process_state" not in run_summary:
            run_index_for_state = None
            run_index_id = str(run_summary.get("run_id") or "").strip()
            if run_index_id:
                run_index_for_state = db.get(RunIndex, run_index_id)
            if run_index_for_state is None and latest_execution is not None:
                run_index_for_state = (
                    db.query(RunIndex)
                    .filter(RunIndex.linked_execution_id == latest_execution.id)
                    .first()
                )
            if run_index_for_state is None:
                run_index_for_state = (
                    db.query(RunIndex)
                    .filter(RunIndex.linked_task_id == trigger.id)
                    .order_by(RunIndex.started_at.desc(), RunIndex.created_at.desc())
                    .first()
                )
            if run_index_for_state is not None:
                run_summary["process_state"] = self._run_process_state(
                    db,
                    run_index_for_state,
                    trigger=trigger,
                    execution=latest_execution,
                )
        if run_locator["run_name"] and run_locator["runs_root"]:
            run_summary = {
                "name": run_locator["run_name"],
                "root_path": run_locator["runs_root"],
                "path": run_locator["run_path"],
                "linked_task_id": trigger.id,
                "linked_execution_id": latest_execution.id if latest_execution else None,
                **run_summary,
            }
        return ScanTaskResponse(
            task_id=trigger.id,
            project_id=trigger.project_id,
            derived_from_task_id=str(derivation.get("source_task_id") or "").strip() or None,
            derived_from_execution_id=str(derivation.get("source_execution_id") or "").strip() or None,
            derived_from_run_id=str(derivation.get("source_run_id") or "").strip() or None,
            derivation_kind="evolution_replay" if str(derivation.get("kind") or "").strip() == "evolution_replay" else None,
            task_origin_type=task_origin_type,
            parent_project_id=trigger.parent_project_id,
            parent_task_id=trigger.parent_task_id,
            parent_task_type=parent_task_type,
            parent_stage_name=trigger.parent_stage_name,
            parent_stage_item_id=trigger.parent_stage_item_id,
            parent_stage_item_key=trigger.parent_stage_item_key,
            origin_label=origin_label,
            parent_task_display=trigger.parent_task_id,
            profile_id=trigger.profile_id or trigger.workflow_definition_id,
            profile_version=version.version_no,
            task_purpose=task_purpose,
            agent_state_dirs={
                key: DataflowAgentStateDirResponse.model_validate(value)
                for key, value in self._agent_state_dirs_from_metadata(
                    project_id=trigger.project_id,
                    compiled_config=compiled_config,
                    metadata=task_metadata,
                ).items()
            },
            title=self._trigger_title(trigger),
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
            run_name=run_locator["run_name"],
            runs_root=run_locator["runs_root"],
            run_path=run_locator["run_path"],
            run=run_summary,
            latest_run=run_summary,
            auto_report_vulnerabilities=bool(
                task_metadata.get("auto_report_vulnerabilities", True)
            ),
            vuln_report_status=get_task_vuln_report_status(
                db,
                trigger,
                latest_execution.id if latest_execution else None,
            ),
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
            task_metadata = dict(first_task.metadata or {})
            dataflow_cli = task_metadata.get("dataflow_cli") if isinstance(task_metadata.get("dataflow_cli"), dict) else {}
            candidate_task_paths = [
                str(first_task.task_md_path or "").strip(),
                str(dataflow_cli.get("task_md_path") or "").strip(),
            ]
            for candidate in candidate_task_paths:
                if not candidate:
                    continue
                try:
                    task_markdown = Path(candidate).read_text(encoding="utf-8")
                    if task_markdown:
                        break
                except FileNotFoundError:
                    continue
            for item in task_metadata.get("artifact_refs") or []:
                if isinstance(item, dict):
                    artifact_refs.append(ArtifactRef.model_validate(item))
            runtime_overrides = dict(task_metadata.get("runtime_overrides") or {})
        attempts = []
        run_service = get_run_index_service()
        for item in self._list_executions_for_trigger(db, trigger.id):
            try:
                run_index = run_service.get_run_index_by_execution(db, item) if item.workspace_root else None
            except Exception:
                db.rollback()
                run_index = None
            if not task_markdown and run_index is not None:
                try:
                    task_path = Path(run_index.run_root_path) / "run" / "input" / "task.md"
                    if not task_path.exists():
                        task_path = Path(run_index.run_root_path) / "input" / "task.md"
                    task_markdown = task_path.read_text(encoding="utf-8")
                except (FileNotFoundError, TypeError):
                    task_markdown = ""
            attempts.append(self._attempt_response(item, run_id=run_index.id if run_index else None))
        payload = response.model_dump()
        payload["title"] = title
        return ScanTaskDetailResponse(
            **payload,
            task_markdown=task_markdown,
            artifact_refs=artifact_refs,
            runtime_overrides=runtime_overrides,
            task_metadata=task_metadata,
            attempts=attempts,
        )

    def _attempt_response(self, execution: WorkflowExecution, run_id: str | None = None) -> ScanTaskAttemptResponse:
        return ScanTaskAttemptResponse(
            execution_id=execution.id,
            task_id=execution.trigger_task_id,
            attempt_no=execution.attempt_no,
            status=execution.status,
            run_id=run_id,
            owner_pod_id=execution.owner_pod_id,
            process_pid=execution.process_pid,
            process_host=execution.process_host,
            process_status=execution.process_status,
            process_started_at=execution.process_started_at,
            process_finished_at=execution.process_finished_at,
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

    def _execution_command_payload(self, db: Session, execution_id: str) -> dict[str, Any]:
        event = (
            db.query(WorkflowExecutionEvent)
            .filter(
                WorkflowExecutionEvent.execution_id == execution_id,
                WorkflowExecutionEvent.event_type == "execution_started",
            )
            .order_by(WorkflowExecutionEvent.created_at.desc())
            .first()
        )
        payload = dict(event.payload_json or {}) if event else {}
        command = payload.get("command") if isinstance(payload.get("command"), list) else []
        return {
            "command": [str(item) for item in command],
            "command_display": str(payload.get("command_display") or ""),
        }

    def _register_cli_process(self, execution_id: str, process: subprocess.Popen) -> None:
        with self._process_lock:
            self._active_cli_processes[execution_id] = process

    def _forget_cli_process(self, execution_id: str, process: subprocess.Popen | None = None) -> None:
        with self._process_lock:
            current = self._active_cli_processes.get(execution_id)
            if process is None or current is process:
                self._active_cli_processes.pop(execution_id, None)

    def _local_cli_process(self, execution_id: str) -> subprocess.Popen | None:
        with self._process_lock:
            process = self._active_cli_processes.get(execution_id)
        if process is not None and process.poll() is None:
            return process
        if process is not None:
            self._forget_cli_process(execution_id, process)
        return None

    def _process_heartbeat_stale_after_seconds(self) -> int:
        cfg = get_config()
        configured_seconds = max(int(getattr(cfg.service, "process_heartbeat_stale_after_seconds", 0) or 0), 0)
        scheduler_seconds = max(int(getattr(cfg.scheduler, "heartbeat_interval_seconds", 0) or 0) * 3, 0)
        cancel_poll_seconds = max(int(getattr(cfg.service, "execution_cancel_check_interval_seconds", 0) or 0) * 5, 0)
        return max(configured_seconds, scheduler_seconds, cancel_poll_seconds, 30)

    def _parse_process_timestamp(self, value: Any) -> datetime | None:
        text = str(value or "").strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is not None:
                return parsed.astimezone(UTC_PLUS_8).replace(tzinfo=None)
            return parsed
        except ValueError:
            return None

    def _read_run_process_file(self, run_root: str | Path | None) -> dict[str, Any]:
        if not run_root:
            return {}
        root = Path(run_root)
        path = root / "run" / "_meta" / "process.json"
        if not path.is_file():
            path = root / "_meta" / "process.json"
        if not path.is_file():
            return {}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {"read_error": f"failed to read {path}"}
        return payload if isinstance(payload, dict) else {}

    def _write_cli_process_file(
        self,
        *,
        execution: WorkflowExecution,
        trigger: TriggerTask,
        cmd: list[str],
        process: subprocess.Popen,
        status_text: str,
        return_code: int | None = None,
    ) -> None:
        if not execution.workspace_root:
            return
        current = now_local()
        payload: dict[str, Any] = {
            "execution_id": execution.id,
            "trigger_task_id": trigger.id,
            "pid": process.pid,
            "pod_id": get_config().scheduler.pod_id,
            "host_name": get_config().scheduler.host_name,
            "command": cmd,
            "command_display": _command_display(cmd),
            "started_at": isoformat_local(execution.process_started_at or current) or "",
            "status": status_text,
            "updated_at": isoformat_local(current) or "",
        }
        if status_text in {"running", "timeout_requested", "stop_requested", "delete_requested"}:
            payload["heartbeat_at"] = isoformat_local(current) or ""
        if execution.process_finished_at:
            payload["finished_at"] = isoformat_local(execution.process_finished_at) or ""
        if return_code is not None:
            payload["return_code"] = return_code
        write_json(Path(execution.workspace_root) / "run" / "_meta" / "process.json", payload)

    def _try_write_cli_process_file(
        self,
        *,
        execution: WorkflowExecution,
        trigger: TriggerTask,
        cmd: list[str],
        process: subprocess.Popen,
        status_text: str,
        return_code: int | None = None,
    ) -> bool:
        try:
            self._write_cli_process_file(
                execution=execution,
                trigger=trigger,
                cmd=cmd,
                process=process,
                status_text=status_text,
                return_code=return_code,
            )
            return True
        except OSError as exc:
            logger.warning(
                "run process metadata write failed; child process will continue: execution_id=%s status=%s error=%s",
                execution.id,
                status_text,
                exc,
            )
            return False

    def _resume_command_payload_from_plan(self, *, plan: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
        argv, _ = self._build_dataflow_cli_argv(
            plan=plan,
            config_payload={},
            request=request,
            compiled_config={},
            runtime_overrides={},
            agent_state_dirs={},
        )
        command = [sys.executable, str(Path(__file__).resolve().parents[2] / "run_vuln_scan.py"), *argv]
        return {
            "argv": argv,
            "command": command,
            "command_display": _command_display(command),
        }

    def _task_dataflow_cli_metadata(self, trigger: TriggerTask | None) -> dict[str, Any]:
        if trigger is None:
            return {}
        try:
            manifest = TaskManifest.model_validate(trigger.input_tasks_json)
        except Exception:
            return {}
        for task in manifest.tasks:
            metadata = dict(task.metadata or {})
            cli_payload = metadata.get("dataflow_cli")
            if isinstance(cli_payload, dict):
                return dict(cli_payload)
        return {}

    def _command_payload_is_resume(self, payload: dict[str, Any]) -> bool:
        command_items = payload.get("command") if isinstance(payload.get("command"), list) else []
        argv_items = payload.get("argv") if isinstance(payload.get("argv"), list) else []
        text = " ".join(str(item) for item in [*command_items, *argv_items, payload.get("command_display") or ""])
        return "--resume-run-dir" in text or str(payload.get("mode") or "").lower() == "resume"

    def _retry_command_display(
        self,
        db: Session,
        *,
        run_index,
        trigger: TriggerTask | None,
        execution: WorkflowExecution | None,
    ) -> str:
        candidates: list[dict[str, Any]] = []
        task_payload = self._task_dataflow_cli_metadata(trigger)
        if task_payload:
            candidates.append(task_payload)
        if execution is not None:
            event_payload = self._execution_command_payload(db, execution.id)
            if event_payload:
                candidates.append(event_payload)
        process_payload = self._read_run_process_file(run_index.run_root_path)
        if process_payload:
            candidates.append(process_payload)
        raw_summary = dict(_load_externalized_json_payload(run_index.run_root_path, run_index.raw_summary_json) or {})
        raw_cli = raw_summary.get("dataflow_cli") if isinstance(raw_summary.get("dataflow_cli"), dict) else {}
        if raw_cli:
            candidates.append(dict(raw_cli))
        for payload in candidates:
            if not self._command_payload_is_resume(payload):
                continue
            display = str(payload.get("command_display") or "").strip()
            if display:
                return display
            command = payload.get("command") if isinstance(payload.get("command"), list) else payload.get("argv")
            if isinstance(command, list) and command:
                return _command_display([str(item) for item in command])
        return ""

    def _signal_local_cli_process(
        self,
        execution_id: str,
        *,
        wait: bool,
        graceful_timeout: float = 5.0,
        terminate_timeout: float = 5.0,
    ) -> dict[str, Any]:
        process = self._local_cli_process(execution_id)
        if process is None:
            return {"found": False, "signal": "db_flag_only"}
        payload: dict[str, Any] = {"found": True, "pid": process.pid, "signal": "sigint"}
        if process.poll() is None:
            try:
                process.send_signal(signal.SIGINT)
            except ProcessLookupError:
                payload["signal"] = "already_exited"
                return payload
        if not wait:
            return payload
        try:
            payload["exit_code"] = process.wait(timeout=graceful_timeout)
            payload["signal"] = "sigint"
            return payload
        except subprocess.TimeoutExpired:
            if process.poll() is None:
                process.terminate()
            payload["signal"] = "terminate"
        try:
            payload["exit_code"] = process.wait(timeout=terminate_timeout)
            return payload
        except subprocess.TimeoutExpired:
            if process.poll() is None:
                process.kill()
            payload["signal"] = "kill"
            payload["exit_code"] = process.wait()
            return payload

    def _write_run_control_state(self, run_root: str | Path | None, *, status_text: str, message: str) -> None:
        if not run_root:
            return
        try:
            root = Path(run_root)
            if not root.exists():
                return
            timestamp_path = root / "run" / "_meta" / "run_timestamps.json"
            if not timestamp_path.exists() and (root / "_meta").exists():
                timestamp_path = root / "_meta" / "run_timestamps.json"
            payload: dict[str, Any] = {}
            if timestamp_path.is_file():
                try:
                    import json

                    payload = json.loads(timestamp_path.read_text(encoding="utf-8"))
                except Exception:
                    payload = {}
            payload.update(
                {
                    "status": status_text,
                    "control_message": message,
                    "last_updated_at": isoformat_local(now_local()),
                }
            )
            write_json(
                timestamp_path,
                payload,
            )
        except OSError:
            pass

    def _build_workspace_root(self, execution_id: str, definition: WorkflowDefinition) -> Path:
        base_dir = definition.workspace_base_dir or get_config().service.workspace_base_dir
        return ensure_dir(Path(base_dir) / execution_id)

    def _copy_uploaded_inputs_to_task_dir(self, *, project_id: str, task_input_dir: Path, metadata: Dict[str, Any]) -> List[Dict[str, str]]:
        uploads = metadata.get("task_input_uploads")
        if not isinstance(uploads, list) or not uploads:
            return []
        copied: List[Dict[str, str]] = []
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
            source_path = self._resolve_project_storage_key(project_id=project_id, storage_key=storage_key, label="uploaded file")
            if not source_path.exists() or not source_path.is_file():
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"uploaded file not found in project storage: {storage_key}",
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
            "updated_at": datetime.fromtimestamp(stat.st_mtime, tz=UTC_PLUS_8).isoformat(),
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

    def _resolve_project_storage_key(self, *, project_id: str, storage_key: str, label: str) -> Path:
        storage_path = Path(str(storage_key or "").strip())
        if not storage_path.parts or storage_path.is_absolute() or ".." in storage_path.parts:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"invalid {label} storage_key")
        config = get_config()
        parts = storage_path.parts
        project_component = sanitize_name(project_id)
        if parts and parts[0] == config.fileserver_service.project_files_dirname:
            if len(parts) < 2 or parts[1] != project_component:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{label} escapes project root")
        data_mount_path = Path(config.fileserver_service.data_mount_path).resolve()
        project_root = self._project_files_root(project_id)
        candidates = [
            data_mount_path / storage_path,
            project_root / storage_path,
        ]
        for candidate in candidates:
            try:
                return self._ensure_path_within(path=candidate, root=project_root, label=label)
            except HTTPException:
                continue
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{label} escapes project root")

    def _resolve_dataflow_input_ref(self, *, project_id: str, ref: dict[str, Any], expected: str) -> Path:
        source = str(ref.get("source") or "project_filesystem").strip()
        if source in {"project_filesystem", "project_path", "project"}:
            project_root = self._project_files_root(project_id)
            normalized = self._normalize_project_path(str(ref.get("path") or ""))
            candidate = project_root / normalized.lstrip("/")
            resolved = self._ensure_path_within(path=candidate, root=project_root, label=expected)
        elif source in {"fileserver_storage", "storage_key", "managed_file"}:
            storage_key = str(ref.get("storage_key") or ref.get("path") or "").strip()
            if not storage_key:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{expected} storage_key is required")
            resolved = self._resolve_project_storage_key(project_id=project_id, storage_key=storage_key, label=expected)
        elif source in {"absolute", "absolute_path", "local_path"}:
            if not get_config().service.allow_absolute_input_refs:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{expected} absolute_path input is disabled")
            raw = str(ref.get("path") or "").strip()
            if not raw:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{expected} path is required")
            candidate = Path(raw)
            if not candidate.is_absolute():
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{expected} absolute path is required")
            resolved = self._ensure_path_within(path=candidate, root=self._project_files_root(project_id), label=expected)
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
        # Dataflow vulnerability scan tasks use the standard task-root layout:
        # <project>/app/secflow-app-dataflow-vuln-scanner/<task_id>/{input,output,run}.
        # User-provided workspace/output refs are treated as input metadata only
        # and must not move runtime or final artifacts outside the task root.
        return None, None

    def _default_dataflow_cli_runs_root(self, project_id: str) -> Path:
        config = get_config()
        return (
            Path(config.fileserver_service.data_mount_path)
            / config.fileserver_service.project_files_dirname
            / sanitize_name(project_id)
            / "app"
            / "secflow-app-dataflow-vuln-scanner"
        ).resolve()

    def _normalize_model_override(self, *, model: str | None, provider: str | None) -> str | None:
        model_text = str(model or "").strip()
        provider_text = str(provider or "").strip()
        if not model_text:
            return None
        if provider_text and "/" not in model_text:
            return f"{provider_text}/{model_text}"
        return model_text

    def _is_dataflow_cli_resume_request(self, request: dict[str, Any]) -> bool:
        return bool(str(request.get("resume_run_dir") or "").strip())

    def _resolve_dataflow_cli_runs_root(self, *, project_id: str, request: dict[str, Any]) -> Path:
        # Keep every dataflow-vuln task under the service task root. A
        # workspace_dir request may still be stored in input metadata, but it
        # must not redirect the task directory outside app/<service>/<task_id>.
        return ensure_dir(self._default_dataflow_cli_runs_root(project_id)).resolve()

    def _build_dataflow_cli_run_name(
        self,
        *,
        data_flow_path: Path,
        runs_root: Path,
        execution_id: str,
        requested_run_name: str | None = None,
    ) -> str:
        requested = str(requested_run_name or "").strip()
        if requested:
            base_name = _sanitize_dataflow_run_name(requested)
        else:
            base_name = f"{_sanitize_dataflow_run_name(data_flow_path.stem)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        run_name = base_name or f"dataflow_vuln_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        if not (runs_root / run_name).exists():
            return run_name
        fallback = f"{run_name}_{sanitize_name(execution_id)[-8:]}"
        if not (runs_root / fallback).exists():
            return fallback
        return f"{fallback}_{uuid.uuid4().hex[:6]}"

    def _build_dataflow_cli_resume_plan(
        self,
        *,
        project_id: str,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        raw_run_dir = str(request.get("resume_run_dir") or "").strip()
        if not raw_run_dir:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="resume_run_dir is required")
        candidate = Path(raw_run_dir)
        if not candidate.is_absolute():
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="resume_run_dir must be an absolute path")
        run_dir = self._ensure_path_within(
            path=candidate,
            root=self._project_files_root(project_id),
            label="resume_run_dir",
        )
        if not run_dir.is_dir():
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"resume_run_dir not found: {run_dir}")
        task_md_path = run_dir / "run" / "input" / "task.md"
        if not task_md_path.exists():
            task_md_path = run_dir / "input" / "task.md"
        return {
            "launcher": "run_vuln_scan.py",
            "mode": "resume",
            "run_name": run_dir.name,
            "runs_root": abs_path(run_dir.parent),
            "run_dir": abs_path(run_dir),
            "task_md_path": abs_path(task_md_path),
            "resume_run_dir": abs_path(run_dir),
            "extra_cycles": max(int(request.get("resume_extra_cycles") or 5), 1),
        }

    def _build_dataflow_cli_plan(
        self,
        *,
        project_id: str,
        request: dict[str, Any],
        execution_id: str,
    ) -> dict[str, Any]:
        if self._is_dataflow_cli_resume_request(request):
            return self._build_dataflow_cli_resume_plan(project_id=project_id, request=request)
        data_flow_ref = request.get("data_flow")
        source_dir_ref = request.get("source_dir")
        if not isinstance(data_flow_ref, dict) or not isinstance(source_dir_ref, dict):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="dataflow scan request is incomplete")
        if request.get("output_dir") is not None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="output_dir is not supported by run_vuln_scan.py launcher; final outputs are written to the task output directory",
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
        task_md_path = run_dir / "run" / "input" / "task.md"
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
        run_dir = Path(plan["run_dir"])
        task_md_path = Path(plan["task_md_path"])
        ensure_dir(task_md_path.parent)
        input_manifest = {
            "schema_version": 1,
            "generated_at": isoformat_local(now_local()),
            "task": {
                "task_id": plan.get("run_name"),
                "launcher": plan.get("launcher"),
                "mode": plan.get("mode") or "fresh",
            },
            "input": {},
            "prompt": {"task_md_path": abs_path(task_md_path)},
        }
        if plan.get("mode") == "resume":
            if not task_md_path.exists():
                write_text(
                    task_md_path,
                    (
                        "# Resume Existing Dataflow Vulnerability Scan\n\n"
                        f"- Run directory: `{plan['run_dir']}`\n"
                        f"- Extra cycles: `{plan.get('extra_cycles', 5)}`\n"
                    ),
                )
            input_manifest["input"] = {"resume_run_dir": plan.get("resume_run_dir")}
        else:
            from run_vuln_scan import generate_task_md
            task_content = generate_task_md(plan["data_flow_file"], plan["source_dir"]).strip() + "\n"
            write_text(
                task_md_path,
                task_content,
            )
            import hashlib
            input_manifest["input"] = {
                "data_flow_file": plan.get("data_flow_file"),
                "source_dir": plan.get("source_dir"),
            }
            input_manifest["prompt"].update({
                "content_length": len(task_content),
                "content_sha256": hashlib.sha256(task_content.encode("utf-8")).hexdigest(),
            })
        write_json(run_dir / "input" / "input_manifest.json", input_manifest)
        ensure_dir(run_dir / "output")

    def _dataflow_cli_config_requires_file(self, *, request: dict[str, Any], runtime_overrides: dict[str, Any]) -> bool:
        # worker_timeout/advisor_timeout are deprecated compatibility fields and
        # do not control RPC prompt timeout, so they must not force the launcher
        # onto a stale compiled -c config path. Only real runtime_overrides need
        # a temporary config file.
        return bool(runtime_overrides)

    def _build_dataflow_cli_argv(
        self,
        *,
        plan: dict[str, Any],
        config_payload: dict[str, Any],
        request: dict[str, Any],
        compiled_config: dict[str, Any],
        runtime_overrides: dict[str, Any],
        agent_state_dirs: dict[str, dict[str, str]],
    ) -> tuple[list[str], str | None]:
        if plan.get("mode") == "resume" or self._is_dataflow_cli_resume_request(request):
            argv = [
                "--resume-run-dir",
                plan["resume_run_dir"],
                "--extra-cycles",
                str(max(int(request.get("resume_extra_cycles") or plan.get("extra_cycles") or 5), 1)),
            ]
            model = self._normalize_model_override(
                model=str(request.get("model") or "").strip() or None,
                provider=str(request.get("provider") or "").strip() or None,
            )
            if model:
                argv.extend(["--model", model])
            if bool(request.get("clean_workspace")):
                argv.append("--clean")
            return argv, None

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

        def first_present_int(*values: Any, default: int) -> int:
            for value in values:
                if value is None or value == "":
                    continue
                return int(value)
            return default

        model = str(config_payload.get("model") or request.get("model") or "").strip()
        review_profile = str(config_payload.get("review_profile") or request.get("review_profile") or "balanced").strip() or "balanced"
        max_cycles = first_present_int(config_payload.get("max_review_cycles"), request.get("max_review_cycles"), default=0)
        agent_timeout_retry_enabled = request.get("agent_timeout_retry_enabled")
        if agent_timeout_retry_enabled is None:
            agent_timeout_retry_enabled = config_payload.get("agent_timeout_retry_enabled", True)
        agent_timeout_retry_enabled = bool(agent_timeout_retry_enabled)
        configured_timeout_max_retries = first_present_int(
            request.get("timeout_max_retries"),
            config_payload.get("timeout_max_retries"),
            request.get("agent_timeout_max_retries"),
            config_payload.get("agent_timeout_max_retries"),
            default=3,
        )
        timeout_max_retries = max(configured_timeout_max_retries, 1) if agent_timeout_retry_enabled else 1
        timeout_retry_interval_seconds = first_present_int(config_payload.get("timeout_retry_interval_seconds"), request.get("timeout_retry_interval_seconds"), default=30)
        result_review_concurrency = first_present_int(config_payload.get("result_review_concurrency"), request.get("result_review_concurrency"), default=3)

        if agent_state_dirs or self._dataflow_cli_config_requires_file(request=request, runtime_overrides=runtime_overrides):
            fd, temp_config_path = tempfile.mkstemp(prefix="secflow-dataflow-cli-", suffix=".json")
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json_payload = self._apply_agent_state_dirs_to_compiled_config(
                    compiled_config=compiled_config or {},
                    agent_state_dirs=agent_state_dirs,
                )
                apply_profile_runtime_policy_to_config(json_payload, review_profile)
                import json

                json.dump(json_payload, handle, ensure_ascii=False, indent=2)
            argv.extend(["--config", temp_config_path])
            argv.extend(["--timeout-max-retries", str(max(timeout_max_retries, 1))])
            argv.extend(["--timeout-retry-interval-seconds", str(max(timeout_retry_interval_seconds, 0))])
            return argv, temp_config_path

        if model:
            argv.extend(["--model", model])
        if max_cycles > 0:
            argv.extend(["--max-cycles", str(max_cycles)])
        argv.extend(["--timeout-max-retries", str(max(timeout_max_retries, 1))])
        argv.extend(["--timeout-retry-interval-seconds", str(max(timeout_retry_interval_seconds, 0))])
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

    def _materialize_dataflow_scan_inputs(self, *, materialized_input_dir: Path, metadata: Dict[str, Any]) -> tuple[str | None, Dict[str, Any]]:
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
        scan_input_dir = ensure_dir(materialized_input_dir / "dataflow_scan")
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
        project_id: str,
        input_tasks: List[TriggerTaskInputTask],
        workspace_root: Path,
        entry_input_task_type: str,
    ) -> List[TaskItem]:
        metadata_tasks_root = ensure_dir(workspace_root / "input" / "tasks")
        runtime_tasks_root = ensure_dir(workspace_root / "run" / "input" / "tasks")
        materialized_tasks_root = ensure_dir(workspace_root / "run" / "materialized_inputs" / "tasks")
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
            metadata_dir = ensure_dir(metadata_tasks_root / task_slug)
            runtime_input_dir = ensure_dir(runtime_tasks_root / task_slug)
            materialized_input_dir = ensure_dir(materialized_tasks_root / task_slug)
            metadata = dict(raw_task.metadata or {})
            markdown = raw_task.task_markdown
            if markdown is None and raw_task.task_md_path:
                markdown = Path(raw_task.task_md_path).read_text(encoding="utf-8")
            generated_markdown, materialized_inputs = self._materialize_dataflow_scan_inputs(
                materialized_input_dir=materialized_input_dir,
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
            task_content = markdown.strip() + "\n"
            task_md_path = write_text(runtime_input_dir / "task.md", task_content)
            copied_inputs = self._copy_uploaded_inputs_to_task_dir(
                project_id=project_id,
                task_input_dir=materialized_input_dir,
                metadata=metadata,
            )
            import hashlib

            write_json(
                metadata_dir / "task.json",
                {
                    "schema_version": 1,
                    "task_id": task_id,
                    "task_type": entry_input_task_type,
                    "title": raw_task.title,
                    "metadata": metadata,
                    "upstream_refs": raw_task.upstream_refs,
                    "task_md_path": abs_path(task_md_path),
                    "task_md_content_length": len(task_content),
                    "task_md_sha256": hashlib.sha256(task_content.encode("utf-8")).hexdigest(),
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
        task_file = write_text(workspace_root / "run" / "input" / "task.md", markdown.strip() + "\n")
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
            / "app"
            / "secflow-app-dataflow-vuln-scanner"
            / sanitize_name(trigger_id)
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
        now = now_local()
        execution.status = execution_status
        execution.message = message
        execution.finished_at = now
        execution.output_manifest_path = output_manifest_path
        execution.output_task_count = output_task_count
        execution.current_stage_id = None
        if execution.process_status in {"running", "stop_requested", "delete_requested"}:
            execution.process_status = "exited"
            execution.process_finished_at = now
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
            project_id=definition.project_id,
            input_tasks=raw_input_tasks,
            workspace_root=workspace_root,
            entry_input_task_type=validated_definition.resolve_entry_input_task_type(),
        )
        input_manifest_path = write_task_manifest(workspace_root / "input" / "tasks.json", normalized_tasks)
        write_json(
            workspace_root / "run" / "execution_meta.json",
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
        trigger.message = "pending start" if not recovery_reason else f"pending start: {recovery_reason}"
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
            message="pending start" if not recovery_reason else f"pending start: {recovery_reason}",
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
            task_origin_type=str(trigger_type if trigger_type == "binary_security" else "manual"),
            input_tasks_json=TaskManifest(tasks=[]).model_dump(mode="json"),
            priority=priority,
            status="pending",
            submitted_by=actor,
            retry_count=0,
            max_retry_count=definition.max_retry_count,
            latest_execution_id=None,
            message="pending start",
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
        )
        normalized_tasks = self._normalize_trigger_tasks(
            project_id=definition.project_id,
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
        request = {**request, "task_id": trigger.id}
        plan = self._build_dataflow_cli_plan(
            project_id=definition.project_id,
            request=request,
            execution_id=execution_id,
        )
        if plan.get("mode") == "resume" or self._is_dataflow_cli_resume_request(request):
            plan = {
                **plan,
                **self._resume_command_payload_from_plan(plan=plan, request=request),
            }
        metadata["dataflow_cli"] = plan
        self._write_dataflow_cli_task_preview(plan)
        if not str(metadata.get("task_title") or "").strip():
            metadata["task_title"] = plan["run_name"]
            task.title = plan["run_name"]
        task.task_md_path = plan["task_md_path"]
        task.metadata = metadata
        trigger.input_tasks_json = TaskManifest(tasks=[task, *manifest.tasks[1:]]).model_dump(mode="json")
        trigger.status = "pending"
        trigger.latest_execution_id = execution_id
        trigger.workflow_definition_version_id = definition_version.id
        trigger.profile_id = definition.id
        trigger.finished_at = None
        trigger.message = "pending start" if not recovery_reason else f"pending start: {recovery_reason}"
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
            message="pending start" if not recovery_reason else f"pending start: {recovery_reason}",
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
            task_purpose=self._normalize_task_purpose(payload.task_purpose),
            task_origin_type=str(payload.task_origin_type or "").strip() or "manual",
            parent_project_id=payload.parent_project_id,
            parent_task_id=payload.parent_task_id,
            parent_task_type=payload.parent_task_type,
            parent_stage_name=payload.parent_stage_name,
            parent_stage_item_id=payload.parent_stage_item_id,
            parent_stage_item_key=payload.parent_stage_item_key,
            input_tasks_json=TaskManifest(tasks=[]).model_dump(mode="json"),
            priority=priority,
            status="pending",
            submitted_by=actor,
            retry_count=0,
            max_retry_count=definition.max_retry_count,
            latest_execution_id=None,
            message="pending start",
        )
        db.add(trigger)
        db.flush()
        trigger.input_tasks_json = TaskManifest(
            tasks=[
                TaskItem(
                    task_id=_new_id("task"),
                    task_type="dataflow_vuln_scan_cli",
                    title=str(payload.title or "").strip() or "Pending dataflow vulnerability scan",
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

    def _run_mutation_response(
        self,
        *,
        run_id: str,
        project_id: str,
        status_text: str,
        message: str,
        linked_task_id: str | None,
        linked_execution_id: str | None,
        process_pid: int | None = None,
        process_host: str | None = None,
        process_signal: str | None = None,
    ) -> dict[str, Any]:
        return {
            "success": True,
            "run_id": run_id,
            "project_id": project_id,
            "status": status_text,
            "message": message,
            "linked_task_id": linked_task_id,
            "linked_execution_id": linked_execution_id,
            "process_pid": process_pid,
            "process_host": process_host,
            "process_signal": process_signal,
        }

    def _run_index_status_is_active(self, status_text: str | None) -> bool:
        return str(status_text or "").strip().lower() in _ACTIVE_RUN_INDEX_STATUSES

    def _adopted_run_index_task_status(self, status_text: str | None) -> str:
        value = str(status_text or "").strip().lower()
        if value in {"pending", "queued", "running", "cancel_requested", "delete_requested", "failed", "cancelled"}:
            return value
        if value == "orphaned":
            return "failed"
        if value in {"completed", "succeeded", "success", "passed"}:
            return "succeeded"
        if value in {"interrupted", "stopped"}:
            return "cancelled"
        if value in {
            "timeout",
            "error",
            "review_error",
            "review_plateau",
            "summary_incomplete",
            "runtime_output_limit",
            "runtime_timeout",
            "blocked_context_window",
            "blocked_quota",
            "provider_rate_limited",
            "model_contract_violation",
            "blocked_external_source",
            "no_workspace",
        }:
            return "failed"
        return value or "succeeded"

    def _run_index_output_manifest_path(self, run_index) -> str | None:
        atomic_work_path = str(run_index.atomic_work_path or "").strip()
        if not atomic_work_path:
            return None
        candidate = Path(atomic_work_path) / "_meta" / "results_manifest.json"
        return abs_path(candidate) if candidate.exists() else None

    def _run_index_task_md_path(self, run_index) -> str:
        candidate = Path(run_index.run_root_path) / "run" / "input" / "task.md"
        if not candidate.exists():
            candidate = Path(run_index.run_root_path) / "input" / "task.md"
        return abs_path(candidate)

    def _run_index_adoption_manifest(self, run_index) -> dict[str, Any]:
        return TaskManifest(
            tasks=[
                TaskItem(
                    task_id=_new_id("task"),
                    task_type="dataflow_vuln_scan_cli",
                    title=f"Run {run_index.run_name}",
                    task_md_path=self._run_index_task_md_path(run_index),
                    metadata={
                        "run_adoption": {
                            "run_id": run_index.id,
                            "source_type": run_index.source_type,
                            "run_root_path": run_index.run_root_path,
                            "adopted_at": isoformat_local(now_local()),
                        },
                        "runtime_overrides": {},
                        "task_title": f"Run {run_index.run_name}",
                    },
                    upstream_refs=[],
                )
            ]
        ).model_dump(mode="json")

    def _select_run_index_definition(self, db: Session, run_index, principal: dict) -> WorkflowDefinition:
        workflow_service = get_workflow_service()
        candidate_ids: list[str] = []
        if run_index.linked_task_id:
            try:
                trigger = self._trigger_or_404(db, run_index.linked_task_id)
                candidate_ids.append(trigger.workflow_definition_id)
            except HTTPException:
                pass
        if run_index.profile_id:
            candidate_ids.append(run_index.profile_id)
        for definition_id in candidate_ids:
            try:
                definition = workflow_service._get_definition_or_404(db, definition_id)
            except HTTPException:
                continue
            self._ensure_project_access(principal, definition.project_id)
            return definition
        return workflow_service.get_or_create_default_profile_model(db, run_index.project_id, principal)

    def _build_run_index_resume_request(self, *, run_index, payload: RunRetryRequest) -> dict[str, Any]:
        return {
            "launcher": "run_vuln_scan.py",
            "project_id": run_index.project_id,
            "resume_run_dir": run_index.run_root_path,
            "resume_extra_cycles": payload.extra_cycles,
            "model": self._normalize_model_override(model=payload.model, provider=payload.provider),
            "provider": None,
            "clean_workspace": payload.clean_workspace,
            "options": {
                "run_id": run_index.id,
                "resume": True,
            },
        }

    def _update_trigger_for_run_index_resume(
        self,
        *,
        trigger: TriggerTask,
        run_index,
        request: dict[str, Any],
    ) -> None:
        manifest = TaskManifest.model_validate(trigger.input_tasks_json)
        if manifest.tasks:
            first_task = manifest.tasks[0]
            remaining_tasks = list(manifest.tasks[1:])
        else:
            first_task = TaskItem(
                task_id=_new_id("task"),
                task_type="dataflow_vuln_scan_cli",
                title=f"Resume {run_index.run_name}",
                task_md_path="",
                metadata={},
                upstream_refs=[],
            )
            remaining_tasks = []
        extra_cycles = int(request.get("resume_extra_cycles") or 5)
        metadata = dict(first_task.metadata or {})
        metadata["dataflow_scan_request"] = request
        metadata["run_retry"] = {
            "run_id": run_index.id,
            "source_type": run_index.source_type,
            "requested_at": isoformat_local(now_local()),
            "extra_cycles": extra_cycles,
        }
        metadata["task_title"] = f"Resume {run_index.run_name}"
        first_task.task_type = "dataflow_vuln_scan_cli"
        first_task.title = f"Resume {run_index.run_name}"
        first_task.metadata = metadata
        trigger.input_tasks_json = TaskManifest(tasks=[first_task, *remaining_tasks]).model_dump(mode="json")
        trigger.message = f"pending start: resume requested (+{extra_cycles} cycles)"

    def _create_run_index_resume_task_record(
        self,
        db: Session,
        *,
        definition: WorkflowDefinition,
        definition_version: WorkflowDefinitionVersion,
        run_index,
        request: dict[str, Any],
        actor: str,
    ) -> tuple[TriggerTask, WorkflowExecution]:
        extra_cycles = int(request.get("resume_extra_cycles") or 5)
        trigger = TriggerTask(
            id=_new_id("tt"),
            workflow_definition_id=definition.id,
            workflow_definition_version_id=definition_version.id,
            profile_id=definition.id,
            project_id=definition.project_id,
            trigger_type="manual",
            input_tasks_json=TaskManifest(tasks=[]).model_dump(mode="json"),
            priority=definition.priority_default,
            status="pending",
            submitted_by=actor,
            retry_count=0,
            max_retry_count=definition.max_retry_count,
            latest_execution_id=None,
            message=f"pending start: resume requested (+{extra_cycles} cycles)",
        )
        db.add(trigger)
        db.flush()
        trigger.input_tasks_json = TaskManifest(
            tasks=[
                TaskItem(
                    task_id=_new_id("task"),
                    task_type="dataflow_vuln_scan_cli",
                    title=f"Resume {run_index.run_name}",
                    task_md_path=self._run_index_task_md_path(run_index),
                    metadata={
                        "dataflow_scan_request": request,
                        "run_retry": {
                            "run_id": run_index.id,
                            "source_type": run_index.source_type,
                            "requested_at": isoformat_local(now_local()),
                            "extra_cycles": extra_cycles,
                        },
                        "runtime_overrides": {},
                        "task_title": f"Resume {run_index.run_name}",
                    },
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
                recovery_reason="manual run resume requested",
        )
        return trigger, execution

    def create_scan_task(
        self,
        db: Session,
        payload: ScanTaskCreateRequest,
        principal: dict,
        *,
        authorization_token: str | None = None,
        extra_task_metadata: dict[str, Any] | None = None,
    ) -> ScanTaskResponse:
        self._ensure_project_access(principal, payload.project_id)
        workflow_service = get_workflow_service()
        definition = (
            workflow_service.get_or_create_default_profile_model(db, payload.project_id, principal)
            if not payload.profile_id
            else workflow_service._get_definition_or_404(db, payload.profile_id)
        )
        self._ensure_project_access(principal, definition.project_id)
        if definition.project_id != payload.project_id:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="profile_id belongs to a different project",
            )
        actor = _principal_id(principal)
        config_payload_overrides = {
            "model": payload.model,
            "review_profile": payload.review_profile,
            "max_review_cycles": payload.max_review_cycles,
            "agent_run_timeout_seconds": payload.agent_run_timeout_seconds,
            "agent_timeout_retry_enabled": payload.agent_timeout_retry_enabled,
            "agent_timeout_max_retries": payload.agent_timeout_max_retries,
            "worker_timeout": payload.worker_timeout,
            "advisor_timeout": payload.advisor_timeout,
            "timeout_max_retries": payload.timeout_max_retries,
            "timeout_retry_interval_seconds": payload.timeout_retry_interval_seconds,
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
        requested_title = str(payload.title or "").strip()
        metadata = {
            "artifact_refs": [item.model_dump(mode="json") for item in payload.artifact_refs],
            "task_input_uploads": self._artifact_uploads_from_refs(payload.artifact_refs),
            "runtime_overrides": payload.runtime_overrides,
            "task_purpose": self._normalize_task_purpose(payload.task_purpose),
            "agent_state_roots": {
                agent_id: item.model_dump(mode="json")
                for agent_id, item in (payload.agent_state_roots or {}).items()
            },
            "task_title": requested_title,
            "task_origin_type": str(payload.task_origin_type or "").strip() or "manual",
            "parent_project_id": payload.parent_project_id,
            "parent_task_id": payload.parent_task_id,
            "parent_task_type": payload.parent_task_type,
            "parent_stage_name": payload.parent_stage_name,
            "parent_stage_item_id": payload.parent_stage_item_id,
            "parent_stage_item_key": payload.parent_stage_item_key,
            "auto_report_vulnerabilities": bool(payload.auto_report_vulnerabilities),
        }
        if extra_task_metadata:
            metadata.update(dict(extra_task_metadata))
        if payload.data_flow and payload.source_dir:
            scan_options = dict(payload.scan_options or {})
            if requested_title:
                scan_options.setdefault("run_name", requested_title)
            metadata["dataflow_scan_request"] = {
                "launcher": "run_vuln_scan.py",
                "project_id": payload.project_id,
                "workspace_dir": payload.workspace_dir.model_dump(mode="json") if payload.workspace_dir else None,
                "data_flow": payload.data_flow.model_dump(mode="json"),
                "source_dir": payload.source_dir.model_dump(mode="json"),
                "output_dir": payload.output_dir.model_dump(mode="json") if payload.output_dir else None,
                "model": payload.model,
                "provider": payload.provider,
                "review_profile": payload.review_profile,
                "max_review_cycles": payload.max_review_cycles,
                "agent_run_timeout_seconds": payload.agent_run_timeout_seconds,
                "agent_timeout_retry_enabled": payload.agent_timeout_retry_enabled,
                "agent_timeout_max_retries": payload.agent_timeout_max_retries,
                "worker_timeout": payload.worker_timeout,
                "advisor_timeout": payload.advisor_timeout,
                "timeout_max_retries": payload.timeout_max_retries,
                "timeout_retry_interval_seconds": payload.timeout_retry_interval_seconds,
                "result_review_concurrency": payload.result_review_concurrency,
                "options": scan_options,
            }
        self._agent_state_dirs_from_metadata(
            project_id=payload.project_id,
            compiled_config=definition_version.compiled_config_json or definition_version.definition_json or definition.definition_json or {},
            metadata=metadata,
        )
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
                        title=requested_title or f"Task {datetime.now().strftime('%Y%m%d_%H%M%S')}",
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
            trigger.task_origin_type = str(payload.task_origin_type or "").strip() or "manual"
            trigger.task_purpose = self._normalize_task_purpose(payload.task_purpose)
            trigger.parent_project_id = payload.parent_project_id
            trigger.parent_task_id = payload.parent_task_id
            trigger.parent_task_type = payload.parent_task_type
            trigger.parent_stage_name = payload.parent_stage_name
            trigger.parent_stage_item_id = payload.parent_stage_item_id
            trigger.parent_stage_item_key = payload.parent_stage_item_key
        db.commit()
        db.refresh(trigger)
        latest_execution = self._latest_execution_for_trigger(db, trigger.id)
        if latest_execution is not None and self._trigger_uses_run_directory(trigger):
            self._ensure_run_index_for_execution(db, latest_execution, trigger)
            db.commit()
            db.refresh(trigger)
        if latest_execution is not None:
            self.record_event(
                db,
                execution_id=latest_execution.id,
                event_type="execution_queued",
                message="task start requested",
                payload_json={"task_id": trigger.id, "attempt_no": latest_execution.attempt_no},
            )
        return self._scan_task_response(db, trigger)

    def create_evolution_task(
        self,
        db: Session,
        *,
        source_task_id: str,
        payload: CreateEvolutionTaskRequest,
        principal: dict,
        authorization_token: str | None = None,
    ) -> ScanTaskResponse:
        source_trigger = self._trigger_or_404(db, source_task_id)
        self._ensure_project_access(principal, source_trigger.project_id)
        source_execution = self._latest_execution_for_trigger(db, source_trigger.id)
        create_payload, extra_metadata = self._build_evolution_create_payload(
            db=db,
            source_trigger=source_trigger,
            source_execution=source_execution,
            payload=payload,
        )
        created = self.create_scan_task(
            db,
            create_payload,
            principal,
            authorization_token=authorization_token,
            extra_task_metadata=extra_metadata,
        )
        if created.latest_execution_id:
            self.record_event(
                db,
                execution_id=created.latest_execution_id,
                event_type="task_evolution_created",
                message="evolution task created from normal source task",
                payload_json={
                    "source_task_id": source_trigger.id,
                    "source_execution_id": source_execution.id if source_execution is not None else None,
                    "source_run_id": extra_metadata.get("derivation", {}).get("source_run_id"),
                    "created_task_id": created.task_id,
                },
            )
        return created

    def get_task_replay_ready(self, db: Session, task_id: str, principal: dict) -> ReplayReadyResponse:
        trigger = self._trigger_or_404(db, task_id)
        self._ensure_project_access(principal, trigger.project_id)
        metadata = self._trigger_task_metadata(trigger)
        task_purpose = self._normalize_task_purpose(getattr(trigger, "task_purpose", None) or metadata.get("task_purpose"))
        latest_execution = self._latest_execution_for_trigger(db, trigger.id)
        latest_run = self._source_run_index_for_trigger(db, trigger, latest_execution)
        reason = None
        replay_ready = True
        if task_purpose != "normal":
            replay_ready = False
            reason = "only normal tasks can create evolution tasks"
        elif not self._is_dataflow_cli_task_metadata(metadata):
            replay_ready = False
            reason = "source task is not a run_vuln_scan.py launcher task"
        else:
            source_request = metadata.get("dataflow_scan_request") if isinstance(metadata.get("dataflow_scan_request"), dict) else {}
            if not isinstance(source_request.get("data_flow"), dict) or not isinstance(source_request.get("source_dir"), dict):
                replay_ready = False
                reason = "source task is missing reusable data_flow/source_dir inputs"
        task_payload = self._scan_task_response(db, trigger, include_run_summary=False)
        return ReplayReadyResponse(
            task_id=trigger.id,
            project_id=trigger.project_id,
            task_purpose=task_purpose,
            replay_ready=replay_ready,
            reason=reason,
            latest_execution_id=latest_execution.id if latest_execution is not None else None,
            latest_run_id=latest_run.id if latest_run is not None else None,
            agent_state_dirs=task_payload.agent_state_dirs,
        )

    def list_scan_tasks(
        self,
        db: Session,
        principal: dict,
        *,
        project_id: str | None = None,
        status_filter: str | None = None,
        profile_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
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
        safe_limit = max(1, min(int(limit or 100), 500))
        safe_offset = max(0, int(offset or 0))
        # Keep list rendering lightweight.  Full run indexing / filesystem
        # inspection can be expensive on NFS and previously made the async API
        # worker miss health probes under task-list load, producing nginx 502s.
        # The list only needs the run locator; detail/run endpoints hydrate the
        # full run summary on demand.
        return [self._scan_task_response(db, item, include_run_summary=False) for item in query.offset(safe_offset).limit(safe_limit).all()]

    def get_scan_task(self, db: Session, task_id: str, principal: dict) -> ScanTaskDetailResponse:
        trigger = self._trigger_or_404(db, task_id)
        self._ensure_project_access(principal, trigger.project_id)
        latest_execution = self._latest_execution_for_trigger(db, trigger.id)
        run_index = self._ensure_run_index_for_execution(db, latest_execution, trigger) if latest_execution is not None else None
        if self._reconcile_stale_runtime(db, run_index=run_index, trigger=trigger, execution=latest_execution):
            db.commit()
            db.refresh(trigger)
        return self._scan_task_detail(db, trigger)

    def get_scan_task_summary(self, db: Session, task_id: str, principal: dict) -> ScanTaskResponse:
        trigger = self._trigger_or_404(db, task_id)
        self._ensure_project_access(principal, trigger.project_id)
        latest_execution = self._latest_execution_for_trigger(db, trigger.id)
        run_index = self._ensure_run_index_for_execution(db, latest_execution, trigger) if latest_execution is not None else None
        if self._reconcile_stale_runtime(db, run_index=run_index, trigger=trigger, execution=latest_execution):
            db.commit()
            db.refresh(trigger)
        return self._scan_task_response(db, trigger)

    def _run_index_or_404(self, db: Session, run_index_id: str, principal: dict) -> Any:
        run_index = get_run_index_service()._run_index_or_404(db, run_index_id)
        self._ensure_project_access(principal, run_index.project_id)
        return run_index

    def list_runs(self, db: Session, principal: dict, *, project_id: str) -> list[dict[str, Any]]:
        self._ensure_project_access(principal, project_id)
        payloads = get_run_index_service().list_runs(db, project_id)
        enriched: list[dict[str, Any]] = []
        for payload in payloads:
            run_index = db.get(RunIndex, payload.get("run_id"))
            enriched.append(self._enrich_run_payload(db, run_index, payload) if run_index is not None else payload)
        return enriched

    def _run_index_resolve_response(self, run_index: RunIndex) -> dict[str, Any]:
        return {
            "run_id": run_index.id,
            "project_id": run_index.project_id,
            "run_name": run_index.run_name,
            "root_path": str(Path(run_index.run_root_path).resolve().parent),
            "source_type": run_index.source_type,
            "linked_task_id": run_index.linked_task_id,
            "linked_execution_id": run_index.linked_execution_id,
        }

    def resolve_run(self, db: Session, principal: dict, *, project_id: str, run_name: str, root_path: str) -> dict[str, Any]:
        self._ensure_project_access(principal, project_id)
        run_index = get_run_index_service().resolve_run(db, project_id=project_id, run_name=run_name, root_path=root_path)
        return self._run_index_resolve_response(run_index)

    def resolve_run_by_task(
        self,
        db: Session,
        principal: dict,
        *,
        project_id: str,
        task_id: str,
        execution_id: str | None = None,
    ) -> dict[str, Any]:
        self._ensure_project_access(principal, project_id)
        trigger = db.get(TriggerTask, task_id)
        if trigger is None or trigger.project_id != project_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="task not found")
        execution: WorkflowExecution | None = None
        if execution_id:
            execution = db.get(WorkflowExecution, execution_id)
            if (
                execution is None
                or execution.project_id != project_id
                or execution.trigger_task_id != task_id
            ):
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="execution not found for task")
        else:
            execution = self._latest_execution_for_trigger(db, task_id)
        get_run_index_service().sync_project_runs(db, project_id)
        query = db.query(RunIndex).filter(
            RunIndex.project_id == project_id,
            RunIndex.source_type == "execution_workspace",
            RunIndex.linked_task_id == task_id,
        )
        if execution_id:
            query = query.filter(RunIndex.linked_execution_id == execution_id)
        run_index = query.order_by(RunIndex.started_at.desc(), RunIndex.created_at.desc()).first()
        if run_index is not None and not Path(run_index.run_root_path).is_dir():
            run_index = None
        if run_index is None:
            run_index = self._ensure_run_index_for_execution(db, execution, trigger)
            if run_index is not None:
                db.commit()
        if run_index is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="run not found for task")
        return self._run_index_resolve_response(run_index)

    def get_run(self, db: Session, run_index_id: str, principal: dict) -> dict[str, Any]:
        run_index = self._run_index_or_404(db, run_index_id, principal)
        payload = get_run_index_service().get_run_detail(db, run_index)
        db.refresh(run_index)
        return self._enrich_run_payload(db, run_index, payload)

    def report_run_vulnerabilities(
        self,
        db: Session,
        run_index_id: str,
        principal: dict,
        result_files: list[str],
    ) -> dict[str, Any]:
        run_index = self._run_index_or_404(db, run_index_id, principal)
        trigger, execution = self._linked_run_index_runtime(db, run_index)
        if trigger is None or execution is None:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="run is not linked to a managed scan task")
        selected = [str(item or "").strip() for item in result_files if str(item or "").strip()]
        if not selected:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="result_files must not be empty")
        try:
            report_status = get_vuln_report_service().report_run_results(
                db,
                trigger=trigger,
                execution=execution,
                run_index=run_index,
                result_files=selected,
            )
        except Exception as exc:
            db.rollback()
            report_status = {"status": "failed", "enabled": True, "error": str(exc), "items": []}
        self.record_event(
            db,
            execution_id=execution.id,
            event_type="vuln_report_manual",
            message=f"manual vulnerability suspicion report {report_status.get('status', 'unknown')}",
            level="warning" if report_status.get("status") in {"failed", "partial_failed"} else "info",
            payload_json={**report_status, "result_files": selected},
        )
        return report_status

    def get_run_cycle(self, db: Session, run_index_id: str, cycle: int, principal: dict) -> dict[str, Any]:
        run_index = self._run_index_or_404(db, run_index_id, principal)
        return get_run_index_service().get_run_cycle(db, run_index, cycle)

    def list_run_sessions(self, db: Session, run_index_id: str, principal: dict) -> list[dict[str, Any]]:
        run_index = self._run_index_or_404(db, run_index_id, principal)
        return get_run_index_service().list_run_sessions(db, run_index)

    def list_run_files(self, db: Session, run_index_id: str, principal: dict, limit: int = 1200) -> list[dict[str, Any]]:
        run_index = self._run_index_or_404(db, run_index_id, principal)
        return get_run_index_service().list_run_files(db, run_index, limit=limit)

    def get_run_file(self, db: Session, run_index_id: str, principal: dict, path: str) -> dict[str, Any]:
        run_index = self._run_index_or_404(db, run_index_id, principal)
        return get_run_index_service().get_run_file(db, run_index, path)

    def get_run_session_file(self, db: Session, run_index_id: str, principal: dict, path: str) -> dict[str, Any]:
        run_index = self._run_index_or_404(db, run_index_id, principal)
        return get_run_index_service().get_run_session_file(db, run_index, path)

    def get_run_log(self, db: Session, run_index_id: str, principal: dict, lines: int = 300) -> dict[str, Any]:
        run_index = self._run_index_or_404(db, run_index_id, principal)
        return get_run_index_service().get_run_log(db, run_index, lines=lines)

    def _linked_run_index_runtime(self, db: Session, run_index) -> tuple[TriggerTask | None, WorkflowExecution | None]:
        trigger = db.get(TriggerTask, run_index.linked_task_id) if run_index.linked_task_id else None
        execution = db.get(WorkflowExecution, run_index.linked_execution_id) if run_index.linked_execution_id else None
        if trigger is None and execution is not None:
            trigger = db.get(TriggerTask, execution.trigger_task_id)
        if trigger is not None and (execution is None or execution.trigger_task_id != trigger.id):
            execution = self._latest_execution_for_trigger(db, trigger.id)
        return trigger, execution

    def _run_process_state(
        self,
        db: Session,
        run_index,
        *,
        trigger: TriggerTask | None = None,
        execution: WorkflowExecution | None = None,
    ) -> dict[str, Any]:
        trigger, execution = (trigger, execution) if (trigger is not None or execution is not None) else self._linked_run_index_runtime(db, run_index)
        checked_at = now_local()
        stale_after = self._process_heartbeat_stale_after_seconds()
        base: dict[str, Any] = {
            "checked_at": isoformat_local(checked_at) or "",
            "stale_after_seconds": stale_after,
            "run_status": str(run_index.status or ""),
            "trigger_task_id": trigger.id if trigger is not None else run_index.linked_task_id,
            "trigger_status": str(trigger.status or "") if trigger is not None else "",
            "execution_id": execution.id if execution is not None else run_index.linked_execution_id,
            "execution_status": str(execution.status or "") if execution is not None else "",
            "process_status": str(execution.process_status or "") if execution is not None else "",
            "can_retry": True,
            "is_running": False,
            "is_queued": False,
            "reason": "未发现活跃 run_vuln_scan.py 进程，可以重试",
            "source": "terminal_or_no_process",
        }

        run_status = str(run_index.status or "").strip().lower()
        trigger_status = str(trigger.status or "").strip().lower() if trigger is not None else ""
        execution_status = str(execution.status or "").strip().lower() if execution is not None else ""
        if run_status in _QUEUE_RUN_INDEX_STATUSES or trigger_status in _QUEUE_RUN_INDEX_STATUSES or execution_status in _QUEUE_RUN_INDEX_STATUSES:
            base.update(
                {
                    "can_retry": False,
                    "is_queued": True,
                    "reason": "该 Run 已有 pending/queued 的执行或 resume 请求，不能重复重试",
                    "source": "queued_execution",
                }
            )
            return base

        if execution is not None:
            local_process = self._local_cli_process(execution.id)
            if local_process is not None:
                base.update(
                    {
                        "can_retry": False,
                        "is_running": True,
                        "pid": local_process.pid,
                        "pod_id": get_config().scheduler.pod_id,
                        "reason": "当前 Pod 仍持有 run_vuln_scan.py 进程，不能重试；如需停止请先取消 Run",
                        "source": "local_process",
                    }
                )
                return base

        process_payload = self._read_run_process_file(run_index.run_root_path)
        if process_payload:
            heartbeat_at = self._parse_process_timestamp(
                process_payload.get("heartbeat_at")
                or process_payload.get("updated_at")
                or process_payload.get("started_at")
            )
            heartbeat_age = int(max((checked_at - heartbeat_at).total_seconds(), 0)) if heartbeat_at else None
            file_status = str(process_payload.get("status") or "").strip().lower()
            base.update(
                {
                    "pid": process_payload.get("pid"),
                    "pod_id": process_payload.get("pod_id") or "",
                    "process_file_status": file_status,
                    "process_file_execution_id": process_payload.get("execution_id") or "",
                    "heartbeat_at": process_payload.get("heartbeat_at") or process_payload.get("updated_at") or "",
                    "heartbeat_age_seconds": heartbeat_age,
                }
            )
            if file_status in {"running", "timeout_requested", "stop_requested", "delete_requested"}:
                if heartbeat_age is not None and heartbeat_age <= stale_after:
                    base.update(
                        {
                            "can_retry": False,
                            "is_running": True,
                            "reason": "共享心跳显示 run_vuln_scan.py 仍在运行，不能重试；如需停止请先取消 Run",
                            "source": "process_file_heartbeat",
                        }
                    )
                    return base
                base.update(
                    {
                        "can_retry": True,
                        "is_running": False,
                        "stale": True,
                        "display_status": "runtime_lost",
                        "display_label": "运行失联",
                        "severity": "warning",
                        "reason": "旧运行记录仍标记 active，但进程心跳已过期，可以通过 resume 重试",
                        "source": "stale_process_heartbeat",
                    }
                )
                return base

        if run_status in _ACTIVE_RUN_INDEX_STATUSES or trigger_status in _ACTIVE_RUN_INDEX_STATUSES or execution_status in _ACTIVE_RUN_INDEX_STATUSES:
            base.update(
                {
                    "can_retry": True,
                    "is_running": False,
                    "stale": True,
                    "display_status": "runtime_lost",
                    "display_label": "运行失联",
                    "severity": "warning",
                    "reason": "旧运行记录仍标记 active，但未发现本地进程或有效心跳，可以通过 resume 重试",
                    "source": "stale_active_record",
                }
            )
            return base

        return base

    def _enrich_run_payload(self, db: Session, run_index, payload: dict[str, Any]) -> dict[str, Any]:
        trigger, execution = self._linked_run_index_runtime(db, run_index)
        enriched = dict(payload)
        enriched["process_state"] = self._run_process_state(db, run_index, trigger=trigger, execution=execution)
        retry_command = self._retry_command_display(db, run_index=run_index, trigger=trigger, execution=execution)
        enriched["retry_command_display"] = retry_command or None
        if trigger is not None:
            task_payload = self._scan_task_response(db, trigger, include_run_summary=False)
            enriched["linked_task_purpose"] = task_payload.task_purpose
            enriched["linked_task_agent_state_dirs"] = {
                key: value.model_dump(mode="json")
                for key, value in task_payload.agent_state_dirs.items()
            }
        return enriched

    def _mark_stale_runtime_exited(
        self,
        db: Session,
        *,
        trigger: TriggerTask | None,
        execution: WorkflowExecution | None,
        message: str,
    ) -> None:
        now = now_local()
        if execution is not None and self._run_index_status_is_active(execution.status):
            execution.status = "failed"
            execution.message = message
            execution.finished_at = now
            execution.process_status = "exited"
            execution.process_finished_at = now
            db.add(execution)
        if trigger is not None and self._run_index_status_is_active(trigger.status):
            trigger.status = "failed"
            trigger.message = message
            trigger.finished_at = now
            db.add(trigger)
        db.flush()

    def _reconcile_stale_runtime(
        self,
        db: Session,
        *,
        run_index: RunIndex | None,
        trigger: TriggerTask | None,
        execution: WorkflowExecution | None,
    ) -> bool:
        if run_index is None or (trigger is None and execution is None):
            return False
        process_state = self._run_process_state(db, run_index, trigger=trigger, execution=execution)
        if not bool(process_state.get("stale")):
            return False

        execution_status = str(execution.status or "").strip().lower() if execution is not None else ""
        trigger_status = str(trigger.status or "").strip().lower() if trigger is not None else ""
        if execution_status not in _ACTIVE_RUN_INDEX_STATUSES and trigger_status not in _ACTIVE_RUN_INDEX_STATUSES:
            return False

        if execution_status in {"cancel_requested", "delete_requested"} or trigger_status in {"cancel_requested", "delete_requested"}:
            delete_requested = execution_status == "delete_requested" or trigger_status == "delete_requested"
            message = (
                "stale delete_requested runtime assumed stopped"
                if delete_requested
                else "stale cancel_requested runtime assumed cancelled"
            )
            if execution is not None and trigger is not None:
                self._set_terminal_state(
                    db,
                    execution=execution,
                    trigger=trigger,
                    execution_status="cancelled",
                    message=message,
                    output_manifest_path=execution.output_manifest_path,
                    output_task_count=int(execution.output_task_count or run_index.result_count or 0),
                )
            else:
                now = now_local()
                if execution is not None:
                    execution.status = "cancelled"
                    execution.message = message
                    execution.finished_at = now
                    execution.process_status = "exited"
                    execution.process_finished_at = now
                    db.add(execution)
                if trigger is not None:
                    trigger.status = "cancelled"
                    trigger.message = message
                    trigger.finished_at = now
                    db.add(trigger)
                db.flush()
            self._write_run_control_state(run_index.run_root_path, status_text="cancelled", message=message)
            get_run_index_service().sync_execution_run(db, execution)
            db.flush()
            if execution is not None:
                self.record_event(
                    db,
                    execution_id=execution.id,
                    event_type="execution_cancelled",
                    message=message,
                    level="warning",
                    payload_json={"reason": "stale_runtime_reconciled", "process_state": process_state},
                )
            return True

        message = "stale active runtime assumed failed"
        self._mark_stale_runtime_exited(
            db,
            trigger=trigger,
            execution=execution,
            message=message,
        )
        self._write_run_control_state(run_index.run_root_path, status_text="failed", message=message)
        get_run_index_service().sync_execution_run(db, execution)
        db.flush()
        if execution is not None:
            self.record_event(
                db,
                execution_id=execution.id,
                event_type="execution_failed",
                message=message,
                level="warning",
                payload_json={"reason": "stale_runtime_reconciled", "process_state": process_state},
            )
        return True

    def reconcile_stale_active_executions(self, db: Session, *, limit: int = 200) -> int:
        reconciled = 0
        rows = (
            db.query(WorkflowExecution)
            .filter(WorkflowExecution.status.in_(tuple(_ACTIVE_RUN_INDEX_STATUSES)))
            .order_by(WorkflowExecution.updated_at.asc())
            .limit(limit)
            .all()
        )
        for execution in rows:
            trigger = db.get(TriggerTask, execution.trigger_task_id)
            run_index = self._ensure_run_index_for_execution(db, execution, trigger)
            if self._reconcile_stale_runtime(
                db,
                run_index=run_index,
                trigger=trigger,
                execution=execution,
            ):
                reconciled += 1
                db.commit()
        return reconciled

    def _preflight_run_resume(self, *, run_index, payload: RunRetryRequest) -> dict[str, Any]:
        run_dir = Path(run_index.run_root_path)
        if not run_dir.is_dir():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="run directory not found")
        try:
            import run_vuln_scan as launcher
            from app.pi_vuln_core.resume import build_resume_plan, rebuild_review_state

            config_obj, plan = build_resume_plan(run_dir)
            review_state = rebuild_review_state(plan.atomic_work_dir)
            diagnostics = launcher._collect_resume_diagnostics(  # type: ignore[attr-defined]
                plan.atomic_work_dir,
                review_state=review_state,
            )
            current_model, current_thinking = launcher._extract_worker_runtime(config_obj)  # type: ignore[attr-defined]
            display_model = self._normalize_model_override(model=payload.model, provider=payload.provider) if payload.model else current_model
            display_thinking = launcher.resolve_profile_thinking(  # type: ignore[attr-defined]
                display_model,
                launcher._extract_review_profile_from_config_obj(config_obj),  # type: ignore[attr-defined]
            ) or current_thinking
            preview_path = launcher._write_resume_preview_file(  # type: ignore[attr-defined]
                run_dir=str(run_dir.resolve()),
                atomic_work_dir=plan.atomic_work_dir,
                current_status=plan.current_status or "unknown",
                completed_cycles=plan.completed_cycles,
                extra_cycles=payload.extra_cycles,
                worker_session_id=plan.worker_session_id,
                timeout_detected=plan.timeout_detected,
                timeout_call_dir=plan.timeout_call_dir,
                timeout_agent_id=plan.timeout_agent_id,
                timeout_error=plan.timeout_error,
                resume_state=plan.resume_state,
                checkpoint_cycle=plan.checkpoint_cycle,
                checkpoint_phase=plan.checkpoint_phase,
                checkpoint_step_key=plan.checkpoint_step_key,
                checkpoint_status=plan.checkpoint_status,
                resume_cursor=plan.resume_cursor,
                resume_start_cycle=plan.resume_start_cycle,
                resume_target_node={
                    "cycle": int((plan.resume_cursor or {}).get("cycle") or 0),
                    "phase": plan.resume_target_phase,
                    "step_key": plan.resume_target_step_key,
                    "node_kind": str((plan.resume_cursor or {}).get("node_kind") or ""),
                } if plan.resume_target_phase else None,
                node_resume_policy=plan.node_resume_policy,
                model_display=launcher._format_model_display(display_model),  # type: ignore[attr-defined]
                thinking=display_thinking,
                task_file=plan.task_file,
                diagnostics=diagnostics,
            )
            return {
                "preview_path": preview_path,
                "atomic_work_dir": plan.atomic_work_dir,
                "current_status": plan.current_status,
                "completed_cycles": plan.completed_cycles,
                "extra_cycles": payload.extra_cycles,
                "resume_start_cycle": plan.resume_start_cycle,
                "resume_total_cycle_limit": max(plan.completed_cycles, plan.resume_start_cycle) + payload.extra_cycles,
                "resume_cursor": plan.resume_cursor,
                "resume_target_node": {
                    "cycle": int((plan.resume_cursor or {}).get("cycle") or 0),
                    "phase": plan.resume_target_phase,
                    "step_key": plan.resume_target_step_key,
                    "node_kind": str((plan.resume_cursor or {}).get("node_kind") or ""),
                } if plan.resume_target_phase else None,
                "node_resume_policy": plan.node_resume_policy,
            }
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=422,
                detail=f"resume preflight failed: {exc}",
            ) from exc

    def _wait_until_execution_inactive(self, db: Session, execution_id: str, *, timeout_seconds: float) -> bool:
        deadline = time.monotonic() + max(timeout_seconds, 0.0)
        while True:
            db.expire_all()
            execution = db.get(WorkflowExecution, execution_id)
            if execution is None:
                return True
            if not self._run_index_status_is_active(execution.status):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.5)

    def _delete_linked_runtime_records(self, db: Session, *, linked_task_id: str | None, linked_execution_id: str | None) -> None:
        execution_ids: list[str] = []
        if linked_task_id:
            execution_ids = [
                item[0]
                for item in db.query(WorkflowExecution.id)
                .filter(WorkflowExecution.trigger_task_id == linked_task_id)
                .all()
            ]
        elif linked_execution_id:
            execution_ids = [linked_execution_id]
        if execution_ids:
            db.query(WorkflowExecutionEvent).filter(WorkflowExecutionEvent.execution_id.in_(execution_ids)).delete(synchronize_session=False)
            db.query(WorkflowExecution).filter(WorkflowExecution.id.in_(execution_ids)).delete(synchronize_session=False)
        if linked_task_id:
            trigger = db.get(TriggerTask, linked_task_id)
            if trigger is not None:
                db.delete(trigger)
        db.flush()

    def delete_run(self, db: Session, run_index_id: str, principal: dict) -> dict[str, Any]:
        run_index = self._run_index_or_404(db, run_index_id, principal)
        project_id = run_index.project_id
        run_name = run_index.run_name
        linked_task_id = run_index.linked_task_id
        linked_execution_id = run_index.linked_execution_id
        trigger, execution = self._linked_run_index_runtime(db, run_index)
        stop_payload: dict[str, Any] = {"signal": None}
        process_pid = execution.process_pid if execution is not None else None
        process_host = execution.process_host if execution is not None else None
        if execution is None and self._run_index_status_is_active(run_index.status):
            process_state = self._run_process_state(db, run_index, trigger=trigger, execution=execution)
            if process_state.get("is_running"):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="active run is not linked to a managed execution and still appears to be running; retry delete after it stops",
                )
        if execution is not None and execution.status == "pending":
            execution.status = "cancelled"
            execution.finished_at = now_local()
            execution.message = "deleted before dispatch"
            execution.process_status = "not_started"
            db.add(execution)
            if trigger is not None:
                trigger.status = "cancelled"
                trigger.finished_at = execution.finished_at
                trigger.message = "deleted before dispatch"
                db.add(trigger)
        elif execution is not None and self._run_index_status_is_active(execution.status):
            execution.status = "delete_requested"
            execution.message = "delete requested; stopping run_vuln_scan.py"
            execution.process_status = "delete_requested"
            db.add(execution)
            if trigger is not None:
                trigger.status = "delete_requested"
                trigger.message = "delete requested; stopping run_vuln_scan.py"
                db.add(trigger)
            run_index = get_run_index_service().bind_runtime_state(
                db,
                run_index,
                linked_execution=execution,
                linked_task=trigger,
                profile_id=run_index.profile_id,
                status_text="delete_requested",
            )
            self._write_run_control_state(run_index.run_root_path, status_text="delete_requested", message="delete requested")
            db.commit()
            stop_payload = self._signal_local_cli_process(execution.id, wait=True)
            process_pid = stop_payload.get("pid") or process_pid
            if stop_payload.get("exit_code") is not None or stop_payload.get("signal") == "already_exited":
                if trigger is not None:
                    self._set_terminal_state(
                        db,
                        execution=execution,
                        trigger=trigger,
                        execution_status="cancelled",
                        message="run_vuln_scan.py stopped for delete",
                    )
                else:
                    execution.status = "cancelled"
                    execution.message = "run_vuln_scan.py stopped for delete"
                    execution.finished_at = now_local()
                    execution.process_status = "exited"
                    execution.process_finished_at = now_local()
                    db.add(execution)
                db.commit()
            else:
                stopped = self._wait_until_execution_inactive(db, execution.id, timeout_seconds=45)
                if not stopped:
                    db.expire_all()
                    run_index = db.get(type(run_index), run_index_id)
                    if run_index is None:
                        return self._run_mutation_response(
                            run_id=run_index_id,
                            project_id=project_id,
                            status_text="deleted",
                            message=f"Run {run_name} deleted",
                            linked_task_id=linked_task_id,
                            linked_execution_id=linked_execution_id,
                            process_pid=process_pid,
                            process_host=process_host,
                            process_signal=stop_payload.get("signal"),
                        )
                    trigger, execution = self._linked_run_index_runtime(db, run_index)
                    process_state = self._run_process_state(db, run_index, trigger=trigger, execution=execution)
                    if process_state.get("is_running"):
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail="run deletion requested but run_vuln_scan.py is still stopping; retry delete shortly",
                        )
                    self._mark_stale_runtime_exited(
                        db,
                        trigger=trigger,
                        execution=execution,
                        message="stale delete_requested run assumed stopped during delete",
                    )
                    db.commit()
            db.expire_all()
            run_index = db.get(type(run_index), run_index_id)
            if run_index is None:
                return self._run_mutation_response(
                    run_id=run_index_id,
                    project_id=project_id,
                    status_text="deleted",
                    message=f"Run {run_name} deleted",
                    linked_task_id=linked_task_id,
                    linked_execution_id=linked_execution_id,
                    process_pid=process_pid,
                    process_host=process_host,
                    process_signal=stop_payload.get("signal"),
                )
        self._delete_linked_runtime_records(db, linked_task_id=linked_task_id, linked_execution_id=linked_execution_id)
        get_run_index_service().delete_run_index(db, run_index, allow_active=True)
        db.commit()
        return self._run_mutation_response(
            run_id=run_index_id,
            project_id=project_id,
            status_text="deleted",
            message=f"Run {run_name} deleted",
            linked_task_id=linked_task_id,
            linked_execution_id=linked_execution_id,
            process_pid=process_pid,
            process_host=process_host,
            process_signal=stop_payload.get("signal"),
        )

    def adopt_run(self, db: Session, run_index_id: str, principal: dict) -> dict[str, Any]:
        run_index = self._run_index_or_404(db, run_index_id, principal)
        run_root = Path(run_index.run_root_path)
        if not run_root.is_dir():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="run directory not found")

        trigger = db.get(TriggerTask, run_index.linked_task_id) if run_index.linked_task_id else None
        execution = db.get(WorkflowExecution, run_index.linked_execution_id) if run_index.linked_execution_id else None
        if trigger is None and execution is not None:
            trigger = db.get(TriggerTask, execution.trigger_task_id)
        if trigger is not None and execution is not None and execution.trigger_task_id != trigger.id:
            execution = None
        if trigger is not None and execution is None:
            execution = self._latest_execution_for_trigger(db, trigger.id)

        definition = self._select_run_index_definition(db, run_index, principal)
        definition_version = get_workflow_service().get_profile_version_model(db, definition.id)
        actor = _principal_id(principal)
        task_status = self._adopted_run_index_task_status(run_index.status)
        active = self._run_index_status_is_active(run_index.status)
        started_at = run_index.started_at
        finished_at = None if active else (run_index.finished_at or run_index.last_activity_at)
        adoption_message = f"adopted Run {run_index.run_name}"

        if trigger is None:
            trigger = TriggerTask(
                id=_new_id("tt"),
                workflow_definition_id=definition.id,
                workflow_definition_version_id=definition_version.id,
                profile_id=definition.id,
                project_id=run_index.project_id,
                trigger_type="manual",
                input_tasks_json=self._run_index_adoption_manifest(run_index),
                priority=definition.priority_default,
                status=task_status,
                submitted_by=actor,
                retry_count=0,
                max_retry_count=definition.max_retry_count,
                latest_execution_id=None,
                started_at=started_at,
                finished_at=finished_at,
                message=adoption_message,
            )
        else:
            self._ensure_project_access(principal, trigger.project_id)
            trigger.workflow_definition_id = definition.id
            trigger.workflow_definition_version_id = definition_version.id
            trigger.profile_id = definition.id
            trigger.project_id = run_index.project_id
            trigger.input_tasks_json = self._run_index_adoption_manifest(run_index)
            trigger.status = task_status
            trigger.started_at = started_at
            trigger.finished_at = finished_at
            trigger.message = adoption_message
        db.add(trigger)
        db.flush()

        if execution is None:
            execution = WorkflowExecution(
                id=_new_id("exec"),
                trigger_task_id=trigger.id,
                workflow_definition_id=definition.id,
                workflow_definition_version_id=definition_version.id,
                project_id=run_index.project_id,
                attempt_no=(
                    db.query(WorkflowExecution)
                    .filter(WorkflowExecution.trigger_task_id == trigger.id)
                    .count()
                ) + 1,
                status=task_status,
                recovery_reason="run adopted",
                workspace_root=abs_path(run_root),
                output_manifest_path=self._run_index_output_manifest_path(run_index),
                output_task_count=run_index.result_count,
                started_at=started_at,
                finished_at=finished_at,
                message=adoption_message,
            )
        else:
            self._ensure_project_access(principal, execution.project_id)
            execution.trigger_task_id = trigger.id
            execution.workflow_definition_id = definition.id
            execution.workflow_definition_version_id = definition_version.id
            execution.project_id = run_index.project_id
            execution.status = task_status
            execution.recovery_reason = execution.recovery_reason or "run adopted"
            execution.workspace_root = abs_path(run_root)
            execution.output_manifest_path = self._run_index_output_manifest_path(run_index)
            execution.output_task_count = run_index.result_count
            execution.started_at = started_at
            execution.finished_at = finished_at
            execution.message = adoption_message
        db.add(execution)
        db.flush()

        trigger.latest_execution_id = execution.id
        db.add(trigger)
        run_index = get_run_index_service().bind_runtime_state(
            db,
            run_index,
            linked_execution=execution,
            linked_task=trigger,
            profile_id=definition.id,
            status_text=run_index.status,
        )
        db.commit()
        self.record_event(
            db,
            execution_id=execution.id,
            event_type="run_adopted",
            message=adoption_message,
            payload_json={
                "run_id": run_index.id,
                "project_id": run_index.project_id,
                "run_root_path": run_index.run_root_path,
            },
        )
        return self._run_mutation_response(
            run_id=run_index.id,
            project_id=run_index.project_id,
            status_text=run_index.status,
            message=adoption_message,
            linked_task_id=trigger.id,
            linked_execution_id=execution.id,
        )

    def cancel_run(self, db: Session, run_index_id: str, principal: dict) -> dict[str, Any]:
        run_index = self._run_index_or_404(db, run_index_id, principal)
        if run_index.linked_task_id:
            self.cancel_scan_task(db, run_index.linked_task_id, principal, signal_process=False)
            trigger = self._trigger_or_404(db, run_index.linked_task_id)
            latest_execution = self._latest_execution_for_trigger(db, trigger.id)
            stop_payload = (
                self._signal_local_cli_process(latest_execution.id, wait=False)
                if latest_execution is not None and latest_execution.status in {"running", "cancel_requested"}
                else {"signal": None}
            )
            status_text = "cancel_requested"
            message = "Run cancel requested"
            if latest_execution is None or latest_execution.status == "cancelled":
                status_text = "cancelled"
                message = "Run cancelled before dispatch"
            elif latest_execution.status == "pending":
                status_text = "cancelled"
                message = "Run cancelled before dispatch"
            self._write_run_control_state(run_index.run_root_path, status_text=status_text, message=message)
            run_index = get_run_index_service().bind_runtime_state(
                db,
                run_index,
                linked_execution=latest_execution,
                linked_task=trigger,
                profile_id=run_index.profile_id,
                status_text=status_text,
            )
            db.commit()
            return self._run_mutation_response(
                run_id=run_index.id,
                project_id=run_index.project_id,
                status_text=run_index.status,
                message=message,
                linked_task_id=run_index.linked_task_id,
                linked_execution_id=run_index.linked_execution_id,
                process_pid=stop_payload.get("pid") or (latest_execution.process_pid if latest_execution else None),
                process_host=latest_execution.process_host if latest_execution else None,
                process_signal=stop_payload.get("signal"),
            )
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="run is not managed by a cancellable execution")

    def retry_run(
        self,
        db: Session,
        run_index_id: str,
        principal: dict,
        payload: RunRetryRequest,
    ) -> dict[str, Any]:
        run_index = self._run_index_or_404(db, run_index_id, principal)
        run_index = get_run_index_service().refresh_run_index(db, run_index)
        run_root = Path(run_index.run_root_path)
        if not run_root.is_dir():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="run directory not found")

        trigger, latest_execution = self._linked_run_index_runtime(db, run_index)
        process_state = self._run_process_state(db, run_index, trigger=trigger, execution=latest_execution)
        if not bool(process_state.get("can_retry")):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(process_state.get("reason") or "run_vuln_scan.py is still active; cannot retry"),
            )
        preflight = self._preflight_run_resume(run_index=run_index, payload=payload)
        self._mark_stale_runtime_exited(
            db,
            trigger=trigger,
            execution=latest_execution,
            message="previous run_vuln_scan.py process is no longer active; retrying via resume",
        )

        definition = self._select_run_index_definition(db, run_index, principal)
        workflow_service = get_workflow_service()
        definition_version = workflow_service.get_profile_version_model(db, definition.id)
        request = self._build_run_index_resume_request(run_index=run_index, payload=payload)
        actor = _principal_id(principal)

        trigger = db.get(TriggerTask, run_index.linked_task_id) if run_index.linked_task_id else None
        if trigger is not None:
            self._ensure_project_access(principal, trigger.project_id)
            self._update_trigger_for_run_index_resume(trigger=trigger, run_index=run_index, request=request)
            db.add(trigger)
            execution = self._create_dataflow_cli_execution_attempt(
                db,
                trigger=trigger,
                definition=definition,
                definition_version=definition_version,
                actor=actor,
                recovery_reason="manual run resume requested",
            )
        else:
            trigger, execution = self._create_run_index_resume_task_record(
                db,
                definition=definition,
                definition_version=definition_version,
                run_index=run_index,
                request=request,
                actor=actor,
            )

        run_index = get_run_index_service().bind_runtime_state(
            db,
            run_index,
            linked_execution=execution,
            linked_task=trigger,
            profile_id=definition.id,
            status_text="queued",
        )
        db.commit()
        self.record_event(
            db,
            execution_id=execution.id,
            event_type="run_resume_queued",
            message="manual run resume requested",
            payload_json={
                "run_id": run_index.id,
                "project_id": run_index.project_id,
                "run_root_path": run_index.run_root_path,
                "extra_cycles": payload.extra_cycles,
                "resume_preflight": preflight,
            },
        )
        return self._run_mutation_response(
            run_id=run_index.id,
            project_id=run_index.project_id,
            status_text=run_index.status,
            message="Run resume started",
            linked_task_id=trigger.id,
            linked_execution_id=execution.id,
        )

    def cancel_scan_task(self, db: Session, task_id: str, principal: dict, *, signal_process: bool = True) -> ScanTaskResponse:
        trigger = self._trigger_or_404(db, task_id)
        self._ensure_project_access(principal, trigger.project_id)
        latest_execution = self._latest_execution_for_trigger(db, trigger.id)
        now = now_local()
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
                latest_execution.process_status = "stop_requested"
                db.add(latest_execution)
        else:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="task is not cancelable")
        db.add(trigger)
        db.commit()
        if signal_process and latest_execution is not None:
            self._write_run_control_state(latest_execution.workspace_root, status_text=trigger.status, message=trigger.message or "cancel requested")
            if latest_execution.status in {"running", "cancel_requested"}:
                self._signal_local_cli_process(latest_execution.id, wait=False)
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
        run_index_ids: set[str] = set()
        workspace_roots: set[str] = set()
        for execution in executions:
            if execution.workspace_root:
                workspace_roots.add(execution.workspace_root)
            run_index = get_run_index_service().get_run_index_by_execution(db, execution) if execution.workspace_root else None
            if run_index:
                run_index_ids.add(run_index.id)
                if run_index.run_root_path:
                    workspace_roots.add(run_index.run_root_path)

        if run_index_ids:
            db.query(RunIndexFile).filter(RunIndexFile.run_index_id.in_(list(run_index_ids))).delete(synchronize_session=False)
            db.query(RunIndexSession).filter(RunIndexSession.run_index_id.in_(list(run_index_ids))).delete(synchronize_session=False)
            db.query(RunIndexRemovedResult).filter(RunIndexRemovedResult.run_index_id.in_(list(run_index_ids))).delete(synchronize_session=False)
            db.query(RunIndexResultReview).filter(RunIndexResultReview.run_index_id.in_(list(run_index_ids))).delete(synchronize_session=False)
            db.query(RunIndexResult).filter(RunIndexResult.run_index_id.in_(list(run_index_ids))).delete(synchronize_session=False)
            db.query(RunIndexGlobalReview).filter(RunIndexGlobalReview.run_index_id.in_(list(run_index_ids))).delete(synchronize_session=False)
            db.query(RunIndexCycle).filter(RunIndexCycle.run_index_id.in_(list(run_index_ids))).delete(synchronize_session=False)
            db.query(RunIndex).filter(RunIndex.id.in_(list(run_index_ids))).delete(synchronize_session=False)

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
        safe_payload = jsonable_encoder(payload_json or {})
        event = WorkflowExecutionEvent(
            id=_new_id("evt"),
            execution_id=execution_id,
            event_type=event_type,
            stage_id=stage_id,
            round_no=round_no,
            level=level,
            message=message,
            payload_json=safe_payload,
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event

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
        self._register_cli_process(execution.id, process)
        now = now_local()
        execution.process_pid = int(process.pid)
        execution.process_host = get_config().scheduler.pod_id
        execution.process_status = "running"
        execution.process_started_at = now
        execution.process_finished_at = None
        db.add(execution)
        db.commit()
        self._try_write_cli_process_file(
            execution=execution,
            trigger=trigger,
            cmd=cmd,
            process=process,
            status_text="running",
        )
        self.record_event(
            db,
            execution_id=execution.id,
            event_type="run_vuln_scan_process_started",
            message=f"run_vuln_scan.py process started pid={process.pid}",
            payload_json={
                "pid": process.pid,
                "pod_id": get_config().scheduler.pod_id,
                "host_name": get_config().scheduler.host_name,
                "command": cmd,
            },
        )
        try:
            while process.poll() is None:
                time.sleep(max(1, int(get_config().service.execution_cancel_check_interval_seconds)))
                self._try_write_cli_process_file(
                    execution=execution,
                    trigger=trigger,
                    cmd=cmd,
                    process=process,
                    status_text="running",
                )
                db.expire(execution)
                db.expire(trigger)
                if execution.status in {"cancel_requested", "delete_requested"} or trigger.status in {"cancel_requested", "delete_requested"}:
                    execution.process_status = "delete_requested" if execution.status == "delete_requested" or trigger.status == "delete_requested" else "stop_requested"
                    db.add(execution)
                    db.commit()
                    self._try_write_cli_process_file(
                        execution=execution,
                        trigger=trigger,
                        cmd=cmd,
                        process=process,
                        status_text=execution.process_status,
                    )
                    try:
                        process.send_signal(signal.SIGINT)
                    except ProcessLookupError:
                        return int(process.returncode or 0)
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
            self._forget_cli_process(execution.id, process)
            try:
                execution.process_status = "exited"
                execution.process_finished_at = now_local()
                db.add(execution)
                db.commit()
                self._try_write_cli_process_file(
                    execution=execution,
                    trigger=trigger,
                    cmd=cmd,
                    process=process,
                    status_text="exited",
                    return_code=process.returncode,
                )
            except Exception:
                db.rollback()

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
            execution.started_at = now_local()
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
        agent_state_dirs = self._agent_state_dirs_from_metadata(
            project_id=trigger.project_id,
            compiled_config=compiled_config,
            metadata=metadata,
        )
        self._ensure_agent_state_dirs(agent_state_dirs)
        temp_config_path: str | None = None
        argv: list[str] = []
        try:
            argv, temp_config_path = self._build_dataflow_cli_argv(
                plan=plan,
                config_payload=config_payload,
                request=request,
                compiled_config=compiled_config,
                runtime_overrides=runtime_overrides,
                agent_state_dirs=agent_state_dirs,
            )
            command = [sys.executable, str(Path(__file__).resolve().parents[2] / "run_vuln_scan.py"), *argv]
            metadata["dataflow_cli"] = {
                **plan,
                "agent_state_dirs": agent_state_dirs,
                "argv": argv,
                "command": command,
                "command_display": _command_display(command),
                "launch_mode": launcher_mode,
            }
            self._update_trigger_cli_task(trigger=trigger, metadata=metadata, task_md_path=plan["task_md_path"])
            db.add(trigger)
            db.commit()
            get_run_index_service().sync_execution_run(db, execution)
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
            invoke_kwargs: dict[str, Any] = {
                "argv": argv,
                "db": db,
                "execution": execution,
                "trigger": trigger,
            }
            exit_code = self._invoke_run_vuln_scan_cli(**invoke_kwargs)
            db.refresh(execution)
            db.refresh(trigger)
            run_index = get_run_index_service().sync_execution_run(db, execution)
            output_summary = run_dir / "output" / "execution_summary.json"
            output_manifest = run_dir / "output" / "tasks.json"
            output_manifest_path = output_manifest if output_manifest.is_file() else output_summary if output_summary.is_file() else None
            if exit_code == 0:
                terminal_status = "succeeded"
                message = "run_vuln_scan.py completed"
            elif (
                exit_code in {130, -signal.SIGINT, -signal.SIGTERM, -signal.SIGKILL}
                or execution.status in {"cancel_requested", "delete_requested"}
                or trigger.status in {"cancel_requested", "delete_requested"}
            ):
                terminal_status = "cancelled"
                message = "run_vuln_scan.py stopped for delete" if execution.status == "delete_requested" or trigger.status == "delete_requested" else "run_vuln_scan.py cancelled"
            elif exit_code == 124:
                terminal_status = "failed"
                message = "run_vuln_scan.py exited with timeout code 124"
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
                output_task_count=int(run_index.result_count if run_index else 0),
            )
            db.commit()
            get_run_index_service().sync_execution_run(db, execution)
            db.commit()
            report_status = {}
            if terminal_status == "succeeded":
                try:
                    run_index = get_run_index_service().get_run_index_by_execution(db, execution)
                    report_status = get_vuln_report_service().report_execution_results(
                        db,
                        trigger=trigger,
                        execution=execution,
                        run_index=run_index,
                    )
                except Exception as exc:
                    db.rollback()
                    report_status = {"status": "failed", "enabled": True, "error": str(exc)}
                self.record_event(
                    db,
                    execution_id=execution.id,
                    event_type="vuln_report_finished",
                    message=f"vulnerability suspicion auto-report {report_status.get('status', 'unknown')}",
                    level="warning" if report_status.get("status") in {"failed", "partial_failed"} else "info",
                    payload_json=report_status,
                )
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
                    "vuln_report_status": report_status,
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
            agent_state_dirs = self._agent_state_dirs_from_metadata(
                project_id=trigger.project_id,
                compiled_config=compiled_config,
                metadata=task_metadata,
            )
            self._ensure_agent_state_dirs(agent_state_dirs)
            compiled_config = self._apply_agent_state_dirs_to_compiled_config(
                compiled_config=compiled_config,
                agent_state_dirs=agent_state_dirs,
            )
            workspace_root = Path(execution.workspace_root) if execution.workspace_root else self._build_workspace_root(execution.id, definition)
            input_manifest_path = workspace_root / "input" / "tasks.json"
            if not input_manifest_path.exists():
                input_manifest_path = write_task_manifest(input_manifest_path, TaskManifest.model_validate(trigger.input_tasks_json).tasks)

            execution.workspace_root = abs_path(workspace_root)
            execution.message = "execution running"
            if execution.started_at is None:
                execution.started_at = now_local()
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
            runtime_root = ensure_dir(workspace_root / "run")
            runtime_workspace_root = ensure_dir(runtime_root / "workspace")
            runtime_config = build_runtime_framework_config(
                compiled_config,
                workspace_root=abs_path(runtime_workspace_root),
                execution_id=execution.id,
                input_task_file=entry_task_file,
                input_task_id=service_manifest.tasks[0].task_id,
                output_dir=abs_path(custom_output_dir or (workspace_root / "output")),
                summary_file=abs_path((custom_output_dir or (workspace_root / "output")) / "execution_summary.json"),
                runtime_mode=launcher_mode,
            )
            write_json(runtime_root / "config.json", runtime_config.model_dump(mode="json"))
            write_json(
                runtime_root / "_meta" / "run_timestamps.json",
                {
                    "started_at": isoformat_local(now_local()),
                    "status": "running",
                    "last_mode": launcher_mode,
                    "last_updated_at": isoformat_local(now_local()),
                },
            )
            get_run_index_service().sync_execution_run(db, execution)
            db.commit()
            log_path = attach_log_file(abs_path(runtime_root / "run.log"))
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
            recorder = DbExecutionRecorder(abs_path(runtime_workspace_root), execution.id)
            ensure_event_loop_policy()
            try:
                sync_providers_to_pi()
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
                workspace_root / "run" / "_meta" / "run_timestamps.json",
                {
                    "started_at": isoformat_local(execution.started_at or trigger.started_at or now_local()),
                    "finished_at": isoformat_local(now_local()),
                    "status": execution.status,
                    "exit_code": 0 if artifacts.result.success else 1,
                    "last_mode": launcher_mode,
                    "last_updated_at": isoformat_local(now_local()),
                },
            )
            get_run_index_service().sync_execution_run(db, execution)
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
                        workspace_root / "run" / "_meta" / "run_timestamps.json",
                        {
                            "started_at": isoformat_local(execution.started_at or trigger.started_at or now_local()),
                            "finished_at": isoformat_local(now_local()),
                            "status": "cancelled",
                            "exit_code": 130,
                            "last_mode": launcher_mode,
                            "last_updated_at": isoformat_local(now_local()),
                        },
                    )
                    get_run_index_service().sync_execution_run(db, execution)
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
                    workspace_root / "run" / "_meta" / "run_timestamps.json",
                    {
                        "started_at": isoformat_local(execution.started_at or trigger.started_at or now_local()),
                        "finished_at": isoformat_local(now_local()),
                        "status": "failed",
                        "exit_code": 1,
                        "last_mode": launcher_mode,
                        "last_updated_at": isoformat_local(now_local()),
                    },
                )
                get_run_index_service().sync_execution_run(db, execution)
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
