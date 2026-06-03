from __future__ import annotations

import json
import subprocess
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from fastapi import HTTPException, status

from app.core.config import get_config
from app.core.ids import new_attempt_id, new_task_id
from app.core.time_utils import utc_now_z
from app.db.database import DatabaseConnection, DatabaseRow, get_database
from app.schemas import (
    ArtifactListResponse,
    AttemptDetailResponse,
    AttemptWorkerResponse,
    EventPageResponse,
    GraphValidateRequest,
    GraphValidateResponse,
    InputRef,
    PagedTaskResponse,
    StageLogResponse,
    StageRunResponse,
    SuccessResponse,
    TaskCreateRequest,
    TaskDetailResponse,
    TaskRetryRequest,
    TaskSummaryResponse,
)
from app.services.artifact_service import get_artifact_service
from app.services.catalog_service import get_catalog_service
from app.services.event_service import get_event_service
from app.services.provider_client import ProviderClientError
from app.services.provider_runtime import get_provider_runtime_service
from app.services.workspace_service import get_workspace_service
from app.workers.poc_runtime import build_in_container_qemu_runtime, build_poc_qemu_instance_name
from app.workers.runner import (
    StageContext,
    build_agentflow_process_env_and_summary,
    normalize_attempt_relative_path,
    read_json_file,
    resolve_attempt_relative_path,
    resolve_stage_work_dir,
)

ACTIVE_TASK_STATUSES = {"queued", "running", "cancel_requested"}
ACTIVE_ATTEMPT_STATUSES = {"queued", "claimed", "running", "cancel_requested"}
TERMINAL_TASK_STATUSES = {"succeeded", "partial_success", "failed", "cancelled", "needs_attention"}


@dataclass(frozen=True)
class ResolvedStageSessionSource:
    normalized_path: PurePosixPath
    source_path: Path


class TaskService:
    def create_task(self, payload: TaskCreateRequest, subject) -> TaskSummaryResponse:
        normalized = get_workspace_service().validate_input(payload.workspace_id, payload.input_ref)
        workspace = get_workspace_service().get_workspace(payload.workspace_id)
        if payload.input_ref.kind == "preset_project":
            get_catalog_service().ensure_preset_exists(payload.workspace_id, normalized.normalized_input_ref.project_path or "")
        if payload.input_ref.kind == "custom_project" and not workspace.allow_custom_project_path:
                raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="custom project path is not allowed in current workspace",
            )
        poc_available = (
            get_config().execution.poc_enabled
            and get_config().execution.poc_runtime_available
            and workspace.supports_poc
        )
        if payload.pipeline_mode == "audit_then_poc" and not poc_available:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="poc is not supported in current workspace")
        if payload.pipeline_mode == "poc_only" and normalized.normalized_input_ref.kind != "existing_audit_report":
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="poc_only requires existing_audit_report input")
        if payload.pipeline_mode == "poc_only" and not poc_available:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="poc is not supported in current workspace")
        if payload.pipeline_mode == "custom_graph" and payload.graph_source is None:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="custom_graph requires graph_source")
        if payload.graph_source is not None and payload.pipeline_mode != "custom_graph":
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="graph_source is only supported with custom_graph")

        input_ref = normalized.normalized_input_ref
        target_key = input_ref.project_path or input_ref.report_path or ""
        now = utc_now_z()
        execution_cfg = get_config().execution
        executor_mode = str(payload.executor_mode or execution_cfg.mode)
        if payload.pipeline_mode == "custom_graph" and executor_mode != "agentflow_cli":
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="custom_graph currently requires agentflow_cli")
        explicit_task_model = str(payload.model or "").strip() or None
        runtime_provider = self._resolve_runtime_provider(
            provider_keys=payload.provider_keys,
            executor_mode=executor_mode,
            explicit_task_model=explicit_task_model,
        )
        self._validate_runtime_provider_compatibility(
            runtime_provider,
            executor_mode=executor_mode,
            pipeline_mode=payload.pipeline_mode,
            graph_source=payload.graph_source.model_dump() if payload.graph_source is not None else None,
        )
        report_outputs = self._normalize_report_outputs(payload)
        stage_names = self._determine_stage_names(payload, report_outputs)
        with get_database().connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if payload.idempotency_key:
                existing = conn.execute(
                    "select task_id from ipc_audit_tasks where idempotency_key = ? limit 1",
                    (payload.idempotency_key,),
                ).fetchone()
                if existing is not None:
                    conn.rollback()
                    return self.get_task_summary(existing["task_id"])
            conflict = conn.execute(
                """
                select task_id from ipc_audit_tasks
                where workspace_id = ?
                  and pipeline_mode = ?
                  and ifnull(project_path, report_path) = ?
                  and status in ('queued', 'running', 'cancel_requested')
                limit 1
                """,
                (payload.workspace_id, payload.pipeline_mode, target_key),
            ).fetchone()
            if conflict is not None:
                conn.rollback()
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"active task already exists: {conflict['task_id']}")

            task_id = new_task_id()
            attempt_id = new_attempt_id()
            selected_model = runtime_provider.effective_model
            effective_config = {
                "execution_mode": executor_mode,
                "executor_mode": executor_mode,
                "model": selected_model,
                "task_model": explicit_task_model,
                "provider_keys": runtime_provider.provider_keys,
                "provider_snapshots": runtime_provider.provider_snapshots,
                "provider_source_backend": get_config().provider_source.backend,
                "audit_skill": execution_cfg.default_audit_skill,
                "poc_skill": execution_cfg.default_poc_skill,
                "audit_sandbox_mode": execution_cfg.audit_sandbox_mode,
                "audit_approval_policy": execution_cfg.audit_approval_policy,
                "audit_network_access": execution_cfg.audit_network_access,
                "poc_sandbox_mode": execution_cfg.poc_sandbox_mode,
                "poc_approval_policy": execution_cfg.poc_approval_policy,
                "poc_network_access": execution_cfg.poc_network_access,
                "report_language": "zh-CN",
                "start_stage": "poc" if payload.pipeline_mode == "poc_only" else stage_names[0],
                "stage_names": stage_names,
                "report_outputs": report_outputs,
                "graph_source": payload.graph_source.model_dump() if payload.graph_source is not None else None,
            }
            conn.execute(
                """
                insert into ipc_audit_tasks (
                  task_id, project_id, workspace_id, title, pipeline_mode, input_kind,
                  project_path, report_path, status, current_stage, latest_attempt_id,
                  attempt_count, notes, idempotency_key, created_by, created_at, updated_at, message
                ) values (?, ?, ?, ?, ?, ?, ?, ?, 'queued', null, ?, 1, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    payload.project_id,
                    payload.workspace_id,
                    payload.title,
                    payload.pipeline_mode,
                    input_ref.kind,
                    input_ref.project_path,
                    input_ref.report_path,
                    attempt_id,
                    payload.notes,
                    payload.idempotency_key,
                    subject.username,
                    now,
                    now,
                    "task queued",
                ),
            )
            conn.execute(
                """
                insert into ipc_audit_task_attempts (
                  attempt_id, task_id, attempt_no, status, created_at, updated_at, effective_config_json
                ) values (?, ?, 1, 'queued', ?, ?, ?)
                """,
                (attempt_id, task_id, now, now, json.dumps(effective_config, ensure_ascii=False)),
            )
            self._insert_stage_rows(
                conn,
                attempt_id,
                attempt_no=1,
                start_stage=effective_config["start_stage"],
                pipeline_mode=payload.pipeline_mode,
                stage_names=stage_names,
                created_at=now,
            )
            get_event_service().append_event(
                conn,
                task_id=task_id,
                attempt_id=attempt_id,
                stage_name=None,
                event_type="task.created",
                level="info",
                message="task created",
                payload={"attempt_id": attempt_id},
            )
            get_event_service().append_event(
                conn,
                task_id=task_id,
                attempt_id=attempt_id,
                stage_name=None,
                event_type="task.queued",
                level="info",
                message="task queued",
                payload={"attempt_id": attempt_id},
            )
            conn.commit()
        return self.get_task_summary(task_id)

    def validate_graph(self, payload: GraphValidateRequest) -> GraphValidateResponse:
        executor_mode = str(payload.executor_mode or "agentflow_cli").strip() or "agentflow_cli"
        if executor_mode != "agentflow_cli":
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="graph validation currently requires agentflow_cli")

        workspace = get_workspace_service().get_workspace(payload.workspace_id)
        repo_root = Path(workspace.repo_root).resolve()
        if not repo_root.exists() or not repo_root.is_dir():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"workspace repo root not available: {workspace.workspace_id}",
            )

        runtime_provider = self._resolve_runtime_provider(
            provider_keys=payload.provider_keys,
            executor_mode=executor_mode,
            explicit_task_model=str(payload.model or "").strip() or None,
        )
        report_outputs = self._normalize_report_outputs_from_items(
            [item.model_dump() for item in payload.report_outputs] if payload.report_outputs else [],
            pipeline_mode="custom_graph",
        )
        graph_source = payload.graph_source.model_dump()
        declared_stage_names = self._collect_declared_stage_names(graph_source, report_outputs)
        pipeline_payload = self._materialize_validation_pipeline(
            workspace_id=workspace.workspace_id,
            repo_root=repo_root,
            graph_source=graph_source,
            report_outputs=report_outputs,
            declared_stage_names=declared_stage_names,
            runtime_provider=runtime_provider,
        )

        actual_node_ids = [
            str(item.get("id") or "").strip()
            for item in pipeline_payload.get("nodes", [])
            if isinstance(item, dict) and str(item.get("id") or "").strip()
        ]
        actual_node_id_set = set(actual_node_ids)
        missing_stage_names = [item for item in declared_stage_names if item not in actual_node_id_set]
        if missing_stage_names:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"declared/report nodes not found in generated graph: {', '.join(missing_stage_names)}",
            )
        if declared_stage_names and actual_node_id_set != set(declared_stage_names):
            extras = [item for item in actual_node_ids if item not in set(declared_stage_names)]
            if extras:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail=(
                        "generated graph nodes do not match declared/report nodes; "
                        f"missing report_outputs or declared_nodes for: {', '.join(extras)}"
                    ),
                )

        self._validate_runtime_provider_compatibility(
            runtime_provider,
            executor_mode=executor_mode,
            pipeline_mode="custom_graph",
            graph_source={"type": "inline_json", "content": pipeline_payload},
        )
        return GraphValidateResponse(
            valid=True,
            message=f"graph validation passed with {len(actual_node_ids)} nodes",
            graph_source_type=str(graph_source.get("type") or "inline_json"),
            node_count=len(actual_node_ids),
            node_ids=actual_node_ids,
        )

    def _resolve_runtime_provider(
        self,
        *,
        provider_keys: list[str],
        executor_mode: str,
        explicit_task_model: str | None,
    ):
        try:
            return get_provider_runtime_service().resolve_runtime(
                provider_keys,
                executor_mode=executor_mode,
                explicit_task_model=explicit_task_model,
            )
        except ProviderClientError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc

    def _materialize_validation_pipeline(
        self,
        *,
        workspace_id: str,
        repo_root: Path,
        graph_source: dict[str, Any],
        report_outputs: list[dict[str, Any]],
        declared_stage_names: list[str],
        runtime_provider,
    ) -> dict[str, Any]:
        from app.workers.stage_graph import (
            _materialize_builder_script,
            _normalize_pipeline_payload,
            _render_inline_json_pipeline,
            _render_secflow_template_payload,
        )

        validation_task_id = "__graph_validation__"
        validation_attempt_id = new_attempt_id()
        with tempfile.TemporaryDirectory(prefix="ipc-audit-graph-validate-") as temp_dir:
            temp_root = Path(temp_dir)
            attempt_root = temp_root / "attempt"
            runtime_root = temp_root / "runtime"
            logs_dir = temp_root / "logs"
            artifacts_dir = temp_root / "artifacts"
            scratch_dir = temp_root / "scratch"
            graph_runtime_dir = runtime_root / "graph"
            for path in (attempt_root, runtime_root, logs_dir, artifacts_dir, scratch_dir, graph_runtime_dir):
                path.mkdir(parents=True, exist_ok=True)

            effective_config = {
                "executor_mode": "agentflow_cli",
                "execution_mode": "agentflow_cli",
                "report_outputs": report_outputs,
                "stage_names": declared_stage_names,
            }
            context = StageContext(
                task_id=validation_task_id,
                attempt_id=validation_attempt_id,
                workspace_id=workspace_id,
                stage_name="graph",
                input_kind="custom_project",
                pipeline_mode="custom_graph",
                project_path="__graph_validation_target__",
                report_path=None,
                repo_root=repo_root,
                attempt_root=attempt_root,
                runtime_root=runtime_root,
                logs_dir=logs_dir,
                artifacts_dir=artifacts_dir,
                scratch_dir=scratch_dir,
                effective_config=effective_config,
                provider_runtime=runtime_provider,
            )
            template_context = self._build_graph_validation_template_context(context, report_outputs)
            graph_type = str(graph_source.get("type") or "").strip()
            if graph_type == "inline_json":
                content = graph_source.get("content")
                if not isinstance(content, dict):
                    raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="inline_json graph_source.content must be an object")
                try:
                    rendered = _render_inline_json_pipeline(content, template_context)
                    return _normalize_pipeline_payload(context, rendered)
                except Exception as exc:  # noqa: BLE001
                    raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"invalid inline_json graph source: {exc}") from exc

            if graph_type != "python_builder":
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"unsupported graph source type: {graph_type}")

            builder_path = _materialize_builder_script(context, graph_source, graph_runtime_dir)
            if builder_path is None:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="python_builder requires a valid entry or code")
            if not builder_path.exists() or not builder_path.is_file():
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"python builder entry not found: {builder_path}")

            graph_context_path = graph_runtime_dir / "graph-context.json"
            graph_context_path.write_text(json.dumps(template_context, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            pipeline_path = graph_runtime_dir / "agentflow-pipeline.json"
            process_env, _, _ = build_agentflow_process_env_and_summary(context)
            cmd = [
                str(get_config().execution.agentflow_python_bin),
                str(builder_path),
                "--context",
                str(graph_context_path),
                "--output",
                str(pipeline_path),
            ]
            try:
                completed = subprocess.run(
                    cmd,
                    cwd=str(repo_root),
                    env=process_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=min(30, max(5, int(get_config().execution.task_timeout_seconds))),
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                output = self._summarize_validation_command_output(exc.stdout)
                suffix = f"\n{output}" if output else ""
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"python_builder validation timed out{suffix}") from exc

            if completed.returncode != 0:
                output = self._summarize_validation_command_output(completed.stdout)
                suffix = f"\n{output}" if output else ""
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail=f"python_builder validation failed with return code {completed.returncode}{suffix}",
                )

            payload = read_json_file(pipeline_path)
            if not isinstance(payload, dict):
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="python_builder did not produce a valid JSON pipeline")
            try:
                rendered = _render_secflow_template_payload(
                    payload,
                    template_context,
                    source_label="python_builder output",
                )
                return _normalize_pipeline_payload(context, rendered)
            except Exception as exc:  # noqa: BLE001
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"invalid graph builder pipeline: {exc}") from exc

    def _build_graph_validation_template_context(
        self,
        context: StageContext,
        report_outputs: list[dict[str, Any]],
    ) -> dict[str, Any]:
        report_output_map: dict[str, dict[str, Any]] = {}
        report_output_list: list[dict[str, Any]] = []
        for item in sorted(report_outputs, key=lambda value: (int(value.get("order") or 0), str(value.get("output_id") or ""))):
            relative_path = normalize_attempt_relative_path(str(item["path"])).as_posix()
            absolute_path = resolve_attempt_relative_path(context.attempt_root, relative_path)
            payload = {
                "output_id": str(item["output_id"]),
                "node_id": str(item["node_id"]),
                "title": str(item["title"]),
                "relative_path": relative_path,
                "absolute_path": str(absolute_path),
                "format": str(item.get("format") or "markdown"),
                "required": bool(item.get("required", True)),
                "order": int(item.get("order") or 0),
            }
            report_output_map[payload["output_id"]] = payload
            report_output_list.append(payload)
        poc_runtime = build_in_container_qemu_runtime(build_poc_qemu_instance_name(context.task_id))
        work_dir = resolve_stage_work_dir(context)
        project_absolute_path = str(work_dir) if context.project_path else None
        task_context = {
            "task_id": context.task_id,
            "attempt_id": context.attempt_id,
            "workspace_id": context.workspace_id,
            "input_kind": context.input_kind,
            "input_ref": {
                "kind": context.input_kind,
                "project_path": context.project_path,
                "report_path": context.report_path,
            },
            "project_path": project_absolute_path,
            "project_relative_path": context.project_path,
            "project_absolute_path": project_absolute_path,
            "report_path": context.report_path,
            "repo_root": str(context.repo_root),
            "work_dir": str(work_dir),
            "attempt_root": str(context.attempt_root),
            "runtime_root": str(context.runtime_root),
            "stage_names": list(context.effective_config.get("stage_names") or []),
            "poc_runtime": poc_runtime,
            "report_outputs": report_output_map,
            "report_outputs_list": report_output_list,
        }
        return {
            **task_context,
            "task": task_context,
        }

    @staticmethod
    def _summarize_validation_command_output(raw_output: str | None) -> str:
        text = str(raw_output or "").strip()
        if not text:
            return ""
        lines = text.splitlines()
        if len(lines) > 40:
            lines = lines[-40:]
        trimmed = "\n".join(lines)
        return trimmed[-4000:] if len(trimmed) > 4000 else trimmed

    def _validate_runtime_provider_compatibility(
        self,
        runtime_provider,
        *,
        executor_mode: str,
        pipeline_mode: str,
        graph_source: dict[str, Any] | None,
    ) -> None:
        effective_executor_mode = self._normalize_executor_mode_for_provider_validation(
            executor_mode,
            pipeline_mode=pipeline_mode,
            graph_source=graph_source,
        )
        if effective_executor_mode != "codex_cli":
            return
        incompatible_labels: list[str] = []
        for snapshot in list(getattr(runtime_provider, "provider_snapshots", []) or []):
            if not isinstance(snapshot, dict):
                continue
            provider_key = str(snapshot.get("provider_key") or "").strip()
            display_name = str(snapshot.get("display_name") or "").strip()
            model = str(snapshot.get("model") or "").strip()
            provider_type = str(snapshot.get("provider_type") or "").strip()
            api_base = str(snapshot.get("api_base") or "").strip()
            search_text = " ".join(part for part in (provider_key, display_name, model, provider_type, api_base) if part).lower()
            if "minimax" not in search_text:
                continue
            label = display_name or provider_key or model or "unknown-provider"
            if model and model not in label:
                label = f"{label} ({model})"
            incompatible_labels.append(label)
        if incompatible_labels:
            detail = (
                "selected provider is not compatible with the current Codex/AgentFlow execution path: "
                f"{', '.join(incompatible_labels)}. "
                "MiniMax-family providers currently return non-standard tool-call payloads here and cannot reliably "
                "execute repository/file tools. Choose a Codex/OpenAI-compatible or Anthropic provider instead."
            )
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=detail)

    @classmethod
    def _normalize_executor_mode_for_provider_validation(
        cls,
        executor_mode: str | None,
        *,
        pipeline_mode: str,
        graph_source: dict[str, Any] | None,
    ) -> str:
        normalized_mode = str(executor_mode or "").strip().lower()
        if normalized_mode != "agentflow_cli":
            return normalized_mode
        declared_agents = cls._declared_graph_agents_for_validation(graph_source)
        if declared_agents:
            return "codex_cli" if "codex" in declared_agents else "opencode_cli"
        if str(pipeline_mode or "").strip().lower() == "custom_graph":
            return "opencode_cli"
        agent = str(get_config().execution.agentflow_agent or "").strip().lower()
        if agent == "opencode":
            return "opencode_cli"
        return "codex_cli"

    @staticmethod
    def _declared_graph_agents_for_validation(graph_source: dict[str, Any] | None) -> set[str]:
        if not isinstance(graph_source, dict):
            return set()
        if str(graph_source.get("type") or "").strip() != "inline_json":
            return set()
        content = graph_source.get("content")
        if not isinstance(content, dict):
            return set()
        nodes = content.get("nodes")
        if not isinstance(nodes, list):
            return set()
        agents: set[str] = set()
        for node in nodes:
            if not isinstance(node, dict):
                continue
            agent = str(node.get("agent") or "").strip().lower()
            if agent in {"codex", "opencode"}:
                agents.add(agent)
        return agents

    def list_tasks(
        self,
        *,
        project_id: str | None,
        workspace_id: str | None,
        status_filter: str | None,
        stage: str | None,
        keyword: str | None,
        created_by: str | None,
        page: int,
        per_page: int,
    ) -> PagedTaskResponse:
        where = ["1=1"]
        params: list[object] = []
        if project_id:
            where.append("project_id = ?")
            params.append(project_id)
        if workspace_id:
            where.append("workspace_id = ?")
            params.append(workspace_id)
        if status_filter:
            where.append("status = ?")
            params.append(status_filter)
        if stage:
            where.append("current_stage = ?")
            params.append(stage)
        if keyword:
            where.append("(title like ? or ifnull(project_path, report_path) like ?)")
            like = f"%{keyword}%"
            params.extend([like, like])
        if created_by:
            where.append("created_by = ?")
            params.append(created_by)
        where_sql = " and ".join(where)
        offset = (page - 1) * per_page
        with get_database().connect() as conn:
            total = conn.execute(f"select count(*) from ipc_audit_tasks where {where_sql}", params).fetchone()[0]
            rows = conn.execute(
                f"""
                select * from ipc_audit_tasks
                where {where_sql}
                order by created_at desc
                limit ? offset ?
                """,
                [*params, per_page, offset],
            ).fetchall()
        return PagedTaskResponse(items=[self._task_row_to_summary(row) for row in rows], total=total, page=page, per_page=per_page)

    def get_task_summary(self, task_id: str) -> TaskSummaryResponse:
        with get_database().connect() as conn:
            row = self._get_task_row(conn, task_id)
            return self._task_row_to_summary(row)

    def get_task(self, task_id: str) -> TaskDetailResponse:
        with get_database().connect() as conn:
            row = self._get_task_row(conn, task_id)
            latest_attempt = None
            if row["latest_attempt_id"]:
                attempt_row = self._get_attempt_row(conn, row["latest_attempt_id"])
                latest_attempt = self._attempt_row_to_model(conn, attempt_row)
            summary = self._task_row_to_summary(row)
            return TaskDetailResponse(**summary.model_dump(), attempt_count=row["attempt_count"], latest_attempt=latest_attempt)

    def list_attempts(self, task_id: str) -> list[AttemptDetailResponse]:
        with get_database().connect() as conn:
            self._get_task_row(conn, task_id)
            rows = conn.execute(
                """
                select * from ipc_audit_task_attempts
                where task_id = ?
                order by attempt_no desc
                """,
                (task_id,),
            ).fetchall()
            return [self._attempt_row_to_model(conn, row) for row in rows]

    def get_attempt(self, task_id: str, attempt_id: str) -> AttemptDetailResponse:
        with get_database().connect() as conn:
            attempt_row = self._get_attempt_row(conn, attempt_id)
            if attempt_row["task_id"] != task_id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"attempt not found for task: {attempt_id}")
            return self._attempt_row_to_model(conn, attempt_row)

    def list_events(self, task_id: str, *, attempt_id: str | None, cursor: int | None, limit: int) -> EventPageResponse:
        with get_database().connect() as conn:
            self._get_task_row(conn, task_id)
        return get_event_service().list_events(task_id=task_id, attempt_id=attempt_id, cursor=cursor, limit=limit)

    def get_stage_log(self, task_id: str, attempt_id: str, stage_name: str, *, lines: int, cursor: int | None) -> StageLogResponse:
        with get_database().connect() as conn:
            self._get_attempt_row(conn, attempt_id)
        path = get_artifact_service().stage_log_path(task_id, attempt_id, stage_name)
        if not path.exists():
            return StageLogResponse(task_id=task_id, attempt_id=attempt_id, stage_name=stage_name, content="", next_cursor=0)
        data = path.read_bytes()
        if cursor is not None:
            chunk = data[cursor:]
            return StageLogResponse(
                task_id=task_id,
                attempt_id=attempt_id,
                stage_name=stage_name,
                content=chunk.decode("utf-8", errors="replace"),
                next_cursor=len(data),
            )
        text = data.decode("utf-8", errors="replace")
        tail = "\n".join(text.splitlines()[-lines:])
        return StageLogResponse(task_id=task_id, attempt_id=attempt_id, stage_name=stage_name, content=tail, next_cursor=len(data))

    def list_stage_sessions(self, task_id: str, attempt_id: str, stage_name: str) -> list[dict]:
        attempt_root = get_artifact_service().attempt_root(task_id, attempt_id).resolve()
        with get_database().connect() as conn:
            attempt_row = self._get_attempt_row(conn, attempt_id)
            if attempt_row["task_id"] != task_id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"attempt not found for task: {attempt_id}")
            stage_row = conn.execute(
                """
                select stage_name
                from ipc_audit_stage_runs
                where attempt_id = ? and stage_name = ?
                limit 1
                """,
                (attempt_id, stage_name),
            ).fetchone()
            if stage_row is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"unsupported stage: {stage_name}")
            rows = conn.execute(
                """
                select display_name, relative_path, content_type, size, created_at
                from ipc_audit_artifacts
                where task_id = ? and attempt_id = ? and stage_name = ? and artifact_kind = 'session_file'
                order by created_at asc
                """,
                (task_id, attempt_id, stage_name),
            ).fetchall()
        items = [
            {
                "path": row["relative_path"],
                "display_name": row["display_name"],
                "content_type": row["content_type"],
                "size": row["size"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]
        known_paths = {item["path"] for item in items}
        for trace_path in self._discover_stage_trace_files(attempt_root, stage_name):
            relative_path = trace_path.resolve().relative_to(attempt_root).as_posix()
            if relative_path in known_paths:
                continue
            stat = trace_path.stat()
            items.append(
                {
                    "path": relative_path,
                    "display_name": "trace.jsonl",
                    "content_type": "application/x-ndjson",
                    "size": stat.st_size,
                    "created_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
                }
            )
            known_paths.add(relative_path)
        for filename in ("prompt.txt", "events.jsonl", "last-message.md"):
            path = attempt_root / "runtime" / stage_name / filename
            if not path.exists() or not path.is_file():
                continue
            relative_path = path.resolve().relative_to(attempt_root).as_posix()
            if relative_path in known_paths:
                continue
            stat = path.stat()
            content_type = "application/x-ndjson" if filename.endswith(".jsonl") else "text/plain"
            items.append(
                {
                    "path": relative_path,
                    "display_name": filename,
                    "content_type": content_type,
                    "size": stat.st_size,
                    "created_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
                }
            )
        return items

    def get_stage_session_file(self, task_id: str, attempt_id: str, stage_name: str, path: str) -> dict:
        source = self.resolve_stage_session_source(task_id, attempt_id, stage_name, path)
        if not source.source_path.exists() or not source.source_path.is_file():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"session file not found: {path}")
        data = source.source_path.read_bytes()
        max_bytes = 1024 * 1024
        return {
            "path": source.normalized_path.as_posix(),
            "content": data[:max_bytes].decode("utf-8", errors="replace"),
            "truncated": len(data) > max_bytes,
            "next_cursor": min(len(data), max_bytes),
        }

    def resolve_stage_session_source(
        self,
        task_id: str,
        attempt_id: str,
        stage_name: str,
        path: str,
    ) -> ResolvedStageSessionSource:
        normalized, candidate = self.resolve_stage_session_file_path(task_id, attempt_id, stage_name, path)
        return ResolvedStageSessionSource(normalized, candidate)

    def resolve_stage_session_file_path(self, task_id: str, attempt_id: str, stage_name: str, path: str) -> tuple[PurePosixPath, Path]:
        with get_database().connect() as conn:
            attempt_row = self._get_attempt_row(conn, attempt_id)
            if attempt_row["task_id"] != task_id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"attempt not found for task: {attempt_id}")
            stage_row = conn.execute(
                """
                select stage_name
                from ipc_audit_stage_runs
                where attempt_id = ? and stage_name = ?
                limit 1
                """,
                (attempt_id, stage_name),
            ).fetchone()
            if stage_row is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"unsupported stage: {stage_name}")
        normalized = PurePosixPath((path or "").strip())
        if not normalized.parts or normalized.is_absolute() or ".." in normalized.parts:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"invalid session file path: {path}")
        attempt_root = get_artifact_service().attempt_root(task_id, attempt_id).resolve()
        candidate = (attempt_root / normalized.as_posix()).resolve()
        try:
            candidate.relative_to(attempt_root)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="session file escapes attempt root") from exc
        return normalized, candidate

    @staticmethod
    def _discover_stage_trace_files(attempt_root: Path, stage_name: str) -> list[Path]:
        candidates: list[Path] = []
        run_roots = [
            attempt_root / "runtime" / stage_name / "agentflow-runs",
            attempt_root / "runtime" / "agentflow-runs",
            attempt_root / "runtime" / "graph" / "agentflow-runs",
        ]
        for runs_dir in run_roots:
            if not runs_dir.exists() or not runs_dir.is_dir():
                continue
            for run_dir in sorted(path for path in runs_dir.iterdir() if path.is_dir()):
                trace_path = run_dir / "artifacts" / stage_name / "trace.jsonl"
                if trace_path.exists() and trace_path.is_file():
                    candidates.append(trace_path)
        return candidates

    def list_artifacts(self, task_id: str, attempt_id: str) -> ArtifactListResponse:
        with get_database().connect() as conn:
            self._get_attempt_row(conn, attempt_id)
        return get_artifact_service().list_artifacts(task_id, attempt_id)

    def cancel_task(self, task_id: str) -> TaskSummaryResponse:
        now = utc_now_z()
        with get_database().connect() as conn:
            row = self._get_task_row(conn, task_id)
            if row["status"] not in ACTIVE_TASK_STATUSES:
                return self._task_row_to_summary(row)
            attempt_row = self._get_attempt_row(conn, row["latest_attempt_id"]) if row["latest_attempt_id"] else None
            conn.execute("BEGIN IMMEDIATE")
            if attempt_row is not None and attempt_row["status"] == "queued":
                cursor = conn.execute(
                    """
                    update ipc_audit_task_attempts
                    set status = 'cancelled', finished_at = ?, updated_at = ?, failure_reason = 'task cancelled'
                    where attempt_id = ? and status = 'queued'
                    """,
                    (now, now, row["latest_attempt_id"]),
                )
                if cursor.rowcount == 1:
                    conn.execute(
                        """
                        update ipc_audit_stage_runs
                        set status = 'cancelled', finished_at = coalesce(finished_at, ?), updated_at = ?, message = 'task cancelled'
                        where attempt_id = ? and status in ('pending', 'queued', 'running')
                        """,
                        (now, now, row["latest_attempt_id"]),
                    )
                    conn.execute(
                        """
                        update ipc_audit_tasks
                        set status = 'cancelled', current_stage = null, finished_at = ?, updated_at = ?, message = 'task cancelled'
                        where task_id = ?
                        """,
                        (now, now, task_id),
                    )
                    get_event_service().append_event(
                        conn,
                        task_id=task_id,
                        attempt_id=row["latest_attempt_id"],
                        stage_name=None,
                        event_type="task.cancelled",
                        level="warning",
                        message="task cancelled",
                        payload={"reason": "cancelled_before_claim"},
                    )
                    conn.commit()
                    return self.get_task_summary(task_id)
            conn.execute(
                """
                update ipc_audit_tasks
                set status = 'cancel_requested', updated_at = ?, message = 'cancel requested'
                where task_id = ?
                """,
                (now, task_id),
            )
            if row["latest_attempt_id"]:
                conn.execute(
                    """
                    update ipc_audit_task_attempts
                    set status = case when status in ('queued', 'claimed', 'running') then 'cancel_requested' else status end,
                        updated_at = ?
                    where attempt_id = ?
                    """,
                    (now, row["latest_attempt_id"]),
                )
            get_event_service().append_event(
                conn,
                task_id=task_id,
                attempt_id=row["latest_attempt_id"],
                stage_name=None,
                event_type="task.cancel_requested",
                level="info",
                message="cancel requested",
                payload={},
            )
            conn.commit()
        return self.get_task_summary(task_id)

    def retry_task(self, task_id: str, payload: TaskRetryRequest, subject) -> TaskSummaryResponse:
        now = utc_now_z()
        with get_database().connect() as conn:
            row = self._get_task_row(conn, task_id)
            if row["status"] in ACTIVE_TASK_STATUSES:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"task is active: {task_id}")
            latest_attempt = self._get_attempt_row(conn, row["latest_attempt_id"]) if row["latest_attempt_id"] else None
            if latest_attempt is None:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"task has no attempts: {task_id}")
            effective_config = json.loads(latest_attempt["effective_config_json"] or "{}")
            start_stage = "audit"
            if payload.retry_scope == "from_stage":
                if row["pipeline_mode"] == "custom_graph":
                    raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="from_stage retry is not yet supported for custom_graph")
                stage_names = self._effective_stage_names(effective_config, row["pipeline_mode"])
                if payload.stage is None or payload.stage not in stage_names:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="stage is required for from_stage retry")
                if payload.stage == "poc":
                    start_stage = "poc"
                    self._find_latest_audit_report(conn, task_id)
                else:
                    start_stage = payload.stage
            effective_config["start_stage"] = start_stage
            attempt_id = new_attempt_id()
            attempt_no = int(row["attempt_count"]) + 1
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                update ipc_audit_tasks
                set status = 'queued',
                    current_stage = null,
                    latest_attempt_id = ?,
                    attempt_count = ?,
                    updated_at = ?,
                    finished_at = null,
                    message = 'task re-queued'
                where task_id = ?
                """,
                (attempt_id, attempt_no, now, task_id),
            )
            conn.execute(
                """
                insert into ipc_audit_task_attempts (
                  attempt_id, task_id, attempt_no, status, created_at, updated_at, effective_config_json
                ) values (?, ?, ?, 'queued', ?, ?, ?)
                """,
                (attempt_id, task_id, attempt_no, now, now, json.dumps(effective_config, ensure_ascii=False)),
            )
            self._insert_stage_rows(
                conn,
                attempt_id,
                attempt_no=attempt_no,
                start_stage=start_stage,
                pipeline_mode=row["pipeline_mode"],
                stage_names=self._effective_stage_names(effective_config, row["pipeline_mode"]),
                created_at=now,
            )
            get_event_service().append_event(
                conn,
                task_id=task_id,
                attempt_id=attempt_id,
                stage_name=None,
                event_type="task.queued",
                level="info",
                message="task re-queued",
                payload={"attempt_id": attempt_id, "requested_by": subject.username},
            )
            conn.commit()
        return self.get_task_summary(task_id)

    def delete_task(self, task_id: str, *, delete_artifacts: bool) -> SuccessResponse:
        with get_database().connect() as conn:
            row = self._get_task_row(conn, task_id)
            if row["status"] in ACTIVE_TASK_STATUSES:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"cannot delete active task: {task_id}")
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("delete from ipc_audit_tasks where task_id = ?", (task_id,))
            conn.commit()
        if delete_artifacts:
            task_root = get_artifact_service().task_root(task_id)
            if task_root.exists():
                shutil.rmtree(task_root, ignore_errors=True)
        return SuccessResponse(success=True, task_id=task_id, status="deleted", message="task deleted")

    def claim_next_attempt(self, worker_id: str) -> str | None:
        now = utc_now_z()
        lease_expires_at = self._future_time(get_config().execution.lease_duration_seconds)
        with get_database().connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                select attempt_id, task_id
                from ipc_audit_task_attempts
                where status = 'queued'
                order by created_at asc
                limit 1
                """
            ).fetchone()
            if row is None:
                conn.commit()
                return None
            lease_token = f"{worker_id}:{now}"
            claim_cursor = conn.execute(
                """
                update ipc_audit_task_attempts
                set status = 'claimed',
                    worker_id = ?,
                    lease_token = ?,
                    claimed_at = ?,
                    heartbeat_at = ?,
                    lease_expires_at = ?,
                    updated_at = ?
                where attempt_id = ? and status = 'queued'
                """,
                (worker_id, lease_token, now, now, lease_expires_at, now, row["attempt_id"]),
            )
            changes = claim_cursor.rowcount
            if changes != 1:
                conn.commit()
                return None
            conn.execute(
                """
                update ipc_audit_tasks
                set status = 'running', updated_at = ?, message = 'attempt claimed'
                where task_id = ?
                """,
                (now, row["task_id"]),
            )
            get_event_service().append_event(
                conn,
                task_id=row["task_id"],
                attempt_id=row["attempt_id"],
                stage_name=None,
                event_type="attempt.claimed",
                level="info",
                message="attempt claimed",
                payload={"worker_id": worker_id},
            )
            conn.commit()
            return row["attempt_id"]

    def recover_expired_attempts(self, *, excluded_attempt_ids: set[str] | None = None) -> int:
        now = utc_now_z()
        recovered = 0
        excluded = excluded_attempt_ids or set()
        with get_database().connect() as conn:
            rows = conn.execute(
                """
                select attempt_id, task_id
                from ipc_audit_task_attempts
                where status in ('claimed', 'running', 'cancel_requested')
                  and lease_expires_at is not null
                  and lease_expires_at < ?
                """,
                (now,),
            ).fetchall()
            for row in rows:
                attempt_id = str(row["attempt_id"])
                if attempt_id in excluded:
                    continue
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """
                    update ipc_audit_task_attempts
                    set status = 'lost', updated_at = ?, finished_at = ?, failure_reason = 'lease expired'
                    where attempt_id = ?
                      and status in ('claimed', 'running', 'cancel_requested')
                      and lease_expires_at is not null
                      and lease_expires_at < ?
                    """,
                    (now, now, attempt_id, now),
                )
                if conn.execute("select changes()").fetchone()[0] != 1:
                    conn.commit()
                    continue
                conn.execute(
                    """
                    update ipc_audit_tasks
                    set status = 'failed', updated_at = ?, finished_at = ?, message = 'worker lease expired'
                    where task_id = ? and latest_attempt_id = ?
                    """,
                    (now, now, row["task_id"], attempt_id),
                )
                get_event_service().append_event(
                    conn,
                    task_id=row["task_id"],
                    attempt_id=attempt_id,
                    stage_name=None,
                    event_type="worker.lost",
                    level="error",
                    message="worker lease expired",
                    payload={},
                )
                conn.commit()
                recovered += 1
        return recovered

    def _insert_stage_rows(
        self,
        conn: DatabaseConnection,
        attempt_id: str,
        *,
        attempt_no: int,
        start_stage: str,
        pipeline_mode: str,
        stage_names: list[str],
        created_at: str,
    ) -> None:
        if pipeline_mode in {"audit_then_poc", "audit_only", "poc_only"} and stage_names == ["audit", "poc"]:
            audit_status = "pending"
            poc_status = "pending"
            if pipeline_mode == "audit_only":
                poc_status = "skipped"
            if pipeline_mode == "poc_only" or start_stage == "poc":
                audit_status = "skipped"
            conn.execute(
                """
                insert into ipc_audit_stage_runs (
                  stage_run_id, attempt_id, stage_name, status, attempt_no, created_at, updated_at, message
                ) values (?, ?, 'audit', ?, ?, ?, ?, ?)
                """,
                (f"{attempt_id}:audit", attempt_id, audit_status, attempt_no, created_at, created_at, "awaiting execution"),
            )
            conn.execute(
                """
                insert into ipc_audit_stage_runs (
                  stage_run_id, attempt_id, stage_name, status, attempt_no, created_at, updated_at, message
                ) values (?, ?, 'poc', ?, ?, ?, ?, ?)
                """,
                (f"{attempt_id}:poc", attempt_id, poc_status, attempt_no, created_at, created_at, "awaiting execution"),
            )
            return
        if start_stage not in stage_names:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"unknown start stage: {start_stage}")
        start_index = stage_names.index(start_stage)
        for index, stage_name in enumerate(stage_names):
            status = "pending" if index >= start_index else "skipped"
            message = "awaiting execution" if status == "pending" else "retry starts from later stage"
            conn.execute(
                """
                insert into ipc_audit_stage_runs (
                  stage_run_id, attempt_id, stage_name, status, attempt_no, created_at, updated_at, message
                ) values (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (f"{attempt_id}:{stage_name}", attempt_id, stage_name, status, attempt_no, created_at, created_at, message),
            )

    def _get_task_row(self, conn: DatabaseConnection, task_id: str) -> DatabaseRow:
        row = conn.execute("select * from ipc_audit_tasks where task_id = ?", (task_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"task not found: {task_id}")
        return row

    def _get_attempt_row(self, conn: DatabaseConnection, attempt_id: str) -> DatabaseRow:
        row = conn.execute("select * from ipc_audit_task_attempts where attempt_id = ?", (attempt_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"attempt not found: {attempt_id}")
        return row

    def _task_row_to_summary(self, row: DatabaseRow) -> TaskSummaryResponse:
        input_ref = InputRef(kind=row["input_kind"], project_path=row["project_path"], report_path=row["report_path"])
        return TaskSummaryResponse(
            task_id=row["task_id"],
            project_id=row["project_id"],
            workspace_id=row["workspace_id"],
            title=row["title"],
            pipeline_mode=row["pipeline_mode"],
            status=row["status"],
            current_stage=row["current_stage"],
            input_ref=input_ref,
            latest_attempt_id=row["latest_attempt_id"],
            created_by=row["created_by"],
            created_at=row["created_at"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            message=row["message"],
        )

    def _attempt_row_to_model(self, conn: DatabaseConnection, row: DatabaseRow) -> AttemptDetailResponse:
        effective_config = json.loads(row["effective_config_json"] or "{}")
        get_artifact_service().reconcile_attempt_artifacts(
            conn,
            task_id=row["task_id"],
            attempt_id=row["attempt_id"],
        )
        stage_rows = conn.execute(
            """
            select stage_name, status, attempt_no, started_at, finished_at, return_code, log_artifact_id, message
            from ipc_audit_stage_runs
            where attempt_id = ?
            order by stage_name asc
            """,
            (row["attempt_id"],),
        ).fetchall()
        artifact_rows = conn.execute(
            """
            select artifact_id, stage_name, artifact_kind, display_name, relative_path, content_type, size, sha256, created_at
            from ipc_audit_artifacts
            where attempt_id = ?
            order by created_at asc
            """,
            (row["attempt_id"],),
        ).fetchall()
        stage_runs = [
            StageRunResponse(
                stage_name=item["stage_name"],
                status=item["status"],
                attempt_no=item["attempt_no"],
                started_at=item["started_at"],
                finished_at=item["finished_at"],
                return_code=item["return_code"],
                log_artifact_id=item["log_artifact_id"],
                message=item["message"],
            )
            for item in stage_rows
        ]
        return AttemptDetailResponse(
            attempt_id=row["attempt_id"],
            task_id=row["task_id"],
            attempt_no=row["attempt_no"],
            status=row["status"],
            worker=AttemptWorkerResponse(
                worker_id=row["worker_id"],
                claimed_at=row["claimed_at"],
                heartbeat_at=row["heartbeat_at"],
                lease_expires_at=row["lease_expires_at"],
            ),
            effective_config=effective_config,
            stage_runs=stage_runs,
            report_outputs=self._build_attempt_report_outputs(effective_config, artifact_rows),
            message=row["failure_reason"],
            created_at=row["created_at"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
        )

    def _build_attempt_report_outputs(self, effective_config: dict[str, Any], artifact_rows: list[DatabaseRow]) -> list:
        from app.schemas import TaskReportOutputResponse

        artifact_by_path = {
            str(item["relative_path"]): item
            for item in artifact_rows
            if item["artifact_kind"] in {"report_output", "audit_report", "poc_report", "audited_result_json"}
        }
        outputs: list[TaskReportOutputResponse] = []
        declared_paths: set[str] = set()
        report_outputs = effective_config.get("report_outputs") if isinstance(effective_config.get("report_outputs"), list) else []
        for item in sorted(
            [value for value in report_outputs if isinstance(value, dict)],
            key=lambda value: (int(value.get("order") or 0), str(value.get("output_id") or "")),
        ):
            relative_path = normalize_attempt_relative_path(str(item.get("path") or "")).as_posix()
            declared_paths.add(relative_path)
            artifact = artifact_by_path.get(relative_path)
            outputs.append(
                TaskReportOutputResponse(
                    output_id=str(item.get("output_id") or ""),
                    node_id=str(item.get("node_id") or ""),
                    title=str(item.get("title") or item.get("output_id") or ""),
                    path=relative_path,
                    format=str(item.get("format") or "markdown"),
                    required=bool(item.get("required", True)),
                    order=int(item.get("order") or 0),
                    exists=artifact is not None,
                    artifact_id=artifact["artifact_id"] if artifact is not None else None,
                    preview_url=(f"/api/app/ipc-audit/artifacts/{artifact['artifact_id']}/content" if artifact is not None else None),
                    download_url=(f"/api/app/ipc-audit/artifacts/{artifact['artifact_id']}/download" if artifact is not None else None),
                    size=artifact["size"] if artifact is not None else None,
                    created_at=artifact["created_at"] if artifact is not None else None,
                    content_type=artifact["content_type"] if artifact is not None else None,
                    sha256=artifact["sha256"] if artifact is not None else None,
                )
            )
        next_order = (max((item.order for item in outputs), default=0) // 10 + 1) * 10
        for index, artifact in enumerate(
            item for item in artifact_rows
            if str(item["artifact_kind"]) in {"report_output", "audit_report", "poc_report", "audited_result_json"}
            and str(item["relative_path"]) not in declared_paths
        ):
            relative_path = str(artifact["relative_path"])
            outputs.append(
                TaskReportOutputResponse(
                    output_id=self._synthesized_report_output_id(relative_path, str(artifact["artifact_kind"])),
                    node_id=str(artifact["stage_name"] or ""),
                    title=str(artifact["display_name"] or Path(relative_path).name),
                    path=relative_path,
                    format=self._infer_report_output_format(relative_path, artifact["content_type"]),
                    required=False,
                    order=next_order + index * 10,
                    exists=True,
                    artifact_id=artifact["artifact_id"],
                    preview_url=f"/api/app/ipc-audit/artifacts/{artifact['artifact_id']}/content",
                    download_url=f"/api/app/ipc-audit/artifacts/{artifact['artifact_id']}/download",
                    size=artifact["size"],
                    created_at=artifact["created_at"],
                    content_type=artifact["content_type"],
                    sha256=artifact["sha256"],
                )
            )
        return outputs

    @staticmethod
    def _synthesized_report_output_id(relative_path: str, artifact_kind: str) -> str:
        if artifact_kind == "audited_result_json":
            return "audited_result"
        stem = Path(relative_path).stem or "output"
        normalized = "".join(char if char.isalnum() else "_" for char in stem).strip("_")
        return normalized or "output"

    @staticmethod
    def _infer_report_output_format(relative_path: str, content_type: Any) -> str:
        normalized_content_type = str(content_type or "").lower()
        normalized_path = relative_path.lower()
        if "json" in normalized_content_type or normalized_path.endswith(".json"):
            return "json"
        if "markdown" in normalized_content_type or normalized_path.endswith(".md") or normalized_path.endswith(".markdown"):
            return "markdown"
        return "text"

    @staticmethod
    def _future_time(seconds: int) -> str:
        from datetime import timedelta

        now = utc_now_z()
        base = now.replace("Z", "+00:00")
        from datetime import datetime

        value = datetime.fromisoformat(base) + timedelta(seconds=seconds)
        return value.isoformat(timespec="seconds").replace("+00:00", "Z")

    @staticmethod
    def _find_latest_audit_report(conn: DatabaseConnection, task_id: str) -> DatabaseRow:
        row = conn.execute(
            """
            select * from ipc_audit_artifacts
            where task_id = ? and artifact_kind = 'audit_report'
            order by created_at desc
            limit 1
            """,
            (task_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"no audit report available for task: {task_id}")
        return row

    def _normalize_report_outputs(self, payload: TaskCreateRequest) -> list[dict[str, Any]]:
        raw_outputs = [item.model_dump() for item in payload.report_outputs] if payload.report_outputs else []
        return self._normalize_report_outputs_from_items(raw_outputs, pipeline_mode=payload.pipeline_mode)

    def _normalize_report_outputs_from_items(
        self,
        raw_outputs: list[dict[str, Any]],
        *,
        pipeline_mode: str,
    ) -> list[dict[str, Any]]:
        if not raw_outputs:
            raw_outputs = self._default_report_outputs(pipeline_mode)
        normalized_outputs: list[dict[str, Any]] = []
        seen_output_ids: set[str] = set()
        seen_paths: set[str] = set()
        for item in raw_outputs:
            output_id = str(item.get("output_id") or "").strip()
            node_id = str(item.get("node_id") or "").strip()
            title = str(item.get("title") or output_id or node_id).strip()
            if not output_id or not node_id or not title:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="report_outputs require output_id, node_id, and title")
            if output_id in seen_output_ids:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"duplicate report output id: {output_id}")
            seen_output_ids.add(output_id)
            normalized_path = normalize_attempt_relative_path(str(item.get("path") or "")).as_posix()
            if normalized_path in seen_paths:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"duplicate report output path: {normalized_path}")
            seen_paths.add(normalized_path)
            self._validate_stage_name(node_id, label="report output node_id")
            normalized_outputs.append(
                {
                    "output_id": output_id,
                    "node_id": node_id,
                    "title": title,
                    "path": normalized_path,
                    "format": str(item.get("format") or "markdown"),
                    "required": bool(item.get("required", True)),
                    "order": int(item.get("order") or 0),
                }
            )
        return normalized_outputs

    def _collect_declared_stage_names(
        self,
        graph_source: dict[str, Any],
        report_outputs: list[dict[str, Any]],
    ) -> list[str]:
        ordered: list[str] = []
        if str(graph_source.get("type") or "").strip() == "inline_json":
            content = graph_source.get("content")
            nodes_value = content.get("nodes") if isinstance(content, dict) else None
            if isinstance(nodes_value, list):
                for item in nodes_value:
                    if isinstance(item, dict) and str(item.get("id") or "").strip():
                        ordered.append(str(item.get("id") or "").strip())
        for node_id in list(graph_source.get("declared_nodes") or []):
            if str(node_id).strip():
                ordered.append(str(node_id).strip())
        for item in report_outputs:
            ordered.append(str(item["node_id"]))
        deduped: list[str] = []
        seen: set[str] = set()
        for node_id in ordered:
            if node_id in seen:
                continue
            self._validate_stage_name(node_id, label="stage_name")
            seen.add(node_id)
            deduped.append(node_id)
        return deduped

    def _determine_stage_names(self, payload: TaskCreateRequest, report_outputs: list[dict[str, Any]]) -> list[str]:
        if payload.pipeline_mode in {"audit_then_poc", "audit_only", "poc_only"}:
            return ["audit", "poc"]
        graph_source = payload.graph_source
        if graph_source is None:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="custom_graph requires graph_source")
        deduped = self._collect_declared_stage_names(graph_source.model_dump(), report_outputs)
        if not deduped:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="custom_graph must declare at least one stage/node id")
        return deduped

    def _effective_stage_names(self, effective_config: dict[str, Any], pipeline_mode: str) -> list[str]:
        stage_names = effective_config.get("stage_names") if isinstance(effective_config.get("stage_names"), list) else None
        if stage_names:
            return [str(item).strip() for item in stage_names if str(item).strip()]
        if pipeline_mode in {"audit_then_poc", "audit_only", "poc_only"}:
            return ["audit", "poc"]
        return []

    @staticmethod
    def _default_report_outputs(pipeline_mode: str) -> list[dict[str, Any]]:
        outputs: list[dict[str, Any]] = []
        if pipeline_mode in {"audit_then_poc", "audit_only"}:
            outputs.append(
                {
                    "output_id": "audit_report",
                    "node_id": "audit",
                    "title": "Audit Report",
                    "path": "exports/audit-report.md",
                    "format": "markdown",
                    "required": True,
                    "order": 10,
                }
            )
        if pipeline_mode in {"audit_then_poc", "poc_only"}:
            outputs.append(
                {
                    "output_id": "poc_report",
                    "node_id": "poc",
                    "title": "PoC Report",
                    "path": "exports/poc-report.md",
                    "format": "markdown",
                    "required": True,
                    "order": 20,
                }
            )
        return outputs

    @staticmethod
    def _validate_stage_name(value: str, *, label: str) -> None:
        candidate = str(value or "").strip()
        if not candidate or len(candidate) > 128 or any(token in candidate for token in ("/", "\\", "..")):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"invalid {label}: {value}")


_task_service: TaskService | None = None


def get_task_service() -> TaskService:
    global _task_service
    if _task_service is None:
        _task_service = TaskService()
    return _task_service
