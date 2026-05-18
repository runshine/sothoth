from __future__ import annotations

import json
import logging
from collections import Counter
from pathlib import Path
from typing import Any

from app.core.config import get_config
from app.core.time_utils import utc_now_z
from app.db.database import DatabaseConnection, get_database
from app.services.artifact_service import get_artifact_service
from app.services.event_service import get_event_service
from app.services.provider_client import ProviderClientError
from app.services.provider_runtime import get_provider_runtime_service
from app.services.workspace_service import get_workspace_service
from app.workers.runner import StageArtifact, StageContext, StageExecutionResult, StageHooks, write_json_file
from app.workers.stage_graph import GraphExecutionResult, run_graph
from app.workers.stage_audit import run_audit_stage
from app.workers.stage_poc import run_poc_stage

logger = logging.getLogger(__name__)


class ExecutionService:
    def run_attempt(self, attempt_id: str) -> None:
        context = self._load_context(attempt_id)
        try:
            self._attach_provider_runtime(context)
            if str(context["pipeline_mode"]) == "custom_graph":
                graph_result = self._run_custom_graph(context)
                if graph_result.overall_status == "cancelled":
                    raise CancelledError("task cancelled")
                if graph_result.overall_status == "timed_out":
                    raise TimedOutError(graph_result.overall_message)
                if graph_result.overall_status == "failed":
                    raise StageFailedError("custom_graph", graph_result.overall_message)
                if graph_result.overall_status == "partial_success":
                    self._complete_attempt(
                        str(context["task_id"]),
                        attempt_id,
                        task_status="partial_success",
                        attempt_status="partial_success",
                        message=graph_result.overall_message,
                    )
                    return
                self._complete_attempt(
                    str(context["task_id"]),
                    attempt_id,
                    task_status="succeeded",
                    attempt_status="succeeded",
                    message=graph_result.overall_message,
                )
                return
            audit_report_path: Path | None = None
            start_stage = str(context["effective_config"].get("start_stage") or "audit")

            if start_stage == "audit":
                audit_result = self._run_stage(context, "audit")
                audit_report_path = audit_result.output_path
                if audit_result.status == "cancelled":
                    raise CancelledError("task cancelled")
                if audit_result.status == "timed_out":
                    raise TimedOutError(audit_result.message)
                if audit_result.status != "succeeded":
                    raise StageFailedError(audit_result.stage_name, audit_result.message)
            else:
                self._mark_stage_skipped(context, "audit", "retry starts from poc")
                audit_report_path = self._resolve_source_audit_report(context)

            if self._is_cancel_requested(str(context["task_id"]), attempt_id):
                raise CancelledError("task cancelled")

            if str(context["pipeline_mode"]) == "audit_only":
                self._mark_stage_skipped(context, "poc", "pipeline does not include poc")
                self._complete_attempt(
                    str(context["task_id"]),
                    attempt_id,
                    task_status="succeeded",
                    attempt_status="succeeded",
                    message="task completed",
                )
                return

            if not self._poc_available():
                self._mark_stage_skipped(context, "poc", "poc disabled")
                self._complete_attempt(
                    str(context["task_id"]),
                    attempt_id,
                    task_status="succeeded",
                    attempt_status="succeeded",
                    message="task completed",
                )
                return

            if audit_report_path is None:
                raise RuntimeError("audit report path unavailable for poc stage")

            poc_result = self._run_stage(context, "poc", source_audit_report=audit_report_path)
            if poc_result.status == "cancelled":
                raise CancelledError("task cancelled")
            if poc_result.status == "timed_out":
                raise TimedOutError(poc_result.message)
            if poc_result.status != "succeeded":
                self._complete_attempt(
                    str(context["task_id"]),
                    attempt_id,
                    task_status="partial_success",
                    attempt_status="partial_success",
                    message=poc_result.message,
                )
                return

            self._complete_attempt(
                str(context["task_id"]),
                attempt_id,
                task_status="succeeded",
                attempt_status="succeeded",
                message="task completed",
            )
        except CancelledError as exc:
            self._cancel_attempt(str(context["task_id"]), attempt_id, str(exc))
        except TimedOutError as exc:
            logger.warning("attempt %s timed out: %s", attempt_id, exc)
            self._timeout_attempt(str(context["task_id"]), attempt_id, str(exc))
        except StageFailedError as exc:
            logger.warning("attempt %s stage %s failed: %s", attempt_id, exc.stage_name, exc.message)
            self._fail_attempt(str(context["task_id"]), attempt_id, exc.message)
        except Exception as exc:  # noqa: BLE001
            logger.exception("attempt %s failed: %s", attempt_id, exc)
            self._fail_attempt(str(context["task_id"]), attempt_id, str(exc))
        finally:
            try:
                self._write_runtime_manifest(context)
            except Exception as exc:  # noqa: BLE001
                logger.exception("failed to write runtime manifest for %s: %s", attempt_id, exc)

    def _run_stage(
        self,
        context: dict[str, object],
        stage_name: str,
        *,
        source_audit_report: Path | None = None,
    ) -> StageExecutionResult:
        task_id = str(context["task_id"])
        attempt_id = str(context["attempt_id"])
        self._set_stage_running(task_id, attempt_id, stage_name, f"{stage_name} stage started")
        stage_context = self._build_stage_context(context, stage_name)
        hooks = StageHooks(
            heartbeat=lambda: self._heartbeat(attempt_id),
            is_cancel_requested=lambda: self._is_cancel_requested(task_id, attempt_id),
        )
        hooks.heartbeat()
        if stage_name == "audit":
            result = run_audit_stage(stage_context, hooks)
        else:
            if source_audit_report is None:
                raise RuntimeError("source_audit_report is required for poc stage")
            result = run_poc_stage(stage_context, hooks, source_audit_report=source_audit_report)
        self._persist_stage_result(context, result)
        return result

    def _build_stage_context(self, context: dict[str, object], stage_name: str) -> StageContext:
        artifact_service = get_artifact_service()
        task_id = str(context["task_id"])
        attempt_id = str(context["attempt_id"])
        attempt_root = artifact_service.ensure_attempt_dirs(task_id, attempt_id)
        return StageContext(
            task_id=task_id,
            attempt_id=attempt_id,
            workspace_id=str(context["workspace_id"]),
            stage_name=stage_name,
            input_kind=str(context["input_kind"]),
            pipeline_mode=str(context["pipeline_mode"]),
            project_path=str(context["project_path"]) if context["project_path"] else None,
            report_path=str(context["report_path"]) if context["report_path"] else None,
            repo_root=Path(str(context["repo_root"])).resolve(),
            attempt_root=attempt_root,
            runtime_root=attempt_root / "runtime",
            logs_dir=artifact_service.logs_dir(task_id, attempt_id),
            artifacts_dir=artifact_service.artifacts_dir(task_id, attempt_id),
            scratch_dir=artifact_service.scratch_dir(task_id, attempt_id),
            effective_config=dict(context["effective_config"]),
            provider_runtime=context.get("provider_runtime"),
        )

    def _run_custom_graph(self, context: dict[str, object]) -> GraphExecutionResult:
        task_id = str(context["task_id"])
        attempt_id = str(context["attempt_id"])
        stage_names = self._effective_stage_names(context)
        if not stage_names:
            raise RuntimeError("custom_graph has no declared stage names")
        self._set_graph_running(task_id, attempt_id, stage_names, "custom graph execution started")
        stage_context = self._build_stage_context(context, stage_names[0])
        hooks = StageHooks(
            heartbeat=lambda: self._heartbeat(attempt_id),
            is_cancel_requested=lambda: self._is_cancel_requested(task_id, attempt_id),
            graph_prepared=lambda payload: self._publish_materialized_graph_source(
                task_id,
                attempt_id,
                payload,
            ),
            graph_progress=lambda snapshot: self._sync_custom_graph_progress(
                task_id,
                attempt_id,
                snapshot,
            ),
        )
        hooks.heartbeat()
        result = run_graph(stage_context, hooks)
        for stage_result in result.stage_results:
            self._persist_stage_result(context, stage_result)
        for artifact in result.attempt_artifacts:
            self._persist_attempt_artifact(task_id, attempt_id, artifact)
        return result

    def _attach_provider_runtime(self, context: dict[str, object]) -> None:
        effective_config = context["effective_config"] if isinstance(context.get("effective_config"), dict) else {}
        explicit_task_model = str(effective_config.get("task_model") or "").strip() or None
        fallback_model = str(effective_config.get("model") or "").strip() or None
        try:
            resolved = get_provider_runtime_service().resolve_runtime(
                effective_config.get("provider_keys") if isinstance(effective_config.get("provider_keys"), list) else [],
                executor_mode=str(effective_config.get("executor_mode") or effective_config.get("execution_mode") or "").strip() or None,
                explicit_task_model=explicit_task_model,
                fallback_model=fallback_model,
            )
        except ProviderClientError as exc:
            provider_keys = effective_config.get("provider_keys") if isinstance(effective_config.get("provider_keys"), list) else []
            raise StageFailedError(
                "provider",
                f"provider resolution failed for {provider_keys or '[]'}: {exc}",
            ) from exc
        context["provider_runtime"] = resolved

    def _persist_stage_result(self, context: dict[str, object], result: StageExecutionResult) -> None:
        task_id = str(context["task_id"])
        attempt_id = str(context["attempt_id"])
        stage_name = result.stage_name
        log_artifact_id: str | None = None
        recorded_artifacts: list[dict[str, str]] = []

        with get_database().connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if result.log_path.exists():
                log_artifact_id = get_artifact_service().record_artifact(
                    conn,
                    task_id=task_id,
                    attempt_id=attempt_id,
                    stage_name=stage_name,
                    artifact_kind=self._log_artifact_kind(stage_name),
                    file_path=result.log_path,
                    display_name=result.log_path.name,
                )
                recorded_artifacts.append(
                    {
                        "artifact_kind": self._log_artifact_kind(stage_name),
                        "relative_path": self._relative_path_in_attempt(task_id, attempt_id, result.log_path),
                    }
                )

            session_count = 0
            for session_file in result.session_files:
                if not session_file.exists():
                    continue
                get_artifact_service().record_artifact(
                    conn,
                    task_id=task_id,
                    attempt_id=attempt_id,
                    stage_name=stage_name,
                    artifact_kind="session_file",
                    file_path=session_file,
                    display_name=session_file.name,
                )
                recorded_artifacts.append(
                    {
                        "artifact_kind": "session_file",
                        "relative_path": self._relative_path_in_attempt(task_id, attempt_id, session_file),
                    }
                )
                session_count += 1

            for artifact in result.artifacts:
                if not artifact.file_path.exists():
                    continue
                get_artifact_service().record_artifact(
                    conn,
                    task_id=task_id,
                    attempt_id=attempt_id,
                    stage_name=stage_name,
                    artifact_kind=artifact.artifact_kind,
                    file_path=artifact.file_path,
                    display_name=artifact.display_name,
                )
                recorded_artifacts.append(
                    {
                        "artifact_kind": artifact.artifact_kind,
                        "relative_path": self._relative_path_in_attempt(task_id, attempt_id, artifact.file_path),
                    }
                )

            conn.execute(
                """
                update ipc_audit_stage_runs
                set status = ?, return_code = ?, finished_at = ?, updated_at = ?, log_artifact_id = ?, session_count = ?, message = ?
                where attempt_id = ? and stage_name = ?
                """,
                (
                    result.status,
                    result.return_code,
                    utc_now_z(),
                    utc_now_z(),
                    log_artifact_id,
                    session_count,
                    result.message,
                    attempt_id,
                    stage_name,
                ),
            )
            if recorded_artifacts:
                get_event_service().append_event(
                    conn,
                    task_id=task_id,
                    attempt_id=attempt_id,
                    stage_name=stage_name,
                    event_type="stage.artifact.published",
                    level="info",
                    message=f"{stage_name} artifacts published",
                    payload={"artifacts": recorded_artifacts},
                )
            self._append_session_summary_events(
                conn,
                task_id=task_id,
                attempt_id=attempt_id,
                stage_name=stage_name,
                session_files=result.session_files,
            )
            get_event_service().append_event(
                conn,
                task_id=task_id,
                attempt_id=attempt_id,
                stage_name=stage_name,
                event_type="stage.completed",
                level=self._stage_level(result.status),
                message=result.message,
                payload={"status": result.status, "return_code": result.return_code, **result.metadata},
            )
            conn.commit()

    def _persist_attempt_artifact(self, task_id: str, attempt_id: str, artifact: StageArtifact) -> None:
        if not artifact.file_path.exists():
            return
        with get_database().connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                """
                select artifact_id
                from ipc_audit_artifacts
                where attempt_id = ? and relative_path = ?
                limit 1
                """,
                (
                    attempt_id,
                    self._relative_path_in_attempt(task_id, attempt_id, artifact.file_path),
                ),
            ).fetchone()
            if existing is None:
                get_artifact_service().record_artifact(
                    conn,
                    task_id=task_id,
                    attempt_id=attempt_id,
                    stage_name=None,
                    artifact_kind=artifact.artifact_kind,
                    file_path=artifact.file_path,
                    display_name=artifact.display_name,
                )
            conn.commit()

    def _publish_materialized_graph_source(self, task_id: str, attempt_id: str, payload: dict[str, Any]) -> None:
        try:
            with get_database().connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    """
                    select effective_config_json
                    from ipc_audit_task_attempts
                    where task_id = ? and attempt_id = ?
                    limit 1
                    """,
                    (task_id, attempt_id),
                ).fetchone()
                if row is None:
                    conn.commit()
                    return
                effective_config = json.loads(row["effective_config_json"] or "{}")
                if not isinstance(effective_config, dict):
                    effective_config = {}
                effective_config["materialized_graph_source"] = payload
                conn.execute(
                    """
                    update ipc_audit_task_attempts
                    set effective_config_json = ?, updated_at = ?
                    where task_id = ? and attempt_id = ?
                    """,
                    (json.dumps(effective_config, ensure_ascii=False), utc_now_z(), task_id, attempt_id),
                )
                conn.commit()
        except Exception as exc:  # noqa: BLE001
            logger.warning("failed to publish materialized graph for %s/%s: %s", task_id, attempt_id, exc)

    def _sync_custom_graph_progress(self, task_id: str, attempt_id: str, snapshot: dict[str, Any]) -> None:
        nodes = snapshot.get("nodes") if isinstance(snapshot.get("nodes"), dict) else {}
        if not nodes:
            return
        now = utc_now_z()
        current_stage = str(snapshot.get("current_stage") or "").strip() or None
        current_payload = nodes.get(current_stage) if current_stage and isinstance(nodes.get(current_stage), dict) else None
        task_message = (
            str(current_payload.get("message") or "").strip()
            if current_payload
            else "custom graph execution in progress"
        )
        try:
            with get_database().connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """
                    update ipc_audit_tasks
                    set current_stage = ?, updated_at = ?, started_at = coalesce(started_at, ?), message = ?
                    where task_id = ?
                    """,
                    (current_stage, now, now, task_message, task_id),
                )
                conn.execute(
                    """
                    update ipc_audit_task_attempts
                    set status = 'running', started_at = coalesce(started_at, ?), updated_at = ?
                    where attempt_id = ?
                    """,
                    (now, now, attempt_id),
                )
                for stage_name, payload in nodes.items():
                    if not isinstance(payload, dict):
                        continue
                    status = str(payload.get("status") or "").strip() or "pending"
                    message = str(payload.get("message") or "").strip()
                    if status == "running":
                        conn.execute(
                            """
                            update ipc_audit_stage_runs
                            set status = ?, started_at = coalesce(started_at, ?), updated_at = ?, message = ?
                            where attempt_id = ? and stage_name = ?
                            """,
                            (status, now, now, message, attempt_id, stage_name),
                        )
                    elif status in {"succeeded", "failed", "cancelled", "skipped", "timed_out"}:
                        conn.execute(
                            """
                            update ipc_audit_stage_runs
                            set status = ?, started_at = coalesce(started_at, ?), finished_at = coalesce(finished_at, ?), updated_at = ?, message = ?
                            where attempt_id = ? and stage_name = ?
                            """,
                            (status, now, now, now, message, attempt_id, stage_name),
                        )
                    else:
                        conn.execute(
                            """
                            update ipc_audit_stage_runs
                            set status = ?, updated_at = ?, message = ?
                            where attempt_id = ? and stage_name = ?
                            """,
                            (status, now, message, attempt_id, stage_name),
                        )
                conn.commit()
        except Exception as exc:  # noqa: BLE001
            logger.warning("failed to sync custom graph progress for %s/%s: %s", task_id, attempt_id, exc)

    def _set_stage_running(self, task_id: str, attempt_id: str, stage_name: str, message: str) -> None:
        now = utc_now_z()
        with get_database().connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                update ipc_audit_tasks
                set current_stage = ?, updated_at = ?, started_at = coalesce(started_at, ?), message = ?
                where task_id = ?
                """,
                (stage_name, now, now, message, task_id),
            )
            conn.execute(
                """
                update ipc_audit_task_attempts
                set status = 'running', started_at = coalesce(started_at, ?), updated_at = ?, failure_reason = null
                where attempt_id = ?
                """,
                (now, now, attempt_id),
            )
            conn.execute(
                """
                update ipc_audit_stage_runs
                set status = 'running', started_at = coalesce(started_at, ?), updated_at = ?, message = ?
                where attempt_id = ? and stage_name = ?
                """,
                (now, now, message, attempt_id, stage_name),
            )
            get_event_service().append_event(
                conn,
                task_id=task_id,
                attempt_id=attempt_id,
                stage_name=stage_name,
                event_type="stage.started",
                level="info",
                message=message,
                payload={},
            )
            conn.commit()

    def _set_graph_running(self, task_id: str, attempt_id: str, stage_names: list[str], message: str) -> None:
        now = utc_now_z()
        current_stage = stage_names[0]
        with get_database().connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                update ipc_audit_tasks
                set current_stage = ?, updated_at = ?, started_at = coalesce(started_at, ?), message = ?
                where task_id = ?
                """,
                (stage_names[0], now, now, message, task_id),
            )
            conn.execute(
                """
                update ipc_audit_task_attempts
                set status = 'running', started_at = coalesce(started_at, ?), updated_at = ?, failure_reason = null
                where attempt_id = ?
                """,
                (now, now, attempt_id),
            )
            for stage_name in stage_names:
                stage_status = "running" if stage_name == current_stage else "pending"
                stage_started_at = now if stage_name == current_stage else None
                conn.execute(
                    """
                    update ipc_audit_stage_runs
                    set status = ?, started_at = coalesce(started_at, ?), updated_at = ?, message = ?
                    where attempt_id = ? and stage_name = ?
                    """,
                    (
                        stage_status,
                        stage_started_at,
                        now,
                        message if stage_name == current_stage else "waiting for upstream graph dependencies",
                        attempt_id,
                        stage_name,
                    ),
                )
                if stage_name == current_stage:
                    get_event_service().append_event(
                        conn,
                        task_id=task_id,
                        attempt_id=attempt_id,
                        stage_name=stage_name,
                        event_type="stage.started",
                        level="info",
                        message=message,
                        payload={},
                    )
            conn.commit()

    def _mark_stage_skipped(self, context: dict[str, object], stage_name: str, reason: str) -> None:
        now = utc_now_z()
        with get_database().connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                update ipc_audit_stage_runs
                set status = 'skipped', finished_at = coalesce(finished_at, ?), updated_at = ?, message = ?
                where attempt_id = ? and stage_name = ?
                """,
                (now, now, reason, context["attempt_id"], stage_name),
            )
            get_event_service().append_event(
                conn,
                task_id=str(context["task_id"]),
                attempt_id=str(context["attempt_id"]),
                stage_name=stage_name,
                event_type="stage.completed",
                level="info",
                message=reason,
                payload={"status": "skipped"},
            )
            conn.commit()

    def _complete_attempt(
        self,
        task_id: str,
        attempt_id: str,
        *,
        task_status: str,
        attempt_status: str,
        message: str,
    ) -> None:
        now = utc_now_z()
        with get_database().connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                update ipc_audit_task_attempts
                set status = ?, finished_at = ?, updated_at = ?, failure_reason = case when ? = 'partial_success' then ? else null end
                where attempt_id = ?
                """,
                (attempt_status, now, now, attempt_status, message, attempt_id),
            )
            conn.execute(
                """
                update ipc_audit_tasks
                set status = ?, current_stage = null, finished_at = ?, updated_at = ?, message = ?
                where task_id = ?
                """,
                (task_status, now, now, message, task_id),
            )
            get_event_service().append_event(
                conn,
                task_id=task_id,
                attempt_id=attempt_id,
                stage_name=None,
                event_type="attempt.completed",
                level="info" if attempt_status == "succeeded" else "warning",
                message=message,
                payload={"status": attempt_status},
            )
            get_event_service().append_event(
                conn,
                task_id=task_id,
                attempt_id=attempt_id,
                stage_name=None,
                event_type="task.completed",
                level="info" if task_status == "succeeded" else "warning",
                message=message,
                payload={"status": task_status},
            )
            conn.commit()

    def _fail_attempt(self, task_id: str, attempt_id: str, message: str) -> None:
        now = utc_now_z()
        with get_database().connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                update ipc_audit_stage_runs
                set status = case when status = 'running' then 'failed' else 'skipped' end,
                    finished_at = coalesce(finished_at, ?),
                    updated_at = ?,
                    message = case when status = 'running' then ? else 'not executed because upstream stage failed' end
                where attempt_id = ? and status in ('pending', 'queued', 'running')
                """,
                (now, now, message, attempt_id),
            )
            conn.execute(
                """
                update ipc_audit_task_attempts
                set status = 'failed', failure_reason = ?, finished_at = ?, updated_at = ?
                where attempt_id = ?
                """,
                (message, now, now, attempt_id),
            )
            conn.execute(
                """
                update ipc_audit_tasks
                set status = 'failed', current_stage = null, finished_at = ?, updated_at = ?, message = ?
                where task_id = ?
                """,
                (now, now, message, task_id),
            )
            get_event_service().append_event(
                conn,
                task_id=task_id,
                attempt_id=attempt_id,
                stage_name=None,
                event_type="task.failed",
                level="error",
                message=message,
                payload={},
            )
            conn.commit()

    def _cancel_attempt(self, task_id: str, attempt_id: str, message: str) -> None:
        now = utc_now_z()
        with get_database().connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                update ipc_audit_stage_runs
                set status = 'cancelled', finished_at = coalesce(finished_at, ?), updated_at = ?, message = ?
                where attempt_id = ? and status in ('pending', 'queued', 'running')
                """,
                (now, now, message, attempt_id),
            )
            conn.execute(
                """
                update ipc_audit_task_attempts
                set status = 'cancelled', finished_at = ?, updated_at = ?, failure_reason = ?
                where attempt_id = ?
                """,
                (now, now, message, attempt_id),
            )
            conn.execute(
                """
                update ipc_audit_tasks
                set status = 'cancelled', current_stage = null, finished_at = ?, updated_at = ?, message = ?
                where task_id = ?
                """,
                (now, now, message, task_id),
            )
            get_event_service().append_event(
                conn,
                task_id=task_id,
                attempt_id=attempt_id,
                stage_name=None,
                event_type="task.cancelled",
                level="warning",
                message=message,
                payload={},
            )
            conn.commit()

    def _timeout_attempt(self, task_id: str, attempt_id: str, message: str) -> None:
        now = utc_now_z()
        with get_database().connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                update ipc_audit_stage_runs
                set status = case when status = 'running' then 'timed_out' else 'skipped' end,
                    finished_at = coalesce(finished_at, ?),
                    updated_at = ?,
                    message = case when status = 'running' then ? else 'not executed because task timed out' end
                where attempt_id = ? and status in ('pending', 'queued', 'running')
                """,
                (now, now, message, attempt_id),
            )
            conn.execute(
                """
                update ipc_audit_task_attempts
                set status = 'timed_out', finished_at = ?, updated_at = ?, failure_reason = ?
                where attempt_id = ?
                """,
                (now, now, message, attempt_id),
            )
            conn.execute(
                """
                update ipc_audit_tasks
                set status = 'failed', current_stage = null, finished_at = ?, updated_at = ?, message = ?
                where task_id = ?
                """,
                (now, now, message, task_id),
            )
            get_event_service().append_event(
                conn,
                task_id=task_id,
                attempt_id=attempt_id,
                stage_name=None,
                event_type="task.failed",
                level="error",
                message=message,
                payload={"attempt_status": "timed_out"},
            )
            conn.commit()

    def _heartbeat(self, attempt_id: str) -> None:
        now = utc_now_z()
        lease = self._future_time(get_config().execution.lease_duration_seconds)
        with get_database().connect() as conn:
            conn.execute(
                """
                update ipc_audit_task_attempts
                set heartbeat_at = ?, lease_expires_at = ?, updated_at = ?
                where attempt_id = ?
                """,
                (now, lease, now, attempt_id),
            )

    def _load_context(self, attempt_id: str) -> dict[str, object]:
        with get_database().connect() as conn:
            row = conn.execute(
                """
                select
                  t.task_id,
                  t.workspace_id,
                  t.pipeline_mode,
                  t.input_kind,
                  t.project_path,
                  t.report_path,
                  t.status as task_status,
                  a.attempt_id,
                  a.effective_config_json,
                  a.status as attempt_status
                from ipc_audit_task_attempts a
                join ipc_audit_tasks t on t.task_id = a.task_id
                where a.attempt_id = ?
                """,
                (attempt_id,),
            ).fetchone()
        if row is None:
            raise RuntimeError(f"attempt not found: {attempt_id}")
        workspace = get_workspace_service().get_workspace(row["workspace_id"])
        return {
            "task_id": row["task_id"],
            "workspace_id": row["workspace_id"],
            "workspace_supports_poc": workspace.supports_poc,
            "pipeline_mode": row["pipeline_mode"],
            "input_kind": row["input_kind"],
            "project_path": row["project_path"],
            "report_path": row["report_path"],
            "task_status": row["task_status"],
            "attempt_id": row["attempt_id"],
            "attempt_status": row["attempt_status"],
            "effective_config": json.loads(row["effective_config_json"] or "{}"),
            "repo_root": workspace.repo_root,
        }

    def _resolve_source_audit_report(self, context: dict[str, object]) -> Path:
        workspace = get_workspace_service().get_workspace(str(context["workspace_id"]))
        if context["input_kind"] == "existing_audit_report" and context["report_path"]:
            return get_workspace_service().resolve_relative_path(workspace, str(context["report_path"]), expect="file")
        if context["report_path"]:
            return get_workspace_service().resolve_relative_path(workspace, str(context["report_path"]), expect="file")
        with get_database().connect() as conn:
            row = conn.execute(
                """
                select task_id, attempt_id, relative_path
                from ipc_audit_artifacts
                where task_id = ? and artifact_kind = 'audit_report'
                order by created_at desc
                limit 1
                """,
                (context["task_id"],),
            ).fetchone()
        if row is None:
            raise RuntimeError(f"no audit report available for task: {context['task_id']}")
        return get_artifact_service().attempt_root(row["task_id"], row["attempt_id"]) / row["relative_path"]

    def _poc_available(self) -> bool:
        cfg = get_config().execution
        return cfg.poc_enabled and cfg.poc_runtime_available

    def _is_cancel_requested(self, task_id: str, attempt_id: str) -> bool:
        with get_database().connect() as conn:
            row = conn.execute(
                """
                select t.status as task_status, a.status as attempt_status
                from ipc_audit_tasks t
                join ipc_audit_task_attempts a on a.task_id = t.task_id
                where t.task_id = ? and a.attempt_id = ?
                """,
                (task_id, attempt_id),
            ).fetchone()
        return row is not None and (
            row["task_status"] == "cancel_requested" or row["attempt_status"] == "cancel_requested"
        )

    def _write_runtime_manifest(self, context: dict[str, object]) -> None:
        task_id = str(context["task_id"])
        attempt_id = str(context["attempt_id"])
        attempt_root = get_artifact_service().ensure_attempt_dirs(task_id, attempt_id)
        manifest_path = attempt_root / "runtime" / "manifest.json"
        with get_database().connect() as conn:
            task_row = conn.execute("select * from ipc_audit_tasks where task_id = ?", (task_id,)).fetchone()
            attempt_row = conn.execute("select * from ipc_audit_task_attempts where attempt_id = ?", (attempt_id,)).fetchone()
            stage_rows = conn.execute(
                """
                select stage_name, status, started_at, finished_at, return_code, session_count, message
                from ipc_audit_stage_runs
                where attempt_id = ?
                order by stage_name asc
                """,
                (attempt_id,),
            ).fetchall()
            artifact_rows = conn.execute(
                """
                select artifact_kind, relative_path, display_name, content_type, size, created_at
                from ipc_audit_artifacts
                where attempt_id = ?
                order by created_at asc
                """,
                (attempt_id,),
            ).fetchall()
        payload = {
            "service": "secflow-app-ipc-audit",
            "generated_at": utc_now_z(),
            "task": dict(task_row) if task_row is not None else {"task_id": task_id},
            "attempt": dict(attempt_row) if attempt_row is not None else {"attempt_id": attempt_id},
            "execution": {
                "mode": get_config().execution.mode,
                "repo_root": str(context["repo_root"]),
                "attempt_root": str(attempt_root),
                "provider_keys": list(getattr(context.get("provider_runtime"), "provider_keys", []) or []),
                "mapped_env_keys": list(getattr(context.get("provider_runtime"), "merged_env", {}).keys()),
                "mapped_file_paths": [
                    str(item.get("path") or "").strip()
                    for item in getattr(context.get("provider_runtime"), "merged_files", []) or []
                    if isinstance(item, dict) and str(item.get("path") or "").strip()
                ],
                "effective_model": getattr(context.get("provider_runtime"), "effective_model", None),
                "executor_model": getattr(context.get("provider_runtime"), "executor_model", None),
            },
            "stages": [dict(row) for row in stage_rows],
            "artifacts": [dict(row) for row in artifact_rows],
            "report_outputs": [
                {
                    **item,
                    "exists": any(str(artifact["relative_path"]) == str(item.get("path") or "") for artifact in artifact_rows),
                }
                for item in (
                    context["effective_config"].get("report_outputs")
                    if isinstance(context["effective_config"], dict) and isinstance(context["effective_config"].get("report_outputs"), list)
                    else []
                )
                if isinstance(item, dict)
            ],
        }
        write_json_file(manifest_path, payload)
        now = utc_now_z()
        with get_database().connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                """
                select artifact_id
                from ipc_audit_artifacts
                where attempt_id = ? and artifact_kind = 'runtime_manifest'
                limit 1
                """,
                (attempt_id,),
            ).fetchone()
            if existing is None:
                get_artifact_service().record_artifact(
                    conn,
                    task_id=task_id,
                    attempt_id=attempt_id,
                    stage_name=None,
                    artifact_kind="runtime_manifest",
                    file_path=manifest_path,
                    display_name=manifest_path.name,
                )
            conn.execute(
                """
                update ipc_audit_task_attempts
                set runtime_manifest_path = ?, updated_at = ?
                where attempt_id = ?
                """,
                (
                    manifest_path.resolve().relative_to(attempt_root.resolve()).as_posix(),
                    now,
                    attempt_id,
                ),
            )
            conn.commit()

    @staticmethod
    def _log_artifact_kind(stage_name: str) -> str:
        if stage_name == "audit":
            return "audit_log"
        if stage_name == "poc":
            return "poc_log"
        return "stage_log"

    @staticmethod
    def _stage_level(status: str) -> str:
        if status == "succeeded":
            return "info"
        if status in {"cancelled", "skipped"}:
            return "warning"
        return "error"

    @staticmethod
    def _relative_path_in_attempt(task_id: str, attempt_id: str, path: Path) -> str:
        attempt_root = get_artifact_service().attempt_root(task_id, attempt_id).resolve()
        return path.resolve().relative_to(attempt_root).as_posix()

    @staticmethod
    def _effective_stage_names(context: dict[str, object]) -> list[str]:
        effective_config = context["effective_config"] if isinstance(context.get("effective_config"), dict) else {}
        stage_names = effective_config.get("stage_names") if isinstance(effective_config.get("stage_names"), list) else []
        return [str(item).strip() for item in stage_names if str(item).strip()]

    def _append_session_summary_events(
        self,
        conn: DatabaseConnection,
        *,
        task_id: str,
        attempt_id: str,
        stage_name: str,
        session_files: list[Path],
    ) -> None:
        for path in session_files:
            if not path.exists():
                continue
            relative_path = self._relative_path_in_attempt(task_id, attempt_id, path)
            if path.name == "events.jsonl":
                payload = self._summarize_jsonl_session(path, relative_path=relative_path)
                if payload["line_count"] > 0:
                    get_event_service().append_event(
                        conn,
                        task_id=task_id,
                        attempt_id=attempt_id,
                        stage_name=stage_name,
                        event_type="stage.stdout.appended",
                        level="info",
                        message=f"{stage_name} executor output captured",
                        payload=payload,
                    )
            elif path.name == "last-message.md":
                payload = self._summarize_text_session(path, relative_path=relative_path)
                if payload["chars"] > 0:
                    get_event_service().append_event(
                        conn,
                        task_id=task_id,
                        attempt_id=attempt_id,
                        stage_name=stage_name,
                        event_type="stage.agent.message",
                        level="info",
                        message=f"{stage_name} final agent message captured",
                        payload=payload,
                    )

    @staticmethod
    def _summarize_jsonl_session(path: Path, *, relative_path: str) -> dict[str, Any]:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        type_counter: Counter[str] = Counter()
        preview_parts: list[str] = []
        parsed_count = 0
        raw_count = 0
        for line in lines[:200]:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                item = json.loads(stripped)
            except json.JSONDecodeError:
                raw_count += 1
                if len(preview_parts) < 3:
                    preview_parts.append(stripped[:240])
                continue
            parsed_count += 1
            event_type = str(item.get("type") or item.get("event") or "unknown")
            type_counter[event_type] += 1
            preview = ExecutionService._extract_event_preview(item)
            if preview and len(preview_parts) < 3:
                preview_parts.append(preview[:240])
        return {
            "session_file_path": relative_path,
            "line_count": len(lines),
            "byte_count": path.stat().st_size,
            "parsed_json_count": parsed_count,
            "raw_line_count": raw_count,
            "event_types": dict(type_counter),
            "preview": preview_parts,
        }

    @staticmethod
    def _summarize_text_session(path: Path, *, relative_path: str) -> dict[str, Any]:
        content = path.read_text(encoding="utf-8", errors="replace")
        preview_limit = 1200
        return {
            "session_file_path": relative_path,
            "chars": len(content),
            "truncated": len(content) > preview_limit,
            "preview": content[:preview_limit],
        }

    @staticmethod
    def _extract_event_preview(item: Any) -> str | None:
        return ExecutionService._extract_text_preview(item)

    @staticmethod
    def _extract_text_preview(item: Any, *, depth: int = 0) -> str | None:
        if depth > 5:
            return None
        if isinstance(item, str):
            stripped = item.strip()
            return stripped or None
        if isinstance(item, list):
            parts = [part for value in item if (part := ExecutionService._extract_text_preview(value, depth=depth + 1))]
            if parts:
                return "\n".join(parts)
            return None
        if not isinstance(item, dict):
            return None
        for key in ("text", "message", "content", "delta", "output_text", "value"):
            if key not in item:
                continue
            if preview := ExecutionService._extract_text_preview(item[key], depth=depth + 1):
                return preview
        for key in ("part", "payload", "data", "response", "item"):
            if key not in item:
                continue
            if preview := ExecutionService._extract_text_preview(item[key], depth=depth + 1):
                return preview
        return None

    @staticmethod
    def _future_time(seconds: int) -> str:
        from datetime import datetime, timedelta

        value = datetime.fromisoformat(utc_now_z().replace("Z", "+00:00")) + timedelta(seconds=seconds)
        return value.isoformat(timespec="seconds").replace("+00:00", "Z")


class CancelledError(RuntimeError):
    pass


class TimedOutError(RuntimeError):
    pass


class StageFailedError(RuntimeError):
    def __init__(self, stage_name: str, message: str) -> None:
        super().__init__(message)
        self.stage_name = stage_name
        self.message = message


_execution_service: ExecutionService | None = None


def get_execution_service() -> ExecutionService:
    global _execution_service
    if _execution_service is None:
        _execution_service = ExecutionService()
    return _execution_service
