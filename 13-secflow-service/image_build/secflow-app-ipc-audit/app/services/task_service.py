from __future__ import annotations

import json
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from fastapi import HTTPException, status

from app.core.config import get_config
from app.core.ids import new_attempt_id, new_task_id
from app.core.time_utils import utc_now_z
from app.db.database import get_database
from app.schemas import (
    ArtifactListResponse,
    AttemptDetailResponse,
    AttemptWorkerResponse,
    EventPageResponse,
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

ACTIVE_TASK_STATUSES = {"queued", "running", "cancel_requested"}
ACTIVE_ATTEMPT_STATUSES = {"queued", "claimed", "running", "cancel_requested"}
TERMINAL_TASK_STATUSES = {"succeeded", "partial_success", "failed", "cancelled", "needs_attention"}


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

        input_ref = normalized.normalized_input_ref
        target_key = input_ref.project_path or input_ref.report_path or ""
        now = utc_now_z()
        execution_cfg = get_config().execution
        executor_mode = str(payload.executor_mode or execution_cfg.mode)
        explicit_task_model = str(payload.model or "").strip() or None
        try:
            runtime_provider = get_provider_runtime_service().resolve_runtime(
                payload.provider_keys,
                explicit_task_model=explicit_task_model,
            )
        except ProviderClientError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
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
                "start_stage": "poc" if payload.pipeline_mode == "poc_only" else "audit",
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
        if stage_name not in {"audit", "poc"}:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"unsupported stage: {stage_name}")
        with get_database().connect() as conn:
            attempt_row = self._get_attempt_row(conn, attempt_id)
            if attempt_row["task_id"] != task_id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"attempt not found for task: {attempt_id}")
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
        attempt_root = get_artifact_service().attempt_root(task_id, attempt_id).resolve()
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
        normalized, candidate = self.resolve_stage_session_file_path(task_id, attempt_id, stage_name, path)
        if not candidate.exists() or not candidate.is_file():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"session file not found: {path}")
        data = candidate.read_bytes()
        max_bytes = 1024 * 1024
        return {
            "path": normalized.as_posix(),
            "content": data[:max_bytes].decode("utf-8", errors="replace"),
            "truncated": len(data) > max_bytes,
            "next_cursor": min(len(data), max_bytes),
        }

    def resolve_stage_session_file_path(self, task_id: str, attempt_id: str, stage_name: str, path: str) -> tuple[PurePosixPath, Path]:
        with get_database().connect() as conn:
            attempt_row = self._get_attempt_row(conn, attempt_id)
            if attempt_row["task_id"] != task_id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"attempt not found for task: {attempt_id}")
        if stage_name not in {"audit", "poc"}:
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
            conn.execute("BEGIN IMMEDIATE")
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
                if payload.stage == "poc":
                    start_stage = "poc"
                    self._find_latest_audit_report(conn, task_id)
                elif payload.stage == "audit":
                    start_stage = "audit"
                else:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="stage is required for from_stage retry")
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
            conn.execute(
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
            changes = conn.execute("select changes()").fetchone()[0]
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

    def recover_expired_attempts(self) -> int:
        now = utc_now_z()
        recovered = 0
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
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """
                    update ipc_audit_task_attempts
                    set status = 'lost', updated_at = ?, finished_at = ?, failure_reason = 'lease expired'
                    where attempt_id = ?
                    """,
                    (now, now, row["attempt_id"]),
                )
                conn.execute(
                    """
                    update ipc_audit_tasks
                    set status = 'failed', updated_at = ?, finished_at = ?, message = 'worker lease expired'
                    where task_id = ? and latest_attempt_id = ?
                    """,
                    (now, now, row["task_id"], row["attempt_id"]),
                )
                get_event_service().append_event(
                    conn,
                    task_id=row["task_id"],
                    attempt_id=row["attempt_id"],
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
        conn: sqlite3.Connection,
        attempt_id: str,
        *,
        attempt_no: int,
        start_stage: str,
        pipeline_mode: str,
        created_at: str,
    ) -> None:
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

    def _get_task_row(self, conn: sqlite3.Connection, task_id: str) -> sqlite3.Row:
        row = conn.execute("select * from ipc_audit_tasks where task_id = ?", (task_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"task not found: {task_id}")
        return row

    def _get_attempt_row(self, conn: sqlite3.Connection, attempt_id: str) -> sqlite3.Row:
        row = conn.execute("select * from ipc_audit_task_attempts where attempt_id = ?", (attempt_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"attempt not found: {attempt_id}")
        return row

    def _task_row_to_summary(self, row: sqlite3.Row) -> TaskSummaryResponse:
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

    def _attempt_row_to_model(self, conn: sqlite3.Connection, row: sqlite3.Row) -> AttemptDetailResponse:
        stage_rows = conn.execute(
            """
            select stage_name, status, attempt_no, started_at, finished_at, return_code, log_artifact_id, message
            from ipc_audit_stage_runs
            where attempt_id = ?
            order by stage_name asc
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
            effective_config=json.loads(row["effective_config_json"] or "{}"),
            stage_runs=stage_runs,
            message=row["failure_reason"],
            created_at=row["created_at"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
        )

    @staticmethod
    def _future_time(seconds: int) -> str:
        from datetime import timedelta

        now = utc_now_z()
        base = now.replace("Z", "+00:00")
        from datetime import datetime

        value = datetime.fromisoformat(base) + timedelta(seconds=seconds)
        return value.isoformat(timespec="seconds").replace("+00:00", "Z")

    @staticmethod
    def _find_latest_audit_report(conn: sqlite3.Connection, task_id: str) -> sqlite3.Row:
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


_task_service: TaskService | None = None


def get_task_service() -> TaskService:
    global _task_service
    if _task_service is None:
        _task_service = TaskService()
    return _task_service
