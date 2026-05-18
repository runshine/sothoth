from __future__ import annotations

import json
from typing import Any

from fastapi import HTTPException, status

from app.core.ids import new_template_id
from app.core.time_utils import utc_now_z
from app.db.database import DatabaseRow, get_database
from app.schemas import (
    InputRef,
    TaskCreateRequest,
    TaskTemplateConfig,
    TaskTemplateCreateRequest,
    TaskTemplateResponse,
    TaskTemplateUpdateRequest,
)
from app.services.task_service import get_task_service
from app.services.workspace_service import get_workspace_service
from app.core.config import get_config


class TemplateService:
    def list_templates(self, *, workspace_id: str | None = None) -> list[TaskTemplateResponse]:
        params: list[Any] = []
        where_sql = "1=1"
        if workspace_id:
            get_workspace_service().get_workspace(workspace_id)
            where_sql += " and workspace_id = ?"
            params.append(workspace_id)
        with get_database().connect() as conn:
            rows = conn.execute(
                f"""
                select *
                from ipc_audit_task_templates
                where {where_sql}
                order by workspace_id asc, updated_at desc, name asc
                """,
                tuple(params),
            ).fetchall()
        return [self._row_to_model(row) for row in rows]

    def get_template(self, template_id: str) -> TaskTemplateResponse:
        with get_database().connect() as conn:
            row = conn.execute(
                "select * from ipc_audit_task_templates where template_id = ?",
                (template_id,),
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"template not found: {template_id}")
        return self._row_to_model(row)

    def create_template(self, payload: TaskTemplateCreateRequest, subject) -> TaskTemplateResponse:
        workspace = get_workspace_service().get_workspace(payload.workspace_id)
        normalized = self._normalize_template_config(payload.workspace_id, payload.config)
        template_id = new_template_id()
        now = utc_now_z()
        with get_database().connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                """
                select template_id from ipc_audit_task_templates
                where workspace_id = ? and name = ?
                limit 1
                """,
                (payload.workspace_id, payload.name.strip()),
            ).fetchone()
            if existing is not None:
                conn.rollback()
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"template name already exists in workspace {workspace.workspace_id}: {payload.name.strip()}",
                )
            conn.execute(
                """
                insert into ipc_audit_task_templates (
                  template_id, workspace_id, name, description, pipeline_mode, executor_mode, model,
                  provider_keys_json, graph_source_json, report_outputs_json, notes,
                  created_by, created_at, updated_by, updated_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    template_id,
                    payload.workspace_id,
                    payload.name.strip(),
                    str(payload.description or "").strip() or None,
                    normalized["pipeline_mode"],
                    normalized["executor_mode"],
                    normalized["model"],
                    json.dumps(normalized["provider_keys"], ensure_ascii=False),
                    json.dumps(normalized["graph_source"], ensure_ascii=False) if normalized["graph_source"] is not None else None,
                    json.dumps(normalized["report_outputs"], ensure_ascii=False),
                    normalized["notes"],
                    subject.username,
                    now,
                    subject.username,
                    now,
                ),
            )
            conn.commit()
        return self.get_template(template_id)

    def update_template(self, template_id: str, payload: TaskTemplateUpdateRequest, subject) -> TaskTemplateResponse:
        with get_database().connect() as conn:
            current = conn.execute(
                "select * from ipc_audit_task_templates where template_id = ?",
                (template_id,),
            ).fetchone()
            if current is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"template not found: {template_id}")
            normalized = self._normalize_template_config(current["workspace_id"], payload.config)
            now = utc_now_z()
            conn.execute("BEGIN IMMEDIATE")
            conflict = conn.execute(
                """
                select template_id from ipc_audit_task_templates
                where workspace_id = ? and name = ? and template_id <> ?
                limit 1
                """,
                (current["workspace_id"], payload.name.strip(), template_id),
            ).fetchone()
            if conflict is not None:
                conn.rollback()
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"template name already exists in workspace {current['workspace_id']}: {payload.name.strip()}",
                )
            conn.execute(
                """
                update ipc_audit_task_templates
                set name = ?,
                    description = ?,
                    pipeline_mode = ?,
                    executor_mode = ?,
                    model = ?,
                    provider_keys_json = ?,
                    graph_source_json = ?,
                    report_outputs_json = ?,
                    notes = ?,
                    updated_by = ?,
                    updated_at = ?
                where template_id = ?
                """,
                (
                    payload.name.strip(),
                    str(payload.description or "").strip() or None,
                    normalized["pipeline_mode"],
                    normalized["executor_mode"],
                    normalized["model"],
                    json.dumps(normalized["provider_keys"], ensure_ascii=False),
                    json.dumps(normalized["graph_source"], ensure_ascii=False) if normalized["graph_source"] is not None else None,
                    json.dumps(normalized["report_outputs"], ensure_ascii=False),
                    normalized["notes"],
                    subject.username,
                    now,
                    template_id,
                ),
            )
            conn.commit()
        return self.get_template(template_id)

    def delete_template(self, template_id: str) -> None:
        with get_database().connect() as conn:
            cursor = conn.execute("delete from ipc_audit_task_templates where template_id = ?", (template_id,))
            conn.commit()
        if cursor.rowcount <= 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"template not found: {template_id}")

    def _normalize_template_config(self, workspace_id: str, payload: TaskTemplateConfig) -> dict[str, Any]:
        workspace = get_workspace_service().get_workspace(workspace_id)
        poc_available = (
            get_config().execution.poc_enabled
            and get_config().execution.poc_runtime_available
            and workspace.supports_poc
        )
        if payload.pipeline_mode == "audit_then_poc" and not poc_available:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="poc is not supported in current workspace")
        if payload.pipeline_mode == "poc_only" and not poc_available:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="poc is not supported in current workspace")

        executor_mode = str(payload.executor_mode or get_config().execution.mode)
        if payload.pipeline_mode == "custom_graph" and executor_mode != "agentflow_cli":
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="custom_graph currently requires agentflow_cli")

        provider_keys = self._normalize_provider_keys(payload.provider_keys)
        dummy = TaskCreateRequest(
            title="template",
            workspace_id=workspace_id,
            pipeline_mode=payload.pipeline_mode,
            input_ref=InputRef(kind="custom_project", project_path="template"),
            executor_mode=executor_mode,
            model=str(payload.model or "").strip() or None,
            provider_keys=provider_keys,
            graph_source=payload.graph_source,
            report_outputs=payload.report_outputs,
            notes=str(payload.notes or "").strip() or None,
        )
        task_service = get_task_service()
        runtime_provider = task_service._resolve_runtime_provider(
            provider_keys=provider_keys,
            executor_mode=executor_mode,
            explicit_task_model=str(payload.model or "").strip() or None,
        )
        task_service._validate_runtime_provider_compatibility(
            runtime_provider,
            executor_mode=executor_mode,
            pipeline_mode=payload.pipeline_mode,
            graph_source=payload.graph_source.model_dump() if payload.graph_source is not None else None,
        )
        report_outputs = task_service._normalize_report_outputs(dummy)
        task_service._determine_stage_names(dummy, report_outputs)

        return {
            "pipeline_mode": payload.pipeline_mode,
            "executor_mode": executor_mode,
            "model": str(payload.model or "").strip() or None,
            "provider_keys": provider_keys,
            "graph_source": payload.graph_source.model_dump() if payload.graph_source is not None else None,
            "report_outputs": report_outputs,
            "notes": str(payload.notes or "").strip() or None,
        }

    @staticmethod
    def _normalize_provider_keys(values: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for item in values:
            provider_key = str(item or "").strip()
            if not provider_key or provider_key in seen:
                continue
            seen.add(provider_key)
            normalized.append(provider_key)
        return normalized

    def _row_to_model(self, row: DatabaseRow) -> TaskTemplateResponse:
        graph_source = json.loads(row["graph_source_json"]) if row["graph_source_json"] else None
        report_outputs = json.loads(row["report_outputs_json"] or "[]")
        provider_keys = json.loads(row["provider_keys_json"] or "[]")
        config = TaskTemplateConfig(
            pipeline_mode=row["pipeline_mode"],
            executor_mode=row["executor_mode"],
            model=row["model"],
            provider_keys=provider_keys if isinstance(provider_keys, list) else [],
            graph_source=graph_source,
            report_outputs=report_outputs if isinstance(report_outputs, list) else [],
            notes=row["notes"],
        )
        return TaskTemplateResponse(
            template_id=row["template_id"],
            workspace_id=row["workspace_id"],
            name=row["name"],
            description=row["description"],
            config=config,
            created_by=row["created_by"],
            created_at=row["created_at"],
            updated_by=row["updated_by"],
            updated_at=row["updated_at"],
        )


_template_service: TemplateService | None = None


def get_template_service() -> TemplateService:
    global _template_service
    if _template_service is None:
        _template_service = TemplateService()
    return _template_service
