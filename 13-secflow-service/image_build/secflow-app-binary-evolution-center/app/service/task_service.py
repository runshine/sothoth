from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import shutil
import uuid
from pathlib import Path
from typing import Any

import httpx
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.config import get_config
from app.model import (
    EvolutionServiceConfig,
    EvolutionTask,
    EvolutionTaskArtifact,
    EvolutionTaskEvent,
    EvolutionTaskRound,
    EvolutionTaskSource,
)
from app.observability import get_observability
from app.schemas import (
    DEFAULT_EVOLVE_AGENTS,
    EvolutionApplyResponse,
    EvolutionConfigPayload,
    EvolutionConfigResponse,
    EvolutionExperimentCreateRequest,
    EvolutionMemoryModePatchRequest,
    EvolutionMemoryModeResponse,
    EvolutionPreviewRequest,
    EvolutionPreviewResponse,
    EvolutionPreviewSource,
    EvolutionTaskCreateRequest,
    EvolutionTaskDetail,
    EvolutionTaskRoundResponse,
    EvolutionTaskSummary,
)
from app.service.dataflow_client import get_dataflow_vuln_client
from app.service.vuln_client import get_vuln_client
from app.time_utils import isoformat_local, now_local

logger = logging.getLogger(__name__)

TERMINAL_TASK_STATUSES = {"succeeded", "failed", "cancelled"}
TERMINAL_DFVS_STATUSES = {"completed", "succeeded", "failed", "cancelled", "interrupted", "error"}
ALLOWED_EVOLVE_AGENTS = set(DEFAULT_EVOLVE_AGENTS)


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:20]}"


def _json_dict(value: Any) -> dict[str, Any]:
    return dict(value or {}) if isinstance(value, dict) else {}


def _json_list(value: Any) -> list[Any]:
    return list(value or []) if isinstance(value, list) else []


def _trimmed(value: Any) -> str:
    return str(value or "").strip()


def _as_int(value: Any, fallback: int) -> int:
    try:
        return int(value)
    except Exception:
        return fallback


def _is_downstream_transport_error(exc: Exception) -> bool:
    if isinstance(exc, httpx.TimeoutException | httpx.ConnectError | httpx.RequestError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        return int(exc.response.status_code or 0) >= 500
    return False


class TaskService:
    async def preview(
        self,
        *,
        project_id: str,
        payload: EvolutionPreviewRequest,
        token: str,
    ) -> EvolutionPreviewResponse:
        requested_case_ids = self._normalize_case_ids(payload.case_ids)
        if not requested_case_ids:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="case_ids is required")

        vuln_client = get_vuln_client()
        dataflow_client = get_dataflow_vuln_client()

        groups: dict[str, dict[str, Any]] = {}
        blocked_reasons: list[str] = []

        for case_id in requested_case_ids:
            case = await vuln_client.get_case(case_id, token)
            source_task = _json_dict(case.get("source_task"))
            source_service = _trimmed(source_task.get("service_name") or source_task.get("service_id"))
            if source_service != "secflow-app-dataflow-vuln-scanner":
                blocked_reasons.append(f"案例 {case_id} 不是来自数据流漏洞挖掘服务")
                continue
            source_task_id = _trimmed(source_task.get("task_id"))
            if not source_task_id:
                blocked_reasons.append(f"案例 {case_id} 缺少原始任务信息")
                continue
            grouped = groups.setdefault(
                source_task_id,
                {
                    "selected_case_ids": [],
                    "source_execution_id": source_task.get("execution_id"),
                    "source_run_id": source_task.get("run_id"),
                    "source_title": source_task.get("run_name") or source_task_id,
                },
            )
            grouped["selected_case_ids"].append(case_id)

        sources: list[EvolutionPreviewSource] = []
        effective_case_ids: list[str] = []
        can_create = not blocked_reasons

        for source_task_id, grouped in groups.items():
            all_cases_resp = await vuln_client.list_cases(
                token,
                project_id=project_id,
                source_service_name="secflow-app-dataflow-vuln-scanner",
                source_task_id=source_task_id,
            )
            all_cases = list(all_cases_resp.get("items") or [])
            all_case_ids = self._normalize_case_ids(item.get("id") for item in all_cases)
            auto_expanded_case_ids = [case_id for case_id in all_case_ids if case_id not in grouped["selected_case_ids"]]
            effective_case_ids.extend(all_case_ids)

            source_blocked_reasons: list[str] = []
            for case in all_cases:
                reason = self._case_block_reason(case)
                if reason:
                    source_blocked_reasons.append(f"{case.get('id')}: {reason}")

            replay_payload = await dataflow_client.get_replay_ready(source_task_id, token)
            source_summary = await dataflow_client.get_task(source_task_id, token)
            task_purpose = _trimmed(replay_payload.get("task_purpose") or source_summary.get("task_purpose") or "normal").lower()
            replay_ready = bool(replay_payload.get("replay_ready"))
            replay_reason = _trimmed(replay_payload.get("reason")) or None

            if task_purpose != "normal":
                source_blocked_reasons.append("原始任务不是 normal 类型，不能作为进化输入")
            if not replay_ready:
                source_blocked_reasons.append(replay_reason or "原始任务当前不可 replay")

            if source_blocked_reasons:
                can_create = False

            sources.append(
                EvolutionPreviewSource(
                    source_task_id=source_task_id,
                    source_execution_id=_trimmed(grouped.get("source_execution_id")) or None,
                    source_run_id=_trimmed(grouped.get("source_run_id")) or None,
                    source_title=_trimmed(grouped.get("source_title")) or source_task_id,
                    selected_case_ids=list(grouped["selected_case_ids"]),
                    all_case_ids=all_case_ids,
                    auto_expanded_case_ids=auto_expanded_case_ids,
                    blocked_reasons=source_blocked_reasons,
                    replay_ready=replay_ready and task_purpose == "normal",
                    replay_reason=replay_reason,
                    source_task_summary={
                        "task_id": source_task_id,
                        "task_purpose": task_purpose,
                        "status": source_summary.get("status"),
                        "title": source_summary.get("title"),
                        "latest_execution_id": source_summary.get("latest_execution_id"),
                        "latest_run": source_summary.get("latest_run"),
                    },
                )
            )

        return EvolutionPreviewResponse(
            project_id=project_id,
            requested_case_ids=requested_case_ids,
            effective_case_ids=self._normalize_case_ids(effective_case_ids),
            can_create=can_create and bool(sources),
            blocked_reasons=blocked_reasons,
            sources=sources,
        )

    def _normalize_case_ids(self, values: Any) -> list[str]:
        deduped: list[str] = []
        seen: set[str] = set()
        for raw in values or []:
            case_id = _trimmed(raw)
            if case_id and case_id not in seen:
                deduped.append(case_id)
                seen.add(case_id)
        return deduped

    def _normalize_evolve_agents(self, values: Any) -> list[str]:
        deduped: list[str] = []
        seen: set[str] = set()
        raw_values = DEFAULT_EVOLVE_AGENTS if values is None else values
        for raw in raw_values:
            agent_id = _trimmed(raw)
            if not agent_id:
                continue
            if agent_id not in ALLOWED_EVOLVE_AGENTS:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"unsupported evolve agent: {agent_id}",
                )
            if agent_id not in seen:
                deduped.append(agent_id)
                seen.add(agent_id)
        if not deduped:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="evolve_agents is required")
        return deduped

    def _case_block_reason(self, case: dict[str, Any]) -> str | None:
        metadata = _json_dict(case.get("metadata"))
        review = _json_dict(metadata.get("evolution_review"))
        summary = _trimmed(case.get("summary"))
        decision_status = _trimmed(case.get("decision_status"))
        finished_reason = _trimmed(case.get("finished_reason")).lower()
        if not decision_status and not finished_reason:
            return "案例未进入人工收敛状态"
        if finished_reason == "non_issue" and not _trimmed(review.get("manual_resolution_reason") or summary):
            return "误报案例缺少人工原因"
        source = _json_dict(metadata.get("source"))
        original_severity = _trimmed(source.get("reported_severity") or case.get("original_severity")).lower()
        current_severity = _trimmed(case.get("severity")).lower()
        if original_severity and current_severity and original_severity != current_severity:
            if not _trimmed(review.get("severity_adjust_reason") or summary):
                return "等级调整案例缺少原因"
        return None

    def _workspace_root(self, project_id: str) -> Path:
        cfg = get_config()
        base_dir = Path(cfg.fileserver_service.data_mount_path) / cfg.fileserver_service.project_files_dirname
        return base_dir / project_id / "app" / cfg.fileserver_service.evolution_subproject_name

    def _task_root(self, project_id: str, task_id: str) -> Path:
        return self._workspace_root(project_id) / "tasks" / task_id

    def _dataflow_agent_state_root(self, project_id: str) -> Path:
        return (
            Path(get_config().fileserver_service.data_mount_path)
            / get_config().fileserver_service.project_files_dirname
            / project_id
            / "app"
            / get_config().fileserver_service.dataflow_subproject_name
            / "agent-state"
        )

    def _candidate_round_root(self, project_id: str, task_id: str, round_no: int) -> Path:
        return self._dataflow_agent_state_root(project_id) / "evolution" / task_id / "rounds" / f"round-{round_no}"

    def _promoted_root(self, project_id: str, task_id: str, round_no: int) -> Path:
        return self._dataflow_agent_state_root(project_id) / "promoted-evolution" / task_id / f"round-{round_no}"

    def _memory_mode_config_path(self, project_id: str) -> Path:
        return self._dataflow_agent_state_root(project_id) / "evolution-memory-mode.json"

    def _default_service_config(self) -> EvolutionConfigPayload:
        service_cfg = get_config().service
        return EvolutionConfigPayload(
            max_concurrent_tasks=service_cfg.default_max_concurrent_tasks,
            max_concurrent_source_tasks=service_cfg.default_max_concurrent_source_tasks,
            default_min_rounds=service_cfg.default_min_rounds,
            default_max_rounds=service_cfg.default_max_rounds,
            evolution_agent_model=service_cfg.default_evolution_agent_model,
            evolution_agent_timeout_seconds=service_cfg.default_evolution_agent_timeout_seconds,
            evolution_agent_context_window=service_cfg.default_context_window,
        )

    def get_service_config(self, db: Session) -> EvolutionConfigResponse:
        row = db.get(EvolutionServiceConfig, "global")
        payload = self._default_service_config()
        if row and isinstance(row.config_json, dict):
            payload = EvolutionConfigPayload(**{**payload.model_dump(), **row.config_json})
        return EvolutionConfigResponse(config=payload, updated_at=row.updated_at if row else None)

    def save_service_config(self, db: Session, payload: EvolutionConfigPayload) -> EvolutionConfigResponse:
        row = db.get(EvolutionServiceConfig, "global")
        if row is None:
            row = EvolutionServiceConfig(config_key="global", config_json=payload.model_dump())
        else:
            row.config_json = payload.model_dump()
        db.add(row)
        db.commit()
        db.refresh(row)
        return EvolutionConfigResponse(config=EvolutionConfigPayload(**_json_dict(row.config_json)), updated_at=row.updated_at)

    async def create_task(
        self,
        db: Session,
        *,
        project_id: str,
        payload: EvolutionTaskCreateRequest,
        principal: dict[str, Any],
        token: str,
    ) -> EvolutionTaskSummary:
        preview = await self.preview(
            project_id=project_id,
            payload=EvolutionPreviewRequest(case_ids=payload.case_ids),
            token=token,
        )
        if not preview.can_create:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="preview blocked")

        service_config = self.get_service_config(db).config
        task_id = _new_id("evo")
        task_root = self._task_root(project_id, task_id)
        task_root.mkdir(parents=True, exist_ok=True)
        (task_root / "rounds").mkdir(parents=True, exist_ok=True)
        evolve_agents = self._normalize_evolve_agents(payload.evolve_agents)
        agent_layout = await self._initialize_agent_layout(
            project_id=project_id,
            task_id=task_id,
            preview=preview,
            token=token,
            evolve_agents=evolve_agents,
        )

        min_rounds = payload.min_rounds or service_config.default_min_rounds
        max_rounds = payload.max_rounds or service_config.default_max_rounds
        if max_rounds < min_rounds:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="max_rounds must be >= min_rounds")

        task_config = {
            "min_rounds": min_rounds,
            "max_rounds": max_rounds,
            "max_concurrent_source_tasks": payload.max_concurrent_source_tasks or service_config.max_concurrent_source_tasks,
            "profile_id": payload.profile_id,
            "model": payload.model or service_config.evolution_agent_model,
            "provider": payload.provider,
            "review_profile": payload.review_profile,
            "agent_run_timeout_seconds": payload.agent_run_timeout_seconds or service_config.evolution_agent_timeout_seconds,
            "evolution_agent_context_window": service_config.evolution_agent_context_window,
            "evolve_agents": evolve_agents,
            "candidate_memory_only": True,
            "meta_evaluator_isolated": True,
            "replay_auto_report_vulnerabilities": False,
        }
        created_by = _trimmed(principal.get("username") or principal.get("user_id") or principal.get("subject")) or "system"
        task = EvolutionTask(
            id=task_id,
            project_id=project_id,
            title=payload.title,
            status="pending" if payload.auto_start else "created",
            objective=_trimmed(payload.objective) or None,
            metrics_json=dict(payload.metrics or {}),
            source_case_ids_json=preview.effective_case_ids,
            source_task_ids_json=[item.source_task_id for item in preview.sources],
            preview_payload_json=preview.model_dump(mode="json"),
            agent_state_roots_json=agent_layout["roots"],
            default_agent_source_dirs_json=agent_layout["sources"],
            config_json=task_config,
            created_by=created_by,
            message="等待 worker 执行" if payload.auto_start else "等待 start 启动",
        )
        db.add(task)
        for source in preview.sources:
            db.add(
                EvolutionTaskSource(
                    id=_new_id("src"),
                    task_id=task_id,
                    source_task_id=source.source_task_id,
                    source_execution_id=source.source_execution_id,
                    source_run_id=source.source_run_id,
                    source_title=source.source_title,
                    case_ids_json=source.all_case_ids,
                    case_keys_json=source.all_case_ids,
                    source_task_summary_json=source.source_task_summary,
                )
            )
        db.add(
            EvolutionTaskEvent(
                id=_new_id("evt"),
                task_id=task_id,
                event_type="task_created",
                summary="进化任务已创建",
                payload_json={"preview": preview.model_dump(mode="json"), "config": task_config, "evolve_agents": evolve_agents},
            )
        )
        db.commit()
        db.refresh(task)
        get_observability().record_task_created(task, len(preview.sources))

        (task_root / "preview.json").write_text(
            json.dumps(preview.model_dump(mode="json"), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        (task_root / "config.json").write_text(
            json.dumps(task_config, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return self._task_summary(task)

    async def create_experiment(
        self,
        db: Session,
        *,
        payload: EvolutionExperimentCreateRequest,
        principal: dict[str, Any],
        token: str,
    ) -> EvolutionTaskSummary:
        direction = _trimmed(payload.direction)
        title = _trimmed(payload.title) or (f"Evolution: {direction[:80]}" if direction else "Evolution Experiment")
        task_payload = EvolutionTaskCreateRequest(
            case_ids=payload.selected_results,
            title=title,
            objective=direction,
            metrics=payload.metrics,
            min_rounds=payload.min_rounds,
            max_rounds=payload.max_rounds,
            max_concurrent_source_tasks=payload.max_concurrent_source_tasks,
            profile_id=payload.profile_id,
            model=payload.model,
            provider=payload.provider,
            review_profile=payload.review_profile,
            agent_run_timeout_seconds=payload.agent_run_timeout_seconds,
            evolve_agents=payload.evolve_agents,
            auto_start=False,
        )
        return await self.create_task(
            db,
            project_id=payload.project_id,
            payload=task_payload,
            principal=principal,
            token=token,
        )

    async def _initialize_agent_layout(
        self,
        *,
        project_id: str,
        task_id: str,
        preview: EvolutionPreviewResponse,
        token: str,
        evolve_agents: list[str],
    ) -> dict[str, dict[str, str]]:
        if not preview.sources:
            return {"roots": {}, "sources": {}}

        client = get_dataflow_vuln_client()
        task_detail = await client.get_task(preview.sources[0].source_task_id, token)
        source_dirs = _json_dict(task_detail.get("agent_state_dirs"))
        if not source_dirs:
            effective_config = await client.get_service_effective_config(token)
            source_dirs = self._default_agent_dirs_from_config(project_id, effective_config)

        roots: dict[str, str] = {}
        sources: dict[str, str] = {}
        for agent_id in evolve_agents:
            item = _json_dict(source_dirs.get(agent_id))
            safe_agent_id = _trimmed(agent_id)
            if not safe_agent_id:
                continue
            root_path = (
                self._dataflow_agent_state_root(project_id)
                / "evolution"
                / task_id
                / "seed"
                / safe_agent_id
            )
            root_path.mkdir(parents=True, exist_ok=True)
            source_root_text = _trimmed(item.get("root_dir"))
            source_root = Path(source_root_text) if source_root_text else Path()
            if source_root_text and source_root.exists() and source_root.is_dir():
                for child in source_root.iterdir():
                    target = root_path / child.name
                    if child.is_dir():
                        shutil.copytree(child, target, dirs_exist_ok=True)
                    else:
                        shutil.copy2(child, target)
            (root_path / "skills").mkdir(parents=True, exist_ok=True)
            (root_path / "memory").mkdir(parents=True, exist_ok=True)
            roots[safe_agent_id] = str(root_path)
            sources[safe_agent_id] = str(source_root) if source_root_text else ""
        return {"roots": roots, "sources": sources}

    def _default_agent_dirs_from_config(self, project_id: str, config_payload: dict[str, Any]) -> dict[str, dict[str, str]]:
        result: dict[str, dict[str, str]] = {}
        agent_storage = _json_dict(config_payload.get("agent_storage"))
        for item in _json_list(agent_storage.get("agents")):
            if not isinstance(item, dict):
                continue
            agent_id = _trimmed(item.get("agent_id"))
            if not agent_id:
                continue
            root = self._agent_template_to_absolute(_trimmed(item.get("root_dir_template")), project_id)
            skills = self._agent_template_to_absolute(_trimmed(item.get("skills_dir_template")), project_id)
            memory = self._agent_template_to_absolute(_trimmed(item.get("memory_dir_template")), project_id)
            result[agent_id] = {"root_dir": root, "skills_dir": skills, "memory_dir": memory}
        return result

    def _agent_template_to_absolute(self, template: str, project_id: str) -> str:
        resolved = template.replace("{project_id}", project_id).replace("<project_id>", project_id)
        normalized = resolved.replace("\\", "/")
        files_prefix = f"/{get_config().fileserver_service.project_files_dirname}/"
        if normalized.startswith(files_prefix):
            return str(Path(get_config().fileserver_service.data_mount_path) / normalized.lstrip("/"))
        return normalized

    def list_tasks(self, db: Session, project_id: str) -> list[EvolutionTaskSummary]:
        rows = (
            db.query(EvolutionTask)
            .filter(EvolutionTask.project_id == project_id, EvolutionTask.deleted.is_(False))
            .order_by(EvolutionTask.updated_at.desc())
            .all()
        )
        return [self._task_summary(item) for item in rows]

    def get_task(self, db: Session, project_id: str, task_id: str) -> EvolutionTaskDetail:
        task = self._task_or_404(db, project_id, task_id)
        sources = (
            db.query(EvolutionTaskSource)
            .filter(EvolutionTaskSource.task_id == task.id)
            .order_by(EvolutionTaskSource.created_at.asc())
            .all()
        )
        rounds = (
            db.query(EvolutionTaskRound)
            .filter(EvolutionTaskRound.task_id == task.id)
            .order_by(EvolutionTaskRound.round_no.asc())
            .all()
        )
        artifacts = (
            db.query(EvolutionTaskArtifact)
            .filter(EvolutionTaskArtifact.task_id == task.id)
            .order_by(EvolutionTaskArtifact.created_at.desc())
            .all()
        )
        events = (
            db.query(EvolutionTaskEvent)
            .filter(EvolutionTaskEvent.task_id == task.id)
            .order_by(EvolutionTaskEvent.created_at.asc())
            .all()
        )
        return EvolutionTaskDetail(
            **self._task_summary(task).model_dump(),
            preview=EvolutionPreviewResponse.model_validate(_json_dict(task.preview_payload_json)),
            agent_state_roots={key: str(value) for key, value in _json_dict(task.agent_state_roots_json).items()},
            default_agent_source_dirs={key: str(value) for key, value in _json_dict(task.default_agent_source_dirs_json).items()},
            best_candidate_agent_state_roots=self._best_candidate_roots(db, task),
            sources=[
                {
                    "source_task_id": row.source_task_id,
                    "source_execution_id": row.source_execution_id,
                    "source_run_id": row.source_run_id,
                    "source_title": row.source_title,
                    "case_ids": _json_list(row.case_ids_json),
                    "summary": _json_dict(row.source_task_summary_json),
                }
                for row in sources
            ],
            rounds=[self._round_payload(item) for item in rounds],
            artifacts=[
                {
                    "artifact_type": item.artifact_type,
                    "path": item.path,
                    "metadata": _json_dict(item.metadata_json),
                    "round_no": item.round_no,
                    "created_at": isoformat_local(item.created_at),
                }
                for item in artifacts
            ],
            events=[
                {
                    "event_type": item.event_type,
                    "summary": item.summary,
                    "payload": _json_dict(item.payload_json),
                    "created_at": isoformat_local(item.created_at),
                }
                for item in events
            ],
        )

    def _best_candidate_roots(self, db: Session, task: EvolutionTask) -> dict[str, str]:
        best_round = task.best_round
        if best_round is None:
            return {}
        row = (
            db.query(EvolutionTaskRound)
            .filter(EvolutionTaskRound.task_id == task.id, EvolutionTaskRound.round_no == best_round)
            .first()
        )
        if row is None:
            return {}
        return {
            key: str(value)
            for key, value in _json_dict(_json_dict(row.diff_summary_json).get("candidate_agent_state_roots")).items()
        }

    def list_rounds(self, db: Session, project_id: str, task_id: str) -> list[EvolutionTaskRoundResponse]:
        self._task_or_404(db, project_id, task_id)
        rows = (
            db.query(EvolutionTaskRound)
            .filter(EvolutionTaskRound.task_id == task_id)
            .order_by(EvolutionTaskRound.round_no.asc())
            .all()
        )
        return [self._round_payload(item) for item in rows]

    def start_task(self, db: Session, *, project_id: str, task_id: str) -> EvolutionTaskSummary:
        task = self._task_or_404(db, project_id, task_id)
        if task.status == "created":
            task.status = "pending"
            task.message = "等待 worker 执行"
            db.add(
                EvolutionTaskEvent(
                    id=_new_id("evt"),
                    task_id=task.id,
                    event_type="task_start_requested",
                    summary="进化任务已启动",
                    payload_json={},
                )
            )
            db.commit()
            db.refresh(task)
        elif task.status != "pending":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"task cannot start from status: {task.status}")
        return self._task_summary(task)

    async def apply_task(self, db: Session, *, project_id: str, task_id: str, token: str) -> EvolutionApplyResponse:
        _ = token
        task = self._task_or_404(db, project_id, task_id)
        if task.status != "succeeded":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="only succeeded task can be applied")
        if task.best_round is None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="task has no promotable round")

        promoted_roots = self._promote_round_roots(task, int(task.best_round))
        memory_mode = self._save_memory_mode(
            db,
            project_id=project_id,
            payload=EvolutionMemoryModePatchRequest(
                mode="evolution",
                enabled_agents=list(promoted_roots.keys()),
                promoted_task_id=task.id,
                promoted_round=int(task.best_round),
            ),
            agent_state_roots=promoted_roots,
        )

        task.apply_status = "applied"
        task.apply_snapshot_path = str(self._promoted_root(project_id, task.id, int(task.best_round)))
        task.message = "已应用进化产物"
        db.add(
            EvolutionTaskArtifact(
                id=_new_id("art"),
                task_id=task.id,
                round_no=None,
                artifact_type="promotion",
                path=task.apply_snapshot_path,
                metadata_json={"applied_at": isoformat_local(now_local()), "memory_mode": memory_mode.model_dump(mode="json")},
            )
        )
        db.add(
            EvolutionTaskEvent(
                id=_new_id("evt"),
                task_id=task.id,
                event_type="task_applied",
                summary="已应用进化产物",
                payload_json={"promoted_roots": promoted_roots, "memory_mode": memory_mode.model_dump(mode="json")},
            )
        )
        db.commit()
        return EvolutionApplyResponse(status="ok", task_id=task.id, snapshot_path=task.apply_snapshot_path, message="进化产物已晋级并启用")

    async def promote_task(self, db: Session, *, project_id: str, task_id: str, token: str) -> EvolutionApplyResponse:
        return await self.apply_task(db, project_id=project_id, task_id=task_id, token=token)

    def _promote_round_roots(self, task: EvolutionTask, round_no: int) -> dict[str, str]:
        candidate_roots = self._candidate_roots_for_round(task, round_no)
        if not candidate_roots:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="best round has no candidate memory package")
        promoted_root = self._promoted_root(task.project_id, task.id, round_no)
        promoted_root.mkdir(parents=True, exist_ok=True)
        promoted_roots: dict[str, str] = {}
        for agent_id, source_root_raw in candidate_roots.items():
            source_root = Path(_trimmed(source_root_raw))
            destination = promoted_root / agent_id
            if destination.exists():
                shutil.rmtree(destination, ignore_errors=True)
            destination.mkdir(parents=True, exist_ok=True)
            memory_source = source_root / "memory"
            if memory_source.exists() and memory_source.is_dir():
                shutil.copytree(memory_source, destination / "memory", dirs_exist_ok=True)
            else:
                (destination / "memory").mkdir(parents=True, exist_ok=True)
            promoted_roots[agent_id] = str(destination)
        return promoted_roots

    def get_memory_mode(self, db: Session, project_id: str) -> EvolutionMemoryModeResponse:
        row = db.get(EvolutionServiceConfig, self._memory_mode_key(project_id))
        config = _json_dict(row.config_json) if row else {}
        return self._memory_mode_response(project_id, config, row.updated_at if row else None)

    def save_memory_mode(
        self,
        db: Session,
        *,
        project_id: str,
        payload: EvolutionMemoryModePatchRequest,
    ) -> EvolutionMemoryModeResponse:
        current = self.get_memory_mode(db, project_id).model_dump(mode="json")
        roots = _json_dict(current.get("agent_state_roots"))
        if payload.mode == "evolution":
            task_id = _trimmed(payload.promoted_task_id or current.get("promoted_task_id"))
            round_no = payload.promoted_round or current.get("promoted_round")
            if task_id and round_no:
                task = self._task_or_404(db, project_id, task_id)
                roots = {
                    agent_id: str(self._promoted_root(project_id, task.id, int(round_no)) / agent_id)
                    for agent_id in self._normalize_evolve_agents(payload.enabled_agents)
                    if (self._promoted_root(project_id, task.id, int(round_no)) / agent_id).exists()
                }
            if not roots:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="evolution memory mode requires promoted agent roots")
        else:
            roots = {}
        return self._save_memory_mode(db, project_id=project_id, payload=payload, agent_state_roots=roots)

    def _save_memory_mode(
        self,
        db: Session,
        *,
        project_id: str,
        payload: EvolutionMemoryModePatchRequest,
        agent_state_roots: dict[str, str],
    ) -> EvolutionMemoryModeResponse:
        requested_agents = self._normalize_evolve_agents(payload.enabled_agents) if payload.mode == "evolution" else []
        enabled_agents = [agent_id for agent_id in requested_agents if _trimmed(agent_state_roots.get(agent_id))]
        if payload.mode == "evolution" and not enabled_agents:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="evolution memory mode requires enabled promoted agent roots")
        config = {
            "project_id": project_id,
            "mode": payload.mode,
            "enabled_agents": enabled_agents,
            "promoted_task_id": _trimmed(payload.promoted_task_id) or None,
            "promoted_round": payload.promoted_round,
            "agent_state_roots": {
                agent_id: _trimmed(agent_state_roots.get(agent_id))
                for agent_id in enabled_agents
                if _trimmed(agent_state_roots.get(agent_id))
            },
            "updated_at": isoformat_local(now_local()),
        }
        row = db.get(EvolutionServiceConfig, self._memory_mode_key(project_id))
        if row is None:
            row = EvolutionServiceConfig(config_key=self._memory_mode_key(project_id), config_json=config)
        else:
            row.config_json = config
        db.add(row)
        db.flush()
        self._write_memory_mode_file(project_id, config)
        db.commit()
        db.refresh(row)
        return self._memory_mode_response(project_id, _json_dict(row.config_json), row.updated_at)

    def _memory_mode_key(self, project_id: str) -> str:
        digest = hashlib.sha256(project_id.encode("utf-8")).hexdigest()[:32]
        return f"project-memory-mode:{digest}"

    def _memory_mode_response(
        self,
        project_id: str,
        config: dict[str, Any],
        updated_at: Any = None,
    ) -> EvolutionMemoryModeResponse:
        mode = _trimmed(config.get("mode")) or "shared"
        if mode not in {"shared", "evolution"}:
            mode = "shared"
        roots = {key: str(value) for key, value in _json_dict(config.get("agent_state_roots")).items()} if mode == "evolution" else {}
        raw_enabled = _json_list(config.get("enabled_agents"))
        enabled_agents = [agent_id for agent_id in raw_enabled if _trimmed(agent_id) in roots]
        if mode == "evolution" and not enabled_agents:
            enabled_agents = list(roots.keys())
        return EvolutionMemoryModeResponse(
            project_id=project_id,
            mode=mode,  # type: ignore[arg-type]
            enabled_agents=enabled_agents,
            promoted_task_id=_trimmed(config.get("promoted_task_id")) or None,
            promoted_round=config.get("promoted_round"),
            agent_state_roots=roots,
            config_path=str(self._memory_mode_config_path(project_id)),
            updated_at=updated_at,
        )

    def _write_memory_mode_file(self, project_id: str, config: dict[str, Any]) -> None:
        path = self._memory_mode_config_path(project_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")

    async def delete_task(self, db: Session, *, project_id: str, task_id: str, token: str) -> None:
        task = self._task_or_404(db, project_id, task_id)
        vuln_client = get_vuln_client()
        related_cases = await vuln_client.list_cases(
            token,
            project_id=project_id,
            evolution_task_id=task.id,
            pool_type="evolution",
        )
        for case in related_cases.get("items") or []:
            case_id = _trimmed(case.get("id"))
            if case_id:
                try:
                    await vuln_client.delete_case(case_id, token)
                except Exception:
                    logger.warning("failed to delete evolution case %s", case_id, exc_info=True)

        task.deleted = True
        if task.status not in TERMINAL_TASK_STATUSES:
            task.status = "cancelled"
        task.message = "任务已删除"
        task.finished_at = task.finished_at or now_local()

        task_root = self._task_root(project_id, task.id)
        if task_root.exists():
            shutil.rmtree(task_root, ignore_errors=True)
        for root in _json_dict(task.agent_state_roots_json).values():
            path = Path(_trimmed(root))
            if path.exists():
                shutil.rmtree(path, ignore_errors=True)
        db.commit()

    def _task_summary(self, row: EvolutionTask) -> EvolutionTaskSummary:
        return EvolutionTaskSummary(
            task_id=row.id,
            project_id=row.project_id,
            title=row.title,
            status=row.status,
            objective=row.objective,
            metrics=_json_dict(row.metrics_json),
            current_round=int(row.current_round or 0),
            best_round=row.best_round,
            overall_score=row.overall_score,
            convergence_reason=row.convergence_reason,
            apply_status=row.apply_status or "not_applied",
            source_task_ids=_json_list(row.source_task_ids_json),
            source_case_ids=_json_list(row.source_case_ids_json),
            evolve_agents=_json_list(_json_dict(row.config_json).get("evolve_agents")),
            config=_json_dict(row.config_json),
            message=row.message,
            created_by=row.created_by,
            created_at=row.created_at,
            started_at=row.started_at,
            finished_at=row.finished_at,
            updated_at=row.updated_at,
        )

    def _round_payload(self, row: EvolutionTaskRound) -> EvolutionTaskRoundResponse:
        return EvolutionTaskRoundResponse(
            round_no=row.round_no,
            status=row.status,
            metrics=_json_dict(row.metrics_json),
            score=row.score,
            score_reason=row.score_reason,
            adjustment_summary=row.adjustment_summary,
            convergence_decision=row.convergence_decision,
            convergence_reason=row.convergence_reason,
            derived_tasks=_json_list(row.derived_tasks_json),
            diff_summary=_json_dict(row.diff_summary_json),
            candidate_agent_state_roots={
                key: str(value)
                for key, value in _json_dict(_json_dict(row.diff_summary_json).get("candidate_agent_state_roots")).items()
            },
            meta_evaluation=_json_dict(_json_dict(row.diff_summary_json).get("meta_evaluation")),
            started_at=row.started_at,
            finished_at=row.finished_at,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    def _task_or_404(self, db: Session, project_id: str, task_id: str) -> EvolutionTask:
        row = (
            db.query(EvolutionTask)
            .filter(EvolutionTask.project_id == project_id, EvolutionTask.id == task_id, EvolutionTask.deleted.is_(False))
            .first()
        )
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="task not found")
        return row

    def task_project_id_or_404(self, db: Session, task_id: str) -> str:
        row = db.query(EvolutionTask).filter(EvolutionTask.id == task_id, EvolutionTask.deleted.is_(False)).first()
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="task not found")
        return row.project_id

    def _service_authorization(self) -> str:
        token = _trimmed(get_config().auth_service.service_machine_token)
        if not token:
            raise RuntimeError("service machine token is required for worker execution")
        return token if token.lower().startswith("bearer ") else f"Bearer {token}"

    async def run_task(self, db: Session, task_id: str) -> None:
        task = db.query(EvolutionTask).filter(EvolutionTask.id == task_id, EvolutionTask.deleted.is_(False)).first()
        if task is None:
            return

        config = _json_dict(task.config_json)
        preview = EvolutionPreviewResponse.model_validate(_json_dict(task.preview_payload_json))
        sources = (
            db.query(EvolutionTaskSource)
            .filter(EvolutionTaskSource.task_id == task.id)
            .order_by(EvolutionTaskSource.created_at.asc())
            .all()
        )
        max_rounds = max(1, _as_int(config.get("max_rounds"), 1))
        min_rounds = max(1, _as_int(config.get("min_rounds"), 1))
        service_token = self._service_authorization()

        task.status = "running"
        task.started_at = task.started_at or now_local()
        task.message = "开始执行进化轮次"
        task.last_error = None
        db.add(
            EvolutionTaskEvent(
                id=_new_id("evt"),
                task_id=task.id,
                event_type="task_started",
                summary="进化任务开始执行",
                payload_json={"max_rounds": max_rounds, "min_rounds": min_rounds},
            )
        )
        db.commit()

        best_score: int | None = None
        try:
            for round_no in range(1, max_rounds + 1):
                round_row = EvolutionTaskRound(
                    id=_new_id("rnd"),
                    task_id=task.id,
                    round_no=round_no,
                    status="running",
                    started_at=now_local(),
                )
                task.current_round = round_no
                task.message = f"第 {round_no} 轮执行中"
                db.add(round_row)
                db.add(
                    EvolutionTaskEvent(
                        id=_new_id("evt"),
                        task_id=task.id,
                        event_type="round_started",
                        summary=f"第 {round_no} 轮开始",
                        payload_json={"round_no": round_no},
                    )
                )
                db.commit()

                derived_tasks = await self._run_round(task, sources, round_no, service_token)
                round_cases = await get_vuln_client().list_cases(
                    service_token,
                    project_id=task.project_id,
                    evolution_task_id=task.id,
                    evolution_round=round_no,
                    pool_type="evolution",
                )
                metrics = self._compute_round_metrics(preview, list(round_cases.get("items") or []), derived_tasks=derived_tasks)
                score, score_reason = self._score_metrics(metrics)
                candidate_roots = self._candidate_roots_for_round(task, round_no)
                meta_evaluation = self._meta_evaluate_round(
                    task=task,
                    round_no=round_no,
                    metrics=metrics,
                    score=score,
                    score_reason=score_reason,
                    candidate_roots=candidate_roots,
                )
                adjustment_summary = self._write_adjustment_files(
                    task,
                    round_no,
                    metrics,
                    score_reason,
                    candidate_roots=candidate_roots,
                    meta_evaluation=meta_evaluation,
                )
                converge = round_no >= min_rounds and self._should_converge(
                    metrics,
                    score,
                    best_score,
                    round_no,
                    max_rounds,
                    meta_evaluation=meta_evaluation,
                )
                convergence_reason = self._round_convergence_reason(
                    round_no=round_no,
                    max_rounds=max_rounds,
                    meta_evaluation=meta_evaluation,
                ) if converge else None

                round_row.status = "succeeded"
                round_row.metrics_json = metrics
                round_row.score = score
                round_row.score_reason = score_reason
                round_row.adjustment_summary = adjustment_summary
                round_row.convergence_decision = converge
                round_row.convergence_reason = convergence_reason
                round_row.derived_tasks_json = derived_tasks
                round_row.diff_summary_json = {
                    "agent_count": len(candidate_roots),
                    "candidate_agent_state_roots": candidate_roots,
                    "meta_evaluation": meta_evaluation,
                }
                round_row.finished_at = now_local()
                get_observability().record_round_metrics(round_no, metrics, score, derived_tasks)

                db.add(
                    EvolutionTaskArtifact(
                        id=_new_id("art"),
                        task_id=task.id,
                        round_no=round_no,
                        artifact_type="round_report",
                        path=str(self._task_root(task.project_id, task.id) / "rounds" / f"round-{round_no}" / "evolution-agent-report.md"),
                        metadata_json={"metrics": metrics, "score": score},
                    )
                )
                db.add(
                    EvolutionTaskEvent(
                        id=_new_id("evt"),
                        task_id=task.id,
                        event_type="round_completed",
                        summary=f"第 {round_no} 轮完成",
                        payload_json={"round_no": round_no, "metrics": metrics, "score": score},
                    )
                )

                if best_score is None or score > best_score:
                    best_score = score
                    task.best_round = round_no
                    task.overall_score = score

                if converge:
                    task.status = "succeeded"
                    task.finished_at = now_local()
                    task.convergence_reason = convergence_reason
                    task.message = f"已在第 {round_no} 轮收敛"
                    get_observability().record_task_finished(task, task.status)
                    db.commit()
                    return

                db.commit()

            task.status = "succeeded"
            task.finished_at = now_local()
            task.convergence_reason = "达到最大轮次"
            task.message = "已执行到最大轮次"
            get_observability().record_task_finished(task, task.status)
            db.commit()
        except Exception as exc:
            logger.exception("binary evolution task failed: %s", exc)
            if _is_downstream_transport_error(exc):
                task.status = "pending"
                task.message = f"下游通信异常，等待调度器自动重试: {exc}"
                task.last_error = str(exc)
                task.owner_pod_id = None
                db.add(
                    EvolutionTaskEvent(
                        id=_new_id("evt"),
                        task_id=task.id,
                        event_type="task_deferred_transport_error",
                        summary="下游通信异常，任务回退到待调度",
                        payload_json={"error": str(exc)},
                    )
                )
                db.commit()
                return
            task.status = "failed"
            task.finished_at = now_local()
            task.message = str(exc)
            task.last_error = str(exc)
            error_type = "timeout" if "timed out" in str(exc).lower() else type(exc).__name__
            if "timed out" in str(exc).lower():
                get_observability().record_timeout("task")
            get_observability().record_error("task", error_type)
            get_observability().record_task_finished(task, task.status)
            db.add(
                EvolutionTaskEvent(
                    id=_new_id("evt"),
                    task_id=task.id,
                    event_type="task_failed",
                    summary="进化任务失败",
                    payload_json={"error": str(exc)},
                )
            )
            db.commit()

    async def _run_round(
        self,
        task: EvolutionTask,
        sources: list[EvolutionTaskSource],
        round_no: int,
        token: str,
    ) -> list[dict[str, Any]]:
        concurrency = max(1, _as_int(_json_dict(task.config_json).get("max_concurrent_source_tasks"), 1))
        timeout_seconds = max(300, _as_int(_json_dict(task.config_json).get("agent_run_timeout_seconds"), 1800) * 4)
        semaphore = asyncio.Semaphore(concurrency)
        dataflow_client = get_dataflow_vuln_client()
        derived_results: list[dict[str, Any]] = []
        candidate_roots = self._prepare_candidate_roots(task, round_no)

        async def _launch(source: EvolutionTaskSource) -> None:
            async with semaphore:
                payload = {
                    "title": f"{task.title} / round {round_no} / {source.source_task_id}",
                    "profile_id": _json_dict(task.config_json).get("profile_id"),
                    "model": _json_dict(task.config_json).get("model"),
                    "provider": _json_dict(task.config_json).get("provider"),
                    "review_profile": _json_dict(task.config_json).get("review_profile"),
                    "agent_run_timeout_seconds": _json_dict(task.config_json).get("agent_run_timeout_seconds"),
                    "agent_state_roots": {
                        agent_id: {
                            "root_dir": {
                                "source": "project_filesystem",
                                "path": self._project_visible_path(task.project_id, Path(str(root_path))),
                            }
                        }
                        for agent_id, root_path in candidate_roots.items()
                    },
                    "scan_options": {},
                    "evolution_task_id": task.id,
                    "evolution_round": round_no,
                    "evolution_source_task_id": source.source_task_id,
                    "evolution_source_execution_id": source.source_execution_id,
                    "auto_report_vulnerabilities": False,
                }
                payload = {key: value for key, value in payload.items() if value not in (None, "", {}, [])}

                created = await dataflow_client.create_evolution_task(source.source_task_id, payload, token)
                derived_task_id = _trimmed(created.get("task_id"))
                result = {
                    "source_task_id": source.source_task_id,
                    "source_execution_id": source.source_execution_id,
                    "derived_task_id": derived_task_id,
                    "status": created.get("status"),
                }
                if derived_task_id:
                    deadline = asyncio.get_event_loop().time() + timeout_seconds
                    while True:
                        if asyncio.get_event_loop().time() > deadline:
                            get_observability().record_timeout("derived_task")
                            raise RuntimeError(f"round {round_no} derived task {derived_task_id} timed out")
                        await asyncio.sleep(5)
                        detail = await dataflow_client.get_task(derived_task_id, token)
                        current_status = _trimmed(detail.get("status")).lower()
                        result["status"] = current_status or detail.get("status")
                        result["latest_execution_id"] = detail.get("latest_execution_id")
                        latest_run = detail.get("latest_run") or detail.get("run") or {}
                        if isinstance(latest_run, dict):
                            result["latest_run"] = latest_run
                            result["result_count"] = latest_run.get("result_count")
                        if current_status in TERMINAL_DFVS_STATUSES:
                            break
                    if _trimmed(result.get("status")).lower() not in {"completed", "succeeded"}:
                        get_observability().record_error("derived_task", str(result.get("status") or "upstream_error"))
                        raise RuntimeError(f"round {round_no} derived task {derived_task_id} finished with {result.get('status')}")
                derived_results.append(result)

        await asyncio.gather(*[_launch(source) for source in sources])
        return derived_results

    def _prepare_candidate_roots(self, task: EvolutionTask, round_no: int) -> dict[str, str]:
        candidate_root = self._candidate_round_root(task.project_id, task.id, round_no)
        seed_roots = self._candidate_roots_for_round(task, round_no - 1) if round_no > 1 else {}
        if not seed_roots:
            seed_roots = _json_dict(task.agent_state_roots_json)
        roots: dict[str, str] = {}
        for agent_id, seed_root_raw in seed_roots.items():
            safe_agent_id = _trimmed(agent_id)
            if not safe_agent_id:
                continue
            target_root = candidate_root / safe_agent_id
            seed_root = Path(_trimmed(seed_root_raw))
            if seed_root.exists() and seed_root.is_dir():
                shutil.copytree(seed_root, target_root, dirs_exist_ok=True)
            target_root.mkdir(parents=True, exist_ok=True)
            (target_root / "memory").mkdir(parents=True, exist_ok=True)
            roots[safe_agent_id] = str(target_root)
        self._write_candidate_memory(task, round_no, roots)
        return roots

    def _write_candidate_memory(self, task: EvolutionTask, round_no: int, roots: dict[str, str]) -> None:
        config = _json_dict(task.config_json)
        summary = (
            f"# Evolution Candidate Round {round_no}\n\n"
            f"- objective: {_trimmed(task.objective) or 'not specified'}\n"
            f"- evolved_agents: `{json.dumps(_json_list(config.get('evolve_agents')), ensure_ascii=False)}`\n"
            "- scope: memory-only candidate generated before replay\n"
            "- guardrail: do not suppress high-value real vulnerabilities unless the objective explicitly targets them\n"
        )
        for agent_id, root in roots.items():
            memory_dir = Path(root) / "memory"
            memory_dir.mkdir(parents=True, exist_ok=True)
            advisor_guardrails = ""
            if agent_id == "pi-advisor":
                advisor_guardrails = (
                    "\nAdvisor-specific guardrails:\n"
                    "- Do not make the scanner appear better by relaxing review standards.\n"
                    "- Do not mark real vulnerabilities false_positive without evidence.\n"
                    "- Do not shorten global review coverage depth just to pass faster.\n"
                )
            (memory_dir / f"evolution-candidate-round-{round_no}.md").write_text(
                summary + advisor_guardrails,
                encoding="utf-8",
            )

    def _candidate_roots_for_round(self, task: EvolutionTask, round_no: int) -> dict[str, str]:
        root = self._candidate_round_root(task.project_id, task.id, round_no)
        config_agents = self._normalize_evolve_agents(_json_dict(task.config_json).get("evolve_agents"))
        roots: dict[str, str] = {}
        for agent_id in config_agents:
            candidate = root / agent_id
            if candidate.exists():
                roots[agent_id] = str(candidate)
        return roots

    def _project_visible_path(self, project_id: str, absolute_path: Path) -> str:
        project_root = (
            Path(get_config().fileserver_service.data_mount_path)
            / get_config().fileserver_service.project_files_dirname
            / project_id
        )
        resolved = absolute_path.resolve()
        try:
            relative = resolved.relative_to(project_root)
        except ValueError as exc:
            raise RuntimeError(f"invalid fileserver path for agent state root: {absolute_path}") from exc
        visible = "/" + str(relative).replace("\\", "/").lstrip("/")
        return visible or "/"

    def _compute_round_metrics(
        self,
        preview: EvolutionPreviewResponse,
        evolution_cases: list[dict[str, Any]],
        *,
        derived_tasks: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        expected_by_source = {item.source_task_id: len(item.all_case_ids) for item in preview.sources}
        actual_by_source: dict[str, int] = {}
        review_cycles: list[float] = []
        severity_shift_count = 0

        for case in evolution_cases:
            metadata = _json_dict(case.get("metadata"))
            source = _json_dict(metadata.get("source"))
            source_task_id = _trimmed(source.get("evolution_source_task_id") or source.get("source_task_id"))
            if source_task_id:
                actual_by_source[source_task_id] = actual_by_source.get(source_task_id, 0) + 1
            cycle = _json_dict(metadata.get("dataflow_vuln_scanner")).get("review_cycle")
            try:
                if cycle is not None:
                    review_cycles.append(float(cycle))
            except Exception:
                pass
            reported_severity = _trimmed(source.get("reported_severity")).lower()
            current_severity = _trimmed(case.get("severity")).lower()
            if reported_severity and current_severity and reported_severity != current_severity:
                severity_shift_count += 1

        if not evolution_cases:
            for derived in derived_tasks or []:
                source_task_id = _trimmed(derived.get("source_task_id"))
                if not source_task_id:
                    continue
                result_count = _as_int(derived.get("result_count"), -1)
                if result_count < 0:
                    latest_run = _json_dict(derived.get("latest_run"))
                    result_count = _as_int(latest_run.get("result_count"), 0)
                actual_by_source[source_task_id] = actual_by_source.get(source_task_id, 0) + max(result_count, 0)

        false_negative_count = 0
        false_positive_count = 0
        for source_task_id, expected_count in expected_by_source.items():
            actual_count = actual_by_source.get(source_task_id, 0)
            false_negative_count += max(expected_count - actual_count, 0)
            false_positive_count += max(actual_count - expected_count, 0)

        unknown_cases = max(len(evolution_cases) - sum(actual_by_source.values()), 0)
        false_positive_count += unknown_cases

        expected_case_count = sum(expected_by_source.values())
        formal_case_count = len(evolution_cases)
        derived_task_reported_count = sum(actual_by_source.values()) if not evolution_cases else None
        reported_case_count = formal_case_count if formal_case_count else int(derived_task_reported_count or 0)
        avg_discovery_round = sum(review_cycles) / len(review_cycles) if review_cycles else 0.0
        return {
            "expected_case_count": expected_case_count,
            "reported_case_count": reported_case_count,
            "derived_task_reported_count": derived_task_reported_count,
            "formal_evolution_case_count": formal_case_count,
            "false_negative_count": false_negative_count,
            "false_positive_count": false_positive_count,
            "false_negative_rate": (false_negative_count / expected_case_count) if expected_case_count else 0.0,
            "false_positive_rate": (false_positive_count / max(reported_case_count, 1)) if reported_case_count else 0.0,
            "avg_discovery_round": avg_discovery_round,
            "severity_shift_count": severity_shift_count,
            "actual_case_count_by_source": actual_by_source,
            "expected_case_count_by_source": expected_by_source,
        }

    def _score_metrics(self, metrics: dict[str, Any]) -> tuple[int, str]:
        false_negative_rate = float(metrics.get("false_negative_rate") or 0.0)
        false_positive_rate = float(metrics.get("false_positive_rate") or 0.0)
        avg_discovery_round = float(metrics.get("avg_discovery_round") or 0.0)
        severity_shift_count = _as_int(metrics.get("severity_shift_count"), 0)
        score = int(1000 - 500 * false_negative_rate - 300 * false_positive_rate - 20 * avg_discovery_round - 5 * severity_shift_count)
        return score, "规则评分：综合漏报率、误报率、漏洞发现轮次与等级漂移"

    def _meta_evaluate_round(
        self,
        *,
        task: EvolutionTask,
        round_no: int,
        metrics: dict[str, Any],
        score: int,
        score_reason: str,
        candidate_roots: dict[str, str],
    ) -> dict[str, Any]:
        advisor_evolved = "pi-advisor" in candidate_roots
        false_negative_rate = float(metrics.get("false_negative_rate") or 0.0)
        false_positive_rate = float(metrics.get("false_positive_rate") or 0.0)
        reported_count = _as_int(metrics.get("reported_case_count"), 0)
        expected_count = _as_int(metrics.get("expected_case_count"), 0)
        guardrails: list[str] = []
        if advisor_evolved:
            guardrails.extend(
                [
                    "candidate pi-advisor memory is not used by this meta evaluator",
                    "晋级不能只依赖 scanner 内部 advisor 的通过结论",
                    "需防止把真实漏洞错误标记为 false positive 或降低全局评审深度",
                ]
            )
        risks: list[str] = []
        if expected_count and reported_count < expected_count:
            risks.append("candidate replay reported fewer results than baseline-selected source set; check high-value false suppression")
        if false_negative_rate > 0:
            risks.append("non-target/high-value result loss risk is non-zero")
        if advisor_evolved and (false_negative_rate > 0 or reported_count == 0):
            risks.append("advisor memory may be relaxing review acceptance instead of improving exploration")
        passed = score >= 800 and false_negative_rate <= 0.05 and false_positive_rate <= 0.2 and not (advisor_evolved and reported_count == 0)
        report = {
            "evaluator": "secflow-binary-evolution-meta-evaluator",
            "isolated_from_candidate_agent_memory": True,
            "round_no": round_no,
            "objective": task.objective,
            "score": score,
            "score_reason": score_reason,
            "decision": "pass" if passed else "continue",
            "passed": passed,
            "advisor_memory_evolved": advisor_evolved,
            "guardrails": guardrails,
            "risks": risks,
            "metrics": metrics,
        }
        round_root = self._task_root(task.project_id, task.id) / "rounds" / f"round-{round_no}"
        round_root.mkdir(parents=True, exist_ok=True)
        (round_root / "meta-evaluator-report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return report

    def _write_adjustment_files(
        self,
        task: EvolutionTask,
        round_no: int,
        metrics: dict[str, Any],
        score_reason: str,
        *,
        candidate_roots: dict[str, str] | None = None,
        meta_evaluation: dict[str, Any] | None = None,
    ) -> str:
        round_root = self._task_root(task.project_id, task.id) / "rounds" / f"round-{round_no}"
        round_root.mkdir(parents=True, exist_ok=True)
        candidate_roots = dict(candidate_roots or self._candidate_roots_for_round(task, round_no))
        meta_evaluation = dict(meta_evaluation or {})
        summary = (
            f"# Evolution Round {round_no}\n\n"
            f"- score_reason: {score_reason}\n"
            f"- metrics: `{json.dumps(metrics, ensure_ascii=False)}`\n"
            f"- meta_evaluator: `{json.dumps(meta_evaluation, ensure_ascii=False)}`\n"
        )
        (round_root / "evolution-agent-report.md").write_text(summary, encoding="utf-8")
        (round_root / "metrics.json").write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
        roots = candidate_roots
        for agent_id, root in roots.items():
            memory_dir = Path(str(root)) / "memory"
            memory_dir.mkdir(parents=True, exist_ok=True)
            (memory_dir / f"evolution-round-{round_no}.md").write_text(summary, encoding="utf-8")
        return summary

    def _should_converge(
        self,
        metrics: dict[str, Any],
        score: int,
        best_score: int | None,
        round_no: int,
        max_rounds: int,
        *,
        meta_evaluation: dict[str, Any] | None = None,
    ) -> bool:
        _ = metrics, score, best_score
        if round_no >= max_rounds:
            return True
        if bool(_json_dict(meta_evaluation).get("passed")):
            return True
        return False

    def _round_convergence_reason(
        self,
        *,
        round_no: int,
        max_rounds: int,
        meta_evaluation: dict[str, Any],
    ) -> str:
        if round_no >= max_rounds:
            return "达到最大轮次"
        if bool(_json_dict(meta_evaluation).get("passed")):
            return "meta evaluator 评审通过"
        return "达到收敛条件"


_task_service: TaskService | None = None


def get_task_service() -> TaskService:
    global _task_service
    if _task_service is None:
        _task_service = TaskService()
    return _task_service
