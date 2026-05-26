"""
Worker 执行器

负责原子工作流中的:
- Worker 执行阶段 (R6c)
- 自我反思阶段 (R6d)
- 总结阶段 (R6e)
"""

from __future__ import annotations

import inspect
import hashlib
import os
import re
from pathlib import Path
from typing import Any, Optional

from app.pi_vuln_core.agents.models import AgentResponse
from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.config.models import AtomicWorkflowDef
from app.pi_vuln_core.engine.checkpoint import (
    is_terminal_checkpoint,
    load_step_checkpoint,
    record_step_checkpoint,
)
from app.pi_vuln_core.engine.models import WorkflowContext
from app.pi_vuln_core.recorder.recorder import ExecutionRecorder
from app.pi_vuln_core.review.previous_limitations import (
    extract_markdown_section,
    is_substantive_limitations,
)
from app.pi_vuln_core.review.profile import (
    format_review_profile_policy,
    get_review_profile_policy,
)
from app.pi_vuln_core.review.state import ReviewState
from app.pi_vuln_core.utils.file_ops import read_file, read_json, write_file, write_json
from app.pi_vuln_core.utils.result_docs import (
    classify_final_result_files,
    extract_result_number,
    infer_result_lifecycle_from_text,
    is_result_report_filename,
    list_result_report_files,
    list_supporting_markdown_files,
    sync_structured_result_manifests,
    sync_result_relations_manifest,
)
from app.pi_vuln_core.utils.template import (
    TemplateRenderError,
    collect_template_kwargs,
    referenced_placeholders,
    render_string,
)
from app.pi_vuln_core.utils.logger import get_logger

logger = get_logger("worker_executor")


class WorkerStageError(RuntimeError):
    """Worker / reflection / summary 任一阶段失败时抛出。"""

    def __init__(self, phase: str, message: str, response: AgentResponse | None = None):
        super().__init__(message)
        self.phase = phase
        self.response = response


class WorkerExecutor:
    """Worker 执行器"""

    REWORK_STAGE_DEFS = (
        {
            "id": "profile_driven_exploration",
            "step_key": "worker::profile_exploration",
            "prompt_filename": "worker_profile_driven_exploration.md",
        },
        {
            "id": "missed_vuln_hunting",
            "step_key": "worker::rework_missed_hunt",
            "prompt_filename": "worker_rework_missed_hunt.md",
        },
    )

    def __init__(
        self,
        agent_registry: AgentRuntimeRegistry,
        recorder: ExecutionRecorder,
    ):
        self.agents = agent_registry
        self.recorder = recorder

    async def execute_worker(
        self,
        wf_def: AtomicWorkflowDef,
        ctx: WorkflowContext,
        review_state: ReviewState,
        resume_cursor: dict[str, Any] | None = None,
    ) -> AgentResponse:
        """
        Worker 阶段 (R6c)

        调用 worker 智能体执行任务,直到完成。
        如果非首轮,prompt 中包含评审失败反馈。
        """
        worker_cfg = wf_def.roles.worker
        agent = self.agents.get(worker_cfg.agent_id)

        # Worker 会话策略:同一 cycle 内共用,跨 cycle 重建。
        session_id = await self._ensure_worker_session(agent, wf_def, ctx)
        self._sync_worker_scaffolds(ctx)
        current_result_files = self._list_result_files(
            os.path.join(ctx.working_dir, "results")
        )
        uses_rework_prompt = self._should_use_rework_prompt(
            ctx,
            review_state,
            current_result_files=current_result_files,
        )

        if uses_rework_prompt and self._has_staged_rework_prompts(wf_def):
            legacy_checkpoint = load_step_checkpoint(
                ctx.working_dir,
                cycle=ctx.cycle,
                phase="worker",
                step_key="worker::rework",
            )
            if self._can_skip_worker_node(legacy_checkpoint, "rework"):
                logger.info(
                    "resume_skip_legacy_worker_rework_node",
                    workflow_id=ctx.workflow_id,
                    task_id=ctx.task_id,
                    cycle=ctx.cycle,
                    checkpoint_status=legacy_checkpoint.get("status"),
                )
                metadata = {
                    "worker_prompt_kind": "rework",
                    "skip_reflection_after_worker": True,
                    "resume_skipped": True,
                    "resume_cursor": resume_cursor or {},
                    "resume_checkpoint": legacy_checkpoint,
                }
                if str(legacy_checkpoint.get("status") or "") == "partial_salvaged":
                    metadata["partial_salvaged"] = True
                return AgentResponse(
                    content="",
                    conversation_id=session_id,
                    turn_count=0,
                    finished=True,
                    metadata=metadata,
                )

            system_prompt = self._build_worker_system_prompt(
                worker_cfg.prompts.work.system_prompt_file,
                ctx,
            )
            try:
                return await self._execute_rework_sequence(
                    wf_def=wf_def,
                    ctx=ctx,
                    review_state=review_state,
                    agent=agent,
                    session_id=session_id,
                    system_prompt=system_prompt,
                    resume_cursor=resume_cursor,
                )
            except TemplateRenderError as exc:
                raise WorkerStageError("worker", f"Rework prompt 渲染失败：{exc}") from exc

        worker_prompt_kind = "rework" if uses_rework_prompt else "initial"
        worker_step_key = "worker::rework" if uses_rework_prompt else "worker::work"

        existing_checkpoint = load_step_checkpoint(
            ctx.working_dir,
            cycle=ctx.cycle,
            phase="worker",
            step_key=worker_step_key,
        )
        if self._can_skip_worker_node(existing_checkpoint, worker_prompt_kind):
            logger.info(
                "resume_skip_worker_node",
                workflow_id=ctx.workflow_id,
                task_id=ctx.task_id,
                cycle=ctx.cycle,
                step_key=worker_step_key,
                checkpoint_status=existing_checkpoint.get("status"),
            )
            metadata = {
                "worker_prompt_kind": worker_prompt_kind,
                "skip_reflection_after_worker": uses_rework_prompt,
                "resume_skipped": True,
                "resume_cursor": resume_cursor or {},
                "resume_checkpoint": existing_checkpoint,
            }
            if str(existing_checkpoint.get("status") or "") == "partial_salvaged":
                metadata["partial_salvaged"] = True
            return AgentResponse(
                content="",
                conversation_id=session_id,
                turn_count=0,
                finished=True,
                metadata=metadata,
            )

        # 构建 prompt
        system_prompt = self._build_worker_system_prompt(
            worker_cfg.prompts.work.system_prompt_file,
            ctx,
        )
        try:
            user_prompt = self._build_user_prompt(
                wf_def,
                ctx,
                review_state,
                current_result_files=current_result_files,
            )
        except TemplateRenderError as exc:
            raise WorkerStageError("worker", f"Prompt 渲染失败：{exc}") from exc

        logger.info("worker_execute_start",
                     workflow_id=ctx.workflow_id,
                     task_id=ctx.task_id,
                     cycle=ctx.cycle,
                     session_id=session_id)
        record_step_checkpoint(
            ctx.working_dir,
            cycle=ctx.cycle,
            phase="worker",
            step_key=worker_step_key,
            status="started",
            agent_id=worker_cfg.agent_id,
            session_id=session_id,
            extra={"prompt_kind": worker_prompt_kind},
        )

        # 多轮执行
        max_turns = self._effective_worker_max_turns(wf_def, ctx)
        pre_worker_digest = self._worker_editable_artifact_digest(ctx)
        response = await agent.multi_turn_execute(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            working_dir=ctx.working_dir,
            max_turns=max_turns,
            session_id=session_id,
        )
        response.metadata = dict(response.metadata or {})
        response.metadata.update({
            "worker_prompt_kind": "rework" if uses_rework_prompt else "initial",
            "skip_reflection_after_worker": uses_rework_prompt,
        })

        self._relocate_misplaced_outputs(ctx, response.turn_count)

        if not response.success or not response.finished:
            error = response.error or "Worker 未完成当前分析阶段"
            if self._can_salvage_worker_turn_limit(
                ctx=ctx,
                response=response,
                pre_worker_digest=pre_worker_digest,
            ):
                record_step_checkpoint(
                    ctx.working_dir,
                    cycle=ctx.cycle,
                    phase="worker",
                    step_key=worker_step_key,
                    status="partial_salvaged",
                    agent_id=worker_cfg.agent_id,
                    session_id=session_id,
                    detail=error,
                    extra={"turn_count": response.turn_count, "prompt_kind": worker_prompt_kind},
                )
                logger.warning(
                    "worker_turn_limit_partial_salvaged",
                    workflow_id=ctx.workflow_id,
                    task_id=ctx.task_id,
                    cycle=ctx.cycle,
                    error=error,
                    turns=response.turn_count,
                )
                metadata = dict(response.metadata or {})
                metadata.update({
                    "partial_salvaged": True,
                    "salvage_reason": "runtime_turn_limit_with_artifact_changes",
                    "original_error": error,
                    "original_error_code": response.error_code,
                })
                return AgentResponse(
                    content=response.content,
                    tool_outputs=list(response.tool_outputs or []),
                    files_created=list(response.files_created or []),
                    files_modified=list(response.files_modified or []),
                    conversation_id=response.conversation_id,
                    turn_count=response.turn_count,
                    finished=True,
                    token_usage=dict(response.token_usage or {}),
                    raw_response=response.raw_response,
                    metadata=metadata,
                )
            record_step_checkpoint(
                ctx.working_dir,
                cycle=ctx.cycle,
                phase="worker",
                step_key=worker_step_key,
                status="failed",
                agent_id=worker_cfg.agent_id,
                session_id=session_id,
                detail=error,
                extra={"turn_count": response.turn_count, "prompt_kind": worker_prompt_kind},
            )
            logger.error(
                "worker_execute_error",
                error=error,
                workflow_id=ctx.workflow_id,
                turns=response.turn_count,
                finished=response.finished,
            )
            raise WorkerStageError("worker", error, response)

        record_step_checkpoint(
            ctx.working_dir,
            cycle=ctx.cycle,
            phase="worker",
            step_key=worker_step_key,
            status="completed",
            agent_id=worker_cfg.agent_id,
            session_id=session_id,
            extra={
                "turn_count": response.turn_count,
                "max_turns": max_turns,
                "prompt_kind": response.metadata.get("worker_prompt_kind"),
                "internal_turn_count": response.metadata.get("internal_turn_count"),
                "event_total_count": response.metadata.get("event_total_count"),
            },
        )
        logger.info("worker_execute_done",
                     workflow_id=ctx.workflow_id,
                     turns=response.turn_count,
                     internal_turns=response.metadata.get("internal_turn_count"),
                     finished=response.finished)
        return response

    @staticmethod
    def _can_skip_worker_node(
        checkpoint: dict[str, Any] | None,
        worker_prompt_kind: str,
    ) -> bool:
        if not is_terminal_checkpoint(checkpoint):
            return False
        step_key = str((checkpoint or {}).get("step_key") or "").strip()
        if step_key != "worker":
            return True
        extra = checkpoint.get("extra") if isinstance(checkpoint.get("extra"), dict) else {}
        recorded_kind = str(
            extra.get("prompt_kind")
            or extra.get("worker_prompt_kind")
            or ""
        ).strip().lower()
        # Legacy worker checkpoints may not have a prompt kind. Treat them as
        # compatible so old histories keep their previous resume behavior.
        return not recorded_kind or recorded_kind == worker_prompt_kind

    @classmethod
    def _staged_rework_prompt_files(cls, wf_def: AtomicWorkflowDef) -> list[dict[str, str]]:
        work_prompts = wf_def.roles.worker.prompts.work
        prompt_dirs: list[Path] = []
        for prompt_file in (
            getattr(work_prompts, "rework_prompt_file", None),
            getattr(work_prompts, "user_prompt_file", None),
            getattr(work_prompts, "system_prompt_file", None),
        ):
            if prompt_file:
                prompt_dir = Path(str(prompt_file)).parent
                if prompt_dir not in prompt_dirs:
                    prompt_dirs.append(prompt_dir)

        if not prompt_dirs:
            return []

        prompt_dir = prompt_dirs[0]
        for candidate_dir in prompt_dirs:
            if all((candidate_dir / str(item["prompt_filename"])).is_file() for item in cls.REWORK_STAGE_DEFS):
                prompt_dir = candidate_dir
                break
        else:
            return []

        stages: list[dict[str, str]] = []
        for item in cls.REWORK_STAGE_DEFS:
            prompt_file = str(prompt_dir / str(item["prompt_filename"]))
            stages.append({
                "id": str(item["id"]),
                "step_key": str(item["step_key"]),
                "prompt_file": prompt_file,
            })
        return stages

    @classmethod
    def _has_staged_rework_prompts(cls, wf_def: AtomicWorkflowDef) -> bool:
        return bool(cls._staged_rework_prompt_files(wf_def))

    def _select_rework_stages(
        self,
        *,
        ctx: WorkflowContext,
        review_state: ReviewState,
        stages: list[dict[str, str]],
    ) -> tuple[list[dict[str, str]], list[str]]:
        """Route staged rework nodes by current state instead of always running all nodes."""
        if not stages:
            return [], []

        route = self._build_rework_route_state(ctx, review_state)
        selected: list[dict[str, str]] = []
        skipped: list[str] = []

        for stage in stages:
            stage_id = str(stage.get("id") or "")
            should_run = True
            record_skip = True
            if stage_id == "profile_driven_exploration":
                should_run = route["has_profile_exploration"]
                record_skip = False
            elif stage_id == "missed_vuln_hunting":
                should_run = route["has_missed_hunt_work"]

            if should_run:
                selected.append(stage)
            elif record_skip:
                skipped.append(stage_id)

        if skipped:
            logger.info(
                "worker_rework_route_filtered_stages",
                workflow_id=ctx.workflow_id,
                task_id=ctx.task_id,
                cycle=ctx.cycle,
                skipped=skipped,
                selected=[item.get("id") for item in selected],
                route=route,
            )
        return selected, skipped

    def _build_rework_route_state(
        self,
        ctx: WorkflowContext,
        review_state: ReviewState,
    ) -> dict[str, Any]:
        """Classify current blockers into result repair, security hunt, or summary handoff."""
        is_closure = ctx.review_mode == "closure" or review_state.workflow_mode == "closure"
        summary_doc_rework = self._has_summary_doc_rework(ctx, review_state)
        failed_files = self._get_rework_failed_files(ctx, review_state)
        active_entries = review_state.get_active_issue_entries(include_framework=False)
        worker_issue_entries, summary_handoff_entries = self._split_rework_issue_entries(active_entries)
        profile_issue_entries = [
            item for item in worker_issue_entries
            if self._is_profile_depth_budget_issue_entry(item)
        ]
        security_worker_issue_entries = [
            item for item in worker_issue_entries
            if not self._is_profile_depth_budget_issue_entry(item)
        ]
        unstructured_analysis_feedback = self._has_unstructured_analysis_feedback(
            review_state,
            is_closure=is_closure,
            summary_doc_rework=summary_doc_rework,
        )
        has_missed_hunt_work = bool(
            security_worker_issue_entries
            or unstructured_analysis_feedback
        )
        if is_closure and not failed_files and not security_worker_issue_entries:
            has_missed_hunt_work = False

        return {
            "is_closure": is_closure,
            "summary_doc_rework": summary_doc_rework,
            "has_failed_results": False,
            "failed_files": [],
            "worker_issue_count": len(security_worker_issue_entries),
            "profile_issue_count": len(profile_issue_entries),
            "summary_handoff_count": len(summary_handoff_entries),
            "has_profile_exploration": bool(profile_issue_entries),
            "has_missed_hunt_work": has_missed_hunt_work,
            "has_summary_handoff": bool(summary_handoff_entries or summary_doc_rework),
            "has_repeated_issue_summary": False,
        }

    def _get_rework_failed_files(
        self,
        ctx: WorkflowContext,
        review_state: ReviewState,
    ) -> list[str]:
        failed_sources = [
            item.filename for item in (ctx.failed_result_items or [])
            if is_result_report_filename(item.filename)
        ]
        if not failed_sources:
            failed_sources = [
                item.filename
                for item in review_state.get_failed_results(current_results=ctx.pre_cycle_result_files)
                if is_result_report_filename(item.filename)
            ]
        return sorted(dict.fromkeys(failed_sources))

    @classmethod
    def _has_unstructured_analysis_feedback(
        cls,
        review_state: ReviewState,
        *,
        is_closure: bool,
        summary_doc_rework: bool,
    ) -> bool:
        if is_closure or summary_doc_rework:
            return False
        for record in reversed(review_state.global_review_history):
            if record.passed:
                continue
            if list(record.issues or []):
                return False
            feedback = str(record.feedback or "")
            if cls._text_has_security_signal(feedback):
                return True
            return False
        return False

    async def _execute_rework_sequence(
        self,
        *,
        wf_def: AtomicWorkflowDef,
        ctx: WorkflowContext,
        review_state: ReviewState,
        agent,
        session_id: str,
        system_prompt: str,
        resume_cursor: dict[str, Any] | None = None,
    ) -> AgentResponse:
        self._prepare_rework_context(ctx, review_state)
        worker_cfg = wf_def.roles.worker
        configured_stages = self._staged_rework_prompt_files(wf_def)
        stages, route_skips = self._select_rework_stages(
            ctx=ctx,
            review_state=review_state,
            stages=configured_stages,
        )
        max_turns = self._effective_worker_max_turns(wf_def, ctx)
        responses: list[AgentResponse] = []
        skipped: list[str] = list(route_skips)
        partial_salvaged = False

        logger.info(
            "worker_rework_sequence_start",
            workflow_id=ctx.workflow_id,
            task_id=ctx.task_id,
            cycle=ctx.cycle,
            session_id=session_id,
            stages=[item["id"] for item in stages],
            route_skips=route_skips,
        )

        for index, stage in enumerate(stages):
            step_key = stage["step_key"]
            stage_prompt_kind = self._prompt_kind_for_rework_stage(stage["id"])
            existing_checkpoint = load_step_checkpoint(
                ctx.working_dir,
                cycle=ctx.cycle,
                phase="worker",
                step_key=step_key,
            )
            if self._can_skip_worker_node(existing_checkpoint, stage_prompt_kind):
                skipped.append(stage["id"])
                logger.info(
                    "resume_skip_worker_rework_subnode",
                    workflow_id=ctx.workflow_id,
                    task_id=ctx.task_id,
                    cycle=ctx.cycle,
                    step_key=step_key,
                    checkpoint_status=existing_checkpoint.get("status"),
                )
                if str(existing_checkpoint.get("status") or "") == "partial_salvaged":
                    partial_salvaged = True
                continue

            prompt = self._build_rework_stage_prompt(
                ctx=ctx,
                review_state=review_state,
                prompt_file=stage["prompt_file"],
            )
            response = await self._execute_rework_subnode(
                ctx=ctx,
                agent=agent,
                agent_id=worker_cfg.agent_id,
                session_id=session_id,
                stage_id=stage["id"],
                step_key=step_key,
                prompt=prompt,
                system_prompt=system_prompt if index == 0 else "",
                max_turns=max_turns,
                worker_prompt_kind=stage_prompt_kind,
            )
            partial_salvaged = partial_salvaged or bool(
                (response.metadata or {}).get("partial_salvaged")
            )
            responses.append(response)

        total_turns = max((int(response.turn_count or 0) for response in responses), default=0)
        if responses:
            final_response = responses[-1]
            content = final_response.content
            token_usage = dict(final_response.token_usage or {})
            raw_response = final_response.raw_response
            tool_outputs = [
                output
                for response in responses
                for output in (response.tool_outputs or [])
            ]
            files_created = [
                path
                for response in responses
                for path in (response.files_created or [])
            ]
            files_modified = [
                path
                for response in responses
                for path in (response.files_modified or [])
            ]
        else:
            content = ""
            token_usage = {}
            raw_response = None
            tool_outputs = []
            files_created = []
            files_modified = []

        metadata = {
            "worker_prompt_kind": (
                self._prompt_kind_for_rework_stage(stages[-1]["id"])
                if stages else
                "rework"
            ),
            "skip_reflection_after_worker": True,
            "rework_sequence": True,
            "rework_stages": [item["id"] for item in stages],
            "rework_skipped_stages": skipped,
            "resume_cursor": resume_cursor or {},
        }
        if partial_salvaged:
            metadata["partial_salvaged"] = True

        logger.info(
            "worker_rework_sequence_done",
            workflow_id=ctx.workflow_id,
            task_id=ctx.task_id,
            cycle=ctx.cycle,
            turns=total_turns,
            skipped=skipped,
            partial_salvaged=partial_salvaged,
        )
        return AgentResponse(
            content=content,
            tool_outputs=tool_outputs,
            files_created=files_created,
            files_modified=files_modified,
            conversation_id=session_id,
            turn_count=total_turns,
            finished=True,
            token_usage=token_usage,
            raw_response=raw_response,
            metadata=metadata,
        )

    def _build_rework_stage_prompt(
        self,
        *,
        ctx: WorkflowContext,
        review_state: ReviewState,
        prompt_file: str,
    ) -> str:
        template = read_file(prompt_file)
        required_keys = set(referenced_placeholders(template)) or None
        sections = self._build_rework_prompt_sections(
            ctx,
            review_state,
            required_keys=required_keys,
        )
        return render_string(template, strict=True, **sections)

    @staticmethod
    def _prompt_kind_for_rework_stage(stage_id: str) -> str:
        if stage_id == "profile_driven_exploration":
            return "profile_exploration"
        return "rework"

    async def _execute_rework_subnode(
        self,
        *,
        ctx: WorkflowContext,
        agent,
        agent_id: str,
        session_id: str,
        stage_id: str,
        step_key: str,
        prompt: str,
        system_prompt: str,
        max_turns: int,
        worker_prompt_kind: str = "rework",
    ) -> AgentResponse:
        logger.info(
            "worker_rework_subnode_start",
            workflow_id=ctx.workflow_id,
            task_id=ctx.task_id,
            cycle=ctx.cycle,
            stage_id=stage_id,
            step_key=step_key,
            session_id=session_id,
        )
        record_step_checkpoint(
            ctx.working_dir,
            cycle=ctx.cycle,
            phase="worker",
            step_key=step_key,
            status="started",
            agent_id=agent_id,
            session_id=session_id,
            extra={"prompt_kind": worker_prompt_kind, "rework_stage": stage_id},
        )

        pre_worker_digest = self._worker_editable_artifact_digest(ctx)
        if system_prompt:
            response = await agent.multi_turn_execute(
                system_prompt=system_prompt,
                user_prompt=prompt,
                working_dir=ctx.working_dir,
                max_turns=max_turns,
                session_id=session_id,
            )
        else:
            response = await agent.send_message(
                message=prompt,
                session_id=session_id,
                working_dir=ctx.working_dir,
            )
        response.metadata = dict(response.metadata or {})
        response.metadata.update({
            "worker_prompt_kind": worker_prompt_kind,
            "rework_stage": stage_id,
            "skip_reflection_after_worker": True,
        })

        self._relocate_misplaced_outputs(ctx, response.turn_count)

        if not response.success or not response.finished:
            error = response.error or f"Worker rework subnode {stage_id} 未完成"
            if self._can_salvage_worker_turn_limit(
                ctx=ctx,
                response=response,
                pre_worker_digest=pre_worker_digest,
            ):
                record_step_checkpoint(
                    ctx.working_dir,
                    cycle=ctx.cycle,
                    phase="worker",
                    step_key=step_key,
                    status="partial_salvaged",
                    agent_id=agent_id,
                    session_id=session_id,
                    detail=error,
                    extra={
                        "turn_count": response.turn_count,
                        "prompt_kind": worker_prompt_kind,
                        "rework_stage": stage_id,
                    },
                )
                metadata = dict(response.metadata or {})
                metadata.update({
                    "partial_salvaged": True,
                    "salvage_reason": "runtime_turn_limit_with_artifact_changes",
                    "original_error": error,
                    "original_error_code": response.error_code,
                })
                response.metadata = metadata
                return response
            record_step_checkpoint(
                ctx.working_dir,
                cycle=ctx.cycle,
                phase="worker",
                step_key=step_key,
                status="failed",
                agent_id=agent_id,
                session_id=session_id,
                detail=error,
                extra={
                    "turn_count": response.turn_count,
                    "prompt_kind": worker_prompt_kind,
                    "rework_stage": stage_id,
                },
            )
            logger.error(
                "worker_rework_subnode_error",
                workflow_id=ctx.workflow_id,
                task_id=ctx.task_id,
                cycle=ctx.cycle,
                stage_id=stage_id,
                error=error,
                turns=response.turn_count,
                finished=response.finished,
            )
            raise WorkerStageError("worker", error, response)

        record_step_checkpoint(
            ctx.working_dir,
            cycle=ctx.cycle,
            phase="worker",
            step_key=step_key,
            status="completed",
            agent_id=agent_id,
            session_id=session_id,
            extra={
                "turn_count": response.turn_count,
                "prompt_kind": worker_prompt_kind,
                "rework_stage": stage_id,
                "internal_turn_count": response.metadata.get("internal_turn_count"),
                "event_total_count": response.metadata.get("event_total_count"),
            },
        )
        logger.info(
            "worker_rework_subnode_done",
            workflow_id=ctx.workflow_id,
            task_id=ctx.task_id,
            cycle=ctx.cycle,
            stage_id=stage_id,
            turns=response.turn_count,
        )
        return response

    def _can_salvage_worker_turn_limit(
        self,
        *,
        ctx: WorkflowContext,
        response: AgentResponse,
        pre_worker_digest: str,
    ) -> bool:
        if not self._is_runtime_turn_limit_response(response):
            return False
        post_worker_digest = self._worker_editable_artifact_digest(ctx)
        return bool(pre_worker_digest and post_worker_digest and pre_worker_digest != post_worker_digest)

    @staticmethod
    def _is_runtime_turn_limit_response(response: AgentResponse) -> bool:
        code = str(response.error_code or response.metadata.get("status") or "").lower()
        text = str(response.error or "").lower()
        return (
            "runtime_turn_limit" in code
            or "runtime_turn_limit" in text
            or "internal turn limit" in text
        )

    @classmethod
    def _worker_editable_artifact_digest(cls, ctx: WorkflowContext) -> str:
        h = hashlib.sha256()
        roots = [
            Path(ctx.working_dir) / "results",
            Path(ctx.working_dir) / "supporting_docs",
        ]
        files = [
            Path(ctx.working_dir) / "summary.md",
            Path(ctx.working_dir) / "previous_limitations.md",
        ]
        for root in roots:
            if root.is_dir():
                files.extend(sorted(path for path in root.glob("*.md") if path.is_file()))
        found = False
        for path in sorted(files, key=lambda item: str(item)):
            if not path.is_file():
                continue
            found = True
            rel = os.path.relpath(path, ctx.working_dir)
            h.update(rel.encode("utf-8", errors="replace"))
            h.update(b"=")
            try:
                with open(path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(8192), b""):
                        h.update(chunk)
            except OSError:
                h.update(b"<unreadable>")
            h.update(b"\n")
        return h.hexdigest() if found else "<empty>"

    @staticmethod
    def _effective_worker_max_turns(
        wf_def: AtomicWorkflowDef,
        ctx: WorkflowContext,
    ) -> int:
        configured = getattr(wf_def.engine, "max_worker_turns_per_cycle", None)
        if configured:
            return int(configured)
        return get_review_profile_policy(ctx.review_profile).max_worker_turns_per_cycle

    @staticmethod
    def _effective_reflection_runtime_limits(
        wf_def: AtomicWorkflowDef,
        ctx: WorkflowContext,
    ) -> dict[str, int]:
        policy = get_review_profile_policy(ctx.review_profile)

        def configured_int(name: str, fallback: int, *, floor: int | None = None) -> int:
            raw = getattr(wf_def.engine, name, None)
            value = int(raw) if raw is not None else int(fallback)
            if floor is not None and value < int(floor):
                logger.warning(
                    "reflection_runtime_limit_below_profile_floor",
                    workflow_id=ctx.workflow_id,
                    review_profile=ctx.review_profile,
                    limit=name,
                    configured=value,
                    profile_floor=int(floor),
                )
                return int(floor)
            return value

        reflection_abort_bytes = 0
        if policy.reflection_rpc_stdout_abort_bytes > 0:
            reflection_abort_bytes = configured_int(
                "reflection_rpc_stdout_abort_bytes",
                policy.reflection_rpc_stdout_abort_bytes,
                floor=policy.reflection_rpc_stdout_abort_bytes,
            )

        return {
            "max_internal_turns": 0,
            "rpc_stdout_trace_bytes": configured_int(
                "reflection_rpc_stdout_trace_bytes",
                policy.reflection_rpc_stdout_trace_bytes,
            ),
            "rpc_stdout_abort_bytes": reflection_abort_bytes,
        }

    @staticmethod
    async def _send_message_with_optional_runtime_limits(
        agent,
        *,
        message: str,
        session_id: str | None,
        working_dir: str,
        runtime_limits: dict[str, int],
    ) -> AgentResponse:
        kwargs: dict[str, Any] = {
            "message": message,
            "session_id": session_id,
            "working_dir": working_dir,
        }
        try:
            parameters = inspect.signature(agent.send_message).parameters
        except (TypeError, ValueError):
            parameters = {}
        for key, value in runtime_limits.items():
            if key in parameters:
                kwargs[key] = value
        return await agent.send_message(**kwargs)

    def _sync_worker_scaffolds(self, ctx: WorkflowContext) -> None:
        """Generate stable result manifests before the Worker prompt."""
        results_dir = ctx.results_dir or os.path.join(ctx.working_dir, "results")
        summary_file = ctx.summary_file or os.path.join(ctx.working_dir, "summary.md")
        supporting_docs_dir = self._supporting_docs_dir(ctx.working_dir)
        try:
            os.makedirs(results_dir, exist_ok=True)
            os.makedirs(supporting_docs_dir, exist_ok=True)
            sync_structured_result_manifests(
                working_dir=ctx.working_dir,
                results_dir=results_dir,
                summary_file=summary_file,
                task_file=ctx.task_file,
                supporting_docs_dir=supporting_docs_dir,
            )
        except Exception as exc:
            logger.warning(
                "worker_scaffold_sync_failed",
                workflow_id=ctx.workflow_id,
                task_id=ctx.task_id,
                cycle=ctx.cycle,
                error=str(exc),
            )

    async def _ensure_worker_session(
        self,
        agent,
        wf_def: AtomicWorkflowDef,
        ctx: WorkflowContext,
    ) -> str:
        """Reuse one Worker session inside a cycle; rebuild between cycles by default."""
        engine_cfg = getattr(wf_def, "engine", None)
        reset_per_cycle = bool(getattr(engine_cfg, "reset_worker_session_per_cycle", False))
        if ctx.worker_session_id and (
            not reset_per_cycle or ctx.worker_session_cycle == ctx.cycle
        ):
            if not reset_per_cycle:
                ctx.worker_session_cycle = ctx.cycle
            return ctx.worker_session_id

        if ctx.worker_session_id and reset_per_cycle:
            try:
                await agent.close_session(ctx.worker_session_id)
            except Exception as exc:
                logger.debug(
                    "worker_session_close_before_cycle_reset_failed",
                    workflow_id=ctx.workflow_id,
                    task_id=ctx.task_id,
                    session_id=ctx.worker_session_id,
                    error=str(exc),
                )

        if not hasattr(agent, "create_session_with_hint"):
            if not ctx.worker_session_id:
                ctx.worker_session_id = f"worker_{ctx.workflow_id}_{ctx.task_id}_cycle_{ctx.cycle:03d}"
            ctx.worker_session_cycle = ctx.cycle
            return ctx.worker_session_id

        session_id = await agent.create_session_with_hint(
            f"worker_{ctx.workflow_id}_{ctx.task_id}_cycle_{ctx.cycle:03d}"
        )
        ctx.worker_session_id = session_id
        ctx.worker_session_cycle = ctx.cycle
        return session_id

    # ─────────────────────────────────────────────
    #  Prompt 构建 / Direct 模式
    # ─────────────────────────────────────────────

    def _build_worker_system_prompt(
        self,
        system_prompt_file: str,
        ctx: WorkflowContext,
    ) -> str:
        """Build the stable Worker system prompt.

        Run-scoped guidance belongs in the user prompt so the system prompt stays
        close to its role boundary: identity, durable constraints, and safety
        invariants.
        """
        return read_file(system_prompt_file).rstrip() + "\n"

    @staticmethod
    def _load_profile_worker_appendix(
        system_prompt_file: str,
        ctx: WorkflowContext,
    ) -> str:
        policy = get_review_profile_policy(ctx.review_profile)
        if policy.name != "audit":
            return ""
        appendix_path = Path(system_prompt_file).with_name("worker_audit_appendix.md")
        if not appendix_path.exists():
            return ""
        return read_file(appendix_path).rstrip()

    @staticmethod
    def _result_report_template(*, compact: bool = False) -> str:
        if compact:
            return "\n".join([
                "## result_NNN.md 强制结构摘要",
                "- 每个 result 只描述一个独立漏洞疑点；无源码证据不得写入 results/。",
                "- 必须包含：疑点元信息、数据流绑定、受控输入、源码证据、触发条件、校验/绕过分析、影响、修复建议、相关数据流/评审线索。",
                "- 若为补充/修正报告，文件开头必须写 `- **原始报告**: result_NNN.md` 与 `- **本报告性质**: 补充分析/修正`。",
            ])
        return "\n".join([
            "",
            "每个 `results/result_NNN.md` 必须严格按下列结构撰写；缺少关键字段会导致评审返工。",
            "",
            "```markdown",
            "# <疑点标题：一句话描述漏洞本质>",
            "",
            "## 1. 疑点元信息",
            "- **report_id**: result_NNN",
            "- **title**: <疑点标题>",
            "- **summary**: <3-5 句话概述底层问题、影响和关键证据>",
            "- **severity**: critical / high / medium / low",
            "- **cvss_score**: <可选；未知写 0.0>",
            "- **confidence**: <0-100 整数>",
            "- **state**: suspected",
            "- **category**: <CWE 或漏洞类别，如 CWE-787 / integer_safety>",
            "- **rule_id**: <可选；如 DATAFLOW-USED-OOB>",
            "- **rule_name**: <可选；规则/模式名称>",
            "- **fingerprint**: <函数名+sink+关键字段组成的稳定指纹>",
            "",
            "## 2. 上报主体 subject",
            "- **subject.type**: source_function / binary_function / module / path",
            "- **subject.locator**: <文件路径、函数名、行号或反编译地址>",
            "- **subject.name**: <目标函数/模块名>",
            "- **subject.version**: <未知可写 unknown>",
            "",
            "## 3. 数据流绑定（必须）",
            "- **data_flow_file**: <原始数据流文件路径>",
            "- **data_flow_kind**: INPUT / DIRECT_SINK / EXPORT / USED / CLEANED / STAR",
            "- **data_flow_source_line**: <数据流报告行号或原文片段>",
            "- **INPUT**: <INPUT-N、字段、偏移、攻击者可控性>",
            "- **传播路径**: INPUT → ... → sink",
            "- **sink/危险操作**: <函数/表达式/内存操作/索引/长度使用点>",
            "",
            "## 4. evidence.summary",
            "<用源码级证据说明底层问题为何真实存在。必须包含文件、函数、关键代码片段、变量来源。>",
            "",
            "## 5. evidence.reproduction_hint",
            "<触发条件、输入字段取值、边界值、配置/权限前提；不可复现时说明静态触发路径。>",
            "",
            "## 6. evidence.references",
            "- `<源码文件或反编译文件>:<行号/函数>` — <说明>",
            "- `<数据流报告>:<行号>` — <说明>",
            "",
            "## 7. 校验与绕过分析",
            "- 已检查的上游/本地校验：<列出 if/范围检查/长度检查>",
            "- 绕过或失效原因：<边界值、整数溢出、符号混用、TOCTOU、错误处理等>",
            "- 若校验充分阻断问题，不得保留为 result；应移入 supporting_docs/。",
            "",
            "## 8. 影响评估",
            "<崩溃、越界读写、内存破坏、DoS、信息泄露、逻辑绕过等；说明置信度和限制。>",
            "",
            "## 9. 修复建议",
            "<具体到校验、长度计算、类型转换、边界处理或调用契约。>",
            "",
            "## 10. artifacts / metadata",
            "- **artifacts**: <相关 supporting_docs、代码片段、日志或 PoC 文件路径；没有写 none>",
            "- **metadata.related_issue_ids**: <全局评审 issue id；没有写 []>",
            "- **metadata.related_results**: <补充/修正关系；没有写 []>",
            "```",
        ])

    def _build_user_prompt(
        self,
        wf_def: AtomicWorkflowDef,
        ctx: WorkflowContext,
        review_state: ReviewState,
        current_result_files: list[str] | None = None,
    ) -> str:
        """构建 Worker 的 user prompt(direct 模式)"""
        if current_result_files is None:
            current_result_files = self._list_result_files(
                os.path.join(ctx.working_dir, "results")
            )

        if self._should_use_rework_prompt(
            ctx,
            review_state,
            current_result_files=current_result_files,
        ):
            self._prepare_rework_context(ctx, review_state)
            return self._build_rework_prompt(ctx, review_state, wf_def=wf_def)

        base_prompt = read_file(wf_def.roles.worker.prompts.work.user_prompt_file)
        prompt_kwargs = collect_template_kwargs(
            base_prompt,
            value_factories={
                "cycle": lambda: str(ctx.cycle),
                "review_mode": lambda: ctx.review_mode,
                "task": lambda: self._read_task_content(ctx.task_file),
                "task_file": lambda: ctx.task_file,
                "working_dir": lambda: ctx.working_dir,
                "summary_file": lambda: ctx.summary_file or os.path.join(ctx.working_dir, "summary.md"),
                "previous_limitations_file": lambda: os.path.join(ctx.working_dir, "previous_limitations.md"),
                "results_dir": lambda: ctx.results_dir or os.path.join(ctx.working_dir, "results"),
                "supporting_docs_dir": lambda: self._supporting_docs_dir(ctx.working_dir),
                "output_contract_text": lambda: self._build_worker_output_contract_text(ctx),
                "worker_runtime_context": lambda: self._build_initial_worker_context(
                    ctx=ctx,
                    review_state=review_state,
                    current_result_files=current_result_files,
                    system_prompt_file=wf_def.roles.worker.prompts.work.system_prompt_file,
                ),
                "result_report_template": lambda: self._result_report_template(),
            },
        )
        return render_string(base_prompt, strict=True, **prompt_kwargs)

    def _should_use_rework_prompt(
        self,
        ctx: WorkflowContext,
        review_state: ReviewState,
        *,
        current_result_files: list[str] | None = None,
    ) -> bool:
        if ctx.cycle <= 1:
            return False
        if current_result_files is None:
            current_result_files = self._list_result_files(
                os.path.join(ctx.working_dir, "results")
            )
        return (
            review_state.has_failures(
                current_results=current_result_files,
                actionable_by="worker",
            )
            or self._has_summary_doc_rework(ctx, review_state)
        )

    @staticmethod
    def _read_task_content(task_file: str) -> str:
        try:
            return read_file(task_file)
        except Exception as exc:
            return f"(任务文件读取失败: {exc})"

    @classmethod
    def _has_summary_doc_rework(
        cls,
        ctx: WorkflowContext,
        review_state: ReviewState,
    ) -> bool:
        recent_issues = review_state.get_recent_issues(last_n=2)
        if any(
            str(issue.get("actionable_by") or issue.get("owner") or "").strip().lower() == "framework"
            for issue in recent_issues
        ):
            return False
        if "summary" in (ctx.plateau_reason or ""):
            return True

        summary_owners = {"report", "summary"}
        summary_categories = {
            "report_completeness",
            "limitations_honesty",
            "summary",
            "metadata",
            "metadata_sync",
        }
        has_summary_issue = False
        for issue in recent_issues:
            owner = str(issue.get("actionable_by") or issue.get("owner") or "").strip().lower()
            category = str(issue.get("category") or "").strip().lower()
            entry = {"issue": issue, "blocking_type": issue.get("blocking_type") or issue.get("category")}
            if cls._is_summary_doc_issue_entry(entry):
                has_summary_issue = True
                continue
            if owner and owner not in summary_owners:
                return False
            if owner in summary_owners or category in summary_categories:
                has_summary_issue = True
            elif category:
                return False
        if has_summary_issue:
            return True

        scores = review_state.last_global_scores or {}
        return (
            ctx.review_mode == "closure"
            and bool(review_state.last_global_feedback)
            and bool(scores)
            and all(key in {"limitations_honesty", "report_completeness"} for key in scores)
        )

    def _build_output_contract(self, ctx: WorkflowContext) -> dict[str, str]:
        results_dir = ctx.results_dir or os.path.join(ctx.working_dir, "results")
        supporting_docs_dir = self._supporting_docs_dir(ctx.working_dir)
        return {
            "summary_file": ctx.summary_file or os.path.join(ctx.working_dir, "summary.md"),
            "results_dir": results_dir,
            "supporting_docs_dir": supporting_docs_dir,
            "previous_limitations_file": os.path.join(ctx.working_dir, "previous_limitations.md"),
            "result_filename_pattern": "result_NNN.md",
        }

    def _build_worker_output_contract(self, ctx: WorkflowContext) -> dict[str, str]:
        contract = self._build_output_contract(ctx)
        return {
            "results_dir": contract["results_dir"],
            "supporting_docs_dir": contract["supporting_docs_dir"],
            "result_filename_pattern": contract["result_filename_pattern"],
            "deferred_summary_file": contract["summary_file"],
            "deferred_previous_limitations_file": contract["previous_limitations_file"],
        }

    def _build_output_contract_text(self, ctx: WorkflowContext) -> str:
        contract = self._build_output_contract(ctx)
        return f"summary.md: {os.path.abspath(contract['summary_file'])}"

    def _build_worker_output_contract_text(self, ctx: WorkflowContext) -> str:
        contract = self._build_worker_output_contract(ctx)
        return "\n".join([
            f"- RESULTS=`{self._path_for_prompt(ctx, contract['results_dir'])}`; SUPPORTING=`{self._path_for_prompt(ctx, contract['supporting_docs_dir'])}`",
            "- 结果文件命名：`result_NNN.md`；辅助文档只写入 SUPPORTING。",
            f"- `summary.md` 将在后续显式 summary 阶段统一整理到 `{self._path_for_prompt(ctx, contract['deferred_summary_file'])}`；`previous_limitations.md` 同步到 `{self._path_for_prompt(ctx, contract['deferred_previous_limitations_file'])}`",
        ])

    def _build_review_delta_text(
        self,
        *,
        ctx: WorkflowContext,
        review_state: ReviewState,
        current_result_files: list[str],
        include_recent_feedback: bool = True,
    ) -> str:
        """
        构建评审反馈增量摘要。

        由于 Worker 全程复用同一 session，已拥有完整对话历史，
        此处注入上一轮评审的新增信息（通过/失败结果、评审反馈、工作模式）。
        """
        failed_results = review_state.get_failed_results(current_results=current_result_files)
        passed_results = review_state.get_passed_result_filenames(current_results=current_result_files)

        lines = [
            f"# 第 {ctx.cycle} 轮评审反馈摘要",
            "",
            f"- 当前轮次：{ctx.cycle}",
            f"- 工作模式：{ctx.review_mode or review_state.workflow_mode}",
            f"- 当前结果文件数：{len(current_result_files)}",
            f"- 已通过评审：{len(passed_results)}",
            f"- 未通过评审：{len(failed_results)}",
        ]

        if passed_results:
            lines.extend([
                "",
                "## 已通过评审的结果（禁止修改）",
                *[f"- {name}" for name in passed_results],
            ])

        if failed_results:
            lines.extend([
                "",
                "## 未通过评审的结果",
            ])
            for item in failed_results:
                lines.append(f"- {item.filename}: {item.reason.strip()}")

        # 轻量反馈链：注入最近 2 轮的全局评审反馈
        if include_recent_feedback:
            recent_feedback = review_state.format_recent_feedback(last_n=2)
            if recent_feedback:
                lines.extend([
                    "",
                    "## 近期全局评审反馈（请逐条处理）",
                    recent_feedback,
                ])

        return "\n".join(lines).rstrip() + "\n"

    def _build_initial_worker_context(
        self,
        *,
        ctx: WorkflowContext,
        review_state: ReviewState,
        current_result_files: list[str],
        system_prompt_file: str | None = None,
    ) -> str:
        previous_limitations_file = os.path.join(ctx.working_dir, "previous_limitations.md")
        lines = [
            "## 当前执行上下文",
            f"- 当前轮次：{ctx.cycle}",
            f"- 工作模式：{ctx.review_mode or review_state.workflow_mode}",
            f"- 任务文件: `{ctx.task_file}`",
            f"- 工作目录: `{ctx.working_dir}`",
            f"- 本阶段正式结果目录: `{ctx.results_dir or os.path.join(ctx.working_dir, 'results')}`",
            f"- 本阶段辅助文档目录: `{self._supporting_docs_dir(ctx.working_dir)}`",
            f"- 后续 summary 阶段整理的总结报告: `{ctx.summary_file or os.path.join(ctx.working_dir, 'summary.md')}`",
        ]
        audit_appendix = (
            self._load_profile_worker_appendix(system_prompt_file, ctx)
            if system_prompt_file else
            ""
        )
        if audit_appendix:
            lines.extend(["", audit_appendix])
        lines.extend([
            "",
            "## 开始前必须读取",
            f"- `{ctx.task_file}`",
        ])
        if ctx.cycle > 1 and os.path.isfile(previous_limitations_file):
            lines.append(f"- `{previous_limitations_file}`")
        if ctx.cycle > 1 and ctx.summary_file and os.path.isfile(ctx.summary_file):
            lines.append(f"- `{ctx.summary_file}`")
        for name in current_result_files:
            lines.append(f"- `{os.path.join(ctx.working_dir, 'results', name)}`")
        return "\n".join(lines)

    def _build_rework_prompt(
        self,
        ctx: WorkflowContext,
        review_state: ReviewState,
        wf_def: AtomicWorkflowDef | None = None,
    ) -> str:
        """
        构建评审返工轮的 prompt。

        由于 Worker 全程复用同一 session，已拥有完整对话历史，
        此处只注入评审反馈增量（通过/失败结果、近期问题、收敛要求）。
        """
        rework_prompt_file = None
        if wf_def is not None:
            rework_prompt_file = getattr(
                wf_def.roles.worker.prompts.work,
                "rework_prompt_file",
                None,
            )
        if rework_prompt_file:
            try:
                template = read_file(rework_prompt_file)
            except FileNotFoundError:
                logger.warning(
                    "rework_prompt_file_missing_fallback",
                    workflow_id=ctx.workflow_id,
                    task_id=ctx.task_id,
                    cycle=ctx.cycle,
                    prompt_file=rework_prompt_file,
                )
            else:
                required_keys = set(referenced_placeholders(template)) or None
                sections = self._build_rework_prompt_sections(
                    ctx,
                    review_state,
                    required_keys=required_keys,
                )
                return render_string(template, strict=True, **sections)

        sections = self._build_rework_prompt_sections(ctx, review_state)
        return self._build_legacy_rework_prompt(sections)

    def _build_rework_prompt_sections(
        self,
        ctx: WorkflowContext,
        review_state: ReviewState,
        *,
        required_keys: set[str] | None = None,
    ) -> dict[str, Any]:
        """Build dynamic sections shared by file-based and fallback rework prompts."""
        required = set(required_keys or ())

        def needs(key: str) -> bool:
            return not required or key in required
        is_closure = (ctx.review_mode == "closure" or review_state.workflow_mode == "closure")
        summary_doc_rework = self._has_summary_doc_rework(ctx, review_state)
        failed_sources = [
            item.filename for item in (ctx.failed_result_items or [])
            if is_result_report_filename(item.filename)
        ]
        if not failed_sources:
            failed_sources = [
                item.filename
                for item in review_state.get_failed_results(current_results=ctx.pre_cycle_result_files)
                if is_result_report_filename(item.filename)
            ]
        failed_files = sorted(dict.fromkeys(failed_sources))
        summary_repair_only = (
            (is_closure or summary_doc_rework)
            and not failed_files
            and summary_doc_rework
        )
        result_repair_only = bool(failed_files)
        repeated_issue_summary = ""

        global_review_feedback = ""
        if review_state.last_global_feedback:
            global_review_feedback = "\n".join([
                "## 全局评审反馈",
                self._clip_prompt_section(review_state.last_global_feedback, max_chars=6000),
            ])

        repeated_issue_summary_text = ""

        backlog_max_items = 6 if summary_repair_only or is_closure else 10
        open_backlog = review_state.format_open_issue_backlog(
            max_items=backlog_max_items,
            include_framework=False,
        )
        active_issue_backlog = ""
        if open_backlog:
            active_issue_backlog = "\n".join([
                "## Active issue backlog（本轮必须逐项关闭或记录 residual）",
                open_backlog,
            ])

        active_entries = review_state.get_active_issue_entries(include_framework=False)
        worker_issue_entries, summary_handoff_entries = self._split_rework_issue_entries(active_entries)
        profile_issue_entries = [
            item for item in worker_issue_entries
            if self._is_profile_depth_budget_issue_entry(item)
        ]
        worker_issue_entries = [
            item for item in worker_issue_entries
            if not self._is_profile_depth_budget_issue_entry(item)
        ]

        failed_result_reasons = ""
        if needs("failed_result_reasons") and failed_files:
            failed_lines = [
                "## 未通过结果的失败原因",
            ]
            for item in review_state.get_failed_results(current_results=ctx.pre_cycle_result_files):
                if item.filename not in failed_files:
                    continue
                failed_lines.extend([
                    f"### {item.filename}",
                    item.reason,
                    "",
                ])
            failed_result_reasons = "\n".join(failed_lines).rstrip()

        numbering_rules = self._build_summary_rework_rules(ctx) if needs("numbering_rules") else ""
        convergence_requirements = ""
        if needs("convergence_requirements"):
            convergence_requirements = self._build_rework_convergence_requirements(
                ctx=ctx,
                is_closure=is_closure,
                summary_repair_only=summary_repair_only,
                result_repair_only=result_repair_only,
                repeated_issue_summary=repeated_issue_summary,
            )

        summary_file = ctx.summary_file or os.path.join(ctx.working_dir, "summary.md")
        results_dir = ctx.results_dir or os.path.join(ctx.working_dir, "results")
        previous_limitations_file = os.path.join(ctx.working_dir, "previous_limitations.md")
        supporting_docs_dir = self._supporting_docs_dir(ctx.working_dir)
        issue_closure_file = os.path.join(
            supporting_docs_dir,
            f"issue_closure_cycle_{ctx.cycle:03d}.md",
        )
        issue_closure_template = (
            self._build_issue_closure_template(
                ctx=ctx,
                review_state=review_state,
                issue_closure_file=issue_closure_file,
                failed_files=failed_files,
                worker_issue_entries=worker_issue_entries,
            )
            if needs("issue_closure_template") else
            ""
        )
        sections = {
            "cycle": str(ctx.cycle),
            "review_mode": ctx.review_mode or review_state.workflow_mode,
            "task": self._read_task_content(ctx.task_file),
            "task_file": ctx.task_file,
            "working_dir": ctx.working_dir,
            "summary_file": summary_file,
            "previous_limitations_file": previous_limitations_file,
            "results_dir": results_dir,
            "supporting_docs_dir": supporting_docs_dir,
            "rework_session_context": self._build_rework_session_context(ctx, review_state),
            "rework_recovery_context": self._build_rework_recovery_context(ctx, review_state),
            "required_read_files": (
                self._build_rework_required_read_files(
                    ctx=ctx,
                    failed_files=failed_files,
                    worker_issue_entries=worker_issue_entries,
                    summary_handoff_entries=summary_handoff_entries,
                )
                if needs("required_read_files") else
                ""
            ),
            "failed_review_guidance": (
                self._build_failed_review_guidance(
                    review_state=review_state,
                )
                if needs("failed_review_guidance") else
                ""
            ),
            "profile_exploration_guidance": (
                self._build_profile_exploration_guidance(
                    ctx=ctx,
                    review_state=review_state,
                    profile_issue_entries=profile_issue_entries,
                )
                if needs("profile_exploration_guidance") else
                ""
            ),
            "review_delta_text": self._build_review_delta_text(
                ctx=ctx,
                review_state=review_state,
                current_result_files=ctx.pre_cycle_result_files,
                include_recent_feedback=False,
            ).rstrip(),
            "global_review_feedback": global_review_feedback,
            "repeated_issue_summary": repeated_issue_summary_text,
            "active_issue_backlog": active_issue_backlog,
            "completeness_rework_plan": self._build_advisor_driven_rework_plan(
                review_state=review_state,
                advisor_tokens=("global_completeness", "completeness", "全面"),
                plan_kind="completeness",
            ),
            "completeness_rework_summary": self._build_advisor_rework_summary(
                review_state=review_state,
                advisor_tokens=("global_completeness", "completeness", "全面"),
                plan_kind="completeness",
            ),
            "depth_rework_plan": self._build_advisor_driven_rework_plan(
                review_state=review_state,
                advisor_tokens=("global_depth", "depth", "深入"),
                plan_kind="depth",
            ),
            "depth_rework_summary": self._build_advisor_rework_summary(
                review_state=review_state,
                advisor_tokens=("global_depth", "depth", "深入"),
                plan_kind="depth",
            ),
            "result_repair_plan": self._build_result_repair_plan(
                ctx=ctx,
                review_state=review_state,
                failed_files=failed_files,
            ),
            "result_repair_summary": self._build_result_repair_summary(
                ctx=ctx,
                review_state=review_state,
                failed_files=failed_files,
            ),
            "missed_hunt_variant_seeds": (
                self._build_missed_hunt_variant_seeds(
                    ctx=ctx,
                    review_state=review_state,
                    failed_files=failed_files,
                )
                if needs("missed_hunt_variant_seeds") else
                ""
            ),
            "issue_hypothesis_queue": self._build_issue_hypothesis_queue(
                worker_issue_entries=worker_issue_entries,
            ),
            "rework_priority_queue": self._build_rework_priority_queue(
                ctx=ctx,
                review_state=review_state,
                failed_files=failed_files,
                worker_issue_entries=worker_issue_entries,
            ),
            "summary_handoff_queue": self._build_summary_handoff_queue(summary_handoff_entries),
            "failed_result_reasons": failed_result_reasons,
            "output_contract_text": (
                self._build_worker_output_contract_text(ctx)
                if needs("output_contract_text") else
                ""
            ),
            "result_report_template": (
                self._result_report_template(compact=True)
                if needs("result_report_template") else
                ""
            ),
            "issue_closure_file": issue_closure_file,
            "issue_closure_template": issue_closure_template,
            "rework_scope_policy": self._build_rework_scope_policy(
                summary_repair_only=summary_repair_only,
                result_repair_only=result_repair_only,
                is_closure=is_closure,
                worker_issue_count=len(worker_issue_entries),
            ),
            "numbering_rules": numbering_rules,
            "convergence_requirements": convergence_requirements,
            "direct_read_instruction": (
                "直接使用 read 工具读取需要的文件，不要要求框架重复粘贴全文。"
            ),
        }
        if required:
            return {key: value for key, value in sections.items() if key in required}
        return sections

    @staticmethod
    def _record_matches_advisor(
        record: Any,
        advisor_tokens: tuple[str, ...],
    ) -> bool:
        haystack = " ".join([
            str(getattr(record, "advisor_id", "") or ""),
            str(getattr(record, "role_name", "") or ""),
        ]).strip().lower()
        return any(str(token).lower() in haystack for token in advisor_tokens)

    def _build_advisor_driven_rework_plan(
        self,
        *,
        review_state: ReviewState,
        advisor_tokens: tuple[str, ...],
        plan_kind: str,
    ) -> str:
        # Rework runs in one long-lived Worker session, so the model already
        # has earlier-cycle history. Keep only the latest matching advisor
        # record here to avoid making every rework stage re-ingest old reviews.
        records = [
            record for record in reversed(review_state.global_review_history)
            if self._record_matches_advisor(record, advisor_tokens)
        ][:1]
        if not records:
            if plan_kind == "completeness":
                return "\n".join([
                    "- 当前没有可识别的全面性评审记录。",
                    "- 若本轮仍有 active worker issue，请只把它们当作高收益漏洞假设来源。",
                ])
            return "\n".join([
                "- 当前没有可识别的深入性评审记录。",
                "- 若本轮已有弱证据 result，请优先做校验绕过、边界值和攻击前提复核。",
            ])

        lines: list[str] = []
        for record in records:
            advisor_id = str(getattr(record, "advisor_id", "") or "global_review")
            role_name = str(getattr(record, "role_name", "") or advisor_id)
            passed = bool(getattr(record, "passed", False))
            status = "PASS" if passed else "FAIL"
            cycle = int(getattr(record, "cycle", 0) or 0)
            lines.append(f"### Cycle {cycle} - {advisor_id} / {role_name} ({status})")
            if passed:
                lines.extend([
                    "- no_action: 该 advisor 本轮通过，不产生 rework 任务。",
                    "- guardrail: 不要把 PASS 反馈当成继续挖洞或继续修结果的驱动；仅保护已验证结论，避免无关重写。",
                    "- feedback: omitted for PASS，完整内容保留在 review artifacts 中。",
                ])
                continue

            scores = getattr(record, "scores", {}) or {}
            if scores:
                score_text = ", ".join(f"{key}={float(value):.2f}" for key, value in scores.items())
                lines.append(f"- scores: {score_text}")
            issues = [issue for issue in list(getattr(record, "issues", []) or []) if isinstance(issue, dict)]
            if issues:
                lines.append("- failed advisor issues -> 本轮漏洞动作:")
                for issue in issues[:5]:
                    issue_id = ReviewState.prompt_safe_issue_id(
                        issue.get("id") or issue.get("issue_id") or ""
                    ) or "(no-id)"
                    target = str(issue.get("target") or issue.get("path") or "(未指定 target)").strip()
                    action = str(
                        issue.get("required_action")
                        or issue.get("detail")
                        or issue.get("description")
                        or ""
                    ).strip()
                    acceptance = str(
                        issue.get("acceptance_criteria")
                        or issue.get("acceptance")
                        or ""
                    ).strip()
                    blocking_type = ReviewState.prompt_safe_blocking_type(
                        issue.get("blocking_type") or issue.get("category") or ""
                    )
                    issue_entry = {"issue": issue, "blocking_type": blocking_type}
                    if plan_kind == "completeness":
                        if self._is_summary_doc_issue_entry(issue_entry):
                            model_action = (
                                "summary 同步或文档证据问题：交给 handoff/summary 阶段整理，"
                                "不要转成漏洞挖掘任务。"
                            )
                        elif self._is_security_worker_issue_entry(issue_entry):
                            model_action = (
                                "安全相关漏报补扫假设：只跟入 target 指向的具体源码路径/数据流/sink；"
                                "确认真实漏洞才新增 result，证伪则写简短 source_closed supporting_doc。"
                            )
                        else:
                            model_action = (
                                "低收益或非安全类反馈：默认跳过漏洞挖掘，只在 handoff/summary 中记录 residual。"
                            )
                    else:
                        if self._is_summary_doc_issue_entry(issue_entry):
                            model_action = (
                                "文档同步问题：不进入深挖，交给 summary 阶段处理。"
                            )
                        else:
                            model_action = (
                                "将该反馈转成深挖/证伪问题：复核边界值、校验绕过、变体路径、攻击前提和 "
                                "严重度/置信度，确认则补强或新增 result，证伪则记录 false-positive/residual。"
                            )
                    issue_line = (
                        f"  - `{issue_id}`: target={target[:240]}; "
                        f"blocking_type={blocking_type or 'unspecified'}; "
                        f"required_action={action[:320] or '(无)'}; "
                        f"rework_action={model_action}"
                    )
                    if acceptance:
                        issue_line += f"; acceptance={acceptance[:240]}"
                    lines.append(issue_line)
                if len(issues) > 5:
                    lines.append(f"  - ... 另有 {len(issues) - 5} 个 failed advisor issue，请参考本轮评审记录。")
            else:
                feedback = str(getattr(record, "feedback", "") or "").strip()
                lines.append("- 本 failed advisor 未返回结构化 issue；仅把下面短 feedback 当 fallback 线索，不作为完整任务清单。")
                if feedback:
                    lines.append(f"- fallback_feedback: {self._clip_prompt_section(feedback, max_chars=700)}")
        return "\n".join(lines)

    def _build_result_repair_plan(
        self,
        *,
        ctx: WorkflowContext,
        review_state: ReviewState,
        failed_files: list[str],
    ) -> str:
        return "- fp_repair 节点已删除；旧漏洞确认/误报状态由结果评审写入漏洞列表，Worker 不做误报修复。"

        lines = [
        ]
        for item in review_state.get_failed_results(current_results=ctx.pre_cycle_result_files):
            if item.filename not in failed_files:
                continue
            reason = (item.reason or "").strip()
            lines.append(
                f"- `{item.filename}`: review_reason={reason[:360] or '(无原因)'}; "
                "required_action=重读源码证伪，真则补强，假则撤回或标记 false_positive。"
            )
        return "\n".join(lines)

    def _build_advisor_rework_summary(
        self,
        *,
        review_state: ReviewState,
        advisor_tokens: tuple[str, ...],
        plan_kind: str,
    ) -> str:
        records = [
            record for record in reversed(review_state.global_review_history)
            if self._record_matches_advisor(record, advisor_tokens)
        ][:1]
        if not records:
            if plan_kind == "completeness":
                return "- 当前没有可识别的全面性评审记录；missed_hunt 不需要为它分配专门漏报补扫方向。"
            return "- 当前没有可识别的深入性评审记录；missed_hunt 不需要为它分配专门深挖方向。"

        record = records[0]
        advisor_id = str(getattr(record, "advisor_id", "") or "global_review")
        role_name = str(getattr(record, "role_name", "") or advisor_id)
        passed = bool(getattr(record, "passed", False))
        status = "PASS" if passed else "FAIL"
        cycle = int(getattr(record, "cycle", 0) or 0)
        lines = [f"- latest: Cycle {cycle} - {advisor_id} / {role_name} ({status})"]

        if passed:
            lines.extend([
                "- no_action: 该 advisor 本轮通过；不生成 missed_hunt 任务。",
                "- guardrail: 不要把 PASS 正反馈当作 missed_hunt 驱动；完整 feedback 不注入 rework。",
            ])
            return "\n".join(lines)

        scores = getattr(record, "scores", {}) or {}
        if scores:
            score_text = ", ".join(f"{key}={float(value):.2f}" for key, value in list(scores.items())[:6])
            lines.append(f"- scores: {score_text}")

        issues = [issue for issue in list(getattr(record, "issues", []) or []) if isinstance(issue, dict)]
        if issues:
            lines.append(f"- failed_issue_count: {len(issues)}; top_actionable_signals:")
            for issue in issues[:3]:
                issue_id = ReviewState.prompt_safe_issue_id(
                    issue.get("id") or issue.get("issue_id") or ""
                ) or "(no-id)"
                target = str(issue.get("target") or issue.get("path") or "(未指定 target)")[:140]
                action = str(
                    issue.get("required_action")
                    or issue.get("detail")
                    or issue.get("description")
                    or ""
                ).strip()[:220]
                blocking_type = ReviewState.prompt_safe_blocking_type(
                    issue.get("blocking_type") or issue.get("category") or ""
                )
                acceptance = str(
                    issue.get("acceptance_criteria")
                    or issue.get("acceptance")
                    or ""
                ).strip()[:180]
                issue_line = (
                    f"  - `{issue_id}`: blocking_type={blocking_type or 'unspecified'}; "
                    f"target={target}; action={action or '(无)'}"
                )
                if acceptance:
                    issue_line += f"; acceptance={acceptance}"
                lines.append(issue_line)
        else:
            feedback = str(getattr(record, "feedback", "") or "").strip()
            lines.append("- failed_issue_count: 0; 仅使用短 fallback feedback，不注入完整长评审。")
            if feedback:
                lines.append(f"- fallback_feedback: {self._clip_prompt_section(feedback, max_chars=320)}")

        return "\n".join(lines)

    def _build_failed_review_guidance(
        self,
        *,
        review_state: ReviewState,
    ) -> str:
        sections: list[str] = []
        for advisor_tokens, title in (
            (("global_completeness", "completeness", "全面"), "全面性评审"),
            (("global_depth", "depth", "深入"), "深入性评审"),
        ):
            record = self._latest_matching_advisor_record(
                review_state=review_state,
                advisor_tokens=advisor_tokens,
            )
            if record is None or bool(getattr(record, "passed", False)):
                continue
            sections.extend(self._format_failed_review_record(record=record, title=title))

        if not sections:
            return "- 当前没有来自未通过全局评审的漏洞方向；若本节点仍被执行，只围绕尚未闭环的真实源码路径做补扫。"
        return "\n".join(sections)

    def _build_profile_exploration_guidance(
        self,
        *,
        ctx: WorkflowContext,
        review_state: ReviewState,
        profile_issue_entries: list[dict[str, Any]],
    ) -> str:
        _ = review_state, profile_issue_entries
        output_file = (
            f"`supporting_docs/profile_exploration_cycle_{ctx.cycle}.md`"
            if ctx.cycle else
            "`supporting_docs/profile_exploration_cycle_{cycle}.md`"
        )
        lines = [
            "- 上一轮可能已经通过，但当前审计配置要求至少再做一轮探索，所以这一轮不能马虎收尾。",
            "- 不要修文档，也不要重复确认已经坐实的结论；重点是继续找那些还没看透、但可能藏着真漏洞的路径。",
            "- 先读 task、summary、results、supporting_docs，分清哪些地方已经查实，哪些地方只是带过。",
            "- **重点关注跨多个函数的复杂调用链**，深度分析其中是否隐藏着漏掉的深度/细节漏洞**。",
            "- 也可以从已有漏洞的相邻路径、对称分支、边界值、错误路径、状态差异，以及 EXPORT / USED 的后续去向里，选 2 到 4 个方向继续深挖。",
            "- 每条路径都要回到源码：谁能控制、数据怎么走、校验够不够、最后落到什么危险操作。",
            "- 只有确认是新的独立漏洞，才新增更高编号的 result。",
            f"- 如果没有新漏洞，就写 {output_file}，记清这轮看了什么、为什么没成漏洞，以及哪些边界暂时下不了结论。",
        ]
        return "\n".join(lines)

    def _latest_matching_advisor_record(
        self,
        *,
        review_state: ReviewState,
        advisor_tokens: tuple[str, ...],
    ) -> Any | None:
        for record in reversed(review_state.global_review_history):
            if self._record_matches_advisor(record, advisor_tokens):
                return record
        return None

    def _format_failed_review_record(
        self,
        *,
        record: Any,
        title: str,
    ) -> list[str]:
        cycle = int(getattr(record, "cycle", 0) or 0)
        lines = [f"### {title}（Cycle {cycle}）"]

        scores = getattr(record, "scores", {}) or {}
        if scores:
            score_text = ", ".join(
                f"{key}={float(value):.2f}"
                for key, value in list(scores.items())[:4]
            )
            lines.append(f"- scores: {score_text}")

        feedback = str(getattr(record, "feedback", "") or "").strip()
        if feedback:
            lines.append(f"- feedback: {feedback}")

        issues = [
            issue for issue in list(getattr(record, "issues", []) or [])
            if isinstance(issue, dict)
        ]
        if not issues:
            lines.append("- issues: 无结构化 issue；按上面的完整 feedback 自行回到源码和数据流定位路径。")
            return lines

        lines.append("- issues:")
        for issue in issues:
            issue_id = ReviewState.prompt_safe_issue_id(
                issue.get("id") or issue.get("issue_id") or ""
            ) or "(no-id)"
            target = str(issue.get("target") or issue.get("path") or "").strip()
            action = str(
                issue.get("required_action")
                or issue.get("detail")
                or issue.get("description")
                or ""
            ).strip()
            acceptance = str(
                issue.get("acceptance_criteria")
                or issue.get("acceptance")
                or ""
            ).strip()
            line = f"  - `{issue_id}`"
            if target:
                line += f": target={target}"
            if action:
                line += f"; required_action={action}"
            if acceptance:
                line += f"; acceptance={acceptance}"
            lines.append(line)
        return lines

    def _build_result_repair_summary(
        self,
        *,
        ctx: WorkflowContext,
        review_state: ReviewState,
        failed_files: list[str],
    ) -> str:
        return "- 结果修复节点已删除；missed_hunt 只处理漏报/新漏洞方向。"

    def _build_missed_hunt_variant_seeds(
        self,
        *,
        ctx: WorkflowContext,
        review_state: ReviewState,
        failed_files: list[str],
    ) -> str:
        results_dir = ctx.results_dir or os.path.join(ctx.working_dir, "results")
        current_files = ctx.pre_cycle_result_files or self._list_result_files(results_dir)
        protected_files = list(ctx.protected_result_files or [])
        failed_set = set(failed_files or [])
        ordered_files = list(dict.fromkeys([*protected_files, *current_files]))

        seeds: list[dict[str, str]] = []
        for name in ordered_files:
            if name in failed_set or not is_result_report_filename(name):
                continue
            path = os.path.join(results_dir, name)
            if not os.path.isfile(path):
                continue
            try:
                content = read_file(path)
            except Exception:
                continue
            lifecycle = infer_result_lifecycle_from_text(content, name)
            if not bool(lifecycle.get("active", True)):
                continue
            seeds.append(self._summarize_result_variant_seed(name, content))
            if len(seeds) >= 8:
                break

        lines = [
            "- 用已有有效 result 派生 sibling-path、symmetry-break、guard-bypass、state/config、error-path 变体。",
            "- 不要重复报告已有漏洞；只有 sink、触发条件、保护缺口或攻击面有实质差异时才新增 result。",
        ]
        if seeds:
            lines.append("### Active result variant seeds")
            for seed in seeds:
                parts = [
                    f"`{seed['filename']}`",
                    f"title={seed['title']}",
                    f"severity={seed['severity']}",
                    f"category={seed['category']}",
                    f"subject={seed['subject']}",
                    f"sink={seed['sink']}",
                ]
                lines.append("- " + "; ".join(parts))
        else:
            lines.append("- 当前没有可用的 active result 变体种子；优先从 advisor feedback 生成候选。")

        return "\n".join(lines)

    @staticmethod
    def _summarize_result_variant_seed(filename: str, content: str) -> dict[str, str]:
        return {
            "filename": filename,
            "title": WorkerExecutor._extract_markdown_title(content)[:140] or "(untitled)",
            "severity": WorkerExecutor._extract_result_meta_field(content, "severity")[:40] or "unknown",
            "category": WorkerExecutor._extract_result_meta_field(content, "category")[:80] or "unknown",
            "subject": (
                WorkerExecutor._extract_result_meta_field(content, "subject.name")
                or WorkerExecutor._extract_result_meta_field(content, "subject.locator")
                or WorkerExecutor._extract_result_meta_field(content, "subject")
            )[:120] or "unknown",
            "sink": (
                WorkerExecutor._extract_result_meta_field(content, "sink/危险操作")
                or WorkerExecutor._extract_result_meta_field(content, "sink")
                or WorkerExecutor._extract_result_meta_field(content, "危险操作")
            )[:120] or "unknown",
        }

    @staticmethod
    def _extract_markdown_title(content: str) -> str:
        for line in (content or "").splitlines()[:20]:
            stripped = line.strip()
            if stripped.startswith("#"):
                return stripped.lstrip("#").strip()
        return ""

    @staticmethod
    def _extract_result_meta_field(content: str, field_name: str) -> str:
        head = "\n".join((content or "").splitlines()[:120])
        escaped = re.escape(field_name)
        patterns = [
            rf"(?im)^\s*[-*]?\s*(?:\*\*)?{escaped}(?:\*\*)?\s*[:：]\s*(.+?)\s*$",
            rf"(?im)^\s*[-*]?\s*{escaped}\s*=\s*(.+?)\s*$",
        ]
        for pattern in patterns:
            match = re.search(pattern, head)
            if match:
                value = match.group(1).strip()
                return value.strip("`* ")
        return ""

    def _build_issue_hypothesis_queue(
        self,
        *,
        worker_issue_entries: list[dict[str, Any]],
    ) -> str:
        lines = [
            "- 优先处理 advisor 明确点名、靠近危险 sink 的路径。",
        ]
        if worker_issue_entries:
            lines.append("### Worker-actionable issue hypotheses")
            lines.extend(
                self._format_issue_entry_for_prompt(item)
                for item in worker_issue_entries[:6]
            )
            if len(worker_issue_entries) > 6:
                lines.append(f"- ... 另有 {len(worker_issue_entries) - 6} 个 worker issue，低收益项本轮可不处理。")
        if not worker_issue_entries:
            lines.append("- 当前没有高收益假设；本轮漏报补扫应主要依据 advisor feedback。")
        return "\n".join(lines)

    @staticmethod
    def _issue_owner(item: dict[str, Any]) -> str:
        issue = item.get("issue") if isinstance(item.get("issue"), dict) else {}
        return str(
            issue.get("actionable_by")
            or issue.get("owner")
            or item.get("actionable_by")
            or item.get("owner")
            or ""
        ).strip().lower()

    @staticmethod
    def _issue_category(item: dict[str, Any]) -> str:
        issue = item.get("issue") if isinstance(item.get("issue"), dict) else {}
        return str(issue.get("category") or item.get("category") or "").strip().lower()

    @staticmethod
    def _issue_blocking_type(item: dict[str, Any]) -> str:
        issue = item.get("issue") if isinstance(item.get("issue"), dict) else {}
        return str(
            issue.get("blocking_type")
            or issue.get("blocker_type")
            or item.get("blocking_type")
            or ""
        ).strip().lower()

    @staticmethod
    def _issue_prompt_text(item: dict[str, Any]) -> str:
        issue = item.get("issue") if isinstance(item.get("issue"), dict) else {}
        parts = [
            issue.get("id"),
            issue.get("category"),
            issue.get("blocking_type"),
            issue.get("target"),
            issue.get("path"),
            issue.get("required_action"),
            issue.get("detail"),
            issue.get("description"),
            issue.get("acceptance_criteria"),
            item.get("semantic_key"),
            item.get("blocking_type"),
            item.get("acceptance_criteria"),
        ]
        return " ".join(str(part or "") for part in parts).lower()

    @classmethod
    def _is_profile_depth_budget_issue_entry(cls, item: dict[str, Any]) -> bool:
        issue = item.get("issue") if isinstance(item.get("issue"), dict) else {}
        category = cls._issue_category(item)
        blocking_type = cls._issue_blocking_type(item)
        advisor_id = str(issue.get("advisor_id") or item.get("advisor_id") or "").strip().lower()
        issue_id = str(issue.get("id") or issue.get("issue_id") or item.get("signature") or "").strip().lower()
        return (
            category == "profile_depth_budget"
            or blocking_type == "profile_depth_budget"
            or advisor_id == "profile_execution_policy"
            or issue_id.startswith("profile-")
        )

    @staticmethod
    def _text_has_security_signal(text: str) -> bool:
        lowered = str(text or "").lower()
        security_markers = (
            "security", "vuln", "漏洞", "cwe", "sink", "危险", "源码", "source",
            "function", "函数", "memory", "integer", "overflow", "oob", "越界",
            "校验", "绕过", "边界", "input", "export", "used", "cleaned", "star",
        )
        line_marker = re.search(r"\bL\d{2,}\b|:[0-9]{2,}", lowered) is not None
        return line_marker or any(marker in lowered for marker in security_markers)

    @classmethod
    def _is_summary_doc_issue_entry(cls, item: dict[str, Any]) -> bool:
        owner = cls._issue_owner(item)
        category = cls._issue_category(item)
        blocking_type = cls._issue_blocking_type(item)
        text = cls._issue_prompt_text(item)
        summary_owners = {"summary", "report"}
        summary_categories = {
            "report_completeness",
            "limitations_honesty",
            "summary",
            "metadata",
            "metadata_sync",
            "format",
            "format_gap",
        }
        summary_blocking_types = {
            "documentation_gap",
            "metadata_sync",
            "summary_only_evidence",
            "format_gap",
            "report_completeness",
            "limitations_honesty",
        }
        if owner == "worker" and cls._text_has_security_signal(text) and blocking_type not in summary_blocking_types:
            return False
        if owner in summary_owners:
            return True
        if category in summary_categories or blocking_type in summary_blocking_types:
            return True
        if "summary" in text and ("同步" in text or "table" in text or "表格" in text):
            return True
        return False

    @classmethod
    def _is_security_worker_issue_entry(cls, item: dict[str, Any]) -> bool:
        if cls._is_summary_doc_issue_entry(item):
            return False
        owner = cls._issue_owner(item)
        if owner == "framework":
            return False
        category = cls._issue_category(item)
        blocking_type = cls._issue_blocking_type(item)
        text = cls._issue_prompt_text(item)
        security_types = {
            "security_gap",
            "vulnerability_gap",
            "missed_vuln",
            "missed_vulnerability",
            "analysis_gap",
            "source_evidence_gap",
            "evidence_gap",
            "scan_depth",
            "export_followthrough",
        }
        if blocking_type in security_types or category in security_types:
            return cls._text_has_security_signal(text) or blocking_type in {"analysis_gap", "scan_depth"}
        return cls._text_has_security_signal(text)

    @classmethod
    def _split_rework_issue_entries(
        cls,
        entries: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        worker_entries: list[dict[str, Any]] = []
        summary_entries: list[dict[str, Any]] = []
        for item in entries:
            if cls._issue_owner(item) == "framework":
                continue
            if cls._is_profile_depth_budget_issue_entry(item):
                worker_entries.append(item)
                continue
            if cls._is_summary_doc_issue_entry(item):
                summary_entries.append(item)
                continue
            if cls._is_security_worker_issue_entry(item):
                worker_entries.append(item)
            else:
                summary_entries.append(item)
        return worker_entries, summary_entries

    @staticmethod
    def _path_for_prompt(ctx: WorkflowContext, path: str | Path) -> str:
        value = str(path)
        if not value:
            return value
        try:
            rel = os.path.relpath(value, ctx.working_dir)
        except ValueError:
            return value
        if rel == ".":
            return "."
        if rel.startswith("..") or os.path.isabs(rel) and rel == value:
            return value
        return rel

    def _build_rework_session_context(
        self,
        ctx: WorkflowContext,
        review_state: ReviewState,
    ) -> str:
        summary_path = ctx.summary_file or os.path.join(ctx.working_dir, "summary.md")
        results_dir = ctx.results_dir or os.path.join(ctx.working_dir, "results")
        supporting_docs_dir = self._supporting_docs_dir(ctx.working_dir)
        previous_limitations_file = os.path.join(ctx.working_dir, "previous_limitations.md")
        lines = [
            "## 共享 session 增量上下文",
            "- 共用同一个 Worker session；本 prompt 只补充本轮 delta，历史细节按需读取文件。",
            f"- Cycle={ctx.cycle}; mode={ctx.review_mode or review_state.workflow_mode}",
            f"- WORKDIR=`{ctx.working_dir}`",
            f"- TASK=`{self._path_for_prompt(ctx, ctx.task_file)}`",
            f"- SUMMARY=`{self._path_for_prompt(ctx, summary_path)}`; RESULTS=`{self._path_for_prompt(ctx, results_dir)}`; SUPPORTING=`{self._path_for_prompt(ctx, supporting_docs_dir)}`",
            f"- PREVIOUS_LIMITATIONS=`{self._path_for_prompt(ctx, previous_limitations_file)}`",
        ]
        if ctx.review_mode == "closure" or review_state.workflow_mode == "closure":
            lines.append("- 当前已经进入 **closure（收敛）模式**。")
            reason = str(getattr(review_state, "closure_reason", "") or getattr(ctx, "plateau_reason", "") or "").strip()
            if reason:
                lines.append(f"- closure 触发原因：{reason[:500]}")
        return "\n".join(lines)

    def _build_rework_required_read_files(
        self,
        *,
        ctx: WorkflowContext,
        failed_files: list[str],
        worker_issue_entries: list[dict[str, Any]],
        summary_handoff_entries: list[dict[str, Any]],
    ) -> str:
        results_dir = ctx.results_dir or os.path.join(ctx.working_dir, "results")
        required: list[str] = [ctx.task_file]

        for name in failed_files:
            path = os.path.join(results_dir, name)
            if os.path.isfile(path):
                required.append(path)

        for item in worker_issue_entries[:5]:
            issue = item.get("issue") if isinstance(item.get("issue"), dict) else {}
            for value in (
                issue.get("target"),
                issue.get("evidence"),
                issue.get("source_file"),
            ):
                required.extend(self._resolve_rework_read_paths(ctx, str(value or "").strip()))

        unique: list[str] = []
        for path in required:
            if path and path not in unique:
                unique.append(path)

        lines = ["## 本轮必须读取的增量文件"]
        lines.extend(f"- `{self._path_for_prompt(ctx, path)}`" for path in unique[:10])
        if len(unique) > 10:
            lines.append(f"- ... 另有 {len(unique) - 10} 个相关文件，按本轮方向需要再读取。")
        lines.append("- 不要重新通读所有历史 result/supporting_docs；只按本轮目标队列追加读取。")
        return "\n".join(lines)

    @staticmethod
    def _resolve_rework_read_paths(ctx: WorkflowContext, text: str) -> list[str]:
        if not text:
            return []
        matches = re.findall(r"[\w./:-]+\.md", text)
        if text.endswith(".md") and text not in matches:
            matches.append(text)
        candidates: list[str] = []
        for raw in matches:
            value = raw.strip("`'\"，,;:()[]{}")
            if not value:
                continue
            path_candidates = [value]
            if not os.path.isabs(value):
                path_candidates.extend([
                    os.path.join(ctx.working_dir, value),
                    os.path.join(ctx.working_dir, "results", value),
                    os.path.join(ctx.working_dir, "supporting_docs", value),
                ])
            for candidate in path_candidates:
                if os.path.isfile(candidate):
                    candidates.append(candidate)
                    break
        unique: list[str] = []
        for path in candidates:
            if path not in unique:
                unique.append(path)
        return unique

    @staticmethod
    def _format_issue_entry_for_prompt(item: dict[str, Any]) -> str:
        issue = item.get("issue") if isinstance(item.get("issue"), dict) else {}
        issue_id = ReviewState.prompt_safe_issue_id(
            issue.get("id") or issue.get("issue_id") or item.get("signature") or ""
        )
        target = str(issue.get("target") or "(未指定 target)")[:180]
        owner = str(issue.get("actionable_by") or item.get("actionable_by") or "worker")
        blocking_type = ReviewState.prompt_safe_blocking_type(
            item.get("blocking_type") or issue.get("blocking_type") or ""
        )
        action = str(
            issue.get("required_action")
            or issue.get("detail")
            or item.get("semantic_key")
            or ""
        ).strip()
        line = (
            f"- `{issue_id or item.get('signature')}`: target={target}; "
            f"actionable_by={owner}; blocking_type={blocking_type or 'unspecified'}"
        )
        if action:
            line += f"; action={action[:180]}"
        acceptance = str(item.get("acceptance_criteria") or issue.get("acceptance_criteria") or "").strip()
        if acceptance:
            line += f"; acceptance={acceptance[:160]}"
        return line

    def _build_rework_priority_queue(
        self,
        *,
        ctx: WorkflowContext,
        review_state: ReviewState,
        failed_files: list[str],
        worker_issue_entries: list[dict[str, Any]],
    ) -> str:
        lines = [
            "## 本轮增量目标队列（按优先级执行）",
            "- P1：worker 可执行 active issues（漏报/深度缺口）。",
            "- 旧 result 只用于避免重复，不作为误报修复任务。",
        ]
        failed_files = []
        if worker_issue_entries:
            lines.extend(["", "### P1 worker active issues"])
            lines.extend(self._format_issue_entry_for_prompt(item) for item in worker_issue_entries[:8])
            if len(worker_issue_entries) > 8:
                lines.append(f"- ... 另有 {len(worker_issue_entries) - 8} 个 worker issue，请参考本轮评审反馈。")
        if not failed_files and not worker_issue_entries:
            lines.extend(["", "- 当前没有强制 Worker 返工目标；若只是 summary 同步问题，请只补充 summary 阶段需要的 supporting_docs 证据。"])
        return "\n".join(lines)

    def _build_summary_handoff_queue(self, summary_handoff_entries: list[dict[str, Any]]) -> str:
        lines = [
            "- 下列问题主要由后续 summary 阶段统一整理或说明；Worker 只需补足必要证据。",
        ]
        if summary_handoff_entries:
            lines.extend(self._format_issue_entry_for_prompt(item) for item in summary_handoff_entries[:6])
            if len(summary_handoff_entries) > 6:
                lines.append(f"- ... 另有 {len(summary_handoff_entries) - 6} 个 summary issue，请参考本轮评审反馈。")
        else:
            lines.append("- 当前没有单独的 summary handoff issue。")
        return "\n".join(lines)

    @staticmethod
    def _build_rework_scope_policy(
        *,
        summary_repair_only: bool,
        result_repair_only: bool,
        is_closure: bool,
        worker_issue_count: int = 0,
    ) -> str:
        lines = [
            "## 返工范围硬约束",
            "- 返工不是重新漏洞挖掘，而是基于本轮增量目标队列做定向闭环。",
            "- 本轮新增探索必须至少命中以下一项：P1 worker issue 或明确源码证据缺口。",
            "- 脱离 INPUT / EXPORT / USED / CLEANED / ★ 主轴的全源码发散不得写入正式结果。",
            "- 如果历史 session 中的旧目标与本轮队列冲突，以本轮队列为准。",
        ]
        if summary_repair_only:
            lines.extend([
                "- 本轮主要为 summary handoff：只补充后续 summary 阶段需要的 supporting_docs 证据。",
                "- 禁止新增、删除、重写、重新编号 `results/result_NNN.md`。",
            ])
        elif result_repair_only:
            lines.extend([
                "- 结果修复节点已删除；忽略旧漏洞状态，只围绕全局评审缺口寻找新的独立漏洞。",
                "- 不要把返工扩张成全量攻击面重扫。",
            ])
        elif is_closure:
            lines.extend([
                "- 当前为 closure：优先关闭 P1 active issues。",
                "- 若源码/外部依赖缺失，写 accepted_residual/external_blocked 与人工验收条件，不要反复写继续分析。",
            ])
        else:
            lines.append("- discovery 返工只围绕评审反馈定向扩展，不重新全量重扫。")
        lines.append(
            f"- 本轮队列规模：worker issues={worker_issue_count}。"
        )
        return "\n".join(lines)

    @staticmethod
    def _build_issue_closure_template(
        *,
        ctx: WorkflowContext,
        review_state: ReviewState,
        issue_closure_file: str,
        failed_files: list[str] | None = None,
        worker_issue_entries: list[dict[str, Any]] | None = None,
    ) -> str:
        issue_lines = []
        for name in failed_files or []:
            reason = ""
            for item in review_state.get_failed_results(current_results=ctx.pre_cycle_result_files):
                if item.filename == name:
                    reason = item.reason[:80]
                    break
            issue_lines.append(
                f"| failed_result:{name} | {name} |  | 修复/撤回/补证：{reason} |  |  |"
            )
        for item in (worker_issue_entries or [])[:8]:
            issue = item.get("issue") if isinstance(item.get("issue"), dict) else {}
            issue_id = str(issue.get("id") or issue.get("issue_id") or item.get("signature") or "").strip()
            target = ""
            if issue:
                target = str(issue.get("target") or "").strip()
            if issue_id:
                safe_issue_id = ReviewState.prompt_safe_issue_id(issue_id)
                issue_lines.append(f"| {safe_issue_id} | {target} |  |  |  |  |")
        if not issue_lines:
            issue_lines.append("| <issue_id> | <目标> | <source_closed/promoted_to_result/accepted_residual/not_applicable/external_blocked> | <本轮动作> | <results/... 或 supporting_docs/...> | <剩余限制> |")
        return "\n".join([
            "## issue closure 记录要求",
            f"本轮必须创建或更新：`{issue_closure_file}`",
            "只需要覆盖本轮 P0/P1/P2 目标队列。",
            "",
            "建议内容模板：",
            "",
            "```markdown",
            f"# Issue Closure Cycle {ctx.cycle:03d}",
            "",
            "| issue_id | target | status | action | evidence | residual/限制 |",
            "|---|---|---|---|---|---|",
            *issue_lines,
            "```",
            "",
            "status 只能使用：source_closed / promoted_to_result / accepted_residual / not_applicable / external_blocked。",
        ])

    def _build_rework_convergence_requirements(
        self,
        *,
        ctx: WorkflowContext,
        is_closure: bool,
        summary_repair_only: bool,
        result_repair_only: bool,
        repeated_issue_summary: str,
    ) -> str:
        lines = ["## 收敛要求"]
        if summary_repair_only:
            lines.append("- 当前已经进入 **closure（收敛）模式**。")
            lines.append("- 本轮只补充后续 summary 阶段需要的 `supporting_docs/` 证据与 handoff 说明。")
            lines.append("- 不要新增、删除、重写或重新编号 `results/result_NNN.md`；结果评审已经通过。")
            lines.append("- 不要手工编辑 `_meta/` 下的框架生成文件；只修正正式文档。")
        elif result_repair_only:
            lines.append("- 结果修复节点已删除；本轮不处理旧漏洞状态，只围绕全局评审缺口寻找新的独立漏洞。")
            lines.append("- 不要继续扩张到队列之外的攻击面；未列出的低收益方向留给后续轮次或 summary handoff。")
        elif is_closure:
            lines.append("- 当前已经进入 **closure（收敛）模式**。")
            lines.append("- 优先关闭本轮 P1/P2 队列，不要继续扩张攻击面。")
            lines.append("- 若没有新增结果，必须在 `supporting_docs/` 记录本轮深挖证据，供后续 summary 阶段统一整理。")
            if repeated_issue_summary:
                residual_path = os.path.join(
                    self._supporting_docs_dir(ctx.working_dir),
                    f"residual_cycle_{ctx.cycle:03d}.md",
                )
                lines.append("- 对上方重复阻塞项，本轮必须三选一给出明确处置：")
                lines.append(f"  1. `source_closed`：补齐源码证据并在 result/supporting_docs 中写明闭环链路。")
                lines.append("  2. `promoted_to_result`：若确认形成漏洞，创建或修正一个最小粒度 `result_NNN.md`。")
                lines.append(f"  3. `accepted_residual`：若因外部源码/上下文缺失不可闭环，写入 `{residual_path}`，说明已查证范围、缺失依赖、风险和后续人工验收条件。")
                lines.append("- 不要只写“继续跟入/需要继续分析”；本轮结束时必须留下可评审的闭环证据或 residual 记录。")
        else:
            lines.append("- 围绕近期评审反馈和已有证据定向扩展，不要全量重扫。")
        return "\n".join(lines)

    @staticmethod
    def _build_legacy_rework_prompt(sections: dict[str, Any]) -> str:
        """Fallback for old configs that do not declare a rework prompt file."""
        lines = [
            f"# 第 {sections['cycle']} 轮评审返工",
            "",
            sections.get("rework_session_context") or sections["rework_recovery_context"],
            "",
            sections.get("required_read_files", ""),
            "",
            sections["review_delta_text"],
        ]
        for key in (
            "global_review_feedback",
            "repeated_issue_summary",
            "rework_priority_queue",
            "summary_handoff_queue",
            "rework_scope_policy",
        ):
            if sections.get(key):
                lines.extend(["", str(sections[key])])
        lines.extend([
            "",
            "## 本阶段输出位置",
            sections["output_contract_text"],
        ])
        if sections.get("numbering_rules"):
            lines.extend(["", sections["numbering_rules"]])
        lines.extend([
            "",
            sections["convergence_requirements"],
            "",
            sections["direct_read_instruction"],
        ])
        return "\n".join(lines)

    def _build_rework_recovery_context(
        self,
        ctx: WorkflowContext,
        review_state: ReviewState,
    ) -> str:
        """Build enough context for a fresh Worker session to resume safely."""
        summary_path = ctx.summary_file or os.path.join(ctx.working_dir, "summary.md")
        results_dir = ctx.results_dir or os.path.join(ctx.working_dir, "results")
        supporting_docs_dir = self._supporting_docs_dir(ctx.working_dir)
        previous_limitations_file = os.path.join(ctx.working_dir, "previous_limitations.md")
        supporting_docs = list_supporting_markdown_files(supporting_docs_dir)
        result_files = ctx.pre_cycle_result_files or self._list_result_files(results_dir)

        lines = [
            "## 返工上下文恢复包",
            f"- 当前轮次：{ctx.cycle}",
            f"- 工作模式：{ctx.review_mode or review_state.workflow_mode}",
            f"- 任务文件: `{ctx.task_file}`",
            f"- 工作目录: `{ctx.working_dir}`",
            f"- summary: `{summary_path}`",
            f"- results_dir: `{results_dir}`",
            f"- supporting_docs_dir: `{supporting_docs_dir}`",
            f"- previous_limitations: `{previous_limitations_file}`",
            "",
            "### 开始前必须读取",
            f"- `{ctx.task_file}`",
        ]
        for candidate in (summary_path, previous_limitations_file):
            if os.path.isfile(candidate):
                lines.append(f"- `{candidate}`")
        for name in result_files:
            lines.append(f"- `{os.path.join(results_dir, name)}`")
        for name in supporting_docs:
            lines.append(f"- `{os.path.join(supporting_docs_dir, name)}`")
        lines.extend([
            "",
            format_review_profile_policy(ctx.review_profile),
            "",
            self._format_profile_execution_context(ctx),
            "",
            "### 返工原则",
            "- 优先回应本轮评审反馈中明确指出的源码证据缺口。",
            "- 对每个阻塞项必须给出 `source_closed`、`promoted_to_result`、`accepted_residual`、`unused/not_applicable` 之一的明确状态。",
            "- 若受外部源码/上下文限制不可闭环，写入 supporting_docs 并在 summary 局限性章节保留 residual，不要反复写“继续分析”。",
        ])
        return "\n".join(lines)

    @staticmethod
    def _format_profile_execution_context(ctx: WorkflowContext) -> str:
        policy = get_review_profile_policy(ctx.review_profile)
        if policy.required_pattern_families:
            pattern_focus = ", ".join(policy.required_pattern_families)
        else:
            pattern_focus = "优先沿数据流主轴验证显性、高置信漏洞。"
        depth_lanes = WorkerExecutor._prompt_facing_depth_lanes(policy)
        lines = [
            "## 本轮挖掘目标与深度提示",
            f"- 本轮目标: {policy.execution_goal}",
            f"- 漏洞模式重点: {pattern_focus}",
            "- 深挖路线:",
        ]
        lines.extend(f"  - {lane}" for lane in depth_lanes)
        lines.extend([
            (
                "- 如果本轮没有新增高置信漏洞，也要在 `supporting_docs/` 中留下 "
                "`source_closed` / `accepted_residual` / `not_applicable` 等可复核证据，"
                "不要只写“继续分析”。"
            ),
            "- 使用 `rg` 先定位，再用小窗口 `read` 跟入；避免无边界读取整文件造成单轮膨胀。",
        ])
        return "\n".join(lines)

    @staticmethod
    def _prompt_facing_depth_lanes(policy) -> tuple[str, ...]:
        if policy.name == "audit":
            return (
                "沿主路径、高风险端点和关键 EXPORT/USED 路线继续深挖。",
                "对 STAR/EXPORT/USED 线索深度闭环，并对 INPUT/CLEANED 保留可复核边界。",
                "跨函数、跨协议族、跨方向的漏洞变体搜索。",
                "未立项端点的可复核负证据矩阵。",
                "可利用性前提、攻击者能力、配置依赖和 residual 边界审计。",
                "对候选漏洞做反例/误报证伪后再保留最终报告。",
            )
        return tuple(policy.depth_lanes)

    @staticmethod
    def _clip_prompt_section(text: str, *, max_chars: int) -> str:
        text = text or ""
        if max_chars <= 0 or len(text) <= max_chars:
            return text
        omitted = len(text) - max_chars
        return (
            text[:max_chars].rstrip()
            + f"\n\n[section clipped: omitted {omitted} chars; full details are in review artifacts under `_meta/` and `reviews/`]\n"
        )

    @staticmethod
    def _extract_result_number(name: str) -> int | None:
        if not name.endswith(".md"):
            name = f"{name}.md"
        return extract_result_number(name)

    @classmethod
    def _list_result_files(cls, results_dir: str) -> list[str]:
        return list_result_report_files(results_dir)

    @classmethod
    def _get_max_result_number(cls, working_dir: str) -> int:
        results_dir = os.path.join(working_dir, "results")
        max_num = 0
        for name in cls._list_result_files(results_dir):
            number = cls._extract_result_number(name)
            if number is not None:
                max_num = max(max_num, number)
        return max_num

    @classmethod
    def _get_historical_max_result_number(cls, working_dir: str) -> int:
        max_num = cls._get_max_result_number(working_dir)
        reviews_root = os.path.join(working_dir, "reviews", "results")
        if os.path.isdir(reviews_root):
            for name in os.listdir(reviews_root):
                number = cls._extract_result_number(name)
                if number is not None and os.path.isdir(os.path.join(reviews_root, name)):
                    max_num = max(max_num, number)
        return max_num

    def _prepare_rework_context(
        self,
        ctx: WorkflowContext,
        review_state: ReviewState,
    ) -> None:
        results_dir = os.path.join(ctx.working_dir, "results")
        pre_cycle_files = self._list_result_files(results_dir)
        pre_cycle_set = set(pre_cycle_files)

        active_passed_results = set(pre_cycle_files)
        summary_path = ctx.summary_file or os.path.join(ctx.working_dir, "summary.md")
        if os.path.isfile(summary_path):
            try:
                final_selection = classify_final_result_files(results_dir, summary_path)
                selected = set(final_selection.get("final_results") or [])
                if selected:
                    active_passed_results = selected
            except Exception as exc:
                logger.warning(
                    "rework_context_result_selection_fallback",
                    workflow_id=ctx.workflow_id,
                    task_id=ctx.task_id,
                    cycle=ctx.cycle,
                    error=str(exc),
                )

        protected_files = sorted(
            name for name in pre_cycle_files
            if name in pre_cycle_set and name in active_passed_results
        )
        snapshots: dict[str, str] = {}
        for name in protected_files:
            path = os.path.join(results_dir, name)
            try:
                snapshots[name] = read_file(path)
            except FileNotFoundError:
                continue

        # Result-review business statuses (confirmed/false_positive/pending)
        # are owned by the reviewer and vulnerability_list.json. Rework should
        # not treat any old result as a repair target, so keep failed snapshots
        # empty in the normal path.
        failed_snapshots: dict[str, str] = {}
        failed_reasons: dict[str, str] = {}

        ctx.pre_cycle_result_files = pre_cycle_files
        ctx.protected_result_files = protected_files
        ctx.protected_result_snapshots = snapshots
        ctx.failed_result_snapshots = failed_snapshots
        ctx.failed_result_reasons = failed_reasons
        ctx.historical_max_result_number = self._get_historical_max_result_number(
            ctx.working_dir)
        ctx.next_result_number = max(1, ctx.historical_max_result_number + 1)

        logger.info(
            "rework_context_prepared",
            workflow_id=ctx.workflow_id,
            task_id=ctx.task_id,
            cycle=ctx.cycle,
            existing_results=len(pre_cycle_files),
            protected_results=len(protected_files),
            failed_results=len(failed_snapshots),
            next_result_number=ctx.next_result_number,
        )

    def _build_summary_rework_rules(self, ctx: WorkflowContext) -> str:
        if ctx.cycle <= 1 or not ctx.pre_cycle_result_files:
            return ""

        mutable_files = [
            name for name in ctx.pre_cycle_result_files
            if name not in set(ctx.protected_result_files)
        ]
        protected_text = ", ".join(ctx.protected_result_files) or "无"
        mutable_text = ", ".join(mutable_files[:8]) or "无"
        if len(mutable_files) > 8:
            mutable_text += f" ... 另有 {len(mutable_files) - 8} 个"

        lines = [
            "## Result 文件稳定性 contract",
            f"- 已通过评审的结果 protected(read-only)：{protected_text}",
            f"- 新增真实漏洞从 `result_{ctx.next_result_number:03d}.md` 开始；历史编号永不复用，已通过 result 不覆盖、不重命名。",
            "- `results/` 只放独立漏洞 `result_NNN.md`；辅助审计、撤回说明、coverage/residual 写入 `supporting_docs/`。",
            "- 一个 result 只描述一个独立漏洞；补充/修正报告必须标注原始报告与报告性质。",
        ]
        if ctx.review_mode == "closure":
            lines.append("- closure 模式：禁止批量新增或全量重扫，只允许直接回应近期安全类评审问题。")
        return "\n".join(lines)

    @classmethod
    def _reserve_new_result_path(
        cls,
        results_dir: Path,
        start_num: int,
    ) -> tuple[Path, int]:
        next_num = max(1, start_num)
        while True:
            candidate = results_dir / f"result_{next_num:03d}.md"
            if not candidate.exists():
                return candidate, next_num + 1
            next_num += 1

    @staticmethod
    def _rewrite_summary_result_references(
        summary_path: Path,
        rename_map: dict[str, str],
    ) -> None:
        if not rename_map or not summary_path.is_file():
            return
        content = summary_path.read_text(encoding="utf-8", errors="replace")
        updated = content
        for old_name, new_name in rename_map.items():
            updated = updated.replace(old_name, new_name)
        if updated != content:
            summary_path.write_text(updated, encoding="utf-8")

    @staticmethod
    def _is_explicitly_withdrawn_result(content: str) -> bool:
        lifecycle = infer_result_lifecycle_from_text(content)
        return str(lifecycle.get("status") or "") in {
            "withdrawn",
            "false_positive",
            "superseded",
        }

    def _auto_remove_withdrawn_failed_results(self, ctx: WorkflowContext) -> list[str]:
        # Do not silently remove result files based on lifecycle markers. A
        # withdrawn / false-positive report is still part of the Run evidence
        # trail; the inspector can mark it inactive without changing the user's
        # file layout.
        return []

    def _relocate_inactive_result_files(self, ctx: WorkflowContext) -> list[str]:
        # Lifecycle classification is metadata, not permission to mutate the
        # Run. Keep inactive/superseded files in results/ and let the index/UI
        # show their status explicitly.
        return []

    def _backup_removed_failed_results(self, ctx: WorkflowContext) -> list[str]:
        if ctx.cycle <= 1 or not ctx.results_dir or not ctx.failed_result_snapshots:
            return []

        results_dir = Path(ctx.results_dir)
        current_files = set(self._list_result_files(str(results_dir)))
        backup_root = Path(ctx.working_dir) / "removed_results" / f"cycle_{ctx.cycle:03d}"
        backed_up: list[str] = []

        for name, content in sorted(ctx.failed_result_snapshots.items()):
            if name in current_files:
                continue

            backup_root.mkdir(parents=True, exist_ok=True)
            backup_md = backup_root / name
            backup_meta = backup_root / f"{Path(name).stem}.json"
            if backup_md.exists() or backup_meta.exists():
                continue

            backup_md.write_text(content, encoding="utf-8")
            write_json(
                backup_meta,
                {
                    "workflow_id": ctx.workflow_id,
                    "task_id": ctx.task_id,
                    "removed_in_cycle": ctx.cycle,
                    "original_filename": name,
                    "original_path": str(results_dir / name),
                    "backup_path": str(backup_md),
                    "reason": ctx.failed_result_reasons.get(name, ""),
                },
            )
            backed_up.append(name)

        if backed_up:
            logger.info(
                "removed_failed_results_backed_up",
                workflow_id=ctx.workflow_id,
                task_id=ctx.task_id,
                cycle=ctx.cycle,
                count=len(backed_up),
                files=backed_up,
                backup_dir=str(backup_root),
            )

        return backed_up

    def _reconcile_results_after_rework(self, ctx: WorkflowContext) -> None:
        if ctx.cycle <= 1 or not ctx.results_dir:
            return

        results_dir = Path(ctx.results_dir)
        if not results_dir.is_dir():
            return

        rename_floor = max(1, ctx.next_result_number)
        next_num = max(
            rename_floor,
            self._get_historical_max_result_number(ctx.working_dir) + 1,
        )
        actions: list[str] = []
        summary_rename_map: dict[str, str] = {}
        protected_set = set(ctx.protected_result_files)
        pre_cycle_set = set(ctx.pre_cycle_result_files)

        for name in ctx.protected_result_files:
            snapshot = ctx.protected_result_snapshots.get(name)
            if snapshot is None:
                continue

            protected_path = results_dir / name
            if protected_path.is_file():
                current = protected_path.read_text(encoding="utf-8", errors="replace")
                if current == snapshot:
                    continue
                relocated_path, next_num = self._reserve_new_result_path(results_dir, next_num)
                protected_path.replace(relocated_path)
                summary_rename_map[name] = relocated_path.name
                actions.append(
                    f"restored protected file {name}; moved overwritten content to {relocated_path.name}")
            else:
                actions.append(f"restored deleted protected file {name}")

            protected_path.write_text(snapshot, encoding="utf-8")

        for name in list(self._list_result_files(str(results_dir))):
            if name in pre_cycle_set or name in protected_set:
                continue
            number = self._extract_result_number(name)
            if number is None or number >= rename_floor:
                continue

            src = results_dir / name
            dst, next_num = self._reserve_new_result_path(results_dir, next_num)
            src.replace(dst)
            summary_rename_map[name] = dst.name
            actions.append(f"renamed new report {name} -> {dst.name}")

        self._rewrite_summary_result_references(Path(ctx.summary_file or ""), summary_rename_map)
        auto_removed = self._auto_remove_withdrawn_failed_results(ctx)
        if auto_removed:
            actions.extend(
                f"auto-removed withdrawn failed report {name}" for name in auto_removed
            )

        backed_up = self._backup_removed_failed_results(ctx)
        if backed_up:
            actions.extend(
                f"backed up removed failed report {name}" for name in backed_up
            )

        inactive_moved = self._relocate_inactive_result_files(ctx)
        if inactive_moved:
            actions.extend(f"relocated inactive result {name}" for name in inactive_moved)

        if actions:
            logger.warning(
                "rework_result_reconciliation_applied",
                workflow_id=ctx.workflow_id,
                task_id=ctx.task_id,
                cycle=ctx.cycle,
                actions=actions,
            )

    # ─────────────────────────────────────────────
    #  反思 & 总结
    # ─────────────────────────────────────────────

    def _relocate_misplaced_outputs(
        self,
        ctx: WorkflowContext,
        turn_count: int,
    ) -> None:
        """
        兜底修复:如果模型把 summary.md / result_*.md 写到了
        sessions/<session>/calls/<turn>_* 下面,则自动搬运回工作目录。
        """
        if not ctx.worker_session_id or not ctx.working_dir or turn_count <= 0:
            return

        calls_dir = Path(ctx.working_dir) / "sessions" / ctx.worker_session_id / "calls"
        if not calls_dir.is_dir():
            return

        call_dirs = sorted(calls_dir.glob(f"{turn_count:03d}_*"))
        if not call_dirs:
            return

        call_dir = call_dirs[-1]
        summary_dst = Path(ctx.working_dir) / "summary.md"
        results_dst = Path(ctx.working_dir) / "results"
        supporting_docs_dst = Path(self._supporting_docs_dir(ctx.working_dir))

        relocated: list[str] = []

        moved_summary = self._move_file_if_exists(call_dir / "summary.md", summary_dst)
        if moved_summary:
            relocated.append(moved_summary)

        misplaced_results_dir = call_dir / "results"
        if misplaced_results_dir.is_dir():
            for src in sorted(misplaced_results_dir.glob("*.md")):
                destination = (
                    results_dst / src.name
                    if is_result_report_filename(src.name)
                    else supporting_docs_dst / src.name
                )
                moved = self._move_file_if_exists(src, destination)
                if moved:
                    relocated.append(moved)
            self._remove_dir_if_empty(misplaced_results_dir)

        for src in sorted(call_dir.glob("result_*.md")):
            moved = self._move_file_if_exists(src, results_dst / src.name)
            if moved:
                relocated.append(moved)

        if relocated:
            logger.warning(
                "misplaced_outputs_relocated",
                workflow_id=ctx.workflow_id,
                task_id=ctx.task_id,
                cycle=ctx.cycle,
                call_dir=str(call_dir),
                relocated=relocated,
            )

    def _relocate_supporting_docs_from_results(self, ctx: WorkflowContext) -> list[str]:
        if not ctx.results_dir or not os.path.isdir(ctx.results_dir):
            return []

        results_dir = Path(ctx.results_dir)
        supporting_docs_dir = Path(self._supporting_docs_dir(ctx.working_dir))
        moved: list[str] = []
        rename_map: dict[str, str] = {}

        for name in list_supporting_markdown_files(results_dir):
            src = results_dir / name
            dst = supporting_docs_dir / name
            supporting_docs_dir.mkdir(parents=True, exist_ok=True)
            if dst.exists() and dst.is_file():
                dst.unlink()
            src.replace(dst)
            moved.append(name)
            rename_map[name] = f"supporting_docs/{name}"

        self._rewrite_summary_result_references(Path(ctx.summary_file or ""), rename_map)

        if moved:
            logger.info(
                "supporting_docs_relocated_from_results",
                workflow_id=ctx.workflow_id,
                task_id=ctx.task_id,
                cycle=ctx.cycle,
                files=moved,
                supporting_docs_dir=str(supporting_docs_dir),
            )
        return moved

    def _sync_previous_limitations_sidecar(self, ctx: WorkflowContext) -> None:
        summary_path = Path(ctx.summary_file or "")
        if not summary_path.is_file():
            return
        try:
            summary_content = summary_path.read_text(encoding="utf-8", errors="replace")
            section = extract_markdown_section(
                summary_content,
                ["局限性与未覆盖区域", "局限性"],
            )
            if not is_substantive_limitations(section):
                return
            sidecar_path = Path(ctx.working_dir) / "previous_limitations.md"
            sidecar_path.write_text(section.rstrip() + "\n", encoding="utf-8")
        except Exception as exc:
            logger.warning("previous_limitations_sidecar_sync_failed", error=str(exc))

    @staticmethod
    def _move_file_if_exists(src: Path, dst: Path) -> Optional[str]:
        if not src.is_file():
            return None
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists():
            if dst.is_file():
                dst.unlink()
            else:
                return None
        src.replace(dst)
        return str(dst)

    @staticmethod
    def _remove_dir_if_empty(dir_path: Path) -> None:
        try:
            if dir_path.is_dir() and not any(dir_path.iterdir()):
                dir_path.rmdir()
        except OSError:
            pass

    @staticmethod
    def _supporting_docs_dir(working_dir: str) -> str:
        return os.path.join(working_dir, "supporting_docs")

    def _build_reflection_scope(
        self,
        ctx: WorkflowContext,
        review_state: ReviewState | None,
    ) -> str:
        supporting_docs_dir = self._supporting_docs_dir(ctx.working_dir)
        current_result_files = self._list_result_files(os.path.join(ctx.working_dir, "results"))
        has_rework_context = bool(
            review_state
            and (
                review_state.has_failures(
                    current_results=current_result_files,
                    actionable_by="worker",
                )
                or review_state.get_recent_issues(last_n=2)
                or (ctx.failed_result_items or [])
                or ctx.review_mode == "closure"
            )
        )
        if ctx.cycle <= 1 or review_state is None or not has_rework_context:
            return "\n".join([
                "当前为首轮深度自审，按下面的深挖清单检查即可。",
                f"若需要补充辅助审计文档，请写到 `{supporting_docs_dir}/`，不要写进 `results/`。",
            ])

        recent_feedback = review_state.format_recent_feedback(last_n=2)

        if ctx.failed_result_items or review_state.get_failed_results(current_results=current_result_files):
            failed_items = [
                item.filename for item in (ctx.failed_result_items or [])
                if is_result_report_filename(item.filename)
            ]
            failed_items_text = (
                "\n".join(f"- {name}" for name in failed_items)
                if failed_items else
                "- (当前无可识别的待修结果文件)"
            )
            return "\n".join([
                "当前不是首轮全量发散式自审，而是结果修复阶段。",
                "本轮自审只服务于未通过结果修复和近期评审反馈，禁止重新铺开全量攻击面。",
                f"辅助审计文档统一写到 `{supporting_docs_dir}/`;`results/` 里只保留 `result_NNN.md`。",
                "",
                "### 本轮优先复核的历史待修结果",
                failed_items_text,
                "",
                "### 自审边界",
                "- 仅复核上述失败结果及其直接相关代码路径",
                "- 若没有新证据，不要新增新的攻击面章节或批量新报告",
                "- 若需要补充删除说明、附录或证据矩阵，写到 `supporting_docs/` 而不是 `results/`",
            ])

        return "\n".join([
            "当前不是首轮全量发散式自审，而是返工/收敛阶段。",
            "本轮自审必须优先服务于近期评审反馈和弱结果修复，不要重新把任务扩张成全量攻击面重扫。",
            f"辅助审计文档统一写到 `{supporting_docs_dir}/`;`results/` 里只保留 `result_NNN.md`。",
            "",
            "### 近期全局评审反馈",
            recent_feedback or "(无近期全局评审反馈)",
            "",
            "### 自审边界",
            "- 只对近期评审反馈、待修结果、以及本轮新改动直接影响的路径做深入复核",
            "- 若没有新证据，不要把 Summary 又写回'全量重扫'口径",
            "- 若需要补充 USED/EXPORT 附录、删除审计说明、覆盖矩阵，写到 `supporting_docs/` 而不是 `results/`",
        ])

    def _build_reflection_checklist(
        self,
        ctx: WorkflowContext,
        review_state: ReviewState | None,
        prompts_dir: str = "",
    ) -> str:
        # 真正的首轮：无评审状态
        if ctx.cycle <= 1 or review_state is None:
            checklist_file = os.path.join(prompts_dir, "reflect_checklist_initial.md") if prompts_dir else ""
            if checklist_file and os.path.isfile(checklist_file):
                return read_file(checklist_file)
            return "(reflection checklist file not found; proceed with deep vulnerability hunting)"

        # 与 _build_reflection_scope 对齐：检查是否存在返工上下文
        current_result_files = self._list_result_files(os.path.join(ctx.working_dir, "results"))
        has_recent_issues = bool(review_state.get_recent_issues(last_n=2))
        has_failed_results = bool(
            (ctx.failed_result_items or [])
            or review_state.get_failed_results(current_results=current_result_files)
        )
        is_closure = ctx.review_mode == "closure"

        # 无失败、无近期问题、非 closure → 初始发现模式
        if not has_recent_issues and not has_failed_results and not is_closure:
            checklist_file = os.path.join(prompts_dir, "reflect_checklist_initial.md") if prompts_dir else ""
            if checklist_file and os.path.isfile(checklist_file):
                return read_file(checklist_file)
            return "(reflection checklist file not found; proceed with deep vulnerability hunting)"

        # 仅有失败结果、无近期全局问题 → 结果修复模式
        if not has_recent_issues and has_failed_results and not is_closure:
            checklist_file = os.path.join(prompts_dir, "reflect_checklist_result_repair.md") if prompts_dir else ""
            if checklist_file and os.path.isfile(checklist_file):
                return read_file(checklist_file)
            return "(result repair checklist file not found)"

        # 有近期全局问题或 closure 模式 → 返工模式
        checklist_file = os.path.join(prompts_dir, "reflect_checklist_rework.md") if prompts_dir else ""
        if checklist_file and os.path.isfile(checklist_file):
            return read_file(checklist_file)
        return "(rework checklist file not found)"

    async def execute_reflection(
        self,
        wf_def: AtomicWorkflowDef,
        ctx: WorkflowContext,
        review_state: ReviewState | None = None,
        resume_cursor: dict[str, Any] | None = None,
    ) -> None:
        """
        自我反思阶段 (R6d)

        按序执行反思 prompt,每一轮等待上一轮完成。
        """
        worker_cfg = wf_def.roles.worker
        reflection_prompts = worker_cfg.prompts.reflection

        if not reflection_prompts:
            logger.debug("no_reflection_prompts", workflow_id=ctx.workflow_id)
            return

        agent = self.agents.get(worker_cfg.agent_id)
        prompts_dir = os.path.dirname(reflection_prompts[0].prompt_file) if reflection_prompts else ""
        policy = get_review_profile_policy(ctx.review_profile)
        configured_passes = getattr(wf_def.engine, "reflection_passes_per_cycle", None)
        reflection_passes = (
            int(configured_passes)
            if configured_passes is not None else
            policy.reflection_passes_per_cycle
        )
        if reflection_passes <= 0:
            logger.info(
                "reflection_skipped_by_profile",
                workflow_id=ctx.workflow_id,
                review_profile=ctx.review_profile,
            )
            return

        current_result_files = self._list_result_files(os.path.join(ctx.working_dir, "results"))
        reflection_state = review_state or ReviewState()
        reflection_state.workflow_mode = ctx.review_mode
        # 单 session 模式下，Worker 已拥有完整对话历史，无需重复注入上下文
        reflection_runtime_context = "\n".join([
            f"- 当前轮次：第 {ctx.cycle} 轮",
            f"- 工作模式：{ctx.review_mode or reflection_state.workflow_mode}",
            f"- 本轮自审目标：{policy.execution_goal}",
        ])
        reflection_runtime_limits = self._effective_reflection_runtime_limits(wf_def, ctx)
        reflection_scope = self._build_reflection_scope(ctx, review_state)
        reflection_checklist = self._build_reflection_checklist(ctx, review_state, prompts_dir=prompts_dir)

        expanded_prompts = [
            (pass_index, reflect_cfg)
            for pass_index in range(1, reflection_passes + 1)
            for reflect_cfg in reflection_prompts
        ]
        for i, (pass_index, reflect_cfg) in enumerate(expanded_prompts):
            step_key = f"reflect::{reflect_cfg.id}::pass_{pass_index:02d}"
            existing_checkpoint = load_step_checkpoint(
                ctx.working_dir,
                cycle=ctx.cycle,
                phase="reflect",
                step_key=step_key,
            )
            if is_terminal_checkpoint(existing_checkpoint):
                logger.info(
                    "resume_skip_reflection_node",
                    round=i + 1,
                    pass_index=pass_index,
                    prompt_id=reflect_cfg.id,
                    cycle=ctx.cycle,
                    step_key=step_key,
                    checkpoint_status=existing_checkpoint.get("status"),
                    resume_cursor=resume_cursor or {},
                )
                continue
            prompt = read_file(reflect_cfg.prompt_file)
            try:
                prompt_kwargs = collect_template_kwargs(
                    prompt,
                    value_factories={
                        "cycle": lambda: str(ctx.cycle),
                        "review_mode": lambda: ctx.review_mode,
                        "task": lambda: self._read_task_content(ctx.task_file),
                        "task_file": lambda: ctx.task_file,
                        "working_dir": lambda: ctx.working_dir,
                        "summary_file": lambda: ctx.summary_file or os.path.join(ctx.working_dir, "summary.md"),
                        "results_dir": lambda: ctx.results_dir or os.path.join(ctx.working_dir, "results"),
                        "supporting_docs_dir": lambda: self._supporting_docs_dir(ctx.working_dir),
                        "previous_limitations_file": lambda: os.path.join(ctx.working_dir, "previous_limitations.md"),
                        "reflection_runtime_context": lambda: reflection_runtime_context,
                        "reflection_scope": lambda: reflection_scope,
                        "reflection_checklist": lambda: reflection_checklist,
                    },
                )
                prompt = render_string(prompt, strict=True, **prompt_kwargs)
            except TemplateRenderError as exc:
                raise WorkerStageError(
                    "reflect",
                    f"Reflection {reflect_cfg.id} prompt 渲染失败：{exc}",
                ) from exc

            logger.info("reflection_start",
                         round=i + 1,
                         pass_index=pass_index,
                         prompt_id=reflect_cfg.id,
                         workflow_id=ctx.workflow_id)
            record_step_checkpoint(
                ctx.working_dir,
                cycle=ctx.cycle,
                phase="reflect",
                step_key=step_key,
                status="started",
                agent_id=worker_cfg.agent_id,
                session_id=ctx.worker_session_id or "",
            )

            # 每一轮必须等上一轮结束 (R6d: 串行)
            response = await self._send_message_with_optional_runtime_limits(
                agent,
                message=prompt,
                session_id=ctx.worker_session_id,
                working_dir=ctx.working_dir,
                runtime_limits=reflection_runtime_limits,
            )

            self._relocate_misplaced_outputs(ctx, response.turn_count)

            empty_response = response.success and response.finished and not (response.content or "").strip()
            if not response.success or not response.finished or empty_response:
                if response.error:
                    error = response.error
                elif empty_response:
                    error = f"Reflection {reflect_cfg.id} 返回空响应"
                else:
                    error = f"Reflection {reflect_cfg.id} 未完成"
                await self.recorder.record_reflection(
                    work_dir=ctx.working_dir,
                    round_num=i + 1,
                    prompt_id=reflect_cfg.id,
                    response=f"[WARN] Reflection skipped as non-blocking advisory step: {error}",
                    cycle=ctx.cycle,
                )
                record_step_checkpoint(
                    ctx.working_dir,
                    cycle=ctx.cycle,
                    phase="reflect",
                    step_key=step_key,
                    status="soft_failed",
                    agent_id=worker_cfg.agent_id,
                    session_id=ctx.worker_session_id or "",
                    detail=error,
                    extra={"turn_count": response.turn_count, "non_blocking": True},
                )
                logger.warning(
                    "reflection_soft_failed",
                    round=i + 1,
                    pass_index=pass_index,
                    prompt_id=reflect_cfg.id,
                    workflow_id=ctx.workflow_id,
                    error=error,
                    turns=response.turn_count,
                    finished=response.finished,
                )
                # 新 Worker 会话策略要求所有轮次/阶段尽量复用同一 RPC session。
                # Reflection 是非阻塞自审步骤；即使它超时，RPC pi 进程也应继续存活，
                # 后续 summary 作为 follow-up 发送到同一 session/进程，而不是重建上下文。
                logger.info(
                    "reflection_soft_failed_keep_worker_session",
                    workflow_id=ctx.workflow_id,
                    task_id=ctx.task_id,
                    session_id=ctx.worker_session_id or "",
                    reason=error,
                )
                return

            await self.recorder.record_reflection(
                work_dir=ctx.working_dir,
                round_num=i + 1,
                prompt_id=reflect_cfg.id,
                response=response.content,
                cycle=ctx.cycle,
            )

            record_step_checkpoint(
                ctx.working_dir,
                cycle=ctx.cycle,
                phase="reflect",
                step_key=step_key,
                status="completed",
                agent_id=worker_cfg.agent_id,
                session_id=ctx.worker_session_id or "",
                extra={"turn_count": response.turn_count, "pass_index": pass_index},
            )
            logger.info("reflection_done",
                         round=i + 1, pass_index=pass_index, prompt_id=reflect_cfg.id)

    async def execute_summary(
        self,
        wf_def: AtomicWorkflowDef,
        ctx: WorkflowContext,
        review_state: ReviewState | None = None,
        resume_cursor: dict[str, Any] | None = None,
    ) -> tuple[str, str]:
        """
        总结阶段 (R6e)

        输出 summary.md + results/ 目录

        Returns:
            (summary_path, results_dir)
        """
        worker_cfg = wf_def.roles.worker
        summary_cfg = worker_cfg.prompts.summary
        agent = self.agents.get(worker_cfg.agent_id)
        if not ctx.worker_session_id or ctx.worker_session_cycle != ctx.cycle:
            await self._ensure_worker_session(agent, wf_def, ctx)

        summary_path = os.path.join(
            ctx.working_dir, summary_cfg.output_summary_filename)
        results_dir = os.path.join(
            ctx.working_dir, summary_cfg.output_results_dir)
        supporting_docs_dir = self._supporting_docs_dir(ctx.working_dir)

        # 确保目录存在
        os.makedirs(os.path.dirname(summary_path), exist_ok=True)
        os.makedirs(results_dir, exist_ok=True)
        os.makedirs(supporting_docs_dir, exist_ok=True)

        ctx.summary_file = summary_path
        ctx.results_dir = results_dir

        existing_checkpoint = load_step_checkpoint(
            ctx.working_dir,
            cycle=ctx.cycle,
            phase="summary",
            step_key="summary",
        )
        if (
            is_terminal_checkpoint(existing_checkpoint)
            and os.path.isfile(summary_path)
            and os.path.isdir(results_dir)
        ):
            logger.info(
                "resume_skip_summary_node",
                workflow_id=ctx.workflow_id,
                task_id=ctx.task_id,
                cycle=ctx.cycle,
                checkpoint_status=existing_checkpoint.get("status"),
                summary_path=summary_path,
                results_dir=results_dir,
                resume_cursor=resume_cursor or {},
            )
            return summary_path, results_dir

        prompt = read_file(summary_cfg.prompt_file)
        summary_state = review_state or ReviewState()
        summary_state.workflow_mode = ctx.review_mode
        summary_runtime_context = "\n".join([
            f"当前轮次：第 {ctx.cycle} 轮",
            f"工作模式：{ctx.review_mode or summary_state.workflow_mode}",
            f"任务文件: {os.path.abspath(ctx.task_file)}",
            f"工作目录: {os.path.abspath(ctx.working_dir)}",
        ])
        summary_contract_cache: tuple[str, int, str] | None = None

        def _summary_contract() -> tuple[str, int, str]:
            nonlocal summary_contract_cache
            if summary_contract_cache is None:
                summary_contract_cache = self._summary_section_contract_for_cycle(ctx.cycle)
            return summary_contract_cache

        try:
            prompt_kwargs = collect_template_kwargs(
                prompt,
                value_factories={
                    "cycle": lambda: str(ctx.cycle),
                    "review_mode": lambda: ctx.review_mode,
                    "task": lambda: self._read_task_content(ctx.task_file),
                    "task_file": lambda: ctx.task_file,
                    "working_dir": lambda: ctx.working_dir,
                    "summary_file": lambda: summary_path,
                    "summary_path": lambda: summary_path,
                    "results_dir": lambda: results_dir,
                    "supporting_docs_dir": lambda: supporting_docs_dir,
                    "previous_limitations_file": lambda: os.path.join(ctx.working_dir, "previous_limitations.md"),
                    "summary_runtime_context": lambda: summary_runtime_context,
                    "summary_section_template": lambda: _summary_contract()[0],
                    "summary_section_count": lambda: str(_summary_contract()[1]),
                    "summary_limitations_requirement": lambda: _summary_contract()[2],
                    "summary_rework_rules": lambda: self._build_summary_rework_rules(ctx) or "(本轮无额外返工规则)",
                    "summary_feedback_context": lambda: self._build_summary_feedback_context(ctx, summary_state),
                    "output_contract_text": lambda: self._build_output_contract_text(ctx),
                },
            )
            prompt = render_string(prompt, strict=True, **prompt_kwargs)
        except TemplateRenderError as exc:
            raise WorkerStageError("summary", f"Summary prompt 渲染失败：{exc}") from exc
        prompt = prompt.rstrip("\n")

        logger.info("summary_start", workflow_id=ctx.workflow_id)
        record_step_checkpoint(
            ctx.working_dir,
            cycle=ctx.cycle,
            phase="summary",
            step_key="summary",
            status="started",
            agent_id=worker_cfg.agent_id,
            session_id=ctx.worker_session_id or "",
            extra={"summary_file": summary_path, "results_dir": results_dir},
        )

        response = await agent.send_message(
            message=prompt,
            session_id=ctx.worker_session_id,
            working_dir=ctx.working_dir,
        )
        self._relocate_misplaced_outputs(ctx, response.turn_count)

        if not response.success or not response.finished:
            error = response.error or "Summary 未完成"
            record_step_checkpoint(
                ctx.working_dir,
                cycle=ctx.cycle,
                phase="summary",
                step_key="summary",
                status="failed",
                agent_id=worker_cfg.agent_id,
                session_id=ctx.worker_session_id or "",
                detail=error,
                extra={"turn_count": response.turn_count, "summary_file": summary_path, "results_dir": results_dir},
            )
            logger.error(
                "summary_error",
                workflow_id=ctx.workflow_id,
                error=error,
                turns=response.turn_count,
                finished=response.finished,
            )
            raise WorkerStageError("summary", error, response)

        self._reconcile_results_after_rework(ctx)
        self._relocate_supporting_docs_from_results(ctx)
        self._sync_previous_limitations_sidecar(ctx)
        self._sync_result_relations_manifest(ctx)

        record_step_checkpoint(
            ctx.working_dir,
            cycle=ctx.cycle,
            phase="summary",
            step_key="summary",
            status="completed",
            agent_id=worker_cfg.agent_id,
            session_id=ctx.worker_session_id or "",
            extra={"turn_count": response.turn_count, "summary_file": summary_path, "results_dir": results_dir},
        )
        logger.info("summary_done",
                     workflow_id=ctx.workflow_id,
                     summary_path=summary_path,
                     results_dir=results_dir)

        return summary_path, results_dir

    @staticmethod
    def _summary_section_contract_for_cycle(cycle: int) -> tuple[str, int, str]:
        if int(cycle) <= 1:
            return (
                "\n".join([
                    "# 数据流驱动漏洞挖掘总结",
                    "",
                    "1. 攻击面分析",
                    "2. 分析覆盖度",
                    "3. 漏洞汇总表",
                    "4. 局限性与不足",
                ]),
                4,
                "\n\n`局限性与不足`章节必须诚实、具体地列出当前分析的盲区、未覆盖的攻击面、潜在的误报风险和无法判断的关键路径；注意，不要写成空泛模板。\n",
            )
        return (
            "\n".join([
                "# 数据流驱动漏洞挖掘总结",
                "",
                "1. 攻击面分析",
                "2. 分析覆盖度",
                "3. 漏洞汇总表",
                "4. 局限性与不足",
            ]),
            4,
            "\n\n`局限性与不足`章节必须诚实、具体地列出当前分析的盲区、未覆盖的攻击面、潜在的误报风险和无法判断的关键路径；注意，不要写成空泛模板。\n",
        )

    def _build_summary_feedback_context(
        self,
        ctx: WorkflowContext,
        review_state: ReviewState,
    ) -> str:
        lines = [
            f"- 当前轮次：{ctx.cycle}",
            f"- 当前工作模式：{ctx.review_mode or review_state.workflow_mode}",
        ]
        lines.extend(["", format_review_profile_policy(ctx.review_profile)])
        if ctx.plateau_reason:
            lines.append(f"- 收敛/返工原因：{ctx.plateau_reason}")
        policy = get_review_profile_policy(ctx.review_profile)
        summary_backlog_limits = {"fast": 4, "balanced": 8, "strict": 12, "audit": 16}
        open_backlog = review_state.format_open_issue_backlog(
            max_items=summary_backlog_limits.get(policy.name, 8),
            include_framework=False,
        )
        if open_backlog:
            lines.extend([
                "",
                "## Active issue backlog",
                open_backlog,
            ])
        recent_feedback = self._clip_prompt_section(
            review_state.format_recent_feedback(last_n=1),
            max_chars=5000,
        )
        if recent_feedback:
            lines.extend([
                "",
                "## 近期全局评审反馈",
                recent_feedback,
            ])
        failed_results = review_state.get_failed_results(
            current_results=self._list_result_files(ctx.results_dir or os.path.join(ctx.working_dir, "results"))
        )
        if failed_results:
            lines.extend([
                "",
                "## 当前未通过结果",
                *[f"- {item.filename}: {item.reason.strip()[:400]}" for item in failed_results],
            ])
        if ctx.review_mode == "closure":
            lines.extend([
                "",
                "## Closure 输出边界",
                "- 优先修复 summary.md、previous_limitations.md、supporting_docs/ 与正式结果的一致性。",
                "- 若结果评审已经通过，不要为了整理 summary 重新编号、删除或重写已通过的 result_NNN.md。",
            ])
        return "\n".join(lines)

    @staticmethod
    def _sync_result_relations_manifest(ctx: WorkflowContext) -> None:
        if not ctx.results_dir:
            return
        sync_result_relations_manifest(
            working_dir=ctx.working_dir,
            results_dir=ctx.results_dir,
            summary_file=ctx.summary_file,
        )
        sync_structured_result_manifests(
            working_dir=ctx.working_dir,
            results_dir=ctx.results_dir,
            summary_file=ctx.summary_file,
            task_file=ctx.task_file,
            supporting_docs_dir=WorkerExecutor._supporting_docs_dir(ctx.working_dir),
        )
