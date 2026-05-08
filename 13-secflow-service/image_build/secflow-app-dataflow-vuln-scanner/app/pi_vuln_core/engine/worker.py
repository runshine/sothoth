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
from pathlib import Path
from typing import Any, Optional

from app.pi_vuln_core.agents.models import AgentResponse
from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.config.models import AtomicWorkflowDef
from app.pi_vuln_core.engine.checkpoint import record_step_checkpoint
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
    coverage_ledger_path,
    extract_result_number,
    format_coverage_obligation_summary,
    infer_result_lifecycle_from_text,
    is_result_report_filename,
    list_result_report_files,
    list_supporting_markdown_files,
    sync_structured_result_manifests,
    sync_result_relations_manifest,
)
from app.pi_vuln_core.utils.template import TemplateRenderError, render_string
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
            step_key="worker",
            status="started",
            agent_id=worker_cfg.agent_id,
            session_id=session_id,
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
                    step_key="worker",
                    status="partial_salvaged",
                    agent_id=worker_cfg.agent_id,
                    session_id=session_id,
                    detail=error,
                    extra={"turn_count": response.turn_count},
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
                step_key="worker",
                status="failed",
                agent_id=worker_cfg.agent_id,
                session_id=session_id,
                detail=error,
                extra={"turn_count": response.turn_count},
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
            step_key="worker",
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

        return {
            "max_internal_turns": 0,
            "rpc_stdout_trace_bytes": configured_int(
                "reflection_rpc_stdout_trace_bytes",
                policy.reflection_rpc_stdout_trace_bytes,
            ),
            "rpc_stdout_abort_bytes": configured_int(
                "reflection_rpc_stdout_abort_bytes",
                policy.reflection_rpc_stdout_abort_bytes,
                floor=policy.reflection_rpc_stdout_abort_bytes,
            ),
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
        """Generate stable result/coverage ledgers before the Worker prompt.

        This makes profile gates visible from cycle 1 instead of only after the
        summary/review phases have already discovered missing obligations.
        """
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
        """Build the effective Worker system prompt with profile-owned scope.

        The prompt file intentionally contains only the stable role/contract.
        The breadth/depth checklist is injected here so fast/balanced/audit do
        not all receive the same unbounded audit instructions.
        """
        base = read_file(system_prompt_file).rstrip()
        dynamic_sections = [
            self._format_profile_worker_scope(ctx),
            self._result_report_template(compact=True),
        ]
        return base + "\n\n" + "\n\n".join(
            section for section in dynamic_sections if section.strip()
        ).rstrip() + "\n"

    @staticmethod
    def _result_report_template(*, compact: bool = False) -> str:
        if compact:
            return "\n".join([
                "## result_NNN.md 强制结构摘要",
                "- 每个 result 只描述一个独立漏洞疑点；无源码证据不得写入 results/。",
                "- 必须包含：疑点元信息、数据流绑定、受控输入、源码证据、触发条件、校验/绕过分析、影响、修复建议、关联 obligation/issue。",
                "- 若为补充/修正报告，文件开头必须写 `- **原始报告**: result_NNN.md` 与 `- **本报告性质**: 补充分析/修正`。",
            ])
        return "\n".join([
            "## result_NNN.md 强制模板（按疑点上报字段组织）",
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
            "- **coverage_obligation_id**: <INPUT/EXPORT/USED/CLEANED/STAR obligation id；未知需说明>",
            "- **data_flow_kind**: INPUT / EXPORT / USED / CLEANED / STAR",
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
            "- **metadata.review_profile**: <fast/balanced/audit>",
            "- **metadata.related_issue_ids**: <全局评审 issue id；没有写 []>",
            "- **metadata.related_results**: <补充/修正关系；没有写 []>",
            "```",
        ])

    @staticmethod
    def _format_profile_worker_scope(ctx: WorkflowContext) -> str:
        policy = get_review_profile_policy(ctx.review_profile)
        common = [
            "## 当前 review_profile 下的 Worker 初始挖掘范围（框架动态裁剪）",
            f"- profile: `{policy.name}`",
            "- 本任务是 data-flow driven vulnerability hunting，不是无边界全源码审计。",
            "- 所有正式漏洞报告、补扫记录和返工动作都必须能回链到数据流文件中的 INPUT / EXPORT / USED / CLEANED / ★，或其直接上下游源码证据。",
        ]
        if policy.name == "fast":
            lanes = [
                "只审计主 INPUT、★ 关键发现、最直接的高风险 USED/EXPORT。",
                "漏洞模式裁剪为显性内存安全、整数安全、输入校验缺失和明显 DoS。",
                "不要求低风险 EXPORT 穷尽；未覆盖项在 supporting_docs/ 中记录 residual 即可。",
                "不要为满足产物数量创建低置信 result。",
            ]
        elif policy.name == "balanced":
            lanes = [
                "优先闭环所有 INPUT、★、critical/high 风险 EXPORT/USED/CLEANED。",
                "漏洞模式覆盖 memory_safety、integer_safety、input_validation；对路径相关的 logic_state/resource_lifetime 做定向扫描。",
                "EXPORT 跟入到 sink 或可信边界；源码缺失时记录 accepted_residual/external_blocked，不无限追外部依赖。",
                "低风险、与数据流主轴弱相关的全源码探索不得阻塞本轮。",
            ]
        else:
            lanes = [
                "审计档需要尽量闭环全部 INPUT/EXPORT/USED/CLEANED/★ obligations。",
                "漏洞模式完整覆盖 memory_safety、integer_safety、input_validation、logic_state、resource_lifetime、concurrency_timing、resource_exhaustion、information_disclosure。",
                "对关键校验做边界值、符号混用、整数截断/溢出、TOCTOU、错误处理分支和对称路径分析。",
                "无法闭环的外部源码/上下文必须写 accepted_residual/external_blocked，并给出人工验收条件。",
            ]
        return "\n".join(common + [f"- {item}" for item in lanes])

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
        return render_string(
            base_prompt,
            strict=True,
            cycle=str(ctx.cycle),
            review_mode=ctx.review_mode,
            task=self._read_task_content(ctx.task_file),
            task_file=ctx.task_file,
            working_dir=ctx.working_dir,
            summary_file=ctx.summary_file or os.path.join(ctx.working_dir, "summary.md"),
            previous_limitations_file=os.path.join(ctx.working_dir, "previous_limitations.md"),
            results_dir=ctx.results_dir or os.path.join(ctx.working_dir, "results"),
            supporting_docs_dir=self._supporting_docs_dir(ctx.working_dir),
            output_contract_text=self._build_worker_output_contract_text(ctx),
            worker_runtime_context=self._build_initial_worker_context(
                ctx=ctx,
                review_state=review_state,
                current_result_files=current_result_files,
            ),
            result_report_template=self._result_report_template(),
        )

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
            or self._has_summary_or_ledger_rework(ctx, review_state)
        )

    @staticmethod
    def _read_task_content(task_file: str) -> str:
        try:
            return read_file(task_file)
        except Exception as exc:
            return f"(任务文件读取失败: {exc})"

    @staticmethod
    def _has_summary_or_ledger_rework(
        ctx: WorkflowContext,
        review_state: ReviewState,
    ) -> bool:
        recent_issues = review_state.get_recent_issues(last_n=2)
        if any(
            str(issue.get("actionable_by") or issue.get("owner") or "").strip().lower() == "framework"
            for issue in recent_issues
        ):
            return False
        if "summary/ledger" in (ctx.plateau_reason or ""):
            return True

        summary_owners = {"report", "summary", "ledger"}
        summary_categories = {
            "report_completeness",
            "limitations_honesty",
            "summary",
            "ledger",
            "metadata",
            "metadata_sync",
        }
        has_summary_issue = False
        for issue in recent_issues:
            owner = str(issue.get("actionable_by") or issue.get("owner") or "").strip().lower()
            category = str(issue.get("category") or "").strip().lower()
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
        return "\n".join([
            f"- summary.md: `{contract['summary_file']}`",
            f"- results/: `{contract['results_dir']}`",
            f"- supporting_docs/: `{contract['supporting_docs_dir']}`",
            f"- previous_limitations.md: `{contract['previous_limitations_file']}`",
            "- 结果文件命名：`result_NNN.md`",
        ])

    def _build_worker_output_contract_text(self, ctx: WorkflowContext) -> str:
        contract = self._build_worker_output_contract(ctx)
        return "\n".join([
            f"- results/: `{contract['results_dir']}`",
            f"- supporting_docs/: `{contract['supporting_docs_dir']}`",
            "- 结果文件命名：`result_NNN.md`",
            f"- `summary.md` 将在后续显式 summary 阶段统一整理到 `{contract['deferred_summary_file']}`",
            f"- `previous_limitations.md` 将在后续显式 summary 阶段从 summary 第 7 节同步到 `{contract['deferred_previous_limitations_file']}`",
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
            f"- Review profile：{ctx.review_profile}",
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
    ) -> str:
        previous_limitations_file = os.path.join(ctx.working_dir, "previous_limitations.md")
        lines = [
            "## 当前执行上下文",
            f"- 当前轮次：{ctx.cycle}",
            f"- 工作模式：{ctx.review_mode or review_state.workflow_mode}",
            f"- Review profile：{ctx.review_profile}",
            f"- 任务文件: `{ctx.task_file}`",
            f"- 工作目录: `{ctx.working_dir}`",
            f"- 本阶段正式结果目录: `{ctx.results_dir or os.path.join(ctx.working_dir, 'results')}`",
            f"- 本阶段辅助文档目录: `{self._supporting_docs_dir(ctx.working_dir)}`",
            f"- 后续 summary 阶段整理的总结报告: `{ctx.summary_file or os.path.join(ctx.working_dir, 'summary.md')}`",
            f"- 后续 summary 阶段同步的局限性记录: `{previous_limitations_file}`",
            "",
            self._format_profile_execution_context(ctx),
            "",
            self._format_profile_worker_scope(ctx),
        ]
        coverage_context = self._format_coverage_obligation_context(ctx)
        if coverage_context:
            lines.extend(["", coverage_context])
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

        lines.extend([
            "",
            "## 本阶段输出位置 contract",
            self._build_worker_output_contract_text(ctx),
        ])
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
        sections = self._build_rework_prompt_sections(ctx, review_state)
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
                return render_string(template, strict=True, **sections)

        return self._build_legacy_rework_prompt(sections)

    def _build_rework_prompt_sections(
        self,
        ctx: WorkflowContext,
        review_state: ReviewState,
    ) -> dict[str, Any]:
        """Build dynamic sections shared by file-based and fallback rework prompts."""
        is_closure = (ctx.review_mode == "closure" or review_state.workflow_mode == "closure")
        summary_or_ledger_rework = self._has_summary_or_ledger_rework(ctx, review_state)
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
            (is_closure or summary_or_ledger_rework)
            and not failed_files
            and summary_or_ledger_rework
        )
        result_repair_only = bool(failed_files)
        repeated_issue_summary = review_state.format_issue_ledger_summary(
            min_consecutive=2,
            max_items=5,
        )

        global_review_feedback = ""
        if review_state.last_global_feedback:
            global_review_feedback = "\n".join([
                "## 全局评审反馈",
                self._clip_prompt_section(review_state.last_global_feedback, max_chars=6000),
            ])

        repeated_issue_summary_text = ""
        if repeated_issue_summary:
            repeated_issue_summary_text = "\n".join([
                "## 重复阻塞项 ledger",
                repeated_issue_summary,
            ])

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

        if summary_repair_only:
            policy = get_review_profile_policy(ctx.review_profile)
            summary_repair_limits = {"fast": 6, "balanced": 12, "strict": 20, "audit": 32}
            coverage_max_open = summary_repair_limits.get(policy.name, 12)
        else:
            coverage_max_open = None
        coverage_context = self._format_coverage_obligation_context(ctx, max_open=coverage_max_open)

        failed_result_reasons = ""
        if failed_files:
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

        numbering_rules = self._build_summary_rework_rules(ctx)
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
        issue_closure_template = self._build_issue_closure_template(
            ctx=ctx,
            review_state=review_state,
            issue_closure_file=issue_closure_file,
        )
        return {
            "cycle": str(ctx.cycle),
            "review_mode": ctx.review_mode or review_state.workflow_mode,
            "task": self._read_task_content(ctx.task_file),
            "task_file": ctx.task_file,
            "working_dir": ctx.working_dir,
            "summary_file": summary_file,
            "previous_limitations_file": previous_limitations_file,
            "results_dir": results_dir,
            "supporting_docs_dir": supporting_docs_dir,
            "rework_recovery_context": self._build_rework_recovery_context(ctx, review_state),
            "review_delta_text": self._build_review_delta_text(
                ctx=ctx,
                review_state=review_state,
                current_result_files=ctx.pre_cycle_result_files,
                include_recent_feedback=False,
            ).rstrip(),
            "global_review_feedback": global_review_feedback,
            "repeated_issue_summary": repeated_issue_summary_text,
            "active_issue_backlog": active_issue_backlog,
            "coverage_context": coverage_context,
            "failed_result_reasons": failed_result_reasons,
            "output_contract_text": self._build_worker_output_contract_text(ctx),
            "result_report_template": self._result_report_template(),
            "issue_closure_file": issue_closure_file,
            "issue_closure_template": issue_closure_template,
            "rework_scope_policy": self._build_rework_scope_policy(
                summary_repair_only=summary_repair_only,
                result_repair_only=result_repair_only,
                is_closure=is_closure,
            ),
            "numbering_rules": numbering_rules,
            "convergence_requirements": convergence_requirements,
            "direct_read_instruction": (
                "直接使用 read 工具读取需要的文件，不要要求框架重复粘贴全文。"
            ),
        }

    @staticmethod
    def _build_rework_scope_policy(
        *,
        summary_repair_only: bool,
        result_repair_only: bool,
        is_closure: bool,
    ) -> str:
        lines = [
            "## 返工范围硬约束",
            "- 返工不是重新漏洞挖掘，而是基于 data-flow obligation、failed result 与 active issue 的定向闭环。",
            "- 本轮新增探索必须至少命中以下一项：active issue、coverage ledger open obligation、failed result 补证/撤回、previous limitations residual 验证。",
            "- 脱离 INPUT / EXPORT / USED / CLEANED / ★ 主轴的全源码发散不得写入正式结果。",
        ]
        if summary_repair_only:
            lines.extend([
                "- 本轮只修复 `summary.md`、`previous_limitations.md`、`supporting_docs/` 与覆盖/issue 映射说明。",
                "- 禁止新增、删除、重写、重新编号 results/result_NNN.md。",
            ])
        elif result_repair_only:
            lines.extend([
                "- 当前为结果修复：只处理失败 result 及其直接相关源码路径。",
                "- 新增 result 只能用于拆分独立真实漏洞或补充已证实的更高编号修正报告。",
            ])
        elif is_closure:
            lines.extend([
                "- 当前为 closure：优先关闭 active issue backlog 与 high/STAR open obligations。",
                "- 若源码/外部依赖缺失，写 accepted_residual/external_blocked 与人工验收条件，不要反复写继续分析。",
            ])
        else:
            lines.append("- discovery 返工只围绕评审反馈定向扩展，不重新全量重扫。")
        return "\n".join(lines)

    @staticmethod
    def _build_issue_closure_template(
        *,
        ctx: WorkflowContext,
        review_state: ReviewState,
        issue_closure_file: str,
    ) -> str:
        open_backlog = review_state.get_active_issue_entries()
        issue_lines = []
        for item in open_backlog[:20]:
            issue_id = str(getattr(item, "issue_id", "") or getattr(item, "id", "") or "").strip()
            target = ""
            issue = getattr(item, "issue", None)
            if isinstance(issue, dict):
                issue_id = issue_id or str(issue.get("id") or "").strip()
                target = str(issue.get("target") or "").strip()
            if issue_id:
                issue_lines.append(f"| {issue_id} | {target} |  |  |  |  |")
        if not issue_lines:
            issue_lines.append("| <issue_id 或 obligation_id> | <目标> | <source_closed/promoted_to_result/accepted_residual/unused/not_applicable/external_blocked> | <本轮动作> | <results/... 或 supporting_docs/...> | <剩余限制> |")
        return "\n".join([
            "## issue closure 记录要求",
            f"本轮必须创建或更新：`{issue_closure_file}`",
            "",
            "建议内容模板：",
            "",
            "```markdown",
            f"# Issue Closure Cycle {ctx.cycle:03d}",
            "",
            "| issue_id / obligation_id | target | status | action | evidence | residual/限制 |",
            "|---|---|---|---|---|---|",
            *issue_lines,
            "```",
            "",
            "status 只能使用：source_closed / promoted_to_result / accepted_residual / unused / not_applicable / external_blocked。",
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
            lines.append("- 本轮只修复 `summary.md`、`previous_limitations.md`、`supporting_docs/` 与 summary 阶段可影响的结果映射/覆盖账本一致性。")
            lines.append("- 不要新增、删除、重写或重新编号 `results/result_NNN.md`；结果评审已经通过。")
            lines.append("- 不要手工编辑 `_meta/` 下的框架生成文件；只修正正式文档，让框架在 summary 后重新同步 manifest/ledger。")
        elif result_repair_only:
            lines.append("- 本轮只聚焦**修复/删除未通过结果**，不要继续扩张攻击面。")
        elif is_closure:
            lines.append("- 当前已经进入 **closure（收敛）模式**。")
            lines.append("- 优先关闭近期全局评审反馈指出的问题，不要继续扩张攻击面。")
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
            sections["rework_recovery_context"],
            "",
            sections["review_delta_text"],
        ]
        for key in (
            "global_review_feedback",
            "repeated_issue_summary",
            "active_issue_backlog",
            "coverage_context",
            "failed_result_reasons",
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
        issue_ledger_file = os.path.join(ctx.working_dir, "_meta", "issue_ledger.json")
        coverage_file = coverage_ledger_path(ctx.working_dir)
        supporting_docs = list_supporting_markdown_files(supporting_docs_dir)
        result_files = ctx.pre_cycle_result_files or self._list_result_files(results_dir)

        lines = [
            "## 返工上下文恢复包",
            f"- 当前轮次：{ctx.cycle}",
            f"- 工作模式：{ctx.review_mode or review_state.workflow_mode}",
            f"- Review profile：{ctx.review_profile}",
            f"- 任务文件: `{ctx.task_file}`",
            f"- 工作目录: `{ctx.working_dir}`",
            f"- summary: `{summary_path}`",
            f"- results_dir: `{results_dir}`",
            f"- supporting_docs_dir: `{supporting_docs_dir}`",
            f"- previous_limitations: `{previous_limitations_file}`",
            f"- issue ledger: `{issue_ledger_file}`",
            f"- coverage ledger: `{coverage_file}`",
            "",
            "### 开始前必须读取",
            f"- `{ctx.task_file}`",
        ]
        for candidate in (summary_path, previous_limitations_file, str(coverage_file), issue_ledger_file):
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
            "- 先关闭 active issue backlog 与 coverage ledger 的 open obligations；不要只处理最近一条自然语言反馈。",
            "- 对每个阻塞项必须给出 `source_closed`、`promoted_to_result`、`accepted_residual`、`unused/not_applicable` 之一的明确状态。",
            "- 若受外部源码/上下文限制不可闭环，写入 supporting_docs 并在 summary 局限性章节保留 residual，不要反复写“继续分析”。",
        ])
        return "\n".join(lines)

    @staticmethod
    def _format_profile_execution_context(ctx: WorkflowContext) -> str:
        policy = get_review_profile_policy(ctx.review_profile)
        lines = [
            "## Profile 执行预算与深度目标",
            "- 单轮 Worker 内部 turn 硬上限: 不限制",
            f"- 每轮反思 pass: {policy.reflection_passes_per_cycle}",
            "- 单次反思内部 turn 硬上限: 不限制",
            "- Pi/provider timeout: 仅依赖 Pi 原生 timeout；不再使用档位级 no-progress / wall-clock watchdog",
            f"- 最少探索轮次: {policy.min_discovery_cycles_before_pass}",
            f"- 最少证据产物数: {policy.min_evidence_artifacts}",
            (
                "- 必须覆盖漏洞模式族: "
                + (
                    ", ".join(policy.required_pattern_families)
                    if policy.required_pattern_families else
                    "(none)"
                )
            ),
            f"- 本档挖掘目标: {policy.execution_goal}",
            "- 本档深挖路线:",
        ]
        lines.extend(f"  - {lane}" for lane in policy.depth_lanes)
        lines.extend([
            (
                "- 如果本轮没有新增高置信漏洞，必须在 `supporting_docs/` 中留下 "
                "`source_closed` / `accepted_residual` / `not_applicable` 等可评审证据，"
                "不要只写“继续分析”。"
            ),
            "- 使用 `rg` 先定位，再用小窗口 `read` 跟入；避免无边界读取整文件造成单轮膨胀。",
        ])
        return "\n".join(lines)

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

    def _format_coverage_obligation_context(self, ctx: WorkflowContext, *, max_open: int | None = None) -> str:
        policy = get_review_profile_policy(ctx.review_profile)
        max_open = (
            int(max_open)
            if max_open is not None else
            policy.max_open_obligations_in_worker_prompt
        )
        ledger_file = coverage_ledger_path(ctx.working_dir)
        if not ledger_file.is_file():
            return (
                "## Coverage obligation ledger\n"
                f"- 尚未生成 `{ledger_file}`；本轮 summary 后框架会根据 task/data-flow 与正式产物同步。"
            )
        try:
            ledger = read_json(ledger_file)
        except Exception as exc:
            return f"## Coverage obligation ledger\n- 读取 `{ledger_file}` 失败：{exc}"
        return format_coverage_obligation_summary(ledger, max_open=max_open)

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
            name for name in review_state.get_passed_result_filenames(current_results=pre_cycle_files)
            if name in pre_cycle_set and name in active_passed_results
        )
        snapshots: dict[str, str] = {}
        for name in protected_files:
            path = os.path.join(results_dir, name)
            try:
                snapshots[name] = read_file(path)
            except FileNotFoundError:
                continue

        failed_snapshots: dict[str, str] = {}
        failed_reasons: dict[str, str] = {}
        for item in review_state.get_failed_results():
            name = item.filename
            if name not in pre_cycle_set:
                continue
            path = os.path.join(results_dir, name)
            try:
                failed_snapshots[name] = read_file(path)
                failed_reasons[name] = item.reason
            except FileNotFoundError:
                continue

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

        lines = [
            "## 返工轮文件稳定性规则(本阶段必须严格遵守)",
            "",
            "- 不允许为了\u201c整理\u201d或\u201c精简\u201d而给已有漏洞报告重新编号。",
            "- 不允许把新漏洞写到任何历史编号上，也不允许覆盖已通过评审的报告。",
        ]

        if ctx.protected_result_files:
            lines.extend([
                "",
                "### 已通过评审、受保护的结果文件(禁止修改 / 覆盖 / 重命名)",
            ])
            lines.extend(f"- {name}" for name in ctx.protected_result_files)

        if mutable_files:
            lines.extend([
                "",
                "### 可修改或删除的已有结果文件(如需修正，只能沿用原编号)",
            ])
            lines.extend(f"- {name}" for name in mutable_files)

        lines.extend([
            "",
            "### 新增漏洞报告编号起点",
            f"- 本轮任何新增漏洞报告必须从 `result_{ctx.next_result_number:03d}.md` 开始顺延编号。",
            "- 即使旧报告已删除，其历史编号也不得复用。",
            "- 如果你发现某个已通过评审的报告需要补充，请保留原文件不动，新增一个更高编号的补充报告。",
            "- 若新增的是补充/修正报告，请在文件开头显式写出 `- **原始报告**: result_NNN.md` 与 `- **本报告性质**: 补充分析/修正`，便于框架建立结果关系。",
        ])

        lines.extend([
            "",
            "### 结果粒度要求",
            "- 每个 `results/result_NNN.md` 只能描述一个独立漏洞问题。",
            "- 如果你发现多个独立漏洞，必须拆成多个 result 文件；不要把多个 `VULN-*` 塞进同一份报告。",
            "",
            "### 辅助审计文档位置",
            f"- 像 `USED_ENDPOINTS.md`、`REMOVED.md`、覆盖矩阵、附录等辅助文档，请写到 `{self._supporting_docs_dir(ctx.working_dir)}/`。",
            "- `results/` 目录只保留 `result_NNN.md`；不要把辅助文档混进结果目录。",
        ])

        if ctx.review_mode == "closure":
            lines.extend([
                "",
                "### Closure 模式附加规则",
                "- 当前处于收敛阶段：禁止为了“继续扩展攻击面”而批量新增结果或重新铺开全量重扫。",
                "- 仅允许新增那些**直接回应近期评审问题** 的报告。",
                "- 若需要记录某个新增/删除结果回应了哪个评审问题，请优先写入 `supporting_docs/`；后续显式 summary 阶段会统一整理到 `summary.md`。",
            ])
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
        if ctx.cycle <= 1 or not ctx.results_dir or not ctx.failed_result_snapshots:
            return []

        results_dir = Path(ctx.results_dir)
        backup_root = Path(ctx.working_dir) / "removed_results" / f"cycle_{ctx.cycle:03d}"
        removed: list[str] = []

        for name in sorted(ctx.failed_result_snapshots):
            result_path = results_dir / name
            if not result_path.is_file():
                continue

            current_content = result_path.read_text(encoding="utf-8", errors="replace")
            if not self._is_explicitly_withdrawn_result(current_content):
                continue

            backup_root.mkdir(parents=True, exist_ok=True)
            backup_md = backup_root / name
            backup_meta = backup_root / f"{Path(name).stem}.json"

            backup_md.write_text(current_content, encoding="utf-8")
            write_json(
                backup_meta,
                {
                    "workflow_id": ctx.workflow_id,
                    "task_id": ctx.task_id,
                    "removed_in_cycle": ctx.cycle,
                    "lifecycle_status": infer_result_lifecycle_from_text(
                        current_content,
                        name,
                    ).get("status", "withdrawn"),
                    "original_filename": name,
                    "original_path": str(result_path),
                    "backup_path": str(backup_md),
                    "reason": ctx.failed_result_reasons.get(name)
                    or "结果文件已显式撤回；框架在 summary 后自动迁移出 results/。",
                },
            )
            result_path.unlink()
            removed.append(name)

        if removed:
            logger.info(
                "withdrawn_failed_results_auto_removed",
                workflow_id=ctx.workflow_id,
                task_id=ctx.task_id,
                cycle=ctx.cycle,
                count=len(removed),
                files=removed,
                backup_dir=str(backup_root),
            )

        return removed

    def _relocate_inactive_result_files(self, ctx: WorkflowContext) -> list[str]:
        if not ctx.results_dir or not os.path.isdir(ctx.results_dir):
            return []

        results_dir = Path(ctx.results_dir)
        removed_root = Path(ctx.working_dir) / "removed_results" / f"cycle_{ctx.cycle:03d}"
        supporting_docs_dir = Path(self._supporting_docs_dir(ctx.working_dir))
        moved: list[str] = []

        for name in list_result_report_files(results_dir):
            path = results_dir / name
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except FileNotFoundError:
                continue
            lifecycle = infer_result_lifecycle_from_text(content, name)
            if bool(lifecycle.get("active", True)):
                continue

            bucket = str(lifecycle.get("delivery_bucket") or "removed_results")
            if bucket == "supporting_docs":
                supporting_docs_dir.mkdir(parents=True, exist_ok=True)
                dst = supporting_docs_dir / name
                if dst.exists() and dst.is_file():
                    dst.unlink()
                path.replace(dst)
                moved.append(f"{name}->supporting_docs/{name}")
                continue

            removed_root.mkdir(parents=True, exist_ok=True)
            backup_md = removed_root / name
            backup_meta = removed_root / f"{Path(name).stem}.json"
            if backup_md.exists():
                backup_md.unlink()
            path.replace(backup_md)
            write_json(
                backup_meta,
                {
                    "workflow_id": ctx.workflow_id,
                    "task_id": ctx.task_id,
                    "removed_in_cycle": ctx.cycle,
                    "original_filename": name,
                    "original_path": str(path),
                    "backup_path": str(backup_md),
                    "lifecycle_status": lifecycle.get("status", "inactive"),
                    "signals": lifecycle.get("signals", []),
                    "reason": "结果文件生命周期不是 active；框架自动迁移出 results/。",
                },
            )
            moved.append(f"{name}->removed_results/{backup_md.parent.name}/{name}")

        if moved:
            logger.warning(
                "inactive_result_files_relocated",
                workflow_id=ctx.workflow_id,
                task_id=ctx.task_id,
                cycle=ctx.cycle,
                files=moved,
            )
        return moved

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
        reflection_runtime_context = (
            f"当前轮次：第 {ctx.cycle} 轮，"
            f"工作模式：{ctx.review_mode or reflection_state.workflow_mode}，"
            f"review_profile：{ctx.review_profile}，"
            f"profile_goal：{policy.execution_goal}"
        )
        reflection_runtime_limits = self._effective_reflection_runtime_limits(wf_def, ctx)
        reflection_scope = self._build_reflection_scope(ctx, review_state)
        reflection_checklist = self._build_reflection_checklist(ctx, review_state, prompts_dir=prompts_dir)

        expanded_prompts = [
            (pass_index, reflect_cfg)
            for pass_index in range(1, reflection_passes + 1)
            for reflect_cfg in reflection_prompts
        ]
        for i, (pass_index, reflect_cfg) in enumerate(expanded_prompts):
            prompt = read_file(reflect_cfg.prompt_file)
            try:
                prompt = render_string(
                    prompt,
                    strict=True,
                    cycle=str(ctx.cycle),
                    review_mode=ctx.review_mode,
                    task=self._read_task_content(ctx.task_file),
                    task_file=ctx.task_file,
                    working_dir=ctx.working_dir,
                    summary_file=ctx.summary_file or os.path.join(ctx.working_dir, "summary.md"),
                    results_dir=ctx.results_dir or os.path.join(ctx.working_dir, "results"),
                    supporting_docs_dir=self._supporting_docs_dir(ctx.working_dir),
                    previous_limitations_file=os.path.join(ctx.working_dir, "previous_limitations.md"),
                    reflection_runtime_context=(
                        f"{reflection_runtime_context}，"
                        f"reflection_pass={pass_index}/{reflection_passes}"
                    ),
                    reflection_scope=reflection_scope,
                    reflection_checklist=reflection_checklist,
                )
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
                step_key=f"reflect::{reflect_cfg.id}::pass_{pass_index:02d}",
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
                    step_key=f"reflect::{reflect_cfg.id}::pass_{pass_index:02d}",
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
                step_key=f"reflect::{reflect_cfg.id}::pass_{pass_index:02d}",
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

        prompt = read_file(summary_cfg.prompt_file)
        summary_state = review_state or ReviewState()
        summary_state.workflow_mode = ctx.review_mode
        summary_runtime_context = "\n".join([
            f"- 当前轮次：第 {ctx.cycle} 轮",
            f"- 工作模式：{ctx.review_mode or summary_state.workflow_mode}",
            f"- Review profile：{ctx.review_profile}",
            f"- 任务文件: `{ctx.task_file}`",
            f"- 工作目录: `{ctx.working_dir}`",
            f"- coverage ledger: `{coverage_ledger_path(ctx.working_dir)}`",
            f"- issue ledger: `{os.path.join(ctx.working_dir, '_meta', 'issue_ledger.json')}`",
            "",
            "### Summary 阶段开始前必须读取",
            f"- `{ctx.task_file}`",
            f"- `{coverage_ledger_path(ctx.working_dir)}`（若存在）",
            f"- `{os.path.join(ctx.working_dir, '_meta', 'issue_ledger.json')}`（若存在）",
            f"- `{os.path.join(ctx.working_dir, 'previous_limitations.md')}`（若存在）",
            f"- `{summary_path}`（若存在）",
            f"- `{results_dir}` 下当前所有 `result_NNN.md`",
            f"- `{supporting_docs_dir}` 下当前所有辅助审计文档",
        ])
        try:
            prompt = render_string(
                prompt,
                strict=True,
                cycle=str(ctx.cycle),
                review_mode=ctx.review_mode,
                task=self._read_task_content(ctx.task_file),
                task_file=ctx.task_file,
                working_dir=ctx.working_dir,
                summary_file=summary_path,
                summary_path=summary_path,
                results_dir=results_dir,
                supporting_docs_dir=supporting_docs_dir,
                previous_limitations_file=os.path.join(ctx.working_dir, "previous_limitations.md"),
                summary_runtime_context=summary_runtime_context,
                summary_rework_rules=self._build_summary_rework_rules(ctx) or "(本轮无额外返工规则)",
                summary_feedback_context=self._build_summary_feedback_context(ctx, summary_state),
                output_contract_text=self._build_output_contract_text(ctx),
            )
        except TemplateRenderError as exc:
            raise WorkerStageError("summary", f"Summary prompt 渲染失败：{exc}") from exc

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

    def _build_summary_feedback_context(
        self,
        ctx: WorkflowContext,
        review_state: ReviewState,
    ) -> str:
        lines = [
            f"- 当前轮次：{ctx.cycle}",
            f"- 当前工作模式：{ctx.review_mode or review_state.workflow_mode}",
            f"- Review profile：{ctx.review_profile}",
        ]
        lines.extend(["", format_review_profile_policy(ctx.review_profile)])
        if ctx.plateau_reason:
            lines.append(f"- 收敛/返工原因：{ctx.plateau_reason}")
        repeated_issue_summary = review_state.format_issue_ledger_summary(
            min_consecutive=2,
            max_items=5,
        )
        if repeated_issue_summary:
            lines.extend([
                "",
                "## 重复阻塞项 ledger",
                repeated_issue_summary,
                "",
                "## Residual 同步要求",
                "- 若 Worker 已将重复阻塞项判定为 `accepted_residual`，summary.md 的“局限性与未覆盖区域”必须保留该 residual 的原因、证据边界和人工验收条件。",
                "- 若已闭环，summary.md 必须说明闭环依据，不要静默删除上一轮局限性。",
            ])
        policy = get_review_profile_policy(ctx.review_profile)
        summary_backlog_limits = {"fast": 4, "balanced": 8, "strict": 12, "audit": 16}
        summary_coverage_limits = {"fast": 8, "balanced": 18, "strict": 30, "audit": 50}
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
        coverage_context = self._format_coverage_obligation_context(
            ctx,
            max_open=summary_coverage_limits.get(policy.name, 18),
        )
        if coverage_context:
            lines.extend([
                "",
                coverage_context,
                "",
                "## Coverage ledger 同步要求",
                "- summary.md 必须包含一张 coverage closure matrix，对 coverage ledger 中的 INPUT/EXPORT/USED/CLEANED/STAR obligations 给出 status 与 evidence。",
                "- status 只能使用：`source_closed`、`promoted_to_result`、`accepted_residual`、`unused`、`not_applicable`、`external_blocked`。",
                "- 对 open obligation，必须在 summary 或 supporting_docs 中写明闭环证据、residual 原因或不可适用理由；不要只写泛化类别。",
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
                "- 优先修复 summary.md、previous_limitations.md、supporting_docs/ 与 manifest/ledger 的一致性。",
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
