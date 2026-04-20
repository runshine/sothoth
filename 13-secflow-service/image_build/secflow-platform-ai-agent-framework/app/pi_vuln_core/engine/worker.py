"""
Worker 执行器

负责原子工作流中的：
- Worker 执行阶段 (R6c)
- 自我反思阶段 (R6d)
- 总结阶段 (R6e)
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.config.models import AtomicWorkflowDef
from app.pi_vuln_core.engine.models import WorkflowContext
from app.pi_vuln_core.recorder.recorder import ExecutionRecorder
from app.pi_vuln_core.review.previous_limitations import (
    extract_markdown_section,
    is_substantive_limitations,
    load_previous_limitations,
)
from app.pi_vuln_core.review.state import ReviewState
from app.pi_vuln_core.utils.file_ops import read_file, write_json
from app.pi_vuln_core.utils.result_docs import (
    extract_result_number,
    is_result_report_filename,
    list_result_report_files,
    list_supporting_markdown_files,
)
from app.pi_vuln_core.utils.template import render_string
from app.pi_vuln_core.utils.logger import get_logger

logger = get_logger("worker_executor")


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
    ) -> None:
        """
        Worker 阶段 (R6c)

        调用 worker 智能体执行任务，直到完成。
        如果非首轮，prompt 中包含评审失败反馈。
        """
        worker_cfg = wf_def.roles.worker
        agent = self.agents.get(worker_cfg.agent_id)

        # 决定是否新建会话 (R12)
        if worker_cfg.new_session or ctx.cycle == 1:
            session_id = await agent.create_session()
            ctx.worker_session_id = session_id
        else:
            session_id = ctx.worker_session_id
            if session_id is None:
                session_id = await agent.create_session()
                ctx.worker_session_id = session_id

        # 构建 prompt
        system_prompt = read_file(worker_cfg.prompts.work.system_prompt_file)
        user_prompt = self._build_user_prompt(wf_def, ctx, review_state)

        max_turns = wf_def.engine.max_worker_turns_per_cycle

        logger.info("worker_execute_start",
                     workflow_id=ctx.workflow_id,
                     task_id=ctx.task_id,
                     cycle=ctx.cycle,
                     session_id=session_id)

        # 多轮执行
        response = await agent.multi_turn_execute(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            working_dir=ctx.working_dir,
            max_turns=max_turns,
            session_id=session_id,
        )

        self._relocate_misplaced_outputs(ctx, response.turn_count)

        if not response.success:
            logger.error("worker_execute_error",
                         error=response.error,
                         workflow_id=ctx.workflow_id)

        logger.info("worker_execute_done",
                     workflow_id=ctx.workflow_id,
                     turns=response.turn_count,
                     finished=response.finished)

    # ─────────────────────────────────────────────
    #  Prompt 构建
    # ─────────────────────────────────────────────

    def _build_user_prompt(
        self,
        wf_def: AtomicWorkflowDef,
        ctx: WorkflowContext,
        review_state: ReviewState,
    ) -> str:
        """构建 Worker 的 user prompt"""
        current_result_files = self._list_result_files(os.path.join(ctx.working_dir, "results"))

        # ═══ 首轮 或 无当前未解决失败：发送完整任务指令 ═══
        if ctx.cycle == 1 or not review_state.has_failures(
            current_results=current_result_files,
            actionable_by="worker",
        ):
            task_content = read_file(ctx.task_file)
            base_prompt = read_file(wf_def.roles.worker.prompts.work.user_prompt_file)
            return render_string(
                base_prompt,
                task=task_content,
                task_file=ctx.task_file,
                working_dir=ctx.working_dir,
                cycle=str(ctx.cycle),
                summary_path=os.path.join(ctx.working_dir, "summary.md"),
                results_dir=os.path.join(ctx.working_dir, "results"),
                supporting_docs_dir=self._supporting_docs_dir(ctx.working_dir),
            )

        # ═══ 评审返工轮：仅发送反馈 + 深挖指令（不重复完整任务） ═══
        self._prepare_rework_context(ctx, review_state)
        return self._build_rework_prompt(ctx, review_state)

    def _build_rework_prompt(
        self,
        ctx: WorkflowContext,
        review_state: ReviewState,
    ) -> str:
        """
        构建评审返工轮的 prompt (R6g)

        不重复发送原始任务指令（Worker 会话中已有完整上下文），
        仅发送：评审反馈 + 深挖新漏洞的督促 + 报告编号规则。
        """
        feedback = review_state.format_failure_feedback(
            current_results=ctx.pre_cycle_result_files,
            include_open_blockers=False,
            include_global_feedback_section=False,
        )
        previous_limitations = self._load_previous_limitations_from_current_summary(
            ctx.working_dir,
            ctx.cycle,
        )
        next_num = max(1, ctx.next_result_number)

        summary_path = os.path.join(ctx.working_dir, "summary.md")
        results_dir = os.path.join(ctx.working_dir, "results")
        supporting_docs_dir = self._supporting_docs_dir(ctx.working_dir)
        worker_blockers = review_state.get_open_blockers(
            limit=review_state.MAX_OPEN_BLOCKERS,
            actionable_by="worker",
        )
        protected_targets = set(ctx.protected_result_files or [])
        direct_worker_blockers: list = []
        protected_report_blockers: list = []
        for blocker in worker_blockers:
            target_text = f"{blocker.target}\n{blocker.required_action}\n{blocker.detail}".lower()
            if any(name.lower() in target_text for name in protected_targets):
                protected_report_blockers.append(blocker)
            else:
                direct_worker_blockers.append(blocker)

        open_blockers = (
            self._format_blocker_items(direct_worker_blockers)
            if direct_worker_blockers else
            "(当前无需要 Worker 直接修改产物的全局阻塞项)"
        )
        protected_report_blockers_text = ""
        if protected_report_blockers:
            protected_ids = {item.blocker_id for item in protected_report_blockers}
            protected_lines: list[str] = []
            for item in worker_blockers:
                if item.blocker_id not in protected_ids:
                    continue
                headline = f"- [{item.blocker_id}]"
                extras = [part for part in (item.category, item.target, item.severity) if part]
                if extras:
                    headline += " " + " / ".join(extras)
                protected_lines.append(headline)
                protected_lines.append(
                    "  - 处理规则: 该问题命中了已通过评审、受保护的结果文件；禁止直接改原文件。"
                )
                protected_lines.append(
                    "  - 允许动作: 仅可通过新增更高编号的补充报告、supporting_docs 说明或 summary 澄清来处理。"
                )
                if item.required_action:
                    protected_lines.append(f"  - required_action: {item.required_action}")
                if item.detail and item.detail != item.required_action:
                    protected_lines.append(f"  - detail: {item.detail}")
            protected_report_blockers_text = "\n".join(protected_lines)

        framework_blockers = review_state.get_open_blockers(
            limit=review_state.MAX_OPEN_BLOCKERS,
            actionable_by="framework",
        )
        is_closure = (ctx.review_mode == "closure" or review_state.workflow_mode == "closure")
        result_repair_only = not direct_worker_blockers and bool(ctx.failed_result_items)

        discovery_or_closure_rules = [
            "## 🔍 当前返工策略",
            "",
        ]
        if result_repair_only:
            discovery_or_closure_rules.extend([
                "当前没有需要 Worker 继续扩展的 blocker backlog。",
                "本轮只聚焦**修复/删除未通过结果**，不要继续扩张攻击面，也不要为了‘再找几个漏洞’而新增弱报告。",
                "若需补充说明，请优先写入 `supporting_docs/` 或在 `summary.md` 中澄清，而不是改动已通过报告。",
            ])
        elif is_closure:
            discovery_or_closure_rules.extend([
                "当前已经进入 **closure（收敛）模式**。本轮首要目标不是无限扩张结果，而是**关闭已有 blocker、修正弱报告、让 summary / results / 局限性章节收敛一致**。",
                "",
                "closure 模式硬规则：",
                "- **禁止无界扩张结果集**；除非为了关闭下方某个 blocker 所必需，否则不要新增新的扫描方向",
                "- 若确实需要新增报告，必须在 summary.md 中明确说明它对应关闭了哪个 blocker",
                "- 优先修 blocker backlog、修正/删除未通过结果、补齐局限性章节，避免再把 summary 越写越大",
                "- 不要重新全面铺开整个攻击面，除非 backlog 明确要求你这样做",
            ])
        else:
            discovery_or_closure_rules.extend([
                "当前仍处于 **discovery（扩展）模式**。你需要在修正评审问题的同时，继续补齐遗漏攻击面，但要围绕 blocker backlog 定向扩展，而不是无边界堆积内容。",
                "",
                "discovery 模式要求：",
                "- 优先处理 blocker backlog 中点名的缺口",
                "- 若发现新的高价值漏洞，可以新增报告，但必须与当前 blocker 或覆盖缺口直接相关",
                "- 不要为了“看起来覆盖更多”而复制性地产生弱报告或模板化分析",
            ])

        return "\n".join([
            f"# 第 {ctx.cycle} 轮评审返工",
            "",
            "你的上一轮分析已经过评审，以下是评审结果和反馈。",
            "",
            feedback,
            "",
            "## 🧱 当前未关闭的 Worker 可执行 blocker backlog（稳定 ID，不得静默删除）",
            "",
            open_blockers,
            "",
            *([
                "## 🔒 命中已冻结结果的 blocker（不可直接改原报告）",
                "",
                protected_report_blockers_text,
                "",
            ] if protected_report_blockers else []),
            (
                f"（另有 {len(framework_blockers)} 个 framework/reviewer 状态同步类 blocker "
                "不会下发给 Worker，避免让你处理无权修改的元数据文件。）"
                if framework_blockers else
                "（当前没有 framework-owned blocker 需要额外说明。）"
            ),
            "",
            *discovery_or_closure_rules,
            "",
            "## ⚠️ 上一轮 summary.md 的“局限性与未覆盖区域”（不得遗漏）",
            "",
            previous_limitations,
            "",
            "处理规则：如果上面某一项在本轮已经真正补分析并闭环，你必须在新的 summary.md 中明确说明它如何被解决；如果尚未解决，则必须继续保留在新的“局限性与未覆盖区域”章节中，**严禁静默删除、弱化或遗漏**。",
            "",
            "## 📁 输出位置（必须严格遵守）",
            "",
            f"- `summary.md` 的唯一正确路径：`{summary_path}`",
            f"- 所有漏洞报告的唯一正确目录：`{results_dir}/`",
            f"- 每个漏洞文件必须写到：`{results_dir}/result_NNN.md`",
            f"- 辅助审计文档（如 `USED_ENDPOINTS.md`、`REMOVED.md`、覆盖矩阵、附录）必须写到：`{supporting_docs_dir}/`",
            f"- `previous_limitations.md` 若需要更新，必须写到工作目录根：`{os.path.join(ctx.working_dir, 'previous_limitations.md')}`",
            "- `results/` 目录只允许放 `result_NNN.md`；不要把辅助审计文档混进 `results/`",
            "- 调用 `write` / `edit` 工具时，优先直接使用上述绝对路径",
            "- **严禁**写到 `sessions/`、`sessions/<session>/calls/<call>/`、prompt 文件同级目录，或任何其他目录",
            "",
            "---",
            "",
            "## 🧪 返工时的技术检查清单",
            "",
            "1. **回顾 blocker 指向的数据流路径/EXPORT/USED** — 仅对 backlog 相关区域做更深跟入，不要无边界扩张",
            "2. **重新审查所有被点名跟入不足的函数** — 至少补到能够给出安全/漏洞结论的深度",
            "3. **对关键代码重新执行漏洞检查清单** — 缓冲区溢出、整数溢出、符号混淆、越界、UAF、竞态等",
            "4. **考虑极端边界条件** — 0, -1, 0x7FFFFFFF, 0xFFFFFFFF, 空指针, 超长输入等",
            "5. **审查错误处理路径** — 异常分支和资源释放路径是漏洞高发区",
            '6. **检查你之前标记为"安全"的代码** — 重新用攻击者视角审视，尝试绕过每一个校验',
            "7. **新增发现必须服务于收敛** — 只有在它能直接关闭 blocker 或证明旧结论错误时，才值得新增 result",
            "",
            "## 📝 报告编号规则",
            "",
            "- 已有报告：按评审意见修正或删除，**不要改变已有文件的编号**",
            f"- 新增漏洞报告：从 `result_{next_num:03d}.md` 开始顺延编号",
            "- **禁止复用历史编号**：即使某个旧报告已删除，新报告也不能占用它的编号",
            "- 修正和新增完成后，**同步更新 summary.md**（漏洞汇总表、覆盖度表等）",
        ])

    @staticmethod
    def _format_blocker_items(blockers: list) -> str:
        if not blockers:
            return "(当前无未关闭的阻塞项)"
        lines: list[str] = []
        for item in blockers:
            headline = f"- [{item.blocker_id}]"
            extras = [part for part in (item.category, item.target, item.severity) if part]
            if extras:
                headline += " " + " / ".join(extras)
            lines.append(headline)
            if item.required_action:
                lines.append(f"  - required_action: {item.required_action}")
            if item.detail and item.detail != item.required_action:
                lines.append(f"  - detail: {item.detail}")
            lines.append(
                f"  - first_seen_cycle: {item.first_seen_cycle}, last_seen_cycle: {item.last_seen_cycle}, seen_count: {item.seen_count}"
            )
        return "\n".join(lines)

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
        protected_files = sorted(
            name for name in review_state.get_passed_result_filenames()
            if name in pre_cycle_set
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
            "## 返工轮文件稳定性规则（本阶段必须严格遵守）",
            "",
            "- 不允许为了“整理”或“精简”而给已有漏洞报告重新编号。",
            "- 不允许把新漏洞写到任何历史编号上，也不允许覆盖已通过评审的报告。",
        ]

        if ctx.protected_result_files:
            lines.extend([
                "",
                "### 已通过评审、受保护的结果文件（禁止修改 / 覆盖 / 重命名）",
            ])
            lines.extend(f"- {name}" for name in ctx.protected_result_files)

        if mutable_files:
            lines.extend([
                "",
                "### 可修改或删除的已有结果文件（如需修正，只能沿用原编号）",
            ])
            lines.extend(f"- {name}" for name in mutable_files)

        lines.extend([
            "",
            "### 新增漏洞报告编号起点",
            f"- 本轮任何新增漏洞报告必须从 `result_{ctx.next_result_number:03d}.md` 开始顺延编号。",
            "- 即使旧报告已删除，其历史编号也不得复用。",
            "- 如果你发现某个已通过评审的报告需要补充，请保留原文件不动，新增一个更高编号的补充报告。",
        ])

        lines.extend([
            "",
            "### 辅助审计文档位置",
            f"- 像 `USED_ENDPOINTS.md`、`REMOVED.md`、覆盖矩阵、附录等辅助文档，请写到 `{self._supporting_docs_dir(ctx.working_dir)}/`。",
            "- `results/` 目录只保留 `result_NNN.md`；不要把辅助文档混进结果目录。",
        ])

        if ctx.review_mode == "closure":
            lines.extend([
                "",
                "### Closure 模式附加规则",
                "- 当前处于收敛阶段：禁止为了‘继续扩展攻击面’而大幅改写 summary.md 或批量新增结果。",
                "- 仅允许新增那些**直接用于关闭当前 blocker backlog** 的报告。",
                "- 若新增 result，请在 summary.md 的局限性或覆盖表中明确说明它关闭了哪个 blocker。",
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
        backed_up = self._backup_removed_failed_results(ctx)
        if backed_up:
            actions.extend(
                f"backed up removed failed report {name}" for name in backed_up
            )

        if actions:
            logger.warning(
                "rework_result_reconciliation_applied",
                workflow_id=ctx.workflow_id,
                task_id=ctx.task_id,
                cycle=ctx.cycle,
                actions=actions,
            )

    @classmethod
    def _load_previous_limitations_from_current_summary(
        cls,
        working_dir: str,
        cycle: int,
    ) -> str:
        """
        返工开始前，优先读取与 reviewer 一致的上一轮局限性快照；
        若缺失，再回退到当前工作目录可恢复的记录。
        """
        try:
            content, _ = load_previous_limitations(working_dir, cycle)
            return content
        except Exception as e:
            logger.warning("previous_limitations_extract_failed", error=str(e))
            summary_path = os.path.join(working_dir, "summary.md")
            if not os.path.isfile(summary_path):
                return "(未找到上一轮 summary.md，无法提取“局限性与未覆盖区域”章节)"
            try:
                content = read_file(summary_path)
                section = extract_markdown_section(
                    content,
                    ["局限性与未覆盖区域", "局限性"],
                )
                return section or "(上一轮 summary.md 中未找到“局限性与未覆盖区域”章节)"
            except Exception as inner:
                return f"(提取上一轮“局限性与未覆盖区域”章节失败: {inner})"

    # ─────────────────────────────────────────────
    #  反思 & 总结
    # ─────────────────────────────────────────────

    def _relocate_misplaced_outputs(
        self,
        ctx: WorkflowContext,
        turn_count: int,
    ) -> None:
        """
        兜底修复：如果模型把 summary.md / result_*.md 写到了
        sessions/<session>/calls/<turn>_* 下面，则自动搬运回工作目录。
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
                or review_state.get_open_blockers(actionable_by="worker")
                or (ctx.failed_result_items or [])
                or ctx.review_mode == "closure"
            )
        )
        if ctx.cycle <= 1 or review_state is None or not has_rework_context:
            return "\n".join([
                "当前仍是首轮/无历史失败状态的自审，按下面的全量覆盖清单检查即可。",
                f"若需要补充辅助审计文档，请写到 `{supporting_docs_dir}/`，不要写进 `results/`。",
            ])

        worker_blockers = review_state.get_open_blockers(
            limit=review_state.MAX_OPEN_BLOCKERS,
            actionable_by="worker",
        )
        has_worker_blockers = bool(worker_blockers)

        if not has_worker_blockers and (ctx.failed_result_items or []):
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
                "当前没有需要 Worker 继续扩展的 blocker backlog；本轮自审只服务于未通过结果修复，禁止重新铺开全量攻击面。",
                f"辅助审计文档统一写到 `{supporting_docs_dir}/`；`results/` 里只保留 `result_NNN.md`。",
                "",
                "### 本轮优先复核的历史待修结果",
                failed_items_text,
                "",
                "### 自审边界",
                "- 仅复核上述失败结果及其直接相关代码路径",
                "- 若没有新证据，不要新增新的攻击面章节或批量新报告",
                "- 若需要补充删除说明、附录或证据矩阵，写到 `supporting_docs/` 而不是 `results/`",
            ])

        worker_blockers = review_state.format_open_blockers(
            limit=review_state.MAX_OPEN_BLOCKERS,
            actionable_by="worker",
        )
        failed_items = [
            item.filename for item in (ctx.failed_result_items or [])
            if is_result_report_filename(item.filename)
        ]
        failed_items_text = (
            "\n".join(f"- {name}" for name in failed_items)
            if failed_items else
            "- (当前无明确待修的历史结果文件；优先围绕 Worker blocker 自审)"
        )

        return "\n".join([
            "当前不是首轮全量发散式自审，而是返工/收敛阶段。",
            "本轮自审必须优先服务于 blocker 收敛和弱结果修复，不要重新把任务扩张成全量攻击面重扫。",
            f"辅助审计文档统一写到 `{supporting_docs_dir}/`；`results/` 里只保留 `result_NNN.md`。",
            "",
            "### 本轮 Worker 可执行 blocker",
            worker_blockers,
            "",
            "### 本轮优先复核的历史待修结果",
            failed_items_text,
            "",
            "### 自审边界",
            "- 只对上述 blocker、待修结果、以及本轮新改动直接影响的路径做深入复核",
            "- 若没有新证据，不要把 Summary 又写回‘全量重扫’口径",
            "- 若需要补充 USED/EXPORT 附录、删除审计说明、覆盖矩阵，写到 `supporting_docs/` 而不是 `results/`",
        ])

    def _build_reflection_checklist(
        self,
        ctx: WorkflowContext,
        review_state: ReviewState | None,
    ) -> str:
        current_result_files = self._list_result_files(os.path.join(ctx.working_dir, "results"))
        is_initial = (
            ctx.cycle <= 1
            or review_state is None
            or not review_state.has_failures(
                current_results=current_result_files,
                actionable_by="worker",
            )
        )
        if is_initial:
            return "\n".join([
                "## 一、覆盖度自审（是否有遗漏？）",
                "",
                "### 1.1 数据流路径覆盖",
                "- 回顾数据流分析文件的**每一个 INPUT**——你是否对每个 INPUT 的每一条分支路径都做了漏洞分析？",
                "- 是否有某些 INPUT 或子分支被你跳过了？列出并立即补充。",
                "",
                "### 1.2 EXPORT 终点覆盖",
                "- 数据流中所有 `🟡 EXPORT` 终点——你是否都跟入了目标函数的源码？",
                "- 跟入后是否用完整的漏洞检查清单扫描了？",
                "- **未跟入的 EXPORT = 分析盲区**。列出所有未跟入的 EXPORT，逐个补充。",
                "",
                "### 1.3 USED 终点覆盖",
                "- 所有 `📌 USED` 终点——你是否都检查了操作安全性？",
                "- 作为长度/索引/指针偏移的使用点，是否都做了边界分析？",
                "",
                "### 1.4 CLEANED 终点验证",
                "- 所有 `🟢 CLEANED` 终点——你是否验证了清洗逻辑的完备性？",
                "- 是否尝试了绕过？（整数溢出、符号混淆、off-by-one、TOCTOU）",
                "",
                "### 1.5 关键发现验证",
                "- 数据流中 ★ 标记的关键发现——你是否**全部**做了源码级验证？",
                "",
                "---",
                "",
                "## 二、深度自审（分析是否足够深入？）",
                "",
                "### 2.1 漏洞模式覆盖",
                "- 回顾是否覆盖了内存安全、整数安全、资源耗尽、输入验证、逻辑缺陷。",
                "- 如果某类漏洞模式未被覆盖到，立即补充。",
                "",
                "### 2.2 校验绕过分析",
                "- 对路径上存在的每个安全校验，检查是否尝试了边界值、有符号/无符号混用和竞争条件。",
                "",
                "### 2.3 跨函数分析深度",
                "- 被调用函数链是否追踪到了至少 3 层？深层危险操作是否被识别？",
                "",
                "---",
                "",
                "## 三、证据链自审（报告质量是否过关？）",
                "",
                "### 3.1 每个漏洞报告是否有：",
                "- [ ] 源代码片段（≥5 行上下文）",
                "- [ ] 从 INPUT 到危险操作的完整路径",
                "- [ ] 具体到字段级别的触发条件",
                "- [ ] 明确的 CWE 分类和严重性评级",
                "",
                "### 3.2 是否有发现了但未报告的可疑点？",
                "- 如果有‘不太确定’的问题，**请写入报告并标注置信度为低**。",
                "- 宁可多报，不可漏报。",
                "",
                "---",
                "",
                "## 四、行动要求",
                "",
                "- 发现覆盖不足 → **立即阅读代码并补充分析**",
                "- 发现未跟入的 EXPORT → **立即跟入并扫描**",
                "- 发现未报告的可疑点 → **立即创建漏洞报告**",
                "- 所有变更后 → **同步更新 summary.md**",
                "- results/ 文件命名 → 严格 `result_001.md`, `result_002.md`, ...",
            ])

        if not review_state.get_open_blockers(actionable_by="worker") and (ctx.failed_result_items or []):
            return "\n".join([
                "## 一、失败结果复核（仅面向当前失败项）",
                "",
                "- 只复核当前未通过的 `result_NNN.md` 及其直接相关代码路径。",
                "- 核查报告是否遗漏了上游校验、是否误解了数据来源、是否夸大了影响。",
                "- 若确认误报，删除结果文件并在 summary / supporting_docs 中说明删除理由。",
                "",
                "---",
                "",
                "## 二、证据链修复",
                "",
                "- 对仍保留的失败报告，补齐源代码片段、INPUT→危险操作路径、字段级触发条件、CWE/严重性。",
                "- 若没有新证据，不要新增新的漏洞方向或全量覆盖章节。",
                "",
                "---",
                "",
                "## 三、行动要求",
                "",
                "- 只修当前失败结果，不要重新全量重扫。",
                "- 需要补充附录、删除审计或证据矩阵时，写到 `supporting_docs/`。",
                "- 所有变更后同步更新 `summary.md`。",
            ])

        return "\n".join([
            "## 一、返工范围核对（仅围绕当前 blocker / 待修结果）",
            "",
            "- 优先核对本轮 Worker blocker 指向的数据流路径、EXPORT/USED 终点和待修结果。",
            "- 不要重新回到‘每个 INPUT / 所有 EXPORT 全量重扫’模式。",
            "- 若当前代码结论没有新增证据支撑，不要新增弱报告。",
            "",
            "---",
            "",
            "## 二、定向深挖",
            "",
            "- 对 blocker 指向的函数重新执行漏洞模式检查：内存安全、整数安全、逻辑绕过、资源耗尽。",
            "- 对报告中已有的安全校验，专门验证是否可绕过，而不是看到 if 就判安全。",
            "- 对本轮新改动直接影响的 summary / supporting_docs / 附录口径做一致性检查。",
            "",
            "---",
            "",
            "## 三、证据链与收敛",
            "",
            "- 保留的结果必须有完整证据链；删除的结果必须在 summary / REMOVED 审计中给出理由。",
            "- 若问题命中了已冻结报告，不要改原文件；改用更高编号补充报告或 supporting_docs/summary 澄清。",
            "- 若没有新证据，不要把任务扩张成更多新结果。",
            "",
            "---",
            "",
            "## 四、行动要求",
            "",
            "- 发现 blocker 未闭环 → **立即定向补分析并修正 summary / supporting docs**",
            "- 发现失败结果仍为误报 → **立即删除该结果并保留删除审计**",
            "- 发现需要补证据但原报告受保护 → **新增更高编号补充报告，不改原文件**",
            "- 所有变更后 → **同步更新 summary.md 与 previous_limitations.md**",
            "- 不要重新全量发散。",
        ])

    async def execute_reflection(
        self,
        wf_def: AtomicWorkflowDef,
        ctx: WorkflowContext,
        review_state: ReviewState | None = None,
    ) -> None:
        """
        自我反思阶段 (R6d)

        按序执行反思 prompt，每一轮等待上一轮完成。
        """
        worker_cfg = wf_def.roles.worker
        reflection_prompts = worker_cfg.prompts.reflection

        if not reflection_prompts:
            logger.debug("no_reflection_prompts", workflow_id=ctx.workflow_id)
            return

        agent = self.agents.get(worker_cfg.agent_id)

        for i, reflect_cfg in enumerate(reflection_prompts):
            prompt = read_file(reflect_cfg.prompt_file)
            prompt = render_string(
                prompt,
                working_dir=ctx.working_dir,
                cycle=str(ctx.cycle),
                review_mode=ctx.review_mode,
                supporting_docs_dir=self._supporting_docs_dir(ctx.working_dir),
                reflection_scope=self._build_reflection_scope(ctx, review_state),
                reflection_checklist=self._build_reflection_checklist(ctx, review_state),
            )

            logger.info("reflection_start",
                         round=i + 1,
                         prompt_id=reflect_cfg.id,
                         workflow_id=ctx.workflow_id)

            # 每一轮必须等上一轮结束 (R6d: 串行)
            response = await agent.send_message(
                message=prompt,
                session_id=ctx.worker_session_id,
                working_dir=ctx.working_dir,
            )

            self._relocate_misplaced_outputs(ctx, response.turn_count)

            await self.recorder.record_reflection(
                work_dir=ctx.working_dir,
                round_num=i + 1,
                prompt_id=reflect_cfg.id,
                response=response.content,
                cycle=ctx.cycle,
            )

            logger.info("reflection_done",
                         round=i + 1, prompt_id=reflect_cfg.id)

    async def execute_summary(
        self,
        wf_def: AtomicWorkflowDef,
        ctx: WorkflowContext,
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
        prompt = render_string(
            prompt,
            working_dir=ctx.working_dir,
            summary_path=summary_path,
            results_dir=results_dir,
            supporting_docs_dir=supporting_docs_dir,
            cycle=str(ctx.cycle),
        )
        rework_rules = self._build_summary_rework_rules(ctx)
        if rework_rules:
            prompt += "\n\n---\n\n" + rework_rules

        logger.info("summary_start", workflow_id=ctx.workflow_id)

        response = await agent.send_message(
            message=prompt,
            session_id=ctx.worker_session_id,
            working_dir=ctx.working_dir,
        )
        self._relocate_misplaced_outputs(ctx, response.turn_count)
        self._reconcile_results_after_rework(ctx)
        self._relocate_supporting_docs_from_results(ctx)
        self._sync_previous_limitations_sidecar(ctx)

        logger.info("summary_done",
                     workflow_id=ctx.workflow_id,
                     summary_path=summary_path,
                     results_dir=results_dir)

        return summary_path, results_dir
