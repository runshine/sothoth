"""
可视化日志工具

在 structlog JSON 日志之外，提供人类可读的阶段标记输出
"""

from __future__ import annotations

import re
import sys
import time
from datetime import datetime


class VisualLogger:
    """可视化日志 — 输出到 stderr (不干扰 stdout 的 JSON 日志)"""

    COLORS = {
        "reset":   "\033[0m",
        "bold":    "\033[1m",
        "red":     "\033[31m",
        "green":   "\033[32m",
        "yellow":  "\033[33m",
        "blue":    "\033[34m",
        "magenta": "\033[35m",
        "cyan":    "\033[36m",
        "gray":    "\033[90m",
    }

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._start_time = time.monotonic()
        self._phase_start = time.monotonic()

    def _elapsed(self) -> str:
        secs = int(time.monotonic() - self._start_time)
        m, s = divmod(secs, 60)
        h, m = divmod(m, 60)
        if h > 0:
            return f"{h}h{m:02d}m{s:02d}s"
        elif m > 0:
            return f"{m}m{s:02d}s"
        return f"{s}s"

    def _phase_elapsed(self) -> str:
        secs = time.monotonic() - self._phase_start
        if secs < 1:
            return f"{secs*1000:.0f}ms"
        elif secs < 60:
            return f"{secs:.1f}s"
        else:
            m, s = divmod(int(secs), 60)
            return f"{m}m{s:02d}s"

    def _print(self, msg: str):
        if self.enabled:
            print(msg, file=sys.stderr, flush=True)

    def _c(self, color: str, text: str) -> str:
        return f"{self.COLORS.get(color, '')}{text}{self.COLORS['reset']}"

    def _one_line(self, text: str, limit: int = 80) -> str:
        cleaned = re.sub(r'\s+', ' ', (text or '')).strip()
        if len(cleaned) > limit:
            return cleaned[:limit - 3] + '...'
        return cleaned

    def _verdict_line(self, text: str, limit: int = 80) -> str:
        """从可能很长的 feedback 中提取简洁 verdict 摘要"""
        if not text:
            return ""
        import re as _re
        # 尝试提取结构化 verdict
        verdict_patterns = [
            _re.compile(r'(?:评审结论|最终判定|裁决|verdict|final_verdict)[\s::：]+\**\s*(.+?)(?:\s*[(（].*?[)）])?\s*(?:\*|$)', _re.IGNORECASE),
            _re.compile(r'(CONFIRMED|FALSE_POSITIVE|INSUFFICIENT_INFO|REJECTED|TRUE_POSITIVE|UNVERIFIED|REFUTED|DISMISS)', _re.IGNORECASE),
        ]
        for p in verdict_patterns:
            m = p.search(text)
            if m:
                verdict = m.group(1).strip().strip('*').strip()
                return verdict if len(verdict) <= limit else verdict[:limit - 3] + '...'
        # 没找到就用首行
        return self._one_line(text, limit)

    # ═══════════════════════════════════════
    # 顶层标记
    # ═══════════════════════════════════════

    def banner(self, title: str):
        self._print(f"\n{self._c('bold', '═' * 60)}")
        self._print(f"  {self._c('bold', title)}")
        self._print(f"  {self._c('gray', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}")
        self._print(f"{self._c('bold', '═' * 60)}")
        self._start_time = time.monotonic()

    def section(self, icon: str, title: str, detail: str = ""):
        self._phase_start = time.monotonic()
        sep = self._c('cyan', '─' * 50)
        elapsed = self._c('gray', f'[{self._elapsed()}]')
        det = f"  {self._c('gray', detail)}" if detail else ""
        self._print(f"\n{sep}")
        self._print(f"  {icon} {self._c('bold', title)}{det}  {elapsed}")
        self._print(sep)

    def phase_done(self, icon: str, msg: str):
        elapsed = self._c('gray', f'({self._phase_elapsed()})')
        self._print(f"  {icon} {msg} {elapsed}")

    # ═══════════════════════════════════════
    # 工作流生命周期
    # ═══════════════════════════════════════

    def workflow_start(self, wf_id: str, task_id: str, work_dir: str):
        self.section("🚀", f"原子工作流启动：{wf_id}",
                      f"task={task_id}")
        self._print(f"  📁 工作目录：{work_dir}")

    def cycle_start(self, cycle: int, max_cycles: int):
        color = 'green' if cycle == 1 else 'yellow'
        self._print(f"\n  {self._c(color, f'◆ Cycle {cycle}/{max_cycles}')}")

    def plugin_executed(self, plugin_id: str, phase: str, code: str, msg: str):
        icon = "✅" if code.startswith("ok") else "⚠️" if "continue" in code else "❌"
        self._print(f"    {icon} [{phase}] {plugin_id}: {msg} ({code})")

    def worker_start(self, cycle: int):
        self.section("🔨", f"Worker 执行", f"cycle={cycle}")

    def worker_done(self, turns: int):
        self.phase_done("✅", f"Worker 完成 (turns={turns})")

    def reflection_start(self, round_num: int, prompt_id: str):
        self._print(f"    🪞 反思 [{round_num}] {prompt_id}...")

    def reflection_done(self, round_num: int):
        self.phase_done("    ✅", f"反思 [{round_num}] 完成")

    def summary_done(self, summary_path: str, results_count: int):
        self.phase_done("📋", f"总结完成：{results_count} 个结果文件")

    # ═══════════════════════════════════════
    # 评审
    # ═══════════════════════════════════════

    def global_review_start(self, cycle: int, advisor_count: int):
        self.section("🔍", f"全局评审", f"cycle={cycle}, advisors={advisor_count}")

    def global_review_advisor_result(
        self,
        advisor_id: str,
        role_name: str,
        passed: bool,
        feedback_preview: str,
    ):
        icon = "✅" if passed else "❌"
        fb = self._verdict_line(feedback_preview) or ("通过" if passed else "未通过")
        label = f"{advisor_id}"
        if role_name:
            label += f" ({role_name})"
        self._print(f"    {icon} {label}: {fb}")

    def global_review_result(
        self,
        passed: bool,
        advisor_results: list[dict] | None = None,
        feedback_preview: str = "",
    ):
        advisor_results = advisor_results or []
        if passed:
            total = len(advisor_results)
            suffix = f" ({total}/{total})" if total > 1 else ""
            self._print(f"  {self._c('green', f'✅ 全局评审全部通过{suffix}')}")
            return

        failed_item = next((item for item in advisor_results if not item.get("passed", True)), None)
        if failed_item:
            advisor_id = str(failed_item.get("advisor_id") or "global")
            role_name = str(failed_item.get("role_name") or "").strip()
            label = advisor_id
            if role_name:
                label += f" / {role_name}"
            self._print(f"  {self._c('red', f'❌ 全局评审未通过 → 卡在 {label}')}")
            return

        fb = self._verdict_line(feedback_preview) or "未通过"
        self._print(f"  {self._c('red', f'❌ 全局评审未通过：{fb}')}")

    def result_review_start(self, cycle: int, total: int, pending: int):
        self.section("🎯", f"结果评审", f"cycle={cycle}, 待审={pending}/{total}")

    def result_review_item(self, filename: str, passed: bool, reason_preview: str = ""):
        icon = "✅" if passed else "❌"
        preview = self._verdict_line(reason_preview) if not passed else ""
        reason = f" — {preview}" if preview else ""
        self._print(f"    {icon} {filename}{reason}")

    def result_review_summary(self, passed: int, failed: int):
        total = passed + failed
        if failed == 0:
            self.phase_done("✅", f"结果评审全部通过 ({total}/{total})")
        else:
            self._print(
                f"  {self._c('red', f'⚠️  结果评审: {passed} 通过, {failed} 不通过 → 回到 Worker')}")

    # ═══════════════════════════════════════
    # 收尾
    # ═══════════════════════════════════════

    def workflow_completed(self, cycles: int, next_tasks: int):
        self._print(f"\n{self._c('green', '═' * 60)}")
        self._print(f"  {self._c('green', f'✅ 工作流完成')}  "
                     f"cycles={cycles}  next_tasks={next_tasks}  "
                     f"total={self._elapsed()}")
        self._print(f"{self._c('green', '═' * 60)}")

    def workflow_failed(self, error: str):
        self._print(f"\n{self._c('red', '═' * 60)}")
        self._print(f"  {self._c('red', f'❌ 工作流失败')}: {error}")
        self._print(f"{self._c('red', '═' * 60)}")

    def stage_start(self, stage_id: str, task_count: int):
        self.section("📦", f"阶段：{stage_id}", f"任务数={task_count}")

    def stage_done(self, stage_id: str, output_tasks: int, errors: int):
        if errors == 0:
            self.phase_done("✅", f"阶段 {stage_id} 完成 → {output_tasks} 个输出任务")
        else:
            self._print(f"  ⚠️  阶段 {stage_id}: {errors} 个失败")


# 全局实例
vlog = VisualLogger(enabled=True)
