"""
执行记录器

持久化记录工作流执行过程中的所有关键事件：
- 插件执行结果 (R8)
- 评审记录 (R6h)
- 状态变更
- 异常退出 (R10)
"""

from __future__ import annotations

from datetime import datetime, timezone
import os
import shutil
from pathlib import Path
from typing import Any, Optional

from app.pi_vuln_core.plugins.base import PluginResult
from app.pi_vuln_core.utils.file_ops import write_json
from app.pi_vuln_core.utils.logger import get_logger

logger = get_logger("recorder")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ExecutionRecorder:
    """
    执行记录器

    所有记录以 JSON 文件写入对应的工作目录
    """

    def __init__(self, workspace_root: str = "/workspace"):
        self.workspace_root = Path(workspace_root)

    # ═══════════════════════════════════════
    # 插件记录 (R8)
    # ═══════════════════════════════════════

    async def record_plugin(
        self,
        workflow_id: str,
        task_id: str,
        phase: str,
        plugin_id: str,
        sequence: int,
        result: PluginResult,
        work_dir: Optional[str] = None,
    ) -> None:
        """记录插件执行结果"""
        record = {
            "plugin_id": plugin_id,
            "phase": phase,
            "sequence": sequence,
            "timestamp": _now_iso(),
            "duration_ms": result.duration_ms,
            "result_code": result.code.value,
            "message": result.message,
            "data": result.data,
            "error_detail": result.error_detail,
        }

        if work_dir:
            record_dir = Path(work_dir) / "plugins" / phase
            record_dir.mkdir(parents=True, exist_ok=True)
            filename = f"{sequence:03d}_{plugin_id}.json"
            write_json(record_dir / filename, record)

        logger.info("plugin_recorded",
                     plugin_id=plugin_id, phase=phase,
                     code=result.code.value)

    # ═══════════════════════════════════════
    # 评审记录 (R6h)
    # ═══════════════════════════════════════

    async def record_global_review(
        self,
        work_dir: str,
        advisor_id: str,
        cycle: int,
        passed: bool,
        content: str,
        agent_id: str = "",
        role_name: str = "",
        scores: Optional[dict] = None,
        confidence: Optional[float] = None,
        raw_content: str = "",
    ) -> None:
        """记录全局评审结果"""
        record = {
            "advisor_instance_id": advisor_id,
            "agent_id": agent_id,
            "role_name": role_name,
            "cycle": cycle,
            "timestamp": _now_iso(),
            "passed": passed,
            "scores": scores or {},
            "confidence": confidence,
            "feedback": content,
            "raw_response": raw_content,
        }

        record_dir = Path(work_dir) / "reviews" / "global" / f"cycle_{cycle:03d}"
        record_dir.mkdir(parents=True, exist_ok=True)
        write_json(record_dir / f"{advisor_id}.json", record)

        logger.info("global_review_recorded",
                     advisor_id=advisor_id, cycle=cycle, passed=passed)

    async def record_result_review(
        self,
        work_dir: str,
        result_file: str,
        advisor_id: str,
        cycle: int,
        passed: bool,
        content: str,
        agent_id: str = "",
        role_name: str = "",
        scores: Optional[dict] = None,
        confidence: Optional[float] = None,
        raw_content: str = "",
    ) -> None:
        """记录结果评审（以每个结果为对象）(R6h)"""
        result_stem = Path(result_file).stem  # "result_001"
        record = {
            "result_file": result_file,
            "advisor_instance_id": advisor_id,
            "agent_id": agent_id,
            "role_name": role_name,
            "cycle": cycle,
            "timestamp": _now_iso(),
            "passed": passed,
            "scores": scores or {},
            "confidence": confidence,
            "feedback": content,
            "raw_response": raw_content,
        }

        record_dir = (Path(work_dir) / "reviews" / "results" /
                      result_stem / f"cycle_{cycle:03d}")
        record_dir.mkdir(parents=True, exist_ok=True)
        write_json(record_dir / f"{advisor_id}.json", record)

        logger.info("result_review_recorded",
                     result_file=result_file, advisor_id=advisor_id,
                     cycle=cycle, passed=passed)

    # ═══════════════════════════════════════
    # 反思记录
    # ═══════════════════════════════════════

    async def record_reflection(
        self,
        work_dir: str,
        round_num: int,
        prompt_id: str,
        response: str,
    ) -> None:
        """记录Worker自我反思"""
        record = {
            "round": round_num,
            "prompt_id": prompt_id,
            "timestamp": _now_iso(),
            "response": response,
        }
        record_dir = Path(work_dir) / "_meta" / "reflections"
        record_dir.mkdir(parents=True, exist_ok=True)
        write_json(record_dir / f"reflect_{round_num:03d}_{prompt_id}.json", record)

    # ═══════════════════════════════════════
    # 状态与异常记录 (R10)
    # ═══════════════════════════════════════

    async def record_state_change(
        self, work_dir: str, old_state: str, new_state: str,
        detail: str = "",
    ) -> None:
        """记录状态变更"""
        state_file = Path(work_dir) / "_meta" / "state.json"
        record = {
            "current_state": new_state,
            "previous_state": old_state,
            "timestamp": _now_iso(),
            "detail": detail,
        }
        write_json(state_file, record)

    async def record_workflow_result(
        self,
        work_dir: str,
        status: str,
        detail: dict[str, Any] | None = None,
    ) -> None:
        """记录工作流最终结果"""
        record = {
            "status": status,
            "timestamp": _now_iso(),
            "detail": detail or {},
        }
        write_json(Path(work_dir) / "_meta" / "workflow_result.json", record)

    async def record_abnormal_exit(
        self,
        work_dir: str,
        error: str,
        context: dict[str, Any] | None = None,
    ) -> None:
        """记录异常退出 (R10)"""
        record = {
            "type": "abnormal_exit",
            "timestamp": _now_iso(),
            "error": error,
            "context": context or {},
        }
        write_json(Path(work_dir) / "_meta" / "abnormal_exit.json", record)
        logger.error("abnormal_exit_recorded", error=error)

    async def record_warning(
        self, work_dir: str, message: str,
    ) -> None:
        """记录警告"""
        logger.warning("workflow_warning", message=message)

    # ═══════════════════════════════════════
    # summary.md 版本记录 (任务2)
    # ═══════════════════════════════════════

    async def snapshot_summary(
        self, work_dir: str, cycle: int, phase: str,
    ) -> None:
        """
        对 summary.md 做版本快照
        保存到: _meta/summary_versions/cycle_{N}_{phase}.md
        """
        summary_path = os.path.join(work_dir, "summary.md")
        if not os.path.exists(summary_path):
            return

        versions_dir = os.path.join(work_dir, "_meta", "summary_versions")
        os.makedirs(versions_dir, exist_ok=True)
        snapshot_name = f"cycle_{cycle:03d}_{phase}.md"
        dst = os.path.join(versions_dir, snapshot_name)
        shutil.copy2(summary_path, dst)

        logger.info("summary_snapshot",
                     cycle=cycle, phase=phase, path=dst)

    # ═══════════════════════════════════════
    # 评审轮次汇总记录 (任务3)
    # ═══════════════════════════════════════

    async def record_review_cycle_summary(
        self,
        work_dir: str,
        cycle: int,
        global_passed: bool,
        global_feedback: str,
        total_results: int,
        passed_results: list[str],
        failed_results: list[dict],
    ) -> None:
        """
        记录每轮评审汇总
        写入: _meta/review_summaries/cycle_{N}.json
        """
        record = {
            "cycle": cycle,
            "timestamp": _now_iso(),
            "global_review": {
                "passed": global_passed,
                "feedback_preview": global_feedback[:500] if global_feedback else "",
            },
            "result_review": {
                "total": total_results,
                "passed_count": len(passed_results),
                "failed_count": len(failed_results),
                "passed_files": passed_results,
                "failed_files": [
                    {"filename": f["filename"], "reason_preview": f["reason"][:200]}
                    for f in failed_results
                ],
            },
            "outcome": ("all_passed" if (global_passed and len(failed_results) == 0)
                        else "global_failed" if not global_passed
                        else "results_failed"),
        }

        summaries_dir = os.path.join(work_dir, "_meta", "review_summaries")
        os.makedirs(summaries_dir, exist_ok=True)
        write_json(
            os.path.join(summaries_dir, f"cycle_{cycle:03d}.json"),
            record)

        logger.info("review_cycle_summary",
                     cycle=cycle,
                     outcome=record["outcome"],
                     passed=len(passed_results),
                     failed=len(failed_results))
