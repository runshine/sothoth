from __future__ import annotations

from typing import Any, TYPE_CHECKING

from sqlalchemy.orm import Session

from app.model import BinarySecurityTask, TASK_TYPE_BINARY_MODULE
from app.service.stages.base import BinarySecurityStageHandler

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager


class EntryAnalysisStageHandler(BinarySecurityStageHandler):
    def __init__(self) -> None:
        super().__init__(stage_name="entry_analysis")

    def manages_stage_refresh(self) -> bool:
        return True

    def manages_stage_compaction(self) -> bool:
        return True

    def build_inputs(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> list[dict[str, Any]]:
        return manager._entry_analysis_inputs(db, task)

    def continue_stage_input_error(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> str | None:
        summary = dict(task.summary or {})
        if manager._task_type(task) == TASK_TYPE_BINARY_MODULE:
            inputs = [dict(item) for item in (summary.get("b2s_results") or []) if isinstance(item, dict)]
            if not inputs:
                return "binary-to-source 尚未产出可用结果，不能继续入口分析阶段"
            ready_inputs = [item for item in inputs if item.get("entry_descriptor_ready")]
            if not ready_inputs:
                return "binary-to-source 已成功，但未生成入口分析所需模块描述文件"
            if not any(str(item.get("entry_files_list") or "").strip() for item in ready_inputs):
                return "入口分析模块描述文件已生成但文件列表为空"
            return None
        inputs = list(summary.get("selected_modules") or [])
        if not inputs:
            return "系统分析尚未产出可用模块，不能继续入口分析阶段"
        return None

    def refresh_summary_from_items(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> None:
        stage_run = manager._refresh_stage_run_from_items(db, task, self.stage_name)
        manager._rebuild_entry_results_from_stage_items(db, task, stage_run)

    def compact_success_items(
        self,
        manager: TaskManager,
        rows: list[dict[str, Any]],
        *,
        summary_key: str | None = None,
    ) -> list[dict[str, Any]]:
        del summary_key
        return [
            manager._compact_entry_summary_item(row)
            for row in rows
            if isinstance(row, dict)
        ]

    def archive_input_signature(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> dict[str, Any]:
        entry_results = manager._effective_entry_inputs(task)
        entries: list[dict[str, Any]] = []
        for row in entry_results:
            if isinstance(row, dict):
                entries.extend([dict(entry) for entry in list(row.get("entries") or []) if isinstance(entry, dict)])
        deduped = _deduplicate_entry_keys(entries)
        entry_keys = [str(entry.get("entry_key") or "").strip() for entry in deduped if str(entry.get("entry_key") or "").strip()]
        return {
            "stage_name": self.stage_name,
            "entry_count": len(deduped),
            "entry_keys": entry_keys,
        }

    def archive_signature_has_runnable_inputs(self, signature: dict[str, Any] | None) -> bool:
        payload = dict(signature or {})
        return int(payload.get("entry_count") or 0) > 0

    def repair_after_archive_apply(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> None:
        self.refresh_summary_from_items(manager, db, task)

    def has_authoritative_success_payload(
        self,
        manager: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> bool:
        items = manager._stage_items(db, task.id, self.stage_name)
        return any(str(item.status or "").strip() == "success" for item in items)

    def should_skip_without_runnable_work(
        self,
        manager: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> bool:
        manager._ensure_stage_inputs_available(db, task, self.stage_name)
        if manager._stage_items(db, task.id, self.stage_name):
            return False
        return bool(self.continue_stage_input_error(manager, db, task))


def _deduplicate_entry_keys(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    fallback_index = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        key = str(entry.get("entry_key") or "").strip()
        if not key:
            key = f"entry-{fallback_index}"
            fallback_index += 1
        deduped[key] = dict(entry)
    return list(deduped.values())
