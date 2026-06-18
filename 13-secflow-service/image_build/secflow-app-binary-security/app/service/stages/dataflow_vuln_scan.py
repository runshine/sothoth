from __future__ import annotations

from typing import Any, TYPE_CHECKING

from sqlalchemy.orm import Session

from app.model import BinarySecurityTask
from app.service.stages.base import BinarySecurityStageHandler

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager


class DataflowVulnScanStageHandler(BinarySecurityStageHandler):
    def __init__(self) -> None:
        super().__init__(stage_name="dataflow_vuln_scan")

    def manages_stage_refresh(self) -> bool:
        return True

    def manages_stage_compaction(self) -> bool:
        return True

    def build_inputs(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> list[dict[str, Any]]:
        del db
        entries: list[dict[str, Any]] = []
        for result in manager._effective_entry_inputs(task):
            if isinstance(result, dict):
                entries.extend([dict(entry) for entry in list(result.get("entries") or []) if isinstance(entry, dict)])
        return _deduplicate_entry_rows(entries)

    def continue_stage_input_error(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> str | None:
        if self.build_inputs(manager, db, task):
            return None
        return "入口分析尚未产出可用入口结果，不能继续数据流漏洞挖掘阶段"

    def refresh_summary_from_items(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> None:
        manager._refresh_stage_run_from_items(db, task, self.stage_name)
        manager._rebuild_summary_results_from_stage_items(db, task, self.stage_name, "dataflow_results")

    def compact_success_items(
        self,
        manager: TaskManager,
        rows: list[dict[str, Any]],
        *,
        summary_key: str | None = None,
    ) -> list[dict[str, Any]]:
        compactor = manager._compact_vuln_summary_item if summary_key == "vuln_results" else manager._compact_dataflow_summary_item
        compacted = [compactor(row) for row in rows if isinstance(row, dict)]
        deduped: dict[tuple[str, str], dict[str, Any]] = {}
        for row in compacted:
            key = (
                str(row.get("entry_key") or "").strip(),
                str(row.get("module_key") or "").strip(),
            )
            if key == ("", ""):
                key = (str(len(deduped)), "")
            deduped[key] = row
        return list(deduped.values())

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


def _deduplicate_entry_rows(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
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
