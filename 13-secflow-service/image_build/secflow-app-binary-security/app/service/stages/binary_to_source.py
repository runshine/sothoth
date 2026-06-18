from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy.orm import Session

from app.model import BinarySecurityTask
from app.service.stages.base import BinarySecurityStageHandler

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager


class BinaryToSourceStageHandler(BinarySecurityStageHandler):
    def __init__(self) -> None:
        super().__init__(stage_name="binary_to_source")

    def manages_stage_refresh(self) -> bool:
        return True

    def manages_stage_compaction(self) -> bool:
        return True

    def build_inputs(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> list[dict[str, object]]:
        del db
        return [dict(module) for module in list((task.summary or {}).get("selected_modules") or []) if isinstance(module, dict)]

    def continue_stage_input_error(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> str | None:
        if self.build_inputs(manager, db, task):
            return None
        return "系统分析尚未产出可用模块，不能继续二进制逆向阶段"

    def refresh_summary_from_items(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> None:
        manager._refresh_stage_run_from_items(db, task, self.stage_name)
        manager._rebuild_summary_results_from_stage_items(db, task, self.stage_name, "b2s_results")

    def compact_success_items(
        self,
        manager: TaskManager,
        rows: list[dict[str, object]],
        *,
        summary_key: str | None = None,
    ) -> list[dict[str, object]]:
        del summary_key
        return [
            manager._compact_b2s_summary_item(row)
            for row in rows
            if isinstance(row, dict)
        ]

    def archive_input_signature(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> dict[str, object]:
        entry_inputs = manager._entry_analysis_inputs(db, task)
        entry_keys = [
            str(row.get("module_key") or row.get("entry_key") or "").strip()
            for row in entry_inputs
            if isinstance(row, dict)
        ]
        return {
            "stage_name": self.stage_name,
            "entry_input_count": len(entry_inputs),
            "entry_input_keys": [key for key in entry_keys if key],
        }

    def archive_signature_has_runnable_inputs(self, signature: dict[str, object] | None) -> bool:
        payload = dict(signature or {})
        return int(payload.get("entry_input_count") or 0) > 0

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
