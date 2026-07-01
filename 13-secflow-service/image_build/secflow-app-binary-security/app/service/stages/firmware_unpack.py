from __future__ import annotations

from typing import Any, TYPE_CHECKING

from sqlalchemy.orm import Session

from app.model import BinarySecurityTask
from app.service.stages.base import BinarySecurityStageHandler

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager


class FirmwareUnpackStageHandler(BinarySecurityStageHandler):
    def __init__(self) -> None:
        super().__init__(stage_name="firmware_unpack")

    def build_inputs(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> list[dict[str, Any]]:
        del manager, db
        return [
            dict(item)
            for item in list((task.summary or {}).get("input_files") or [])
            if isinstance(item, dict)
        ]

    def has_runnable_inputs(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> bool:
        return bool(self.build_inputs(manager, db, task))

    def continue_stage_input_error(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> str | None:
        if not self.has_runnable_inputs(manager, db, task):
            return "缺少输入文件"
        return None

    def manages_stage_refresh(self) -> bool:
        return True

    def manages_stage_compaction(self) -> bool:
        return True

    def refresh_summary_from_items(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> None:
        manager._refresh_stage_run_from_items(db, task, self.stage_name)

    def compact_success_items(
        self,
        manager: TaskManager,
        rows: list[dict[str, object]],
        *,
        summary_key: str | None = None,
    ) -> list[dict[str, object]]:
        del summary_key
        return [
            manager._compact_firmware_unpack_summary_item(row)
            for row in rows
            if isinstance(row, dict)
        ]

    def archive_input_signature(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> dict[str, object]:
        system_inputs = manager._system_analysis_inputs(task, db=db)
        firmware_keys = [
            str(row.get("firmware_key") or "").strip()
            for row in system_inputs
            if isinstance(row, dict) and str(row.get("firmware_key") or "").strip()
        ]
        return {
            "stage_name": self.stage_name,
            "system_input_count": len(system_inputs),
            "firmware_keys": firmware_keys,
        }

    def archive_signature_has_runnable_inputs(self, signature: dict[str, object] | None) -> bool:
        payload = dict(signature or {})
        return int(payload.get("system_input_count") or 0) > 0

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
