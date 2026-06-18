from __future__ import annotations

from dataclasses import dataclass
from typing import Any, TYPE_CHECKING

from sqlalchemy.orm import Session

from app.model import BinarySecurityTask, normalize_stage_name

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager


@dataclass(frozen=True)
class BinarySecurityStageHandler:
    stage_name: str

    def manages_stage_refresh(self) -> bool:
        return False

    def manages_stage_compaction(self) -> bool:
        return False

    def build_inputs(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> list[dict[str, Any]]:
        del manager, db, task
        return []

    def has_runnable_inputs(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> bool:
        return bool(self.build_inputs(manager, db, task))

    def continue_stage_input_error(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> str | None:
        del manager, db, task
        return None

    def refresh_summary_from_items(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> None:
        del manager, db, task

    def compact_success_items(
        self,
        manager: TaskManager,
        rows: list[dict[str, Any]],
        *,
        summary_key: str | None = None,
    ) -> list[dict[str, Any]]:
        del manager, summary_key
        return list(rows)

    def archive_input_signature(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> dict[str, Any]:
        del manager, db, task
        return {"stage_name": normalize_stage_name(self.stage_name)}

    def archive_signature_has_runnable_inputs(self, signature: dict[str, Any] | None) -> bool:
        del signature
        return False

    def repair_after_archive_apply(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> None:
        del manager, db, task

    def has_authoritative_success_payload(
        self,
        manager: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> bool:
        del manager, db, task
        return False

    def downstream_service(self) -> str | None:
        return None

    def create_child_payload(
        self,
        manager: TaskManager,
        db: Session,
        task: BinarySecurityTask,
        item: Any,
    ) -> dict[str, Any]:
        del manager, db, task, item
        return {}

    def descendant_stages(self, manager: TaskManager, task: BinarySecurityTask) -> list[str]:
        stage_sequence = manager._stage_sequence_for_task(task)
        if self.stage_name not in stage_sequence:
            return []
        index = stage_sequence.index(self.stage_name)
        return list(stage_sequence[index + 1 :])

    def should_skip_without_runnable_work(
        self,
        manager: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> bool:
        del manager, db, task
        return False
