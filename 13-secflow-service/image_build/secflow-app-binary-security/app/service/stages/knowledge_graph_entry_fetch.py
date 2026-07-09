from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy.orm import Session

from app.model import BinarySecurityTask
from app.service.stages.base import BinarySecurityStageHandler

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager


class KnowledgeGraphEntryFetchStageHandler(BinarySecurityStageHandler):
    def __init__(self) -> None:
        super().__init__(stage_name="knowledge_graph_entry_fetch")

    def manages_stage_refresh(self) -> bool:
        return True

    def manages_stage_compaction(self) -> bool:
        return True

    def build_inputs(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> list[dict[str, Any]]:
        del db
        source_dir = str((task.summary or {}).get("input_dir") or "").strip()
        return [
            {
                "source_project_key": manager._knowledge_graph_source_project_key(),
                "module_key": manager._knowledge_graph_source_project_key(),
                "source_dir": source_dir,
                "module_name": "source-project",
            }
        ] if source_dir else []

    def continue_stage_input_error(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> str | None:
        del manager, db
        source_dir = str((task.summary or {}).get("input_dir") or "").strip()
        if source_dir:
            return None
        return "源码任务缺少输入目录，不能继续知识图谱入口获取阶段"

    def refresh_summary_from_items(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> None:
        del db
        manager._refresh_knowledge_graph_entry_fetch_summary(task)

    def compact_success_items(
        self,
        manager: TaskManager,
        rows: list[dict[str, Any]],
        *,
        summary_key: str | None = None,
    ) -> list[dict[str, Any]]:
        del summary_key
        return [manager._compact_entry_summary_item(row) for row in rows if isinstance(row, dict)]

    def has_authoritative_success_payload(
        self,
        manager: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> bool:
        del db
        return bool(manager._knowledge_graph_entry_results(task)) and bool(manager._entry_results(task))

    def archive_virtual_status(
        self,
        manager: TaskManager,
        db: Session,
        task: BinarySecurityTask,
    ) -> str | None:
        if not self.has_authoritative_success_payload(manager, db, task):
            return None
        return "success"
