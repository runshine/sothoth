from __future__ import annotations

from typing import Any, TYPE_CHECKING

from sqlalchemy.orm import Session

from app.model import BinarySecurityStageRun, BinarySecurityTask
from app.service.stages.base import BinarySecurityStageHandler
from app.service.task import shared as task_shared
from app.time_utils import now_local

if TYPE_CHECKING:
    from app.service.task_manager import TaskManager


MODULE_SELECTION_MODE_AUTO = "auto"
MODULE_SELECTION_MODE_MANUAL_CONFIRM = "manual_confirm"
TASK_STATUS_PENDING_MODULE_CONFIRMATION = "pending_module_confirmation"
NO_CANDIDATE_MODULES_FAILURE_MESSAGE = "系统分析已完成，但未发现匹配所选风险等级的风险模块"


def _no_candidate_modules_failure() -> dict[str, str]:
    return {
        "failure_code": "no_candidate_modules",
        "failure_category": "business",
        "failure_message": NO_CANDIDATE_MODULES_FAILURE_MESSAGE,
        "error": NO_CANDIDATE_MODULES_FAILURE_MESSAGE,
    }


class SystemAnalysisStageHandler(BinarySecurityStageHandler):
    def __init__(self) -> None:
        super().__init__(stage_name="system_analysis")

    def build_inputs(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> list[dict[str, Any]]:
        return manager._system_analysis_inputs(task, db=db)

    def has_runnable_inputs(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> bool:
        return bool(self.build_inputs(manager, db, task))

    def continue_stage_input_error(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> str | None:
        if not manager._system_analysis_inputs(task, db=db):
            return "系统分析缺少可执行输入，不能继续"
        return None

    def archive_input_signature(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> dict[str, Any]:
        del db
        summary = dict(task.summary or {})
        selected_modules = [
            str(module.get("module_key") or "").strip()
            for module in list(summary.get("selected_modules") or [])
            if isinstance(module, dict) and str(module.get("module_key") or "").strip()
        ]
        candidate_modules = [
            str(module.get("module_key") or "").strip()
            for module in list(summary.get("candidate_modules") or [])
            if isinstance(module, dict) and str(module.get("module_key") or "").strip()
        ]
        return {
            "stage_name": self.stage_name,
            "selected_module_count": len(selected_modules),
            "selected_module_keys": selected_modules,
            "candidate_module_count": len(candidate_modules),
        }

    def archive_signature_has_runnable_inputs(self, signature: dict[str, Any] | None) -> bool:
        payload = dict(signature or {})
        return int(payload.get("selected_module_count") or 0) > 0

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

    def refresh_summary_from_items(self, manager: TaskManager, db: Session, task: BinarySecurityTask) -> None:
        stage_run = db.query(BinarySecurityStageRun).filter(
            BinarySecurityStageRun.task_id == task.id,
            BinarySecurityStageRun.stage_name == self.stage_name,
        ).first()
        if not stage_run:
            return
        items = manager._stage_items(db, task.id, self.stage_name)
        success: list[dict[str, Any]] = []
        failed = [
            {"status": item.status, "error": item.error_message, "item_key": item.item_key}
            for item in items
            if item.status in {"failed", "cancelled", "downstream_missing"}
        ]
        archive_jobs_by_item = manager._stage_archive_jobs_by_item(db, task.id, self.stage_name)
        all_modules: list[dict[str, Any]] = []
        for item in items:
            if item.status != "success":
                continue
            result = manager._load_stage_item_result_payload(item)
            item_modules = manager._system_analysis_modules_from_item(
                task,
                item,
                archive_jobs=archive_jobs_by_item.get(str(item.id or ""), []),
            )
            all_modules.extend(item_modules)
            success.append(
                {
                    **result,
                    "modules": manager._lightweight_modules_for_storage(item_modules),
                    "module_count": len(item_modules),
                }
            )
        status = manager._aggregate_item_statuses([item.status for item in items])
        candidate_modules = manager._filter_candidate_modules(
            all_modules,
            manager._module_selection_candidate_levels(task),
        )
        if (
            not candidate_modules
            and manager._task_type(task) == "source"
            and any(not manager._normalize_module_risk_level(module.get("risk_level"), module.get("risk_score")) for module in all_modules)
        ):
            candidate_modules = [dict(module) for module in all_modules]
        summary = dict(task.summary or {})
        existing_selected_modules = [
            dict(module)
            for module in list(summary.get("selected_modules") or [])
            if isinstance(module, dict) and str(module.get("module_key") or "").strip()
        ]
        candidate_keys = {
            str(module.get("module_key") or "").strip()
            for module in candidate_modules
            if str(module.get("module_key") or "").strip()
        }
        existing_selected_map = {
            str(module.get("module_key") or "").strip(): module
            for module in existing_selected_modules
        }
        confirmed_selected_modules = [
            {
                **dict(next(module for module in candidate_modules if str(module.get("module_key") or "").strip() == module_key)),
                **{
                    "selected_by": existing_selected_map[module_key].get("selected_by"),
                    "selected_at": existing_selected_map[module_key].get("selected_at"),
                },
            }
            for module_key in existing_selected_map.keys()
            if module_key in candidate_keys
        ]
        has_confirmed_manual_selection = any(
            str(module.get("selected_by") or "").strip() == MODULE_SELECTION_MODE_MANUAL_CONFIRM
            for module in confirmed_selected_modules
        )
        selected_modules: list[dict[str, Any]] = []
        if status in {"success", "partial_success"} and candidate_modules:
            if manager._module_selection_mode(task) == MODULE_SELECTION_MODE_AUTO:
                selected_modules = manager._mark_selected_modules(
                    candidate_modules,
                    selected_by=MODULE_SELECTION_MODE_AUTO,
                )
            elif has_confirmed_manual_selection:
                selected_modules = confirmed_selected_modules
            else:
                manager._set_task_status(
                    db,
                    task,
                    TASK_STATUS_PENDING_MODULE_CONFIRMATION,
                    reason="系统分析完成，等待人工确认模块",
                    source="stage_system_analysis",
                    stage_name=self.stage_name,
                )
                manager._record_event(
                    db,
                    task,
                    "module_selection_required",
                    "系统分析已同步完成，等待人工确认模块",
                    stage_name=self.stage_name,
                    payload={"candidate_module_count": len(candidate_modules)},
                )
        downstream_stage_runs = db.query(BinarySecurityStageRun).filter(BinarySecurityStageRun.task_id == task.id).all()
        stage_sequence = manager._stage_sequence_for_task(task)
        has_active_downstream_stage = False
        if self.stage_name in stage_sequence:
            current_index = stage_sequence.index(self.stage_name)
            downstream_stage_names = set(stage_sequence[current_index + 1 :])
            has_active_downstream_stage = any(
                str(run.stage_name or "").strip() in downstream_stage_names
                and str(run.status or "").strip() in {"running", "dispatching", "pending", "queued", "applying", "success", "partial_success"}
                for run in downstream_stage_runs
            )
        no_candidate_modules_failure = status == "success" and not failed and not candidate_modules and not has_active_downstream_stage
        if no_candidate_modules_failure:
            failure = _no_candidate_modules_failure()
            status = "failed"
            failed = failed or [{"status": "failed", **failure}]
        summary.update(
            {
                "system_analysis_results": manager._lightweight_system_analysis_items(success),
                "system_analysis_modules": manager._lightweight_modules_for_storage(all_modules),
                "system_analysis_module_count": len(all_modules),
                "candidate_modules": candidate_modules,
                "selected_modules": selected_modules,
                "high_risk_modules": selected_modules,
                **(_no_candidate_modules_failure() if no_candidate_modules_failure else {}),
            }
        )
        task.summary = summary
        module_metrics = manager._module_metrics(all_modules, candidate_modules, selected_modules)
        task.metrics = {
            **(task.metrics or {}),
            **module_metrics,
        }
        stage_run.status = "waiting_confirmation" if task.status == TASK_STATUS_PENDING_MODULE_CONFIRMATION else status
        stage_run.finished_at = None if stage_run.status in {"running", "pending", "queued"} else (stage_run.finished_at or now_local())
        stage_run.started_at = stage_run.started_at or now_local()
        stage_run.counts = manager._stage_counts(db, stage_run)
        stage_run.last_error = failed[0].get("error") if failed and status == "failed" else None
        if no_candidate_modules_failure and stage_run.last_error == NO_CANDIDATE_MODULES_FAILURE_MESSAGE:
            task.last_error = stage_run.last_error
            manager._record_event(
                db,
                task,
                "system_analysis_no_candidate_modules",
                NO_CANDIDATE_MODULES_FAILURE_MESSAGE,
                level="error",
                stage_name=self.stage_name,
                payload=_no_candidate_modules_failure(),
            )
        else:
            task.last_error = None
        manager._persist_stage_run_output_summary(
            task,
            stage_run,
            {
                "items": manager._lightweight_system_analysis_items(success),
                "failed_items": failed,
                "success_count": len(success),
                "failed_count": len(failed),
                "module_count": len(all_modules),
                "high_risk_module_count": module_metrics["high_risk_module_count"],
                "medium_risk_module_count": module_metrics["medium_risk_module_count"],
                "low_risk_module_count": module_metrics["low_risk_module_count"],
                "candidate_module_count": len(candidate_modules),
                "selected_module_count": len(selected_modules),
                "status_synced": True,
                "sync_status": stage_run.status,
                "error": stage_run.last_error,
                **(_no_candidate_modules_failure() if no_candidate_modules_failure else {}),
                **stage_run.counts,
            },
        )
        manager._merge_task_stage_summary_entry(
            task,
            stage_run,
            {
                "sequence_no": stage_run.sequence_no,
                "status": stage_run.status,
                "total_items": int((stage_run.counts or {}).get("total_items") or len(items)),
                "success_items": int((stage_run.counts or {}).get("success_items") or len(success)),
                "failed_items": int((stage_run.counts or {}).get("failed_items") or len(failed)),
                "orchestration_failed_items": int((stage_run.counts or {}).get("failed_items") or len(failed)),
                "downstream_missing_items": int((stage_run.counts or {}).get("downstream_missing_items") or 0),
                "skipped_items": int((stage_run.counts or {}).get("skipped_items") or 0),
                "running_items": int((stage_run.counts or {}).get("running_items") or 0),
                "cancelled_items": int((stage_run.counts or {}).get("cancelled_items") or 0),
                "downstream_status_counts": {},
                "started_at": task_shared._isoformat_or_none(stage_run.started_at),
                "finished_at": task_shared._isoformat_or_none(stage_run.finished_at),
                "last_error": stage_run.last_error,
            },
        )
