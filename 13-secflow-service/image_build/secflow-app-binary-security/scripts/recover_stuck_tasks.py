from __future__ import annotations

import argparse
import asyncio
import json
from datetime import datetime

from app.config import load_config
from app.model import BinarySecurityStageItem, BinarySecurityTask, get_session_factory
from app.service.task_manager import get_task_manager
from app.service.task_queue import get_task_queue


def _now_iso() -> str:
    return datetime.utcnow().isoformat()


async def main() -> None:
    parser = argparse.ArgumentParser(description="Recover stuck binary security tasks")
    parser.add_argument("--project-id", dest="project_id", help="Only recover tasks in the given project")
    parser.add_argument("--task-id", dest="task_id", help="Only recover the given task")
    parser.add_argument("--dry-run", dest="dry_run", action="store_true", help="Only print what would be changed")
    args = parser.parse_args()

    load_config()
    manager = get_task_manager()
    session = get_session_factory()()
    try:
        queue = get_task_queue()
        task_queue_key = manager.cfg.queue.task_queue_key
        operation_queue_key = manager.cfg.queue.operation_queue_key
        task_queue_runtime_before = await queue.dedupe_orphans(task_queue_key)
        operation_queue_runtime_before = await queue.dedupe_orphans(operation_queue_key)
        query = session.query(BinarySecurityTask)
        if args.project_id:
            query = query.filter(BinarySecurityTask.project_id == args.project_id)
        if args.task_id:
            query = query.filter(BinarySecurityTask.id == args.task_id)
        tasks = query.all()
        task_ids = {str(task.id or "").strip() for task in tasks if str(task.id or "").strip()}

        queue_info_by_project = {}
        recoverable_before = []
        for task in tasks:
            project_id = str(task.project_id or "").strip()
            queue_info = queue_info_by_project.get(project_id)
            if queue_info is None:
                queue_info = manager._build_queue_info(session, project_id=project_id)
                queue_info_by_project[project_id] = queue_info
            queue_state, reason = manager._task_queue_state(task, queue_info)
            if (
                str(task.status or "").strip().lower() in {"pending", "dispatching", "running"}
                or queue_state in {"db_pending_not_enqueued", "tail_reconciling", "leased", "dispatching"}
            ):
                recoverable_before.append(
                    {
                        "task_id": task.id,
                        "project_id": task.project_id,
                        "status": task.status,
                        "runtime_phase": task.runtime_phase,
                        "queue_state": queue_state,
                        "recoverable_reason": reason,
                        "current_stage": task.current_stage,
                        "dispatcher_instance_id": task.dispatcher_instance_id,
                        "lease_expires_at": _iso_or_none(task.lease_expires_at),
                        "dispatch_started_at": _iso_or_none(task.dispatch_started_at),
                        "tail_reconcile_state": getattr(task, "tail_reconcile_state", None),
                    }
                )

        stale_items_query = session.query(BinarySecurityStageItem).filter(
            BinarySecurityStageItem.status.in_(["running", "dispatching"]),
        )
        if args.task_id:
            stale_items_query = stale_items_query.filter(BinarySecurityStageItem.task_id == args.task_id)
        elif task_ids:
            stale_items_query = stale_items_query.filter(BinarySecurityStageItem.task_id.in_(sorted(task_ids)))
        stale_items = stale_items_query.all()
        reclaimed_items_before = []
        for item in stale_items:
            reclaimed_items_before.append(
                {
                    "item_id": item.id,
                    "task_id": item.task_id,
                    "stage_name": item.stage_name,
                    "status": item.status,
                    "downstream_task_id": item.downstream_task_id,
                    "updated_at": _iso_or_none(item.updated_at),
                    "started_at": _iso_or_none(item.started_at),
                }
            )

        reclaim_summary = {
            "stale_dispatching_reclaimed": False,
            "stale_stage_item_reclaimed": False,
            "stale_running_reclaimed": False,
            "released_running_requeued": False,
            "recovered_missing_terminal_events": False,
        }
        force_requeued_task_ids: list[str] = []
        if not args.dry_run:
            cleaned_task_orphans = await queue.cleanup_dedupe_orphans(task_queue_key)
            cleaned_operation_orphans = await queue.cleanup_dedupe_orphans(operation_queue_key)
            (
                reclaim_summary["stale_dispatching_reclaimed"],
                reclaim_summary["stale_stage_item_reclaimed"],
                reclaim_summary["stale_running_reclaimed"],
                reclaim_summary["released_running_requeued"],
                reclaim_summary["recovered_missing_terminal_events"],
            ) = manager._run_parent_reclaim_pass(session)
            session.commit()
            await manager._reconcile_work_queues(session, force=True)
            session.commit()

            refreshed_tasks = query.all()
            queue_info_by_project.clear()
            for task in refreshed_tasks:
                project_id = str(task.project_id or "").strip()
                queue_info = queue_info_by_project.get(project_id)
                if queue_info is None:
                    queue_info = manager._build_queue_info(session, project_id=project_id)
                    queue_info_by_project[project_id] = queue_info
                queue_state, _ = manager._task_queue_state(task, queue_info)
                if queue_state == "db_pending_not_enqueued":
                    await queue.force_requeue_task(task.id)
                    force_requeued_task_ids.append(str(task.id))

        task_queue_runtime_after = await queue.dedupe_orphans(task_queue_key)
        operation_queue_runtime_after = await queue.dedupe_orphans(operation_queue_key)
        refreshed_tasks = query.all()
        queue_info_by_project.clear()
        recoverable_after = []
        for task in refreshed_tasks:
            project_id = str(task.project_id or "").strip()
            queue_info = queue_info_by_project.get(project_id)
            if queue_info is None:
                queue_info = manager._build_queue_info(session, project_id=project_id)
                queue_info_by_project[project_id] = queue_info
            queue_state, reason = manager._task_queue_state(task, queue_info)
            recoverable_after.append(
                {
                    "task_id": task.id,
                    "status": task.status,
                    "runtime_phase": task.runtime_phase,
                    "queue_state": queue_state,
                    "recoverable_reason": reason,
                    "current_stage": task.current_stage,
                    "dispatcher_instance_id": task.dispatcher_instance_id,
                    "lease_expires_at": _iso_or_none(task.lease_expires_at),
                    "dispatch_started_at": _iso_or_none(task.dispatch_started_at),
                    "tail_reconcile_state": getattr(task, "tail_reconcile_state", None),
                }
            )

        print(
            json.dumps(
                {
                    "checked_at": _now_iso(),
                    "dry_run": args.dry_run,
                    "task_filter": {
                        "project_id": args.project_id,
                        "task_id": args.task_id,
                    },
                    "queue_runtime": {
                        "task_queue_before": task_queue_runtime_before,
                        "operation_queue_before": operation_queue_runtime_before,
                        **(
                            {
                                "task_queue_cleaned": cleaned_task_orphans,
                                "operation_queue_cleaned": cleaned_operation_orphans,
                            }
                            if not args.dry_run
                            else {}
                        ),
                        "task_queue_after": task_queue_runtime_after,
                        "operation_queue_after": operation_queue_runtime_after,
                    },
                    "reclaim_summary": reclaim_summary,
                    "force_requeued_task_ids": force_requeued_task_ids,
                    "recoverable_before": recoverable_before,
                    "recoverable_after": recoverable_after,
                    "reclaimed_running_items_before": reclaimed_items_before,
                    "recoverable_task_count": len(recoverable_before),
                    "reclaimed_running_item_count": len(reclaimed_items_before),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    finally:
        session.close()


def _iso_or_none(value) -> str | None:
    return value.isoformat() if value else None


if __name__ == "__main__":
    asyncio.run(main())
