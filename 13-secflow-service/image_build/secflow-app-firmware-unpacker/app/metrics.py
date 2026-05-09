"""Prometheus text metrics for firmware unpacker runtime state."""

from __future__ import annotations

from collections import Counter

from fastapi import APIRouter, Response


router = APIRouter(tags=["Metrics"])


def _prom_escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _line(name: str, value: int | float, labels: dict[str, str] | None = None) -> str:
    if labels:
        label_text = ",".join(f'{key}="{_prom_escape(val)}"' for key, val in sorted(labels.items()))
        return f"{name}{{{label_text}}} {value}"
    return f"{name} {value}"


def collect_metrics() -> str:
    from app.model import TaskStatus, UnpackTask, get_db_session
    from app.services.worker import get_cluster_snapshot

    db = get_db_session()
    try:
        tasks = db.query(UnpackTask).all()
    finally:
        db.close()

    status_counts = Counter(str(task.status or "unknown") for task in tasks)
    cluster = get_cluster_snapshot()
    lines = [
        "# HELP firmware_unpacker_tasks_total Firmware unpacker tasks by status.",
        "# TYPE firmware_unpacker_tasks_total gauge",
    ]
    for status in [
        TaskStatus.PENDING.value,
        TaskStatus.RUNNING.value,
        TaskStatus.CANCELLING.value,
        TaskStatus.CANCELLED.value,
        TaskStatus.SUCCESS.value,
        TaskStatus.FAILED.value,
    ]:
        lines.append(_line("firmware_unpacker_tasks_total", status_counts.get(status, 0), {"status": status}))

    completed_durations = []
    token_total = 0
    for task in tasks:
        if task.started_at and task.completed_at:
            completed_durations.append(max(0.0, (task.completed_at - task.started_at).total_seconds()))
        token_total += int(task.total_tokens or 0)

    lines.extend(
        [
            "# HELP firmware_unpacker_task_duration_seconds_sum Sum of completed task durations.",
            "# TYPE firmware_unpacker_task_duration_seconds_sum counter",
            _line("firmware_unpacker_task_duration_seconds_sum", round(sum(completed_durations), 3)),
            "# HELP firmware_unpacker_task_duration_seconds_count Count of completed task durations.",
            "# TYPE firmware_unpacker_task_duration_seconds_count counter",
            _line("firmware_unpacker_task_duration_seconds_count", len(completed_durations)),
            "# HELP firmware_unpacker_agentflow_active_runs Active AgentFlow runs known to the service.",
            "# TYPE firmware_unpacker_agentflow_active_runs gauge",
            _line("firmware_unpacker_agentflow_active_runs", int(cluster.get("agentflow_active_runs") or 0)),
            "# HELP firmware_unpacker_agentflow_max_concurrent Configured maximum concurrent AgentFlow runs.",
            "# TYPE firmware_unpacker_agentflow_max_concurrent gauge",
            _line("firmware_unpacker_agentflow_max_concurrent", int(cluster.get("agentflow_max_concurrent") or 0)),
            "# HELP firmware_unpacker_agentflow_runs_dir_usage_mb AgentFlow runs directory usage in MiB.",
            "# TYPE firmware_unpacker_agentflow_runs_dir_usage_mb gauge",
            _line("firmware_unpacker_agentflow_runs_dir_usage_mb", float(cluster.get("agentflow_runs_dir_usage_mb") or 0.0)),
            "# HELP firmware_unpacker_agentflow_tokens_total Total AgentFlow tokens recorded on tasks.",
            "# TYPE firmware_unpacker_agentflow_tokens_total counter",
            _line("firmware_unpacker_agentflow_tokens_total", token_total),
        ]
    )
    return "\n".join(lines) + "\n"


@router.get("/metrics")
@router.get("/api/app/firmware-unpacker/metrics")
async def metrics() -> Response:
    return Response(content=collect_metrics(), media_type="text/plain; version=0.0.4")
