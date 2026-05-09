"""Stage: validate the matched-skill executor result."""

from __future__ import annotations

from typing import Any


def run(payload: dict[str, Any], nodes: dict[str, Any] | None = None) -> None:
    nodes = nodes or {}
    executor = nodes.get("skill_executor") or {}
    executor_status = str(executor.get("status") or "").strip()
    executor_output = str(executor.get("output") or "")

    print("AGENTFLOW_PROGRESS stage=skill_reviewer event=start", flush=True)
    if "AGENTFLOW_EXECUTOR_SKIPPED" in executor_output or "SKIPPED" in executor_output:
        reason = "SKIPPED_NO_SKILL"
        if "reason=" in executor_output:
            reason = executor_output.split("reason=", 1)[1].split()[0].strip()
        print(f"AGENTFLOW_PROGRESS stage=skill_reviewer event=finish result=skipped reason={reason}", flush=True)
        print(f"AGENTFLOW_REVIEW_SKIPPED reason={reason}")
    elif executor_status != "completed":
        print(
            f"AGENTFLOW_PROGRESS stage=skill_reviewer event=finish "
            f"result=fail executor_status={executor_status}",
            flush=True,
        )
        print("AGENTFLOW_REVIEW_FAIL category=STRUCTURAL_FAILURE reason=executor_failed")
    elif any(token in executor_output.lower() for token in ("fail", "failed", "invalid", "error")):
        print("AGENTFLOW_PROGRESS stage=skill_reviewer event=finish result=fail reason=executor_reported_failure", flush=True)
        print("AGENTFLOW_REVIEW_FAIL category=STRUCTURAL_FAILURE reason=executor_reported_failure")
    elif executor_output.strip():
        print("AGENTFLOW_PROGRESS stage=skill_reviewer event=finish result=success", flush=True)
        print("AGENTFLOW_REVIEW_SUCCESS")
    else:
        print("AGENTFLOW_PROGRESS stage=skill_reviewer event=finish result=fail reason=empty_executor_output", flush=True)
        print("AGENTFLOW_REVIEW_FAIL category=STRUCTURAL_FAILURE reason=empty_executor_output")

