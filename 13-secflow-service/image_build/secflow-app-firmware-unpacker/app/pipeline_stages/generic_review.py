"""Stage: validate the generic firmware unpack result."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def run(payload: dict[str, Any], nodes: dict[str, Any] | None = None) -> None:
    nodes = nodes or {}
    executor = nodes.get("generic_executor") or {}
    executor_status = str(executor.get("status") or "").strip()
    executor_output = str(executor.get("output") or "")

    print("AGENTFLOW_PROGRESS stage=generic_reviewer event=start", flush=True)
    if "AGENTFLOW_EXECUTOR_SKIPPED" in executor_output or "SKIPPED" in executor_output:
        reason = "SKIPPED"
        if "reason=" in executor_output:
            reason = executor_output.split("reason=", 1)[1].split()[0].strip()
        print(f"AGENTFLOW_PROGRESS stage=generic_reviewer event=finish result=skipped reason={reason}", flush=True)
        print(f"AGENTFLOW_REVIEW_SKIPPED reason={reason}")
    elif executor_status != "completed":
        print(
            f"AGENTFLOW_PROGRESS stage=generic_reviewer event=finish "
            f"result=fail executor_status={executor_status}",
            flush=True,
        )
        print("AGENTFLOW_REVIEW_FAIL category=STRUCTURAL_FAILURE reason=executor_failed")
    else:
        output = Path(payload["output_path"])
        summary = output / "summary.txt"
        artifacts = [path for path in output.rglob("*") if path.is_file() and path.name not in {"summary.txt", "reason.txt"}]
        if not summary.is_file() or summary.stat().st_size == 0:
            print("AGENTFLOW_PROGRESS stage=generic_reviewer event=finish result=fail reason=missing_summary", flush=True)
            print("AGENTFLOW_REVIEW_FAIL category=STRUCTURAL_FAILURE reason=missing_summary")
        elif not artifacts:
            print("AGENTFLOW_PROGRESS stage=generic_reviewer event=finish result=fail reason=empty_output", flush=True)
            print("AGENTFLOW_REVIEW_FAIL category=CONTENT_MISSING reason=empty_output")
        else:
            print(f"AGENTFLOW_PROGRESS stage=generic_reviewer event=finish result=success artifacts={len(artifacts)}", flush=True)
            print("AGENTFLOW_REVIEW_SUCCESS")

