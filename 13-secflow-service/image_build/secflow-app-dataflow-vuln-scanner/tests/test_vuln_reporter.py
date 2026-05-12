from __future__ import annotations

import hashlib
import re
from datetime import datetime

from app.models.database import RunIndex, RunIndexResult, TriggerTask, WorkflowExecution
from app.services.vuln_reporter import VulnReportService


def test_build_report_id_is_readable_and_stable():
    service = VulnReportService()
    trigger = TriggerTask(id="task-1", project_id="default", started_at=datetime(2026, 5, 12, 10, 11, 12))
    execution = WorkflowExecution(id="exec-1", started_at=datetime(2026, 5, 12, 10, 11, 13))
    run_index = RunIndex(id="run-1", started_at=datetime(2026, 5, 12, 10, 11, 14))
    result = RunIndexResult(filename="result_001.md")

    report_id = service._build_report_id(
        trigger=trigger,
        execution=execution,
        run_index=run_index,
        result=result,
        sequence_no=7,
        sequence_width=3,
    )

    assert re.fullmatch(r"DFVS-20260512-101114-007-[0-9A-F]{6}", report_id)
    assert report_id == service._build_report_id(
        trigger=trigger,
        execution=execution,
        run_index=run_index,
        result=result,
        sequence_no=7,
        sequence_width=3,
    )


def test_payload_uses_readable_finding_id_and_legacy_fingerprint(tmp_path):
    result_path = tmp_path / "result_001.md"
    result_path.write_text("# Demo finding\n\nsummary line\n", encoding="utf-8")

    service = VulnReportService()
    trigger = TriggerTask(
        id="task-1",
        project_id="default",
        task_purpose="normal",
        started_at=datetime(2026, 5, 12, 10, 11, 12),
    )
    execution = WorkflowExecution(
        id="exec-1",
        owner_pod_id="pod-1",
        started_at=datetime(2026, 5, 12, 10, 11, 13),
    )
    run_index = RunIndex(
        id="run-1",
        run_name="run-001",
        run_root_path=str(tmp_path),
        status="succeeded",
        started_at=datetime(2026, 5, 12, 10, 11, 14),
    )
    result = RunIndexResult(
        filename="result_001.md",
        path=str(result_path),
        title="Demo finding",
        confidence=0.91,
    )

    payload = service._payload_for_result(
        trigger=trigger,
        execution=execution,
        run_index=run_index,
        result=result,
        sequence_no=1,
        sequence_width=3,
    )

    assert re.fullmatch(r"DFVS-20260512-101114-001-[0-9A-F]{6}", payload["report_id"])
    assert payload["metadata"]["source"]["finding_id"] == payload["report_id"]
    assert payload["metadata"]["dataflow_vuln_scanner"]["finding_id"] == payload["report_id"]
    assert payload["reporter"]["version"] == "1.0.0"
    assert payload["evidence"]["references"] == [{"path": str(result_path), "kind": "report"}]
    assert payload["fingerprint"] == hashlib.sha256(
        "dfvs:task-1:exec-1:result_001.md:Demo finding".encode("utf-8")
    ).hexdigest()
