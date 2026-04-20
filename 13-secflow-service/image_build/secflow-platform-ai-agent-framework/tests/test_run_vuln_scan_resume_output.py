from __future__ import annotations

import json
from pathlib import Path

from app.pi_vuln_core.review.state import ReviewState
from run_vuln_scan import (
    _collect_resume_diagnostics,
    _format_resume_diagnostic_lines,
    _write_resume_preview_file,
)


def test_collect_resume_diagnostics_reads_cycle_files_and_review_state(tmp_path: Path) -> None:
    atomic_dir = tmp_path / "atomic"
    meta_dir = atomic_dir / "_meta"
    (meta_dir / "review_summaries").mkdir(parents=True, exist_ok=True)
    (meta_dir / "cycle_metrics").mkdir(parents=True, exist_ok=True)
    (meta_dir / "blockers").mkdir(parents=True, exist_ok=True)

    (meta_dir / "review_summaries" / "cycle_003.json").write_text(
        json.dumps(
            {
                "cycle": 3,
                "workflow_mode": "closure",
                "outcome": "global_failed",
                "result_review": {
                    "passed_count": 2,
                    "failed_count": 1,
                },
                "global_review": {
                    "open_blockers": [
                        {
                            "id": "export-followthrough:send-socket",
                            "target": "IPSEC_SOCK_SendToSocket",
                            "required_action": "继续跟入 send socket 链",
                        }
                    ]
                },
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    (meta_dir / "cycle_metrics" / "cycle_003.json").write_text(
        json.dumps(
            {
                "cycle": 3,
                "workflow_mode": "discovery",
                "scores": {
                    "export_followthrough": 0.5,
                    "report_completeness": 0.8,
                },
                "plateau_status": {
                    "stagnant": True,
                    "streak": 2,
                    "workflow_mode": "closure",
                    "switched_to_closure": True,
                    "abort": False,
                    "reason": "open blocker IDs 未变化",
                },
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    (meta_dir / "blockers" / "cycle_003.json").write_text(
        json.dumps(
            {
                "cycle": 3,
                "blockers": [
                    {
                        "id": "export-followthrough:send-socket",
                        "target": "IPSEC_SOCK_SendToSocket",
                        "required_action": "继续跟入 send socket 链",
                    },
                    {
                        "id": "limitations:section-7",
                        "target": "summary.md#7",
                        "required_action": "补全局限性章节",
                    },
                ],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    state = ReviewState()
    state.activate_closure_mode(3, "open blocker IDs 未变化")
    state.mark_result_passed("result_001.md", 1, "sha1")
    state.mark_result_passed("result_002.md", 2, "sha2")
    state.record_result_failures([], 0)

    diagnostics = _collect_resume_diagnostics(str(atomic_dir), review_state=state)

    assert diagnostics["latest_cycle"] == 3
    assert diagnostics["latest_outcome"] == "global_failed"
    assert diagnostics["workflow_mode"] == "closure"
    assert diagnostics["passed_count"] == 2
    assert diagnostics["failed_count"] == 1
    assert diagnostics["open_blocker_count"] == 2
    assert diagnostics["plateau_status"]["stagnant"] is True
    assert diagnostics["plateau_status"]["switched_to_closure"] is True
    assert diagnostics["plateau_reason"] == "open blocker IDs 未变化"
    assert diagnostics["scores"]["export_followthrough"] == 0.5
    assert diagnostics["blockers_preview"][0].startswith("[export-followthrough:send-socket]")


def test_format_resume_diagnostic_lines_includes_mode_plateau_and_blockers() -> None:
    diagnostics = {
        "latest_cycle": 3,
        "latest_outcome": "global_failed",
        "workflow_mode": "closure",
        "passed_count": 2,
        "failed_count": 1,
        "open_blocker_count": 2,
        "scores": {
            "export_followthrough": 0.5,
            "report_completeness": 0.8,
        },
        "plateau_status": {
            "stagnant": True,
            "streak": 2,
            "switched_to_closure": True,
            "abort": False,
        },
        "plateau_reason": "open blocker IDs 未变化；summary/result 未表现出收缩趋势",
        "blockers_preview": [
            "[export-followthrough:send-socket] IPSEC_SOCK_SendToSocket | 继续跟入 send socket 链",
            "[limitations:section-7] summary.md#7 | 补全局限性章节",
        ],
    }

    lines = _format_resume_diagnostic_lines(
        diagnostics,
        completed_cycles=3,
        extra_cycles=2,
    )
    rendered = "\n".join(lines)

    assert "轮次窗口:   3 -> 5" in rendered
    assert "当前模式:   closure" in rendered
    assert "最近评审:   Cycle 3 / global_failed" in rendered
    assert "已通过结果: 2" in rendered
    assert "待修结果:   1" in rendered
    assert "OpenBlockers: 2" in rendered
    assert "Plateau:    stagnant=yes, streak=2, closure_switch=yes, abort=no" in rendered
    assert "Plateau原因: open blocker IDs 未变化；summary/result 未表现出收缩趋势" in rendered
    assert "主要Blocker:" in rendered
    assert "[export-followthrough:send-socket]" in rendered


def test_write_resume_preview_file_persists_diagnostics(tmp_path: Path) -> None:
    atomic_dir = tmp_path / "atomic"
    diagnostics = {
        "workflow_mode": "closure",
        "open_blocker_count": 2,
        "plateau_reason": "open blocker IDs 未变化",
    }

    preview_path = _write_resume_preview_file(
        run_dir=str(tmp_path / "run"),
        atomic_work_dir=str(atomic_dir),
        current_status="failed",
        completed_cycles=3,
        extra_cycles=2,
        worker_session_id="session_pi-worker_1",
        model_display="github-copilot/gpt-5.4",
        thinking="xhigh",
        task_file=str(tmp_path / "task.md"),
        diagnostics=diagnostics,
    )

    payload = json.loads(Path(preview_path).read_text(encoding="utf-8"))
    assert payload["current_status"] == "failed"
    assert payload["resume_total_cycle_limit"] == 5
    assert payload["worker_session_id"] == "session_pi-worker_1"
    assert payload["model"] == "github-copilot/gpt-5.4"
    assert payload["diagnostics"]["workflow_mode"] == "closure"
    assert payload["diagnostics"]["open_blocker_count"] == 2
