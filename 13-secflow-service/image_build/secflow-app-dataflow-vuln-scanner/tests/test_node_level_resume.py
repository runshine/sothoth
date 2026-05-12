from __future__ import annotations

import json
from pathlib import Path

from app.pi_vuln_core.config.models import FrameworkConfig
from app.pi_vuln_core.engine import checkpoint as checkpoint_module
from app.pi_vuln_core.engine.checkpoint import record_step_checkpoint
from app.pi_vuln_core.resume import build_resume_plan, rebuild_review_state
from app.pi_vuln_core.review.result_review import ResultReviewExecutor
from app.pi_vuln_core.review.state import calculate_file_sha256
from app.services import run_inspector as run_inspector_module
from app.services.run_inspector import inspect_run_detail
from run_vuln_scan import generate_config


def _make_resume_run(tmp_path: Path, *, reflection_passes: int = 1) -> tuple[Path, Path, FrameworkConfig]:
    run_dir = tmp_path / "node-resume-run"
    run_dir.mkdir(parents=True, exist_ok=True)
    task_file = tmp_path / "task.md"
    task_file.write_text("# node resume task\n", encoding="utf-8")

    config_payload = generate_config(
        run_dir=str(run_dir),
        task_file=str(task_file),
        run_name="node_resume",
        model="mock-provider/mock-model",
        max_cycles=3,
        review_profile="balanced",
    )
    config_payload["workflows"]["atomic"][0]["engine"]["reflection_passes_per_cycle"] = reflection_passes
    (run_dir / "config.json").write_text(
        json.dumps(config_payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    config = FrameworkConfig.model_validate(config_payload)

    atomic_dir = (
        run_dir
        / "run"
        / "workspace"
        / "pipeline_node_resume_run_001"
        / "stage_01_vuln_scan"
        / "vuln_scan_node_resume"
    )
    (atomic_dir / "_meta").mkdir(parents=True, exist_ok=True)
    (atomic_dir / "input").mkdir(parents=True, exist_ok=True)
    (atomic_dir / "input" / "task.md").write_text("# copied task\n", encoding="utf-8")

    call_dir = atomic_dir / "sessions" / "session_pi-worker_1" / "calls" / "001_pi_worker"
    call_dir.mkdir(parents=True, exist_ok=True)
    (call_dir / "request.json").write_text(
        json.dumps({"agent_id": "pi-worker"}, ensure_ascii=False),
        encoding="utf-8",
    )
    return run_dir, atomic_dir, config


def test_resume_plan_reruns_nonterminal_worker_node(tmp_path: Path) -> None:
    run_dir, atomic_dir, _ = _make_resume_run(tmp_path)
    record_step_checkpoint(
        atomic_dir,
        cycle=1,
        phase="worker",
        step_key="worker::work",
        status="started",
        agent_id="pi-worker",
        session_id="session_pi-worker_1",
    )

    _, plan = build_resume_plan(run_dir)

    assert plan.resume_start_cycle == 0
    assert plan.resume_target_phase == "worker"
    assert plan.resume_target_step_key == "worker::work"
    assert plan.resume_cursor["source"]["terminal_status"] is False


def test_resume_plan_moves_completed_worker_to_first_reflection(tmp_path: Path) -> None:
    run_dir, atomic_dir, _ = _make_resume_run(tmp_path)
    record_step_checkpoint(
        atomic_dir,
        cycle=1,
        phase="worker",
        step_key="worker::work",
        status="completed",
        agent_id="pi-worker",
        session_id="session_pi-worker_1",
        extra={"prompt_kind": "initial"},
    )

    _, plan = build_resume_plan(run_dir)

    assert plan.resume_target_phase == "reflect"
    assert plan.resume_target_step_key == "reflect::reflect_completeness::pass_01"
    assert plan.resume_cursor["source"]["terminal_status"] is True


def test_resume_plan_moves_partial_salvaged_worker_to_summary(tmp_path: Path) -> None:
    run_dir, atomic_dir, _ = _make_resume_run(tmp_path)
    record_step_checkpoint(
        atomic_dir,
        cycle=1,
        phase="worker",
        step_key="worker::work",
        status="partial_salvaged",
        agent_id="pi-worker",
        session_id="session_pi-worker_1",
        extra={"prompt_kind": "initial"},
    )

    _, plan = build_resume_plan(run_dir)

    assert plan.resume_target_phase == "summary"
    assert plan.resume_target_step_key == "summary"


def test_resume_plan_moves_completed_reflection_pass_to_next_pass(tmp_path: Path) -> None:
    run_dir, atomic_dir, _ = _make_resume_run(tmp_path, reflection_passes=2)
    record_step_checkpoint(
        atomic_dir,
        cycle=1,
        phase="reflect",
        step_key="reflect::reflect_completeness::pass_01",
        status="completed",
        agent_id="pi-worker",
        session_id="session_pi-worker_1",
    )

    _, plan = build_resume_plan(run_dir)

    assert plan.resume_target_phase == "reflect"
    assert plan.resume_target_step_key == "reflect::reflect_completeness::pass_02"


def test_resume_plan_moves_completed_summary_to_global_review(tmp_path: Path) -> None:
    run_dir, atomic_dir, _ = _make_resume_run(tmp_path)
    record_step_checkpoint(
        atomic_dir,
        cycle=1,
        phase="summary",
        step_key="summary",
        status="completed",
        agent_id="pi-worker",
        session_id="session_pi-worker_1",
    )

    _, plan = build_resume_plan(run_dir)

    assert plan.resume_target_phase == "global_review"
    assert plan.resume_target_step_key == "global::global_completeness"


def test_step_checkpoints_record_node_and_cycle_timing(tmp_path: Path, monkeypatch) -> None:
    run_dir, atomic_dir, _ = _make_resume_run(tmp_path)

    monkeypatch.setattr(checkpoint_module.time, "time", lambda: 1000.0)
    started = record_step_checkpoint(
        atomic_dir,
        cycle=1,
        phase="worker",
        step_key="worker::work",
        status="started",
        agent_id="pi-worker",
        session_id="session_pi-worker_1",
    )

    assert started["started_epoch"] == 1000.0
    assert "duration_seconds" not in started

    monkeypatch.setattr(checkpoint_module.time, "time", lambda: 1120.4)
    completed = record_step_checkpoint(
        atomic_dir,
        cycle=1,
        phase="worker",
        step_key="worker::work",
        status="completed",
        agent_id="pi-worker",
        session_id="session_pi-worker_1",
    )

    assert completed["started_epoch"] == 1000.0
    assert completed["finished_epoch"] == 1120.4
    assert completed["duration_seconds"] == 120
    assert completed["duration_ms"] == 120400

    monkeypatch.setattr(checkpoint_module.time, "time", lambda: 1130.0)
    record_step_checkpoint(
        atomic_dir,
        cycle=1,
        phase="summary",
        step_key="summary",
        status="started",
        agent_id="pi-worker",
        session_id="session_pi-worker_1",
    )
    monkeypatch.setattr(run_inspector_module.time, "time", lambda: 1160.0)

    detail = inspect_run_detail(run_dir)

    worker_step = next(item for item in detail["step_history"] if item["step_key"] == "worker::work")
    assert worker_step["duration_seconds"] == 120
    assert detail["current_step"]["step_key"] == "summary"
    assert detail["current_step"]["elapsed_seconds"] == 30
    assert detail["cycle_timing"]["1"]["running"] is True
    assert detail["cycle_timing"]["1"]["elapsed_seconds"] == 160
    assert detail["cycle_timing"]["1"]["node_count"] == 2


def test_legacy_checkpoints_without_timing_do_not_create_fake_cycle_timing(tmp_path: Path) -> None:
    run_dir, atomic_dir, _ = _make_resume_run(tmp_path)
    legacy_path = atomic_dir / "_meta" / "checkpoints" / "steps" / "cycle_001" / "worker" / "worker.json"
    legacy_path.parent.mkdir(parents=True, exist_ok=True)
    legacy_path.write_text(
        json.dumps(
            {
                "timestamp": "2026-05-12T00:00:00+00:00",
                "cycle": 1,
                "phase": "worker",
                "step_key": "worker",
                "status": "completed",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    detail = inspect_run_detail(run_dir)

    assert detail["step_history"][0]["step_key"] == "worker"
    assert detail["cycle_timing"] == {}


def test_rebuild_review_state_ignores_agent_error_records(tmp_path: Path) -> None:
    _, atomic_dir, _ = _make_resume_run(tmp_path)
    results_dir = atomic_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    result_file = results_dir / "result_001.md"
    result_file.write_text("# candidate\n", encoding="utf-8")

    global_dir = atomic_dir / "reviews" / "global" / "cycle_001"
    global_dir.mkdir(parents=True, exist_ok=True)
    (global_dir / "global_completeness.json").write_text(
        json.dumps(
            {
                "advisor_instance_id": "global_completeness",
                "cycle": 1,
                "passed": False,
                "verdict": "ERROR",
                "parser_mode": "agent_error",
                "feedback_detail": "runtime failed",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    result_dir = atomic_dir / "reviews" / "results" / "result_001" / "cycle_001"
    result_dir.mkdir(parents=True, exist_ok=True)
    (result_dir / "result_fp_check.json").write_text(
        json.dumps(
            {
                "result_file": "result_001.md",
                "cycle": 1,
                "passed": False,
                "verdict": "ERROR",
                "parser_mode": "agent_error",
                "feedback_detail": "runtime failed",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    state = rebuild_review_state(atomic_dir)

    assert state.global_review_history == []
    fingerprint = calculate_file_sha256(str(result_file))
    assert state.get_pending_results(
        ["result_001.md"],
        [{"re_review_on_cycle": False}],
        {"result_001.md": fingerprint},
    ) == ["result_001.md"]


def test_result_review_marks_current_cycle_missing_advisor_pending(tmp_path: Path) -> None:
    _, atomic_dir, config = _make_resume_run(tmp_path)
    results_dir = atomic_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    result_file = results_dir / "result_001.md"
    result_file.write_text("# candidate\n", encoding="utf-8")

    advisors = config.workflows.atomic[0].roles.advisors.result_review
    second_advisor = advisors[0].model_copy(update={"instance_id": "result_second_check"})
    advisors = [advisors[0], second_advisor]

    result_dir = atomic_dir / "reviews" / "results" / "result_001" / "cycle_001"
    result_dir.mkdir(parents=True, exist_ok=True)
    (result_dir / "result_fp_check.json").write_text(
        json.dumps(
            {
                "result_file": "result_001.md",
                "cycle": 1,
                "passed": True,
                "verdict": "CONFIRMED",
                "feedback_detail": "first advisor passed",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    state = rebuild_review_state(atomic_dir)
    fingerprint = calculate_file_sha256(str(result_file))
    assert state.get_pending_results(
        ["result_001.md"],
        [advisor.model_dump() for advisor in advisors],
        {"result_001.md": fingerprint},
    ) == []

    executor = ResultReviewExecutor(agent_registry=None, recorder=None)  # type: ignore[arg-type]
    assert executor._results_with_incomplete_current_cycle(
        advisors_cfg=advisors,
        work_dir=str(atomic_dir),
        cycle=1,
        result_files=["result_001.md"],
    ) == ["result_001.md"]
