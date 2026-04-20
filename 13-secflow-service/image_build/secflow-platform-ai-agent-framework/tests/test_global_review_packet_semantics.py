from __future__ import annotations

import asyncio
import json
from pathlib import Path

from app.pi_vuln_core.agents.registry import AgentRuntimeRegistry
from app.pi_vuln_core.recorder.recorder import ExecutionRecorder
from app.pi_vuln_core.review.global_review import GlobalReviewExecutor
from app.pi_vuln_core.review.state import ReviewState


def _make_executor(tmp_path: Path) -> tuple[GlobalReviewExecutor, ExecutionRecorder]:
    recorder = ExecutionRecorder(str(tmp_path))
    executor = GlobalReviewExecutor(AgentRuntimeRegistry(), recorder)
    return executor, recorder


def _prepare_work_dir(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    work_dir = tmp_path / "atomic"
    results_dir = work_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "result_001.md").write_text("# result\n", encoding="utf-8")

    summary_path = work_dir / "summary.md"
    summary_path.write_text(
        "# summary\n\n## 7. 局限性与未覆盖区域\n",
        encoding="utf-8",
    )
    task_path = work_dir / "task.md"
    task_path.write_text("# task\n", encoding="utf-8")
    return work_dir, summary_path, results_dir, task_path


def test_review_packet_falls_back_to_workspace_previous_limitations_for_historical_runs(
    tmp_path: Path,
) -> None:
    executor, _ = _make_executor(tmp_path)
    work_dir, summary_path, results_dir, task_path = _prepare_work_dir(tmp_path)

    snapshots_dir = work_dir / "_meta" / "summary_snapshots"
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    (snapshots_dir / "cycle_001_after_summary.md").write_text(
        "# summary cycle 1\n\n## 7. 局限性与未覆盖区域\n",
        encoding="utf-8",
    )
    (work_dir / "previous_limitations.md").write_text(
        "# 局限性与覆盖盲区记录\n\n- 未跟入 EXPORT: IPSEC_SOCK_SendToSocket\n- 仍需验证错误处理路径\n",
        encoding="utf-8",
    )

    packet = executor._build_review_packet(
        task_file=str(task_path),
        summary_file=str(summary_path),
        results_dir=str(results_dir),
        work_dir=str(work_dir),
        cycle=2,
        review_state=ReviewState(),
    )

    packet_json = json.loads(Path(packet["review_packet_path"]).read_text(encoding="utf-8"))
    previous_limitations_text = Path(packet_json["previous_limitations_file"]).read_text(
        encoding="utf-8"
    )

    assert packet_json["previous_limitations_source"]["kind"] == "workspace_fallback"
    assert packet_json["previous_limitations_source"]["fallback"] is True
    assert "上一轮局限性快照缺失或仅为占位内容" in previous_limitations_text
    assert "IPSEC_SOCK_SendToSocket" in previous_limitations_text


def test_review_packet_prefers_snapshotted_previous_limitations_sidecar(
    tmp_path: Path,
) -> None:
    executor, recorder = _make_executor(tmp_path)
    work_dir, summary_path, results_dir, task_path = _prepare_work_dir(tmp_path)

    original_content = (
        "# 局限性与覆盖盲区记录\n\n"
        "- 上一轮未完成: USED 终点逐项清单\n"
        "- 上一轮未完成: TOCTOU 静态分析\n"
    )
    (work_dir / "previous_limitations.md").write_text(original_content, encoding="utf-8")
    asyncio.run(recorder.snapshot_summary(str(work_dir), cycle=1))

    (work_dir / "previous_limitations.md").write_text(
        "# 当前轮新内容\n\n- 这是本轮更新后的 sidecar，不应被当作上一轮快照\n",
        encoding="utf-8",
    )

    packet = executor._build_review_packet(
        task_file=str(task_path),
        summary_file=str(summary_path),
        results_dir=str(results_dir),
        work_dir=str(work_dir),
        cycle=2,
        review_state=ReviewState(),
    )

    packet_json = json.loads(Path(packet["review_packet_path"]).read_text(encoding="utf-8"))
    previous_limitations_text = Path(packet_json["previous_limitations_file"]).read_text(
        encoding="utf-8"
    )

    assert packet_json["previous_limitations_source"]["kind"] == "sidecar_snapshot"
    assert packet_json["previous_limitations_source"]["fallback"] is False
    assert packet_json["previous_limitations_source"]["path"].endswith(
        "cycle_001_previous_limitations.md"
    )
    assert previous_limitations_text == original_content
    assert "本轮更新后的 sidecar" not in previous_limitations_text


def test_review_packet_marks_open_blockers_as_pre_review_snapshot_and_prompts_explain_it(
    tmp_path: Path,
) -> None:
    executor, _ = _make_executor(tmp_path)
    work_dir, summary_path, results_dir, task_path = _prepare_work_dir(tmp_path)

    review_state = ReviewState()
    review_state.record_global_review_result(
        cycle=1,
        passed=False,
        feedback="仍有 blocker",
        scores={"report_completeness": 0.6},
        blocking_issues=[
            {
                "id": "report:state-sync",
                "category": "report_completeness",
                "target": "summary.md#7",
                "severity": "high",
                "required_action": "补全 blocker 关闭说明",
            }
        ],
        resolved_issue_ids=[],
    )

    packet = executor._build_review_packet(
        task_file=str(task_path),
        summary_file=str(summary_path),
        results_dir=str(results_dir),
        work_dir=str(work_dir),
        cycle=2,
        review_state=review_state,
    )

    packet_json = json.loads(Path(packet["review_packet_path"]).read_text(encoding="utf-8"))
    open_blockers_json = json.loads(
        Path(packet_json["open_blockers_file"]).read_text(encoding="utf-8")
    )

    assert packet_json["open_blockers_snapshot_phase"] == "pre_review"
    assert "resolved_issues" in packet_json["open_blockers_sync_note"]
    assert "状态不一致" in packet_json["open_blockers_sync_note"]
    assert open_blockers_json["snapshot_phase"] == "pre_review"
    assert "resolved_issues" in open_blockers_json["reviewer_instruction"]

    user_prompt = Path("prompts/vuln_scan/global_review_user.md").read_text(encoding="utf-8")
    sys_prompt = Path("prompts/vuln_scan/global_review_sys.md").read_text(encoding="utf-8")
    assert "本轮评审开始前" in user_prompt
    assert "状态不一致" in user_prompt
    assert "resolved_issues" in user_prompt
    assert "不要" in sys_prompt and "状态不一致" in sys_prompt


def test_review_packet_separates_supporting_docs_from_reviewable_results(
    tmp_path: Path,
) -> None:
    executor, _ = _make_executor(tmp_path)
    work_dir, summary_path, results_dir, task_path = _prepare_work_dir(tmp_path)

    (results_dir / "USED_ENDPOINTS.md").write_text("# appendix\n", encoding="utf-8")
    supporting_docs_dir = work_dir / "supporting_docs"
    supporting_docs_dir.mkdir(parents=True, exist_ok=True)
    (supporting_docs_dir / "REMOVED.md").write_text("# removed\n", encoding="utf-8")

    packet = executor._build_review_packet(
        task_file=str(task_path),
        summary_file=str(summary_path),
        results_dir=str(results_dir),
        work_dir=str(work_dir),
        cycle=1,
        review_state=ReviewState(),
    )

    packet_json = json.loads(Path(packet["review_packet_path"]).read_text(encoding="utf-8"))
    results_manifest = json.loads(
        Path(packet_json["results_manifest_file"]).read_text(encoding="utf-8")
    )
    supporting_manifest = json.loads(
        Path(packet_json["supporting_docs_manifest_file"]).read_text(encoding="utf-8")
    )

    assert [item["filename"] for item in results_manifest["results"]] == ["result_001.md"]
    assert sorted(item["filename"] for item in supporting_manifest["supporting_docs"]) == [
        "REMOVED.md"
    ]
    assert packet_json["supporting_doc_count"] == 1
    assert packet_json["supporting_docs_dir"].endswith("supporting_docs")


def test_review_packet_uses_current_failed_count_and_exposes_pending_and_historical_removed(
    tmp_path: Path,
) -> None:
    executor, _ = _make_executor(tmp_path)
    work_dir, summary_path, results_dir, task_path = _prepare_work_dir(tmp_path)

    removed_dir = work_dir / "removed_results" / "cycle_001"
    removed_dir.mkdir(parents=True, exist_ok=True)
    (removed_dir / "result_002.md").write_text("# removed\n", encoding="utf-8")

    review_state = ReviewState()
    review_state.mark_result_failed("result_999.md", 1, "stale deleted result")

    packet = executor._build_review_packet(
        task_file=str(task_path),
        summary_file=str(summary_path),
        results_dir=str(results_dir),
        work_dir=str(work_dir),
        cycle=2,
        review_state=review_state,
    )

    packet_json = json.loads(Path(packet["review_packet_path"]).read_text(encoding="utf-8"))
    manifest_json = json.loads(
        Path(packet_json["results_manifest_file"]).read_text(encoding="utf-8")
    )

    assert packet_json["failed_result_count"] == 0
    assert packet_json["pending_result_count"] == 1
    assert packet_json["historical_removed_result_count"] == 1
    assert packet_json["result_status_snapshot_phase"] == "pre_result_review"
    assert manifest_json["review_status_snapshot_phase"] == "pre_result_review"
    assert manifest_json["results"][0]["review_status"] == "pending_review"


def test_review_packet_extracts_previous_limitations_section_with_nested_subheadings(
    tmp_path: Path,
) -> None:
    executor, recorder = _make_executor(tmp_path)
    work_dir, summary_path, results_dir, task_path = _prepare_work_dir(tmp_path)

    summary_path.write_text(
        "# summary\n\n## 7. 局限性与未覆盖区域\n\n### 7.1 未解决\n- 未跟入 EXPORT A\n\n### 7.2 后续方向\n- 需要补 USED B\n",
        encoding="utf-8",
    )
    asyncio.run(recorder.snapshot_summary(str(work_dir), cycle=1))

    packet = executor._build_review_packet(
        task_file=str(task_path),
        summary_file=str(summary_path),
        results_dir=str(results_dir),
        work_dir=str(work_dir),
        cycle=2,
        review_state=ReviewState(),
    )

    packet_json = json.loads(Path(packet["review_packet_path"]).read_text(encoding="utf-8"))
    previous_limitations_text = Path(packet_json["previous_limitations_file"]).read_text(
        encoding="utf-8"
    )

    assert packet_json["previous_limitations_source"]["kind"] == "sidecar_snapshot"
    assert "### 7.1 未解决" in previous_limitations_text
    assert "未跟入 EXPORT A" in previous_limitations_text
