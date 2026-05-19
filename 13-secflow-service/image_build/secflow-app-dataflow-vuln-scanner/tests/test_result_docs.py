from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.pi_vuln_core.plugins.base import PluginContext
from app.pi_vuln_core.plugins.builtin.final_output_collector import FinalOutputCollectorPlugin
from app.pi_vuln_core.plugins.builtin.next_task_generator import NextTaskGeneratorPlugin
from app.pi_vuln_core.utils.result_docs import (
    classify_final_result_files,
    collect_multi_finding_result_reports,
    build_results_manifest,
    extract_final_result_files_from_summary,
    infer_result_lifecycle_from_text,
    list_final_result_report_files,
    results_manifest_path,
    result_relations_manifest_path,
    sync_structured_result_manifests,
    sync_result_relations_manifest,
)
from app.pi_vuln_core.utils.vulnerability_list import apply_result_review_verdict


def _prepare_results_with_superseded_report(tmp_path: Path) -> tuple[Path, Path, Path]:
    work_dir = tmp_path / "work"
    results_dir = work_dir / "results"
    results_dir.mkdir(parents=True)
    for name in ("result_004.md", "result_005.md", "result_009.md"):
        (results_dir / name).write_text(f"# {name}\n", encoding="utf-8")

    summary_file = work_dir / "summary.md"
    summary_file.write_text(
        "# summary\n\n"
        "## 5. 漏洞汇总表\n\n"
        "| 编号 | 文件 | 漏洞 |\n"
        "|---|---|---|\n"
        "| 004 | result_004.md | memcpy_s 返回值未处理 |\n"
        "| 009 | result_009.md | IP header 越界写入 |\n\n"
        "**关于 result_005.md**: result_005.md 是 result_009.md 的早期分析版本，描述同一漏洞。\n",
        encoding="utf-8",
    )
    return work_dir, results_dir, summary_file


def _prepare_results_with_supplement_report(tmp_path: Path) -> tuple[Path, Path, Path]:
    work_dir = tmp_path / "work"
    results_dir = work_dir / "results"
    results_dir.mkdir(parents=True)

    (results_dir / "result_001.md").write_text(
        "# VULN-001\n\n独立漏洞。\n",
        encoding="utf-8",
    )
    (results_dir / "result_005.md").write_text(
        "# VULN-005\n\n独立漏洞。\n",
        encoding="utf-8",
    )
    (results_dir / "result_011.md").write_text(
        "# 漏洞补充分析: VULN-005 攻击前提条件修正\n\n"
        "## 关联漏洞\n"
        "- **原始报告**: VULN-005 (result_005.md)\n"
        "- **本报告性质**: 补充分析，修正攻击前提条件评估\n",
        encoding="utf-8",
    )

    summary_file = work_dir / "summary.md"
    summary_file.write_text(
        "# summary\n\n"
        "## 执行摘要\n\n"
        "发现 2 个有效漏洞；result_011.md 是 result_005.md 的补充分析。\n\n"
        "## 5. 漏洞汇总表\n\n"
        "| 编号 | 漏洞 | 状态 |\n"
        "|---|---|---|\n"
        "| VULN-001 | 独立漏洞 | 已确认 |\n"
        "| VULN-005 | 载荷长度整数溢出 | 已确认 |\n\n"
        "## 5.2 漏洞详情引用\n\n"
        "- [VULN-001](./results/result_001.md)\n"
        "- [VULN-005](./results/result_005.md)\n"
        "- [VULN-005 补充分析](./results/result_011.md)\n",
        encoding="utf-8",
    )
    return work_dir, results_dir, summary_file


def test_summary_vulnerability_table_defines_final_result_set(tmp_path: Path) -> None:
    _, results_dir, summary_file = _prepare_results_with_superseded_report(tmp_path)

    assert extract_final_result_files_from_summary(summary_file, [
        "result_004.md",
        "result_005.md",
        "result_009.md",
    ]) == ["result_004.md", "result_009.md"]
    assert list_final_result_report_files(results_dir, summary_file) == [
        "result_004.md",
        "result_009.md",
    ]

    selection = classify_final_result_files(results_dir, summary_file)
    assert selection["selection_source"] == "summary_vulnerability_table"
    assert selection["final_results"] == ["result_004.md", "result_009.md"]
    assert selection["excluded_results"] == ["result_005.md"]


@pytest.mark.asyncio
async def test_final_output_collector_excludes_superseded_result_reports(tmp_path: Path) -> None:
    work_dir, results_dir, summary_file = _prepare_results_with_superseded_report(tmp_path)

    plugin = FinalOutputCollectorPlugin()
    result = await plugin.execute(
        PluginContext(
            workflow_id="wf",
            task_id="task",
            execution_id="exec",
            working_dir=str(work_dir),
            task_file=str(work_dir / "task.md"),
            plugin_config={},
            shared_state={},
            global_config={},
            summary_file=str(summary_file),
            results_dir=str(results_dir),
        )
    )

    assert result.code.value == "ok_next"
    final_dir = work_dir / "final_output"
    assert sorted(path.name for path in (final_dir / "results").glob("result_*.md")) == [
        "result_004.md",
        "result_009.md",
    ]
    assert not (final_dir / "results" / "result_005.md").exists()

    index = json.loads((final_dir / "index.json").read_text(encoding="utf-8"))
    assert index["result_selection"]["excluded_results"] == ["result_005.md"]
    assert "results/result_005.md" not in index["files"]


@pytest.mark.asyncio
async def test_next_task_generator_uses_final_result_set(tmp_path: Path) -> None:
    work_dir, results_dir, summary_file = _prepare_results_with_superseded_report(tmp_path)

    plugin = NextTaskGeneratorPlugin()
    await plugin.execute(
        PluginContext(
            workflow_id="wf",
            task_id="task",
            execution_id="exec",
            working_dir=str(work_dir),
            task_file=str(work_dir / "task.md"),
            plugin_config={},
            shared_state={},
            global_config={},
            summary_file=str(summary_file),
            results_dir=str(results_dir),
        )
    )

    next_tasks = json.loads((work_dir / "output" / "next_tasks.json").read_text(encoding="utf-8"))
    assert [task["id"] for task in next_tasks["tasks"]] == ["result_004", "result_009"]
    assert not (work_dir / "output" / "task_result_005.md").exists()


def test_collect_multi_finding_result_reports_detects_bundled_vulnerabilities(tmp_path: Path) -> None:
    work_dir = tmp_path / "work"
    results_dir = work_dir / "results"
    results_dir.mkdir(parents=True)
    (results_dir / "result_001.md").write_text(
        "# bundle\n\n## VULN-001: one\n\ntext\n\n## VULN-002: two\n",
        encoding="utf-8",
    )
    (results_dir / "result_002.md").write_text(
        "# single\n\n## VULN-003: three\n",
        encoding="utf-8",
    )

    findings = collect_multi_finding_result_reports(results_dir)
    assert findings == {"result_001.md": ["VULN-001", "VULN-002"]}


def test_result_relations_manifest_marks_supplements_as_non_taskable(tmp_path: Path) -> None:
    work_dir, results_dir, summary_file = _prepare_results_with_supplement_report(tmp_path)

    manifest = sync_result_relations_manifest(work_dir, results_dir, summary_file)

    assert manifest["final_results"] == ["result_001.md", "result_005.md", "result_011.md"]
    assert manifest["taskable_results"] == ["result_001.md", "result_005.md"]
    assert manifest["supplemental_results"] == ["result_011.md"]

    relationships = {entry["filename"]: entry for entry in manifest["relationships"]}
    assert relationships["result_011.md"]["role"] == "supplement"
    assert relationships["result_011.md"]["related_to"] == "result_005.md"
    assert relationships["result_011.md"]["taskable"] is False
    assert result_relations_manifest_path(work_dir).exists()


def test_result_lifecycle_marks_withdrawals_false_positives_and_supporting_docs_inactive() -> None:
    assert infer_result_lifecycle_from_text("# 修正：撤回 VULN-008\n\n确认为误报。")["status"] == "withdrawn"
    assert infer_result_lifecycle_from_text("- **状态**: false positive\n")["status"] == "false_positive"
    assert infer_result_lifecycle_from_text("# 覆盖矩阵附录\n\nsupporting doc")["delivery_bucket"] == "supporting_docs"


def test_structured_results_manifest_excludes_inactive_reports(tmp_path: Path) -> None:
    work_dir = tmp_path / "work"
    results_dir = work_dir / "results"
    results_dir.mkdir(parents=True)
    (results_dir / "result_001.md").write_text("# VULN-001\n\nreal issue\n", encoding="utf-8")
    (results_dir / "result_008.md").write_text(
        "# 修正：撤回 VULN-008\n\n- **状态**: 已撤回，确认为误报\n",
        encoding="utf-8",
    )
    summary_file = work_dir / "summary.md"
    summary_file.write_text(
        "# summary\n\nresult_001.md\nresult_008.md\n",
        encoding="utf-8",
    )

    manifest = build_results_manifest(work_dir, results_dir, summary_file)
    assert manifest["taskable_results"] == ["result_001.md"]
    assert manifest["inactive_results"] == ["result_008.md"]

    sync_structured_result_manifests(work_dir, results_dir, summary_file)
    assert results_manifest_path(work_dir).exists()


@pytest.mark.asyncio
async def test_final_output_and_next_tasks_do_not_double_count_supplements(tmp_path: Path) -> None:
    work_dir, results_dir, summary_file = _prepare_results_with_supplement_report(tmp_path)

    collector = FinalOutputCollectorPlugin()
    await collector.execute(
        PluginContext(
            workflow_id="wf",
            task_id="task",
            execution_id="exec",
            working_dir=str(work_dir),
            task_file=str(work_dir / "task.md"),
            plugin_config={},
            shared_state={},
            global_config={},
            summary_file=str(summary_file),
            results_dir=str(results_dir),
        )
    )

    final_dir = work_dir / "final_output"
    assert sorted(path.name for path in (final_dir / "results").glob("result_*.md")) == [
        "result_001.md",
        "result_005.md",
    ]
    assert sorted(path.name for path in (final_dir / "result_supplements").glob("result_*.md")) == [
        "result_011.md",
    ]
    index = json.loads((final_dir / "index.json").read_text(encoding="utf-8"))
    assert index["result_selection"]["taskable_results"] == ["result_001.md", "result_005.md"]
    assert index["result_selection"]["supplemental_results"] == ["result_011.md"]

    generator = NextTaskGeneratorPlugin()
    await generator.execute(
        PluginContext(
            workflow_id="wf",
            task_id="task",
            execution_id="exec",
            working_dir=str(work_dir),
            task_file=str(work_dir / "task.md"),
            plugin_config={},
            shared_state={},
            global_config={},
            summary_file=str(summary_file),
            results_dir=str(results_dir),
        )
    )

    next_tasks = json.loads((work_dir / "output" / "next_tasks.json").read_text(encoding="utf-8"))
    assert [task["id"] for task in next_tasks["tasks"]] == ["result_001", "result_005"]
    assert next_tasks["result_selection"]["supplemental_results"] == ["result_011.md"]
    assert not (work_dir / "output" / "task_result_011.md").exists()


@pytest.mark.asyncio
async def test_final_output_and_next_tasks_exclude_false_positive_but_keep_pending(tmp_path: Path) -> None:
    work_dir = tmp_path / "work"
    results_dir = work_dir / "results"
    results_dir.mkdir(parents=True)
    (results_dir / "result_001.md").write_text("# FP\n", encoding="utf-8")
    (results_dir / "result_002.md").write_text("# Pending\n", encoding="utf-8")
    summary_file = work_dir / "summary.md"
    summary_file.write_text(
        "# summary\n\n"
        "| 编号 | 文件 | 漏洞 |\n"
        "|---|---|---|\n"
        "| 001 | result_001.md | fp |\n"
        "| 002 | result_002.md | pending |\n",
        encoding="utf-8",
    )
    apply_result_review_verdict(
        working_dir=work_dir,
        results_dir=results_dir,
        result_file="result_001.md",
        verdict="FALSE_POSITIVE",
        passed=False,
        feedback="not a bug",
        cycle=1,
    )

    ctx = PluginContext(
        workflow_id="wf",
        task_id="task",
        execution_id="exec",
        working_dir=str(work_dir),
        task_file=str(work_dir / "task.md"),
        plugin_config={},
        shared_state={},
        global_config={},
        summary_file=str(summary_file),
        results_dir=str(results_dir),
    )

    await FinalOutputCollectorPlugin().execute(ctx)
    final_dir = work_dir / "final_output"
    assert sorted(path.name for path in (final_dir / "results").glob("result_*.md")) == ["result_002.md"]
    assert sorted(path.name for path in (final_dir / "false_positive_results").glob("result_*.md")) == ["result_001.md"]

    await NextTaskGeneratorPlugin().execute(ctx)
    next_tasks = json.loads((work_dir / "output" / "next_tasks.json").read_text(encoding="utf-8"))
    assert [task["id"] for task in next_tasks["tasks"]] == ["result_002"]
