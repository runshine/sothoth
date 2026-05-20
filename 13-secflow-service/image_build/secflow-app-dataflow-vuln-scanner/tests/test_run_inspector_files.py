from __future__ import annotations

import json
from pathlib import Path

from app.services.run_inspector import inspect_files


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def test_inspect_files_indexes_vulnerability_list_and_final_output_artifacts(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    work_dir = run_dir / "workspace"
    (work_dir / "input").mkdir(parents=True)
    (work_dir / "results").mkdir(parents=True)
    (work_dir / "input" / "task.md").write_text("# task\n", encoding="utf-8")
    (work_dir / "results" / "result_001.md").write_text("# result\n", encoding="utf-8")

    _write_json(work_dir / "_meta" / "vulnerability_list.json", {"entries": []})
    _write_json(work_dir / "_meta" / "results_manifest.json", {"all_results": []})
    _write_json(work_dir / "_meta" / "checkpoints" / "current_step.json", {"step": "summary"})
    _write_json(work_dir / "final_output" / "index.json", {"files": []})
    _write_json(work_dir / "final_output" / "vulnerability_list.json", {"entries": []})
    (work_dir / "final_output" / "supporting_docs").mkdir(parents=True)
    (work_dir / "final_output" / "supporting_docs" / "coverage.md").write_text(
        "# coverage\n",
        encoding="utf-8",
    )

    paths = {item["path"]: item["category"] for item in inspect_files(run_dir, limit=200)}

    assert paths["_meta/vulnerability_list.json"] == "Meta / Result Manifests"
    assert paths["_meta/checkpoints/current_step.json"] == "Meta / Checkpoints"
    assert paths["final_output/index.json"] == "Outputs / Final Output"
    assert paths["final_output/vulnerability_list.json"] == "Outputs / Final Output"
    assert paths["final_output/supporting_docs/coverage.md"] == "Outputs / Supporting Docs"
