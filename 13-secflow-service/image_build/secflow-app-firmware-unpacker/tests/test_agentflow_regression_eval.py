import json
from pathlib import Path

from scripts.agentflow_regression_eval import summarize


def test_default_regression_manifest_is_a_nonempty_gate():
    manifest_path = Path("plan/agentflow-regression-samples.json")
    summary = summarize(manifest_path)

    assert summary["sample_count"] == 5
    assert summary["success_rate"] == 0.8
    assert summary["gate_passed"] is True
    assert summary["expectation_failures"] == []
    assert summary["threshold_failures"] == []
    assert {item["id"] for item in summary["items"]} >= {
        "zip-preprocess",
        "skill-hit",
        "skill-fallback-author",
        "generic-success",
        "generic-max-retries",
    }
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for sample in manifest["samples"]:
        fixture_dir = Path(sample["result_path"]).parent
        assert (fixture_dir / "run.json").is_file()
        tokens = json.loads(Path(sample["tokens_path"]).read_text(encoding="utf-8"))
        assert {"total_prompt_tokens", "total_completion_tokens", "total_tokens", "nodes"} <= set(tokens)


def test_regression_gate_reports_expectation_failures(tmp_path):
    result = tmp_path / "final_result.json"
    result.write_text(json.dumps({"status": "failed", "rounds": 0, "fallback_to_llm": False}), encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "thresholds": {"min_success_rate": 1.0},
                "samples": [
                    {
                        "id": "failing-fixture",
                        "result_path": str(result),
                        "expected_status": "success",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    summary = summarize(manifest)

    assert summary["gate_passed"] is False
    assert summary["expectation_failures"][0]["field"] == "status"
    assert summary["threshold_failures"][0]["metric"] == "success_rate"
