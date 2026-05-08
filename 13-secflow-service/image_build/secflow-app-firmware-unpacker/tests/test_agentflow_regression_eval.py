import json
from pathlib import Path

from scripts.agentflow_regression_eval import summarize


def test_default_regression_manifest_is_a_nonempty_gate():
    summary = summarize(Path("plan/agentflow-regression-samples.json"))

    assert summary["sample_count"] == 3
    assert summary["success_rate"] == 1.0
    assert summary["gate_passed"] is True
    assert summary["expectation_failures"] == []
    assert summary["threshold_failures"] == []


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
