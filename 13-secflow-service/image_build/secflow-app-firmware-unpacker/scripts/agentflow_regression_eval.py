#!/usr/bin/env python3
"""Gate fixed-sample AgentFlow firmware unpack regression results."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from statistics import mean
from typing import Any


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _result_for_sample(sample: dict[str, Any]) -> dict[str, Any]:
    result_path = Path(sample["result_path"])
    result = _read_json(result_path)
    tokens_path = sample.get("tokens_path")
    tokens = _read_json(Path(tokens_path)) if tokens_path else {}
    grand_total = tokens.get("grand_total") if isinstance(tokens, dict) else {}
    if not isinstance(grand_total, dict):
        grand_total = {}
    row = {
        "id": sample.get("id") or result_path.parent.name,
        "variant": sample.get("variant", "default"),
        "status": result.get("status"),
        "rounds": int(result.get("rounds") or 0),
        "duration_seconds": sample.get("duration_seconds"),
        "total_tokens": int(result.get("total_tokens") or grand_total.get("total_tokens") or 0),
        "generated_skill": bool(result.get("generated_skill_path")),
        "fallback_to_llm": bool(result.get("fallback_to_llm")),
    }
    if "expected_status" in sample:
        row["expected_status"] = sample["expected_status"]
    if "expected_fallback_to_llm" in sample:
        row["expected_fallback_to_llm"] = bool(sample["expected_fallback_to_llm"])
    if "expected_generated_skill" in sample:
        row["expected_generated_skill"] = bool(sample["expected_generated_skill"])
    return row


def _avg(values: list[float]) -> float:
    return round(mean(values), 3) if values else 0.0


def summarize(manifest_path: Path) -> dict[str, Any]:
    manifest = _read_json(manifest_path)
    rows = [_result_for_sample(item) for item in manifest.get("samples", [])]
    total = len(rows)
    successes = [row for row in rows if row["status"] == "success"]
    durations = [float(row["duration_seconds"]) for row in rows if row.get("duration_seconds") is not None]
    summary: dict[str, Any] = {
        "sample_count": total,
        "success_count": len(successes),
        "success_rate": round(len(successes) / total, 4) if total else 0.0,
        "avg_rounds": _avg([float(row["rounds"]) for row in rows]),
        "avg_duration_seconds": _avg(durations),
        "avg_token_count": _avg([float(row["total_tokens"]) for row in rows]),
        "candidate_skill_promotion_rate": round(
            sum(1 for row in rows if row["generated_skill"]) / total,
            4,
        ) if total else 0.0,
        "fallback_to_llm_rate": round(
            sum(1 for row in rows if row["fallback_to_llm"]) / total,
            4,
        ) if total else 0.0,
        "items": rows,
    }
    thresholds = manifest.get("thresholds") or {}
    expectation_failures = []
    for row in rows:
        expected_status = row.get("expected_status")
        if expected_status is not None and row["status"] != expected_status:
            expectation_failures.append(
                {
                    "id": row["id"],
                    "variant": row["variant"],
                    "field": "status",
                    "expected": expected_status,
                    "actual": row["status"],
                }
            )
        expected_fallback = row.get("expected_fallback_to_llm")
        if expected_fallback is not None and row["fallback_to_llm"] != expected_fallback:
            expectation_failures.append(
                {
                    "id": row["id"],
                    "variant": row["variant"],
                    "field": "fallback_to_llm",
                    "expected": expected_fallback,
                    "actual": row["fallback_to_llm"],
                }
            )
        expected_generated = row.get("expected_generated_skill")
        if expected_generated is not None and row["generated_skill"] != expected_generated:
            expectation_failures.append(
                {
                    "id": row["id"],
                    "variant": row["variant"],
                    "field": "generated_skill",
                    "expected": expected_generated,
                    "actual": row["generated_skill"],
                }
            )

    threshold_failures = []
    for metric, limit in thresholds.items():
        if metric.startswith("min_"):
            actual_metric = metric[4:]
            actual = summary.get(actual_metric)
            if actual is None or float(actual) < float(limit):
                threshold_failures.append({"metric": actual_metric, "operator": ">=", "expected": limit, "actual": actual})
        elif metric.startswith("max_"):
            actual_metric = metric[4:]
            actual = summary.get(actual_metric)
            if actual is None or float(actual) > float(limit):
                threshold_failures.append({"metric": actual_metric, "operator": "<=", "expected": limit, "actual": actual})

    summary["thresholds"] = thresholds
    summary["expectation_failures"] = expectation_failures
    summary["threshold_failures"] = threshold_failures
    summary["gate_passed"] = bool(total) and not expectation_failures and not threshold_failures
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        default="plan/agentflow-regression-samples.json",
        help="JSON file with samples containing result_path and optional tokens_path.",
    )
    parser.add_argument("--output", default="", help="Optional summary JSON output path.")
    parser.add_argument("--no-fail", action="store_true", help="Print the summary without failing when the gate does not pass.")
    args = parser.parse_args()

    summary = summarize(Path(args.manifest))
    payload = json.dumps(summary, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(payload + "\n", encoding="utf-8")
    print(payload)
    return 0 if args.no_fail or summary["gate_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
