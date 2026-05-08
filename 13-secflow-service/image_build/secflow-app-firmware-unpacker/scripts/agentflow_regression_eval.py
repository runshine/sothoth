#!/usr/bin/env python3
"""Summarize fixed-sample AgentFlow firmware unpack regression results."""

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
    return {
        "id": sample.get("id") or result_path.parent.name,
        "variant": sample.get("variant", "default"),
        "status": result.get("status"),
        "rounds": int(result.get("rounds") or 0),
        "duration_seconds": sample.get("duration_seconds"),
        "total_tokens": int(result.get("total_tokens") or grand_total.get("total_tokens") or 0),
        "generated_skill": bool(result.get("generated_skill_path")),
        "fallback_to_llm": bool(result.get("fallback_to_llm")),
    }


def _avg(values: list[float]) -> float:
    return round(mean(values), 3) if values else 0.0


def summarize(manifest_path: Path) -> dict[str, Any]:
    manifest = _read_json(manifest_path)
    rows = [_result_for_sample(item) for item in manifest.get("samples", [])]
    total = len(rows)
    successes = [row for row in rows if row["status"] == "success"]
    durations = [float(row["duration_seconds"]) for row in rows if row.get("duration_seconds") is not None]
    summary = {
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
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        default="plan/agentflow-regression-samples.json",
        help="JSON file with samples containing result_path and optional tokens_path.",
    )
    parser.add_argument("--output", default="", help="Optional summary JSON output path.")
    args = parser.parse_args()

    summary = summarize(Path(args.manifest))
    payload = json.dumps(summary, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(payload + "\n", encoding="utf-8")
    print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
