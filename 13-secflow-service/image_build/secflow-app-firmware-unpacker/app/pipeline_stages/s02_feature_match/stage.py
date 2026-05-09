"""Stage 2: firmware feature extraction and reusable-skill matching."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .features import extract_firmware_features
from .skill_store import compute_family_id, match_skill


def run(payload: dict[str, Any], nodes: dict[str, Any] | None = None) -> None:
    print(
        f"AGENTFLOW_PROGRESS stage=feature_match event=start "
        f"firmware={payload['firmware_path']} tools_dir={payload['tools_dir']}",
        flush=True,
    )
    try:
        features = extract_firmware_features(payload["firmware_path"])
        print(
            f"AGENTFLOW_PROGRESS stage=feature_match event=features "
            f"ext={features.get('ext')} magic={features.get('magic_hex')} "
            f"binwalk_sigs={len(features.get('binwalk_sigs') or [])}",
            flush=True,
        )
        features["family_id"] = compute_family_id(features)
        skill_meta, skill_score, skill_match = match_skill(features, Path(payload["tools_dir"]))
        result = {
            "features": features,
            "matched_skill": skill_meta.get("path") if skill_meta else None,
            "matched_skill_version": skill_meta.get("skill_version") if skill_meta else None,
            "matched_skill_score": skill_score,
            "matched_status": skill_match.get("matched_status"),
            "reasons": skill_match.get("reasons"),
        }
    except Exception as exc:
        result = {"features": {}, "matched_skill": None, "matched_skill_score": 0, "error": str(exc)}
        print(f"AGENTFLOW_PROGRESS stage=feature_match event=error error={exc}", flush=True)

    output_file = Path(payload["output_file"])
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    summary = {
        key: result.get(key)
        for key in ("matched_skill", "matched_skill_version", "matched_skill_score", "matched_status", "reasons", "error")
        if key in result
    }
    summary["feature_family_id"] = (result.get("features") or {}).get("family_id")
    summary["feature_count_binwalk_sigs"] = len((result.get("features") or {}).get("binwalk_sigs") or [])
    print(
        f"AGENTFLOW_PROGRESS stage=feature_match event=finish "
        f"matched={bool(result.get('matched_skill'))} score={result.get('matched_skill_score')} "
        f"output_file={output_file}",
        flush=True,
    )
    print(json.dumps(summary, ensure_ascii=False))
