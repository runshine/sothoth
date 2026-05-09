"""Stage: write final AgentFlow result and stage summary files."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from app.skill_store import register_skill_success, save_candidate_skill


def _write_json(path: str, data: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _parse_json_text(text: str) -> dict[str, Any]:
    raw = str(text or "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        pass
    for line in reversed(raw.splitlines()):
        candidate = line.strip()
        if not candidate or candidate[0] not in "{[":
            continue
        try:
            parsed = json.loads(candidate)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            continue
    return {}


def _preview(text: str, limit: int = 320) -> str:
    compact = " ".join(str(text or "").split())
    return compact if len(compact) <= limit else compact[:limit] + "..."


def _review_success(text: str) -> bool:
    raw = str(text or "")
    if "AGENTFLOW_REVIEW_SUCCESS" in raw:
        return True
    lowered = raw.lower()
    return '"result"' in lowered and '"success"' in lowered


def _extract_markdown_document(text: str) -> str:
    raw = str(text or "").strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```[a-zA-Z0-9_-]*\n", "", raw)
        raw = re.sub(r"\n```$", "", raw)
    return raw.strip()


def run(payload: dict[str, Any], nodes: dict[str, Any] | None = None) -> None:
    nodes = nodes or {}
    preprocess_output = str((nodes.get("preprocess") or {}).get("output") or "")
    feature_output = str((nodes.get("feature_match") or {}).get("output") or "")
    skill_output = str((nodes.get("skill_executor") or {}).get("output") or "")
    skill_review = str((nodes.get("skill_reviewer") or {}).get("output") or "")
    generic_output = str((nodes.get("generic_executor") or {}).get("output") or "")
    generic_review = str((nodes.get("generic_reviewer") or {}).get("output") or "")
    author_output = str((nodes.get("skill_author") or {}).get("output") or "")
    skill_status = str((nodes.get("skill_executor") or {}).get("status") or "").strip()
    generic_status = str((nodes.get("generic_executor") or {}).get("status") or "").strip()

    preprocess_data = _parse_json_text(preprocess_output)
    print(f"AGENTFLOW_PROGRESS stage=finalize event=start preprocess_success={bool(preprocess_data.get('success'))}", flush=True)

    try:
        feature_payload = json.loads(Path(payload["feature_match_output_file"]).read_text(encoding="utf-8"))
    except Exception:
        feature_payload = _parse_json_text(feature_output)

    features = feature_payload.get("features") or {}
    matched_skill_path = feature_payload.get("matched_skill")
    matched_skill_version = feature_payload.get("matched_skill_version")
    matched_skill_score = feature_payload.get("matched_skill_score")

    preprocess_passed = bool(preprocess_data.get("success"))
    skill_passed = skill_status not in {"failed", "cancelled"} and _review_success(skill_review)
    generic_passed = generic_status not in {"failed", "cancelled"} and _review_success(generic_review)
    passed = preprocess_passed or skill_passed or generic_passed
    fallback_to_llm = bool(matched_skill_path and not skill_passed)

    generated_skill = None
    skill_update_error = None
    generated_skill_error = None
    matched_skill_after_update = matched_skill_path
    promotion_success_count = None

    if passed and skill_passed and matched_skill_path:
        try:
            updated_skill = register_skill_success(Path(payload["tools_dir"]), matched_skill_path)
            matched_skill_after_update = updated_skill.get("path")
            matched_skill_version = updated_skill.get("skill_version")
            promotion_success_count = updated_skill.get("promotion_success_count")
        except Exception as exc:
            skill_update_error = str(exc)

    author_file = Path(payload["skill_author_output_file"])
    if author_file.is_file():
        author_output = author_file.read_text(encoding="utf-8", errors="replace")
    if passed and generic_passed and author_output.strip() and "SKIPPED" not in author_output:
        try:
            generated_skill = save_candidate_skill(
                Path(payload["tools_dir"]),
                _extract_markdown_document(author_output),
                {
                    "family_id": features.get("family_id") or "generic-firmware",
                    "source_run_id": "",
                    "source_node_id": "generic_executor",
                },
            )
        except Exception as exc:
            generated_skill_error = str(exc)

    failure_summary: dict[str, Any] = {"failed_nodes": []}
    if not passed:
        reason = generic_review or skill_review or generic_output or skill_output
        failure_summary["failed_nodes"].append(
            {
                "node_id": "generic_reviewer" if generic_output else "skill_reviewer",
                "classification": {"failure_category": "non_retryable", "reason": _preview(reason, 180)},
                "output_preview": _preview(reason),
            }
        )

    result = {
        "status": "success" if passed else "failed",
        "message": "Unpacking verified successfully" if passed else "AgentFlow run failed",
        "rounds": 0 if preprocess_passed or skill_passed else (1 if generic_output.strip() else 0),
        "matched_skill": matched_skill_after_update,
        "matched_skill_version": matched_skill_version,
        "matched_skill_score": matched_skill_score if matched_skill_after_update else None,
        "fallback_to_llm": fallback_to_llm,
        "generated_skill_path": generated_skill.get("path") if generated_skill else None,
        "generated_skill_status": generated_skill.get("skill_status") if generated_skill else None,
        "promotion_success_count": promotion_success_count if promotion_success_count is not None else (generated_skill.get("promotion_success_count") if generated_skill else None),
        "firmware_path": payload["firmware_path"],
        "output_path": payload["output_path"],
        "run_path": str(Path(payload["final_result_file"]).parent),
        "node_attempts": {
            "skill_executor": {"status": skill_status},
            "generic_executor": {"status": generic_status},
        },
        "failure_summary": failure_summary,
        "failure_category": failure_summary["failed_nodes"][0]["classification"]["failure_category"] if failure_summary["failed_nodes"] else None,
        "total_tokens": 0,
        "skill_update_error": skill_update_error,
        "generated_skill_error": generated_skill_error,
    }

    _write_json(payload["stage2_file"], feature_payload)
    _write_json(
        payload["stage3_file"],
        {
            "skill": matched_skill_path,
            "success": passed,
            "skill_status": skill_status,
            "response_preview": _preview(skill_output or generic_output),
            "review_preview": _preview(skill_review or generic_review),
        },
    )
    _write_json(
        payload["stage4_file"],
        {
            "matched_skill": matched_skill_path,
            "fallback_to_llm": fallback_to_llm,
            "reason": _preview(generic_review or skill_review, 400),
        },
    )
    _write_json(
        payload["stage5_file"],
        {
            "generated_skill_path": generated_skill.get("path") if generated_skill else None,
            "generated_skill_status": generated_skill.get("skill_status") if generated_skill else None,
            "promotion_success_count": promotion_success_count,
            "source_node_id": "generic_executor" if generated_skill else None,
            "error": generated_skill_error,
        },
    )
    _write_json(payload["final_result_file"], result)
    print(
        f"AGENTFLOW_PROGRESS stage=finalize event=finish "
        f"status={result['status']} fallback_to_llm={result['fallback_to_llm']} "
        f"generated_skill={bool(result['generated_skill_path'])}",
        flush=True,
    )
    print(json.dumps(result, ensure_ascii=False))

