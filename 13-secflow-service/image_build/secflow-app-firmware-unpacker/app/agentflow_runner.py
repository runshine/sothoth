"""AgentFlow-backed firmware unpack execution."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

_repo_root = Path(__file__).resolve().parent.parent
_local_agentflow = _repo_root / "agentflow"
if _local_agentflow.exists() and str(_local_agentflow) not in sys.path:
    sys.path.insert(0, str(_local_agentflow))

from agentflow.orchestrator import Orchestrator
from agentflow.store import RunStore

from app.agentflow_pipeline import build_firmware_unpack_pipeline
from app.config import get_config
from app.skill_store import (
    compute_family_id,
    match_skill,
    register_skill_success,
    save_candidate_skill,
)

log = logging.getLogger("unpacker.agentflow")


def _preview_text(text: str, limit: int = 240) -> str:
    compact = " ".join(str(text or "").split())
    return compact if len(compact) <= limit else compact[:limit] + "..."


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _load_agent_prompt_file(md_path: str) -> tuple[dict[str, Any], Path]:
    from app.unpacker_engine import load_agent_def

    agent_def = load_agent_def(md_path)
    temp = tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False, encoding="utf-8")
    temp.write(agent_def["system_prompt"])
    temp.flush()
    temp.close()
    return agent_def, Path(temp.name)


def _node_output(record: Any, node_id: str) -> str:
    node = record.nodes.get(node_id)
    if node is None:
        return ""
    return str(node.output or node.final_response or "")


def _node_attempts(record: Any, node_id: str) -> int:
    node = record.nodes.get(node_id)
    if node is None:
        return 0
    return max(int(getattr(node, "current_attempt", 0) or 0), len(getattr(node, "attempts", []) or []))


def _json_output(text: str) -> dict[str, Any]:
    try:
        return json.loads(str(text or "").strip())
    except Exception:
        return {}


def _review_success(review_text: str, legacy_check: Callable[[str], bool]) -> bool:
    text = str(review_text or "")
    return "AGENTFLOW_REVIEW_SUCCESS" in text or legacy_check(text)


def _review_skipped(review_text: str) -> bool:
    return "AGENTFLOW_REVIEW_SKIPPED" in str(review_text or "")


def _cancelled_result(rounds: int) -> dict[str, Any]:
    return {
        "status": "cancelled",
        "message": "Task was cancelled",
        "rounds": rounds,
    }


def run_unpack_agentflow(
    firmware_path: str,
    output_path: str,
    cancel_check: Callable[[], bool] | None = None,
    task_id: str | None = None,
    project_id: str | None = None,
) -> dict[str, Any]:
    config = get_config()

    from app.unpacker_engine import (
        AUTHOR_AGENT_DEF,
        CLEAN_AGENT_DEF,
        EXEC_AGENT_DEF,
        TOOLS_DIR,
        VAL_AGENT_DEF,
        _extract_markdown_document,
        _get_max_retries,
        _is_review_success,
        extract_firmware_features,
        get_log_dir,
    )

    def _check_cancel() -> None:
        if cancel_check and cancel_check():
            raise RuntimeError("__CANCELLED__")

    def _build_ctx(log_dir: Path | None, temp_paths: dict[str, Path], exec_def: dict[str, Any], val_def: dict[str, Any], author_def: dict[str, Any], clean_def: dict[str, Any], features: dict[str, Any], skill_meta: dict[str, Any] | None, skill_score: int, skill_match: dict[str, Any]) -> dict[str, Any]:
        output_root = Path(output_path)
        task_root = output_root.parent if output_root.name == "output" else output_root.parent
        run_root = (log_dir or task_root / "run")
        return {
            "base_dir": str(task_root),
            "task_dir": str(task_root),
            "firmware_path": firmware_path,
            "firmware_name": Path(firmware_path).name,
            "output_path": output_path,
            "log_dir": str(log_dir) if log_dir else None,
            "tools_dir": str(TOOLS_DIR),
            "family_id": features.get("family_id"),
            "max_retries": _get_max_retries(),
            "node_timeout_seconds": config.agentflow.node_timeout_seconds,
            "agentflow_concurrency": config.agentflow.max_concurrent_runs,
            "use_worktree": config.agentflow.use_worktree,
            "preprocess_output_file": str(run_root / "preprocess.json"),
            "feature_match_output_file": str(run_root / "feature-match.json"),
            "final_result_file": str(run_root / "final_result.json"),
            "executor_model": exec_def.get("model"),
            "review_model": val_def.get("model"),
            "author_model": author_def.get("model"),
            "cleanup_model": clean_def.get("model"),
            "executor_extra_args": ["--append-system-prompt", str(temp_paths["exec"])],
            "review_extra_args": ["--append-system-prompt", str(temp_paths["review"])],
            "author_extra_args": ["--append-system-prompt", str(temp_paths["author"])],
            "cleanup_extra_args": ["--append-system-prompt", str(temp_paths["cleanup"])],
        }

    os_output = Path(output_path)
    os_output.mkdir(parents=True, exist_ok=True)
    try:
        log_dir = get_log_dir(output_path)
    except Exception:
        log_dir = None

    if log_dir is not None:
        _write_text(log_dir / "agentflow_run_id.txt", "")

    _check_cancel()

    try:
        features = extract_firmware_features(firmware_path)
        features["family_id"] = compute_family_id(features)
        skill_meta, skill_score, skill_match = match_skill(features, TOOLS_DIR)

        temp_paths: dict[str, Path] = {}
        agent_defs = {}
        for key, path in {
            "exec": EXEC_AGENT_DEF,
            "review": VAL_AGENT_DEF,
            "author": AUTHOR_AGENT_DEF,
            "cleanup": CLEAN_AGENT_DEF,
        }.items():
            agent_def, temp_path = _load_agent_prompt_file(path)
            agent_defs[key] = agent_def
            temp_paths[key] = temp_path

        ctx = _build_ctx(
            log_dir,
            temp_paths,
            agent_defs["exec"],
            agent_defs["review"],
            agent_defs["author"],
            agent_defs["cleanup"],
            features,
            skill_meta,
            skill_score,
            skill_match,
        )
        pipeline = build_firmware_unpack_pipeline(ctx)
        run_store_dir = Path(config.agentflow.runs_dir)
        if log_dir is not None:
            run_store_dir = log_dir / "agentflow" / "runs"
        store = RunStore(run_store_dir)
        orchestrator = Orchestrator(store=store, max_concurrent_runs=config.agentflow.max_concurrent_runs)

        async def _execute() -> dict[str, Any]:
            record = await orchestrator.submit(pipeline)
            if log_dir is not None:
                _write_text(log_dir / "agentflow_run_id.txt", record.id)
            while True:
                if cancel_check and cancel_check():
                    await orchestrator.cancel(record.id)
                    await orchestrator.wait(record.id, timeout=5)
                    return _cancelled_result(_node_attempts(store.get_run(record.id), "generic_executor"))
                current = store.get_run(record.id)
                if current.status.value in {"completed", "failed", "cancelled"}:
                    break
                await asyncio.sleep(0.5)
            current = store.get_run(record.id)
            if current.status.value == "cancelled":
                return _cancelled_result(_node_attempts(current, "generic_executor"))

            preprocess_output = _node_output(current, "preprocess")
            feature_output = _node_output(current, "feature_match")
            skill_review = _node_output(current, "skill_reviewer")
            generic_output = _node_output(current, "generic_executor")
            generic_review = _node_output(current, "generic_reviewer")
            author_output = _node_output(current, "skill_author")

            preprocess_passed = bool(_json_output(preprocess_output).get("success"))
            skill_passed = _review_success(skill_review, _is_review_success)
            generic_passed = bool(generic_output.strip()) and _review_success(generic_review, _is_review_success)
            passed = preprocess_passed or skill_passed or generic_passed
            rounds = 0 if preprocess_passed or skill_passed else _node_attempts(current, "generic_executor")
            matched_skill = skill_meta
            fallback_to_llm = bool(skill_meta and not skill_passed)
            promotion_success_count = None
            generated_skill = None

            if skill_meta and skill_passed:
                updated_skill = register_skill_success(TOOLS_DIR, str(skill_meta.get("path")))
                matched_skill = updated_skill
                promotion_success_count = updated_skill.get("promotion_success_count")

            if generic_passed and author_output.strip() and "SKIPPED" not in author_output:
                generated_skill = save_candidate_skill(
                    TOOLS_DIR,
                    _extract_markdown_document(author_output),
                    {"family_id": features["family_id"]},
                )

            result = {
                "status": "success" if passed else "failed",
                "message": (
                    "Unpacking verified successfully"
                    if passed
                    else f"AgentFlow run failed: {current.status.value}"
                ),
                "rounds": rounds,
                "matched_skill": matched_skill.get("path") if matched_skill else None,
                "matched_skill_version": matched_skill.get("skill_version") if matched_skill else None,
                "matched_skill_score": skill_score if matched_skill else None,
                "fallback_to_llm": fallback_to_llm,
                "generated_skill_path": generated_skill.get("path") if generated_skill else None,
                "generated_skill_status": generated_skill.get("skill_status") if generated_skill else None,
                "promotion_success_count": (
                    promotion_success_count
                    if promotion_success_count is not None
                    else generated_skill.get("promotion_success_count") if generated_skill else None
                ),
                "agentflow_run_id": current.id,
                "run_path": str(log_dir) if log_dir else None,
            }
            if log_dir is not None:
                _write_json(log_dir / "final_result.json", result)
                _write_json(
                    log_dir / "stage2_skill_match.json",
                    {
                        "features": features,
                        "matched_skill": matched_skill.get("path") if matched_skill else None,
                        "matched_skill_version": matched_skill.get("skill_version") if matched_skill else None,
                        "matched_skill_score": skill_score,
                        "matched_status": skill_match.get("matched_status"),
                        "reasons": skill_match.get("reasons"),
                    },
                )
                _write_json(
                    log_dir / "stage3_skill_exec.json",
                    {
                        "skill": matched_skill.get("path") if matched_skill else None,
                        "success": passed,
                        "response_preview": _preview_text(generic_output or skill_review),
                        "review_preview": _preview_text(generic_review or skill_review),
                    },
                )
                _write_json(
                    log_dir / "stage4_llm_fallback.json",
                    {
                        "matched_skill": skill_meta.get("path") if skill_meta else None,
                        "reason": _preview_text(generic_review or skill_review, 400),
                    },
                )
                _write_json(
                    log_dir / "stage5_skill_generate.json",
                    {
                        "generated_skill_path": generated_skill.get("path") if generated_skill else None,
                        "generated_skill_status": generated_skill.get("skill_status") if generated_skill else None,
                        "promotion_success_count": promotion_success_count,
                    },
                )
                _write_text(log_dir / "tokens_summary.json", json.dumps({"grand_total": {}}, indent=2))
            return result

        try:
            return asyncio.run(_execute())
        except RuntimeError as exc:
            if str(exc) == "__CANCELLED__":
                if log_dir is not None:
                    _write_json(log_dir / "final_result.json", _cancelled_result(0))
                return _cancelled_result(0)
            raise
    finally:
        for temp_path in locals().get("temp_paths", {}).values():
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass
