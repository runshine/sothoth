"""AgentFlow pipeline builder for firmware unpacking."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_repo_root = Path(__file__).resolve().parent.parent
_local_agentflow = _repo_root / "agentflow"
if _local_agentflow.exists() and str(_local_agentflow) not in sys.path:
    sys.path.insert(0, str(_local_agentflow))

from agentflow import Graph, pi, python_node


REVIEW_SUCCESS_CRITERIA = [
    {
        "kind": "output_regex",
        "value": r"AGENTFLOW_REVIEW_(SUCCESS|SKIPPED)",
    }
]


def _write_json_code(payload: dict[str, Any]) -> str:
    return (
        "import json\n"
        "from pathlib import Path\n\n"
        f"payload = json.loads(r'''{json.dumps(payload, ensure_ascii=False)}''')\n"
        "Path(payload['output_file']).parent.mkdir(parents=True, exist_ok=True)\n"
        "Path(payload['output_file']).write_text(json.dumps(payload['data'], ensure_ascii=False, indent=2), encoding='utf-8')\n"
        "print(json.dumps(payload['data'], ensure_ascii=False))\n"
    )


def _preprocess_code(ctx: dict[str, Any]) -> str:
    payload = {
        "firmware_path": ctx["firmware_path"],
        "output_path": ctx["output_path"],
        "log_dir": ctx.get("log_dir"),
        "output_file": ctx["preprocess_output_file"],
    }
    return (
        "import json\n"
        "from pathlib import Path\n"
        "from app.preprocess import run_preprocess\n\n"
        f"payload = json.loads(r'''{json.dumps(payload, ensure_ascii=False)}''')\n"
        "log_dir = Path(payload['log_dir']) if payload.get('log_dir') else None\n"
        "try:\n"
        "    result = run_preprocess(payload['firmware_path'], payload['output_path'], log_dir=log_dir)\n"
        "except Exception as exc:\n"
        "    result = {'success': False, 'method': None, 'error': str(exc)}\n"
        "Path(payload['output_file']).parent.mkdir(parents=True, exist_ok=True)\n"
        "Path(payload['output_file']).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')\n"
        "print(json.dumps(result, ensure_ascii=False))\n"
    )


def _feature_match_code(ctx: dict[str, Any]) -> str:
    payload = {
        "firmware_path": ctx["firmware_path"],
        "tools_dir": ctx["tools_dir"],
        "output_file": ctx["feature_match_output_file"],
    }
    return (
        "import json\n"
        "from pathlib import Path\n"
        "from app.unpacker_engine import extract_firmware_features\n"
        "from app.skill_store import compute_family_id, match_skill\n\n"
        f"payload = json.loads(r'''{json.dumps(payload, ensure_ascii=False)}''')\n"
        "try:\n"
        "    features = extract_firmware_features(payload['firmware_path'])\n"
        "    features['family_id'] = compute_family_id(features)\n"
        "    skill_meta, skill_score, skill_match = match_skill(features, Path(payload['tools_dir']))\n"
        "    result = {\n"
        "        'features': features,\n"
        "        'matched_skill': skill_meta.get('path') if skill_meta else None,\n"
        "        'matched_skill_version': skill_meta.get('skill_version') if skill_meta else None,\n"
        "        'matched_skill_score': skill_score,\n"
        "        'matched_status': skill_match.get('matched_status'),\n"
        "        'reasons': skill_match.get('reasons'),\n"
        "        'system_prompt': skill_meta.get('system_prompt') if skill_meta else None,\n"
        "    }\n"
        "except Exception as exc:\n"
        "    result = {'features': {}, 'matched_skill': None, 'matched_skill_score': 0, 'error': str(exc)}\n"
        "Path(payload['output_file']).parent.mkdir(parents=True, exist_ok=True)\n"
        "Path(payload['output_file']).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')\n"
        "print(json.dumps(result, ensure_ascii=False))\n"
    )


def build_firmware_unpack_pipeline(ctx: dict[str, Any]):
    """Build the first-pass firmware unpacking graph.

    The graph is intentionally linear so the runner can preserve the legacy
    execution semantics while AgentFlow owns the lifecycle, artifacts, and
    cancellation plumbing.
    """

    base_dir = ctx["base_dir"]
    with Graph(
        "firmware-unpack",
        working_dir=base_dir,
        concurrency=ctx.get("agentflow_concurrency", 2),
        max_iterations=ctx.get("max_retries", 5),
        use_worktree=ctx.get("use_worktree", False),
        fail_fast=False,
    ) as g:
        preprocess = python_node(
            task_id="preprocess",
            code=_preprocess_code(ctx),
            tools="read_only",
        )
        feature_match = python_node(
            task_id="feature_match",
            code=_feature_match_code(ctx),
            tools="read_only",
        )
        skill_executor = pi(
            task_id="skill_executor",
            prompt=(
                "Output protocol: print exactly one final marker line when skipping.\n"
                "- If Preprocess contains JSON with success=true, do not call tools and print exactly: AGENTFLOW_EXECUTOR_SKIPPED reason=SKIPPED_BY_PREPROCESS\n"
                "- If Context has no matched_skill, do not call tools and print exactly: AGENTFLOW_EXECUTOR_SKIPPED reason=SKIPPED_NO_SKILL\n"
                "Otherwise use the system_prompt from feature_match as the reusable skill guidance.\n"
                f"Firmware: {ctx['firmware_path']}\n"
                f"Output path: {ctx['output_path']}\n"
                "Context: {{ nodes.feature_match.output }}\n"
                "Preprocess: {{ nodes.preprocess.output }}\n"
            ),
            tools="read_write",
            model=ctx.get("executor_model"),
            extra_args=ctx.get("executor_extra_args", []),
            timeout_seconds=ctx.get("node_timeout_seconds", 1800),
        )
        skill_reviewer = pi(
            task_id="skill_reviewer",
            prompt=(
                "Output protocol: print exactly one final marker line.\n"
                "- If skill_executor emitted AGENTFLOW_EXECUTOR_SKIPPED or any SKIPPED marker, print AGENTFLOW_REVIEW_SKIPPED reason=<same marker>.\n"
                "- If the matched-skill extraction is valid, print AGENTFLOW_REVIEW_SUCCESS.\n"
                "- If it is invalid, print AGENTFLOW_REVIEW_FAIL reason=<short reason>.\n"
                "Review the matched-skill extraction result.\n"
                "Executor output: {{ nodes.skill_executor.output }}\n"
            ),
            tools="read_only",
            model=ctx.get("review_model"),
            extra_args=ctx.get("review_extra_args", []),
            timeout_seconds=max(300, int(ctx.get("node_timeout_seconds", 1800) // 2)),
            success_criteria=REVIEW_SUCCESS_CRITERIA,
        )
        generic_executor = pi(
            task_id="generic_executor",
            prompt=(
                "Output protocol: print exactly one final marker line when skipping.\n"
                "- If Preprocess contains JSON with success=true, do not call tools and print exactly: AGENTFLOW_EXECUTOR_SKIPPED reason=SKIPPED_BY_PREPROCESS\n"
                "- If Skill review contains AGENTFLOW_REVIEW_SUCCESS, do not call tools and print exactly: AGENTFLOW_EXECUTOR_SKIPPED reason=SKIPPED_BY_SKILL_SUCCESS\n"
                "Unpack the firmware. Use the retry context when present.\n"
                f"Firmware: {ctx['firmware_path']}\n"
                f"Output path: {ctx['output_path']}\n"
                "{% if nodes.skill_reviewer.output %}Skill review: {{ nodes.skill_reviewer.output }}{% endif %}\n"
                "{% if nodes.generic_reviewer.output %}Previous review: {{ nodes.generic_reviewer.output }}{% endif %}\n"
                "{% if nodes.preprocess.output %}Preprocess: {{ nodes.preprocess.output }}{% endif %}"
            ),
            tools="read_write",
            model=ctx.get("executor_model"),
            extra_args=ctx.get("executor_extra_args", []),
            timeout_seconds=ctx.get("node_timeout_seconds", 1800),
        )
        generic_reviewer = pi(
            task_id="generic_reviewer",
            prompt=(
                "Output protocol: print exactly one final marker line.\n"
                "- If generic_executor emitted AGENTFLOW_EXECUTOR_SKIPPED or any SKIPPED marker, print AGENTFLOW_REVIEW_SKIPPED reason=<same marker>.\n"
                "- If the generic extraction is valid, print AGENTFLOW_REVIEW_SUCCESS.\n"
                "- If it is invalid, print AGENTFLOW_REVIEW_FAIL reason=<short reason>.\n"
                "Review the generic unpack result.\n"
                "Executor output: {{ nodes.generic_executor.output }}\n"
            ),
            tools="read_only",
            model=ctx.get("review_model"),
            extra_args=ctx.get("review_extra_args", []),
            timeout_seconds=max(300, int(ctx.get("node_timeout_seconds", 1800) // 2)),
            success_criteria=REVIEW_SUCCESS_CRITERIA,
        )
        skill_author = pi(
            task_id="skill_author",
            prompt=(
                "If neither reviewer output contains AGENTFLOW_REVIEW_SUCCESS, emit SKIPPED_NO_SUCCESS.\n"
                "Author a reusable skill candidate from the successful unpack.\n"
                "Features: {{ nodes.feature_match.output }}\n"
                "Review: {{ nodes.generic_reviewer.output }}\n"
                "Output summary: {{ nodes.generic_executor.output }}\n"
            ),
            tools="read_write",
            model=ctx.get("author_model"),
            extra_args=ctx.get("author_extra_args", []),
            timeout_seconds=ctx.get("node_timeout_seconds", 1800),
        )
        cleanup = pi(
            task_id="cleanup",
            prompt=(
                "Clean and normalize the output directory.\n"
                "Output path: {{ pipeline.working_dir }}/output\n"
            ),
            tools="read_write",
            model=ctx.get("cleanup_model"),
            extra_args=ctx.get("cleanup_extra_args", []),
            timeout_seconds=max(300, int(ctx.get("node_timeout_seconds", 1800) // 3)),
        )
        finalize = python_node(
            task_id="finalize",
            code=_write_json_code(
                {
                    "output_file": ctx["final_result_file"],
                    "data": {
                        "engine_mode": "agentflow",
                        "firmware_path": ctx["firmware_path"],
                        "output_path": ctx["output_path"],
                    },
                }
            ),
            tools="read_only",
        )

        preprocess >> feature_match >> skill_executor >> skill_reviewer
        skill_reviewer.on_failure >> generic_executor
        skill_reviewer >> generic_executor
        generic_executor >> generic_reviewer
        generic_reviewer.on_failure >> generic_executor
        generic_reviewer >> skill_author >> cleanup >> finalize

    return g.to_spec()
