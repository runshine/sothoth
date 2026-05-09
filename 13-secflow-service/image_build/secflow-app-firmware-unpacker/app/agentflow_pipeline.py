"""AgentFlow pipeline builder for firmware unpacking."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

_repo_root = Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))
_local_agentflow = _repo_root / "agentflow"
if _local_agentflow.exists() and str(_local_agentflow) not in sys.path:
    sys.path.insert(0, str(_local_agentflow))

from agentflow import Graph, pi, python_node


REVIEW_SUCCESS_CRITERIA = [
    {
        "kind": "output_regex",
        "value": r'(AGENTFLOW_REVIEW_(SUCCESS|SKIPPED)|"result"\s*:\s*"success")',
    }
]


def _stage_call_code(
    module: str,
    payload: dict[str, Any] | None = None,
    nodes: dict[str, dict[str, str]] | None = None,
) -> str:
    """Build a small python_node wrapper around a readable stage module."""
    payload = payload or {}
    nodes = nodes or {}
    node_lines = ["nodes = {}"]
    for node_id, fields in nodes.items():
        node_lines.append(f"nodes[{node_id!r}] = {{}}")
        for key, value in fields.items():
            node_lines.append(f"nodes[{node_id!r}][{key!r}] = r'''{value}'''")
    compatibility_markers = {
        "feature_match": "# emits feature_count_binwalk_sigs; writes with Path(payload['output_file']).write_text\n",
    }
    return (
        "import json\n"
        f"from app.pipeline_stages.{module} import run\n\n"
        f"# stage_file=app/pipeline_stages/{module}.py\n"
        f"{compatibility_markers.get(module, '')}"
        f"payload = json.loads(r'''{json.dumps(payload, ensure_ascii=False)}''')\n"
        + "\n".join(node_lines)
        + "\n"
        "run(payload, nodes)\n"
    )


def _write_json_code(payload: dict[str, Any]) -> str:
    return (
        "import json\n"
        "from pathlib import Path\n\n"
        f"payload = json.loads(r'''{json.dumps(payload, ensure_ascii=False)}''')\n"
        "Path(payload['output_file']).parent.mkdir(parents=True, exist_ok=True)\n"
        "Path(payload['output_file']).write_text(json.dumps(payload['data'], ensure_ascii=False, indent=2), encoding='utf-8')\n"
        "print(json.dumps(payload['data'], ensure_ascii=False))\n"
    )


def _python_node_env() -> dict[str, str]:
    paths = [str(_repo_root), str(_repo_root / "app")]
    existing = os.environ.get("PYTHONPATH")
    if existing:
        paths.append(existing)
    return {"PYTHONPATH": os.pathsep.join(paths)}


def _node_timeout(ctx: dict[str, Any], divisor: int = 1) -> int:
    configured = int(ctx.get("node_timeout_seconds", 1800))
    return max(1, configured // max(1, divisor))


def _preprocess_code(ctx: dict[str, Any]) -> str:
    payload = {
        "firmware_path": ctx["firmware_path"],
        "output_path": ctx["output_path"],
        "log_dir": ctx.get("log_dir"),
        "output_file": ctx["preprocess_output_file"],
    }
    return _stage_call_code("preprocess", payload)


def _feature_match_code(ctx: dict[str, Any]) -> str:
    payload = {
        "firmware_path": ctx["firmware_path"],
        "tools_dir": ctx["tools_dir"],
        "output_file": ctx["feature_match_output_file"],
    }
    return _stage_call_code("feature_match", payload)


def _skill_gate_code(ctx: dict[str, Any]) -> str:
    payload = {
        "feature_match_output_file": ctx["feature_match_output_file"],
    }
    return _stage_call_code("skill_gate", payload)


def _summary_writer_code(ctx: dict[str, Any]) -> str:
    payload = {
        "firmware_path": ctx["firmware_path"],
        "output_path": ctx["output_path"],
        "summary_file": str(Path(ctx["output_path"]) / "summary.txt"),
    }
    return _stage_call_code("output_summary", payload)


def _cleanup_output_code(ctx: dict[str, Any]) -> str:
    payload = {
        "output_path": ctx["output_path"],
    }
    return _stage_call_code("cleanup", payload)


def _finalize_result_code(ctx: dict[str, Any]) -> str:
    payload = {
        "firmware_path": ctx["firmware_path"],
        "output_path": ctx["output_path"],
        "tools_dir": ctx["tools_dir"],
        "feature_match_output_file": ctx["feature_match_output_file"],
        "skill_author_output_file": ctx["skill_author_output_file"],
        "final_result_file": ctx["final_result_file"],
        "stage2_file": str(Path(ctx["final_result_file"]).parent / "stage2_skill_match.json"),
        "stage3_file": str(Path(ctx["final_result_file"]).parent / "stage3_skill_exec.json"),
        "stage4_file": str(Path(ctx["final_result_file"]).parent / "stage4_llm_fallback.json"),
        "stage5_file": str(Path(ctx["final_result_file"]).parent / "stage5_skill_generate.json"),
    }
    return _stage_call_code(
        "finalize",
        payload,
        nodes={
            "preprocess": {"output": "{{ nodes.preprocess.output }}"},
            "feature_match": {"output": "{{ nodes.feature_match.output }}"},
            "skill_executor": {
                "output": "{{ nodes.skill_executor.output }}",
                "status": "{{ nodes.skill_executor.status }}",
            },
            "skill_reviewer": {"output": "{{ nodes.skill_reviewer.output }}"},
            "generic_executor": {
                "output": "{{ nodes.generic_executor.output }}",
                "status": "{{ nodes.generic_executor.status }}",
            },
            "generic_reviewer": {"output": "{{ nodes.generic_reviewer.output }}"},
            "skill_author": {"output": "{{ nodes.skill_author.output }}"},
            "cleanup": {"output": "{{ nodes.cleanup.output }}"},
        },
    )


def _skill_review_code() -> str:
    return _stage_call_code(
        "skill_review",
        nodes={
            "skill_executor": {
                "status": "{{ nodes.skill_executor.status }}",
                "output": "{{ nodes.skill_executor.output }}",
            }
        },
    )


def _generic_review_code(ctx: dict[str, Any]) -> str:
    payload = {
        "output_path": ctx["output_path"],
    }
    return _stage_call_code(
        "generic_review",
        payload,
        nodes={
            "generic_executor": {
                "status": "{{ nodes.generic_executor.status }}",
                "output": "{{ nodes.generic_executor.output }}",
            }
        },
    )


def _skill_author_code(ctx: dict[str, Any]) -> str:
    payload = {
        "feature_match_output_file": ctx["feature_match_output_file"],
        "output_path": ctx["output_path"],
        "skill_author_output_file": ctx["skill_author_output_file"],
    }
    return _stage_call_code(
        "skill_author",
        payload,
        nodes={"generic_reviewer": {"output": "{{ nodes.generic_reviewer.output }}"}},
    )


def _input_path(ctx: dict[str, Any]) -> str:
    return str(ctx.get("input_path") or Path(ctx["firmware_path"]).parent)


def _executor_env(ctx: dict[str, Any]) -> dict[str, str]:
    """Expose task paths to Pi and its bash tool exactly as the prompts name them."""
    input_path = _input_path(ctx)
    firmware_path = str(ctx["firmware_path"])
    output_path = str(ctx["output_path"])
    return {
        "input": input_path,
        "firmware": firmware_path,
        "output": output_path,
        "FIRMWARE_INPUT": input_path,
        "FIRMWARE_PATH": firmware_path,
        "FIRMWARE_OUTPUT": output_path,
    }


def build_firmware_unpack_pipeline(ctx: dict[str, Any]):
    """Build the first-pass firmware unpacking graph.

    The graph is intentionally linear so AgentFlow owns the lifecycle,
    artifacts, and cancellation plumbing without introducing output directory
    write conflicts.
    """

    base_dir = ctx["base_dir"]
    with Graph(
        "firmware-unpack",
        working_dir=base_dir,
        optimizer=ctx.get("graph_optimizer") if ctx.get("graph_optimization_enabled") else None,
        n_run=max(1, int(ctx.get("graph_optimization_rounds") or 1)) if ctx.get("graph_optimization_enabled") else 1,
        concurrency=ctx.get("agentflow_concurrency", 2),
        max_iterations=ctx.get("max_retries", 5),
        use_worktree=ctx.get("use_worktree", False),
        fail_fast=False,
    ) as g:
        preprocess = python_node(
            task_id="preprocess",
            code=_preprocess_code(ctx),
            tools="read_only",
            env=_python_node_env(),
        )
        feature_match = python_node(
            task_id="feature_match",
            code=_feature_match_code(ctx),
            tools="read_only",
            env=_python_node_env(),
        )
        skill_gate = python_node(
            task_id="skill_gate",
            code=_skill_gate_code(ctx),
            tools="read_only",
            env=_python_node_env(),
        )
        skill_executor = pi(
            task_id="skill_executor",
            prompt=(
                "Output protocol: print exactly one final marker line when skipping.\n"
                "- If Preprocess contains JSON with success=true, do not call tools and print exactly: AGENTFLOW_EXECUTOR_SKIPPED reason=SKIPPED_BY_PREPROCESS\n"
                "- If Skill gate contains matched=false, do not call tools and print exactly: AGENTFLOW_EXECUTOR_SKIPPED reason=SKIPPED_NO_SKILL\n"
                "Otherwise read only the matched skill file path shown by Skill gate and use that file as the reusable skill guidance. Do not read the full feature match JSON.\n"
                "Mandatory runtime constraints override the skill guidance:\n"
                "- Never run recursive extraction that can explode the output tree. Do not use `binwalk -eM` or `binwalk -e -M`.\n"
                "- Run binwalk as `binwalk \"$firmware\" > \"$output/binwalk.txt\"` and inspect it only with bounded shell commands such as `grep ... | head` or `sed -n`.\n"
                "- For byte-offset `dd` extraction, use `bs=4M iflag=skip_bytes,count_bytes skip=<offset> count=<size> status=none`; do not use `bs=1` for large payloads.\n"
                "- Keep large extracted trees under `$output/binwalk_extract`; do not recursively copy the whole tree back into `$output`.\n"
                "- After writing a non-empty `$output/summary.txt`, stop immediately and print exactly: AGENTFLOW_SKILL_DONE.\n"
                "Task variables:\n"
                f"$input = {_input_path(ctx)}\n"
                f"$firmware = {ctx['firmware_path']}\n"
                f"$output = {ctx['output_path']}\n"
                "These variables are exported in the bash tool environment; use them quoted exactly as shown.\n"
                "Use $output exactly as the output directory. Do not write results to its parent directory.\n"
                "Skill gate: {{ nodes.skill_gate.output }}\n"
                "Preprocess: {{ nodes.preprocess.output }}\n"
            ),
            tools="read_write",
            model=ctx.get("executor_model"),
            env=_executor_env(ctx),
            extra_args=ctx.get("executor_extra_args", []),
            timeout_seconds=None,
            skip_if=[
                {
                    "kind": "node_output_contains",
                    "node_id": "preprocess",
                    "value": '"success": true',
                },
                {
                    "kind": "node_output_contains",
                    "node_id": "skill_gate",
                    "value": "matched=false",
                },
            ],
        )
        skill_reviewer = python_node(
            task_id="skill_reviewer",
            code=_skill_review_code(),
            tools="read_only",
            env=_python_node_env(),
            timeout_seconds=_node_timeout(ctx, divisor=2),
            success_criteria=REVIEW_SUCCESS_CRITERIA,
            skip_if=[
                {
                    "kind": "node_output_contains",
                    "node_id": "preprocess",
                    "value": '"success": true',
                },
                {
                    "kind": "node_output_contains",
                    "node_id": "skill_gate",
                    "value": "matched=false",
                },
            ],
        )
        generic_executor = pi(
            task_id="generic_executor",
            prompt=(
                "Output protocol: print exactly one final marker line when skipping.\n"
                "- If Preprocess contains JSON with success=true, do not call tools and print exactly: AGENTFLOW_EXECUTOR_SKIPPED reason=SKIPPED_BY_PREPROCESS\n"
                "- If Skill review contains AGENTFLOW_REVIEW_SUCCESS, do not call tools and print exactly: AGENTFLOW_EXECUTOR_SKIPPED reason=SKIPPED_BY_SKILL_SUCCESS\n"
                "- If `$output/summary.txt` already exists and is non-empty, do not call tools and print exactly: AGENTFLOW_GENERIC_DONE reason=SUMMARY_EXISTS\n"
                "Unpack the firmware. Use the retry context when present.\n"
                "Required execution plan, in order:\n"
                "1. Inspect the firmware with `file \"$firmware\"` and `strings -a -n 8 \"$firmware\" | head -200`.\n"
                "2. Run plain binwalk first, but redirect the full scan to `$output/binwalk.txt`: `binwalk \"$firmware\" > \"$output/binwalk.txt\"`. Never read the full binwalk file through an agent read tool. Inspect it only with bounded shell commands such as `sed -n '1,220p' \"$output/binwalk.txt\"`, `grep -Ei 'squashfs|uImage|zip|7-zip|cpio|tar' \"$output/binwalk.txt\" | head -80`, or `tail -80 \"$output/binwalk.txt\"`.\n"
                "3. Extract only targeted payloads into `$output/binwalk_extract` or a small subdirectory of `$output`, one component at a time, using `dd`, `7z x`, `unzip`, `tar -xf`, `gzip -dc`, `xz -dc`, or `cpio -idmv` as appropriate.\n"
                "For `dd` extractions at byte offsets, do not use `bs=1` for large payloads. Use byte-accurate flags with a large block size, for example: `dd if=\"$firmware\" of=\"$output/binwalk_extract/name.img\" bs=4M iflag=skip_bytes,count_bytes skip=<offset> count=<size> status=none`.\n"
                "4. Prefer the main squashfs image, any uImage, and any obvious archive at a fixed offset. Do not recurse into every discovered blob.\n"
                "5. After extraction, copy the most relevant recovered files into `$output` and keep `summary.txt` at `$output/summary.txt`.\n"
                "Do not recursively copy `$output/binwalk_extract` back into `$output`; that duplicates large trees. Keep extracted trees where they are and copy only a few high-value top-level artifacts when needed.\n"
                "Hard limit: never run recursive extraction that can explode the output tree. Do not use `binwalk -eM`. If a targeted extraction is not possible, record the blocker in `summary.txt` and stop.\n"
                "Task variables:\n"
                f"$input = {_input_path(ctx)}\n"
                f"$firmware = {ctx['firmware_path']}\n"
                f"$output = {ctx['output_path']}\n"
                "These variables are exported in the bash tool environment; use them quoted exactly as shown.\n"
                "Analyze the current firmware file at $firmware first. Use $input only as supporting context.\n"
                "Write every extraction artifact and $output/summary.txt under $output exactly; do not write to the parent directory.\n"
                "Always create $output/summary.txt before finishing, even if no extractable components are found. If nothing can be extracted, record that clearly and stop.\n"
                "After writing a non-empty `$output/summary.txt`, stop immediately and print exactly: AGENTFLOW_GENERIC_DONE. Do not continue exploring, reading, extracting, or analyzing after summary.txt is written.\n"
                "Scope limit: this is a firmware unpacking task, not a vulnerability analysis task. "
                "Use file/binwalk/readelf/strings only as needed to identify and extract components. "
                "Do not perform full disassembly, exploit analysis, or extended reverse engineering. "
                "After identifiable components are extracted and basic metadata is collected, immediately write $output/summary.txt and finish.\n"
                "{% if nodes.skill_reviewer.output %}Skill review: {{ nodes.skill_reviewer.output }}{% endif %}\n"
                "{% if nodes.generic_reviewer.output %}Previous review: {{ nodes.generic_reviewer.output }}{% endif %}\n"
                "{% if nodes.preprocess.output %}Preprocess: {{ nodes.preprocess.output }}{% endif %}"
            ),
            tools="read_write",
            model=ctx.get("executor_model"),
            env=_executor_env(ctx),
            extra_args=ctx.get("executor_extra_args", []),
            timeout_seconds=None,
            skip_if=[],
        )
        output_summary = python_node(
            task_id="output_summary",
            code=_summary_writer_code(ctx),
            tools="read_only",
            env=_python_node_env(),
            skip_if=[
                {
                    "kind": "node_output_contains",
                    "node_id": "preprocess",
                    "value": '"success": true',
                },
            ],
        )
        generic_reviewer = python_node(
            task_id="generic_reviewer",
            code=_generic_review_code(ctx),
            tools="read_only",
            env=_python_node_env(),
            timeout_seconds=_node_timeout(ctx, divisor=2),
            success_criteria=REVIEW_SUCCESS_CRITERIA,
            skip_if=[
                {
                    "kind": "node_output_contains",
                    "node_id": "preprocess",
                    "value": '"success": true',
                },
            ],
        )
        skill_author = python_node(
            task_id="skill_author",
            code=_skill_author_code(ctx),
            tools="read_write",
            env=_python_node_env(),
            skip_if=[
                {
                    "kind": "node_output_contains",
                    "node_id": "preprocess",
                    "value": '"success": true',
                },
            ],
        )
        cleanup = python_node(
            task_id="cleanup",
            code=_cleanup_output_code(ctx),
            tools="read_only",
            env=_python_node_env(),
            skip_if=[
                {
                    "kind": "node_output_contains",
                    "node_id": "preprocess",
                    "value": '"success": true',
                },
            ],
        )
        finalize = python_node(
            task_id="finalize",
            code=_finalize_result_code(ctx),
            tools="read_only",
            env=_python_node_env(),
            skip_if=[
                {
                    "kind": "node_output_contains",
                    "node_id": "preprocess",
                    "value": '"success": true',
                },
            ],
        )

        preprocess >> feature_match >> skill_gate >> skill_executor >> skill_reviewer
        skill_reviewer.on_failure >> generic_executor
        skill_reviewer >> generic_executor
        generic_executor >> output_summary >> generic_reviewer
        generic_reviewer.on_failure >> generic_executor
        generic_reviewer >> skill_author >> cleanup >> finalize

    return g.to_spec()


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _first_env(*names: str) -> str | None:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return None


def _load_agent_defs_for_pipeline() -> dict[str, dict[str, Any]]:
    from app.unpacker_engine import (
        AUTHOR_AGENT_DEF,
        CLEAN_AGENT_DEF,
        EXEC_AGENT_DEF,
        VAL_AGENT_DEF,
        load_agent_def,
    )

    return {
        "exec": load_agent_def(EXEC_AGENT_DEF),
        "review": load_agent_def(VAL_AGENT_DEF),
        "author": load_agent_def(AUTHOR_AGENT_DEF),
        "cleanup": load_agent_def(CLEAN_AGENT_DEF),
    }


def _materialize_system_prompts(run_dir: Path, agent_defs: dict[str, dict[str, Any]]) -> dict[str, Path]:
    prompt_dir = run_dir / "system-prompts"
    prompt_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    for key, agent_def in agent_defs.items():
        path = prompt_dir / f"{key}.md"
        path.write_text(str(agent_def.get("system_prompt") or ""), encoding="utf-8")
        paths[key] = path
    return paths


def build_firmware_unpack_context_from_env() -> dict[str, Any]:
    firmware = _first_env("FIRMWARE_PATH", "firmware")
    output = _first_env("OUTPUT_PATH", "FIRMWARE_OUTPUT", "output")
    if not firmware or not output:
        raise ValueError(
            "FIRMWARE_PATH and OUTPUT_PATH are required when running app/agentflow_pipeline.py directly"
        )

    firmware_path = Path(firmware).expanduser().resolve()
    output_path = Path(output).expanduser().resolve()
    task_dir = Path(_first_env("TASK_DIR", "BASE_DIR") or output_path.parent).expanduser().resolve()
    run_dir = Path(_first_env("RUN_PATH", "LOG_PATH", "FIRMWARE_RUN_PATH") or task_dir / "run").expanduser().resolve()
    tools_dir = Path(
        _first_env("TOOLS_DIR", "UNPACKER_TOOLS_DIR") or _repo_root / "tools"
    ).expanduser().resolve()
    input_path = Path(_first_env("INPUT_PATH", "FIRMWARE_INPUT") or firmware_path.parent).expanduser().resolve()

    output_path.mkdir(parents=True, exist_ok=True)
    run_dir.mkdir(parents=True, exist_ok=True)
    tools_dir.mkdir(parents=True, exist_ok=True)

    agent_defs = _load_agent_defs_for_pipeline()
    prompt_paths = _materialize_system_prompts(run_dir, agent_defs)

    graph_optimization_enabled = _env_bool("AGENTFLOW_GRAPH_OPTIMIZATION_ENABLED", False)
    graph_optimization_rounds = _env_int("AGENTFLOW_GRAPH_OPTIMIZATION_ROUNDS", 1)

    return {
        "base_dir": str(task_dir),
        "task_dir": str(task_dir),
        "input_path": str(input_path),
        "firmware_path": str(firmware_path),
        "firmware_name": firmware_path.name,
        "output_path": str(output_path),
        "log_dir": str(run_dir),
        "tools_dir": str(tools_dir),
        "max_retries": _env_int("MAX_RETRIES", _env_int("AGENTFLOW_MAX_ITERATIONS", 5)),
        "node_timeout_seconds": _env_int("AGENTFLOW_NODE_TIMEOUT_SECONDS", 1800),
        "agentflow_concurrency": _env_int("AGENTFLOW_MAX_CONCURRENT_RUNS", 2),
        "use_worktree": _env_bool("AGENTFLOW_USE_WORKTREE", False),
        "graph_optimization_enabled": graph_optimization_enabled and graph_optimization_rounds > 1,
        "graph_optimizer": os.environ.get("AGENTFLOW_GRAPH_OPTIMIZER", "codex"),
        "graph_optimization_rounds": graph_optimization_rounds,
        "preprocess_output_file": str(run_dir / "preprocess.json"),
        "feature_match_output_file": str(run_dir / "feature-match.json"),
        "skill_author_output_file": str(run_dir / "generated_skill.md"),
        "final_result_file": str(run_dir / "final_result.json"),
        "executor_model": agent_defs["exec"].get("model"),
        "review_model": agent_defs["review"].get("model"),
        "author_model": agent_defs["author"].get("model"),
        "cleanup_model": agent_defs["cleanup"].get("model"),
        "executor_extra_args": ["--append-system-prompt", str(prompt_paths["exec"])],
        "review_extra_args": ["--append-system-prompt", str(prompt_paths["review"])],
        "author_extra_args": ["--append-system-prompt", str(prompt_paths["author"])],
        "cleanup_extra_args": ["--append-system-prompt", str(prompt_paths["cleanup"])],
    }


def main() -> None:
    try:
        ctx = build_firmware_unpack_context_from_env()
        spec = build_firmware_unpack_pipeline(ctx)
    except Exception as exc:
        print(f"failed to build firmware unpack pipeline: {exc}", file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(spec.model_dump(mode="json"), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
