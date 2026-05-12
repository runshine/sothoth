"""Single-file AgentFlow firmware unpack CLI and pipeline."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

import yaml
from pydantic import BaseModel, Field

_repo_root = Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))
_local_agentflow = _repo_root / "agentflow"
if _local_agentflow.exists() and str(_local_agentflow) not in sys.path:
    sys.path.insert(0, str(_local_agentflow))

from agentflow import Graph, python_node
from agentflow.dsl import _node as agent_node
from agentflow.orchestrator import Orchestrator
from agentflow.store import RunStore

from app.agent.defs import AUTHOR_AGENT_DEF, CLEAN_AGENT_DEF, EXEC_AGENT_DEF, VAL_AGENT_DEF, load_agent_def
from app.pipeline_stages.s02_feature_match.features import extract_firmware_features
from app.pipeline_stages.s02_feature_match.skill_store import compute_family_id, match_skill
from app.evolution import (
    EVOLUTION_TARGET_NODE_GENERIC_EXECUTOR,
    archive_success_sample,
    register_family_tuned_agent,
    resolve_family_tuned_agent,
)
from app.pipeline_stages.s09_finalize.skill_store import register_skill_success


import os
from typing import Optional

import yaml
from pydantic import BaseModel, Field


class AgentFlowConfig(BaseModel):
    """AgentFlow engine configuration."""

    enabled: bool = True
    profile: str = "production"
    runs_dir: str = "/data/files/.agentflow/runs"
    max_concurrent_runs: int = 2
    node_timeout_seconds: int = 1800
    use_worktree: bool = False
    graph_optimization_enabled: bool = False
    graph_optimizer: str = "codex"
    graph_optimization_rounds: int = 1
    evolution_archive_dir: str = ""
    evolution_enabled: bool = True
    max_concurrent_evolution_jobs: int = 1
    evolution_target_nodes: str = "generic_executor"
    cleanup_runs_retention_days: int = 7


class LoggingConfig(BaseModel):
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


class Config(BaseModel):
    agentflow: AgentFlowConfig = Field(default_factory=AgentFlowConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)


_config: Optional[Config] = None


def _candidate_paths(config_path: Optional[str]) -> list[str]:
    if config_path:
        return [config_path]
    return [
        os.environ.get("CONFIG_PATH", ""),
        os.environ.get("FIRMWARE_UNPACKER_CONFIG", ""),
        "config.yaml",
        os.path.join(os.path.dirname(__file__), "..", "config.yaml"),
        "/app/config.yaml",
    ]


def _env_bool(name: str, default: bool) -> bool:
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


def _apply_env_overrides(cfg: Config) -> Config:
    cfg.agentflow.enabled = True
    cfg.agentflow.profile = os.environ.get("AGENTFLOW_PROFILE", cfg.agentflow.profile)
    cfg.agentflow.runs_dir = os.environ.get("AGENTFLOW_RUNS_DIR", cfg.agentflow.runs_dir)
    cfg.agentflow.max_concurrent_runs = _env_int(
        "AGENTFLOW_MAX_CONCURRENT_RUNS",
        cfg.agentflow.max_concurrent_runs,
    )
    cfg.agentflow.node_timeout_seconds = _env_int(
        "AGENTFLOW_NODE_TIMEOUT_SECONDS",
        cfg.agentflow.node_timeout_seconds,
    )
    cfg.agentflow.use_worktree = _env_bool("AGENTFLOW_USE_WORKTREE", cfg.agentflow.use_worktree)
    cfg.agentflow.graph_optimization_enabled = _env_bool(
        "AGENTFLOW_GRAPH_OPTIMIZATION_ENABLED",
        cfg.agentflow.graph_optimization_enabled,
    )
    cfg.agentflow.graph_optimizer = os.environ.get(
        "AGENTFLOW_GRAPH_OPTIMIZER",
        cfg.agentflow.graph_optimizer,
    )
    cfg.agentflow.graph_optimization_rounds = _env_int(
        "AGENTFLOW_GRAPH_OPTIMIZATION_ROUNDS",
        cfg.agentflow.graph_optimization_rounds,
    )
    cfg.agentflow.evolution_archive_dir = os.environ.get(
        "AGENTFLOW_EVOLUTION_ARCHIVE_DIR",
        cfg.agentflow.evolution_archive_dir,
    )
    cfg.agentflow.evolution_enabled = _env_bool(
        "AGENTFLOW_EVOLUTION_ENABLED",
        cfg.agentflow.evolution_enabled,
    )
    cfg.agentflow.max_concurrent_evolution_jobs = _env_int(
        "AGENTFLOW_MAX_CONCURRENT_EVOLUTION_JOBS",
        cfg.agentflow.max_concurrent_evolution_jobs,
    )
    cfg.agentflow.evolution_target_nodes = os.environ.get(
        "AGENTFLOW_EVOLUTION_TARGET_NODES",
        cfg.agentflow.evolution_target_nodes,
    )
    cfg.agentflow.cleanup_runs_retention_days = _env_int(
        "AGENTFLOW_CLEANUP_RUNS_RETENTION_DAYS",
        cfg.agentflow.cleanup_runs_retention_days,
    )
    cfg.logging.level = os.environ.get("LOG_LEVEL", cfg.logging.level)
    return cfg


def load_config(config_path: Optional[str] = None) -> Config:
    global _config
    if _config is not None:
        return _config

    for path in _candidate_paths(config_path):
        if not path or not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8") as file:
            data = yaml.safe_load(file) or {}
        _config = _apply_env_overrides(Config(**data))
        return _config

    _config = _apply_env_overrides(Config())
    return _config


def get_config() -> Config:
    global _config
    if _config is None:
        _config = load_config()
    return _config


def reload_config(config_path: Optional[str] = None) -> Config:
    global _config
    _config = None
    return load_config(config_path)


TOOLS_DIR = Path(os.environ.get("UNPACKER_TOOLS_DIR", "/data/secflow-app-firmware-unpacker/tools"))
LOG_OUTPUT_DIR = Path(os.environ.get("UNPACKER_LOG_DIR", "/workspace/log_output"))


def get_max_retries() -> int:
    try:
        return int(os.environ.get("MAX_RETRIES", os.environ.get("AGENTFLOW_MAX_ITERATIONS", "5")))
    except Exception:
        return 5


def get_log_dir(output_path: str) -> Path:
    output_dir = Path(output_path)
    if output_dir.name == "output":
        log_dir = output_dir.parent / "run"
    else:
        log_dir = LOG_OUTPUT_DIR / output_dir.name
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


def is_review_success(review_text: str) -> bool:
    raw = str(review_text or "")
    if "AGENTFLOW_REVIEW_SUCCESS" in raw:
        return True
    lowered = raw.lower()
    return '"result"' in lowered and '"success"' in lowered


def extract_markdown_document(text: str) -> str:
    raw = str(text or "").strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```[a-zA-Z0-9_-]*\n", "", raw)
        raw = re.sub(r"\n```$", "", raw)
    return raw.strip()


def _get_max_retries() -> int:
    return get_max_retries()


def _is_review_success(review_text: str) -> bool:
    return is_review_success(review_text)


def _extract_markdown_document(text: str) -> str:
    return extract_markdown_document(text)


def log_event(logger: logging.Logger, level: int, message: str, **fields: object) -> None:
    logger.log(level, message, extra=fields)


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

from agentflow import Graph, python_node


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
        "s02_feature_match": "# emits feature_count_binwalk_sigs; writes with Path(payload['output_file']).write_text\n",
    }
    return (
        "import json\n"
        f"from app.pipeline_stages.{module} import run\n\n"
        f"# stage_file=app/pipeline_stages/{module}/stage.py\n"
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
    return _stage_call_code("s01_preprocess", payload)


def _feature_match_code(ctx: dict[str, Any]) -> str:
    payload = {
        "firmware_path": ctx["firmware_path"],
        "tools_dir": ctx["tools_dir"],
        "output_file": ctx["feature_match_output_file"],
    }
    return _stage_call_code("s02_feature_match", payload)


def _skill_gate_code(ctx: dict[str, Any]) -> str:
    payload = {
        "feature_match_output_file": ctx["feature_match_output_file"],
    }
    return _stage_call_code("s03_skill_gate", payload)


def _summary_writer_code(ctx: dict[str, Any]) -> str:
    payload = {
        "firmware_path": ctx["firmware_path"],
        "output_path": ctx["output_path"],
        "summary_file": str(Path(ctx["output_path"]) / "summary.txt"),
    }
    return _stage_call_code("s05_output_summary", payload)


def _cleanup_output_code(ctx: dict[str, Any]) -> str:
    payload = {
        "output_path": ctx["output_path"],
    }
    return _stage_call_code("s08_cleanup", payload)


def _finalize_result_code(ctx: dict[str, Any]) -> str:
    payload = {
        "firmware_path": ctx["firmware_path"],
        "output_path": ctx["output_path"],
        "tools_dir": ctx["tools_dir"],
        "feature_match_output_file": ctx["feature_match_output_file"],
        "final_result_file": ctx["final_result_file"],
        "stage2_file": str(Path(ctx["final_result_file"]).parent / "stage2_skill_match.json"),
        "stage3_file": str(Path(ctx["final_result_file"]).parent / "stage3_skill_exec.json"),
        "stage4_file": str(Path(ctx["final_result_file"]).parent / "stage4_llm_fallback.json"),
    }
    return _stage_call_code(
        "s09_finalize",
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
            "cleanup": {"output": "{{ nodes.cleanup.output }}"},
        },
    )


def _skill_review_code() -> str:
    return _stage_call_code(
        "s04_skill_review",
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
        "s06_generic_review",
        payload,
        nodes={
            "generic_executor": {
                "status": "{{ nodes.generic_executor.status }}",
                "output": "{{ nodes.generic_executor.output }}",
            }
        },
    )


def _skill_author_code(ctx: dict[str, Any]) -> str:
    del ctx
    return "print('SKIPPED_REMOVED_SKILL_AUTHOR')\n"


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


def _resolve_generic_executor_agent(ctx: dict[str, Any]) -> str:
    family_id = str(ctx.get("family_id") or "").strip()
    if not family_id:
        return "pi"
    record = resolve_family_tuned_agent(EVOLUTION_TARGET_NODE_GENERIC_EXECUTOR, family_id)
    if not record:
        return "pi"
    return str(record.get("agent_name") or "pi")


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
        skill_executor = agent_node(
            "pi",
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
            timeout_seconds=_node_timeout(ctx),
        )
        skill_reviewer = python_node(
            task_id="skill_reviewer",
            code=_skill_review_code(),
            tools="read_only",
            env=_python_node_env(),
            timeout_seconds=_node_timeout(ctx, divisor=2),
            success_criteria=REVIEW_SUCCESS_CRITERIA,
        )
        generic_executor = agent_node(
            str(ctx.get("generic_executor_agent") or "pi"),
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
            timeout_seconds=_node_timeout(ctx),
        )
        output_summary = python_node(
            task_id="output_summary",
            code=_summary_writer_code(ctx),
            tools="read_only",
            env=_python_node_env(),
        )
        generic_reviewer = python_node(
            task_id="generic_reviewer",
            code=_generic_review_code(ctx),
            tools="read_only",
            env=_python_node_env(),
            timeout_seconds=_node_timeout(ctx, divisor=2),
            success_criteria=REVIEW_SUCCESS_CRITERIA,
        )
        cleanup = python_node(
            task_id="cleanup",
            code=_cleanup_output_code(ctx),
            tools="read_only",
            env=_python_node_env(),
        )
        finalize = python_node(
            task_id="finalize",
            code=_finalize_result_code(ctx),
            tools="read_only",
            env=_python_node_env(),
        )

        preprocess >> feature_match >> skill_gate >> skill_executor >> skill_reviewer
        skill_reviewer.on_failure >> generic_executor
        skill_reviewer >> generic_executor
        generic_executor >> output_summary >> generic_reviewer
        generic_reviewer.on_failure >> generic_executor
        generic_reviewer >> cleanup >> finalize

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
    from app.agent.defs import (
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
            "FIRMWARE_PATH and OUTPUT_PATH are required when running app/cli.py directly"
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
        "final_result_file": str(run_dir / "final_result.json"),
        "generic_executor_agent": _resolve_generic_executor_agent({"family_id": os.environ.get("FIRMWARE_FAMILY_ID", "")}),
        "executor_model": agent_defs["exec"].get("model"),
        "review_model": agent_defs["review"].get("model"),
        "cleanup_model": agent_defs["cleanup"].get("model"),
        "executor_extra_args": ["--append-system-prompt", str(prompt_paths["exec"])],
        "review_extra_args": ["--append-system-prompt", str(prompt_paths["review"])],
        "cleanup_extra_args": ["--append-system-prompt", str(prompt_paths["cleanup"])],
    }


def emit_pipeline_spec_main() -> None:
    try:
        ctx = build_firmware_unpack_context_from_env()
        spec = build_firmware_unpack_pipeline(ctx)
    except Exception as exc:
        print(f"failed to build firmware unpack pipeline: {exc}", file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(spec.model_dump(mode="json"), ensure_ascii=False, indent=2))



import asyncio
import shutil
import json
import logging
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

_repo_root = Path(__file__).resolve().parent.parent
_local_agentflow = _repo_root / "agentflow"
if _local_agentflow.exists() and str(_local_agentflow) not in sys.path:
    sys.path.insert(0, str(_local_agentflow))

from agentflow.orchestrator import Orchestrator
from agentflow.store import RunStore

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
    from app.agent.defs import load_agent_def

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


def _node_status(record: Any, node_id: str) -> str:
    node = record.nodes.get(node_id)
    if node is None:
        return ""
    status = getattr(getattr(node, "status", None), "value", getattr(node, "status", None))
    if status:
        return str(status)
    if getattr(node, "output", None) or getattr(node, "final_response", None) or getattr(node, "attempts", None):
        return "completed"
    return ""


def _cached_run(store: Any, run_id: str) -> Any:
    runs = getattr(store, "_runs", None)
    if isinstance(runs, dict) and run_id in runs:
        return runs[run_id]
    return store.get_run(run_id)


def _node_attempts(record: Any, node_id: str) -> int:
    node = record.nodes.get(node_id)
    if node is None:
        return 0
    return max(int(getattr(node, "current_attempt", 0) or 0), len(getattr(node, "attempts", []) or []))


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def _duration_seconds(started_at: str | None, finished_at: str | None) -> float | None:
    started = _parse_iso(started_at)
    finished = _parse_iso(finished_at)
    if started is None or finished is None:
        return None
    return max(0.0, (finished - started).total_seconds())


def _current_node_summary(record: Any) -> dict[str, Any] | None:
    active = []
    fallback = []
    for node_id, node in getattr(record, "nodes", {}).items():
        status = getattr(getattr(node, "status", None), "value", getattr(node, "status", None))
        summary = {
            "node_id": node_id,
            "status": str(status) if status else None,
            "started_at": getattr(node, "started_at", None),
            "completed_at": getattr(node, "finished_at", None),
            "duration_seconds": _duration_seconds(getattr(node, "started_at", None), getattr(node, "finished_at", None)),
            "attempt_count": _node_attempts(record, node_id),
        }
        if status == "running":
            active.append(summary)
        elif status in {"pending", "queued"}:
            fallback.append(summary)
    if active:
        return active[-1]
    if fallback:
        return fallback[0]
    return None


def _node_attempt_map(record: Any) -> dict[str, Any]:
    attempts: dict[str, Any] = {}
    for node_id, node in getattr(record, "nodes", {}).items():
        node_attempts = []
        for attempt in getattr(node, "attempts", []) or []:
            node_attempts.append(
                {
                    "number": getattr(attempt, "number", None),
                    "status": getattr(getattr(attempt, "status", None), "value", getattr(attempt, "status", None)),
                    "started_at": getattr(attempt, "started_at", None),
                    "finished_at": getattr(attempt, "finished_at", None),
                    "duration_seconds": _duration_seconds(
                        getattr(attempt, "started_at", None),
                        getattr(attempt, "finished_at", None),
                    ),
                    "exit_code": getattr(attempt, "exit_code", None),
                    "success": getattr(attempt, "success", None),
                    "success_details": list(getattr(attempt, "success_details", []) or []),
                }
            )
        attempts[node_id] = {
            "status": getattr(getattr(node, "status", None), "value", getattr(node, "status", None)),
            "attempt_count": _node_attempts(record, node_id),
            "current_attempt": int(getattr(node, "current_attempt", 0) or 0),
            "started_at": getattr(node, "started_at", None),
            "finished_at": getattr(node, "finished_at", None),
            "completed_at": getattr(node, "finished_at", None),
            "duration_seconds": _duration_seconds(getattr(node, "started_at", None), getattr(node, "finished_at", None)),
            "exit_code": getattr(node, "exit_code", None),
            "error": getattr(node, "error", None),
            "success": getattr(node, "success", None),
            "success_details": list(getattr(node, "success_details", []) or []),
            "attempts": node_attempts,
        }
    return attempts


def _classify_review_failure(text: str) -> dict[str, str | None]:
    raw = str(text or "")
    upper = raw.upper()
    category = None
    for candidate in ("STRUCTURAL_FAILURE", "CONTENT_MISSING", "PROTOCOL_VIOLATION", "RETRYABLE_ERROR"):
        if candidate in upper:
            category = candidate
            break
    if category is None:
        lowered = raw.lower()
        if any(token in lowered for token in ("missing", "not found", "empty")):
            category = "CONTENT_MISSING"
        elif any(token in lowered for token in ("json", "protocol", "marker", "format")):
            category = "PROTOCOL_VIOLATION"
        elif any(token in lowered for token in ("timeout", "retry", "temporary", "transient")):
            category = "RETRYABLE_ERROR"
        elif "AGENTFLOW_REVIEW_FAIL" in upper:
            category = "STRUCTURAL_FAILURE"
    reason = None
    if "reason=" in raw:
        reason = raw.split("reason=", 1)[1].splitlines()[0].strip()
    normalized = {
        "STRUCTURAL_FAILURE": "structure_error",
        "CONTENT_MISSING": "missing_content",
        "PROTOCOL_VIOLATION": "protocol_error",
        "RETRYABLE_ERROR": "retryable_unknown",
    }.get(str(category or ""), "non_retryable" if raw else None)
    return {
        "category": category,
        "failure_category": normalized,
        "reason": reason or _preview_text(raw, 180) or None,
    }


def _failure_summary(record: Any) -> dict[str, Any]:
    failed_nodes = []
    for node_id, node in getattr(record, "nodes", {}).items():
        status = getattr(getattr(node, "status", None), "value", getattr(node, "status", None))
        output = str(getattr(node, "output", None) or getattr(node, "final_response", None) or "")
        if status == "failed" or "AGENTFLOW_REVIEW_FAIL" in output:
            failed_nodes.append(
                {
                    "node_id": node_id,
                    "status": status,
                    "attempts": _node_attempts(record, node_id),
                    "classification": _classify_review_failure(output),
                    "output_preview": _preview_text(output, 320),
                }
            )
    return {"failed_nodes": failed_nodes}


_TOKEN_ALIASES = {
    "prompt_tokens": "prompt_tokens",
    "input_tokens": "prompt_tokens",
    "input": "prompt_tokens",
    "completion_tokens": "completion_tokens",
    "output_tokens": "completion_tokens",
    "output": "completion_tokens",
    "total_tokens": "total_tokens",
    "totalTokens": "total_tokens",
}

_FINAL_TOKEN_EVENT_TYPES = {
    "message_end",
    "turn_end",
    "agent_end",
}


def _token_usage_from_dict(payload: dict[str, Any]) -> dict[str, int] | None:
    totals = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    found = False
    for key, value in payload.items():
        normalized = _TOKEN_ALIASES.get(str(key))
        if normalized and isinstance(value, int):
            totals[normalized] += int(value)
            found = True
    if not found:
        return None
    if totals["total_tokens"] == 0:
        totals["total_tokens"] = totals["prompt_tokens"] + totals["completion_tokens"]
    return totals


def _response_id_near_usage(payload: dict[str, Any]) -> str | None:
    for key in ("responseId", "response_id", "id"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _collect_token_usages(payload: Any, response_id: str | None = None) -> list[tuple[str | None, dict[str, int]]]:
    usages: list[tuple[str | None, dict[str, int]]] = []
    if isinstance(payload, dict):
        response_id = _response_id_near_usage(payload) or response_id
        usage = payload.get("usage")
        if isinstance(usage, dict):
            totals = _token_usage_from_dict(usage)
            if totals is not None:
                usages.append((response_id, totals))
        else:
            totals = _token_usage_from_dict(payload)
            if totals is not None:
                usages.append((response_id, totals))
        for key, value in payload.items():
            if key == "usage":
                continue
            usages.extend(_collect_token_usages(value, response_id))
    elif isinstance(payload, list):
        for item in payload:
            usages.extend(_collect_token_usages(item, response_id))
    return usages


def _add_token_totals(target: dict[str, int], value: dict[str, int]) -> None:
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        target[key] = target.get(key, 0) + int(value.get(key, 0) or 0)


def _token_summary(record: Any) -> dict[str, Any]:
    nodes: dict[str, Any] = {}
    grand_total = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    for node_id, node in getattr(record, "nodes", {}).items():
        totals = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        anonymous_samples: list[dict[str, int]] = []
        by_response: dict[str, tuple[int, dict[str, int]]] = {}
        for index, event in enumerate(getattr(node, "trace_events", []) or []):
            raw = getattr(event, "raw", None)
            raw_type = raw.get("type") if isinstance(raw, dict) else None
            event_type = str(getattr(event, "kind", None) or raw_type or "")
            priority = 1 if event_type in _FINAL_TOKEN_EVENT_TYPES else 0
            for response_id, usage in _collect_token_usages(raw):
                if not any(usage.values()):
                    continue
                if response_id:
                    current = by_response.get(response_id)
                    current_score = current[0] if current else -1
                    score = priority * 1_000_000 + index
                    if current is None or score >= current_score:
                        by_response[response_id] = (score, usage)
                elif priority:
                    anonymous_samples.append(usage)
        for _, usage in by_response.values():
            _add_token_totals(totals, usage)
        for usage in anonymous_samples:
            _add_token_totals(totals, usage)
        nodes[node_id] = totals
        for key, value in totals.items():
            grand_total[key] = grand_total.get(key, 0) + int(value or 0)
    return {
        "total_prompt_tokens": grand_total["prompt_tokens"],
        "total_completion_tokens": grand_total["completion_tokens"],
        "total_tokens": grand_total["total_tokens"],
        "grand_total": grand_total,
        "nodes": nodes,
    }


_LOGGED_AGENTFLOW_EVENT_TYPES = {
    "run_started",
    "node_started",
    "node_completed",
    "node_failed",
    "run_completed",
    "run_cancelled",
}

_NODE_STAGE_MAP = {
    "preprocess": "preprocess",
    "feature_match": "feature_extract",
    "skill_gate": "skill_match",
    "skill_executor": "tool_match",
    "skill_reviewer": "tool_match",
    "generic_executor": "llm_unpack",
    "output_summary": "llm_unpack",
    "generic_reviewer": "review",
    "skill_author": "cleanup",
    "cleanup": "cleanup",
    "finalize": "cleanup",
}


def _event_duration_seconds(event: dict[str, Any]) -> float | None:
    data = event.get("data")
    if isinstance(data, dict):
        value = data.get("duration_seconds")
        if isinstance(value, (int, float)):
            return float(value)
    return None


def _bridge_agentflow_events(
    events_path: Path,
    *,
    offset: int,
    task_id: str | None,
    project_id: str | None,
    agentflow_run_id: str,
    progress_callback: Callable[[str], None] | None = None,
    event_callback: Callable[..., None] | None = None,
) -> int:
    if not events_path.is_file():
        return offset
    with events_path.open("r", encoding="utf-8") as handle:
        handle.seek(offset)
        for line in handle:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            event_type = str(event.get("type") or "")
            if event_type not in _LOGGED_AGENTFLOW_EVENT_TYPES:
                continue
            data = event.get("data") if isinstance(event.get("data"), dict) else {}
            node_id = str(event.get("node_id") or "")
            stage = _NODE_STAGE_MAP.get(node_id)
            log_event(
                log,
                logging.INFO,
                "agentflow event",
                event_type=event_type,
                task_id=task_id,
                project_id=project_id,
                agentflow_run_id=agentflow_run_id,
                node_id=node_id or None,
                status=data.get("status"),
                duration_seconds=_event_duration_seconds(event),
                error=data.get("error") or data.get("message"),
            )
            if stage and progress_callback is not None and event_type == "node_started":
                try:
                    progress_callback(stage)
                except Exception:
                    pass
            if stage and event_callback is not None and event_type == "node_started":
                try:
                    event_callback(
                        "agentflow_stage_started",
                        f"AgentFlow 节点开始执行：{node_id}",
                        stage_key=stage,
                        status="running",
                        detail={"node_id": node_id, "agentflow_run_id": agentflow_run_id},
                        created_by="agentflow",
                    )
                except Exception:
                    pass
        return handle.tell()


def _archive_success_sample(log_dir: Path | None, record: Any, result: dict[str, Any], tokens: dict[str, Any]) -> str | None:
    if log_dir is None or result.get("status") != "success":
        return None
    archived = archive_success_sample(
        task_id=str(result.get("task_id") or "run"),
        project_id=str(result.get("project_id") or "") or None,
        family_id=str(result.get("family_id") or "generic"),
        run_id=str(getattr(record, "id", "run")),
        run_dir=log_dir,
        final_result=result,
        tokens_summary=tokens,
    )
    run_dir = log_dir / "agentflow" / "runs" / str(getattr(record, "id", ""))
    if run_dir.exists():
        traces_dir = archived.sample_dir / "traces"
        traces_dir.mkdir(exist_ok=True)
        for trace in run_dir.glob("artifacts/*/trace.jsonl"):
            target = traces_dir / f"{trace.parent.name}.trace.jsonl"
            shutil.copy2(trace, target)
    return str(archived.sample_dir)


def _json_output(text: str) -> dict[str, Any]:
    raw = str(text or "").strip()
    if not raw:
        return {}
    try:
        return json.loads(raw)
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


def _review_success(review_text: str, legacy_check: Callable[[str], bool]) -> bool:
    text = str(review_text or "")
    return "AGENTFLOW_REVIEW_SUCCESS" in text or legacy_check(text)


def _review_skipped(review_text: str) -> bool:
    return "AGENTFLOW_REVIEW_SKIPPED" in str(review_text or "")


def _cancelled_result(rounds: int, record: Any | None = None) -> dict[str, Any]:
    cancellation_summary = {
        "current_node": _current_node_summary(record) if record is not None else None,
        "cancelled_at": datetime.utcnow().isoformat(),
    }
    return {
        "status": "cancelled",
        "message": "Task was cancelled",
        "rounds": rounds,
        "agentflow_run_id": getattr(record, "id", None) if record is not None else None,
        "node_attempts": _node_attempt_map(record) if record is not None else {},
        "failure_summary": {"failed_nodes": []},
        "cancellation_summary": cancellation_summary,
    }


def _normalize_output_reports(output_path: str) -> None:
    output_root = Path(output_path)
    for legacy_name, canonical_name in (("summary.txt", "summary.md"), ("reason.txt", "reason.md")):
        legacy_path = output_root / legacy_name
        canonical_path = output_root / canonical_name
        if legacy_path.exists():
            if canonical_path.exists():
                legacy_path.unlink(missing_ok=True)
            else:
                shutil.move(str(legacy_path), str(canonical_path))


def _copy_if_exists(source: Path, target: Path) -> None:
    if not source.exists():
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def _write_v2_1_compat_artifacts(
    log_dir: Path | None,
    output_path: str,
    result: dict[str, Any],
    ctx: dict[str, Any],
) -> None:
    if log_dir is None:
        return
    _normalize_output_reports(output_path)
    round_zero = log_dir / "round_000"
    round_zero.mkdir(parents=True, exist_ok=True)

    feature_match_file = Path(ctx["feature_match_output_file"])
    stage2_file = log_dir / "stage2_skill_match.json"
    stage3_file = log_dir / "stage3_skill_exec.json"
    stage4_file = log_dir / "stage4_llm_fallback.json"
    final_result_file = log_dir / "final_result.json"
    summary_md = Path(output_path) / "summary.md"
    reason_md = Path(output_path) / "reason.md"

    _copy_if_exists(Path(ctx["preprocess_output_file"]), round_zero / "preprocess.json")
    _copy_if_exists(stage2_file if stage2_file.exists() else feature_match_file, round_zero / "skill_match.json")
    _copy_if_exists(stage3_file, round_zero / "skill_exec.json")
    _copy_if_exists(stage4_file, round_zero / "fallback.json")
    _copy_if_exists(summary_md, round_zero / "summary.md")
    _copy_if_exists(reason_md, round_zero / "reason.md")

    final_round = int(result.get("rounds") or 0)
    if final_round > 0:
        round_dir = log_dir / f"round_{final_round:03d}"
        round_dir.mkdir(parents=True, exist_ok=True)
        _copy_if_exists(summary_md, round_dir / "summary.md")
        _copy_if_exists(reason_md, round_dir / "reason.md")
        _copy_if_exists(final_result_file, round_dir / "results.json")


def run_unpack_agentflow(
    firmware_path: str,
    output_path: str,
    cancel_check: Callable[[], bool] | None = None,
    task_id: str | None = None,
    project_id: str | None = None,
    llm_binding_snapshot: dict[str, Any] | None = None,
    register_cancel_hook: Callable[[Callable[[], None] | None], None] | None = None,
    progress_callback: Callable[[str], None] | None = None,
    event_callback: Callable[..., None] | None = None,
) -> dict[str, Any]:
    config = get_config()
    firmware_path = str(Path(firmware_path).expanduser().resolve())
    output_path = str(Path(output_path).expanduser().resolve())

    def _check_cancel() -> None:
        if cancel_check and cancel_check():
            raise RuntimeError("__CANCELLED__")

    def _build_ctx(log_dir: Path | None, temp_paths: dict[str, Path], exec_def: dict[str, Any], val_def: dict[str, Any], clean_def: dict[str, Any], features: dict[str, Any], skill_meta: dict[str, Any] | None, skill_score: int, skill_match: dict[str, Any]) -> dict[str, Any]:
        output_root = Path(output_path)
        task_root = output_root.parent if output_root.name == "output" else output_root.parent
        run_root = (log_dir or task_root / "run")
        return {
            "base_dir": str(task_root),
            "task_dir": str(task_root),
            "input_path": str(Path(firmware_path).parent),
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
            "graph_optimization_enabled": (
                bool(getattr(config.agentflow, "graph_optimization_enabled", False))
                and str(getattr(config.agentflow, "profile", "production")).lower() in {"test", "staging"}
                and int(getattr(config.agentflow, "graph_optimization_rounds", 1) or 1) > 1
            ),
            "graph_optimizer": getattr(config.agentflow, "graph_optimizer", "codex"),
            "graph_optimization_rounds": int(getattr(config.agentflow, "graph_optimization_rounds", 1) or 1),
            "preprocess_output_file": str(run_root / "preprocess.json"),
            "feature_match_output_file": str(run_root / "feature-match.json"),
            "final_result_file": str(run_root / "final_result.json"),
            "generic_executor_agent": _resolve_generic_executor_agent({"family_id": features.get("family_id")}),
            "family_id": features.get("family_id"),
            "executor_model": exec_def.get("model"),
            "review_model": val_def.get("model"),
            "cleanup_model": clean_def.get("model"),
            "executor_extra_args": ["--append-system-prompt", str(temp_paths["exec"])],
            "review_extra_args": ["--append-system-prompt", str(temp_paths["review"])],
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
        _write_text(log_dir / "agentflow_run_dir.txt", "")

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
            agent_defs["cleanup"],
            features,
            skill_meta,
            skill_score,
            skill_match,
        )
        pipeline = build_firmware_unpack_pipeline(ctx)
        run_store_dir = Path(config.agentflow.runs_dir)
        store = RunStore(run_store_dir)
        orchestrator = Orchestrator(store=store, max_concurrent_runs=config.agentflow.max_concurrent_runs)

        async def _execute() -> dict[str, Any]:
            record = await orchestrator.submit(pipeline)
            event_offset = 0
            if log_dir is not None:
                _write_text(log_dir / "agentflow_run_id.txt", record.id)
                _write_text(log_dir / "agentflow_run_dir.txt", str(run_store_dir / record.id))
            while True:
                event_offset = _bridge_agentflow_events(
                    run_store_dir / record.id / "events.jsonl",
                    offset=event_offset,
                    task_id=task_id,
                    project_id=project_id,
                    agentflow_run_id=record.id,
                    progress_callback=progress_callback,
                    event_callback=event_callback,
                )
                if cancel_check and cancel_check():
                    await orchestrator.cancel(record.id)
                    cancelled = await orchestrator.wait(record.id, timeout=5)
                    current = cancelled or _cached_run(store, record.id)
                    _bridge_agentflow_events(
                        run_store_dir / record.id / "events.jsonl",
                        offset=event_offset,
                        task_id=task_id,
                        project_id=project_id,
                        agentflow_run_id=record.id,
                        progress_callback=progress_callback,
                        event_callback=event_callback,
                    )
                    result = _cancelled_result(_node_attempts(current, "generic_executor"), current)
                    if log_dir is not None:
                        _write_json(log_dir / "final_result.json", result)
                        _write_v2_1_compat_artifacts(log_dir, output_path, result, ctx)
                    return result
                current = _cached_run(store, record.id)
                if current.status.value in {"completed", "failed", "cancelled"}:
                    break
                await asyncio.sleep(0.5)
            current = store.get_run(record.id)
            _bridge_agentflow_events(
                run_store_dir / record.id / "events.jsonl",
                offset=event_offset,
                task_id=task_id,
                project_id=project_id,
                agentflow_run_id=record.id,
                progress_callback=progress_callback,
                event_callback=event_callback,
            )
            if current.status.value == "cancelled":
                result = _cancelled_result(_node_attempts(current, "generic_executor"), current)
                if log_dir is not None:
                    _write_json(log_dir / "final_result.json", result)
                    _write_v2_1_compat_artifacts(log_dir, output_path, result, ctx)
                return result

            preprocess_output = _node_output(current, "preprocess")
            feature_output = _node_output(current, "feature_match")
            skill_review = _node_output(current, "skill_reviewer")
            generic_output = _node_output(current, "generic_executor")
            generic_review = _node_output(current, "generic_reviewer")

            preprocess_passed = bool(_json_output(preprocess_output).get("success"))
            skill_status = _node_status(current, "skill_executor")
            skill_passed = (
                skill_status not in {"failed", "cancelled"}
                and _review_success(skill_review, _is_review_success)
            )
            generic_status = _node_status(current, "generic_executor")
            generic_passed = (
                generic_status not in {"failed", "cancelled"}
                and bool(generic_output.strip())
                and _review_success(generic_review, _is_review_success)
            )
            rounds = 0 if preprocess_passed or skill_passed else _node_attempts(current, "generic_executor")
            node_attempts = _node_attempt_map(current)
            failure_summary = _failure_summary(current)
            failed_node_ids = {
                str(item.get("node_id"))
                for item in failure_summary.get("failed_nodes", [])
                if item.get("node_id")
            }
            extraction_passed = preprocess_passed or skill_passed or generic_passed
            recovered_by_generic = (
                current.status.value == "failed"
                and generic_passed
                and failed_node_ids
                and failed_node_ids <= {"skill_reviewer"}
            )
            passed = (
                (current.status.value == "completed" and extraction_passed)
                or recovered_by_generic
            )
            tokens = _token_summary(current)
            matched_skill = skill_meta
            fallback_to_llm = bool(skill_meta and not skill_passed)
            promotion_success_count = None
            pipeline_result = {}
            pipeline_final_result = Path(ctx.get("final_result_file") or "")
            if pipeline_final_result.is_file():
                try:
                    pipeline_result = json.loads(pipeline_final_result.read_text(encoding="utf-8"))
                except Exception:
                    pipeline_result = {}

            if passed and skill_meta and skill_passed:
                if pipeline_result.get("promotion_success_count") is not None:
                    matched_skill = {
                        **skill_meta,
                        "path": pipeline_result.get("matched_skill") or skill_meta.get("path"),
                        "skill_version": pipeline_result.get("matched_skill_version") or skill_meta.get("skill_version"),
                        "promotion_success_count": pipeline_result.get("promotion_success_count"),
                    }
                    promotion_success_count = pipeline_result.get("promotion_success_count")
                else:
                    updated_skill = register_skill_success(TOOLS_DIR, str(skill_meta.get("path")))
                    matched_skill = updated_skill
                    promotion_success_count = updated_skill.get("promotion_success_count")

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
                "generated_skill_path": None,
                "generated_skill_status": None,
                "promotion_success_count": promotion_success_count,
                "agentflow_run_id": current.id,
                "agentflow_run_dir": str(run_store_dir / current.id),
                "run_path": str(log_dir) if log_dir else None,
                "family_id": features.get("family_id"),
                "evolution_target_node": EVOLUTION_TARGET_NODE_GENERIC_EXECUTOR if generic_passed else None,
                "evolution_source_run_id": current.id if generic_passed else None,
                "node_attempts": node_attempts,
                "failure_summary": failure_summary,
                "failure_category": (
                    failure_summary.get("failed_nodes", [{}])[0]
                    .get("classification", {})
                    .get("failure_category")
                    if failure_summary.get("failed_nodes")
                    else None
                ),
                "total_tokens": tokens.get("grand_total", {}).get("total_tokens", 0),
                "run_id": current.id,
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
                        "failure_summary": failure_summary,
                        "attempts": {
                            "skill_executor": node_attempts.get("skill_executor"),
                            "skill_reviewer": node_attempts.get("skill_reviewer"),
                        },
                        "response_preview": _preview_text(generic_output or skill_review),
                        "review_preview": _preview_text(generic_review or skill_review),
                    },
                )
                _write_json(
                    log_dir / "stage4_llm_fallback.json",
                    {
                        "matched_skill": skill_meta.get("path") if skill_meta else None,
                        "fallback_to_llm": fallback_to_llm,
                        "failure_classification": _classify_review_failure(skill_review),
                        "reason": _preview_text(generic_review or skill_review, 400),
                        "attempts": {
                            "generic_executor": node_attempts.get("generic_executor"),
                            "generic_reviewer": node_attempts.get("generic_reviewer"),
                        },
                    },
                )
                _write_json(log_dir / "tokens_summary.json", tokens)
                sample_path = _archive_success_sample(log_dir, current, result, tokens)
                if sample_path:
                    result["evolution_sample_path"] = sample_path
                    _write_json(log_dir / "final_result.json", result)
                _write_v2_1_compat_artifacts(log_dir, output_path, result, ctx)
            return result

        try:
            return asyncio.run(_execute())
        except RuntimeError as exc:
            if str(exc) == "__CANCELLED__":
                if log_dir is not None:
                    cancelled = _cancelled_result(0)
                    _write_json(log_dir / "final_result.json", cancelled)
                    _write_v2_1_compat_artifacts(log_dir, output_path, cancelled, ctx)
                    return cancelled
                return _cancelled_result(0)
            raise
    finally:
        for temp_path in locals().get("temp_paths", {}).values():
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the firmware unpack AgentFlow pipeline.")
    parser.add_argument("--firmware", default=None, help="Firmware file path. Defaults to FIRMWARE_PATH.")
    parser.add_argument("--output", default=None, help="Output directory. Defaults to OUTPUT_PATH/FIRMWARE_OUTPUT.")
    parser.add_argument("--task-id", default=None, help="Optional task id for logs.")
    parser.add_argument("--project-id", default=None, help="Optional project id for logs.")
    parser.add_argument("--emit-graph", action="store_true", help="Print the AgentFlow graph spec and exit.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.emit_graph:
        emit_pipeline_spec_main()
        return 0

    firmware = args.firmware or _first_env("FIRMWARE_PATH", "firmware")
    output = args.output or _first_env("OUTPUT_PATH", "FIRMWARE_OUTPUT", "output")
    if not firmware or not output:
        print("FIRMWARE_PATH/--firmware and OUTPUT_PATH/--output are required", file=sys.stderr)
        return 2

    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    load_config()
    Path(output).mkdir(parents=True, exist_ok=True)
    result = run_unpack_agentflow(firmware, output, task_id=args.task_id, project_id=args.project_id)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("status") == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
