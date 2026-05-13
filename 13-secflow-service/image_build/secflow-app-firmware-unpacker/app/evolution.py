"""AgentFlow tuned-agent evolution helpers for firmware unpack tasks."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.config import get_config

EVOLUTION_PENDING = "pending"
EVOLUTION_RUNNING = "running"
EVOLUTION_SUCCESS = "success"
EVOLUTION_FAILED = "failed"
EVOLUTION_NOT_APPLICABLE = "not_applicable"

EVOLUTION_TARGET_NODE_GENERIC_EXECUTOR = "generic_executor"
DEFAULT_EVOLUTION_TARGET_AGENT = "codex"
DEFAULT_EVOLUTION_OPTIMIZER = "codex"

_REPO_ROOT = Path(__file__).resolve().parent.parent
_TUNER_CONFIG_DIR = "agent_tuner"
_CODEX_HOME_COMPAT_PATCHED = False


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower())
    return slug.strip("-") or "generic"


def evolution_archive_root() -> Path:
    configured = str(get_config().agentflow.evolution_archive_dir or "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return (Path(get_config().agentflow.runs_dir).expanduser().resolve().parent / "evolution").resolve()


def evolution_enabled() -> bool:
    return bool(getattr(get_config().agentflow, "evolution_enabled", True))


def evolution_target_nodes() -> list[str]:
    raw = str(getattr(get_config().agentflow, "evolution_target_nodes", EVOLUTION_TARGET_NODE_GENERIC_EXECUTOR) or "")
    values = [_slugify(item) for item in raw.split(",") if item.strip()]
    return values or [EVOLUTION_TARGET_NODE_GENERIC_EXECUTOR]


def max_concurrent_evolution_jobs() -> int:
    try:
        return max(1, int(getattr(get_config().agentflow, "max_concurrent_evolution_jobs", 1) or 1))
    except Exception:
        return 1


def tuned_profile_name(target_node: str, family_id: str) -> str:
    return f"{_slugify(target_node)}--{_slugify(family_id)}"


def tuned_agent_alias(target_node: str, family_id: str) -> str:
    return f"{tuned_profile_name(target_node, family_id)}-tuned"


def family_sample_dir(root: Path, family_id: str, task_id: str, run_id: str) -> Path:
    return root / "samples" / _slugify(family_id) / f"{task_id}-{run_id}"


def family_registry_path(root: Path) -> Path:
    return root / "registry.json"


def tuned_manifest_path(root: Path, target_node: str, family_id: str, version: str) -> Path:
    return root / "tuned_agents" / _slugify(target_node) / _slugify(family_id) / version / "manifest.json"


def load_family_registry(root: Path | None = None) -> dict[str, Any]:
    path = family_registry_path(root or evolution_archive_root())
    if not path.exists():
        return {"targets": {}}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"targets": {}}
    if not isinstance(payload, dict):
        return {"targets": {}}
    payload.setdefault("targets", {})
    return payload


def save_family_registry(payload: dict[str, Any], root: Path | None = None) -> None:
    path = family_registry_path(root or evolution_archive_root())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def register_family_tuned_agent(
    *,
    root: Path,
    target_node: str,
    family_id: str,
    agent_name: str,
    version: str,
    task_id: str,
    run_id: str,
    status: str = "active",
) -> dict[str, Any]:
    payload = load_family_registry(root)
    targets = payload.setdefault("targets", {})
    node_bucket = targets.setdefault(_slugify(target_node), {})
    family_key = _slugify(family_id)
    record = {
        "target_node": _slugify(target_node),
        "family_id": family_key,
        "agent_name": agent_name,
        "version": version,
        "status": status,
        "task_id": task_id,
        "source_run_id": run_id,
    }
    node_bucket[family_key] = record
    save_family_registry(payload, root)
    return record


def resolve_family_tuned_agent(target_node: str, family_id: str, *, root: Path | None = None) -> dict[str, Any] | None:
    payload = load_family_registry(root)
    targets = payload.get("targets") or {}
    node_bucket = targets.get(_slugify(target_node)) or {}
    record = node_bucket.get(_slugify(family_id))
    if not isinstance(record, dict):
        return None
    if str(record.get("status") or "").strip().lower() not in {"active", "evaluated"}:
        return None
    return record


def _git_output(args: list[str], *, cwd: Path) -> str | None:
    completed = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        return None
    value = (completed.stdout or "").strip()
    return value or None


def _repo_clone_source() -> tuple[Path, str, str | None]:
    git_root_raw = _git_output(["rev-parse", "--show-toplevel"], cwd=_REPO_ROOT)
    branch = _git_output(["branch", "--show-current"], cwd=_REPO_ROOT) or "main"
    if not git_root_raw:
        return _REPO_ROOT, branch, None
    git_root = Path(git_root_raw).expanduser().resolve()
    try:
        workdir_subpath = str(_REPO_ROOT.relative_to(git_root))
    except ValueError:
        workdir_subpath = None
    return git_root, branch, workdir_subpath


def _prompt_surface_paths(workdir_subpath: str | None) -> list[str]:
    relative_path = Path("app/agent/prompt/unpack-firmware.md")
    if not workdir_subpath:
        return [str(relative_path)]
    return [str(Path(workdir_subpath) / relative_path)]


def _evolution_executable_path() -> str:
    resolved = shutil.which(DEFAULT_EVOLUTION_TARGET_AGENT)
    return resolved or ""


def apply_agentflow_evolution_compat_patches() -> None:
    global _CODEX_HOME_COMPAT_PATCHED
    if _CODEX_HOME_COMPAT_PATCHED:
        return

    from agentflow.agents.codex import CodexAdapter

    original_prepare = CodexAdapter.prepare

    def _patched_prepare(self, node, prompt, paths):
        prepared = original_prepare(self, node, prompt, paths)
        host_home = str(os.environ.get("HOME") or "").strip()
        host_codex_home = str(os.environ.get("CODEX_HOME") or "").strip()
        if not host_codex_home and host_home:
            host_codex_home = str((Path(host_home) / ".codex").resolve())
        codex_home = str(prepared.env.get("CODEX_HOME") or "").strip()
        prepared_home = str(prepared.env.get("HOME") or "").strip()
        if host_home and codex_home and prepared_home == codex_home:
            prepared.env["HOME"] = host_home
        if host_codex_home and codex_home and host_codex_home != codex_home:
            prepared.env["CODEX_HOME"] = host_codex_home
        return prepared

    CodexAdapter.prepare = _patched_prepare
    _CODEX_HOME_COMPAT_PATCHED = True


def ensure_tuner_profile(workspace: Path, *, profile: str, alias: str) -> Path:
    apply_agentflow_evolution_compat_patches()
    tuner_dir = workspace / _TUNER_CONFIG_DIR
    tuner_dir.mkdir(parents=True, exist_ok=True)
    path = tuner_dir / f"{profile}.yaml"
    if path.exists():
        return path
    repo_root, default_branch, workdir_subpath = _repo_clone_source()
    payload = {
        "name": alias,
        "base_agent": DEFAULT_EVOLUTION_TARGET_AGENT,
        "repo_url": str(repo_root),
        "default_branch": default_branch,
        "workdir_subpath": workdir_subpath,
        "build_command": "python -m compileall app",
        "test_command": "pytest -q tests/test_agentflow_migration.py tests/test_task_manager.py tests/test_task_result_api.py",
        "smoke_command": "python -c \"print('agentflow evolution smoke ok')\"",
        "executable_path": _evolution_executable_path(),
        "evolution_prompt": (
            "Improve the generic firmware unpack executor conservatively. "
            "Preserve the output protocol, stop after summary creation, and do not change reviewer semantics."
        ),
        "tunable_surfaces": [
            {
                "name": "generic executor prompt",
                "paths": _prompt_surface_paths(workdir_subpath),
                "notes": "Primary generic executor prompt surface.",
            }
        ],
        "env": {},
        "max_attempts": 1,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def is_generic_success_result(result: dict[str, Any]) -> bool:
    if str(result.get("status") or "").strip().lower() != "success":
        return False
    try:
        return int(result.get("rounds") or 0) > 0
    except Exception:
        return False


@dataclass
class ArchivedSample:
    sample_dir: Path
    manifest_path: Path
    manifest: dict[str, Any]


def archive_success_sample(
    *,
    task_id: str,
    project_id: str | None,
    family_id: str,
    run_id: str,
    run_dir: Path,
    final_result: dict[str, Any],
    tokens_summary: dict[str, Any] | None,
) -> ArchivedSample:
    root = evolution_archive_root()
    sample_dir = family_sample_dir(root, family_id, task_id, run_id)
    sample_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "task_id": task_id,
        "project_id": project_id,
        "run_id": run_id,
        "family_id": _slugify(family_id),
        "matched_skill": final_result.get("matched_skill"),
        "fallback_to_llm": bool(final_result.get("fallback_to_llm")),
        "rounds": int(final_result.get("rounds") or 0),
        "total_tokens": int((tokens_summary or {}).get("total_tokens") or final_result.get("total_tokens") or 0),
        "source_stage": EVOLUTION_TARGET_NODE_GENERIC_EXECUTOR,
        "target_node": EVOLUTION_TARGET_NODE_GENERIC_EXECUTOR,
        "created_at": final_result.get("completed_at"),
    }
    for name in (
        "final_result.json",
        "tokens_summary.json",
        "run.json",
        "feature-match.json",
        "stage2_skill_match.json",
        "stage3_skill_exec.json",
        "stage4_llm_fallback.json",
        "agentflow_run_id.txt",
        "agentflow_run_dir.txt",
    ):
        source = run_dir / name
        if source.exists():
            target = sample_dir / name
            target.write_bytes(source.read_bytes())
    manifest_path = sample_dir / "source_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return ArchivedSample(sample_dir=sample_dir, manifest_path=manifest_path, manifest=manifest)
