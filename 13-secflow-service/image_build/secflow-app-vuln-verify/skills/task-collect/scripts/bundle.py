#!/usr/bin/env python3
"""audit-bundle: pack audit context into a zip, purely manifest-driven."""

import argparse
import fnmatch
import json
import os
import sys
import urllib.request
import urllib.error
import zipfile
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_EXCLUDES = [
    ".git",
    ".gitignore",
    ".gitmodules",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    "*.pyc",
    "*.pyo",
    ".cache",
    ".hg",
    ".svn",
    "*.egg-info",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
]


def should_exclude(rel_path: str, excludes: list[str]) -> bool:
    parts = Path(rel_path).parts
    for part in parts:
        for pat in excludes:
            if fnmatch.fnmatch(part, pat):
                return True
    for pat in excludes:
        if fnmatch.fnmatch(rel_path, pat):
            return True
    return False


def add_dir_to_zip(
    zf: zipfile.ZipFile, src_dir: Path, prefix: str, excludes: list[str]
) -> int:
    count = 0
    if not src_dir.is_dir():
        return count
    for root, dirs, files in os.walk(src_dir):
        rel_root = Path(root).relative_to(src_dir)
        dirs[:] = [d for d in dirs if not should_exclude(str(rel_root / d), excludes)]
        for f in files:
            rel = rel_root / f
            if should_exclude(str(rel), excludes):
                continue
            full = Path(root) / f
            arc = f"{prefix}/{rel}"
            try:
                zf.write(full, arc)
                count += 1
            except (PermissionError, OSError):
                pass
    return count


def add_file_to_zip(zf: zipfile.ZipFile, src: Path, arc: str) -> bool:
    if not src.is_file():
        return False
    try:
        zf.write(src, arc)
        return True
    except (PermissionError, OSError):
        return False


def parse_manifest(raw: str) -> dict:
    if raw.startswith("@"):
        path = Path(raw[1:])
        if not path.is_file():
            print(f"ERROR: manifest file not found: {path}", file=sys.stderr)
            sys.exit(1)
        return json.loads(path.read_text(encoding="utf-8"))
    return json.loads(raw)


def detect_agent_type() -> str:
    if os.environ.get("KILO_SESSION_ID"):
        return "kilo"
    if os.environ.get("OPENCODE_SESSION_ID"):
        return "opencode"
    if os.environ.get("CLAUDE_CODE_SESSION_ID"):
        return "claudecode"
    return "unknown"


def detect_session_id() -> str:
    return (
        os.environ.get("KILO_SESSION_ID")
        or os.environ.get("OPENCODE_SESSION_ID")
        or os.environ.get("CLAUDE_CODE_SESSION_ID")
        or ""
    )


def pack_referenced_env(zf: zipfile.ZipFile, env_vars: list[str]) -> int:
    lines = []
    for var in sorted(env_vars):
        val = os.environ.get(var, "")
        lines.append(f"{var}={val}")
    content = "\n".join(lines) + "\n" if lines else ""
    zf.writestr("env/referenced.env", content)
    return len(lines)


def pack_env_files(zf: zipfile.ZipFile, env_files: list[str]) -> int:
    count = 0
    for raw_path in env_files:
        p = Path(raw_path).expanduser()
        if not p.is_file():
            print(f"WARN: env file not found: {p}", file=sys.stderr)
            continue
        arc = f"env/files/{p.name}"
        if add_file_to_zip(zf, p, arc):
            count += 1
    return count


def pack_skills(
    zf: zipfile.ZipFile, skills: list[dict], excludes: list[str]
) -> int:
    count = 0
    for entry in skills:
        name = entry.get("name", "")
        path = entry.get("path", "")
        if not name or not path:
            print(f"WARN: skill entry missing name or path: {entry}", file=sys.stderr)
            continue
        skill_dir = Path(path).expanduser()
        if not skill_dir.is_dir():
            print(f"WARN: skill dir not found: {skill_dir}", file=sys.stderr)
            continue
        prefix = f"skills/{name}"
        count += add_dir_to_zip(zf, skill_dir, prefix, excludes)
    return count


def pack_config_files(zf: zipfile.ZipFile, config_files: list[str]) -> int:
    count = 0
    for raw_path in config_files:
        p = Path(raw_path).expanduser()
        if not p.is_file():
            print(f"WARN: config file not found: {p}", file=sys.stderr)
            continue
        arc = f"config/{p.name}"
        if add_file_to_zip(zf, p, arc):
            count += 1
    return count


def pack_trace_files(zf: zipfile.ZipFile, trace_files: list[str]) -> int:
    count = 0
    for raw_path in trace_files:
        p = Path(raw_path).expanduser()
        if not p.is_file():
            print(f"WARN: trace file not found: {p}", file=sys.stderr)
            continue
        parent = p.parent.name
        arc = f"task-trace/{parent}/{p.name}"
        if add_file_to_zip(zf, p, arc):
            count += 1
    return count


def pack_source_files(
    zf: zipfile.ZipFile, source_files: list[str], project_dir: Path, excludes: list[str],
    pack_project: bool = False,
) -> int:
    if pack_project and not source_files:
        if project_dir.is_dir():
            return add_dir_to_zip(zf, project_dir, "source", excludes)
        print(f"WARN: project dir not found: {project_dir}", file=sys.stderr)
        return 0
    count = 0
    for raw_path in source_files:
        p = Path(raw_path).expanduser()
        if not p.is_file():
            print(f"WARN: source file not found: {p}", file=sys.stderr)
            continue
        if should_exclude(str(p), excludes):
            continue
        try:
            rel = p.relative_to(project_dir)
        except ValueError:
            rel = Path(p.name)
        arc = f"source/{rel}"
        if add_file_to_zip(zf, p, arc):
            count += 1
    return count


def pack_project_deps(zf: zipfile.ZipFile, project_deps: list[str]) -> int:
    count = 0
    for raw_path in project_deps:
        p = Path(raw_path).expanduser()
        if not p.is_file():
            print(f"WARN: dep file not found: {p}", file=sys.stderr)
            continue
        arc = f"deps/{p.name}"
        if add_file_to_zip(zf, p, arc):
            count += 1
    return count


def pack_mcp_configs(zf: zipfile.ZipFile, mcp_configs: list[str]) -> int:
    count = 0
    for raw_path in mcp_configs:
        p = Path(raw_path).expanduser()
        if not p.is_file():
            print(f"WARN: mcp config not found: {p}", file=sys.stderr)
            continue
        arc = f"mcp/{p.name}"
        if add_file_to_zip(zf, p, arc):
            count += 1
    return count


def upload_to_minio(
    zip_path: Path, minio_url: str, bucket: str, prefix: str = "audit-bundles"
) -> str:
    filename = zip_path.name
    url = f"{minio_url}/{bucket}/{prefix}/{filename}"
    data = zip_path.read_bytes()
    req = urllib.request.Request(
        url,
        data=data,
        method="PUT",
        headers={"Content-Type": "application/zip"},
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            if resp.status not in (200, 204):
                raise RuntimeError(f"MinIO PUT returned {resp.status}")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"MinIO upload failed: {e.code} {e.reason}") from e
    return url


def load_env_file(path: Path) -> dict[str, str]:
    env = {}
    if not path.is_file():
        return env
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        env[k.strip()] = v.strip()
    return env


def main():
    parser = argparse.ArgumentParser(description="Pack audit context into a zip (manifest-driven)")
    parser.add_argument(
        "--project-dir",
        default=os.getcwd(),
        help="Project root directory (default: cwd)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output zip path (default: ~/.cache/audit-bundle/)",
    )
    parser.add_argument("--task", default=None, help="Audit task description")
    parser.add_argument(
        "--manifest",
        default=None,
        help="Manifest JSON string or @file.json (from LLM introspection)",
    )
    parser.add_argument(
        "--exclude", nargs="*", default=[], help="Extra exclude patterns"
    )
    parser.add_argument(
        "--pack-project",
        action="store_true",
        help="Pack entire project dir into source/ when source_files is empty",
    )
    parser.add_argument(
        "--upload",
        action="store_true",
        help="Upload zip to MinIO",
    )
    parser.add_argument(
        "--minio-url",
        default=None,
        help="MinIO base URL (default: from TASK_TRACE_HTTP_ENDPOINT env)",
    )
    parser.add_argument(
        "--minio-bucket",
        default=None,
        help="MinIO bucket (default: from TASK_TRACE_BUCKET env or task-traces)",
    )
    args = parser.parse_args()

    project_dir = Path(args.project_dir).resolve()
    excludes = DEFAULT_EXCLUDES + list(args.exclude)

    task = args.task
    if not task:
        try:
            task = input("Enter audit task description: ").strip()
        except (EOFError, KeyboardInterrupt):
            task = "(no task description provided)"

    manifest: dict = {}
    if args.manifest:
        try:
            manifest = parse_manifest(args.manifest)
        except json.JSONDecodeError as e:
            print(f"ERROR: failed to parse manifest: {e}", file=sys.stderr)
            sys.exit(1)

    agent_type = manifest.get("agent_type", "") or detect_agent_type()
    session_id = manifest.get("session_id", "") or detect_session_id()

    cache_dir = Path.home() / ".cache" / "audit-bundle"
    cache_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    default_output = cache_dir / f"audit-bundle-{ts}.zip"
    output = Path(args.output) if args.output else default_output
    output.parent.mkdir(parents=True, exist_ok=True)

    skills_count = 0
    config_count = 0
    env_ref_count = 0
    env_file_count = 0
    trace_count = 0
    source_count = 0
    deps_count = 0
    mcp_count = 0

    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        # --- manifest.json ---
        if manifest:
            zf.writestr(
                "manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False)
            )

        # --- tasks.json ---
        tasks_list = manifest.get("tasks", [])
        if tasks_list:
            zf.writestr(
                "tasks.json", json.dumps(tasks_list, indent=2, ensure_ascii=False)
            )

        # --- skills (manifest.skills[].path) ---
        skills_entries = manifest.get("skills", [])
        if skills_entries:
            skills_count = pack_skills(zf, skills_entries, excludes)

        # --- config files (manifest.config_files) ---
        config_entries = manifest.get("config_files", [])
        if config_entries:
            config_count = pack_config_files(zf, config_entries)

        # --- env/referenced.env (manifest.env_vars -> os.environ) ---
        env_vars = manifest.get("env_vars", [])
        env_ref_count = pack_referenced_env(zf, env_vars)

        # --- env/files/ (manifest.env_files) ---
        env_files = manifest.get("env_files", [])
        if env_files:
            env_file_count = pack_env_files(zf, env_files)

        # --- task-trace (manifest.trace_files) ---
        trace_files = manifest.get("trace_files", [])
        if trace_files:
            trace_count = pack_trace_files(zf, trace_files)

        # --- source files (manifest.source_files) ---
        source_files = manifest.get("source_files", [])
        if source_files or args.pack_project:
            source_count = pack_source_files(
                zf, source_files, project_dir, excludes, pack_project=args.pack_project,
            )

        # --- project deps (manifest.project_deps) ---
        project_deps = manifest.get("project_deps", [])
        if project_deps:
            deps_count = pack_project_deps(zf, project_deps)

        # --- mcp configs (manifest.mcp_configs) ---
        mcp_configs = manifest.get("mcp_configs", [])
        if mcp_configs:
            mcp_count = pack_mcp_configs(zf, mcp_configs)

        # --- audit-task.json ---
        task_data = {
            "task": task,
            "project_dir": str(project_dir),
            "agent_type": agent_type,
            "session_id": session_id,
            "agent_version": manifest.get("agent_version", ""),
            "model_id": manifest.get("model_id", ""),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "manifest_driven": bool(manifest),
        }
        zf.writestr(
            "audit-task.json", json.dumps(task_data, indent=2, ensure_ascii=False)
        )

    result = {
        "zip_path": str(output),
        "size_bytes": output.stat().st_size,
        "contents": {
            "skills": skills_count,
            "config_files": config_count,
            "env_referenced": env_ref_count,
            "env_files": env_file_count,
            "trace_files": trace_count,
            "source_files": source_count,
            "project_deps": deps_count,
            "mcp_configs": mcp_count,
            "task": task,
            "manifest_driven": bool(manifest),
        },
    }

    if args.upload:
        secocto_env = load_env_file(Path.home() / ".config" / "secocto" / ".env")
        minio_url = (
            args.minio_url
            or os.environ.get("TASK_TRACE_HTTP_ENDPOINT")
            or secocto_env.get("TASK_TRACE_HTTP_ENDPOINT")
        )
        bucket = (
            args.minio_bucket
            or os.environ.get("TASK_TRACE_BUCKET")
            or secocto_env.get("TASK_TRACE_BUCKET", "task-traces")
        )

        if not minio_url:
            print(
                "ERROR: --upload requires --minio-url or TASK_TRACE_HTTP_ENDPOINT",
                file=sys.stderr,
            )
            sys.exit(1)

        zip_size = output.stat().st_size
        zip_url = upload_to_minio(output, minio_url, bucket)
        result["upload"] = {"minio_url": zip_url, "size_bytes": zip_size}

        public_base = os.environ.get("TASK_TRACE_PUBLIC_BASE_URL") or secocto_env.get(
            "TASK_TRACE_PUBLIC_BASE_URL", minio_url
        )
        public_url = zip_url.replace(minio_url, public_base, 1)
        result["upload"]["public_url"] = public_url

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
