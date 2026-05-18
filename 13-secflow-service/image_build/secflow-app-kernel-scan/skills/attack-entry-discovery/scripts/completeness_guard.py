#!/usr/bin/env python3
"""Build, track, and verify all-file processing coverage for a target tree."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".jj",
    ".idea",
    ".vscode",
    "__pycache__",
    "node_modules",
    "out",
    "build",
    "dist",
}
VALID_STATUSES = {"processed", "skipped", "error"}


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def fail(message: str, code: int = 1) -> int:
    print(f"[!] {message}", file=sys.stderr)
    return code


def load_run(run_dir: Path) -> dict:
    run_file = run_dir / "run.json"
    if not run_file.exists():
        raise FileNotFoundError(f"missing run file: {run_file}")
    return json.loads(run_file.read_text())


def normalize_path(raw: str, root: Path) -> str:
    path = Path(raw)
    if raw.startswith("./"):
        path = root / raw[2:]
    elif not path.is_absolute():
        path = root / raw
    path = path.resolve()
    try:
        rel = path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path outside root: {raw}") from exc
    return f"./{rel.as_posix()}"


def normalize_suffixes(raw: Iterable[str]) -> set[str]:
    result: set[str] = set()
    for item in raw:
        if not item:
            continue
        for token in item.split(","):
            token = token.strip().lower()
            if not token:
                continue
            if not token.startswith("."):
                token = "." + token
            result.add(token)
    return result


def match_suffix(filename: str, suffixes: set[str]) -> bool:
    name = filename.lower()
    for suffix in suffixes:
        if name.endswith(suffix):
            return True
    return False


def scan_files(
    root: Path,
    run_dir: Path,
    excluded_dirs: Iterable[str],
    include_suffixes: set[str] | None = None,
    exclude_suffixes: set[str] | None = None,
) -> List[dict]:
    excluded = set(excluded_dirs)
    include_set = include_suffixes or set()
    exclude_set = exclude_suffixes or set()
    files: List[dict] = []
    run_dir_resolved = run_dir.resolve()
    file_id = 0

    for current_root, dirs, filenames in os.walk(root, topdown=True, followlinks=False):
        current = Path(current_root)
        kept_dirs = []
        for dirname in sorted(dirs):
            if dirname in excluded:
                continue
            child = (current / dirname).resolve()
            if child == run_dir_resolved:
                continue
            kept_dirs.append(dirname)
        dirs[:] = kept_dirs

        for filename in sorted(filenames):
            abspath = current / filename
            if not abspath.is_file():
                continue
            if include_set and not match_suffix(filename, include_set):
                continue
            if exclude_set and match_suffix(filename, exclude_set):
                continue
            file_id += 1
            rel = abspath.resolve().relative_to(root)
            stat = abspath.stat()
            files.append(
                {
                    "id": file_id,
                    "path": f"./{rel.as_posix()}",
                    "size": stat.st_size,
                    "mtime": int(stat.st_mtime),
                }
            )
    return files


def write_jsonl(path: Path, rows: Iterable[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def load_manifest(run_dir: Path) -> List[dict]:
    manifest_file = run_dir / "manifest.jsonl"
    rows = []
    with manifest_file.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def load_results(run_dir: Path) -> Dict[str, dict]:
    results_file = run_dir / "results.jsonl"
    latest: Dict[str, dict] = {}
    if not results_file.exists():
        return latest
    with results_file.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            latest[row["path"]] = row
    return latest


def append_results(run_dir: Path, rows: Iterable[dict]) -> None:
    results_file = run_dir / "results.jsonl"
    with results_file.open("a", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def compute_summary(run_dir: Path) -> Tuple[dict, List[str], Counter]:
    manifest = load_manifest(run_dir)
    results = load_results(run_dir)
    counter = Counter()
    missing: List[str] = []

    for entry in manifest:
        record = results.get(entry["path"])
        if not record:
            missing.append(entry["path"])
            continue
        status = record["status"]
        if status not in VALID_STATUSES:
            counter["invalid"] += 1
            continue
        counter[status] += 1

    total = len(manifest)
    summary = {
        "total": total,
        "processed": counter["processed"],
        "skipped": counter["skipped"],
        "error": counter["error"],
        "missing": len(missing),
        "complete": len(missing) == 0 and counter["processed"] + counter["skipped"] + counter["error"] == total,
    }
    return summary, missing, counter


def command_init(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    run_dir = Path(args.run_dir).resolve()
    if not root.is_dir():
        return fail(f"root is not a directory: {root}")
    if run_dir.exists() and any(run_dir.iterdir()) and not args.force:
        return fail(f"run dir already exists and is not empty: {run_dir}")

    run_dir.mkdir(parents=True, exist_ok=True)
    batches_dir = run_dir / "batches"
    batches_dir.mkdir(parents=True, exist_ok=True)

    excluded_dirs = sorted(DEFAULT_EXCLUDED_DIRS | set(args.exclude_dir))
    include_suffixes = normalize_suffixes(args.include_suffix)
    exclude_suffixes = normalize_suffixes(args.exclude_suffix)
    overlap = include_suffixes & exclude_suffixes
    if overlap:
        return fail(f"suffix listed in both include and exclude: {sorted(overlap)}")
    files = scan_files(root, run_dir, excluded_dirs, include_suffixes, exclude_suffixes)
    if not files:
        hint = ""
        if include_suffixes:
            hint = f" (include_suffix={sorted(include_suffixes)})"
        return fail(f"no files found under root: {root}{hint}")

    write_jsonl(run_dir / "manifest.jsonl", files)
    (run_dir / "manifest.txt").write_text("\n".join(entry["path"] for entry in files) + "\n", encoding="utf-8")
    (run_dir / "results.jsonl").write_text("", encoding="utf-8")

    batch_size = args.batch_size
    batch_count = 0
    for start in range(0, len(files), batch_size):
        batch_count += 1
        batch_file = batches_dir / f"batch_{batch_count:04d}.txt"
        chunk = files[start : start + batch_size]
        batch_file.write_text("\n".join(entry["path"] for entry in chunk) + "\n", encoding="utf-8")

    run_meta = {
        "root": str(root),
        "run_dir": str(run_dir),
        "created_at": now_iso(),
        "batch_size": batch_size,
        "total_files": len(files),
        "batch_count": batch_count,
        "excluded_dirs": excluded_dirs,
        "include_suffixes": sorted(include_suffixes),
        "exclude_suffixes": sorted(exclude_suffixes),
    }
    (run_dir / "run.json").write_text(json.dumps(run_meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"run_dir={run_dir}")
    print(f"root={root}")
    print(f"total_files={len(files)}")
    print(f"batch_count={batch_count}")
    print(f"batch_size={batch_size}")
    return 0


def print_summary(summary: dict, missing: List[str], show_missing: int) -> None:
    print(f"total={summary['total']}")
    print(f"processed={summary['processed']}")
    print(f"skipped={summary['skipped']}")
    print(f"error={summary['error']}")
    print(f"missing={summary['missing']}")
    print(f"complete={'yes' if summary['complete'] else 'no'}")
    if show_missing > 0 and missing:
        print("missing_paths:")
        for path in missing[:show_missing]:
            print(path)


def command_status(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir).resolve()
    summary, missing, _ = compute_summary(run_dir)
    print_summary(summary, missing, args.show_missing)
    return 0


def command_verify(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir).resolve()
    summary, missing, _ = compute_summary(run_dir)
    print_summary(summary, missing, args.show_missing)
    return 0 if summary["complete"] else 2


def append_mark_records(run_dir: Path, paths: Iterable[str], status: str, reason: str, batch_id: int | None) -> None:
    run_meta = load_run(run_dir)
    root = Path(run_meta["root"]).resolve()
    rows = []
    for raw in paths:
        norm = normalize_path(raw, root)
        rows.append(
            {
                "path": norm,
                "status": status,
                "reason": reason,
                "batch_id": batch_id,
                "updated_at": now_iso(),
            }
        )
    append_results(run_dir, rows)


def command_mark_batch(args: argparse.Namespace) -> int:
    if args.status not in VALID_STATUSES:
        return fail(f"invalid status: {args.status}")
    run_dir = Path(args.run_dir).resolve()
    batch_file = run_dir / "batches" / f"batch_{args.batch_id:04d}.txt"
    if not batch_file.exists():
        return fail(f"batch file not found: {batch_file}")
    paths = [line.strip() for line in batch_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    append_mark_records(run_dir, paths, args.status, args.reason, args.batch_id)
    print(f"marked={len(paths)}")
    print(f"batch_id={args.batch_id}")
    print(f"status={args.status}")
    return 0


def command_mark_file(args: argparse.Namespace) -> int:
    if args.status not in VALID_STATUSES:
        return fail(f"invalid status: {args.status}")
    run_dir = Path(args.run_dir).resolve()
    append_mark_records(run_dir, args.path, args.status, args.reason, None)
    print(f"marked={len(args.path)}")
    print(f"status={args.status}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    init_cmd = sub.add_parser("init", help="create manifest and batch files")
    init_cmd.add_argument("--root", required=True, help="target root directory")
    init_cmd.add_argument("--run-dir", required=True, help="directory to store manifest and results")
    init_cmd.add_argument("--batch-size", type=int, default=200, help="files per batch")
    init_cmd.add_argument("--exclude-dir", action="append", default=[], help="extra directory names to exclude")
    init_cmd.add_argument(
        "--include-suffix",
        action="append",
        default=[],
        help="only include files ending with these suffixes; may be repeated or comma-separated (e.g. --include-suffix .c,.h)",
    )
    init_cmd.add_argument(
        "--exclude-suffix",
        action="append",
        default=[],
        help="drop files ending with these suffixes; may be repeated or comma-separated",
    )
    init_cmd.add_argument("--force", action="store_true", help="reuse a non-empty run dir")
    init_cmd.set_defaults(func=command_init)

    status_cmd = sub.add_parser("status", help="show current coverage status")
    status_cmd.add_argument("--run-dir", required=True)
    status_cmd.add_argument("--show-missing", type=int, default=0)
    status_cmd.set_defaults(func=command_status)

    verify_cmd = sub.add_parser("verify", help="return non-zero if files are still missing")
    verify_cmd.add_argument("--run-dir", required=True)
    verify_cmd.add_argument("--show-missing", type=int, default=0)
    verify_cmd.set_defaults(func=command_verify)

    mark_batch_cmd = sub.add_parser("mark-batch", help="mark all files in a batch")
    mark_batch_cmd.add_argument("--run-dir", required=True)
    mark_batch_cmd.add_argument("--batch-id", required=True, type=int)
    mark_batch_cmd.add_argument("--status", required=True, choices=sorted(VALID_STATUSES))
    mark_batch_cmd.add_argument("--reason", default="")
    mark_batch_cmd.set_defaults(func=command_mark_batch)

    mark_file_cmd = sub.add_parser("mark-file", help="mark one or more files")
    mark_file_cmd.add_argument("--run-dir", required=True)
    mark_file_cmd.add_argument("--status", required=True, choices=sorted(VALID_STATUSES))
    mark_file_cmd.add_argument("--reason", default="")
    mark_file_cmd.add_argument("--path", action="append", required=True, help="file path to mark; may be repeated")
    mark_file_cmd.set_defaults(func=command_mark_file)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except Exception as exc:  # pragma: no cover
        return fail(str(exc))


if __name__ == "__main__":
    sys.exit(main())
