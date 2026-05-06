"""Read-only workspace guard for advisor phases.

Advisors are allowed to inspect the workspace and write their normal runtime
traces, but they must not mutate analysis artifacts such as ``results/`` or
``summary.md``.  The guard snapshots non-runtime files before and after an
advisor call and reports unexpected changes.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_MONITORED_PATHS = (
    "summary.md",
    "previous_limitations.md",
    "results",
    "supporting_docs",
    "_meta/result_relations_manifest.json",
    "_meta/results_manifest.json",
    "_meta/coverage_ledger.json",
)


@dataclass(frozen=True)
class WorkspaceEntry:
    kind: str
    size: int
    mtime_ns: int


@dataclass(frozen=True)
class WorkspaceSnapshot:
    root: str
    entries: dict[str, WorkspaceEntry]


def take_read_only_snapshot(
    work_dir: str | os.PathLike[str],
    *,
    monitored_paths: Iterable[str] = DEFAULT_MONITORED_PATHS,
) -> WorkspaceSnapshot:
    """Capture a lightweight stat snapshot for advisor-visible artifacts.

    This intentionally watches only stable workflow artifacts instead of the
    whole workspace. Runtime traces/checkpoints live under ``sessions/``,
    ``reviews/`` and most of ``_meta/``; scanning them for every advisor would
    add avoidable IO and produce noisy false positives.
    """
    root = Path(work_dir).resolve()
    entries: dict[str, WorkspaceEntry] = {}

    if not root.is_dir():
        return WorkspaceSnapshot(root=str(root), entries=entries)

    def _add_file(path: Path) -> None:
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            return
        try:
            stat = path.stat()
        except OSError:
            return
        entries[rel] = WorkspaceEntry(
            kind="file",
            size=int(stat.st_size),
            mtime_ns=int(stat.st_mtime_ns),
        )

    for item in monitored_paths:
        rel_item = str(item).strip("/")
        if not rel_item:
            continue
        target = root / rel_item
        if target.is_file():
            _add_file(target)
            continue
        if not target.is_dir():
            continue
        for current_dir, dir_names, file_names in os.walk(target):
            dir_names[:] = [
                dirname for dirname in dir_names
                if dirname not in {"__pycache__", ".git"}
            ]
            current = Path(current_dir)
            for filename in file_names:
                _add_file(current / filename)

    return WorkspaceSnapshot(root=str(root), entries=entries)


def diff_read_only_snapshots(
    before: WorkspaceSnapshot,
    after: WorkspaceSnapshot,
    *,
    limit: int = 20,
) -> list[dict[str, str]]:
    """Return created/deleted/modified entries between two snapshots."""
    changes: list[dict[str, str]] = []
    before_entries = before.entries
    after_entries = after.entries

    for rel in sorted(after_entries):
        if rel not in before_entries:
            changes.append({"path": rel, "change": "created"})
        elif after_entries[rel] != before_entries[rel]:
            changes.append({"path": rel, "change": "modified"})
        if len(changes) >= limit:
            return changes

    for rel in sorted(before_entries):
        if rel not in after_entries:
            changes.append({"path": rel, "change": "deleted"})
        if len(changes) >= limit:
            return changes

    return changes


def format_read_only_violations(changes: list[dict[str, str]]) -> str:
    if not changes:
        return ""
    lines = ["advisor violated read-only workspace contract:"]
    lines.extend(f"- {item['change']}: {item['path']}" for item in changes)
    return "\n".join(lines)
