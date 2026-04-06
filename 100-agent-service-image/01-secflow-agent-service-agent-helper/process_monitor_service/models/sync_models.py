from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

TaskMode = Literal['pid_files', 'path_files']
TaskStatus = Literal['pending', 'running', 'success', 'partial_success', 'failed', 'cancelled']
ResultStatus = Literal['uploaded', 'skipped', 'failed']


@dataclass
class SyncFileCandidate:
    host_path: str
    real_path: str
    relative_path: str
    size: int | None
    entry_type: str = 'file'
    symlink_target: str | None = None
    pid_refs: list[dict[str, Any]] = field(default_factory=list)
    path_refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SyncEvent:
    seq: int
    ts: float
    level: str
    type: str
    message: str
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SyncResult:
    item_id: str
    source_path: str | None
    relative_path: str | None
    entry_type: str
    status: ResultStatus
    size: int | None = None
    sha256: str | None = None
    error: str | None = None
    pid: int | None = None
    reason: str | None = None
    refs: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SyncTask:
    task_id: str
    mode: TaskMode
    remote_root_url: str
    status: TaskStatus
    created_at: float
    started_at: float | None = None
    finished_at: float | None = None
    pids: list[int] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    source_task_id: str | None = None
    remote_path_prefix: str | None = None
    total_files: int = 0
    completed_files: int = 0
    failed_files: int = 0
    skipped_files: int = 0
    total_bytes: int = 0
    uploaded_bytes: int = 0
    speed_bps: float = 0.0
    avg_speed_bps: float = 0.0
    last_error: str | None = None
    pid_summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
