from __future__ import annotations

from pathlib import Path

from app.artifacts.io import ensure_dir


class WorkspaceLayout:
    def __init__(self, workspace_root: str | Path):
        self.workspace_root = ensure_dir(workspace_root)

    def root_workflow_dir(self, workflow_id: str) -> Path:
        return ensure_dir(self.workspace_root / workflow_id)

    def stage_dir(self, parent_dir: str | Path, stage_id: str) -> Path:
        return ensure_dir(Path(parent_dir) / stage_id)

    def task_dir(self, stage_dir: str | Path, task_id: str) -> Path:
        return ensure_dir(Path(stage_dir) / task_id)

    def nested_composite_dir(self, task_dir: str | Path, workflow_id: str) -> Path:
        return ensure_dir(Path(task_dir) / workflow_id)
