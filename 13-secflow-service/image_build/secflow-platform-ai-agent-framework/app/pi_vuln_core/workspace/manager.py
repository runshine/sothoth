from __future__ import annotations

from pathlib import Path


def _safe_name(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in value.strip())
    return cleaned or "default"


class WorkspaceManager:
    def __init__(self, workspace_root: str | Path):
        self.workspace_root = Path(workspace_root)
        self.workspace_root.mkdir(parents=True, exist_ok=True)

    def _render_template(self, template: str, **kwargs: str) -> str:
        rendered = template.format(**kwargs)
        return _safe_name(rendered)

    def _prepare_dir(self, path: Path) -> str:
        path.mkdir(parents=True, exist_ok=True)
        (path / "_meta").mkdir(parents=True, exist_ok=True)
        return str(path)

    def create_composite_dir(
        self,
        working_dir_template: str,
        *,
        parent_dir: str | None = None,
        execution_id: str,
        workflow_id: str | None = None,
    ) -> str:
        base = Path(parent_dir) if parent_dir else self.workspace_root
        name = self._render_template(
            working_dir_template,
            execution_id=execution_id,
            workflow_id=workflow_id or execution_id,
        )
        return self._prepare_dir(base / name)

    def create_stage_dir(self, composite_dir: str | Path, stage_id: str) -> str:
        return self._prepare_dir(Path(composite_dir) / _safe_name(stage_id))

    def create_atomic_dir(
        self,
        working_dir_template: str,
        *,
        task_id: str,
        parent_dir: str | None = None,
        workflow_id: str | None = None,
    ) -> str:
        base = Path(parent_dir) if parent_dir else self.workspace_root
        name = self._render_template(
            working_dir_template,
            task_id=task_id,
            workflow_id=workflow_id or task_id,
        )
        work_dir = Path(self._prepare_dir(base / name))
        for subdir in ("input", "results", "reviews", "output", "working"):
            (work_dir / subdir).mkdir(parents=True, exist_ok=True)
        return str(work_dir)
