from __future__ import annotations

from pathlib import Path, PurePosixPath

from fastapi import HTTPException, status

from app.core.config import WorkspaceConfig, get_config
from app.schemas import InputRef, ValidateInputResponse, WorkspaceSummaryResponse, WorkspaceTreeItemResponse, WorkspaceTreeResponse


class WorkspaceService:
    def list_workspace_summaries(self) -> list[WorkspaceSummaryResponse]:
        return [self._to_summary(item) for item in get_config().workspaces]

    def get_workspace_summary(self, workspace_id: str) -> WorkspaceSummaryResponse:
        return self._to_summary(self.get_workspace(workspace_id))

    def get_workspace(self, workspace_id: str) -> WorkspaceConfig:
        for workspace in get_config().workspaces:
            if workspace.workspace_id == workspace_id:
                return workspace
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"workspace not found: {workspace_id}")

    def browse_tree(
        self,
        workspace_id: str,
        *,
        path: str = "",
        depth: int = 1,
        directories_only: bool = False,
    ) -> WorkspaceTreeResponse:
        workspace = self.get_workspace(workspace_id)
        root = Path(workspace.repo_root).resolve()
        base = self.resolve_relative_path(workspace, path, expect="directory") if path else root
        items = self._list_directory(root=root, base=base, depth=depth, directories_only=directories_only)
        normalized = self.normalize_relative_path(path) if path else ""
        return WorkspaceTreeResponse(workspace_id=workspace_id, path=normalized, items=items)

    def validate_input(self, workspace_id: str, input_ref: InputRef) -> ValidateInputResponse:
        workspace = self.get_workspace(workspace_id)
        if input_ref.kind in {"preset_project", "custom_project"}:
            normalized = self.normalize_relative_path(input_ref.project_path or "")
            resolved = self.resolve_relative_path(workspace, normalized, expect="directory")
            return ValidateInputResponse(
                valid=True,
                normalized_input_ref=InputRef(kind=input_ref.kind, project_path=normalized),
                resolved_kind="directory",
                message=f"path is valid: {resolved}",
            )
        normalized = self.normalize_relative_path(input_ref.report_path or "")
        resolved = self.resolve_relative_path(workspace, normalized, expect="file")
        return ValidateInputResponse(
            valid=True,
            normalized_input_ref=InputRef(kind=input_ref.kind, report_path=normalized),
            resolved_kind="file",
            message=f"path is valid: {resolved}",
        )

    def normalize_relative_path(self, raw: str) -> str:
        value = (raw or "").strip().strip("/")
        if not value:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="relative path must not be empty")
        pure = PurePosixPath(value)
        if pure.is_absolute() or ".." in pure.parts:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"invalid repo-relative path: {raw}")
        normalized = pure.as_posix()
        if normalized.startswith("./"):
            normalized = normalized[2:]
        if not normalized or normalized == ".":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="relative path must not be empty")
        return normalized

    def resolve_relative_path(self, workspace: WorkspaceConfig, relative_path: str, *, expect: str) -> Path:
        repo_root = Path(workspace.repo_root).resolve()
        if not repo_root.exists():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"workspace repo root not available: {workspace.workspace_id}",
            )
        normalized = self.normalize_relative_path(relative_path)
        candidate = (repo_root / normalized).resolve()
        try:
            candidate.relative_to(repo_root)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="path escapes workspace root") from exc
        if not candidate.exists():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"path not found: {normalized}")
        if expect == "directory" and not candidate.is_dir():
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"not a directory: {normalized}")
        if expect == "file" and not candidate.is_file():
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"not a file: {normalized}")
        return candidate

    def _list_directory(
        self,
        *,
        root: Path,
        base: Path,
        depth: int,
        directories_only: bool,
    ) -> list[WorkspaceTreeItemResponse]:
        if depth != 1:
            depth = 1
        items: list[WorkspaceTreeItemResponse] = []
        for child in sorted(base.iterdir(), key=lambda item: (not item.is_dir(), item.name.lower())):
            if directories_only and not child.is_dir():
                continue
            try:
                relative = child.resolve().relative_to(root)
            except ValueError:
                continue
            items.append(
                WorkspaceTreeItemResponse(
                    name=child.name,
                    path=relative.as_posix(),
                    kind="directory" if child.is_dir() else "file",
                )
            )
        return items

    @staticmethod
    def _to_summary(workspace: WorkspaceConfig) -> WorkspaceSummaryResponse:
        return WorkspaceSummaryResponse(
            workspace_id=workspace.workspace_id,
            display_name=workspace.display_name,
            allow_custom_project_path=workspace.allow_custom_project_path,
            supports_poc=workspace.supports_poc,
            default_pipeline_mode=workspace.default_pipeline_mode,
            is_default=workspace.is_default,
        )


_workspace_service: WorkspaceService | None = None


def get_workspace_service() -> WorkspaceService:
    global _workspace_service
    if _workspace_service is None:
        _workspace_service = WorkspaceService()
    return _workspace_service
