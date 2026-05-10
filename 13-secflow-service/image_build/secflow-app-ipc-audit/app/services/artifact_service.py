from __future__ import annotations

import hashlib
import mimetypes
import sqlite3
from pathlib import Path
from typing import Any

from fastapi import HTTPException, status

from app.core.config import get_config
from app.core.ids import new_artifact_id
from app.core.time_utils import utc_now_z
from app.db.database import get_database
from app.schemas import ArtifactContentResponse, ArtifactListResponse, ArtifactResponse


class ArtifactService:
    def state_root(self) -> Path:
        return Path(get_config().state_root).resolve()

    def task_root(self, task_id: str) -> Path:
        return self.state_root() / "tasks" / task_id

    def attempt_root(self, task_id: str, attempt_id: str) -> Path:
        return self.task_root(task_id) / "attempts" / attempt_id

    def logs_dir(self, task_id: str, attempt_id: str) -> Path:
        return self.attempt_root(task_id, attempt_id) / "logs"

    def artifacts_dir(self, task_id: str, attempt_id: str) -> Path:
        return self.attempt_root(task_id, attempt_id) / "artifacts"

    def scratch_dir(self, task_id: str, attempt_id: str) -> Path:
        return self.attempt_root(task_id, attempt_id) / "scratch"

    def ensure_attempt_dirs(self, task_id: str, attempt_id: str) -> Path:
        attempt_root = self.attempt_root(task_id, attempt_id)
        for child in (
            attempt_root / "runtime",
            attempt_root / "logs",
            attempt_root / "artifacts",
            attempt_root / "exports",
            attempt_root / "scratch",
        ):
            child.mkdir(parents=True, exist_ok=True)
        return attempt_root

    def stage_log_path(self, task_id: str, attempt_id: str, stage_name: str) -> Path:
        self.ensure_attempt_dirs(task_id, attempt_id)
        return self.logs_dir(task_id, attempt_id) / f"{stage_name}.codex.log"

    def stage_artifact_path(self, task_id: str, attempt_id: str, filename: str) -> Path:
        self.ensure_attempt_dirs(task_id, attempt_id)
        return self.artifacts_dir(task_id, attempt_id) / filename

    def record_artifact(
        self,
        conn: sqlite3.Connection,
        *,
        task_id: str,
        attempt_id: str,
        stage_name: str | None,
        artifact_kind: str,
        file_path: Path,
        display_name: str | None = None,
    ) -> str:
        attempt_root = self.attempt_root(task_id, attempt_id)
        relative_path = file_path.resolve().relative_to(attempt_root.resolve()).as_posix()
        content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
        if file_path.suffix == ".md":
            content_type = "text/markdown"
        elif file_path.suffix == ".json":
            content_type = "application/json"
        artifact_id = new_artifact_id()
        now = utc_now_z()
        conn.execute(
            """
            insert into ipc_audit_artifacts (
              artifact_id, task_id, attempt_id, stage_name, artifact_kind,
              display_name, relative_path, content_type, size, sha256, created_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                artifact_id,
                task_id,
                attempt_id,
                stage_name,
                artifact_kind,
                display_name or file_path.name,
                relative_path,
                content_type,
                file_path.stat().st_size,
                self._sha256(file_path),
                now,
            ),
        )
        return artifact_id

    def list_artifacts(self, task_id: str, attempt_id: str) -> ArtifactListResponse:
        with get_database().connect() as conn:
            rows = conn.execute(
                """
                select artifact_id, task_id, attempt_id, stage_name, artifact_kind, display_name,
                       relative_path, content_type, size, sha256, created_at
                from ipc_audit_artifacts
                where task_id = ? and attempt_id = ?
                order by created_at asc
                """,
                (task_id, attempt_id),
            ).fetchall()
        return ArtifactListResponse(task_id=task_id, attempt_id=attempt_id, items=[self._row_to_model(row) for row in rows])

    def get_artifact_content(self, artifact_id: str, *, max_bytes: int) -> ArtifactContentResponse:
        artifact, path = self.resolve_artifact(artifact_id)
        data = path.read_bytes()
        truncated = len(data) > max_bytes
        payload = data[:max_bytes].decode("utf-8", errors="replace")
        return ArtifactContentResponse(
            artifact_id=artifact["artifact_id"],
            content=payload,
            truncated=truncated,
            content_type=artifact["content_type"],
        )

    def resolve_artifact(self, artifact_id: str) -> tuple[dict[str, Any], Path]:
        with get_database().connect() as conn:
            row = conn.execute(
                """
                select artifact_id, task_id, attempt_id, stage_name, artifact_kind, display_name,
                       relative_path, content_type, size, sha256, created_at
                from ipc_audit_artifacts
                where artifact_id = ?
                """,
                (artifact_id,),
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"artifact not found: {artifact_id}")
        artifact = dict(row)
        path = self.attempt_root(artifact["task_id"], artifact["attempt_id"]) / artifact["relative_path"]
        if not path.exists():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"artifact file missing: {artifact_id}")
        return artifact, path

    def delete_task_tree(self, task_id: str) -> None:
        root = self.task_root(task_id)
        if not root.exists():
            return
        for child in sorted(root.rglob("*"), reverse=True):
            if child.is_file() or child.is_symlink():
                child.unlink(missing_ok=True)
            elif child.is_dir():
                child.rmdir()
        root.rmdir()

    def _row_to_model(self, row: sqlite3.Row) -> ArtifactResponse:
        artifact_id = row["artifact_id"]
        return ArtifactResponse(
            artifact_id=artifact_id,
            task_id=row["task_id"],
            attempt_id=row["attempt_id"],
            stage_name=row["stage_name"],
            artifact_kind=row["artifact_kind"],
            display_name=row["display_name"],
            relative_path=row["relative_path"],
            content_type=row["content_type"],
            size=row["size"],
            sha256=row["sha256"],
            preview_url=f"/api/app/ipc-audit/artifacts/{artifact_id}/content",
            download_url=f"/api/app/ipc-audit/artifacts/{artifact_id}/download",
            created_at=row["created_at"],
        )

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()


_artifact_service: ArtifactService | None = None


def get_artifact_service() -> ArtifactService:
    global _artifact_service
    if _artifact_service is None:
        _artifact_service = ArtifactService()
    return _artifact_service

