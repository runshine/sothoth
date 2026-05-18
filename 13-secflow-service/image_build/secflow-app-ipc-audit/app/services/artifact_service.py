from __future__ import annotations

import hashlib
import json
import mimetypes
from pathlib import Path
from typing import Any

from fastapi import HTTPException, status

from app.core.config import get_config
from app.core.ids import new_artifact_id
from app.core.time_utils import utc_now_z
from app.db.database import DatabaseConnection, DatabaseRow, get_database
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
        conn: DatabaseConnection,
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

    def reconcile_attempt_artifacts(
        self,
        conn: DatabaseConnection,
        *,
        task_id: str,
        attempt_id: str,
    ) -> None:
        attempt_root = self.attempt_root(task_id, attempt_id)
        if not attempt_root.exists():
            return
        rows = conn.execute(
            """
            select artifact_kind, relative_path
            from ipc_audit_artifacts
            where task_id = ? and attempt_id = ?
            """,
            (task_id, attempt_id),
        ).fetchall()
        existing_paths = {
            str(row["relative_path"]): str(row["artifact_kind"])
            for row in rows
        }

        graph_manifest_path = attempt_root / "runtime" / "graph" / "graph-manifest.json"
        self._record_attempt_artifact_if_missing(
            conn,
            task_id=task_id,
            attempt_id=attempt_id,
            stage_name=None,
            artifact_kind="graph_manifest",
            file_path=graph_manifest_path,
            existing_paths=existing_paths,
        )

        manifest = self._read_json_file(graph_manifest_path)
        if not isinstance(manifest, dict):
            return

        for candidate in self._collect_graph_output_candidates(attempt_root, manifest):
            self._record_attempt_artifact_if_missing(
                conn,
                task_id=task_id,
                attempt_id=attempt_id,
                stage_name=candidate["stage_name"],
                artifact_kind=candidate["artifact_kind"],
                file_path=candidate["file_path"],
                existing_paths=existing_paths,
            )

    def list_artifacts(self, task_id: str, attempt_id: str) -> ArtifactListResponse:
        with get_database().connect() as conn:
            self.reconcile_attempt_artifacts(conn, task_id=task_id, attempt_id=attempt_id)
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

    def _row_to_model(self, row: DatabaseRow) -> ArtifactResponse:
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

    def _record_attempt_artifact_if_missing(
        self,
        conn: DatabaseConnection,
        *,
        task_id: str,
        attempt_id: str,
        stage_name: str | None,
        artifact_kind: str,
        file_path: Path,
        existing_paths: dict[str, str],
    ) -> None:
        if not file_path.exists() or not file_path.is_file() or file_path.stat().st_size <= 0:
            return
        attempt_root = self.attempt_root(task_id, attempt_id)
        relative_path = self._relative_path_in_attempt(attempt_root, file_path)
        if relative_path is None or relative_path in existing_paths:
            return
        self.record_artifact(
            conn,
            task_id=task_id,
            attempt_id=attempt_id,
            stage_name=stage_name,
            artifact_kind=artifact_kind,
            file_path=file_path,
            display_name=file_path.name,
        )
        existing_paths[relative_path] = artifact_kind

    def _collect_graph_output_candidates(self, attempt_root: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        seen_paths: set[str] = set()

        def add_candidate(stage_name: str | None, raw_path: Any, artifact_kind: str | None = None) -> None:
            path = self._resolve_graph_output_path(attempt_root, raw_path)
            if path is None or not path.exists() or not path.is_file() or path.stat().st_size <= 0:
                return
            relative_path = self._relative_path_in_attempt(attempt_root, path)
            if relative_path is None or relative_path in seen_paths:
                return
            seen_paths.add(relative_path)
            candidates.append(
                {
                    "stage_name": stage_name,
                    "artifact_kind": artifact_kind or self._infer_graph_output_artifact_kind(path),
                    "file_path": path,
                }
            )

        for item in manifest.get("reports") if isinstance(manifest.get("reports"), list) else []:
            if not isinstance(item, dict):
                continue
            add_candidate(
                str(item.get("node_id") or "").strip() or None,
                item.get("relative_path"),
                "report_output",
            )

        raw_nodes = manifest.get("nodes")
        if isinstance(raw_nodes, dict):
            for stage_name, payload in raw_nodes.items():
                if not isinstance(payload, dict):
                    continue
                for item in payload.get("reports") if isinstance(payload.get("reports"), list) else []:
                    if not isinstance(item, dict):
                        continue
                    add_candidate(str(stage_name).strip() or None, item.get("relative_path"), "report_output")

        raw_pipeline = manifest.get("pipeline")
        pipeline_nodes = raw_pipeline.get("nodes") if isinstance(raw_pipeline, dict) else None
        if isinstance(pipeline_nodes, list):
            for item in pipeline_nodes:
                if not isinstance(item, dict):
                    continue
                stage_name = str(item.get("id") or "").strip() or None
                criteria = item.get("success_criteria")
                if not isinstance(criteria, list):
                    continue
                for criterion in criteria:
                    if not isinstance(criterion, dict):
                        continue
                    kind = str(criterion.get("kind") or "").strip().lower()
                    if kind not in {"file_nonempty", "json_valid"}:
                        continue
                    add_candidate(stage_name, criterion.get("path"))
        return candidates

    @staticmethod
    def _read_json_file(path: Path) -> dict[str, Any] | None:
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return payload if isinstance(payload, dict) else None

    @staticmethod
    def _resolve_graph_output_path(attempt_root: Path, raw_path: Any) -> Path | None:
        value = str(raw_path or "").strip()
        if not value:
            return None
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = attempt_root / candidate
        try:
            resolved = candidate.resolve()
            resolved.relative_to(attempt_root.resolve())
        except (OSError, ValueError):
            return None
        return resolved

    @staticmethod
    def _relative_path_in_attempt(attempt_root: Path, file_path: Path) -> str | None:
        try:
            return file_path.resolve().relative_to(attempt_root.resolve()).as_posix()
        except (OSError, ValueError):
            return None

    @staticmethod
    def _infer_graph_output_artifact_kind(path: Path) -> str:
        return "audited_result_json" if path.name.lower() == "audited-result.json" else "report_output"

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
