from __future__ import annotations

import threading
from pathlib import Path

from fastapi import HTTPException, status

from app.core.ids import new_refresh_job_id
from app.core.time_utils import utc_now_z
from app.db.database import DatabaseRow, get_database
from app.schemas import CatalogRefreshJobResponse, PagedPresetProjectsResponse, PresetProjectResponse
from app.services.workspace_service import get_workspace_service


class CatalogService:
    def list_projects(
        self,
        *,
        workspace_id: str,
        keyword: str | None,
        source: str | None,
        has_idl: bool | None,
        has_on_remote_request_cpp: bool | None,
        page: int,
        per_page: int,
    ) -> PagedPresetProjectsResponse:
        get_workspace_service().get_workspace(workspace_id)
        where = ["workspace_id = ?"]
        params: list[object] = [workspace_id]
        if keyword:
            where.append("(project_key like ? or project_path like ? or display_name like ?)")
            like = f"%{keyword}%"
            params.extend([like, like, like])
        if source and source != "all":
            where.append("source = ?")
            params.append(source)
        if has_idl is not None:
            where.append("has_idl = ?")
            params.append(1 if has_idl else 0)
        if has_on_remote_request_cpp is not None:
            where.append("has_on_remote_request_cpp = ?")
            params.append(1 if has_on_remote_request_cpp else 0)
        sql_where = " and ".join(where)
        offset = (page - 1) * per_page
        with get_database().connect() as conn:
            total = conn.execute(f"select count(*) from ipc_audit_preset_projects where {sql_where}", params).fetchone()[0]
            rows = conn.execute(
                f"""
                select workspace_id, project_key, project_path, display_name, source, has_idl,
                       has_on_remote_request_cpp, has_existing_audit_report, has_existing_poc_report, last_scanned_at
                from ipc_audit_preset_projects
                where {sql_where}
                order by project_path asc
                limit ? offset ?
                """,
                [*params, per_page, offset],
            ).fetchall()
        items = [self._row_to_model(row) for row in rows]
        return PagedPresetProjectsResponse(items=items, total=total, page=page, per_page=per_page)

    def refresh_projects(
        self,
        *,
        workspace_id: str,
        source: str,
        write_entries_file: bool,
        requested_by: str,
    ) -> CatalogRefreshJobResponse:
        if source not in {"entries_file", "bundle_scan"}:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"unsupported refresh source: {source}")
        get_workspace_service().get_workspace(workspace_id)
        refresh_job_id = new_refresh_job_id()
        created_at = utc_now_z()
        with get_database().connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            active = conn.execute(
                """
                select refresh_job_id
                from ipc_audit_catalog_refresh_jobs
                where workspace_id = ? and source = ? and status in ('queued', 'running')
                limit 1
                """,
                (workspace_id, source),
            ).fetchone()
            if active:
                conn.rollback()
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"catalog refresh already active: {active['refresh_job_id']}",
                )
            conn.execute(
                """
                insert into ipc_audit_catalog_refresh_jobs (
                  refresh_job_id, workspace_id, source, status, requested_by, created_at
                ) values (?, ?, ?, 'queued', ?, ?)
                """,
                (refresh_job_id, workspace_id, source, requested_by, created_at),
            )
            conn.commit()
        thread = threading.Thread(
            target=self._run_refresh_job,
            args=(refresh_job_id, workspace_id, source, write_entries_file),
            name=f"ipc-audit-catalog-refresh-{refresh_job_id}",
            daemon=True,
        )
        thread.start()
        return self.get_refresh_job(refresh_job_id)

    def get_refresh_job(self, refresh_job_id: str) -> CatalogRefreshJobResponse:
        with get_database().connect() as conn:
            row = conn.execute(
                """
                select refresh_job_id, workspace_id, source, status, requested_by, created_at,
                       started_at, finished_at, discovered_count, error_message
                from ipc_audit_catalog_refresh_jobs
                where refresh_job_id = ?
                """,
                (refresh_job_id,),
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"refresh job not found: {refresh_job_id}")
        return CatalogRefreshJobResponse(
            refresh_job_id=row["refresh_job_id"],
            workspace_id=row["workspace_id"],
            source=row["source"],
            status=row["status"],
            requested_by=row["requested_by"],
            created_at=row["created_at"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            discovered_count=row["discovered_count"],
            error_message=row["error_message"],
            message="catalog refresh finished" if row["status"] == "succeeded" else row["status"],
        )

    def ensure_preset_exists(self, workspace_id: str, project_path: str) -> None:
        with get_database().connect() as conn:
            row = conn.execute(
                """
                select 1 from ipc_audit_preset_projects
                where workspace_id = ? and project_path = ?
                limit 1
                """,
                (workspace_id, project_path),
            ).fetchone()
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"preset project not found in catalog: {project_path}",
            )

    def _run_refresh_job(
        self,
        refresh_job_id: str,
        workspace_id: str,
        source: str,
        write_entries_file: bool,
    ) -> None:
        started_at = utc_now_z()
        with get_database().connect() as conn:
            conn.execute(
                """
                update ipc_audit_catalog_refresh_jobs
                set status = 'running', started_at = ?
                where refresh_job_id = ? and status = 'queued'
                """,
                (started_at, refresh_job_id),
            )
        try:
            workspace = get_workspace_service().get_workspace(workspace_id)
            projects = self._scan_workspace(workspace, source=source)
            if write_entries_file:
                self._write_entries_file(workspace, [item["project_path"] for item in projects])
            finished_at = utc_now_z()
            with get_database().connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("delete from ipc_audit_preset_projects where workspace_id = ?", (workspace_id,))
                for item in projects:
                    conn.execute(
                        """
                        insert into ipc_audit_preset_projects (
                          workspace_id, project_key, project_path, display_name, source, has_idl,
                          has_on_remote_request_cpp, has_existing_audit_report, has_existing_poc_report, last_scanned_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            workspace_id,
                            item["project_key"],
                            item["project_path"],
                            item["display_name"],
                            item["source"],
                            item["has_idl"],
                            item["has_on_remote_request_cpp"],
                            item["has_existing_audit_report"],
                            item["has_existing_poc_report"],
                            finished_at,
                        ),
                    )
                conn.execute(
                    """
                    update ipc_audit_catalog_refresh_jobs
                    set status = 'succeeded', finished_at = ?, discovered_count = ?, error_message = null
                    where refresh_job_id = ?
                    """,
                    (finished_at, len(projects), refresh_job_id),
                )
                conn.commit()
        except Exception as exc:  # noqa: BLE001
            with get_database().connect() as conn:
                conn.execute(
                    """
                    update ipc_audit_catalog_refresh_jobs
                    set status = 'failed', finished_at = ?, error_message = ?
                    where refresh_job_id = ?
                    """,
                    (utc_now_z(), str(exc), refresh_job_id),
                )

    @staticmethod
    def _row_to_model(row: DatabaseRow) -> PresetProjectResponse:
        return PresetProjectResponse(
            project_key=row["project_key"],
            project_path=row["project_path"],
            display_name=row["display_name"],
            source=row["source"],
            has_idl=bool(row["has_idl"]),
            has_on_remote_request_cpp=bool(row["has_on_remote_request_cpp"]),
            has_existing_audit_report=bool(row["has_existing_audit_report"]),
            has_existing_poc_report=bool(row["has_existing_poc_report"]),
            last_scanned_at=row["last_scanned_at"],
        )

    def _scan_workspace(self, workspace, *, source: str) -> list[dict[str, object]]:
        repo_root = Path(workspace.repo_root).resolve()
        if not repo_root.exists():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"workspace repo root not available: {workspace.workspace_id}",
            )
        if source == "entries_file":
            projects = self._read_entries_file(repo_root / workspace.entries_file)
        else:
            projects = self._scan_bundle_projects(repo_root, workspace.bundle_scan_roots)
        results: list[dict[str, object]] = []
        for project_path in projects:
            root = repo_root / project_path
            label = project_path.replace("/", ".")
            results.append(
                {
                    "project_key": label,
                    "project_path": project_path,
                    "display_name": project_path,
                    "source": source,
                    "has_idl": 1 if self._has_idl(root) else 0,
                    "has_on_remote_request_cpp": 1 if self._has_on_remote_request_cpp(root) else 0,
                    "has_existing_audit_report": 1 if (repo_root / ".audit" / "ipc" / "project_reports" / f"{label}.md").exists() else 0,
                    "has_existing_poc_report": 1 if (repo_root / ".audit" / "ipc" / "poc_reports" / f"{label}.md").exists() else 0,
                }
            )
        return results

    @staticmethod
    def _read_entries_file(entries_path: Path) -> list[str]:
        if not entries_path.exists():
            return []
        projects: list[str] = []
        for line in entries_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            projects.append(stripped.strip("/"))
        return sorted(dict.fromkeys(projects))

    def _scan_bundle_projects(self, repo_root: Path, scan_roots: list[str]) -> list[str]:
        projects: list[str] = []
        for scan_root in scan_roots:
            absolute_root = repo_root / scan_root
            if not absolute_root.exists():
                continue
            for bundle_path in absolute_root.rglob("bundle.json"):
                project_root = bundle_path.parent
                try:
                    relative = project_root.resolve().relative_to(repo_root)
                except ValueError:
                    continue
                project_path = relative.as_posix().strip("/")
                if "_lite" in project_path:
                    continue
                if not self._has_idl(project_root) and not self._has_on_remote_request_cpp(project_root):
                    continue
                projects.append(project_path)
        return sorted(dict.fromkeys(projects))

    @staticmethod
    def _has_idl(project_root: Path) -> bool:
        return any(project_root.rglob("*.idl"))

    @staticmethod
    def _has_on_remote_request_cpp(project_root: Path) -> bool:
        for path in project_root.rglob("*.cpp"):
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
                if "OnRemoteRequest" in content or "OnRemoteRequst" in content:
                    return True
            except OSError:
                continue
        return False

    @staticmethod
    def _write_entries_file(workspace, projects: list[str]) -> None:
        path = (Path(workspace.repo_root) / workspace.entries_file).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        body = "\n".join(sorted(dict.fromkeys(projects))) + ("\n" if projects else "")
        path.write_text(body, encoding="utf-8")


_catalog_service: CatalogService | None = None


def get_catalog_service() -> CatalogService:
    global _catalog_service
    if _catalog_service is None:
        _catalog_service = CatalogService()
    return _catalog_service
