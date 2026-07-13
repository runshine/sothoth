"""FastAPI routes for poc-gen-verify: task CRUD + cancel/restart + logs/timeline/artifacts.

All reads/writes go through MySQL (DB = source of truth). `POST /tasks` only
INSERTs a pending row — the scheduler dispatcher pump publishes to Celery, the
worker runs the `poc` CLI. Cancel/restart revoke the Celery task via Redis control.
"""
from __future__ import annotations

import io
import shutil
import zipfile
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.orm import Session

from .api_schemas import (
    ActionResponse,
    PocArtifactContentResponse,
    PocArtifactsResponse,
    PocSessionContentResponse,
    PocSessionFile,
    PocSessionListResponse,
    PocTaskCreateResponse,
    PocTaskListResponse,
    PocTaskLogsResponse,
    PocTaskRequest,
    PocTaskStatsResponse,
    PocTaskStatus,
    PocTaskTimelineResponse,
)
from .config import get_config
from .db import get_db
from .service.runtime_bootstrap import get_runtime_bootstrap
from .service.task_service import get_task_service

router = APIRouter(prefix="/api/app/poc-gen-verify", tags=["PoC Gen Verify"])


@router.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "secflow-app-poc-gen-verify"}


@router.get("/ready")
def ready() -> dict:
    cfg = get_config()
    checks = {
        "claude": shutil.which("claude") is not None,
        "tmux": shutil.which("tmux") is not None,
        "gdb": shutil.which("gdb") is not None,
        "tmux-mcp": shutil.which("tmux-mcp") is not None,
        "poc": shutil.which(cfg.poc_bin) is not None,
    }
    bootstrap = get_runtime_bootstrap().status()
    checks["db"] = bool(bootstrap.get("db_ready"))
    ok = all(checks.values())
    return {"status": "ok" if ok else "degraded", "ready": ok, "checks": checks, "bootstrap": bootstrap}


@router.post("/tasks", response_model=PocTaskCreateResponse, status_code=201)
def create_task(req: PocTaskRequest, db: Session = Depends(get_db)) -> PocTaskCreateResponse:
    """Create a PoC task (INSERT pending row; dispatcher publishes to Celery)."""
    rec = get_task_service().create_task(
        db,
        project_id=req.project_id,
        task_name=req.task_name,
        task_description=req.task_description,
        entry_function=req.entry_function,
        vuln_report_path=req.vuln_report_path,
        binary_dir=req.binary_dir,
        output_dir=req.output_dir,
        model=req.model,
        effort=req.effort,
        session_name=req.session_name,
        session_id=req.session_id,
        session_dir=req.session_dir,
        timeout=req.timeout,
        created_by=req.created_by,
    )
    return PocTaskCreateResponse(
        task_id=rec["task_id"], status=rec["status"],
        output_dir=rec["output_dir"], log_path=rec["log_path"],
    )


@router.get("/tasks", response_model=PocTaskListResponse)
def list_tasks(
    project_id: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(100, ge=1, le=1000),
    status: Optional[str] = Query(None),
    db: Session = Depends(get_db),
) -> PocTaskListResponse:
    return PocTaskListResponse(**get_task_service().list_tasks(
        db, project_id=project_id, page=page, per_page=per_page, status=status,
    ))


@router.get("/tasks/stats", response_model=PocTaskStatsResponse)
def get_task_stats(
    project_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
) -> PocTaskStatsResponse:
    return PocTaskStatsResponse(**get_task_service().get_task_stats(db, project_id=project_id))


@router.get("/tasks/{task_id}", response_model=PocTaskStatus)
def get_task(task_id: str, db: Session = Depends(get_db)) -> PocTaskStatus:
    return PocTaskStatus(**get_task_service().get_task(db, task_id))


@router.post("/tasks/{task_id}/cancel", response_model=PocTaskStatus)
def cancel_task(task_id: str, db: Session = Depends(get_db)) -> PocTaskStatus:
    return PocTaskStatus(**get_task_service().cancel_task(db, task_id))


@router.post("/tasks/{task_id}/restart", response_model=PocTaskStatus, status_code=201)
def restart_task(task_id: str, db: Session = Depends(get_db)) -> PocTaskStatus:
    return PocTaskStatus(**get_task_service().restart_task(db, task_id))


@router.get("/tasks/{task_id}/logs", response_model=PocTaskLogsResponse)
def get_task_logs(
    task_id: str,
    tail: int = Query(500, ge=1, le=20000),
    db: Session = Depends(get_db),
) -> PocTaskLogsResponse:
    return PocTaskLogsResponse(**get_task_service().get_task_logs(db, task_id, tail_lines=tail))


@router.get("/tasks/{task_id}/timeline", response_model=PocTaskTimelineResponse)
def get_task_timeline(task_id: str, db: Session = Depends(get_db)) -> PocTaskTimelineResponse:
    return PocTaskTimelineResponse(**get_task_service().get_task_timeline(db, task_id))


@router.get("/tasks/{task_id}/artifacts", response_model=PocArtifactsResponse)
def list_artifacts(task_id: str, db: Session = Depends(get_db)) -> PocArtifactsResponse:
    return PocArtifactsResponse(**get_task_service().list_artifacts(db, task_id))


# batch download MUST be declared before /artifacts/{name} so "download" isn't captured as {name}
@router.get("/tasks/{task_id}/artifacts/download")
def download_artifacts_archive(
    task_id: str,
    names: Optional[str] = Query(None, description="逗号分隔的产物名; 省略则打包全部"),
    db: Session = Depends(get_db),
):
    """Batch-download artifacts as a zip (all on_disk, or the named subset)."""
    name_list = [n.strip() for n in names.split(",") if n.strip()] if names else None
    paths = get_task_service().get_artifact_paths(db, task_id, name_list)
    if not paths:
        raise HTTPException(status_code=404, detail="无可用产物")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in paths:
            zf.write(p, p.name)
    buf.seek(0)
    return StreamingResponse(
        buf, media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="poc-artifacts-{task_id}.zip"'},
    )


@router.get("/tasks/{task_id}/artifacts/{name}", response_model=PocArtifactContentResponse)
def get_artifact_content(task_id: str, name: str, db: Session = Depends(get_db)) -> PocArtifactContentResponse:
    return PocArtifactContentResponse(**get_task_service().get_artifact_content(db, task_id, name))


@router.get("/tasks/{task_id}/artifacts/{name}/download")
def download_artifact(task_id: str, name: str, db: Session = Depends(get_db)):
    """Download a single artifact as raw bytes (incl. binary harness / .bin)."""
    path = get_task_service().get_artifact_path(db, task_id, name)
    return FileResponse(str(path), filename=path.name, media_type="application/octet-stream")


@router.get("/tasks/{task_id}/sessions", response_model=PocSessionListResponse)
def list_sessions(task_id: str, db: Session = Depends(get_db)) -> PocSessionListResponse:
    """List the `poc` CLI's per-stage session files (logs / stream-json / prompts / transcripts)."""
    return PocSessionListResponse(**get_task_service().list_sessions(db, task_id))


@router.get("/tasks/{task_id}/sessions/file", response_model=PocSessionContentResponse)
def get_session_file(
    task_id: str,
    path: str = Query(..., description="会话文件相对路径 (相对 output_dir)"),
    tail: int = Query(1000, ge=1, le=5000),
    db: Session = Depends(get_db),
) -> PocSessionContentResponse:
    """Return a bounded tail of a session file (seek-from-end; .jsonl is never full-parsed)."""
    return PocSessionContentResponse(**get_task_service().get_session_content(db, task_id, path, tail_lines=tail))
