from __future__ import annotations

import asyncio
import base64
import json
import logging
import shutil
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Optional
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.config import get_config
from app.models.database import Case, DownloadJob, get_session_factory
from app.services.reporting import ensure_case_report_documents, list_case_reports, read_report_content


logger = logging.getLogger(__name__)

DOWNLOAD_SOURCE_TYPE = "vuln_intake_report"
DOWNLOAD_STATUS_PENDING = "pending"
DOWNLOAD_STATUS_PROCESSING = "processing"
DOWNLOAD_STATUS_SUCCEEDED = "succeeded"
DOWNLOAD_STATUS_FAILED = "failed"
DOWNLOAD_STATUS_EXPIRED = "expired"
DOWNLOAD_RETENTION_DAYS = 7


def _now() -> datetime:
    return datetime.utcnow()


def _safe_filename(value: str, fallback: str) -> str:
    text = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "-" for ch in (value or "").strip())
    text = "-".join(part for part in text.split("-") if part)
    return text[:96] or fallback


def _job_root(project_id: str, job_id: str) -> Path:
    return Path(get_config().storage.base_path).resolve() / "downloads" / "vuln-center" / project_id / job_id


def _job_zip_path(project_id: str, job_id: str) -> Path:
    return _job_root(project_id, job_id) / "bundle.zip"


def _parse_report_ids(value: str | None) -> list[str]:
    try:
        data = json.loads(value or "[]")
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    return [str(item).strip() for item in data if str(item).strip()]


def _is_downloadable(job: DownloadJob) -> bool:
    if job.status != DOWNLOAD_STATUS_SUCCEEDED or not job.output_path:
        return False
    if job.expires_at and job.expires_at <= _now():
        return False
    path = Path(job.output_path)
    return path.exists() and path.is_file()


def serialize_job(job: DownloadJob) -> dict[str, Any]:
    return {
        "job_id": job.id,
        "project_id": job.project_id,
        "source_type": job.source_type,
        "scope_type": job.scope_type,
        "status": job.status,
        "report_ids": _parse_report_ids(job.report_ids_json),
        "report_count": job.report_count,
        "output_format": job.output_format,
        "output_filename": job.output_filename,
        "output_size_bytes": job.output_size_bytes or 0,
        "created_by": job.created_by,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "expires_at": job.expires_at,
        "last_error": job.last_error,
        "downloadable": _is_downloadable(job),
    }


def list_jobs(db: Session, project_id: str) -> list[dict[str, Any]]:
    items = (
        db.query(DownloadJob)
        .filter(DownloadJob.project_id == project_id)
        .order_by(DownloadJob.created_at.desc())
        .all()
    )
    return [serialize_job(item) for item in items]


def get_job_or_404(db: Session, project_id: str, job_id: str) -> DownloadJob:
    item = db.query(DownloadJob).filter(DownloadJob.id == job_id, DownloadJob.project_id == project_id).first()
    if item is None:
        raise HTTPException(status_code=404, detail="download job not found")
    return item


def get_job_stats(db: Session, project_id: str) -> dict[str, int]:
    items = db.query(DownloadJob).filter(DownloadJob.project_id == project_id).all()
    stats = {
        "total": len(items),
        "pending": 0,
        "processing": 0,
        "succeeded": 0,
        "failed": 0,
        "expired": 0,
        "downloadable": 0,
    }
    for item in items:
        if item.status in stats:
            stats[item.status] += 1
        if _is_downloadable(item):
            stats["downloadable"] += 1
    return stats


def create_job(db: Session, *, project_id: str, report_ids: list[str], created_by: str | None) -> dict[str, Any]:
    cases = db.query(Case).filter(Case.id.in_(report_ids)).all()
    case_by_id = {item.id: item for item in cases}
    missing = [report_id for report_id in report_ids if report_id not in case_by_id]
    if missing:
        raise HTTPException(status_code=404, detail=f"cases not found: {', '.join(missing[:5])}")
    wrong_project = [item.id for item in cases if item.project_id != project_id]
    if wrong_project:
        raise HTTPException(status_code=400, detail="all reports must belong to the same project")

    job_id = uuid4().hex
    filename_stub = _safe_filename(cases[0].title if len(cases) == 1 else f"vuln-reports-{project_id}", "vuln-reports")
    output_filename = f"{filename_stub}-{job_id[:8]}.zip"
    job = DownloadJob(
        id=job_id,
        project_id=project_id,
        source_type=DOWNLOAD_SOURCE_TYPE,
        scope_type="single" if len(report_ids) == 1 else "batch",
        status=DOWNLOAD_STATUS_PENDING,
        report_ids_json=json.dumps(report_ids, ensure_ascii=False),
        report_count=len(report_ids),
        output_format="zip",
        output_filename=output_filename,
        output_path=str(_job_zip_path(project_id, job_id)),
        output_size_bytes=0,
        created_by=created_by,
        last_error=None,
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return serialize_job(job)


def retry_job(db: Session, project_id: str, job_id: str) -> dict[str, Any]:
    job = get_job_or_404(db, project_id, job_id)
    if job.status != DOWNLOAD_STATUS_FAILED:
        raise HTTPException(status_code=400, detail="only failed jobs can be retried")
    root = _job_root(job.project_id, job.id)
    if root.exists():
        shutil.rmtree(root, ignore_errors=True)
    job.status = DOWNLOAD_STATUS_PENDING
    job.started_at = None
    job.finished_at = None
    job.expires_at = None
    job.last_error = None
    job.output_size_bytes = 0
    db.add(job)
    db.commit()
    db.refresh(job)
    return serialize_job(job)


def delete_job(db: Session, project_id: str, job_id: str) -> dict[str, Any]:
    job = get_job_or_404(db, project_id, job_id)
    if job.status in {DOWNLOAD_STATUS_PENDING, DOWNLOAD_STATUS_PROCESSING}:
        raise HTTPException(status_code=400, detail="processing job cannot be deleted")
    root = _job_root(job.project_id, job.id)
    if root.exists():
        shutil.rmtree(root, ignore_errors=True)
    payload = serialize_job(job)
    db.delete(job)
    db.commit()
    return payload


def mark_expired_jobs(db: Session) -> int:
    count = 0
    items = (
        db.query(DownloadJob)
        .filter(DownloadJob.status == DOWNLOAD_STATUS_SUCCEEDED, DownloadJob.expires_at.is_not(None))
        .all()
    )
    current = _now()
    for item in items:
        if item.expires_at and item.expires_at <= current:
            root = _job_root(item.project_id, item.id)
            if root.exists():
                shutil.rmtree(root, ignore_errors=True)
            item.status = DOWNLOAD_STATUS_EXPIRED
            item.updated_at = current
            db.add(item)
            count += 1
    if count:
        db.commit()
    return count


@dataclass
class _ArtifactMaterializeResult:
    warnings: list[str]
    files: list[str]


def _artifact_bytes(artifact: dict[str, Any]) -> tuple[bytes | None, str | None]:
    content = artifact.get("content")
    if not isinstance(content, str):
        return None, None
    encoding = str(artifact.get("encoding") or "").lower()
    if encoding == "base64":
        try:
            return base64.b64decode(content), None
        except Exception as exc:
            return None, f"base64 decode failed for {artifact.get('name') or artifact.get('path') or 'artifact'}: {exc}"
    return content.encode("utf-8"), None


def _write_artifact_tree(base_dir: Path, artifact: dict[str, Any], prefix: str = "") -> _ArtifactMaterializeResult:
    warnings: list[str] = []
    files: list[str] = []
    kind = str(artifact.get("kind") or "other").lower()
    rel_name = str(artifact.get("path") or artifact.get("name") or "artifact").strip().lstrip("/")
    if not rel_name:
        rel_name = "artifact"
    rel_path = Path(prefix) / rel_name

    if kind in {"directory", "tree"}:
        target_dir = (base_dir / rel_path).resolve()
        target_dir.mkdir(parents=True, exist_ok=True)
        for child in artifact.get("children") or []:
            if isinstance(child, dict):
                result = _write_artifact_tree(base_dir, child, prefix="")
                warnings.extend(result.warnings)
                files.extend(result.files)
        return _ArtifactMaterializeResult(warnings=warnings, files=files)

    if artifact.get("children") and kind not in {"directory", "tree"}:
        for child in artifact.get("children") or []:
            if isinstance(child, dict):
                result = _write_artifact_tree(base_dir, child, prefix=str(rel_path.parent))
                warnings.extend(result.warnings)
                files.extend(result.files)

    target_path = (base_dir / rel_path).resolve()
    target_path.parent.mkdir(parents=True, exist_ok=True)
    payload, payload_error = _artifact_bytes(artifact)
    if payload_error:
        warnings.append(payload_error)
    if payload is not None:
        target_path.write_bytes(payload)
        files.append(str(rel_path))
        return _ArtifactMaterializeResult(warnings=warnings, files=files)

    if artifact.get("content_ref"):
        target_path = target_path.with_suffix(target_path.suffix + ".ref.txt")
        target_path.write_text(str(artifact.get("content_ref")), encoding="utf-8")
        files.append(str(target_path.relative_to(base_dir)))
        warnings.append(f"artifact content_ref unresolved: {artifact.get('content_ref')}")
        return _ArtifactMaterializeResult(warnings=warnings, files=files)

    if kind in {"json", "text"}:
        target_path.write_text(json.dumps(artifact, ensure_ascii=False, indent=2), encoding="utf-8")
        files.append(str(rel_path))
        return _ArtifactMaterializeResult(warnings=warnings, files=files)

    warnings.append(f"artifact skipped: {artifact.get('name') or rel_name}")
    return _ArtifactMaterializeResult(warnings=warnings, files=files)


def _prepare_case_bundle(case: Case, case_dir: Path) -> dict[str, Any]:
    case_dir.mkdir(parents=True, exist_ok=True)
    docs, _ = ensure_case_report_documents(case, actions=[], results=[], manual_tasks=[])
    report_files: list[str] = []
    warnings: list[str] = []
    for doc in docs or list_case_reports(case):
        content = read_report_content(doc.get("storage_path"))
        if content is None:
            warnings.append(f"report missing: {doc.get('report_id')}")
            continue
        file_name = _safe_filename(f"{doc.get('title') or doc.get('report_id')}.md", f"{doc.get('report_id') or 'report'}.md")
        report_path = case_dir / file_name
        report_path.write_text(content, encoding="utf-8")
        report_files.append(file_name)

    display_meta = json.loads(case.display_meta_json or "{}")
    artifacts = display_meta.get("artifacts") if isinstance(display_meta.get("artifacts"), list) else []
    artifacts_dir = case_dir / "attachments"
    artifact_files: list[str] = []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        result = _write_artifact_tree(artifacts_dir, artifact)
        warnings.extend(result.warnings)
        artifact_files.extend(result.files)
    (case_dir / "artifacts.json").write_text(json.dumps(artifacts, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "case_id": case.id,
        "title": case.title,
        "reports": report_files,
        "artifacts": artifact_files,
        "warnings": warnings,
    }


def process_job(db: Session, job_id: str) -> Optional[dict[str, Any]]:
    job = db.query(DownloadJob).filter(DownloadJob.id == job_id).first()
    if job is None:
        return None
    if job.status not in {DOWNLOAD_STATUS_PENDING, DOWNLOAD_STATUS_PROCESSING}:
        return serialize_job(job)

    job.status = DOWNLOAD_STATUS_PROCESSING
    job.started_at = job.started_at or _now()
    job.last_error = None
    db.add(job)
    db.commit()
    db.refresh(job)

    report_ids = _parse_report_ids(job.report_ids_json)
    cases = db.query(Case).filter(Case.id.in_(report_ids)).all()
    case_by_id = {item.id: item for item in cases}
    ordered_cases = [case_by_id[report_id] for report_id in report_ids if report_id in case_by_id]
    if not ordered_cases:
        job.status = DOWNLOAD_STATUS_FAILED
        job.finished_at = _now()
        job.last_error = "no case data found for download job"
        db.add(job)
        db.commit()
        db.refresh(job)
        return serialize_job(job)

    root = _job_root(job.project_id, job.id)
    if root.exists():
        shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True, exist_ok=True)
    zip_path = Path(job.output_path or _job_zip_path(job.project_id, job.id))
    manifest: dict[str, Any] = {
        "job_id": job.id,
        "project_id": job.project_id,
        "scope_type": job.scope_type,
        "report_count": job.report_count,
        "generated_at": _now().isoformat(),
        "items": [],
        "warnings": [],
    }

    try:
        with TemporaryDirectory(prefix=f"vuln-dl-{job.id[:8]}-") as tmp_dir:
            bundle_root = Path(tmp_dir) / f"vuln-download-{job.id[:8]}"
            bundle_root.mkdir(parents=True, exist_ok=True)
            for case in ordered_cases:
                case_dir = bundle_root / _safe_filename(f"{case.title}-{case.id}", case.id)
                case_payload = _prepare_case_bundle(case, case_dir)
                manifest["items"].append(case_payload)
                manifest["warnings"].extend(case_payload.get("warnings") or [])
            (bundle_root / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for path in bundle_root.rglob("*"):
                    if path.is_file():
                        archive.write(path, path.relative_to(bundle_root.parent))
        job.status = DOWNLOAD_STATUS_SUCCEEDED
        job.finished_at = _now()
        job.expires_at = job.finished_at + timedelta(days=DOWNLOAD_RETENTION_DAYS)
        job.output_size_bytes = zip_path.stat().st_size if zip_path.exists() else 0
        job.output_path = str(zip_path)
        job.last_error = None
    except Exception as exc:
        logger.exception("download job %s failed", job.id)
        job.status = DOWNLOAD_STATUS_FAILED
        job.finished_at = _now()
        job.last_error = str(exc)
    db.add(job)
    db.commit()
    db.refresh(job)
    return serialize_job(job)


def process_pending_jobs_once() -> int:
    session = get_session_factory()()
    try:
        mark_expired_jobs(session)
        pending = (
            session.query(DownloadJob)
            .filter(DownloadJob.status == DOWNLOAD_STATUS_PENDING)
            .order_by(DownloadJob.created_at.asc())
            .all()
        )
        processed = 0
        for item in pending[:2]:
            process_job(session, item.id)
            processed += 1
        return processed
    finally:
        session.close()


class DownloadCenterService:
    def __init__(self) -> None:
        self._task: Optional[asyncio.Task] = None
        self._running = False

    async def _loop(self) -> None:
        while self._running:
            try:
                await asyncio.to_thread(process_pending_jobs_once)
            except Exception:
                logger.exception("download center loop iteration failed")
            await asyncio.sleep(5)

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass


_download_center_service: Optional[DownloadCenterService] = None


def get_download_center_service() -> DownloadCenterService:
    global _download_center_service
    if _download_center_service is None:
        _download_center_service = DownloadCenterService()
    return _download_center_service
