"""Analysis result cache for Binary-to-Source tasks."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy import case, func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_config
from app.model import B2SAnalysisCache, B2STaskItem
from app.observability import get_observability
from app.time_utils import isoformat_local, now_local

CACHE_KEY_RE = re.compile(r"^[a-f0-9]{64}_(turbo|fast|deep)$")


def _is_ida_intermediate_path(path: str | Path | None) -> bool:
    if not path:
        return False
    name = Path(str(path)).name.lower()
    return "_ida." in name or name.endswith("_ida.c") or name.endswith("_ida.h")


def _is_legacy_re_work_dir(path: str | Path | None) -> bool:
    if not path:
        return False
    try:
        name = Path(str(path)).name
    except Exception:
        return False
    return name.startswith(".re_work_")


def _remove_ida_intermediate_outputs(output_dir: str | Path | None) -> list[str]:
    root = Path(str(output_dir or "")).expanduser()
    if not root.exists():
        return []
    removed: list[str] = []
    for path in sorted(root.rglob("*")):
        try:
            relative_parts = [part.lower() for part in path.relative_to(root).parts]
        except Exception:
            relative_parts = [part.lower() for part in path.parts]
        if "run" in relative_parts:
            continue
        if path.is_dir():
            if not _is_legacy_re_work_dir(path):
                continue
            try:
                shutil.rmtree(path)
                removed.append(str(path))
            except FileNotFoundError:
                continue
            continue
        if path.is_file() and _is_ida_intermediate_path(path):
            try:
                path.unlink()
                removed.append(str(path))
            except FileNotFoundError:
                continue
    return removed


@dataclass(frozen=True)
class FileDigest:
    sha256: str
    size: int


@dataclass(frozen=True)
class CacheLookupResult:
    hit: bool
    cache_key: str | None = None
    miss_reason: str | None = None


@dataclass(frozen=True)
class CacheDeleteResult:
    cache_key: str
    deleted: bool
    status: str
    message: str | None = None


class B2SCacheService:
    """Shared cache for successful B2S item analysis outputs."""

    def enabled(self) -> bool:
        return bool(get_config().cache.enabled)

    def compute_file_digest(self, path: Path) -> FileDigest:
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as file:
            while True:
                chunk = file.read(8 * 1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
        return FileDigest(sha256=digest.hexdigest(), size=size)

    def normalize_cache_mode(self, metadata: dict[str, Any] | None) -> str:
        mode = str((metadata or {}).get("mode") or "").strip().lower()
        if mode == "deep":
            return "deep"
        if mode == "turbo":
            return "turbo"
        return "fast"

    def build_cache_key(self, file_sha256: str, mode: str) -> str:
        digest = str(file_sha256 or "").strip().lower()
        raw_mode = str(mode or "").strip().lower()
        if raw_mode == "deep":
            normalized_mode = "deep"
        elif raw_mode == "turbo":
            normalized_mode = "turbo"
        else:
            normalized_mode = "fast"
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError("invalid file sha256")
        return f"{digest}_{normalized_mode}"

    def cache_root(self) -> Path:
        return Path(get_config().cache.root_dir).resolve()

    def canonical_dir(self, cache_key: str) -> Path:
        self._validate_cache_key(cache_key)
        return self.cache_root() / cache_key

    def canonical_output_dir(self, cache_key: str) -> Path:
        return self.canonical_dir(cache_key) / "output"

    @staticmethod
    def cache_mode_from_key(cache_key: str) -> str:
        key = str(cache_key or "")
        if key.endswith("_deep"):
            return "deep"
        if key.endswith("_turbo"):
            return "turbo"
        return "fast" if key.endswith("_fast") else "unknown"

    def lookup_ready_cache(self, db: Session, cache_key: str) -> B2SAnalysisCache | None:
        self._validate_cache_key(cache_key)
        row = db.query(B2SAnalysisCache).filter(
            B2SAnalysisCache.cache_key == cache_key,
            B2SAnalysisCache.status == "ready",
        ).first()
        if not row:
            return None
        output_dir = Path(row.canonical_output_dir)
        if not output_dir.is_dir() or not (output_dir.parent / "READY").is_file():
            return None
        return row

    def list_cache_entries(
        self,
        db: Session,
        *,
        project_id: str,
        limit: int = 100,
        offset: int = 0,
        include_all_projects: bool = False,
        mode: str | None = None,
        status: str | None = "ready",
        cache_key: str | None = None,
        elf_basename: str | None = None,
        source_task_id: str | None = None,
        source_item_id: str | None = None,
        has_hits: str | None = None,
    ) -> dict[str, Any]:
        query = self._apply_cache_list_filters(
            db.query(B2SAnalysisCache),
            project_id=project_id,
            include_all_projects=include_all_projects,
            mode=mode,
            status=status,
            cache_key=cache_key,
            elf_basename=elf_basename,
            source_task_id=source_task_id,
            source_item_id=source_item_id,
            has_hits=has_hits,
        )
        total = query.count()
        paged_rows = (
            query.order_by(B2SAnalysisCache.last_hit_at.desc(), B2SAnalysisCache.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return {
            "total": total,
            "items": [self._serialize_cache_entry(row) for row in paged_rows],
            "summary": self._build_summary(
                db,
                project_id=project_id,
                include_all_projects=include_all_projects,
                mode=mode,
                status=status,
                cache_key=cache_key,
                elf_basename=elf_basename,
                source_task_id=source_task_id,
                source_item_id=source_item_id,
                has_hits=has_hits,
            ),
        }

    def get_cache_entry_detail(self, db: Session, cache_key: str) -> dict[str, Any] | None:
        self._validate_cache_key(cache_key)
        row = db.query(B2SAnalysisCache).filter(B2SAnalysisCache.cache_key == cache_key).first()
        if not row:
            return None
        payload = self._serialize_cache_entry(row)
        payload["generated_files"] = self._loads(row.generated_files_json, [])
        metadata = self._loads(row.metadata_json, {})
        payload["metadata"] = metadata if isinstance(metadata, dict) else {}
        source_metadata = payload["metadata"].get("source_metadata") if isinstance(payload["metadata"], dict) else {}
        payload["source_metadata"] = source_metadata if isinstance(source_metadata, dict) else {}
        manifest_data, manifest_error = self._read_manifest(row)
        payload["manifest"] = manifest_data
        payload["manifest_parse_error"] = manifest_error
        return payload

    def delete_cache_entry(self, db: Session, cache_key: str) -> CacheDeleteResult:
        self._validate_cache_key(cache_key)
        row = db.query(B2SAnalysisCache).filter(B2SAnalysisCache.cache_key == cache_key).first()
        if not row:
            return CacheDeleteResult(cache_key=cache_key, deleted=False, status="not_found", message="缓存条目不存在")
        if str(row.status or "") != "ready":
            return CacheDeleteResult(cache_key=cache_key, deleted=False, status="invalid_status", message="仅允许删除 ready 状态的缓存条目")

        output_dir = Path(str(row.canonical_output_dir or "")).resolve()
        cache_dir = output_dir.parent
        try:
            self._ensure_path_within_cache_root(cache_dir)
        except ValueError as exc:
            return CacheDeleteResult(cache_key=cache_key, deleted=False, status="invalid_path", message=str(exc))

        message = "缓存目录和数据库记录已删除"
        try:
            if cache_dir.exists():
                if not cache_dir.is_dir():
                    return CacheDeleteResult(cache_key=cache_key, deleted=False, status="invalid_path", message="缓存目录路径不是目录")
                shutil.rmtree(cache_dir)
            else:
                message = "缓存目录缺失，已清理孤儿数据库记录"
            db.delete(row)
            db.commit()
            return CacheDeleteResult(cache_key=cache_key, deleted=True, status="deleted", message=message)
        except Exception as exc:
            db.rollback()
            return CacheDeleteResult(cache_key=cache_key, deleted=False, status="delete_failed", message=str(exc))

    def batch_delete_cache_entries(self, db: Session, cache_keys: list[str]) -> dict[str, Any]:
        results: list[CacheDeleteResult] = []
        for cache_key in cache_keys:
            try:
                results.append(self.delete_cache_entry(db, cache_key))
            except ValueError as exc:
                results.append(CacheDeleteResult(cache_key=cache_key, deleted=False, status="invalid_key", message=str(exc)))
        deleted_count = sum(1 for item in results if item.deleted)
        failed_count = len(results) - deleted_count
        return {
            "status": "ok" if failed_count == 0 else "partial_success",
            "deleted_count": deleted_count,
            "failed_count": failed_count,
            "results": [
                {
                    "status": item.status,
                    "cache_key": item.cache_key,
                    "deleted": item.deleted,
                    "message": item.message,
                }
                for item in results
            ],
        }

    def prepare_cache_metadata(self, item: B2STaskItem, input_path: Path) -> dict[str, Any]:
        digest = self.compute_file_digest(input_path)
        metadata = item.extra_metadata or {}
        mode = self.normalize_cache_mode(metadata)
        reuse_cache = bool(metadata.get("reuse_cache", True))
        cache_meta = {
            "enabled": bool(self.enabled()),
            "hit": False,
            "sharing_mode": "shared",
            "cache_key": self.build_cache_key(digest.sha256, mode),
            "file_sha256": digest.sha256,
            "file_size": digest.size,
            "cache_mode": mode,
            "analysis_signature": mode,
            "analysis_signature_payload": {"mode": mode},
            "reuse_cache_at_create": reuse_cache,
        }
        metadata["cache"] = cache_meta
        item.extra_metadata = metadata
        return cache_meta

    def try_apply_cache_hit(self, db: Session, item: B2STaskItem, input_path: Path) -> CacheLookupResult:
        metadata = item.extra_metadata or {}
        mode = self.normalize_cache_mode(metadata)
        reuse_cache = bool(metadata.get("reuse_cache", True))
        get_observability().record_cache_request(mode=mode, reuse_cache=reuse_cache)
        if not self.enabled():
            metadata["cache"] = {"enabled": False}
            item.extra_metadata = metadata
            get_observability().record_cache_miss(mode=mode, reason="disabled")
            return CacheLookupResult(hit=False, miss_reason="disabled")

        cache_meta = self.prepare_cache_metadata(item, input_path)
        cache_key = str(cache_meta.get("cache_key") or "")
        cache = self.lookup_ready_cache(db, cache_key)
        if not cache:
            metadata = item.extra_metadata or {}
            metadata.setdefault("cache", {}).update({"miss_reason": "not_found"})
            item.extra_metadata = metadata
            get_observability().record_cache_miss(mode=mode, reason="not_found")
            return CacheLookupResult(hit=False, cache_key=cache_key, miss_reason="not_found")

        self._materialize_output(Path(cache.canonical_output_dir), Path(item.output_dir))
        removed_intermediates = _remove_ida_intermediate_outputs(item.output_dir)
        item.status = "success"
        item.dispatch_status = "cache_hit"
        item.phase = "completed"
        item.pi_job_id = None
        item.generated_files = self._remap_generated_files(cache, item)
        item.progress = self._loads(cache.progress_json, {}) or {
            "phase": "completed",
            "phase_label": "已完成",
            "message": "命中B2S分析缓存",
            "percent": 100.0,
            "updated_at": isoformat_local(now_local()),
        }
        progress = item.progress or {}
        progress.update({"phase": "completed", "phase_label": "已完成", "percent": 100.0, "cache_hit": True})
        item.progress = progress
        item.failure_type = None
        item.error_reason = None
        item.started_at = now_local()
        item.finished_at = now_local()
        metadata = item.extra_metadata or {}
        metadata.setdefault("cache", {}).update({
            "hit": True,
            "miss_reason": None,
            "source_project_id": cache.source_project_id,
            "source_task_id": cache.source_task_id,
            "source_item_id": cache.source_item_id,
            "materialize_mode": get_config().cache.materialize_mode,
            "hit_at": isoformat_local(now_local()),
        })
        if removed_intermediates:
            metadata["removed_ida_intermediate_outputs"] = removed_intermediates
        cached_function_stats = self._loads(cache.function_stats_json, None)
        if cached_function_stats:
            metadata["function_stats"] = cached_function_stats
        item.extra_metadata = metadata
        cache.hit_count = int(cache.hit_count or 0) + 1
        cache.last_hit_at = now_local()
        get_observability().record_cache_hit(mode=mode)
        return CacheLookupResult(hit=True, cache_key=cache_key)

    def store_success_cache(self, db: Session, item: B2STaskItem, *, upsert: bool = False) -> bool:
        mode = self.normalize_cache_mode(item.extra_metadata or {})
        if not self.enabled() or item.status != "success":
            get_observability().record_cache_store(mode=mode, result="failed")
            return False
        metadata = item.extra_metadata or {}
        cache_meta = metadata.get("cache") if isinstance(metadata.get("cache"), dict) else {}
        if cache_meta.get("hit"):
            get_observability().record_cache_store(mode=mode, result="skipped")
            return False
        cache_key = str(cache_meta.get("cache_key") or "")
        if not cache_key or not CACHE_KEY_RE.fullmatch(cache_key):
            get_observability().record_cache_store(mode=mode, result="failed")
            return False
        source_output = Path(item.output_dir)
        if not source_output.is_dir():
            get_observability().record_cache_store(mode=mode, result="failed")
            return False

        existing = self.lookup_ready_cache(db, cache_key)
        if existing and not upsert:
            get_observability().record_cache_store(mode=mode, result="skipped")
            return False

        canonical_dir = self.canonical_dir(cache_key)
        canonical_output = canonical_dir / "output"
        tmp_dir = self.cache_root() / f".{cache_key}.building.{os.getpid()}.{uuid4().hex}"
        backup_dir = self.cache_root() / f".{cache_key}.backup.{os.getpid()}.{uuid4().hex}"
        try:
            if tmp_dir.exists():
                shutil.rmtree(tmp_dir)
            tmp_output = tmp_dir / "output"
            shutil.copytree(source_output, tmp_output)
            canonical_dir.parent.mkdir(parents=True, exist_ok=True)
            replaced = bool(existing and upsert)
            if replaced and canonical_dir.exists():
                os.replace(canonical_dir, backup_dir)
                os.replace(tmp_dir, canonical_dir)
                shutil.rmtree(backup_dir, ignore_errors=True)
            elif not canonical_dir.exists():
                os.replace(tmp_dir, canonical_dir)
            else:
                shutil.rmtree(tmp_dir, ignore_errors=True)
            self._write_manifest(canonical_dir, item, cache_meta, replaced=replaced)
            (canonical_dir / "READY").write_text(isoformat_local(now_local()), encoding="utf-8")

            row = existing or B2SAnalysisCache(id=uuid4().hex[:16], cache_key=cache_key)
            row.file_sha256 = str(cache_meta.get("file_sha256") or "")
            row.file_size = int(cache_meta.get("file_size") or 0)
            row.elf_basename = Path(item.elf_path).name
            row.analysis_signature = str(cache_meta.get("analysis_signature") or "")
            row.analysis_signature_json = json.dumps(cache_meta.get("analysis_signature_payload") or {}, ensure_ascii=False)
            row.status = "ready"
            row.source_project_id = item.project_id
            row.source_task_id = item.task_id
            row.source_item_id = item.id
            row.canonical_output_dir = str(canonical_output)
            row.canonical_input_path = item.elf_path
            row.generated_files_json = json.dumps(self._canonical_generated_files(item, canonical_output), ensure_ascii=False)
            row.function_stats_json = json.dumps(metadata.get("function_stats") or {}, ensure_ascii=False)
            row.progress_json = item.progress_json
            row.metadata_json = json.dumps({"source_metadata": metadata.get("cache") or {}}, ensure_ascii=False)
            row.expires_at = None
            try:
                with db.begin_nested():
                    if not existing:
                        db.add(row)
                    db.flush()
            except IntegrityError:
                get_observability().record_cache_store(mode=mode, result="failed")
                return False
            get_observability().record_cache_store(mode=mode, result="updated" if replaced else "created")
            return True
        except Exception:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            shutil.rmtree(backup_dir, ignore_errors=True)
            get_observability().record_cache_store(mode=mode, result="failed")
            raise

    def delete_caches_for_source_task(self, db: Session, project_id: str, task_id: str) -> int:
        del db, project_id, task_id
        return 0

    def _materialize_output(self, source: Path, target: Path) -> None:
        target = target.resolve()
        if target.exists():
            if not target.is_dir():
                raise ValueError("缓存输出目标不是目录")
            shutil.rmtree(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        mode = get_config().cache.materialize_mode
        if mode == "copy":
            shutil.copytree(source, target)
            return
        if mode == "hardlink":
            shutil.copytree(source, target, copy_function=os.link)
            return
        os.symlink(source, target, target_is_directory=True)

    def _canonical_generated_files(self, item: B2STaskItem, canonical_output: Path) -> list[str]:
        output_dir = Path(item.output_dir).resolve()
        result: list[str] = []
        for raw in item.generated_files:
            try:
                path = Path(raw).resolve()
                if _is_ida_intermediate_path(path):
                    continue
                if _is_legacy_re_work_dir(path.parent):
                    continue
                if path.is_relative_to(output_dir):
                    result.append(str(canonical_output / path.relative_to(output_dir)))
                else:
                    result.append(raw)
            except Exception:
                raw_path = Path(str(raw))
                if not _is_ida_intermediate_path(raw) and not _is_legacy_re_work_dir(raw_path.parent):
                    result.append(raw)
        return result

    @staticmethod
    def _normalize_legacy_cached_path(base_output: Path, path: Path) -> Path:
        try:
            rel = path.relative_to(base_output)
        except Exception:
            return path
        parts = list(rel.parts)
        if parts and parts[0].startswith(".re_work_"):
            return base_output / "run" / Path(*parts[1:])
        return path

    def _remap_generated_files(self, cache: B2SAnalysisCache, item: B2STaskItem) -> list[str]:
        canonical_output = Path(cache.canonical_output_dir).resolve()
        item_output = Path(item.output_dir).resolve()
        result: list[str] = []
        for raw in self._loads(cache.generated_files_json, []):
            try:
                raw_path = Path(str(raw)).resolve()
                try:
                    raw_rel = raw_path.relative_to(canonical_output)
                except Exception:
                    raw_rel = None
                if raw_rel and raw_rel.parts and raw_rel.parts[0].startswith(".re_work_"):
                    continue
                path = self._normalize_legacy_cached_path(canonical_output, raw_path)
                if _is_ida_intermediate_path(path):
                    continue
                if _is_legacy_re_work_dir(path.parent):
                    continue
                if path.is_relative_to(canonical_output):
                    result.append(str(item_output / path.relative_to(canonical_output)))
                else:
                    result.append(str(raw))
            except Exception:
                raw_path = Path(str(raw))
                if not _is_ida_intermediate_path(raw) and not _is_legacy_re_work_dir(raw_path.parent):
                    result.append(str(raw))
        return result

    def _write_manifest(self, canonical_dir: Path, item: B2STaskItem, cache_meta: dict[str, Any], *, replaced: bool) -> None:
        payload = {
            "cache_key": cache_meta.get("cache_key"),
            "sharing_mode": "shared",
            "source_project_id": item.project_id,
            "source_task_id": item.task_id,
            "source_item_id": item.id,
            "file_sha256": cache_meta.get("file_sha256"),
            "analysis_signature": cache_meta.get("analysis_signature"),
            "mode": cache_meta.get("cache_mode"),
            "reuse_cache_at_create": cache_meta.get("reuse_cache_at_create"),
            "cache_replaced_by_task_id": item.task_id if replaced else None,
            "cache_replaced_at": isoformat_local(now_local()) if replaced else None,
            "created_at": isoformat_local(now_local()),
        }
        (canonical_dir / "manifest.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def _serialize_cache_entry(self, row: B2SAnalysisCache) -> dict[str, Any]:
        output_dir = Path(str(row.canonical_output_dir or "")).resolve()
        cache_dir = output_dir.parent
        ready_marker = cache_dir / "READY"
        manifest_path = cache_dir / "manifest.json"
        return {
            "cache_key": str(row.cache_key or ""),
            "status": str(row.status or ""),
            "mode": self.cache_mode_from_key(str(row.cache_key or "")),
            "elf_basename": row.elf_basename,
            "source_project_id": row.source_project_id,
            "source_task_id": row.source_task_id,
            "source_item_id": row.source_item_id,
            "file_sha256": str(row.file_sha256 or ""),
            "file_size": int(row.file_size or 0),
            "analysis_signature": row.analysis_signature,
            "hit_count": int(row.hit_count or 0),
            "last_hit_at": isoformat_local(row.last_hit_at) if row.last_hit_at else None,
            "created_at": isoformat_local(row.created_at) if row.created_at else None,
            "updated_at": isoformat_local(row.updated_at) if row.updated_at else None,
            "canonical_output_dir": str(row.canonical_output_dir or ""),
            "canonical_input_path": row.canonical_input_path,
            "cache_dir_exists": cache_dir.is_dir(),
            "ready_marker_exists": ready_marker.is_file(),
            "manifest_exists": manifest_path.is_file(),
            "output_dir_exists": output_dir.is_dir(),
        }

    def _build_summary(
        self,
        db: Session,
        *,
        project_id: str,
        include_all_projects: bool,
        mode: str | None,
        status: str | None,
        cache_key: str | None,
        elf_basename: str | None,
        source_task_id: str | None,
        source_item_id: str | None,
        has_hits: str | None,
    ) -> dict[str, Any]:
        summary_query = self._apply_cache_list_filters(
            db.query(
                func.count(B2SAnalysisCache.id),
                func.sum(case((B2SAnalysisCache.source_project_id == project_id, 1), else_=0)),
                func.sum(case((B2SAnalysisCache.cache_key.like("%_fast"), 1), else_=0)),
                func.sum(case((B2SAnalysisCache.cache_key.like("%_deep"), 1), else_=0)),
                func.sum(case((B2SAnalysisCache.cache_key.like("%_turbo"), 1), else_=0)),
                func.sum(func.coalesce(B2SAnalysisCache.hit_count, 0)),
                func.max(B2SAnalysisCache.last_hit_at),
            ),
            project_id=project_id,
            include_all_projects=include_all_projects,
            mode=mode,
            status=status,
            cache_key=cache_key,
            elf_basename=elf_basename,
            source_task_id=source_task_id,
            source_item_id=source_item_id,
            has_hits=has_hits,
        )
        visible_entries, current_project_entries, fast_entries, deep_entries, turbo_entries, total_hit_count, latest_hit = (
            summary_query.one()
        )
        return {
            "visible_entries": int(visible_entries or 0),
            "current_project_entries": int(current_project_entries or 0),
            "fast_entries": int(fast_entries or 0),
            "deep_entries": int(deep_entries or 0),
            "turbo_entries": int(turbo_entries or 0),
            "total_hit_count": int(total_hit_count or 0),
            "latest_hit_at": isoformat_local(latest_hit) if latest_hit else None,
        }

    def _apply_cache_list_filters(
        self,
        query,
        *,
        project_id: str,
        include_all_projects: bool,
        mode: str | None,
        status: str | None,
        cache_key: str | None,
        elf_basename: str | None,
        source_task_id: str | None,
        source_item_id: str | None,
        has_hits: str | None,
    ):
        if not include_all_projects:
            query = query.filter(B2SAnalysisCache.source_project_id == project_id)
        normalized_status = str(status or "").strip().lower()
        if normalized_status and normalized_status != "all":
            query = query.filter(B2SAnalysisCache.status == normalized_status)
        normalized_mode = str(mode or "").strip().lower()
        if normalized_mode == "fast":
            query = query.filter(B2SAnalysisCache.cache_key.like("%_fast"))
        elif normalized_mode == "deep":
            query = query.filter(B2SAnalysisCache.cache_key.like("%_deep"))
        elif normalized_mode == "turbo":
            query = query.filter(B2SAnalysisCache.cache_key.like("%_turbo"))
        if cache_key:
            query = query.filter(B2SAnalysisCache.cache_key.contains(str(cache_key).strip()))
        if elf_basename:
            query = query.filter(B2SAnalysisCache.elf_basename.contains(str(elf_basename).strip()))
        if source_task_id:
            query = query.filter(B2SAnalysisCache.source_task_id.contains(str(source_task_id).strip()))
        if source_item_id:
            query = query.filter(B2SAnalysisCache.source_item_id.contains(str(source_item_id).strip()))
        normalized_hits = str(has_hits or "").strip().lower()
        if normalized_hits == "hit":
            query = query.filter(B2SAnalysisCache.hit_count > 0)
        elif normalized_hits in {"never", "no_hit"}:
            query = query.filter(or_(B2SAnalysisCache.hit_count == 0, B2SAnalysisCache.hit_count.is_(None)))
        return query

    def _read_manifest(self, row: B2SAnalysisCache) -> tuple[dict[str, Any] | None, str | None]:
        manifest_path = Path(str(row.canonical_output_dir or "")).resolve().parent / "manifest.json"
        if not manifest_path.is_file():
            return None, None
        try:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
            return raw if isinstance(raw, dict) else {"value": raw}, None
        except Exception as exc:
            return None, str(exc)

    def _ensure_path_within_cache_root(self, path: Path) -> None:
        root = self.cache_root().resolve()
        target = path.resolve()
        if target == root or root in target.parents:
            return
        raise ValueError("缓存目录不在 cache.root_dir 下，拒绝删除")

    @staticmethod
    def _loads(raw: str | None, default: Any) -> Any:
        if not raw:
            return default
        try:
            return json.loads(raw)
        except Exception:
            return default

    @staticmethod
    def _validate_cache_key(cache_key: str) -> None:
        if not CACHE_KEY_RE.fullmatch(cache_key or ""):
            raise ValueError("invalid cache key")


_cache_service: B2SCacheService | None = None


def get_cache_service() -> B2SCacheService:
    global _cache_service
    if _cache_service is None:
        _cache_service = B2SCacheService()
    return _cache_service
