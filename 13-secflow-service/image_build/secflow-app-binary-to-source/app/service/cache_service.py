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

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_config
from app.model import B2SAnalysisCache, B2STaskItem
from app.observability import get_observability
from app.time_utils import isoformat_local, now_local

CACHE_KEY_RE = re.compile(r"^[a-f0-9]{64}_(fast|deep)$")


@dataclass(frozen=True)
class FileDigest:
    sha256: str
    size: int


@dataclass(frozen=True)
class CacheLookupResult:
    hit: bool
    cache_key: str | None = None
    miss_reason: str | None = None


class B2SCacheService:
    """Global cache for successful B2S item analysis outputs."""

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
        return "deep" if mode == "deep" else "fast"

    def build_cache_key(self, file_sha256: str, mode: str) -> str:
        digest = str(file_sha256 or "").strip().lower()
        normalized_mode = "deep" if str(mode or "").strip().lower() == "deep" else "fast"
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

    def prepare_cache_metadata(self, item: B2STaskItem, input_path: Path) -> dict[str, Any]:
        digest = self.compute_file_digest(input_path)
        metadata = item.extra_metadata or {}
        mode = self.normalize_cache_mode(metadata)
        reuse_cache = bool(metadata.get("reuse_cache", True))
        cache_meta = {
            "enabled": bool(self.enabled()),
            "hit": False,
            "scope": "global",
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
                if path.is_relative_to(output_dir):
                    result.append(str(canonical_output / path.relative_to(output_dir)))
                else:
                    result.append(raw)
            except Exception:
                result.append(raw)
        return result

    def _remap_generated_files(self, cache: B2SAnalysisCache, item: B2STaskItem) -> list[str]:
        canonical_output = Path(cache.canonical_output_dir).resolve()
        item_output = Path(item.output_dir).resolve()
        result: list[str] = []
        for raw in self._loads(cache.generated_files_json, []):
            try:
                path = Path(str(raw)).resolve()
                if path.is_relative_to(canonical_output):
                    result.append(str(item_output / path.relative_to(canonical_output)))
                else:
                    result.append(str(raw))
            except Exception:
                result.append(str(raw))
        return result

    def _write_manifest(self, canonical_dir: Path, item: B2STaskItem, cache_meta: dict[str, Any], *, replaced: bool) -> None:
        payload = {
            "cache_key": cache_meta.get("cache_key"),
            "scope": "global",
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
