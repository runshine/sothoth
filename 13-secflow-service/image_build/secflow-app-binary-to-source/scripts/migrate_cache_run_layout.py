"""Migrate legacy B2S cache directories from .re_work_* to run/.

Run with:
    python scripts/migrate_cache_run_layout.py
    python scripts/migrate_cache_run_layout.py --cache-key <cache_key>
    python scripts/migrate_cache_run_layout.py --dry-run
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.model import B2SAnalysisCache, get_session_factory
from app.config import get_config
from sqlalchemy.exc import SQLAlchemyError


def _legacy_work_dirs(output_dir: Path) -> list[Path]:
    return sorted(
        [path for path in output_dir.iterdir() if path.is_dir() and path.name.startswith(".re_work_")],
        key=lambda path: path.name,
    ) if output_dir.is_dir() else []


def _cache_dirs_from_root(cache_root: Path) -> list[Path]:
    if not cache_root.is_dir():
        return []
    return sorted(
        [
            path for path in cache_root.iterdir()
            if path.is_dir() and (path / "output").is_dir()
        ],
        key=lambda path: path.name,
    )


def _rewrite_generated_files(raw: str | None, output_dir: Path) -> tuple[str | None, bool]:
    try:
        payload = json.loads(raw) if raw else []
    except Exception:
        return raw, False
    if not isinstance(payload, list):
        return raw, False

    changed = False
    next_payload: list[str] = []
    for entry in payload:
        text = str(entry or "")
        replaced = text
        for legacy_dir in _legacy_work_dirs(output_dir):
            legacy_prefix = str(legacy_dir.resolve())
            run_prefix = str((output_dir / "run").resolve())
            if text.startswith(legacy_prefix):
                replaced = f"{run_prefix}{text[len(legacy_prefix):]}"
                break
        if replaced != text:
            changed = True
        next_payload.append(replaced)
    return (json.dumps(next_payload, ensure_ascii=False) if changed else raw), changed


def _rewrite_manifest(cache_dir: Path, output_dir: Path) -> bool:
    manifest_path = cache_dir / "manifest.json"
    if not manifest_path.is_file():
        return False
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return False
    if not isinstance(payload, dict):
        return False

    changed = False
    legacy_dirs = _legacy_work_dirs(output_dir)
    run_root = (output_dir / "run").resolve()
    for key, value in list(payload.items()):
        if not isinstance(value, str):
            continue
        replaced = value
        for legacy_dir in legacy_dirs:
            legacy_prefix = str(legacy_dir.resolve())
            if value.startswith(legacy_prefix):
                replaced = f"{run_root}{value[len(legacy_prefix):]}"
                break
        if replaced != value:
            payload[key] = replaced
            changed = True
    if changed:
        manifest_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return changed


def _merge_legacy_run_dirs(output_dir: Path, *, dry_run: bool) -> tuple[bool, str | None]:
    legacy_dirs = _legacy_work_dirs(output_dir)
    if not legacy_dirs:
        return False, None

    run_root = output_dir / "run"
    if dry_run:
        return True, f"would migrate {len(legacy_dirs)} legacy dirs into {run_root}"

    run_root.mkdir(parents=True, exist_ok=True)
    for legacy_dir in legacy_dirs:
        for child in legacy_dir.iterdir():
            target = run_root / child.name
            if target.exists():
                if child.is_dir() and target.is_dir():
                    for nested in child.iterdir():
                        nested_target = target / nested.name
                        if nested_target.exists():
                            raise RuntimeError(f"目标已存在，拒绝覆盖: {nested_target}")
                        shutil.move(str(nested), str(nested_target))
                else:
                    raise RuntimeError(f"目标已存在，拒绝覆盖: {target}")
            else:
                shutil.move(str(child), str(target))
        legacy_dir.rmdir()
    return True, None


def main() -> int:
    parser = argparse.ArgumentParser(description="Migrate B2S cache output layout from .re_work_* to run/.")
    parser.add_argument("--cache-key", help="Only migrate a single cache entry.")
    parser.add_argument("--dry-run", action="store_true", help="Only report changes without mutating files.")
    parser.add_argument("--filesystem-only", action="store_true", help="Scan cache.root_dir directly without querying the database.")
    parser.add_argument("--limit", type=int, default=0, help="Only process the first N cache rows.")
    args = parser.parse_args()

    session = None
    scanned = migrated = rewritten_rows = skipped = failed = 0

    try:
        rows: list[B2SAnalysisCache] = []
        used_filesystem_scan = bool(args.filesystem_only)
        if not args.filesystem_only:
            try:
                session = get_session_factory()()
                query = session.query(B2SAnalysisCache).filter(B2SAnalysisCache.status == "ready").order_by(B2SAnalysisCache.created_at.asc())
                if args.cache_key:
                    query = query.filter(B2SAnalysisCache.cache_key == args.cache_key)
                if args.limit and args.limit > 0:
                    query = query.limit(args.limit)
                rows = list(query)
            except SQLAlchemyError as exc:
                used_filesystem_scan = True
                print(f"[warn] 数据库不可达，回退到文件系统扫描: {exc}")
                if session is not None:
                    session.close()
                    session = None

        if used_filesystem_scan:
            cache_root = Path(get_config().cache.root_dir).resolve()
            cache_dirs = _cache_dirs_from_root(cache_root)
            if args.cache_key:
                cache_dirs = [path for path in cache_dirs if path.name == args.cache_key]
            if args.limit and args.limit > 0:
                cache_dirs = cache_dirs[: args.limit]
            for cache_dir in cache_dirs:
                scanned += 1
                try:
                    output_dir = (cache_dir / "output").resolve()
                    layout_changed, message = _merge_legacy_run_dirs(output_dir, dry_run=args.dry_run)
                    manifest_changed = _rewrite_manifest(cache_dir, output_dir) if not args.dry_run else False
                    if not layout_changed and not manifest_changed:
                        skipped += 1
                        print(f"[ok] {cache_dir.name}: already migrated")
                        continue
                    migrated += 1
                    detail = message or "migrated"
                    print(f"[migrated] {cache_dir.name}: {detail}")
                except Exception as exc:
                    failed += 1
                    print(f"[failed] {cache_dir.name}: {exc}")
        else:
            for row in rows:
                scanned += 1
                try:
                    output_dir = Path(str(row.canonical_output_dir or "")).resolve()
                    cache_dir = output_dir.parent
                    if not output_dir.is_dir():
                        skipped += 1
                        print(f"[skip] {row.cache_key}: output dir missing -> {output_dir}")
                        continue

                    layout_changed, message = _merge_legacy_run_dirs(output_dir, dry_run=args.dry_run)
                    generated_files_json, generated_changed = _rewrite_generated_files(row.generated_files_json, output_dir)
                    manifest_changed = _rewrite_manifest(cache_dir, output_dir) if not args.dry_run else False

                    if not layout_changed and not generated_changed and not manifest_changed:
                        skipped += 1
                        print(f"[ok] {row.cache_key}: already migrated")
                        continue

                    if not args.dry_run:
                        if generated_changed:
                            row.generated_files_json = generated_files_json
                            rewritten_rows += 1
                        session.add(row)
                        session.commit()
                    migrated += 1
                    detail = message or "migrated"
                    print(f"[migrated] {row.cache_key}: {detail}")
                except Exception as exc:
                    failed += 1
                    if session is not None:
                        session.rollback()
                    print(f"[failed] {getattr(row, 'cache_key', '-')}: {exc}")

    finally:
        if session is not None:
            session.close()

    print(
        f"scanned={scanned} migrated={migrated} rewritten_rows={rewritten_rows} "
        f"skipped={skipped} failed={failed} dry_run={args.dry_run}"
    )
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
