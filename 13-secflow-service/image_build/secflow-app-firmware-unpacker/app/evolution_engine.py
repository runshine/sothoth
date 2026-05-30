"""Manual firmware evolution job runner."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from app.preprocess import detect_format
from app.subprocess_utils import StreamingLineSink, run_streaming_process
from app.tool_dispatcher import (
    build_versioned_tool_path as _repo_build_versioned_tool_path,
    next_tool_version as _repo_next_tool_version,
    parse_tool_version,
    resolve_active_tool_target,
)
from app.tool_store import compute_family_id, parse_tool_metadata
from app.unpacker_engine_config import (
    DISPATCHER_RULES_PATH,
    DISPATCHER_DIR,
    EVOLUTION_IMPROVER_AGENT_DEF,
    EVOLUTION_IMPROVER_PROMPT_TMPL,
    EVOLUTION_REVIEW_PROMPT_TMPL,
    TOOLS_ACTIVE_DIR,
    TOOLS_DIR,
    TOOLS_ROOT_DIR,
    TOOLS_STORE_DIR,
    VAL_AGENT_DEF,
    load_agent_def,
    render_template,
)
from app.unpacker_engine_logs import (
    append_stage_log as _append_stage_log,
    append_stream_delta as _append_stream_delta,
    get_round_dir as _get_round_dir,
    save_agent_log as _save_agent_log,
    write_json_log as _write_json_log,
)
from app.unpacker_engine_pi import PiRpcClient
from app.unpacker_engine_config import utc_now_iso
from app.unpacker_engine_session import build_session_artifacts, update_session_index


log = logging.getLogger("unpacker.evolution")
DEFAULT_EVOLUTION_MAX_ROUNDS = 3


def _tool_family_slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower())
    return slug.strip("-") or "generic-firmware"


def evolution_job_root(output_path: str, job_id: str) -> Path:
    output_dir = Path(str(output_path or "").strip())
    if output_dir.name != "output":
        raise ValueError(f"invalid unpack output path: {output_path}")
    job_root = output_dir.parent / "run" / "evolution_jobs" / str(job_id).strip()
    job_root.mkdir(parents=True, exist_ok=True)
    return job_root


def evolution_job_workspace_output(job_root: Path) -> Path:
    path = job_root / "workspace" / "output"
    path.mkdir(parents=True, exist_ok=True)
    return path


def evolution_job_sessions_root(job_root: Path) -> Path:
    path = job_root / "sessions"
    path.mkdir(parents=True, exist_ok=True)
    return path


def evolution_round_dir(job_root: Path, round_id: int) -> Path:
    return _get_round_dir(job_root, round_id) or (job_root / f"round_{int(round_id):03d}")


def evolution_working_tool_path(job_root: Path, source_tool_path: str) -> Path:
    working_dir = job_root / "working_tool"
    working_dir.mkdir(parents=True, exist_ok=True)
    source = Path(source_tool_path)
    return working_dir / source.name


def evolution_working_tool_dir(job_root: Path) -> Path:
    path = job_root / "working_tool"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _main_run_dir(output_path: str) -> Path:
    output_dir = Path(str(output_path or "").strip())
    return output_dir.parent / "run"


def _copy_tool_to_working(job_root: Path, source_tool_path: str) -> Path:
    source = Path(source_tool_path)
    if not source.exists():
        raise FileNotFoundError(f"tool not found: {source_tool_path}")
    target = evolution_working_tool_path(job_root, source_tool_path)
    shutil.copy2(source, target)
    return target


def _canonical_family_tool_name(firmware_path: str, source_tool_path: str | None = None) -> str:
    family_id = ""
    if source_tool_path:
        try:
            meta = parse_tool_metadata(Path(source_tool_path))
            family_id = str(meta.get("format_id") or meta.get("name") or "").strip().lower()
        except Exception:
            family_id = ""
    if not family_id:
        info = detect_format(firmware_path)
        family_id = compute_family_id(
            {
                "fmt": info.get("fmt"),
                "ext": info.get("ext"),
                "magic_hex": str((info.get("magic") or b"").hex()),
                "binwalk_sigs": info.get("binwalk_sigs") or [],
            }
        )
    family_id = _tool_family_slug(family_id or "generic-firmware")
    return f"{family_id}.py"


def _normalize_working_tool_name(job_root: Path, firmware_path: str, source_tool_path: str | None = None) -> Path:
    working_dir = evolution_working_tool_dir(job_root)
    if source_tool_path:
        source_name = Path(source_tool_path).name
        preferred_path = working_dir / source_name
        if preferred_path.exists():
            return preferred_path
        existing_tools = sorted(working_dir.glob("*.py"))
        if existing_tools:
            return existing_tools[0]
    canonical_path = working_dir / _canonical_family_tool_name(firmware_path, source_tool_path)
    if canonical_path.exists():
        return canonical_path
    for tool_path in sorted(working_dir.glob("*.py")):
        if tool_path == canonical_path:
            return canonical_path
        shutil.move(str(tool_path), str(canonical_path))
        pycache_dir = working_dir / "__pycache__"
        if pycache_dir.exists():
            shutil.rmtree(pycache_dir, ignore_errors=True)
        return canonical_path
    return canonical_path


def _suggest_initial_working_tool_path(job_root: Path, firmware_path: str) -> Path:
    working_dir = evolution_working_tool_dir(job_root)
    return working_dir / _canonical_family_tool_name(firmware_path, None)


def _write_seed_python_tool(tool_path: Path) -> None:
    if tool_path.exists():
        return
    tool_path.parent.mkdir(parents=True, exist_ok=True)
    tool_path.write_text(
        r'''#!/usr/bin/env python3
# name: huawei-cc-dynamic-unpacker
# format_id: huawei-cc-00000002
# description: Dynamic Huawei .cc firmware unpacker using binwalk/uImage/SquashFS signatures
# extensions: [.cc]
# magic_hex: 00000002
# keywords: [huawei, ne20e, ne, cc, firmware]
# binwalk_sigs: [uimage header, squashfs filesystem, object signature in der format]

import json
import gzip
import lzma
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import time
from pathlib import Path

CHUNK = 8 * 1024 * 1024
UIMAGE_MAGIC = b"\x27\x05\x19\x56"
SQUASHFS_MAGIC = b"hsqs"


def resolve_paths():
    manifest = {}
    manifest_path = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("SECFLOW_TOOL_MANIFEST_PATH", "")
    if manifest_path and Path(manifest_path).is_file():
        manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    input_path = manifest.get("input_path") or os.environ.get("SECFLOW_TOOL_INPUT_PATH")
    output_path = manifest.get("output_path") or os.environ.get("SECFLOW_TOOL_OUTPUT_PATH")
    log_path = (
        manifest.get("log_file_path")
        or manifest.get("log_path")
        or os.environ.get("SECFLOW_TOOL_LOG_FILE_PATH")
        or os.environ.get("SECFLOW_TOOL_LOG_PATH")
    )
    if not input_path or not output_path:
        raise SystemExit("input_path and output_path are required")
    resolved_log_path = Path(log_path) if log_path else None
    if resolved_log_path and (resolved_log_path.exists() and resolved_log_path.is_dir()):
        resolved_log_path = resolved_log_path / "tool.log"
    return Path(input_path), Path(output_path), resolved_log_path


def log(lines, message):
    text = f"[{time.strftime('%Y-%m-%dT%H:%M:%S%z')}] {message}"
    print(text, flush=True)
    lines.append(text)


def run_binwalk(input_path):
    try:
        proc = subprocess.run(["binwalk", str(input_path)], text=True, capture_output=True, timeout=180)
    except Exception:
        return []
    items = []
    for line in proc.stdout.splitlines():
        match = re.match(r"\s*(\d+)\s+0x[0-9A-Fa-f]+\s+(.+)$", line)
        if match:
            items.append((int(match.group(1)), match.group(2).strip()))
    return sorted(set(items))


def read_uimage_size(input_path, offset):
    with input_path.open("rb") as handle:
        handle.seek(offset)
        header = handle.read(64)
    if len(header) < 64 or header[:4] != UIMAGE_MAGIC:
        return None
    return 64 + struct.unpack(">I", header[12:16])[0]


def read_uimage_header(input_path, offset):
    with input_path.open("rb") as handle:
        handle.seek(offset)
        header = handle.read(64)
    if len(header) < 64 or header[:4] != UIMAGE_MAGIC:
        return None
    return {
        "total_size": 64 + struct.unpack(">I", header[12:16])[0],
        "payload_size": struct.unpack(">I", header[12:16])[0],
        "compression": header[31],
        "name": header[32:64].split(b"\x00", 1)[0].decode("utf-8", "ignore") or "uimage",
    }


def read_squashfs_size(input_path, offset):
    with input_path.open("rb") as handle:
        handle.seek(offset)
        header = handle.read(96)
    if len(header) < 48 or header[:4] != SQUASHFS_MAGIC:
        return None
    return struct.unpack("<Q", header[40:48])[0]


def copy_range(input_path, output_path, offset, size):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    remaining = max(0, int(size))
    with input_path.open("rb") as src, output_path.open("wb") as dst:
        src.seek(offset)
        while remaining:
            data = src.read(min(CHUNK, remaining))
            if not data:
                break
            dst.write(data)
            remaining -= len(data)


def range_bytes(input_path, offset, size, limit=96 * 1024 * 1024):
    size = min(max(0, int(size)), limit)
    with input_path.open("rb") as handle:
        handle.seek(offset)
        return handle.read(size)


def desc_size(desc):
    match = re.search(r"\bsize:\s*(\d+)", desc, re.IGNORECASE)
    return int(match.group(1)) if match else None


def next_component_size(entries, offset, file_size, default_limit=96 * 1024 * 1024):
    next_offsets = [item_offset for item_offset, _ in entries if item_offset > offset]
    end = min(next_offsets) if next_offsets else file_size
    return min(max(0, end - offset), default_limit)


def safe_name(value):
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", value).strip("._")[:80] or "artifact"


def write_decompressed(data, output_path, kind):
    try:
        if kind == "gzip":
            decoded = gzip.decompress(data)
        else:
            decoded = lzma.decompress(data)
    except Exception:
        return False
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(decoded)
    return True


def extract_tar_archive(archive_path, output_dir):
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archive_path, "r:*") as archive:
            archive.extractall(output_dir)
        return True
    except Exception:
        return False


def extract_known_nested_archives(root_dir, extracted, logs, limit=80):
    patterns = ["*.tar", "*.tar.gz", "*.tgz", "*.tar.xz", "*.txz", "*.tar.bz2", "*.tbz2"]
    seen = 0
    for pattern in patterns:
        for archive_path in root_dir.rglob(pattern):
            if seen >= limit:
                return
            if not archive_path.is_file() or archive_path.stat().st_size <= 0:
                continue
            target_dir = archive_path.parent / (archive_path.name + ".extracted")
            if extract_tar_archive(archive_path, target_dir):
                extracted.append(str(target_dir))
                log(logs, f"extracted nested tar archive path={archive_path} output={target_dir}")
            seen += 1


def extract_squashfs(raw_path, output_dir):
    if not shutil.which("unsquashfs"):
        return False, "unsquashfs not found"
    root = output_dir / "root"
    proc = subprocess.run(
        ["unsquashfs", "-no-xattrs", "-d", str(root), str(raw_path)],
        text=True,
        capture_output=True,
        timeout=900,
    )
    return proc.returncode == 0, (proc.stdout + proc.stderr)[-2000:]


def main():
    started = time.monotonic()
    input_path, output_path, log_path = resolve_paths()
    output_path.mkdir(parents=True, exist_ok=True)
    logs = []
    with input_path.open("rb") as handle:
        if handle.read(4) != b"\x00\x00\x00\x02":
            raise SystemExit("unsupported firmware magic")
    file_size = input_path.stat().st_size
    log(logs, f"input={input_path} size={file_size}")
    entries = run_binwalk(input_path)
    uimages = [(o, d) for o, d in entries if "uImage header" in d]
    squashfs = [(o, d) for o, d in entries if "Squashfs filesystem" in d]
    certs = [(o, d) for o, d in entries if "certificate" in d.lower() or "object signature" in d.lower()]
    extracted = []

    for idx, (offset, desc) in enumerate(uimages, 1):
        header = read_uimage_header(input_path, offset)
        if not header or offset + header["total_size"] > file_size:
            continue
        name = "kernel" if idx == 1 else f"uimage_{idx}"
        target = output_path / "boot" / f"{name}.uImage"
        copy_range(input_path, target, offset, header["total_size"])
        extracted.append(str(target))
        payload_raw = output_path / "boot" / f"{name}.payload.bin"
        copy_range(input_path, payload_raw, offset + 64, header["payload_size"])
        extracted.append(str(payload_raw))
        payload = range_bytes(input_path, offset + 64, header["payload_size"])
        if header["compression"] == 1 or payload.startswith(b"\x1f\x8b"):
            decoded = output_path / "boot" / f"{name}.payload.gunzip"
            if write_decompressed(payload, decoded, "gzip"):
                extracted.append(str(decoded))
        elif header["compression"] == 2 or payload.startswith(b"\x5d\x00") or payload.startswith(b"\x5d\x00\x00"):
            decoded = output_path / "boot" / f"{name}.payload.unlzma"
            if write_decompressed(payload, decoded, "lzma"):
                extracted.append(str(decoded))
                if extract_tar_archive(decoded, decoded.parent / (decoded.name + ".extracted")):
                    extracted.append(str(decoded.parent / (decoded.name + ".extracted")))
        log(logs, f"extracted uImage offset={offset} size={header['total_size']} payload={header['payload_size']} comp={header['compression']} path={target}")

    for idx, (offset, desc) in enumerate(squashfs, 1):
        size = read_squashfs_size(input_path, offset)
        if not size or offset + size > file_size:
            next_offsets = [o for o, _ in entries if o > offset]
            size = (min(next_offsets) if next_offsets else file_size) - offset
        target_dir = output_path / f"squashfs_{idx}"
        raw = target_dir / f"squashfs_{idx}.sqfs"
        copy_range(input_path, raw, offset, size)
        ok, message = extract_squashfs(raw, target_dir)
        extracted.append(str(raw))
        if ok:
            extract_known_nested_archives(target_dir / "root", extracted, logs)
        log(logs, f"extracted squashfs offset={offset} size={size} raw={raw} unsquashfs={ok} {message[:300]}")

    cert_dir = output_path / "certificates"
    for idx, (offset, desc) in enumerate(certs[:64], 1):
        size = 4096
        target = cert_dir / f"cert_or_signature_{idx:03d}_{offset:x}.bin"
        copy_range(input_path, target, offset, min(size, file_size - offset))
        extracted.append(str(target))

    misc_specs = [
        ("Flattened device tree", "dtb", "dtb"),
        ("gzip compressed data", "gzip", "gz"),
        ("LZMA compressed data", "lzma", "lzma"),
        ("7-zip archive data", "archives", "7z"),
        ("XML document", "xml", "xml"),
        ("Adobe Flash SWF", "swf", "swf"),
        ("Broadcom header", "broadcom", "bin"),
    ]
    for idx, (offset, desc) in enumerate(entries, 1):
        desc_lower = desc.lower()
        for marker, subdir, ext in misc_specs:
            if marker.lower() not in desc_lower:
                continue
            size = desc_size(desc) or next_component_size(entries, offset, file_size)
            target = output_path / "artifacts" / subdir / f"{idx:03d}_{offset:x}_{safe_name(marker)}.{ext}"
            copy_range(input_path, target, offset, min(size, file_size - offset))
            extracted.append(str(target))
            if subdir in {"gzip", "lzma"}:
                data = range_bytes(input_path, offset, size)
                decoded = target.with_suffix(target.suffix + ".decoded")
                if write_decompressed(data, decoded, subdir):
                    extracted.append(str(decoded))
                    if extract_tar_archive(decoded, decoded.parent / (decoded.name + ".extracted")):
                        extracted.append(str(decoded.parent / (decoded.name + ".extracted")))
            if subdir == "archives" and shutil.which("7z"):
                out_dir = target.parent / (target.stem + "_extracted")
                out_dir.mkdir(parents=True, exist_ok=True)
                subprocess.run(["7z", "x", "-y", f"-o{out_dir}", str(target)], text=True, capture_output=True, timeout=180)
            break

    elapsed = time.monotonic() - started
    summary = [
        "# Firmware Tool Extraction Summary",
        "",
        f"- tool: {Path(__file__).resolve()}",
        f"- input: {input_path}",
        f"- elapsed_seconds: {elapsed:.2f}",
        f"- binwalk_entries: {len(entries)}",
        f"- uimage_count: {len(uimages)}",
        f"- squashfs_count: {len(squashfs)}",
        f"- cert_or_signature_count: {len(certs)}",
        "",
        "## Extracted Artifacts",
        *[f"- {item}" for item in extracted],
    ]
    text = "\n".join(summary) + "\n"
    (output_path / "summary.md").write_text(text, encoding="utf-8")
    (output_path / "summary.txt").write_text(text, encoding="utf-8")
    if log_path:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("\n".join(logs) + "\n", encoding="utf-8")
    if not uimages or not squashfs:
        raise SystemExit("required uImage or SquashFS components were not discovered")


if __name__ == "__main__":
    main()
''',
        encoding="utf-8",
    )


def _reset_workspace_output(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)


def _extract_path_only(text: str) -> Path | None:
    raw = str(text or "").strip().splitlines()
    for line in reversed(raw):
        value = line.strip().strip("`")
        if value.endswith(".py") and value.startswith("/"):
            return Path(value)
    return None


def _coerce_job_sandbox_tool_path(path: Path, job_root: Path) -> Path:
    raw = str(path or "").strip()
    if not raw:
        raise RuntimeError("工具进化器未返回有效的 Python 工具路径")
    marker = "/data/files/"
    if marker in raw and not raw.startswith(marker):
        raw = raw[raw.index(marker):]
    candidate = Path(raw).resolve()
    resolved_job_root = job_root.resolve()
    try:
        candidate.relative_to(resolved_job_root)
    except ValueError as exc:
        raise RuntimeError(f"工具进化器返回了 job 沙箱外的非法路径: {candidate}") from exc
    if candidate.suffix.lower() != ".py":
        raise RuntimeError(f"工具进化器返回了非法路径: {candidate}")
    if not candidate.exists():
        raise RuntimeError(f"工具进化器返回的工具文件不存在: {candidate}")
    return candidate


def _recover_tool_from_executor_messages(round_dir: Path, candidate: Path) -> bool:
    messages_path = round_dir / "evolution_executor_messages.json"
    if not messages_path.exists():
        return False
    try:
        payload = json.loads(messages_path.read_text(encoding="utf-8"))
    except Exception:
        return False
    if not isinstance(payload, list):
        return False

    basename = candidate.name
    candidate_text: str | None = None
    for item in reversed(payload):
        if not isinstance(item, dict) or item.get("role") != "assistant":
            continue
        content = item.get("content") or []
        if not isinstance(content, list):
            continue
        for block in reversed(content):
            if not isinstance(block, dict) or block.get("type") != "toolCall":
                continue
            if str(block.get("name") or "").strip() != "write":
                continue
            arguments = block.get("arguments") or {}
            if not isinstance(arguments, dict):
                continue
            path = str(arguments.get("path") or "").strip()
            if not path.endswith(".py"):
                continue
            if path != str(candidate) and Path(path).name != basename:
                continue
            content_text = arguments.get("content")
            if isinstance(content_text, str) and content_text.strip():
                candidate_text = content_text
                break
        if candidate_text:
            break

    if not candidate_text:
        return False
    candidate.parent.mkdir(parents=True, exist_ok=True)
    candidate.write_text(candidate_text, encoding="utf-8")
    return True


def _normalize_tool_into_working_dir(
    *,
    candidate: Path,
    working_dir: Path,
    firmware_path: str,
    source_tool: Path | None,
    round_dir: Path,
) -> Path:
    if not candidate.exists():
        _recover_tool_from_executor_messages(round_dir, candidate)
    if not candidate.exists():
        raise RuntimeError(f"工具进化器返回的工具文件不存在: {candidate}")
    canonical_path = _normalize_working_tool_name(
        working_dir.parent,
        firmware_path,
        str(source_tool) if source_tool is not None else None,
    )
    if candidate.resolve() == canonical_path.resolve():
        return canonical_path
    shutil.copy2(candidate, canonical_path)
    pycache_dir = working_dir / "__pycache__"
    if pycache_dir.exists():
        shutil.rmtree(pycache_dir, ignore_errors=True)
    return canonical_path


def _validate_working_tool_path(path: Path, working_dir: Path) -> Path:
    resolved = path.resolve()
    resolved_working_dir = working_dir.resolve()
    try:
        resolved.relative_to(resolved_working_dir)
    except ValueError as exc:
        raise RuntimeError(f"工具进化器返回了非法路径: {resolved}") from exc
    if resolved.suffix.lower() != ".py":
        raise RuntimeError(f"工具进化器返回了非法路径: {resolved}")
    if not resolved.exists():
        raise RuntimeError(f"工具进化器返回的工具文件不存在: {resolved}")
    source = resolved.read_text(encoding="utf-8")
    if not source.strip():
        raise RuntimeError(f"工具进化器返回的工具文件为空: {resolved}")
    try:
        compile(source, str(resolved), "exec")
    except SyntaxError as exc:
        raise RuntimeError(f"工具进化器生成的 Python 脚本语法错误: {resolved}: {exc}") from exc
    return resolved


def _derive_family_id(firmware_path: str, final_tool_path: Path) -> str:
    try:
        meta = parse_tool_metadata(final_tool_path)
        family_id = str(meta.get("format_id") or meta.get("name") or "").strip().lower()
        if family_id:
            return _tool_family_slug(family_id)
    except Exception:
        pass
    info = detect_format(firmware_path)
    return compute_family_id(
        {
            "fmt": info.get("fmt"),
            "ext": info.get("ext"),
            "magic_hex": str((info.get("magic") or b"").hex()),
            "binwalk_sigs": info.get("binwalk_sigs") or [],
        }
    ) or "generic-firmware"


def _next_generated_tool_version(tools_dir: Path, family_id: str) -> int:
    return _repo_next_tool_version(tools_dir, family_id)


def _build_versioned_tool_path(directory: Path, family_id: str, version: int, *, suffix: str | None = None) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    if directory == TOOLS_STORE_DIR or directory.parent == TOOLS_STORE_DIR:
        return _repo_build_versioned_tool_path(TOOLS_STORE_DIR, family_id, version, timestamp)
    family_id = _tool_family_slug(family_id)
    return directory / f"{family_id}-v{int(version)}-{timestamp}.py"


def _rename_working_tool_if_changed(
    *,
    firmware_path: str,
    working_tool: Path,
    source_tool: Path | None,
    tool_changed: bool,
) -> Path:
    if not tool_changed:
        return working_tool
    family_id = _derive_family_id(firmware_path, working_tool)
    version = _next_generated_tool_version(TOOLS_STORE_DIR, family_id)
    renamed_path = _build_versioned_tool_path(
        working_tool.parent,
        family_id,
        version,
        suffix="evolved",
    )
    if renamed_path.resolve() == working_tool.resolve():
        return working_tool
    shutil.move(str(working_tool), str(renamed_path))
    pycache_dir = renamed_path.parent / "__pycache__"
    if pycache_dir.exists():
        shutil.rmtree(pycache_dir, ignore_errors=True)
    return renamed_path


def _save_generated_tool_to_repo(
    *,
    firmware_path: str,
    working_tool: Path,
    source_tool: Path | None,
) -> tuple[str, str | None, bool]:
    _validate_working_tool_path(working_tool, working_tool.parent)
    family_id = _derive_family_id(firmware_path, working_tool)
    version = _next_generated_tool_version(TOOLS_STORE_DIR, family_id)
    target = _build_versioned_tool_path(TOOLS_STORE_DIR, family_id, version)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(working_tool, target)
    previous = str(resolve_active_tool_target(source_tool)) if source_tool is not None else None
    return str(target), previous, source_tool is None


def _save_generated_tool_to_run(
    *,
    job_root: Path,
    firmware_path: str,
    working_tool: Path,
    source_tool: Path | None,
) -> tuple[str, str | None, bool]:
    _validate_working_tool_path(working_tool, working_tool.parent)
    family_id = _derive_family_id(firmware_path, working_tool)
    version = _next_generated_tool_version(TOOLS_STORE_DIR, family_id)
    generated_dir = job_root / "generated_tools"
    generated_dir.mkdir(parents=True, exist_ok=True)
    target = _build_versioned_tool_path(generated_dir, family_id, version, suffix="generated")
    shutil.copy2(working_tool, target)
    if source_tool is not None and source_tool.resolve() == working_tool.resolve():
        shutil.copy2(working_tool, source_tool)
        return str(target), str(source_tool), False
    if source_tool is not None:
        return str(target), str(source_tool), True
    return str(target), None, True


def _publish_tool_to_store(
    *,
    firmware_path: str,
    working_tool: Path,
    source_tool: Path | None,
    tool_changed: bool,
) -> str:
    _validate_working_tool_path(working_tool, working_tool.parent)
    source_target: Path | None = None
    if source_tool is not None:
        source_target = resolve_active_tool_target(source_tool)
        try:
            if source_target.exists() and working_tool.exists() and source_target.samefile(working_tool) and not tool_changed:
                return str(source_target)
        except Exception:
            pass
    family_id = _derive_family_id(firmware_path, working_tool)
    version = _next_generated_tool_version(TOOLS_STORE_DIR, family_id)
    target = _build_versioned_tool_path(TOOLS_STORE_DIR, family_id, version)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(working_tool, target)
    return str(target)


def _review_passed(review_result: str) -> bool:
    lowered = str(review_result or "").strip().lower()
    return '"result":"success"' in lowered or '"result": "success"' in lowered


def _sync_report_aliases(output_dir: Path) -> None:
    aliases = {
        "summary.md": "summary.txt",
        "reason.md": "reason.txt",
    }
    for canonical_name, alias_name in aliases.items():
        canonical_path = output_dir / canonical_name
        alias_path = output_dir / alias_name
        if canonical_path.exists():
            alias_path.write_text(canonical_path.read_text(encoding="utf-8"), encoding="utf-8")
        elif alias_path.exists():
            canonical_path.write_text(alias_path.read_text(encoding="utf-8"), encoding="utf-8")


def _snapshot_round_report(round_dir: Path, source_path: Path, target_name: str) -> str | None:
    if not source_path.exists() or not source_path.is_file():
        return None
    target = round_dir / target_name
    try:
        shutil.copy2(source_path, target)
    except Exception:
        return str(source_path)
    return str(target)


def _read_small_text(path: Path | None, limit: int = 4000) -> str:
    if path is None or not path.exists() or not path.is_file():
        return ""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...[truncated]..."


def _write_round_context(
    *,
    round_dir: Path,
    main_run_dir: Path,
    job_root: Path,
    firmware_path: str,
    workspace_output: Path,
    working_tool: Path,
    source_tool: Path | None,
    started_without_matched_skill: bool,
    previous_feedback_path: Path | None,
    previous_summary_path: Path | None,
    previous_reason_path: Path | None,
    current_feedback_path: Path | None = None,
    current_summary_path: Path | None = None,
    current_reason_path: Path | None = None,
) -> Path:
    main_sessions_index = main_run_dir / "sessions" / "index.json"
    evolution_sessions_index = job_root / "sessions" / "index.json"
    previous_feedback = _read_execution_feedback(previous_feedback_path)
    lines = [
        "# Evolution Round Context",
        "",
        f"- firmware_path: `{firmware_path}`",
        f"- workspace_output: `{workspace_output}`",
        f"- working_tool: `{working_tool}`",
        f"- source_tool: `{source_tool}`" if source_tool is not None else "- source_tool: <none>",
        f"- started_without_matched_skill: `{started_without_matched_skill}`",
        f"- main_sessions_index: `{main_sessions_index}`",
        f"- evolution_sessions_index: `{evolution_sessions_index}`",
        "",
        "## Reading Budget",
        "",
        "- Do not read full session transcripts by default.",
        "- Prefer this file, the previous feedback file, the previous/current summary and reason files, and the current working tool.",
        "- Only if those are insufficient, read `sessions/index.json` first and then open one targeted session file.",
        "",
        "## Previous Round Feedback",
        "",
    ]
    if previous_feedback_path is not None:
        lines.extend(
            [
                f"- feedback_path: `{previous_feedback_path}`",
                f"- return_code: `{previous_feedback.get('return_code', '-')}`",
                f"- duration_seconds: `{previous_feedback.get('duration_seconds', '-')}`",
                f"- log_path: `{previous_feedback.get('log_path') or '-'}`",
                "",
                "### previous stdout preview",
                "",
                "```text",
                str(previous_feedback.get("stdout_preview") or "").strip()[:2000],
                "```",
            ]
        )
    else:
        lines.append("- No previous feedback file.")

    def _append_text_block(title: str, path: Path | None) -> None:
        lines.extend(["", f"## {title}", ""])
        if path is None or not path.exists():
            lines.append("- missing")
            return
        lines.append(f"- path: `{path}`")
        body = _read_small_text(path)
        if body:
            lines.extend(["```text", body, "```"])

    _append_text_block("Previous Summary", previous_summary_path)
    _append_text_block("Previous Reason", previous_reason_path)
    _append_text_block("Current Summary", current_summary_path)
    _append_text_block("Current Reason", current_reason_path)

    if current_feedback_path is not None and current_feedback_path.exists():
        current_feedback = _read_execution_feedback(current_feedback_path)
        lines.extend(
            [
                "",
                "## Current Tool Execution Feedback",
                "",
                f"- feedback_path: `{current_feedback_path}`",
                f"- return_code: `{current_feedback.get('return_code', '-')}`",
                f"- duration_seconds: `{current_feedback.get('duration_seconds', '-')}`",
                f"- log_path: `{current_feedback.get('log_path') or '-'}`",
                "",
                "```text",
                str(current_feedback.get("stdout_preview") or "").strip()[:2000],
                "```",
            ]
        )

    target = round_dir / "round_context.md"
    target.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
    return target


def _write_tool_execution_failure(output_dir: Path, error: str) -> str:
    text = "\n".join(
        [
            "# Tool Execution Review: FAIL",
            "",
            "当前工具执行失败，下一轮必须先修复工具后再执行。",
            "",
            "## Blocking Issue",
            "",
            f"- {error}",
            "",
            "## Required Fixes",
            "",
            "- 保持 manifest/env 运行接口不变。",
            "- 修复异常后仍需保证工具面向格式族通用，不允许写死单个任务路径、固件文件名、版本号或大段固定 offset 表。",
        ]
    ).strip() + "\n"
    (output_dir / "reason.md").write_text(text, encoding="utf-8")
    (output_dir / "reason.txt").write_text(text, encoding="utf-8")
    return json.dumps({"result": "fail", "reason": str(output_dir / "reason.txt")}, ensure_ascii=False)


def _write_execution_feedback(round_dir: Path, payload: dict[str, Any]) -> Path:
    feedback_path = round_dir / "backend_execution_feedback.json"
    feedback_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return feedback_path


def _read_execution_feedback(feedback_path: Path | None) -> dict[str, Any]:
    if feedback_path is None or not feedback_path.exists():
        return {}
    try:
        payload = json.loads(feedback_path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _run_working_tool(
    *,
    firmware_path: str,
    workspace_output: Path,
    job_root: Path,
    round_dir: Path,
    working_tool: Path,
) -> dict[str, Any]:
    manifest_path = job_root / "tool_manifest.json"
    log_path = workspace_output / "tool.log"
    manifest_path.write_text(
        json.dumps(
            {
                "input_path": firmware_path,
                "output_path": str(workspace_output),
                "run_path": str(job_root),
                "log_path": str(log_path),
                "log_file_path": str(log_path),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["SECFLOW_TOOL_INPUT_PATH"] = firmware_path
    env["SECFLOW_TOOL_OUTPUT_PATH"] = str(workspace_output)
    env["SECFLOW_TOOL_RUN_PATH"] = str(job_root)
    env["SECFLOW_TOOL_LOG_PATH"] = str(log_path)
    env["SECFLOW_TOOL_LOG_FILE_PATH"] = str(log_path)
    env["SECFLOW_TOOL_MANIFEST_PATH"] = str(manifest_path)

    _append_stage_log(
        round_dir,
        "evolution_executor.log",
        "starting backend python tool execution",
        tool=str(working_tool),
        manifest_path=str(manifest_path),
        workspace_output=str(workspace_output),
    )
    lines: list[str] = []
    timeout_seconds = 1800
    started_at = time.monotonic()
    line_sink = StreamingLineSink(
        lambda text: (
            lines.append(text),
            _append_stage_log(round_dir, "evolution_executor.log", text),
        )
    )
    try:
        result = run_streaming_process(
            [sys.executable, str(working_tool), str(manifest_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            text=True,
            stdout_callback=line_sink.feed,
            timeout_seconds=timeout_seconds,
        )
        line_sink.flush()
        return_code = result.returncode
    finally:
        line_sink.flush()
    duration_seconds = max(0.0, time.monotonic() - started_at)
    response = "\n".join(lines).strip()
    _append_stage_log(
        round_dir,
        "evolution_executor.log",
        "backend python tool execution completed",
        return_code=return_code,
        duration_seconds=round(duration_seconds, 3),
        response_preview=response[:1000],
    )
    payload = {
        "tool_path": str(working_tool),
        "manifest_path": str(manifest_path),
        "log_path": str(log_path),
        "return_code": int(return_code),
        "duration_seconds": round(duration_seconds, 3),
        "stdout_preview": response[:4000],
        "summary_path": str(workspace_output / "summary.md") if (workspace_output / "summary.md").exists() else None,
        "reason_path": str(workspace_output / "reason.md") if (workspace_output / "reason.md").exists() else None,
    }
    _write_execution_feedback(round_dir, payload)
    if return_code != 0:
        raise RuntimeError(f"工具执行失败: return_code={return_code}; output={response[:1000]}")
    return payload


def _load_token_stats(round_dir: Path, agent_name: str) -> dict[str, Any]:
    token_path = round_dir / f"{agent_name}_tokens.json"
    if not token_path.exists():
        return {}
    try:
        payload = json.loads(token_path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _augment_tool_summary(
    *,
    output_dir: Path,
    elapsed_seconds: float,
    token_stats: dict[str, Any],
) -> None:
    summary_md = output_dir / "summary.md"
    summary_txt = output_dir / "summary.txt"
    base_text = ""
    if summary_md.exists():
        base_text = summary_md.read_text(encoding="utf-8")
    elif summary_txt.exists():
        base_text = summary_txt.read_text(encoding="utf-8")
    base_text = base_text.rstrip()

    metrics_lines = [
        "",
        "## Evolution Metrics",
        f"- elapsed_seconds: {max(0.0, float(elapsed_seconds)):.2f}",
        f"- token_input: {int(token_stats.get('input') or 0)}",
        f"- token_output: {int(token_stats.get('output') or 0)}",
        f"- token_cache_read: {int(token_stats.get('cacheRead') or 0)}",
        f"- token_cache_write: {int(token_stats.get('cacheWrite') or 0)}",
        f"- token_total: {int(token_stats.get('total') or 0)}",
    ]
    merged = (base_text + "\n" + "\n".join(metrics_lines)).strip() + "\n"
    summary_md.write_text(merged, encoding="utf-8")
    summary_txt.write_text(merged, encoding="utf-8")


def _normalize_token_stats(token_stats: dict[str, Any] | None) -> dict[str, int]:
    payload = token_stats if isinstance(token_stats, dict) else {}
    return {
        "input": int(payload.get("input") or 0),
        "output": int(payload.get("output") or 0),
        "cacheRead": int(payload.get("cacheRead") or 0),
        "cacheWrite": int(payload.get("cacheWrite") or 0),
        "total": int(payload.get("total") or 0),
    }


def _build_evolution_round_metrics(
    *,
    tool_elapsed_seconds: float,
    evolution_executor_tokens: dict[str, Any] | None,
    reviewer_tokens: dict[str, Any] | None = None,
) -> dict[str, Any]:
    executor_tokens = _normalize_token_stats(evolution_executor_tokens)
    review_tokens = _normalize_token_stats(reviewer_tokens)
    total_tokens = {
        key: int(executor_tokens.get(key, 0)) + int(review_tokens.get(key, 0))
        for key in ("input", "output", "cacheRead", "cacheWrite", "total")
    }
    return {
        "tool_unpack_duration_seconds": round(max(0.0, float(tool_elapsed_seconds or 0.0)), 3),
        "evolution_executor_tokens": executor_tokens,
        "reviewer_tokens": review_tokens,
        "total_tokens": total_tokens,
    }


def _build_evolution_generate_prompt(
    *,
    firmware_path: str,
    workspace_output: Path,
    working_tool: Path,
    previous_feedback_path: Path | None,
) -> str:
    previous_feedback = _read_execution_feedback(previous_feedback_path)
    previous_feedback_text = ""
    if previous_feedback_path is not None:
        previous_feedback_text = "\n".join(
            [
                "",
                f"上一轮后端工具执行反馈文件：`{previous_feedback_path}`。",
                f"上一轮工具执行耗时：`{previous_feedback.get('duration_seconds', '-')}` 秒。",
                f"上一轮工具退出码：`{previous_feedback.get('return_code', '-')}`。",
                f"上一轮工具日志：`{previous_feedback.get('log_path') or '-'}`。",
                f"上一轮 summary：`{previous_feedback.get('summary_path') or '-'}`。",
                f"上一轮 reason：`{previous_feedback.get('reason_path') or '-'}`。",
                "你必须基于这份后端执行反馈以及对应 summary/reason 来决定如何继续改进工具。",
            ]
        )
    return "\n".join(
        [
            "当前没有命中可用的 Python 解包工具。",
            "本轮必须先生成首个正式可执行的 Python 解包工具，后端随后会统一执行该工具。",
            f"目标固件：`{firmware_path}`。",
            f"输出目录：`{workspace_output}`。",
            f"建议工具路径：`{working_tool}`。",
            "",
            "要求：",
            "1. 不要生成占位 stub，不要输出只包含 NotImplementedError 的脚本。",
            "2. 必须直接生成一个可执行的正式 Python 解包工具，而不是只修文案或只写元数据。",
            "3. 只允许在当前 evolution job 的 `working_tool/` 目录内创建或修改工具文件。",
            "4. 不要在本轮手工执行解包命令；新的识别、切分、提取、清理逻辑必须沉淀进工具。",
            "5. 工具自身在被执行时必须写出 `summary.txt`，并同步更新 `summary.md`。内容至少包含使用的工具路径、关键步骤、主要产物、剩余问题、本轮耗时。",
            "6. 最终回复只能输出本轮生成或更新后的 Python 工具绝对路径。",
        ]
    ) + previous_feedback_text


def _build_evolution_improve_existing_tool_prompt(
    *,
    firmware_path: str,
    workspace_output: Path,
    working_tool: Path,
    previous_feedback_path: Path | None,
) -> str:
    previous_feedback = _read_execution_feedback(previous_feedback_path)
    previous_feedback_text = ""
    if previous_feedback_path is not None:
        previous_feedback_text = "\n".join(
            [
                "",
                f"上一轮后端工具执行反馈文件：`{previous_feedback_path}`。",
                f"上一轮工具执行耗时：`{previous_feedback.get('duration_seconds', '-')}` 秒。",
                f"上一轮工具退出码：`{previous_feedback.get('return_code', '-')}`。",
                f"上一轮工具日志：`{previous_feedback.get('log_path') or '-'}`。",
                f"上一轮 summary：`{previous_feedback.get('summary_path') or '-'}`。",
                f"上一轮 reason：`{previous_feedback.get('reason_path') or '-'}`。",
                "你必须基于这份后端执行反馈以及对应 summary/reason 来决定如何继续改进工具。",
            ]
        )
    return "\n".join(
        [
            "当前已经命中可用的 Python 解包工具。",
            "本轮不要从零重新发明新工具，应优先检查、修复并完善当前 working tool；工具执行由后端统一完成。",
            f"目标固件：`{firmware_path}`。",
            f"输出目录：`{workspace_output}`。",
            f"当前 working tool：`{working_tool}`。",
            "",
            "要求：",
            "1. 如发现工具存在问题，可以直接修改该 working tool；只有在确有必要时才新建替代工具。",
            "2. 不允许在工具之外手工解包；新的识别、切分、提取、清理逻辑必须沉淀进工具。",
            "3. 目标是完善现有格式族工具，而不是仅针对当前样本做 case by case 修补。",
            "4. 工具自身在被执行时必须写出 `summary.txt`，并同步更新 `summary.md`。内容至少包含：",
            "   - 本轮使用的工具路径",
            "   - 关键执行步骤",
            "   - 主要输出产物",
            "   - 剩余问题或可疑缺口",
            "   - 本轮耗时和 token 数量（若无法精确得出，也要预留该字段）",
            "5. 最终回复只能输出本轮使用或更新后的 Python 工具绝对路径。",
        ]
    ) + previous_feedback_text


def _build_evolution_execute_prompt(
    *,
    round_id: int,
    firmware_path: str,
    workspace_output: Path,
    working_tool: Path,
    started_without_matched_skill: bool,
    previous_feedback_path: Path | None,
) -> str:
    if int(round_id) <= 1 and started_without_matched_skill:
        return _build_evolution_generate_prompt(
            firmware_path=firmware_path,
            workspace_output=workspace_output,
            working_tool=working_tool,
            previous_feedback_path=previous_feedback_path,
        )
    if int(round_id) <= 1:
        return _build_evolution_improve_existing_tool_prompt(
            firmware_path=firmware_path,
            workspace_output=workspace_output,
            working_tool=working_tool,
            previous_feedback_path=previous_feedback_path,
        )
    previous_feedback = _read_execution_feedback(previous_feedback_path)
    previous_feedback_text = ""
    if previous_feedback_path is not None:
        previous_feedback_text = "\n".join(
            [
                "",
                f"上一轮后端工具执行反馈文件：`{previous_feedback_path}`。",
                f"上一轮工具执行耗时：`{previous_feedback.get('duration_seconds', '-')}` 秒。",
                f"上一轮工具退出码：`{previous_feedback.get('return_code', '-')}`。",
                f"上一轮工具日志：`{previous_feedback.get('log_path') or '-'}`。",
                f"上一轮 summary：`{previous_feedback.get('summary_path') or '-'}`。",
                f"上一轮 reason：`{previous_feedback.get('reason_path') or '-'}`。",
                "你必须结合这份后端执行反馈以及 reason.txt / reason.md 一起修复工具，而不是盲改。",
            ]
        )
    return "\n".join(
        [
            "上一轮评审未通过，请先阅读当前输出目录下的 `reason.txt` 和 `reason.md`。",
            f"然后完善当前工具：`{working_tool}`。工具执行由后端统一完成，输出目录为 `{workspace_output}`。",
            "",
            "要求：",
            "1. 必须先根据 reason 中的问题修改或替换当前 working tool。",
            "2. 不要执行工具或额外手工解包；所有新逻辑必须沉淀进工具。",
            "3. 工具自身在被执行时必须写出更新后的 `summary.txt`，并同步更新 `summary.md`。内容至少包含：",
            "   - 当前工具路径",
            "   - 本轮修复了哪些问题",
            "   - 仍然存在的问题",
            "   - 本轮耗时和 token 数量（若无法精确得出，也要预留该字段）",
            "4. 最终回复只能输出本轮更新后的 Python 工具绝对路径。",
        ]
    ) + previous_feedback_text


def _create_client(
    *,
    agent_def_path: str,
    provider_role: str,
    session_role: str,
    session_name: str,
    session_phase: str,
    session_round: int | None,
    task_id: str,
    llm_binding_snapshot: dict[str, Any] | None,
    session_root: Path,
) -> PiRpcClient:
    agent_def = load_agent_def(agent_def_path)
    session_artifacts = build_session_artifacts(
        session_root,
        role=session_role,
        name=session_name,
        provider_role=provider_role,
        phase=session_phase,
        round_id=session_round,
    )
    return PiRpcClient(
        system_prompt_file=agent_def_path,
        model=agent_def.get("model"),
        tools=agent_def.get("tools"),
        provider_role=provider_role,
        llm_binding_snapshot=llm_binding_snapshot,
        session_dir=session_artifacts["session_dir"],
        session_path=session_artifacts["session_path"],
        session_role=session_artifacts["session_role"],
        session_name=session_artifacts["session_name"],
        session_phase=session_artifacts["phase"],
        session_round=session_artifacts["round"],
        session_skill_name=session_artifacts["skill_name"],
        task_id=task_id,
    )


def _write_backend_reviewer_session(
    *,
    job_root: Path,
    round_id: int,
    review_result: str,
    summary_path: Path | None,
    reason_path: Path | None,
    detail: str,
    title: str = "后端评审结论：未通过",
) -> None:
    session_artifacts = build_session_artifacts(
        job_root,
        role="reviewer",
        name=f"round-{round_id}",
        provider_role="backend_reviewer",
        phase="review",
        round_id=round_id,
    )
    session_path = session_artifacts["session_path"]
    now = utc_now_iso()
    payload = {
        "type": "message",
        "id": f"backend-reviewer-round-{round_id}",
        "timestamp": now,
        "message": {
            "role": "assistant",
            "content": [
                {
                    "type": "text",
                    "text": "\n".join(
                        [
                            title,
                            "",
                            detail,
                            "",
                            f"review_result: {review_result}",
                            f"summary_path: {summary_path if summary_path and summary_path.exists() else '-'}",
                            f"reason_path: {reason_path if reason_path and reason_path.exists() else '-'}",
                        ]
                    ),
                }
            ],
        },
    }
    if not session_path.exists() or session_path.stat().st_size == 0:
        session_path.write_text(
            json.dumps(
                {
                    "type": "session",
                    "version": 1,
                    "id": f"backend-reviewer-{round_id}",
                    "timestamp": now,
                    "cwd": str(job_root),
                },
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )
    with session_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
    update_session_index(
        session_artifacts["session_dir"],
        role=session_artifacts["session_role"],
        name=session_artifacts["session_name"],
        session_file=session_path.name,
        provider_role=session_artifacts["provider_role"],
        phase=session_artifacts["phase"],
        status="closed",
        round_id=session_artifacts["round"],
        skill_name=session_artifacts["skill_name"],
    )


def run_evolution_job(
    *,
    task_id: str,
    evolution_job_id: str,
    firmware_path: str,
    unpack_output_path: str,
    active_skill_path: str,
    llm_binding_snapshot: dict[str, Any] | None = None,
    max_rounds: int = DEFAULT_EVOLUTION_MAX_ROUNDS,
    progress_callback: Optional[Callable[[int, str], None]] = None,
) -> dict[str, Any]:
    job_root = evolution_job_root(unpack_output_path, evolution_job_id)
    session_root = evolution_job_sessions_root(job_root)
    workspace_output = evolution_job_workspace_output(job_root)
    working_dir = evolution_working_tool_dir(job_root)
    source_tool_text = str(active_skill_path or "").strip()
    source_tool = Path(source_tool_text) if source_tool_text else None
    started_without_matched_skill = source_tool is None
    if source_tool is not None and not source_tool.exists():
        source_tool = None
        started_without_matched_skill = True
    initial_working_tool = (
        _copy_tool_to_working(job_root, str(source_tool))
        if source_tool is not None
        else _suggest_initial_working_tool_path(job_root, firmware_path)
    )
    if source_tool is not None:
        initial_working_tool = _normalize_working_tool_name(job_root, firmware_path, str(source_tool))
    working_tool = initial_working_tool
    final_tool_path: str | None = None
    replaced_tool_path: str | None = str(source_tool) if source_tool is not None else None
    review_passed = False
    generated_new_tool = False
    round_items: list[dict[str, Any]] = []
    evolution_client = _create_client(
        agent_def_path=EVOLUTION_IMPROVER_AGENT_DEF,
        provider_role="evolution_improver",
        session_role="evolution-executor",
        session_name="shared",
        session_phase="evolution_execute",
        session_round=None,
        task_id=task_id,
        llm_binding_snapshot=llm_binding_snapshot,
        session_root=job_root,
    )

    try:
        for round_id in range(1, max(1, int(max_rounds)) + 1):
            round_dir = evolution_round_dir(job_root, round_id)
            _reset_workspace_output(workspace_output)
            before_path = working_tool
            before_text = before_path.read_text(encoding="utf-8") if before_path.exists() else ""
            executor_prompt_ran = False
            tool_result = ""
            token_stats: dict[str, Any] = {}
            review_token_stats: dict[str, Any] = {}
            review_result = ""
            review_round_passed = False

            if progress_callback:
                progress_callback(round_id, "evolution_execute")
            tool_round_started_at = time.monotonic()
            tool_elapsed_seconds = 0.0
            previous_feedback_path = (
                evolution_round_dir(job_root, round_id - 1) / "backend_execution_feedback.json"
                if round_id > 1 else None
            )
            previous_round_dir = evolution_round_dir(job_root, round_id - 1) if round_id > 1 else None
            previous_summary_path = previous_round_dir / "summary.md" if previous_round_dir is not None else None
            previous_reason_path = previous_round_dir / "reason.md" if previous_round_dir is not None else None
            round_context_path = _write_round_context(
                round_dir=round_dir,
                main_run_dir=_main_run_dir(unpack_output_path),
                job_root=job_root,
                firmware_path=firmware_path,
                workspace_output=workspace_output,
                working_tool=working_tool,
                source_tool=source_tool,
                started_without_matched_skill=started_without_matched_skill,
                previous_feedback_path=previous_feedback_path,
                previous_summary_path=previous_summary_path,
                previous_reason_path=previous_reason_path,
            )
            should_prompt_executor = started_without_matched_skill or round_id > 1
            if should_prompt_executor:
                evolution_prompt = _build_evolution_execute_prompt(
                    round_id=round_id,
                    firmware_path=firmware_path,
                    workspace_output=workspace_output,
                    working_tool=working_tool,
                    started_without_matched_skill=started_without_matched_skill,
                    previous_feedback_path=previous_feedback_path,
                )
                rendered_evolution_prompt = render_template(
                    EVOLUTION_IMPROVER_PROMPT_TMPL,
                    {
                        "$input": firmware_path,
                        "$output": str(workspace_output),
                        "$tools": str(TOOLS_DIR),
                        "$main_run": str(_main_run_dir(unpack_output_path)),
                        "$evolution_run": str(job_root),
                        "$working_tool": str(working_tool),
                        "$round_context": str(round_context_path),
                    },
                )
                try:
                    _append_stage_log(
                        round_dir,
                        "evolution_executor.log",
                        "starting evolution executor round",
                        round=round_id,
                        source_tool_path=str(source_tool) if source_tool is not None else None,
                        working_tool_path=str(working_tool),
                        workspace_output=str(workspace_output),
                        started_without_matched_skill=started_without_matched_skill,
                    )

                    def _stream_evolution_event(event: dict[str, Any]) -> None:
                        _append_stream_delta(
                            round_dir,
                            "evolution_executor.log",
                            f"evolution_executor:round_{round_id}",
                            event,
                        )

                    tool_result = evolution_client.prompt(
                        f"{rendered_evolution_prompt}\n\n{evolution_prompt}",
                        stream_callback=_stream_evolution_event,
                    )
                    token_stats = _save_agent_log(evolution_client, log, round_dir, "evolution_executor")
                    executor_prompt_ran = True
                    evolved_path = _extract_path_only(tool_result or "")
                    if evolved_path is None:
                        if not working_tool.exists():
                            raise RuntimeError("工具进化执行器未返回 Python 工具路径，且 working tool 不存在")
                        evolved_path = working_tool
                    sandbox_tool = _coerce_job_sandbox_tool_path(evolved_path, job_root)
                    working_tool = _normalize_tool_into_working_dir(
                        candidate=sandbox_tool,
                        working_dir=working_dir,
                        firmware_path=firmware_path,
                        source_tool=source_tool,
                        round_dir=round_dir,
                    )
                    working_tool = _validate_working_tool_path(working_tool, working_dir)
                    _append_stage_log(
                        round_dir,
                        "evolution_executor.log",
                        "evolution executor round completed",
                        round=round_id,
                        working_tool_path=str(working_tool),
                        response_preview=tool_result[:1000] if tool_result else None,
                    )
                finally:
                    pass
                _augment_tool_summary(
                    output_dir=workspace_output,
                    elapsed_seconds=time.monotonic() - tool_round_started_at,
                    token_stats=token_stats or _load_token_stats(round_dir, "evolution_executor"),
                )
                tool_elapsed_seconds = time.monotonic() - tool_round_started_at
                _sync_report_aliases(workspace_output)

            else:
                _append_stage_log(
                    round_dir,
                    "evolution_executor.log",
                    "matched tool found; skipping executor prompt and running tool directly",
                    round=round_id,
                    source_tool_path=str(source_tool) if source_tool is not None else None,
                    working_tool_path=str(working_tool),
                    workspace_output=str(workspace_output),
                )

            try:
                tool_execution = _run_working_tool(
                    firmware_path=firmware_path,
                    workspace_output=workspace_output,
                    job_root=job_root,
                    round_dir=round_dir,
                    working_tool=working_tool,
                )
                if tool_execution:
                    tool_result = f"{tool_result}\n\n[backend_tool_execution]\n{json.dumps(tool_execution, ensure_ascii=False, indent=2)}".strip()
                tool_elapsed_seconds = round(max(0.0, float(tool_execution.get('duration_seconds') or 0.0)), 3)
                _augment_tool_summary(
                    output_dir=workspace_output,
                    elapsed_seconds=tool_elapsed_seconds,
                    token_stats=token_stats or _load_token_stats(round_dir, "evolution_executor"),
                )
                _sync_report_aliases(workspace_output)
            except Exception as exc:
                feedback = _read_execution_feedback(round_dir / "backend_execution_feedback.json")
                tool_elapsed_seconds = round(max(0.0, float(feedback.get("duration_seconds") or 0.0)), 3)
                review_result = _write_tool_execution_failure(workspace_output, str(exc))
                review_round_passed = False
                _append_stage_log(
                    round_dir,
                    "reviewer.log",
                    "tool execution failed before llm review",
                    round=round_id,
                    working_tool_path=str(working_tool),
                    error=str(exc),
                )
                _sync_report_aliases(workspace_output)
                tool_changed = before_text != (working_tool.read_text(encoding="utf-8") if working_tool.exists() else "")
                summary_path = workspace_output / "summary.md"
                reason_path = workspace_output / "reason.md"
                round_summary_path = _snapshot_round_report(round_dir, summary_path, "summary.md")
                round_reason_path = _snapshot_round_report(round_dir, reason_path, "reason.md")
                _write_backend_reviewer_session(
                    job_root=job_root,
                    round_id=round_id,
                    review_result=review_result,
                    summary_path=summary_path,
                    reason_path=reason_path,
                    detail=f"工具执行失败。系统已将失败原因归档为评审器会话。错误：{exc}",
                    title="后端工具执行结论：失败",
                )
                round_item = {
                    "round": round_id,
                    "status": "review_failed",
                    "tool_skill_path_before": str(before_path),
                    "tool_skill_path_after": str(working_tool),
                    "tool_path_before": str(before_path),
                    "tool_path_after": str(working_tool),
                    "tool_changed": tool_changed,
                    "review_result": review_result,
                    "summary_path": round_summary_path,
                    "reason_path": round_reason_path,
                    "log_root": str(round_dir),
                    "log_files": {
                        "evolution_executor": str(round_dir / "evolution_executor_transcript.log"),
                        "reviewer": str(round_dir / "reviewer_transcript.log"),
                    },
                    "source_skill_path": str(source_tool) if source_tool is not None else None,
                    "source_tool_path": str(source_tool) if source_tool is not None else None,
                    "started_without_matched_skill": started_without_matched_skill,
                    "generated_new_skill": False,
                    "generated_new_tool": False,
                    "executed_tool": executor_prompt_ran,
                    "tool_response_preview": tool_result[:2000] if tool_result else None,
                    "evolution_executor_response_preview": tool_result[:2000] if tool_result else None,
                    "metrics": _build_evolution_round_metrics(
                        tool_elapsed_seconds=tool_elapsed_seconds,
                        evolution_executor_tokens=token_stats or _load_token_stats(round_dir, "evolution_executor"),
                        reviewer_tokens=review_token_stats,
                    ),
                    "created_at": datetime.now().isoformat(),
                    "completed_at": datetime.now().isoformat(),
                }
                round_items.append(round_item)
                _write_json_log(round_dir, "evolution_round.json", round_item)
                if progress_callback:
                    progress_callback(round_id, "evolution_execute")
                if round_id >= max_rounds:
                    continue
                _append_stage_log(
                    round_dir,
                    "reviewer.log",
                    "review did not pass, evolution round will continue if budget remains",
                    round=round_id,
                    max_rounds=max_rounds,
                )
                continue

            if progress_callback:
                progress_callback(round_id, "review")
            review_client = _create_client(
                agent_def_path=VAL_AGENT_DEF,
                provider_role="reviewer",
                session_role="reviewer",
                session_name=f"round-{round_id}",
                session_phase="review",
                session_round=round_id,
                task_id=task_id,
                llm_binding_snapshot=llm_binding_snapshot,
                session_root=job_root,
            )
            try:
                review_context_path = _write_round_context(
                    round_dir=round_dir,
                    main_run_dir=_main_run_dir(unpack_output_path),
                    job_root=job_root,
                    firmware_path=firmware_path,
                    workspace_output=workspace_output,
                    working_tool=working_tool,
                    source_tool=source_tool,
                    started_without_matched_skill=started_without_matched_skill,
                    previous_feedback_path=previous_feedback_path,
                    previous_summary_path=previous_summary_path,
                    previous_reason_path=previous_reason_path,
                    current_feedback_path=round_dir / "backend_execution_feedback.json",
                    current_summary_path=workspace_output / "summary.md",
                    current_reason_path=workspace_output / "reason.md",
                )
                review_prompt = render_template(
                    EVOLUTION_REVIEW_PROMPT_TMPL,
                    {
                        "$input": firmware_path,
                        "$output": str(workspace_output),
                        "$working_tool": str(working_tool),
                        "$round_context": str(review_context_path),
                    },
                )
                _append_stage_log(
                    round_dir,
                    "reviewer.log",
                    "starting evolution review",
                    round=round_id,
                    workspace_output=str(workspace_output),
                    working_tool_path=str(working_tool),
                )

                def _stream_review_event(event: dict[str, Any]) -> None:
                    _append_stream_delta(
                        round_dir,
                        "reviewer.log",
                        f"reviewer:round_{round_id}",
                        event,
                    )

                review_result = review_client.prompt(
                    review_prompt,
                    stream_callback=_stream_review_event,
                )
                review_token_stats = _save_agent_log(review_client, log, round_dir, "reviewer")
                review_round_passed = _review_passed(review_result)
                _append_stage_log(
                    round_dir,
                    "reviewer.log",
                    "evolution review completed",
                    round=round_id,
                    review_passed=review_round_passed,
                    review_preview=review_result[:1000] if review_result else None,
                )
            finally:
                review_client.close()
            _sync_report_aliases(workspace_output)

            tool_changed = before_text != (working_tool.read_text(encoding="utf-8") if working_tool.exists() else "")

            summary_path = workspace_output / "summary.md"
            reason_path = workspace_output / "reason.md"
            round_summary_path = _snapshot_round_report(round_dir, summary_path, "summary.md")
            round_reason_path = _snapshot_round_report(round_dir, reason_path, "reason.md")
            round_status = "review_passed" if review_round_passed else "review_failed"
            round_item: dict[str, Any] = {
                "round": round_id,
                "status": round_status,
                "tool_skill_path_before": str(before_path),
                "tool_skill_path_after": str(working_tool),
                "tool_path_before": str(before_path),
                "tool_path_after": str(working_tool),
                "tool_changed": tool_changed,
                "review_result": review_result,
                "summary_path": round_summary_path,
                "reason_path": round_reason_path,
                "log_root": str(round_dir),
                "log_files": {
                    "evolution_executor": str(round_dir / "evolution_executor_transcript.log"),
                    "reviewer": str(round_dir / "reviewer_transcript.log"),
                },
                "source_skill_path": str(source_tool) if source_tool is not None else None,
                "source_tool_path": str(source_tool) if source_tool is not None else None,
                "started_without_matched_skill": started_without_matched_skill,
                "generated_new_skill": False,
                "generated_new_tool": False,
                "executed_tool": executor_prompt_ran,
                "tool_response_preview": tool_result[:2000] if tool_result else None,
                "evolution_executor_response_preview": tool_result[:2000] if tool_result else None,
                "metrics": _build_evolution_round_metrics(
                    tool_elapsed_seconds=tool_elapsed_seconds,
                    evolution_executor_tokens=token_stats or _load_token_stats(round_dir, "evolution_executor"),
                    reviewer_tokens=review_token_stats or _load_token_stats(round_dir, "reviewer"),
                ),
                "created_at": datetime.now().isoformat(),
                "completed_at": datetime.now().isoformat(),
            }

            if review_round_passed:
                review_passed = True
                run_tool_path, replaced_tool_path, generated_new_tool = _save_generated_tool_to_run(
                    job_root=job_root,
                    firmware_path=firmware_path,
                    working_tool=working_tool,
                    source_tool=source_tool,
                )
                final_tool_path = _publish_tool_to_store(
                    firmware_path=firmware_path,
                    working_tool=working_tool,
                    source_tool=source_tool,
                    tool_changed=tool_changed,
                )
                round_item["generated_new_skill"] = generated_new_tool
                round_item["generated_new_tool"] = generated_new_tool
                round_item["run_tool_path_after"] = run_tool_path
                round_item["tool_skill_path_after"] = final_tool_path
                round_item["tool_path_after"] = final_tool_path
                _append_stage_log(
                    round_dir,
                    "evolution_executor.log",
                    "published evolution tool result",
                    round=round_id,
                    run_tool_path=run_tool_path,
                    store_tool_path=final_tool_path,
                    replaced_tool_path=replaced_tool_path,
                    generated_new_tool=generated_new_tool,
                )
                round_items.append(round_item)
                _write_json_log(round_dir, "evolution_round.json", round_item)
                break

            round_items.append(round_item)
            _append_stage_log(
                round_dir,
                "reviewer.log",
                "review did not pass, evolution round will continue if budget remains",
                round=round_id,
                max_rounds=max_rounds,
            )
            _write_json_log(round_dir, "evolution_round.json", round_item)
            if round_id >= max_rounds:
                continue
    finally:
        evolution_client.close()

    final_status = "success" if review_passed else "failed"
    replacement_required = bool(review_passed and final_tool_path)
    payload = {
        "status": final_status,
        "review_passed": review_passed,
        "current_round": len(round_items),
        "max_rounds": max_rounds,
        "final_skill_path": final_tool_path,
        "final_tool_path": final_tool_path,
        "replaced_skill_path": replaced_tool_path if review_passed else None,
        "replaced_tool_path": replaced_tool_path if review_passed else None,
        "job_root": str(job_root),
        "session_root": str(session_root),
        "rounds": round_items,
        "working_skill_path": str(working_tool),
        "working_tool_path": str(working_tool),
        "source_skill_path": str(source_tool) if source_tool is not None else None,
        "source_tool_path": str(source_tool) if source_tool is not None else None,
        "started_without_matched_skill": started_without_matched_skill,
        "generated_new_skill": generated_new_tool,
        "generated_new_tool": generated_new_tool,
        "replacement_required": replacement_required,
        "replacement_confirmed": not replacement_required,
        "effective_tool_path": str(final_tool_path or replaced_tool_path or "") or None,
    }
    (job_root / "evolution_result.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return payload
