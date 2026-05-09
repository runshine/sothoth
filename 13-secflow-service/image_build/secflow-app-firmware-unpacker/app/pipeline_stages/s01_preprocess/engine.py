#!/usr/bin/env python3
"""Deterministic firmware pre-processing helpers."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path

log = logging.getLogger("unpacker.service")

MAX_RECURSIVE_ITEMS = int(os.environ.get("UNPACKER_PREPROCESS_MAX_RECURSIVE_ITEMS", "80"))
MAX_RECURSIVE_DEPTH = int(os.environ.get("UNPACKER_PREPROCESS_MAX_RECURSIVE_DEPTH", "4"))
MAX_RECURSIVE_FILE_BYTES = int(os.environ.get("UNPACKER_PREPROCESS_MAX_RECURSIVE_FILE_BYTES", str(256 * 1024 * 1024)))


def log_event(logger: logging.Logger, level: int, message: str, **fields: object) -> None:
    logger.log(level, message, extra=fields)


def _write_stage_log(log_dir, stage_entries: list[dict]) -> None:
    if log_dir is None:
        return
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    Path(log_dir, "stage1_preprocess.json").write_text(
        json.dumps(stage_entries, indent=2)
    )


def _normalize_file_format(file_desc: str) -> str | None:
    desc = str(file_desc or "").strip().lower()
    if not desc:
        return None

    if "glf_binary_msb_first" in desc:
        return "glf"
    if "tar archive" in desc:
        return "tar"
    if "zip archive data" in desc:
        return "zip"
    if "gzip compressed data" in desc:
        return "gzip"
    if "bzip2 compressed data" in desc:
        return "bzip2"
    if "xz compressed data" in desc:
        return "xz"
    if "lzma compressed data" in desc:
        return "lzma"
    if "zstandard compressed data" in desc:
        return "zstd"
    if "lzop compressed data" in desc:
        return "lzop"
    if "squashfs filesystem" in desc:
        return "squashfs"
    if "cpio archive" in desc:
        return "cpio"
    if "7-zip archive data" in desc:
        return "7zip"
    if "cabinet archive data" in desc or "microsoft cabinet archive" in desc:
        return "cab"
    if "romfs filesystem" in desc:
        return "romfs"
    if "cramfs filesystem" in desc:
        return "cramfs"
    if "jffs2 filesystem" in desc:
        return "jffs2"
    if "ubifs" in desc:
        return "ubifs"
    if "ubi image" in desc:
        return "ubi"
    if "elf " in desc:
        return "elf"
    if "pe32 executable" in desc or "dos executable" in desc:
        return "exe"
    return None


def _file_format_hint(firmware_path: str) -> tuple[str | None, str]:
    try:
        proc = subprocess.run(
            ["file", "-b", firmware_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except Exception:
        return None, ""

    file_desc = (proc.stdout or "").strip()
    if proc.returncode != 0:
        return None, file_desc
    return _normalize_file_format(file_desc), file_desc


def detect_format(firmware_path: str) -> dict:
    """Detect firmware format via magic bytes and file extension."""
    path = Path(firmware_path)
    ext = path.suffix.lower()
    suffixes = path.suffixes
    ext2 = "".join(suffixes[-2:]).lower() if len(suffixes) >= 2 else ext
    fmt = None
    magic = b""
    file_desc = ""
    try:
        with open(firmware_path, "rb") as fh:
            header = fh.read(512)
            magic = header[:16]
        if header[257:262] == b"ustar":
            fmt = "tar"
        elif magic[:2] == b"\x1f\x8b":
            fmt = "gzip"
        elif magic[:4] == b"PK\x03\x04":
            fmt = "zip"
        elif magic[:4] in (b"hsqs", b"sqsh", b"shsq", b"qshs"):
            fmt = "squashfs"
        elif magic[:6] in (b"070701", b"070702"):
            fmt = "cpio"
        elif magic[:5] == b"7z\xbc\xaf'":
            fmt = "7zip"
        elif magic[:3] == b"BZh":
            fmt = "bzip2"
        elif magic[:4] == b"\xfd7zX":
            fmt = "xz"
        elif magic[:4] == b"\x28\xb5\x2f\xfd":
            fmt = "zstd"
        elif magic[:9] == b"\x89LZO\x00\x0d\x0a\x1a\x0a":
            fmt = "lzop"
        elif magic[:4] == b"MSCF":
            fmt = "cab"
        elif magic[:8] == b"-rom1fs-":
            fmt = "romfs"
        elif magic[:4] in (b"\x45\x3d\xcd\x28", b"\x28\xcd\x3d\x45"):
            fmt = "cramfs"
        elif magic[:2] in (b"\x85\x19", b"\x19\x85"):
            fmt = "jffs2"
        elif magic[:4] == b"UBI#":
            fmt = "ubi"
        elif magic[:4] == b"\x7fELF":
            fmt = "elf"
        elif magic[:2] == b"MZ":
            fmt = "exe"
    except Exception:
        pass

    if fmt is None:
        if ext2 in (".tar.gz", ".tar.bz2", ".tar.xz", ".tar.lz4", ".tar.zst"):
            fmt = "tar"
        elif ext in (".tar", ".tgz"):
            fmt = "tar"
        elif ext == ".zip":
            fmt = "zip"
        elif ext == ".gz":
            fmt = "gzip"
        elif ext == ".bz2":
            fmt = "bzip2"
        elif ext == ".xz":
            fmt = "xz"
        elif ext in (".zst", ".zstd"):
            fmt = "zstd"
        elif ext in (".lzo", ".lzop"):
            fmt = "lzop"
        elif ext == ".lzma":
            fmt = "lzma"
        elif ext in (".squashfs", ".sqfs", ".sfs"):
            fmt = "squashfs"
        elif ext in (".cramfs", ".crm"):
            fmt = "cramfs"
        elif ext in (".romfs", ".rom"):
            fmt = "romfs"
        elif ext in (".jffs2", ".jffs"):
            fmt = "jffs2"
        elif ext in (".ubi", ".ubiimg"):
            fmt = "ubi"
        elif ext in (".ubifs",):
            fmt = "ubifs"
        elif ext in (".yaffs", ".yaffs2"):
            fmt = "yaffs"
        elif ext == ".cpio":
            fmt = "cpio"
        elif ext == ".7z":
            fmt = "7zip"
        elif ext == ".cab":
            fmt = "cab"

    if fmt in ("gzip", "bzip2", "xz") and ext2 in (".tar.gz", ".tar.bz2", ".tar.xz"):
        fmt = "tar"
    if fmt == "gzip" and ext == ".tgz":
        fmt = "tar"
    if fmt is None:
        fmt, file_desc = _file_format_hint(firmware_path)

    log_event(
        log,
        logging.DEBUG,
        "[detect_format] result",
        event="detect_format",
        firmware=path.name,
        fmt=fmt,
        ext=ext,
        ext2=ext2,
        magic_hex=magic.hex()[:8] if magic else "",
        file_desc=file_desc[:120] if file_desc else "",
    )
    return {"fmt": fmt, "ext": ext, "ext2": ext2, "magic": magic, "file_desc": file_desc}


def run_preprocess(firmware_path: str, output_path: str, log_dir=None) -> dict:
    """Try deterministic extraction for common archive and compressed formats."""
    stage_entries = []
    info = detect_format(firmware_path)
    fmt = info["fmt"]
    firmware_name = Path(firmware_path).name
    os.makedirs(output_path, exist_ok=True)

    stage_entries.append(
        {
            "step": "format_detection",
            "firmware": firmware_name,
            "fmt": fmt,
            "magic_hex": info["magic"].hex()[:8] if info["magic"] else "",
            "file_desc": info.get("file_desc", ""),
        }
    )
    log_event(
        log,
        logging.INFO,
        "[Stage1] detected format",
        event="preprocess_format_detect",
        firmware=firmware_name,
        fmt=fmt,
        magic_hex=info["magic"].hex()[:8] if info["magic"] else "",
        file_desc=(info.get("file_desc", "")[:120] if info.get("file_desc") else ""),
    )

    def _run(cmd, **kw):
        return subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kw
        )

    def _record(tool, proc=None, success=False, extra=None):
        entry = {"step": "tool_attempt", "tool": tool, "success": success}
        if proc is not None:
            entry["returncode"] = proc.returncode
            if proc.stderr:
                entry["stderr"] = proc.stderr[:300]
            if proc.stdout:
                entry["stdout"] = proc.stdout[:300]
        if extra:
            entry.update(extra)
        stage_entries.append(entry)

    def _success(method: str) -> dict:
        log_event(
            log,
            logging.INFO,
            f"[Stage1] {method} succeeded",
            event="preprocess_tool_success",
            tool=method,
        )
        result = {"success": True, "method": method}
        stage_entries.append({"step": "result", "success": True, "method": method})
        _write_stage_log(log_dir, stage_entries)
        return result

    def _find_magic_offset(magic: bytes, max_scan: int = 16 * 1024 * 1024) -> int:
        try:
            with open(firmware_path, "rb") as fh:
                data = fh.read(max_scan)
            return data.find(magic)
        except Exception:
            return -1

    def _copy_from_offset(offset: int, dest: Path) -> int:
        total = 0
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(firmware_path, "rb") as src, open(dest, "wb") as out:
            src.seek(offset)
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)
                total += len(chunk)
        return total

    def _copy_range(offset: int, size: int, dest: Path) -> int:
        total = 0
        remaining = max(0, int(size))
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(firmware_path, "rb") as src, open(dest, "wb") as out:
            src.seek(offset)
            while remaining > 0:
                chunk = src.read(min(4 * 1024 * 1024, remaining))
                if not chunk:
                    break
                out.write(chunk)
                total += len(chunk)
                remaining -= len(chunk)
        return total

    def _safe_name(path: Path) -> str:
        sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", path.name).strip("._")
        return sanitized or "payload"

    def _uimage_payload_info(path: Path) -> tuple[str, int] | None:
        try:
            with open(path, "rb") as fh:
                header = fh.read(64)
            if len(header) != 64 or header[:4] != b"\x27\x05\x19\x56":
                return None
            compression_map = {
                0: "none",
                1: "gzip",
                2: "bzip2",
                3: "lzma",
                5: "lzop",
                6: "lzma",
                7: "xz",
            }
            return compression_map.get(header[31], f"unknown-{header[31]}"), int.from_bytes(header[12:16], "big")
        except Exception:
            return None

    def _extract_uimage_payload(path: Path, dest_dir: Path) -> Path | None:
        info = _uimage_payload_info(path)
        if not info:
            return None
        compression, payload_size = info
        dest_dir.mkdir(parents=True, exist_ok=True)
        raw_payload = dest_dir / f"{_safe_name(path)}.payload"
        remaining = min(payload_size, max(0, path.stat().st_size - 64))
        with open(path, "rb") as src, open(raw_payload, "wb") as out:
            src.seek(64)
            while remaining > 0:
                chunk = src.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                out.write(chunk)
                remaining -= len(chunk)
        if raw_payload.stat().st_size == 0:
            raw_payload.unlink(missing_ok=True)
            return None

        if compression == "none":
            return raw_payload

        suffix_by_compression = {
            "gzip": ".gz",
            "bzip2": ".bz2",
            "xz": ".xz",
            "lzma": ".lzma",
            "lzop": ".lzo",
        }
        raw_payload.rename(raw_payload.with_suffix(raw_payload.suffix + suffix_by_compression.get(compression, ".bin")))
        return raw_payload.with_suffix(raw_payload.suffix + suffix_by_compression.get(compression, ".bin"))

    def _scan_elfs(root: Path) -> list[Path]:
        elfs: list[Path] = []
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            try:
                with open(path, "rb") as fh:
                    if fh.read(4) == b"\x7fELF":
                        elfs.append(path)
            except Exception:
                continue
        return sorted(elfs)

    def _make_tree_user_writable(root: Path) -> None:
        try:
            for path in root.rglob("*"):
                try:
                    mode = path.stat().st_mode
                    if path.is_dir():
                        path.chmod(mode | 0o700)
                    else:
                        path.chmod(mode | 0o600)
                except OSError:
                    continue
            mode = root.stat().st_mode
            root.chmod(mode | 0o700)
        except OSError:
            pass

    def _recursive_extract(seed_files: list[Path]) -> dict:
        extracted_root = Path(output_path) / "extracted"
        queue: list[tuple[Path, int, Path]] = []
        actions: list[dict] = []
        blockers: list[str] = []
        seen: set[Path] = set()

        for path in seed_files:
            if path.exists() and path.is_file():
                queue.append((path, 0, extracted_root / path.stem))

        while queue and len(actions) < MAX_RECURSIVE_ITEMS:
            current, depth, dest_base = queue.pop(0)
            resolved = current.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            if depth > MAX_RECURSIVE_DEPTH:
                blockers.append(f"{current}: skipped because max recursion depth {MAX_RECURSIVE_DEPTH} was reached")
                continue
            try:
                if current.stat().st_size > MAX_RECURSIVE_FILE_BYTES:
                    blockers.append(f"{current}: skipped because size exceeds {MAX_RECURSIVE_FILE_BYTES} bytes")
                    continue
            except OSError:
                continue

            fmt_info = detect_format(str(current))
            item_fmt = fmt_info["fmt"]
            file_desc = fmt_info.get("file_desc", "")
            dest = dest_base
            result_paths: list[Path] = []
            proc = None

            try:
                if item_fmt == "squashfs":
                    if not shutil.which("unsquashfs"):
                        blockers.append(f"{current}: unsquashfs is not available")
                        continue
                    dest.mkdir(parents=True, exist_ok=True)
                    proc = _run(["unsquashfs", "-no-xattrs", "-d", str(dest), str(current)], timeout=300)
                    if proc.returncode == 0:
                        _make_tree_user_writable(dest)
                        result_paths.append(dest)
                elif _uimage_payload_info(current):
                    payload_dir = dest / "uimage_payload"
                    payload = _extract_uimage_payload(current, payload_dir)
                    if payload:
                        result_paths.append(payload)
                        queue.append((payload, depth + 1, payload_dir / payload.stem))
                elif item_fmt == "cpio":
                    dest.mkdir(parents=True, exist_ok=True)
                    proc = _run(["sh", "-c", f"cd '{dest}' && cpio -idm --no-absolute-filenames < '{current.resolve()}'"], timeout=300)
                    if proc.returncode == 0:
                        result_paths.append(dest)
                elif item_fmt == "zip":
                    dest.mkdir(parents=True, exist_ok=True)
                    proc = _run(["7z", "x", str(current), f"-o{dest}", "-y"], timeout=300)
                    if proc.returncode == 0:
                        result_paths.append(dest)
                elif item_fmt == "7zip":
                    dest.mkdir(parents=True, exist_ok=True)
                    proc = _run(["7z", "x", str(current), f"-o{dest}", "-y"], timeout=300)
                    if proc.returncode == 0:
                        result_paths.append(dest)
                elif item_fmt in ("gzip", "bzip2", "xz", "lzma"):
                    tool_by_fmt = {
                        "gzip": "gzip -dc",
                        "bzip2": "bzip2 -dc",
                        "xz": "xz -dc",
                        "lzma": "lzma -dc",
                    }
                    out = dest.parent / f"{_safe_name(current)}.decompressed"
                    out.parent.mkdir(parents=True, exist_ok=True)
                    proc = _run(["sh", "-c", f"{tool_by_fmt[item_fmt]} '{current}' > '{out}'"], timeout=300)
                    if proc.returncode == 0 and out.exists() and out.stat().st_size > 0:
                        result_paths.append(out)
                        queue.append((out, depth + 1, out.parent / f"{out.stem}_extract"))

                if result_paths:
                    actions.append(
                        {
                            "input": str(current),
                            "format": item_fmt or "uimage",
                            "file_desc": file_desc,
                            "outputs": [str(path) for path in result_paths],
                        }
                    )
                    for root in result_paths:
                        if root.is_dir():
                            for nested in root.rglob("*"):
                                if not nested.is_file():
                                    continue
                                nested_info = detect_format(str(nested))
                                if nested_info["fmt"] in {"squashfs", "cpio", "zip", "7zip", "gzip", "bzip2", "xz", "lzma"} or _uimage_payload_info(nested):
                                    queue.append((nested, depth + 1, root / f"{nested.stem}_extract"))
                        elif root.is_file():
                            nested_info = detect_format(str(root))
                            if nested_info["fmt"] in {"squashfs", "cpio", "zip", "7zip", "gzip", "bzip2", "xz", "lzma"} or _uimage_payload_info(root):
                                queue.append((root, depth + 1, root.parent / f"{root.stem}_extract"))
                elif proc is not None and proc.returncode != 0:
                    blockers.append(f"{current}: {item_fmt} extraction failed: {(proc.stderr or proc.stdout)[:160]}")
            except Exception as exc:
                blockers.append(f"{current}: extraction error: {exc}")

        elf_paths = _scan_elfs(extracted_root) if extracted_root.exists() else []
        return {
            "actions": actions,
            "blockers": blockers,
            "elfs": [str(path) for path in elf_paths],
        }

    def _extract_elf_at_offset(offset: int) -> dict | None:
        firmware_stem = Path(firmware_path).stem or "firmware"
        elf_out = Path(output_path) / f"{firmware_stem}_elf"
        header_out = Path(output_path) / "header.bin"
        try:
            extracted_size = _copy_from_offset(offset, elf_out)
            header_size = 0
            if offset > 0:
                with open(firmware_path, "rb") as src, open(header_out, "wb") as out:
                    out.write(src.read(offset))
                header_size = header_out.stat().st_size

            file_proc = _run(["file", str(elf_out)])
            file_desc = file_proc.stdout.strip() if file_proc.returncode == 0 else ""
            summary_lines = [
                f"Firmware: {firmware_path}",
                f"Method: embedded ELF extraction",
                f"ELF offset: {offset} (0x{offset:x})",
                f"Extracted ELF: {elf_out.name} ({extracted_size} bytes)",
            ]
            if header_size:
                summary_lines.append(f"Preserved prefix/header: {header_out.name} ({header_size} bytes)")
            if file_desc:
                summary_lines.append(f"File identification: {file_desc}")
            summary_lines.extend(
                [
                    "",
                    "Tools and commands used:",
                    "- magic scan for ELF header",
                    f"- copied bytes from offset {offset} into {elf_out.name}",
                    "- file on extracted ELF",
                    "",
                    "What was found:",
                    "- Embedded ELF executable/shared object payload",
                    "- Prefix bytes before the ELF were preserved separately when present",
                    "",
                    "Skill Reuse Notes:",
                    "- Check for zero padding followed by ELF magic at a fixed offset.",
                    "- Extract from the ELF offset and preserve the prefix as a header artifact.",
                    "- Record file/readelf metadata for similar samples.",
                    "",
                ]
            )
            Path(output_path, "summary.txt").write_text("\n".join(summary_lines), encoding="utf-8")
            _record(
                "embedded ELF extraction",
                file_proc,
                success=True,
                extra={
                    "offset": offset,
                    "output_file": str(elf_out),
                    "output_size": extracted_size,
                    "header_file": str(header_out) if header_size else None,
                    "header_size": header_size,
                },
            )
            return _success("embedded ELF extraction")
        except Exception as exc:
            _record("embedded ELF extraction", extra={"offset": offset, "error": str(exc)})
            return None

    def _stream_decompress(tool: str, shell_cmd: str) -> dict | None:
        log_event(
            log,
            logging.DEBUG,
            f"[Stage1] trying: {tool}",
            event="preprocess_try_tool",
            tool=tool,
            firmware=firmware_name,
        )
        out = os.path.join(output_path, Path(firmware_path).stem)
        proc = _run(["sh", "-c", shell_cmd.format(src=firmware_path, out=out)])
        if proc.returncode == 0 and os.path.exists(out) and os.path.getsize(out) > 0:
            _record(
                tool,
                proc,
                success=True,
                extra={"output_file": out, "size": os.path.getsize(out)},
            )
            return _success(tool)
        _record(tool, proc)
        log_event(
            log,
            logging.DEBUG,
            f"[Stage1] {tool} failed",
            event="preprocess_tool_fail",
            tool=tool,
            returncode=proc.returncode,
        )
        return None

    def _extract_glf_payloads() -> dict | None:
        log_event(
            log,
            logging.DEBUG,
            "[Stage1] trying: glf binwalk slice extraction",
            event="preprocess_try_tool",
            tool="glf binwalk slice extraction",
            firmware=firmware_name,
        )
        proc = _run(["binwalk", "-B", firmware_path], timeout=60)
        if proc.returncode != 0:
            _record("glf binwalk slice extraction", proc)
            return None

        artifacts_dir = Path(output_path) / "artifacts"
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        extracted: list[dict] = []
        squashfs_index = 0
        uimage_index = 0
        line_re = re.compile(r"^\s*(\d+)\s+0x[0-9A-Fa-f]+\s+(.+)$")
        size_re = re.compile(r"size:\s*(\d+)\s+bytes", re.IGNORECASE)
        image_size_re = re.compile(r"image size:\s*(\d+)\s+bytes", re.IGNORECASE)

        for raw_line in proc.stdout.splitlines():
            match = line_re.match(raw_line.strip())
            if not match:
                continue
            offset = int(match.group(1))
            desc = match.group(2).strip()
            desc_lower = desc.lower()
            if "squashfs filesystem" in desc_lower:
                size_match = size_re.search(desc)
                if not size_match:
                    continue
                squashfs_index += 1
                size = int(size_match.group(1))
                compression = "unknown"
                compression_match = re.search(r"compression:([a-z0-9_-]+)", desc, re.IGNORECASE)
                if compression_match:
                    compression = compression_match.group(1).lower()
                dest = artifacts_dir / f"rootfs_{squashfs_index}_{compression}.squashfs"
                output_size = _copy_range(offset, size, dest)
                if output_size > 0:
                    extracted.append(
                        {
                            "kind": "squashfs",
                            "offset": offset,
                            "size": output_size,
                            "path": str(dest),
                            "description": desc,
                        }
                    )
            elif "uimage header" in desc_lower:
                size_match = image_size_re.search(desc)
                if not size_match:
                    continue
                uimage_index += 1
                size = int(size_match.group(1)) + 64
                dest = artifacts_dir / f"uimage_{uimage_index}.bin"
                output_size = _copy_range(offset, size, dest)
                if output_size > 0:
                    extracted.append(
                        {
                            "kind": "uimage",
                            "offset": offset,
                            "size": output_size,
                            "path": str(dest),
                            "description": desc,
                        }
                    )

        if not extracted:
            _record("glf binwalk slice extraction", proc)
            return None

        recursive_result = _recursive_extract([Path(item["path"]) for item in extracted])

        summary_lines = [
            f"Firmware: {firmware_path}",
            "Method: GLF wrapper extraction via file+binwalk plus recursive payload extraction",
            f"file(1): {info.get('file_desc', '') or 'n/a'}",
            "",
            "Extracted artifacts:",
        ]
        for item in extracted:
            rel = Path(item["path"]).relative_to(output_path)
            summary_lines.append(
                f"- {rel} ({item['size']} bytes) from offset {item['offset']} - {item['description']}"
            )
        if recursive_result["actions"]:
            summary_lines.extend(["", "Recursive extraction:"])
            for action in recursive_result["actions"]:
                input_rel = Path(action["input"]).relative_to(output_path)
                output_rels = []
                for raw_output in action["outputs"]:
                    output_path_obj = Path(raw_output)
                    try:
                        output_rels.append(str(output_path_obj.relative_to(output_path)))
                    except ValueError:
                        output_rels.append(str(output_path_obj))
                summary_lines.append(
                    f"- {input_rel} [{action['format']}] -> {', '.join(output_rels)}"
                )
        if recursive_result["elfs"]:
            summary_lines.extend(["", f"ELF files found: {len(recursive_result['elfs'])}"])
            for elf_path in recursive_result["elfs"][:80]:
                elf = Path(elf_path)
                try:
                    rel = elf.relative_to(output_path)
                except ValueError:
                    rel = elf
                summary_lines.append(f"- {rel}")
            if len(recursive_result["elfs"]) > 80:
                summary_lines.append(f"- ... {len(recursive_result['elfs']) - 80} more ELF files")
        if recursive_result["blockers"]:
            summary_lines.extend(["", "Unextracted or skipped nested payloads:"])
            for blocker in recursive_result["blockers"][:40]:
                summary_lines.append(f"- {blocker}")
        summary_lines.extend(
            [
                "",
                "Skill Reuse Notes:",
                "- When the top-level header is vendor-specific GLF data, fall back to file(1) plus bounded binwalk scanning.",
                "- Extract top-level SquashFS and uImage payloads with fixed offsets and recorded sizes.",
                "- After slicing, run unsquashfs on filesystem images and strip the 64-byte uImage header to expose kernel or ramdisk payloads.",
                "- Continue recursively into cpio, gzip, xz, lzma, zip, and 7z payloads until no more filesystem/archive containers remain.",
            ]
        )
        Path(output_path, "summary.txt").write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
        _record(
            "glf binwalk slice extraction",
            proc,
            success=True,
            extra={
                "artifact_count": len(extracted),
                "artifacts": extracted,
                "recursive_action_count": len(recursive_result["actions"]),
                "elf_count": len(recursive_result["elfs"]),
                "recursive_blockers": recursive_result["blockers"],
            },
        )
        return _success("glf recursive binwalk slice extraction")

    if fmt in (None, "elf"):
        elf_offset = _find_magic_offset(b"\x7fELF")
        if elf_offset >= 0:
            result = _extract_elf_at_offset(elf_offset)
            if result:
                return result

    if fmt == "tar":
        log_event(
            log,
            logging.DEBUG,
            "[Stage1] trying: tar xf",
            event="preprocess_try_tool",
            tool="tar xf",
            firmware=firmware_name,
        )
        proc = _run(["tar", "xf", firmware_path, "-C", output_path])
        if proc.returncode == 0:
            _record("tar xf", proc, success=True)
            return _success("tar xf")
        _record("tar xf", proc)
        log_event(
            log,
            logging.DEBUG,
            "[Stage1] tar xf failed",
            event="preprocess_tool_fail",
            tool="tar xf",
            returncode=proc.returncode,
            stderr=proc.stderr[:200],
        )

    if fmt == "zip":
        log_event(
            log,
            logging.DEBUG,
            "[Stage1] trying: python zipfile",
            event="preprocess_try_tool",
            tool="python zipfile",
            firmware=firmware_name,
        )
        try:
            import zipfile

            with zipfile.ZipFile(firmware_path) as archive:
                archive.extractall(output_path)
            _record("python zipfile", success=True)
            return _success("python zipfile")
        except Exception as exc:
            _record("python zipfile", extra={"error": str(exc)})
            log_event(
                log,
                logging.DEBUG,
                "[Stage1] python zipfile failed",
                event="preprocess_tool_fail",
                tool="python zipfile",
                error=str(exc),
            )

    if fmt == "squashfs":
        log_event(
            log,
            logging.DEBUG,
            "[Stage1] trying: unsquashfs",
            event="preprocess_try_tool",
            tool="unsquashfs",
            firmware=firmware_name,
        )
        dest = os.path.join(output_path, "squashfs-root")
        proc = _run(["unsquashfs", "-d", dest, firmware_path])
        if proc.returncode == 0:
            _record("unsquashfs", proc, success=True)
            return _success("unsquashfs")
        _record("unsquashfs", proc)
        log_event(
            log,
            logging.DEBUG,
            "[Stage1] unsquashfs failed",
            event="preprocess_tool_fail",
            tool="unsquashfs",
            returncode=proc.returncode,
            stderr=proc.stderr[:200],
        )

    if fmt == "glf":
        result = _extract_glf_payloads()
        if result:
            return result

    if fmt == "gzip":
        result = _stream_decompress("gzip -dc", "gzip -dc '{src}' > '{out}'")
        if result:
            return result

    if fmt == "bzip2":
        result = _stream_decompress("bzip2 -dc", "bzip2 -dc '{src}' > '{out}'")
        if result:
            return result

    if fmt == "xz":
        result = _stream_decompress("xz -dc", "xz -dc '{src}' > '{out}'")
        if result:
            return result

    if fmt == "zstd":
        result = _stream_decompress("zstd -dc", "zstd -dc '{src}' > '{out}'")
        if result:
            return result

    if fmt == "lzop":
        result = _stream_decompress("lzop -dc", "lzop -dc '{src}' > '{out}'")
        if result:
            return result

    if fmt == "lzma":
        result = _stream_decompress("lzma -dc", "lzma -dc '{src}' > '{out}'")
        if result:
            return result

    if fmt == "cpio":
        log_event(
            log,
            logging.DEBUG,
            "[Stage1] trying: cpio -idm",
            event="preprocess_try_tool",
            tool="cpio -idm",
            firmware=firmware_name,
        )
        proc = _run(["sh", "-c", f"cd '{output_path}' && cpio -idm < '{firmware_path}'"])
        if proc.returncode == 0:
            _record("cpio -idm", proc, success=True)
            return _success("cpio -idm")
        _record("cpio -idm", proc)
        log_event(
            log,
            logging.DEBUG,
            "[Stage1] cpio -idm failed",
            event="preprocess_tool_fail",
            tool="cpio -idm",
            returncode=proc.returncode,
            stderr=proc.stderr[:200],
        )

    if fmt == "7zip":
        log_event(
            log,
            logging.DEBUG,
            "[Stage1] trying: 7z x",
            event="preprocess_try_tool",
            tool="7z x",
            firmware=firmware_name,
        )
        proc = _run(["7z", "x", firmware_path, f"-o{output_path}", "-y"])
        if proc.returncode == 0:
            _record("7z x", proc, success=True)
            return _success("7z x")
        _record("7z x", proc)
        log_event(
            log,
            logging.DEBUG,
            "[Stage1] 7z x failed",
            event="preprocess_tool_fail",
            tool="7z x",
            returncode=proc.returncode,
            stderr=proc.stderr[:200],
        )

    if fmt == "cab":
        log_event(
            log,
            logging.DEBUG,
            "[Stage1] trying: cabextract",
            event="preprocess_try_tool",
            tool="cabextract",
            firmware=firmware_name,
        )
        proc = _run(["cabextract", "-d", output_path, firmware_path])
        if proc.returncode == 0:
            _record("cabextract", proc, success=True)
            return _success("cabextract")
        _record("cabextract", proc)

    if fmt == "jffs2":
        log_event(
            log,
            logging.DEBUG,
            "[Stage1] trying: jefferson",
            event="preprocess_try_tool",
            tool="jefferson",
            firmware=firmware_name,
        )
        proc = _run(["jefferson", "--dest", output_path, firmware_path])
        if proc.returncode == 0:
            _record("jefferson", proc, success=True)
            return _success("jefferson")
        _record("jefferson", proc)

    if fmt in ("ubi", "ubifs"):
        for tool_cmd, method in (
            (["ubireader_extract_images", "-o", output_path, firmware_path], "ubireader_extract_images"),
            (["ubireader_extract_files", "-o", output_path, firmware_path], "ubireader_extract_files"),
        ):
            log_event(
                log,
                logging.DEBUG,
                f"[Stage1] trying: {method}",
                event="preprocess_try_tool",
                tool=method,
                firmware=firmware_name,
            )
            proc = _run(tool_cmd)
            if proc.returncode == 0:
                _record(method, proc, success=True)
                return _success(method)
            _record(method, proc)

    if fmt == "yaffs":
        log_event(
            log,
            logging.DEBUG,
            "[Stage1] trying: unyaffs",
            event="preprocess_try_tool",
            tool="unyaffs",
            firmware=firmware_name,
        )
        proc = _run(["sh", "-c", f"cd '{output_path}' && unyaffs '{firmware_path}'"])
        if proc.returncode == 0:
            _record("unyaffs", proc, success=True)
            return _success("unyaffs")
        _record("unyaffs", proc)

    if fmt in ("cramfs", "romfs"):
        for tool_cmd, method in (
            (["7z", "x", firmware_path, f"-o{output_path}", "-y"], "7z x"),
            (["binwalk", "-eM", "--directory", output_path, firmware_path], "binwalk -eM"),
        ):
            log_event(
                log,
                logging.DEBUG,
                f"[Stage1] trying: {method}",
                event="preprocess_try_tool",
                tool=method,
                firmware=firmware_name,
            )
            proc = _run(tool_cmd)
            if proc.returncode == 0:
                _record(method, proc, success=True)
                return _success(method)
            _record(method, proc)

    if fmt in ("jffs2", "ubi", "ubifs", "yaffs"):
        log_event(
            log,
            logging.DEBUG,
            "[Stage1] trying: binwalk -eM",
            event="preprocess_try_tool",
            tool="binwalk -eM",
            firmware=firmware_name,
        )
        proc = _run(["binwalk", "-eM", "--directory", output_path, firmware_path])
        if proc.returncode == 0:
            _record("binwalk -eM", proc, success=True)
            return _success("binwalk -eM")
        _record("binwalk -eM", proc)

    log_event(
        log,
        logging.INFO,
        "[Stage1] no tool succeeded",
        event="preprocess_all_fail",
        firmware=firmware_name,
        fmt=fmt,
    )
    stage_entries.append({"step": "result", "success": False, "method": None})
    _write_stage_log(log_dir, stage_entries)
    return {"success": False, "method": None}


def run_quick_preprocess(firmware_path: str, output_path: str, log_dir=None) -> dict:
    """Backward-compatible alias for the Stage 1 deterministic preprocessor."""
    return run_preprocess(firmware_path, output_path, log_dir=log_dir)


__all__ = ["detect_format", "run_preprocess", "run_quick_preprocess"]
