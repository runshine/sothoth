#!/usr/bin/env python3
"""Deterministic firmware pre-processing helpers."""

from __future__ import annotations

import json
import logging
import os
import subprocess
from pathlib import Path

from logging_utils import log_event

log = logging.getLogger("unpacker.service")


def _write_stage_log(log_dir, stage_entries: list[dict]) -> None:
    if log_dir is None:
        return
    Path(log_dir, "stage1_preprocess.json").write_text(
        json.dumps(stage_entries, indent=2)
    )


def detect_format(firmware_path: str) -> dict:
    """Detect firmware format via magic bytes and file extension."""
    path = Path(firmware_path)
    ext = path.suffix.lower()
    suffixes = path.suffixes
    ext2 = "".join(suffixes[-2:]).lower() if len(suffixes) >= 2 else ext
    fmt = None
    magic = b""
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
    )
    return {"fmt": fmt, "ext": ext, "ext2": ext2, "magic": magic}


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
