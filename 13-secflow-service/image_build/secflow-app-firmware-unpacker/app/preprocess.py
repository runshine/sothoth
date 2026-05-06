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
            magic = fh.read(16)
        if magic[:2] == b"\x1f\x8b":
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
        elif ext in (".squashfs", ".sqfs", ".sfs"):
            fmt = "squashfs"
        elif ext == ".cpio":
            fmt = "cpio"
        elif ext == ".7z":
            fmt = "7zip"

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
        log_event(
            log,
            logging.DEBUG,
            "[Stage1] trying: gzip -dc",
            event="preprocess_try_tool",
            tool="gzip -dc",
            firmware=firmware_name,
        )
        out = os.path.join(output_path, Path(firmware_path).stem)
        proc = _run(["sh", "-c", f"gzip -dc '{firmware_path}' > '{out}'"])
        if proc.returncode == 0 and os.path.exists(out) and os.path.getsize(out) > 0:
            _record(
                "gzip -dc",
                proc,
                success=True,
                extra={"output_file": out, "size": os.path.getsize(out)},
            )
            log_event(
                log,
                logging.INFO,
                "[Stage1] gzip -dc succeeded",
                event="preprocess_tool_success",
                tool="gzip -dc",
                output_file=out,
                size=os.path.getsize(out),
            )
            result = {"success": True, "method": "gzip -dc"}
            stage_entries.append({"step": "result", "success": True, "method": "gzip -dc"})
            _write_stage_log(log_dir, stage_entries)
            return result
        _record("gzip -dc", proc)
        log_event(
            log,
            logging.DEBUG,
            "[Stage1] gzip -dc failed",
            event="preprocess_tool_fail",
            tool="gzip -dc",
            returncode=proc.returncode,
        )

    if fmt == "bzip2":
        log_event(
            log,
            logging.DEBUG,
            "[Stage1] trying: bzip2 -dc",
            event="preprocess_try_tool",
            tool="bzip2 -dc",
            firmware=firmware_name,
        )
        out = os.path.join(output_path, Path(firmware_path).stem)
        proc = _run(["sh", "-c", f"bzip2 -dc '{firmware_path}' > '{out}'"])
        if proc.returncode == 0 and os.path.exists(out) and os.path.getsize(out) > 0:
            _record("bzip2 -dc", proc, success=True)
            return _success("bzip2 -dc")
        _record("bzip2 -dc", proc)
        log_event(
            log,
            logging.DEBUG,
            "[Stage1] bzip2 -dc failed",
            event="preprocess_tool_fail",
            tool="bzip2 -dc",
            returncode=proc.returncode,
        )

    if fmt == "xz":
        log_event(
            log,
            logging.DEBUG,
            "[Stage1] trying: xz -dc",
            event="preprocess_try_tool",
            tool="xz -dc",
            firmware=firmware_name,
        )
        out = os.path.join(output_path, Path(firmware_path).stem)
        proc = _run(["sh", "-c", f"xz -dc '{firmware_path}' > '{out}'"])
        if proc.returncode == 0 and os.path.exists(out) and os.path.getsize(out) > 0:
            _record("xz -dc", proc, success=True)
            return _success("xz -dc")
        _record("xz -dc", proc)
        log_event(
            log,
            logging.DEBUG,
            "[Stage1] xz -dc failed",
            event="preprocess_tool_fail",
            tool="xz -dc",
            returncode=proc.returncode,
        )

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
