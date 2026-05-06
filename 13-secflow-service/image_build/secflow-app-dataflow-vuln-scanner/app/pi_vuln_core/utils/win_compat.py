"""
Windows / Git Bash 兼容性工具

解决以下平台差异：
  - subprocess: Windows 上 npm/node CLI 工具通常是 .cmd 文件，需要 shell 执行
  - encoding: Windows 默认编码可能不是 UTF-8
  - rmtree: Windows 文件锁定和只读文件删除
  - path: Git Bash MSYS 路径自动转换
  - asyncio: Windows 需要 ProactorEventLoop 支持子进程
"""

from __future__ import annotations

import asyncio
import os
import platform
import re
import shutil
import stat
import sys
from pathlib import Path
from typing import Any, Optional

IS_WINDOWS = platform.system() == "Windows"


# ─────────────────────────────────────────────────
# Subprocess
# ─────────────────────────────────────────────────

async def create_subprocess(
    *args: str,
    stdout: Any = asyncio.subprocess.PIPE,
    stderr: Any = asyncio.subprocess.PIPE,
    cwd: Optional[str] = None,
    env: Optional[dict[str, str]] = None,
    **kwargs: Any,
) -> asyncio.subprocess.Process:
    """跨平台创建子进程。

    Windows 上 npm/node 安装的 CLI 工具通常是 .cmd/.bat 文件，
    必须通过 shell 执行。Linux/macOS 直接 exec。
    """
    if IS_WINDOWS:
        from subprocess import list2cmdline
        cmd_line = list2cmdline(args)
        return await asyncio.create_subprocess_shell(
            cmd_line,
            stdout=stdout,
            stderr=stderr,
            cwd=cwd,
            env=env,
            **kwargs,
        )
    else:
        return await asyncio.create_subprocess_exec(
            *args,
            stdout=stdout,
            stderr=stderr,
            cwd=cwd,
            env=env,
            **kwargs,
        )


def find_cli_command(name: str) -> list[str]:
    """查找 CLI 命令的可执行路径。

    Windows 上优先查找 .cmd/.bat 包装器（npm 全局安装的标准形式）。
    Git Bash 中 shutil.which 能正确处理 PATH。
    """
    path = shutil.which(name)
    if path:
        return [path]

    if IS_WINDOWS:
        for ext in (".cmd", ".bat", ".exe"):
            path = shutil.which(name + ext)
            if path:
                return [path]

    raise FileNotFoundError(f"CLI command not found: {name}")


# ─────────────────────────────────────────────────
# File I/O
# ─────────────────────────────────────────────────

def safe_open(path: str | Path, mode: str = "r", **kwargs: Any):
    """打开文件，默认 UTF-8 编码。"""
    if "b" not in mode and "encoding" not in kwargs:
        kwargs["encoding"] = "utf-8"
    return open(path, mode, **kwargs)


def safe_read_text(path: str | Path) -> str:
    """读取文本文件，强制 UTF-8。"""
    return Path(path).read_text(encoding="utf-8")


def safe_write_text(path: str | Path, content: str) -> None:
    """写入文本文件，强制 UTF-8，使用 LF 换行。"""
    Path(path).write_text(content, encoding="utf-8", newline="\n")


# ─────────────────────────────────────────────────
# rmtree
# ─────────────────────────────────────────────────

def _on_rm_error(func, path, exc_info):
    """rmtree onerror handler: 处理 Windows 只读文件。"""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


def safe_rmtree(path: str | Path, ignore_errors: bool = True) -> None:
    """跨平台安全删除目录树。

    Windows 上文件可能被锁定或标记为只读，需要特殊处理。
    即使调用方希望忽略错误，也先尝试 onerror 修复只读权限。
    """
    p = Path(path)
    if not p.exists():
        return
    try:
        shutil.rmtree(str(p), ignore_errors=False, onerror=_on_rm_error)
    except Exception:
        if not ignore_errors:
            raise


# ─────────────────────────────────────────────────
# Path normalization
# ─────────────────────────────────────────────────

_MSYS_DRIVE_RE = re.compile(r"^/([a-zA-Z])(?:/|$)")


def from_msys_path(path: str | Path | None) -> str | None:
    """将 Git Bash/MSYS 风格路径转换为 Windows 原生路径。

    Git Bash 通常会自动转换命令行参数，但不会转换 JSON 配置文件里的路径。
    例如 `/c/Users/me/a.txt` -> `C:/Users/me/a.txt`。
    """
    if path is None:
        return None
    s = str(path)
    if not IS_WINDOWS:
        return s
    match = _MSYS_DRIVE_RE.match(s)
    if not match:
        return s
    drive = match.group(1).upper()
    rest = s[3:] if len(s) > 2 else ""
    return f"{drive}:/{rest}" if rest else f"{drive}:/"


def normalize_path(path: str | Path) -> str:
    """规范化路径，确保跨平台一致性。"""
    return str(Path(from_msys_path(path) or path).resolve())


def to_posix_path(path: str | Path) -> str:
    """将路径转换为 POSIX 格式（用于 shell 命令参数/展示）。"""
    return str(Path(path)).replace("\\", "/")


# ─────────────────────────────────────────────────
# asyncio event loop
# ─────────────────────────────────────────────────

def ensure_event_loop_policy() -> None:
    """确保 Windows 上使用 ProactorEventLoop（支持子进程）。

    Python 3.8+ Windows 默认已使用 ProactorEventLoop，
    但某些库可能会切换到 SelectorEventLoop，导致子进程创建失败。
    """
    if IS_WINDOWS and sys.version_info >= (3, 8):
        try:
            policy = asyncio.get_event_loop_policy()
            if not isinstance(policy, asyncio.WindowsProactorEventLoopPolicy):
                asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        except AttributeError:
            pass  # Non-Windows or missing policy class


# ─────────────────────────────────────────────────
# Process cleanup
# ─────────────────────────────────────────────────

async def safe_terminate_process(proc: asyncio.subprocess.Process, timeout: float = 5.0) -> None:
    """跨平台安全终止子进程。

    Windows 没有 SIGTERM，terminate() 和 kill() 都发送 TerminateProcess。
    """
    if proc.returncode is not None:
        return
    try:
        proc.terminate()
        await asyncio.wait_for(proc.wait(), timeout=timeout)
    except (ProcessLookupError, asyncio.TimeoutError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
