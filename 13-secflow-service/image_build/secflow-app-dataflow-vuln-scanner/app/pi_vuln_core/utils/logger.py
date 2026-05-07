"""
日志配置

两路输出:
- stdout / stderr → 终端实时显示 (不变)
- log_file        → 同时写入当前线程绑定的日志文件

CLI 模式通常是单进程单任务，服务模式则可能同进程并发执行多个任务。
因此这里使用线程级日志分流，避免不同执行互相覆盖 run.log。
"""

import io
import logging
import os
import re
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

import structlog

# ═══════════════════════════════════════
# IO 分流器
# ═══════════════════════════════════════

_ANSI_RE = re.compile(r'\033\[[0-9;]*m')


class TeeStream:
    """
    将写入的内容同时输出到原始流和日志文件.

    - 终端侧: 保留 ANSI 色彩
    - 文件侧: 自动去除 ANSI 转义序列
    """

    def __init__(self, original: io.TextIOBase):
        self._original = original

    def _current_log_file(self) -> io.TextIOBase | None:
        with _log_router_lock:
            return _thread_log_files.get(threading.get_ident())

    def write(self, data: str) -> int:
        if data:
            self._original.write(data)
            log_file = self._current_log_file()
            if log_file is not None:
                # 写文件时去掉 ANSI 色彩码
                clean = _ANSI_RE.sub('', data)
                log_file.write(clean)
                log_file.flush()
        return len(data) if data else 0

    def flush(self):
        self._original.flush()
        log_file = self._current_log_file()
        if log_file is not None:
            log_file.flush()

    # 代理其余属性给原始流 (encoding, fileno, isatty 等)
    def __getattr__(self, name):
        return getattr(self._original, name)


# 全局状态: 当前线程 -> 日志文件
_thread_log_files: dict[int, io.TextIOBase] = {}
_original_stdout: Optional[io.TextIOBase] = None
_original_stderr: Optional[io.TextIOBase] = None
_current_log_level: str = "INFO"
_log_router_lock = threading.RLock()


def _write_log_header(log_file: io.TextIOBase) -> None:
    log_file.write(f"\n{'=' * 70}\n")
    log_file.write(f"  Log started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    log_file.write(f"  PID: {os.getpid()}\n")
    log_file.write(f"  Thread: {threading.current_thread().name}\n")
    log_file.write(f"{'=' * 70}\n\n")
    log_file.flush()


def _write_log_footer(log_file: io.TextIOBase) -> None:
    log_file.write(f"\n{'=' * 70}\n")
    log_file.write(f"  Log ended: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    log_file.write(f"{'=' * 70}\n")
    log_file.flush()


def _install_log_router_if_needed() -> None:
    global _original_stdout, _original_stderr
    if _original_stdout is not None and _original_stderr is not None:
        return
    _original_stdout = sys.stdout
    _original_stderr = sys.stderr
    sys.stdout = TeeStream(sys.stdout)
    sys.stderr = TeeStream(sys.stderr)
    setup_logging(_current_log_level)


def _uninstall_log_router_if_possible() -> None:
    global _original_stdout, _original_stderr
    if _thread_log_files:
        return
    if _original_stdout is not None:
        sys.stdout = _original_stdout
        _original_stdout = None
    if _original_stderr is not None:
        sys.stderr = _original_stderr
        _original_stderr = None
    setup_logging(_current_log_level)


def attach_log_file(log_path: str) -> str:
    """
    开始将当前线程的 stdout + stderr 同时写入日志文件.

    Args:
        log_path: 日志文件路径 (自动创建父目录)

    Returns:
        实际日志文件绝对路径
    """
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    log_file = open(path, "a", encoding="utf-8", buffering=1)  # 行缓冲
    _write_log_header(log_file)

    with _log_router_lock:
        thread_id = threading.get_ident()
        previous = _thread_log_files.get(thread_id)
        if previous is not None:
            try:
                _write_log_footer(previous)
                previous.close()
            except Exception:
                pass
        _thread_log_files[thread_id] = log_file
        _install_log_router_if_needed()

    return str(path.resolve())


def detach_log_file() -> None:
    """停止当前线程的日志写入; 当无活跃日志时恢复原始 stdout/stderr."""
    with _log_router_lock:
        log_file = _thread_log_files.pop(threading.get_ident(), None)
        if log_file is not None:
            try:
                _write_log_footer(log_file)
                log_file.close()
            except Exception:
                pass
        _uninstall_log_router_if_possible()


def get_log_file_path() -> Optional[str]:
    """返回当前线程对应的日志文件路径, 未 attach 时返回 None."""
    with _log_router_lock:
        log_file = _thread_log_files.get(threading.get_ident())
        if log_file is not None and hasattr(log_file, "name"):
            return log_file.name
    return None


# ═══════════════════════════════════════
# structlog 配置 (不变)
# ═══════════════════════════════════════

def setup_logging(level: str = "INFO") -> None:
    """初始化 structlog, 输出 JSON 到 stdout"""
    global _current_log_level
    _current_log_level = level.upper()
    log_level = getattr(logging, _current_log_level, logging.INFO)

    try:
        structlog.reset_defaults()
    except Exception:
        pass

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(ensure_ascii=False),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )


def get_logger(name: str = "") -> structlog.stdlib.BoundLogger:
    """获取带名称的 logger"""
    return structlog.get_logger(component=name) if name else structlog.get_logger()
