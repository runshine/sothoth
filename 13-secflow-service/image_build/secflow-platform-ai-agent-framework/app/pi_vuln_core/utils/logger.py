"""
日志配置

两路输出:
- stdout / stderr → 终端实时显示 (不变)
- log_file        → 同时写入日志文件 (新增)

通过 TeeStream 在进程级别做 IO 分流,
不需要框架内部任何模块感知日志文件的存在.
"""

import io
import logging
import os
import re
import sys
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

    def __init__(self, original: io.TextIOBase, log_file: io.TextIOBase):
        self._original = original
        self._log_file = log_file

    def write(self, data: str) -> int:
        if data:
            self._original.write(data)
            # 写文件时去掉 ANSI 色彩码
            clean = _ANSI_RE.sub('', data)
            self._log_file.write(clean)
            self._log_file.flush()
        return len(data) if data else 0

    def flush(self):
        self._original.flush()
        self._log_file.flush()

    # 代理其余属性给原始流 (encoding, fileno, isatty 等)
    def __getattr__(self, name):
        return getattr(self._original, name)


# 全局状态: 记录当前日志文件, 便于 detach
_active_log_file: Optional[io.TextIOBase] = None
_original_stdout: Optional[io.TextIOBase] = None
_original_stderr: Optional[io.TextIOBase] = None
_current_log_level: str = "INFO"


def attach_log_file(log_path: str) -> str:
    """
    开始将 stdout + stderr 同时写入日志文件.

    Args:
        log_path: 日志文件路径 (自动创建父目录)

    Returns:
        实际日志文件绝对路径
    """
    global _active_log_file, _original_stdout, _original_stderr

    # 如果已经 attach 了, 先 detach
    if _active_log_file is not None:
        detach_log_file()

    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    log_file = open(path, "a", encoding="utf-8", buffering=1)  # 行缓冲

    # 写入日志头
    log_file.write(f"\n{'=' * 70}\n")
    log_file.write(f"  Log started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    log_file.write(f"  PID: {os.getpid()}\n")
    log_file.write(f"{'=' * 70}\n\n")
    log_file.flush()

    _active_log_file = log_file
    _original_stdout = sys.stdout
    _original_stderr = sys.stderr

    sys.stdout = TeeStream(sys.stdout, log_file)
    sys.stderr = TeeStream(sys.stderr, log_file)
    setup_logging(_current_log_level)

    return str(path.resolve())


def detach_log_file() -> None:
    """停止写入日志文件, 恢复原始 stdout/stderr."""
    global _active_log_file, _original_stdout, _original_stderr

    if _original_stdout is not None:
        sys.stdout = _original_stdout
        _original_stdout = None
    if _original_stderr is not None:
        sys.stderr = _original_stderr
        _original_stderr = None
    if _active_log_file is not None:
        try:
            _active_log_file.write(f"\n{'=' * 70}\n")
            _active_log_file.write(
                f"  Log ended: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            _active_log_file.write(f"{'=' * 70}\n")
            _active_log_file.close()
        except Exception:
            pass
        _active_log_file = None
    setup_logging(_current_log_level)


def get_log_file_path() -> Optional[str]:
    """返回当前日志文件路径, 未 attach 时返回 None."""
    if _active_log_file is not None and hasattr(_active_log_file, 'name'):
        return _active_log_file.name
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
