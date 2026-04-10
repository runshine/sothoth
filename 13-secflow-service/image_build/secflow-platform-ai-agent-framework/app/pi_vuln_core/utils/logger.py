"""日志配置 — structlog → stdout (K8S JOB 标准实践)"""

import logging
import sys
import structlog


def setup_logging(level: str = "INFO") -> None:
    """初始化 structlog，输出 JSON 到 stdout"""
    log_level = getattr(logging, level.upper(), logging.INFO)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = "") -> structlog.stdlib.BoundLogger:
    """获取带名称的 logger"""
    return structlog.get_logger(component=name) if name else structlog.get_logger()
