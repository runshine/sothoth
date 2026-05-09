"""Retry helpers for single-shot review advisor calls."""

from __future__ import annotations

from typing import Any

from app.pi_vuln_core.agents.models import AgentResponse


DEFAULT_REVIEW_RUNTIME_RETRIES = 0

_RETRYABLE_REVIEW_ERROR_CODES = {
    "runtime_timeout",
}

_RETRYABLE_REVIEW_ERROR_PATTERNS = (
    "no-progress timeout",
    "max wall clock",
    "timed out",
    "timeout",
)


def review_runtime_retry_limit(agent: Any) -> int:
    """Return per-review runtime retry budget; default is no fresh-session retry."""
    runtime_config = getattr(agent, "runtime_config", {}) or {}
    raw_value = runtime_config.get(
        "review_runtime_retries",
        runtime_config.get(
            "advisor_runtime_retries",
            runtime_config.get("advisor_timeout_retries", DEFAULT_REVIEW_RUNTIME_RETRIES),
        ),
    )
    try:
        return max(0, int(raw_value))
    except (TypeError, ValueError):
        return DEFAULT_REVIEW_RUNTIME_RETRIES


def is_retryable_review_runtime_error(response: AgentResponse) -> bool:
    """True when a single-shot review advisor should be retried in a fresh session."""
    if response.success:
        return False
    metadata = response.metadata or {}
    if metadata.get("timeout_retry_exhausted"):
        return False
    error_code = str(response.error_code or "").strip().lower()
    if error_code in _RETRYABLE_REVIEW_ERROR_CODES:
        return True
    error_text = str(response.error or "").lower()
    return any(pattern in error_text for pattern in _RETRYABLE_REVIEW_ERROR_PATTERNS)


def retry_session_hint(base_hint: str, retry_index: int) -> str:
    """Build a deterministic fresh-session hint for retry N, where N starts at 1."""
    base = str(base_hint or "review_advisor").strip() or "review_advisor"
    return f"{base}_retry_{retry_index:03d}"


def append_retry_summary(feedback: str, *, retries_used: int, retry_limit: int) -> str:
    if retries_used <= 0:
        return feedback
    suffix = f"[review_runtime_retries] 已换新 session 重试 {retries_used}/{retry_limit} 次。"
    return f"{feedback}\n\n{suffix}" if feedback else suffix
