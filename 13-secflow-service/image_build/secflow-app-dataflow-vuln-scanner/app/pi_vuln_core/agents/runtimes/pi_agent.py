"""
Pi Agent 运行时适配 (跨平台: Linux / Windows)

命令格式:
  RPC 模式 (当前默认):
    pi --mode rpc --model <provider/model> --thinking <level>
       --append-system-prompt sys.md --session-dir <dir>
       --tools read,bash,edit,write
    user_prompt 内容随后通过 stdin JSONL RPC prompt 消息发送。

  JSON 模式:
    pi --mode json --model <provider/model> -p --thinking <level>
       --append-system-prompt sys.md --session-dir <dir>
       --tools read,bash,edit,write @user.md

  JSON 模式续接调用 (同 session 的后续消息):
    pi --mode json --model <provider/model> -p --thinking <level>
       --session-dir <dir> --continue
       --tools read,bash,edit,write @user.md

关键设计:
  - --model 使用 provider/model 格式, 不再传独立 --provider
  - RPC 模式复用长驻 pi 进程, 通过 stdin/stdout JSONL 协议传递 prompt 和读取事件
  - RPC prompt 超时只接受 Pi/provider 原生 timeout 结果; 框架不再做 client-side no-progress / wall-clock 截断, 后续重试继续向同一会话发送 prompt
  - JSON 模式从 JSON Lines 的 message_end 事件提取 assistant 文本
  - system_prompt 通过 --append-system-prompt file 追加到 pi 内置提示词 (仅首次)
  - RPC 模式 user_message 通过 prompt RPC 消息传入; JSON 模式通过 @file 传入
  - 续接调用通过 --continue 加载已有会话上下文, 不重复传 system_prompt
  - Linux: create_subprocess_exec (直接执行)
  - Windows: create_subprocess_shell (处理 .cmd 文件)
  - 双层重试: API 级错误重试 + pi 进程级错误重试
  - 统一 trace: 每次逻辑调用都在 sessions/<session_id>/calls/ 下落盘命令、prompt、stdout/stderr、解析响应
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import platform
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from app.pi_vuln_core.agents.base import BaseAgentRuntime
from app.pi_vuln_core.agents.models import AgentResponse
from app.pi_vuln_core.agents.runtime_trace import RuntimeTraceContext, command_display, now_iso
from app.pi_vuln_core.utils.file_ops import write_json
from app.pi_vuln_core.utils.logger import get_logger

logger = get_logger("runtime.pi_agent")

IS_WINDOWS = platform.system() == "Windows"
_MAX_BACKOFF_SECONDS = 300.0
_DEFAULT_MAX_STDOUT_BYTES = 64 * 1024 * 1024
_DEFAULT_MAX_STDERR_BYTES = 8 * 1024 * 1024
_DEFAULT_MAX_RESPONSE_BYTES = 32 * 1024 * 1024
_DEFAULT_RPC_STDOUT_TRACE_BYTES = 4 * 1024 * 1024
_DEFAULT_MAX_RPC_LINE_BYTES = 64 * 1024 * 1024
_DEFAULT_MAX_PARSED_EVENTS = 20_000
_DEFAULT_MAX_PARSED_MESSAGES = 1_000
_DEFAULT_MAX_NON_JSON_LINES = 200
_DEFAULT_NO_PROGRESS_TIMEOUT_SECONDS = 600.0
_DEFAULT_MAX_WALL_SECONDS = 4 * 60 * 60
_DEFAULT_MAX_RETRY_WALL_SECONDS = 4 * 60 * 60
_DEFAULT_HEARTBEAT_INTERVAL_SECONDS = 30.0
_DEFAULT_TIMEOUT_MAX_RETRIES = 3
_DEFAULT_TIMEOUT_RETRY_INTERVAL_SECONDS = 30.0
_TERMINAL_ERROR_CODES = {
    "runtime_output_limit",
    "runtime_turn_limit",
    "runtime_timeout",
    "blocked_context_window",
    "blocked_quota",
    "provider_auth_failed",
    "model_contract_violation",
    "runtime_launch_failed",
}

_FATAL_PATTERNS: tuple[tuple[str, ...], ...] = (
    ("model", "not found"),
    ("not found", "use --list"),
    ("invalid", "model"),
    ("invalid", "api key"),
    ("invalid", "api_key"),
    ("unauthorized",),
    ("authentication", "failed"),
    ("401",),
    ("403", "forbidden"),
    ("does not exist",),
    ("cannot find module",),
    ("syntax error",),
    ("syntaxerror",),
)

_RETRYABLE_API_PATTERNS: tuple[str, ...] = (
    "connection", "timeout", "timed out", "econnrefused", "econnreset",
    "etimedout", "enotfound", "socket hang up", "fetch failed",
    "rate limit", "429", "503", "502", "500",
    "overloaded", "capacity", "temporarily unavailable",
    "server error", "internal error", "bad gateway",
    "service unavailable", "request failed",
)

_PI_FAILURE_PATTERNS: tuple[str, ...] = (
    "segfault", "segmentation fault", "killed", "oom", "out of memory",
    "cannot allocate", "spawn", "enoent", "eacces", "eperm",
    "no such file", "permission denied", "abnormal", "core dump",
    "bus error", "illegal instruction", "referenceerror", "typeerror",
    "rangeerror", "heap out of memory", "allocation failed",
    "fatal error", "javascript heap", "execvp",
)


@dataclass
class _ParsedJsonOutput:
    content: str = ""
    events: list[dict[str, Any]] = field(default_factory=list)
    messages: list[dict[str, Any]] = field(default_factory=list)
    token_usage: dict[str, int] = field(default_factory=dict)
    error: Optional[str] = None
    saw_json: bool = False
    saw_agent_end: bool = False
    non_json_lines: list[str] = field(default_factory=list)
    max_events: int = _DEFAULT_MAX_PARSED_EVENTS
    max_messages: int = _DEFAULT_MAX_PARSED_MESSAGES
    max_non_json_lines: int = _DEFAULT_MAX_NON_JSON_LINES
    total_event_count: int = 0
    events_truncated_count: int = 0
    messages_truncated_count: int = 0
    non_json_truncated_count: int = 0


@dataclass
class _AttemptResult:
    stdout_text: str = ""
    stderr_text: str = ""
    response_text: str = ""
    return_code: Optional[int] = None
    duration_ms: Optional[int] = None
    parsed: _ParsedJsonOutput = field(default_factory=_ParsedJsonOutput)
    error: Optional[str] = None
    status: str = "completed"
    timeout: bool = False
    launch_error: bool = False
    error_code: str = ""
    stdout_total_bytes: int = 0
    stderr_total_bytes: int = 0
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    stdout_soft_limit_exceeded: bool = False
    internal_turns: int = 0


class _RuntimeOutputLimitError(RuntimeError):
    """Raised when a child process exceeds framework runtime output limits."""


class _RuntimeTurnLimitError(RuntimeError):
    """Raised when a child process exceeds the profile internal-turn budget."""


class _NoProgressTimeoutError(TimeoutError):
    """Raised when a child process produces no readable output for too long."""


class _BoundedBytesBuffer:
    def __init__(self, limit_bytes: int):
        self.limit_bytes = max(0, int(limit_bytes))
        self.parts: list[bytes] = []
        self.total_bytes = 0
        self.truncated = False

    def append(self, chunk: bytes) -> None:
        if not chunk:
            return
        self.total_bytes += len(chunk)
        retained = sum(len(part) for part in self.parts)
        remaining = self.limit_bytes - retained
        if remaining > 0:
            self.parts.append(chunk[:remaining])
        if len(chunk) > max(0, remaining):
            self.truncated = True

    def text(self) -> str:
        text = b"".join(self.parts).decode("utf-8", errors="replace")
        if self.truncated:
            text += (
                "\n\n[runtime output truncated: original_bytes="
                f"{self.total_bytes}, retained_bytes={self.limit_bytes}]\n"
            )
        return text


class PiAgentRuntime(BaseAgentRuntime):
    """Pi Coding Agent CLI 运行时 (跨平台)"""

    async def initialize(self) -> None:
        try:
            if IS_WINDOWS:
                proc = await asyncio.create_subprocess_shell(
                    "pi --version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            else:
                proc = await asyncio.create_subprocess_exec(
                    "pi",
                    "--version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                logger.info(
                    "pi_cli_available",
                    version=stdout.decode().strip(),
                    agent_id=self.agent_id,
                    platform=platform.system(),
                )
            else:
                logger.warning(
                    "pi_cli_not_found",
                    agent_id=self.agent_id,
                    platform=platform.system(),
                    error=stderr.decode("utf-8", errors="replace")[:300],
                )
        except FileNotFoundError:
            logger.warning("pi_cli_not_found", agent_id=self.agent_id)
        self._initialized = True

    async def create_session(self) -> str:
        session_id = f"pi_{uuid.uuid4().hex[:12]}"
        self._sessions[session_id] = {"turns": 0}
        return session_id

    async def create_session_with_hint(self, session_hint: Optional[str] = None) -> str:
        if not session_hint:
            return await self.create_session()
        session_id = self._reserve_session_id(session_hint)
        self._sessions[session_id] = {"turns": 0}
        return session_id

    def _count_completed_turns_on_disk(
        self,
        session_id: str,
        working_dir: Optional[str],
    ) -> int:
        if not working_dir:
            return 0

        calls_dir = Path(working_dir).resolve() / "sessions" / session_id / "calls"
        if not calls_dir.is_dir():
            return 0

        turns = 0
        for call_dir in sorted(p for p in calls_dir.iterdir() if p.is_dir()):
            response_path = call_dir / "response.json"
            if not response_path.is_file():
                continue
            try:
                payload = json.loads(response_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if str(payload.get("status") or "").strip() == "completed":
                turns += 1
        return turns

    def _restore_session_from_disk(
        self,
        session_id: str,
        working_dir: Optional[str],
    ) -> dict:
        disk_turns = self._count_completed_turns_on_disk(session_id, working_dir)
        calls_dir = (
            Path(working_dir).resolve() / "sessions" / session_id / "calls"
            if working_dir else None
        )

        session = self._sessions.get(session_id)
        if session is not None:
            if disk_turns > int(session.get("turns", 0)):
                session["turns"] = disk_turns
                logger.info(
                    "pi_session_restored_from_disk",
                    agent_id=self.agent_id,
                    session_id=session_id,
                    turns=disk_turns,
                    calls_dir=str(calls_dir) if calls_dir else "",
                )
            return session

        if disk_turns > 0:
            logger.info(
                "pi_session_restored_from_disk",
                agent_id=self.agent_id,
                session_id=session_id,
                turns=disk_turns,
                calls_dir=str(calls_dir) if calls_dir else "",
            )

        session = {"turns": disk_turns}
        self._sessions[session_id] = session
        return session

    @staticmethod
    def _backoff(base_delay: float, attempt: int) -> float:
        return min(float(base_delay) * (2 ** max(0, attempt - 1)), _MAX_BACKOFF_SECONDS)

    def _runtime_int(self, key: str, default: int) -> int:
        value = self.runtime_config.get(key)
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return default
        return parsed if parsed >= 0 else default

    def _runtime_float(self, key: str, default: float) -> float:
        value = self.runtime_config.get(key)
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            return default
        return parsed if parsed > 0 else default

    def _runtime_retry_count(self, key: str, default: int) -> int:
        value = self.runtime_config.get(key)
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _normalize_framework_retry_count(value: Any, default: int, *, allow_unbounded: bool) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return default
        if parsed < 0 and not allow_unbounded:
            return default
        return parsed

    def _runtime_non_negative_float(self, key: str, default: float) -> float:
        value = self.runtime_config.get(key)
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            return default
        return parsed if parsed >= 0 else default

    def _runtime_bool(self, key: str, default: bool = True) -> bool:
        value = self.runtime_config.get(key)
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"1", "true", "yes", "on"}:
                return True
            if normalized in {"0", "false", "no", "off"}:
                return False
        return default

    @staticmethod
    async def _terminate_process(proc, *, grace_seconds: float = 5.0) -> None:
        if proc is None or getattr(proc, "returncode", None) is not None:
            return
        with contextlib.suppress(ProcessLookupError):
            proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=grace_seconds)
            return
        except Exception:
            pass
        with contextlib.suppress(Exception):
            proc.kill()
        with contextlib.suppress(Exception):
            await proc.wait()

    @staticmethod
    def _write_call_heartbeat(
        call_dir: str,
        *,
        status: str,
        detail: dict[str, Any] | None = None,
    ) -> None:
        if not call_dir:
            return
        try:
            write_json(
                Path(call_dir) / "heartbeat.json",
                {
                    "timestamp": now_iso(),
                    "status": status,
                    "detail": detail or {},
                },
            )
        except Exception:
            logger.debug("runtime_heartbeat_write_failed", call_dir=call_dir, status=status)

    @staticmethod
    def _enforce_wall_clock(started_monotonic: float, max_wall_seconds: float) -> None:
        elapsed = time.monotonic() - started_monotonic
        if elapsed > max_wall_seconds:
            raise _NoProgressTimeoutError(
                f"runtime max wall clock exceeded after {elapsed:.1f}s "
                f"(limit={max_wall_seconds:.1f}s)"
            )

    @staticmethod
    def _should_retry(failure_count: int, max_retries: int) -> bool:
        if max_retries < 0:
            return True
        return failure_count <= max_retries

    @staticmethod
    def _extract_text_from_message(message: dict[str, Any]) -> str:
        content = message.get("content") or []
        parts: list[str] = []
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            for block in content:
                if isinstance(block, str):
                    parts.append(block)
                elif isinstance(block, dict):
                    if block.get("type") == "text" and isinstance(block.get("text"), str):
                        parts.append(block["text"])
                    elif isinstance(block.get("content"), str):
                        parts.append(block["content"])
        return "\n".join(part for part in parts if part)

    @staticmethod
    def _merge_usage(target: dict[str, int], usage: dict[str, Any]) -> None:
        mapping = {
            "input": "input",
            "output": "output",
            "cacheRead": "cache_read",
            "cacheWrite": "cache_write",
        }
        for src, dst in mapping.items():
            val = usage.get(src, 0)
            if isinstance(val, (int, float)):
                target[dst] = int(target.get(dst, 0) + val)

    @classmethod
    def _compact_trace_value(
        cls,
        value: Any,
        *,
        max_string_chars: int = 2048,
        max_items: int = 20,
        max_depth: int = 4,
    ) -> Any:
        if max_depth <= 0:
            text = str(value)
            return {
                "summary": text[:max_string_chars],
                "summary_truncated": len(text) > max_string_chars,
                "summary_chars": len(text),
            }
        if isinstance(value, str):
            if len(value) <= max_string_chars:
                return value
            return {
                "preview": value[:max_string_chars],
                "truncated": True,
                "original_chars": len(value),
                "retained_chars": max_string_chars,
            }
        if isinstance(value, list):
            items = [
                cls._compact_trace_value(
                    item,
                    max_string_chars=max_string_chars,
                    max_items=max_items,
                    max_depth=max_depth - 1,
                )
                for item in value[:max_items]
            ]
            if len(value) > max_items:
                items.append({
                    "truncated": True,
                    "omitted_items": len(value) - max_items,
                    "original_items": len(value),
                })
            return items
        if isinstance(value, dict):
            compact: dict[str, Any] = {}
            for idx, (key, item) in enumerate(value.items()):
                if idx >= max_items:
                    compact["_trace_truncated_keys"] = len(value) - max_items
                    break
                compact[str(key)] = cls._compact_trace_value(
                    item,
                    max_string_chars=max_string_chars,
                    max_items=max_items,
                    max_depth=max_depth - 1,
                )
            return compact
        return value

    @staticmethod
    def _json_char_len(value: Any) -> int:
        try:
            return len(json.dumps(value, ensure_ascii=False))
        except (TypeError, ValueError):
            return len(str(value))

    @classmethod
    def _compact_rpc_delta_event(cls, event: dict[str, Any]) -> dict[str, Any]:
        compact: dict[str, Any] = {"type": event.get("type")}
        ame = event.get("assistantMessageEvent")
        if isinstance(ame, dict):
            compact_ame: dict[str, Any] = {
                "type": ame.get("type"),
                "contentIndex": ame.get("contentIndex"),
            }
            for key in ("delta", "partialArgs"):
                if key in ame:
                    compact_ame[key] = cls._compact_trace_value(
                        ame.get(key),
                        max_string_chars=512,
                        max_items=8,
                        max_depth=2,
                    )
            partial = ame.get("partial")
            if partial is not None:
                compact_ame["partial_summary"] = {
                    "json_chars": cls._json_char_len(partial),
                    "keys": sorted(partial.keys()) if isinstance(partial, dict) else None,
                }
                if isinstance(partial, dict):
                    for key in ("role", "api", "provider", "model", "stopReason", "responseId"):
                        if key in partial:
                            compact_ame["partial_summary"][key] = partial.get(key)
                    usage = partial.get("usage")
                    if isinstance(usage, dict):
                        compact_ame["partial_summary"]["usage"] = usage
            compact["assistantMessageEvent"] = compact_ame
        if "message" in event:
            compact["message_summary"] = {
                "json_chars": cls._json_char_len(event.get("message")),
            }
        return compact

    @classmethod
    def _compact_trace_event(cls, event: dict[str, Any]) -> dict[str, Any]:
        """Return a bounded-size copy suitable for trace artifacts.

        Pi RPC emits thousands of ``message_update`` events. Those records can
        contain the entire growing partial assistant message, so retaining them
        verbatim turns a normal long analysis into tens of megabytes of trace
        JSON. Parsing still uses the original event; only the stored artifact is
        compacted.
        """
        if event.get("type") == "message_update":
            return cls._compact_rpc_delta_event(event)
        return cls._compact_trace_value(
            event,
            max_string_chars=4096,
            max_items=40,
            max_depth=5,
        )

    @classmethod
    def _process_json_line(cls, raw_line: str, parsed: _ParsedJsonOutput) -> None:
        """解析单行 JSON 事件，更新 parsed 状态（流式逐行调用）。"""
        line = raw_line.strip()
        if not line:
            return
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            if len(parsed.non_json_lines) < parsed.max_non_json_lines:
                parsed.non_json_lines.append(raw_line)
            else:
                parsed.non_json_truncated_count += 1
            return
        if not isinstance(event, dict):
            return

        parsed.saw_json = True
        parsed.total_event_count += 1
        if len(parsed.events) < parsed.max_events:
            parsed.events.append(cls._compact_trace_event(event))
        else:
            parsed.events_truncated_count += 1
        etype = event.get("type")

        if etype == "agent_end":
            parsed.saw_agent_end = True

        if etype == "response" and event.get("command") == "prompt" and not event.get("success", True):
            parsed.error = str(event.get("error") or "Prompt failed")

        if etype == "message_end" and isinstance(event.get("message"), dict):
            msg = event["message"]
            if len(parsed.messages) >= parsed.max_messages:
                parsed.messages.pop(0)
                parsed.messages_truncated_count += 1
            parsed.messages.append(msg)
            if msg.get("role") == "assistant":
                usage = msg.get("usage") or {}
                if isinstance(usage, dict):
                    cls._merge_usage(parsed.token_usage, usage)
                if msg.get("stopReason") == "error":
                    parsed.error = str(msg.get("errorMessage") or "API error")

    @classmethod
    def _finalize_parsed(cls, parsed: _ParsedJsonOutput) -> None:
        """流式读取结束后，提取最终 assistant 文本内容。"""
        for msg in reversed(parsed.messages):
            if msg.get("role") == "assistant":
                parsed.content = cls._extract_text_from_message(msg)
                break
        if not parsed.content and not parsed.saw_json and parsed.non_json_lines:
            parsed.content = "\n".join(parsed.non_json_lines).strip()

    @classmethod
    def _parse_json_stdout(cls, stdout_text: str) -> _ParsedJsonOutput:
        """一次性解析完整 stdout（兼容非流式场景和测试）。"""
        parsed = _ParsedJsonOutput()
        for raw_line in stdout_text.splitlines():
            cls._process_json_line(raw_line, parsed)
        cls._finalize_parsed(parsed)
        return parsed

    @classmethod
    def _classify_error_code(
        cls,
        error: Optional[str],
        *,
        status: str = "",
    ) -> str:
        text = f"{status} {error or ''}".lower()
        if not text.strip():
            return ""
        if "runtime_turn_limit" in text or "internal turn limit" in text:
            return "runtime_turn_limit"
        if "runtime_output_limit" in text or "stdout limit" in text or "output limit" in text:
            return "runtime_output_limit"
        if "no-progress timeout" in text or "max wall clock" in text or "timeout" in text or "timed out" in text:
            return "runtime_timeout"
        if (
            "contextwindowexceeded" in text
            or "context window" in text
            or "maximum context" in text
            or "context length" in text
            or "too many tokens" in text
            or "token limit" in text
        ):
            return "blocked_context_window"
        if (
            "quota" in text
            or "insufficient_quota" in text
            or "credit" in text
            or "billing" in text
            or ("403" in text and ("limit" in text or "capacity" in text))
        ):
            return "blocked_quota"
        if (
            "rate limit" in text
            or "429" in text
            or "too many requests" in text
            or "temporarily unavailable" in text
            or "overloaded" in text
        ):
            return "provider_rate_limited"
        if (
            "invalid api key" in text
            or "invalid api_key" in text
            or "unauthorized" in text
            or "authentication" in text
            or "401" in text
            or ("403" in text and "forbidden" in text)
        ):
            return "provider_auth_failed"
        if "schema" in text or "contract" in text:
            return "model_contract_violation"
        if "pi cli 未安装" in text or "launch failed" in text or "enoent" in text:
            return "runtime_launch_failed"
        return "runtime_error"

    @classmethod
    def _is_fatal_error(cls, error: Optional[str]) -> bool:
        if not error:
            return False
        if cls._classify_error_code(error) in {
            "blocked_quota",
            "blocked_context_window",
            "provider_rate_limited",
            "runtime_output_limit",
            "runtime_timeout",
        }:
            return False
        lower = error.lower()
        return any(all(part in lower for part in pattern) for pattern in _FATAL_PATTERNS)

    @classmethod
    def _is_retryable_api_error(cls, error: Optional[str]) -> bool:
        if not error:
            return False
        lower = error.lower()
        return any(pattern in lower for pattern in _RETRYABLE_API_PATTERNS)

    @classmethod
    def _is_pi_process_failure(cls, result: _AttemptResult) -> bool:
        if result.error_code in _TERMINAL_ERROR_CODES:
            return False
        if result.timeout or result.launch_error:
            return True
        if cls._is_retryable_api_error(result.error) or cls._is_fatal_error(result.error):
            return False
        if result.return_code is None:
            return False
        if result.return_code < 0 or result.return_code >= 128:
            return True
        if result.return_code != 0 and not result.parsed.messages and not result.response_text.strip():
            return True
        lower = (result.error or "").lower()
        return any(pattern in lower for pattern in _PI_FAILURE_PATTERNS)

    @classmethod
    def _check_stderr_for_errors(cls, stderr_text: str, parsed: _ParsedJsonOutput) -> None:
        """主动扫描 stderr，检测 pi CLI 自身的致命错误或可重试错误。"""
        if not stderr_text or not stderr_text.strip():
            return
        lower = stderr_text.lower()
        # 致命错误优先
        if any(all(part in lower for part in pattern) for pattern in _FATAL_PATTERNS):
            if not parsed.error:
                parsed.error = stderr_text.strip()[:500]
            return
        # 可重试 API 错误
        if any(pattern in lower for pattern in _RETRYABLE_API_PATTERNS):
            if not parsed.error:
                parsed.error = stderr_text.strip()[:500]
            return
        # pi 进程级错误
        if any(pattern in lower for pattern in _PI_FAILURE_PATTERNS):
            if not parsed.error:
                parsed.error = stderr_text.strip()[:500]

    def _effective_model(self) -> tuple[str, str, str]:
        """返回 (effective_model, raw_model, legacy_provider)。

        新配置应直接把 model 写成 provider/model。为兼容旧配置, 如果 model
        不含 '/', 且 sdk_specific.provider 存在, 只在内部合成为 provider/model，
        但不会再向 pi 传 --provider。
        """
        sdk_cfg = self.runtime_config.get("sdk_specific", {})
        raw_model = str(self.runtime_config.get("model") or "github-copilot/gpt-5-mini").strip()
        legacy_provider = str(sdk_cfg.get("provider") or "").strip()
        if "/" in raw_model or not legacy_provider:
            return raw_model, raw_model, legacy_provider
        return f"{legacy_provider}/{raw_model}", raw_model, legacy_provider

    async def _execute_once(
        self,
        *,
        cmd_args: list[str],
        working_dir: Optional[str],
        session_id: str,
        call_dir: str,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
        max_event_count: int,
        max_single_line_bytes: int,
        max_internal_turns: int,
        no_progress_timeout_seconds: float,
        max_wall_seconds: float,
        heartbeat_interval_seconds: float,
        cancel_event: Optional[asyncio.Event] = None,
    ) -> _AttemptResult:
        """执行一次 pi 子进程。

        启动失败 (FileNotFoundError / OSError) 直接抛出，由调用方捕获并重试。
        """
        started_monotonic = time.monotonic()

        # 启动子进程（异常向上抛，由 send_message 的 launch retry 处理）
        if IS_WINDOWS:
            proc = await asyncio.create_subprocess_shell(
                command_display(cmd_args),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=working_dir,
            )
        else:
            proc = await asyncio.create_subprocess_exec(
                *cmd_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=working_dir,
            )

        # Cancel monitor
        cancel_task: asyncio.Task | None = None
        if cancel_event:
            async def _cancel_monitor():
                await cancel_event.wait()
                try:
                    proc.terminate()
                except ProcessLookupError:
                    pass
            cancel_task = asyncio.create_task(_cancel_monitor())

        parsed = _ParsedJsonOutput(max_events=max_event_count)
        stdout_buffer = _BoundedBytesBuffer(max_stdout_bytes)
        stderr_buffer = _BoundedBytesBuffer(max_stderr_bytes)
        last_heartbeat = started_monotonic
        last_progress = started_monotonic
        internal_turns = 0
        stdout_soft_limit_exceeded = False

        try:
            async def _stream_and_wait() -> tuple[str, str]:
                """并发读取 stdout/stderr，避免 stderr 管道塞满导致子进程卡死。"""
                nonlocal last_heartbeat, last_progress, stdout_soft_limit_exceeded

                def _mark_progress() -> None:
                    nonlocal last_progress
                    last_progress = time.monotonic()

                def _maybe_heartbeat() -> None:
                    nonlocal last_heartbeat
                    now = time.monotonic()
                    if now - last_heartbeat < heartbeat_interval_seconds:
                        return
                    last_heartbeat = now
                    self._write_call_heartbeat(
                        call_dir,
                        status="running",
                        detail={
                            "stdout_bytes": stdout_buffer.total_bytes,
                            "stderr_bytes": stderr_buffer.total_bytes,
                            "event_count": parsed.total_event_count,
                            "internal_turns": internal_turns,
                        },
                    )

                def _enforce_internal_turn_budget(event: dict[str, Any]) -> None:
                    nonlocal internal_turns
                    if event.get("type") != "turn_start":
                        return
                    internal_turns += 1

                async def _read_stdout() -> None:
                    nonlocal stdout_soft_limit_exceeded
                    buffer = b""
                    assert proc.stdout is not None
                    while True:
                        chunk = await proc.stdout.read(4096)
                        if not chunk:
                            break
                        _mark_progress()
                        stdout_buffer.append(chunk)
                        if stdout_buffer.truncated and not stdout_soft_limit_exceeded:
                            stdout_soft_limit_exceeded = True
                            logger.warning(
                                "runtime_stdout_trace_limit_exceeded_continue",
                                runtime="pi_agent",
                                agent_id=self.agent_id,
                                session_id=session_id,
                                stdout_bytes=stdout_buffer.total_bytes,
                                trace_limit_bytes=max_stdout_bytes,
                            )
                        buffer += chunk
                        if len(buffer) > max_single_line_bytes:
                            with contextlib.suppress(ProcessLookupError):
                                proc.terminate()
                            raise _RuntimeOutputLimitError(
                                f"runtime single-line stdout limit exceeded: "
                                f"{len(buffer)}>{max_single_line_bytes}"
                            )
                        while b"\n" in buffer:
                            line_bytes, buffer = buffer.split(b"\n", 1)
                            line_text = line_bytes.decode("utf-8", errors="replace")
                            self._process_json_line(line_text, parsed)
                            with contextlib.suppress(json.JSONDecodeError):
                                event = json.loads(line_text.strip())
                                if isinstance(event, dict):
                                    _enforce_internal_turn_budget(event)
                        _maybe_heartbeat()
                    if buffer.strip():
                        line_text = buffer.decode("utf-8", errors="replace")
                        self._process_json_line(line_text, parsed)
                        with contextlib.suppress(json.JSONDecodeError):
                            event = json.loads(line_text.strip())
                            if isinstance(event, dict):
                                _enforce_internal_turn_budget(event)
                    self._finalize_parsed(parsed)

                async def _read_stderr() -> None:
                    if not proc.stderr:
                        return
                    while True:
                        chunk = await proc.stderr.read(4096)
                        if not chunk:
                            break
                        _mark_progress()
                        stderr_buffer.append(chunk)
                        if stderr_buffer.truncated:
                            with contextlib.suppress(ProcessLookupError):
                                proc.terminate()
                            raise _RuntimeOutputLimitError(
                                f"runtime stderr limit exceeded: "
                                f"{stderr_buffer.total_bytes}>{max_stderr_bytes}"
                            )
                        _maybe_heartbeat()

                stdout_task = asyncio.create_task(_read_stdout())
                stderr_task = asyncio.create_task(_read_stderr())
                wait_task = asyncio.create_task(proc.wait())
                tasks = {stdout_task, stderr_task, wait_task}
                try:
                    while tasks:
                        self._enforce_wall_clock(started_monotonic, max_wall_seconds)
                        remaining = no_progress_timeout_seconds - (
                            time.monotonic() - last_progress
                        )
                        if remaining <= 0:
                            with contextlib.suppress(ProcessLookupError):
                                proc.terminate()
                            raise _NoProgressTimeoutError(
                                "runtime no-progress timeout after "
                                f"{no_progress_timeout_seconds:.1f}s"
                            )
                        done, _pending = await asyncio.wait(
                            tasks,
                            timeout=min(1.0, remaining),
                            return_when=asyncio.FIRST_COMPLETED,
                        )
                        if not done:
                            continue
                        for task in done:
                            tasks.remove(task)
                            task.result()
                finally:
                    for task in tasks:
                        task.cancel()
                    for task in tasks:
                        with contextlib.suppress(asyncio.CancelledError):
                            await task

                stdout_text = stdout_buffer.text()
                stderr_text = stderr_buffer.text().strip()
                return stdout_text, stderr_text

            stdout_text, stderr_text = await _stream_and_wait()

            # Cancel 检查
            if cancel_event and cancel_event.is_set():
                return _AttemptResult(
                    stdout_text=stdout_buffer.text(),
                    stderr_text=stderr_buffer.text().strip(),
                    duration_ms=int((time.monotonic() - started_monotonic) * 1000),
                    return_code=proc.returncode,
                    error="cancelled",
                    status="cancelled",
                    stdout_total_bytes=stdout_buffer.total_bytes,
                    stderr_total_bytes=stderr_buffer.total_bytes,
                    internal_turns=internal_turns,
                )

            duration_ms = int((time.monotonic() - started_monotonic) * 1000)
            response_text = parsed.content
            error = parsed.error

            # 主动扫描 stderr
            self._check_stderr_for_errors(stderr_text, parsed)
            if parsed.error and not error:
                error = parsed.error

            if proc.returncode != 0 and not error:
                error_body = (stderr_text or stdout_text or "").strip()
                error = f"pi exit code={proc.returncode}: {error_body[:500]}"

            status = "completed" if proc.returncode == 0 and not error else "error"
            return _AttemptResult(
                stdout_text=stdout_text,
                stderr_text=stderr_text,
                response_text=response_text,
                return_code=proc.returncode,
                duration_ms=duration_ms,
                parsed=parsed,
                error=error,
                status=status,
                error_code=self._classify_error_code(error, status=status) if error else "",
                stdout_total_bytes=stdout_buffer.total_bytes,
                stderr_total_bytes=stderr_buffer.total_bytes,
                stdout_truncated=stdout_buffer.truncated,
                stderr_truncated=stderr_buffer.truncated,
                stdout_soft_limit_exceeded=stdout_soft_limit_exceeded,
                internal_turns=internal_turns,
            )

        except _RuntimeOutputLimitError as exc:
            duration_ms = int((time.monotonic() - started_monotonic) * 1000)
            with contextlib.suppress(Exception):
                proc.kill()
                await proc.wait()
            return _AttemptResult(
                stdout_text=stdout_buffer.text(),
                stderr_text=stderr_buffer.text().strip(),
                duration_ms=duration_ms,
                return_code=getattr(proc, "returncode", -1),
                parsed=parsed,
                error=str(exc),
                status="runtime_output_limit",
                error_code="runtime_output_limit",
                stdout_total_bytes=stdout_buffer.total_bytes,
                stderr_total_bytes=stderr_buffer.total_bytes,
                stdout_truncated=stdout_buffer.truncated,
                stderr_truncated=stderr_buffer.truncated,
                stdout_soft_limit_exceeded=stdout_soft_limit_exceeded,
                internal_turns=internal_turns,
            )
        except _RuntimeTurnLimitError as exc:
            duration_ms = int((time.monotonic() - started_monotonic) * 1000)
            with contextlib.suppress(Exception):
                proc.kill()
                await proc.wait()
            return _AttemptResult(
                stdout_text=stdout_buffer.text(),
                stderr_text=stderr_buffer.text().strip(),
                duration_ms=duration_ms,
                return_code=getattr(proc, "returncode", -1),
                parsed=parsed,
                error=str(exc),
                status="runtime_turn_limit",
                error_code="runtime_turn_limit",
                stdout_total_bytes=stdout_buffer.total_bytes,
                stderr_total_bytes=stderr_buffer.total_bytes,
                stdout_truncated=stdout_buffer.truncated,
                stderr_truncated=stderr_buffer.truncated,
                stdout_soft_limit_exceeded=stdout_soft_limit_exceeded,
                internal_turns=internal_turns,
            )
        except _NoProgressTimeoutError as exc:
            duration_ms = int((time.monotonic() - started_monotonic) * 1000)
            await self._terminate_process(proc)
            return _AttemptResult(
                stdout_text=stdout_buffer.text(),
                stderr_text=stderr_buffer.text().strip(),
                duration_ms=duration_ms,
                return_code=getattr(proc, "returncode", -1),
                parsed=parsed,
                error=str(exc),
                status="timeout",
                timeout=True,
                error_code="runtime_timeout",
                stdout_total_bytes=stdout_buffer.total_bytes,
                stderr_total_bytes=stderr_buffer.total_bytes,
                stdout_truncated=stdout_buffer.truncated,
                stderr_truncated=stderr_buffer.truncated,
                stdout_soft_limit_exceeded=stdout_soft_limit_exceeded,
                internal_turns=internal_turns,
            )
        except Exception as exc:
            # 读取过程中异常（进程被杀、管道断裂等）
            duration_ms = int((time.monotonic() - started_monotonic) * 1000)
            await self._terminate_process(proc)
            return _AttemptResult(
                stdout_text=stdout_buffer.text(),
                stderr_text=stderr_buffer.text().strip(),
                duration_ms=duration_ms,
                return_code=getattr(proc, "returncode", -1),
                error=f"pi process read error: {exc}",
                status="error",
                error_code=self._classify_error_code(str(exc), status="error"),
                stdout_total_bytes=stdout_buffer.total_bytes,
                stderr_total_bytes=stderr_buffer.total_bytes,
                stdout_truncated=stdout_buffer.truncated,
                stderr_truncated=stderr_buffer.truncated,
                stdout_soft_limit_exceeded=stdout_soft_limit_exceeded,
                internal_turns=internal_turns,
            )
        finally:
            if cancel_task:
                cancel_task.cancel()
                try:
                    await cancel_task
                except asyncio.CancelledError:
                    pass

    async def _close_rpc_process_for_session(self, session: dict) -> None:
        proc = session.get("rpc_proc")
        stderr_task = session.get("rpc_stderr_task")
        if stderr_task and not stderr_task.done():
            stderr_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await stderr_task
        session.pop("rpc_stderr_task", None)
        session.pop("rpc_stderr_parts", None)
        session.pop("rpc_stderr_total_bytes", None)
        session.pop("rpc_stderr_retained_bytes", None)
        session.pop("rpc_stderr_truncated", None)
        session.pop("rpc_max_stderr_bytes", None)
        session.pop("rpc_stdout_buffer", None)

        if proc is not None:
            await self._terminate_process(proc)
        session.pop("rpc_proc", None)

    @staticmethod
    async def _rpc_send(proc, command: dict[str, Any]) -> None:
        if proc.stdin is None:
            raise RuntimeError("pi rpc stdin unavailable")
        proc.stdin.write((json.dumps(command, ensure_ascii=False) + "\n").encode("utf-8"))
        await proc.stdin.drain()

    async def _drain_rpc_stderr(self, session: dict, proc) -> None:
        if proc.stderr is None:
            return
        max_bytes = int(session.get("rpc_max_stderr_bytes") or _DEFAULT_MAX_STDERR_BYTES)
        while True:
            chunk = await proc.stderr.read(4096)
            if not chunk:
                break
            total = int(session.get("rpc_stderr_total_bytes") or 0) + len(chunk)
            session["rpc_stderr_total_bytes"] = total
            retained = int(session.get("rpc_stderr_retained_bytes") or 0)
            remaining = max(0, max_bytes - retained)
            if remaining > 0:
                session.setdefault("rpc_stderr_parts", []).append(chunk[:remaining])
                session["rpc_stderr_retained_bytes"] = retained + min(len(chunk), remaining)
            if len(chunk) > remaining:
                session["rpc_stderr_truncated"] = True

    async def _read_rpc_jsonl_record(
        self,
        proc,
        session: dict,
        stdout_buffer: _BoundedBytesBuffer,
        *,
        max_single_line_bytes: int,
    ) -> tuple[str | None, bool]:
        """Read one JSONL record from the RPC stdout stream without line-length limits.

        ``asyncio.StreamReader.readline()`` raises when a single line exceeds its
        internal limit. Pi RPC can emit very large single-line JSON events (for
        example ``message_end`` / ``agent_end`` with long content or many tool
        results). This helper reads fixed-size chunks and splits on ``\n``
        manually, preserving strict JSONL framing and any partial trailing bytes
        across prompt calls in ``session['rpc_stdout_buffer']``.

        Returns ``(line, eof)`` where:
        - ``line`` is the decoded record without trailing ``\r`` / ``\n``;
          ``None`` means EOF with no remaining buffered bytes.
        - ``eof`` is ``True`` if EOF was reached while producing this record.
        """
        buffer = bytes(session.get("rpc_stdout_buffer") or b"")
        while True:
            newline_idx = buffer.find(b"\n")
            if newline_idx != -1:
                if newline_idx > max_single_line_bytes:
                    raise _RuntimeOutputLimitError(
                        f"runtime single-line stdout limit exceeded: "
                        f"{newline_idx}>{max_single_line_bytes}"
                    )
                consumed = buffer[: newline_idx + 1]
                line_bytes = buffer[:newline_idx]
                buffer = buffer[newline_idx + 1 :]
                session["rpc_stdout_buffer"] = buffer
                stdout_buffer.append(consumed)
                return line_bytes.decode("utf-8", errors="replace").rstrip("\r"), False

            assert proc.stdout is not None
            # RPC mode deliberately does not apply framework-side no-progress
            # or wall-clock timeouts.  The pi process/provider is the single
            # source of truth for prompt timeout.  If pi is still working, keep
            # waiting for its normal error/agent_end event instead of creating a
            # client-side timeout that could duplicate queued prompts.
            chunk = await proc.stdout.read(65536)
            if not chunk:
                session["rpc_stdout_buffer"] = b""
                if not buffer:
                    return None, True
                stdout_buffer.append(buffer)
                line = buffer.decode("utf-8", errors="replace").rstrip("\r")
                return line, True

            buffer += chunk
            session["rpc_stdout_buffer"] = buffer
            if b"\n" in buffer:
                continue
            if len(buffer) > max_single_line_bytes:
                raise _RuntimeOutputLimitError(
                    f"runtime single-line stdout limit exceeded: "
                    f"{len(buffer)}>{max_single_line_bytes}"
                )

    async def _ensure_rpc_process(
        self,
        *,
        cmd_args: list[str],
        working_dir: Optional[str],
        session_id: str,
        call_dir: str,
        session: dict,
    ):
        proc = session.get("rpc_proc")
        if proc is not None and proc.returncode is None:
            return proc

        await self._close_rpc_process_for_session(session)
        if IS_WINDOWS:
            proc = await asyncio.create_subprocess_shell(
                command_display(cmd_args),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=working_dir,
            )
        else:
            proc = await asyncio.create_subprocess_exec(
                *cmd_args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=working_dir,
            )

        session["rpc_proc"] = proc
        session["rpc_stderr_parts"] = []
        session["rpc_stdout_buffer"] = b""
        session["rpc_stderr_task"] = asyncio.create_task(self._drain_rpc_stderr(session, proc))
        session["rpc_cmd_args"] = list(cmd_args)
        session["rpc_working_dir"] = working_dir
        logger.info(
            "runtime_rpc_process_started",
            runtime="pi_agent",
            agent_id=self.agent_id,
            session_id=session_id,
            call_dir=call_dir,
            command=command_display(cmd_args),
        )
        await self._rpc_send(
            proc,
            {
                "type": "set_auto_retry",
                "enabled": self._runtime_bool("pi_auto_retry", True),
            },
        )
        return proc

    async def _execute_once_rpc(
        self,
        *,
        cmd_args: list[str],
        message: str,
        working_dir: Optional[str],
        session_id: str,
        call_dir: str,
        session: dict,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
        max_event_count: int,
        max_single_line_bytes: int,
        max_internal_turns: int,
        heartbeat_interval_seconds: float,
        rpc_stdout_abort_bytes: int = 0,
        cancel_event: Optional[asyncio.Event] = None,
    ) -> _AttemptResult:
        """Execute one prompt on a long-lived pi RPC process.

        The process is kept in ``session`` and reused across logical turns until
        it exits or the session is closed. Pi's own provider retry is enabled via
        ``set_auto_retry`` when the process starts. RPC mode deliberately avoids
        framework-side no-progress / wall-clock watchdog timeouts; prompt timeout
        is reported only by Pi/provider itself. RPC stdout is a protocol stream:
        it is counted and trace-limited. The per-call stdout threshold is a soft
        signal: traces are truncated and a warning is recorded, but the agent is
        allowed to finish.
        """
        started_monotonic = time.monotonic()
        parsed = _ParsedJsonOutput(max_events=max_event_count)
        stdout_buffer = _BoundedBytesBuffer(max_stdout_bytes)
        stderr_buffer = _BoundedBytesBuffer(max_stderr_bytes)
        stdout_soft_limit_exceeded = False
        session["rpc_stderr_parts"] = []
        session["rpc_stderr_total_bytes"] = 0
        session["rpc_stderr_retained_bytes"] = 0
        session["rpc_stderr_truncated"] = False
        session["rpc_max_stderr_bytes"] = max_stderr_bytes
        last_heartbeat = started_monotonic
        internal_turns = 0
        stale_agent_ends_to_skip = int(session.get("rpc_stale_agent_ends_to_skip") or 0)

        try:
            proc = await self._ensure_rpc_process(
                cmd_args=cmd_args,
                working_dir=working_dir,
                session_id=session_id,
                call_dir=call_dir,
                session=session,
            )

            cancel_task: asyncio.Task | None = None
            if cancel_event:
                async def _cancel_monitor():
                    await cancel_event.wait()
                    with contextlib.suppress(Exception):
                        await self._rpc_send(proc, {"type": "abort"})
                    with contextlib.suppress(Exception):
                        proc.terminate()
                cancel_task = asyncio.create_task(_cancel_monitor())

            try:
                await self._rpc_send(proc, {
                    "type": "prompt",
                    "message": message,
                    "streamingBehavior": "followUp",
                })

                while True:
                    raw_line, eof = await self._read_rpc_jsonl_record(
                        proc=proc,
                        session=session,
                        stdout_buffer=stdout_buffer,
                        max_single_line_bytes=max_single_line_bytes,
                    )
                    now = time.monotonic()
                    if now - last_heartbeat >= heartbeat_interval_seconds:
                        last_heartbeat = now
                        self._write_call_heartbeat(
                            call_dir,
                            status="running",
                            detail={
                                "stdout_bytes": stdout_buffer.total_bytes,
                                "event_count": parsed.total_event_count,
                                "internal_turns": internal_turns,
                            },
                        )
                    if raw_line is None:
                        raise RuntimeError("pi rpc process exited before agent_end")
                    if (
                        rpc_stdout_abort_bytes > 0
                        and stdout_buffer.total_bytes > rpc_stdout_abort_bytes
                        and not stdout_soft_limit_exceeded
                    ):
                        stdout_soft_limit_exceeded = True
                        logger.warning(
                            "runtime_rpc_stdout_soft_limit_exceeded_continue",
                            runtime="pi_agent",
                            agent_id=self.agent_id,
                            session_id=session_id,
                            stdout_bytes=stdout_buffer.total_bytes,
                            soft_limit_bytes=rpc_stdout_abort_bytes,
                        )
                    try:
                        event = json.loads(raw_line)
                    except json.JSONDecodeError:
                        if eof and not parsed.saw_agent_end and stale_agent_ends_to_skip <= 0:
                            raise RuntimeError("pi rpc process exited before agent_end")
                        continue

                    if stale_agent_ends_to_skip > 0:
                        if event.get("type") == "agent_end":
                            stale_agent_ends_to_skip -= 1
                            session["rpc_stale_agent_ends_to_skip"] = stale_agent_ends_to_skip
                            logger.info(
                                "runtime_rpc_stale_agent_end_ignored",
                                runtime="pi_agent",
                                agent_id=self.agent_id,
                                session_id=session_id,
                                remaining=stale_agent_ends_to_skip,
                            )
                            if stale_agent_ends_to_skip == 0:
                                parsed = _ParsedJsonOutput(max_events=max_event_count)
                                internal_turns = 0
                        continue

                    self._process_json_line(raw_line, parsed)

                    if event.get("type") == "turn_start":
                        internal_turns += 1

                    if (
                        event.get("type") == "response"
                        and event.get("command") == "prompt"
                        and not event.get("success", True)
                    ):
                        parsed.error = str(event.get("error") or "Prompt failed")
                        self._finalize_parsed(parsed)
                        break

                    if event.get("type") == "agent_end":
                        parsed.saw_agent_end = True
                        break

                    if eof and not parsed.saw_agent_end:
                        raise RuntimeError("pi rpc process exited before agent_end")
            finally:
                if cancel_task:
                    cancel_task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await cancel_task

            self._finalize_parsed(parsed)
            for chunk in session.get("rpc_stderr_parts", []):
                stderr_buffer.append(chunk)
            stderr_buffer.total_bytes = int(
                session.get("rpc_stderr_total_bytes") or stderr_buffer.total_bytes
            )
            stderr_buffer.truncated = bool(
                session.get("rpc_stderr_truncated") or stderr_buffer.truncated
            )
            stderr_text = stderr_buffer.text().strip()
            self._check_stderr_for_errors(stderr_text, parsed)

            if cancel_event and cancel_event.is_set():
                return _AttemptResult(
                    stdout_text=stdout_buffer.text(),
                    stderr_text=stderr_text,
                    duration_ms=int((time.monotonic() - started_monotonic) * 1000),
                    return_code=getattr(proc, "returncode", None),
                    parsed=parsed,
                    error="cancelled",
                    status="cancelled",
                    stdout_total_bytes=stdout_buffer.total_bytes,
                    stderr_total_bytes=stderr_buffer.total_bytes,
                    stdout_truncated=stdout_buffer.truncated,
                    stderr_truncated=stderr_buffer.truncated,
                    stdout_soft_limit_exceeded=stdout_soft_limit_exceeded,
                    internal_turns=internal_turns,
                )

            success = parsed.saw_agent_end and not parsed.error
            error_code = self._classify_error_code(parsed.error, status="error") if parsed.error else ""
            return _AttemptResult(
                stdout_text=stdout_buffer.text(),
                stderr_text=stderr_text,
                response_text=parsed.content,
                return_code=0 if proc.returncode is None else proc.returncode,
                duration_ms=int((time.monotonic() - started_monotonic) * 1000),
                parsed=parsed,
                error=parsed.error,
                status="completed" if success else "error",
                error_code=error_code,
                stdout_total_bytes=stdout_buffer.total_bytes,
                stderr_total_bytes=stderr_buffer.total_bytes,
                stdout_truncated=stdout_buffer.truncated,
                stderr_truncated=stderr_buffer.truncated,
                stdout_soft_limit_exceeded=stdout_soft_limit_exceeded,
                internal_turns=internal_turns,
            )
        except _RuntimeOutputLimitError as exc:
            stderr_text = b"".join(session.get("rpc_stderr_parts", [])).decode(
                "utf-8", errors="replace").strip()
            await self._close_rpc_process_for_session(session)
            return _AttemptResult(
                stdout_text=stdout_buffer.text(),
                stderr_text=stderr_text,
                duration_ms=int((time.monotonic() - started_monotonic) * 1000),
                return_code=-1,
                parsed=parsed,
                error=str(exc),
                status="runtime_output_limit",
                error_code="runtime_output_limit",
                stdout_total_bytes=stdout_buffer.total_bytes,
                stderr_total_bytes=stderr_buffer.total_bytes,
                stdout_truncated=stdout_buffer.truncated,
                stderr_truncated=stderr_buffer.truncated,
                stdout_soft_limit_exceeded=stdout_soft_limit_exceeded,
                internal_turns=internal_turns,
            )
        except _RuntimeTurnLimitError as exc:
            stderr_text = b"".join(session.get("rpc_stderr_parts", [])).decode(
                "utf-8", errors="replace").strip()
            await self._close_rpc_process_for_session(session)
            return _AttemptResult(
                stdout_text=stdout_buffer.text(),
                stderr_text=stderr_text,
                duration_ms=int((time.monotonic() - started_monotonic) * 1000),
                return_code=-1,
                parsed=parsed,
                error=str(exc),
                status="runtime_turn_limit",
                error_code="runtime_turn_limit",
                stdout_total_bytes=stdout_buffer.total_bytes,
                stderr_total_bytes=stderr_buffer.total_bytes,
                stdout_truncated=stdout_buffer.truncated,
                stderr_truncated=stderr_buffer.truncated,
                stdout_soft_limit_exceeded=stdout_soft_limit_exceeded,
                internal_turns=internal_turns,
            )
        except Exception as exc:
            stderr_text = b"".join(session.get("rpc_stderr_parts", [])).decode(
                "utf-8", errors="replace").strip()
            await self._close_rpc_process_for_session(session)
            return _AttemptResult(
                stdout_text=stdout_buffer.text(),
                stderr_text=stderr_text,
                duration_ms=int((time.monotonic() - started_monotonic) * 1000),
                return_code=-1,
                parsed=parsed,
                error=f"pi rpc error: {exc}",
                status="error",
                error_code=self._classify_error_code(str(exc), status="error"),
                stdout_total_bytes=stdout_buffer.total_bytes,
                stderr_total_bytes=stderr_buffer.total_bytes,
                stdout_truncated=stdout_buffer.truncated,
                stderr_truncated=stderr_buffer.truncated,
                stdout_soft_limit_exceeded=stdout_soft_limit_exceeded,
                internal_turns=internal_turns,
            )

    async def send_message(
        self,
        message: str,
        system_prompt: Optional[str] = None,
        session_id: Optional[str] = None,
        working_dir: Optional[str] = None,
        cancel_event: Optional[asyncio.Event] = None,
        max_internal_turns: Optional[int] = None,
        no_progress_timeout_seconds: Optional[float] = None,
        max_wall_seconds: Optional[float] = None,
        rpc_stdout_trace_bytes: Optional[int] = None,
        rpc_stdout_abort_bytes: Optional[int] = None,
    ) -> AgentResponse:
        if session_id is None:
            session_id = await self.create_session()

        session = self._restore_session_from_disk(session_id, working_dir)
        # RPC mode delegates prompt timeout to Pi/provider itself and does not
        # keep framework-side no-progress / wall-clock watchdogs. JSON mode
        # retains the legacy subprocess watchdogs for compatibility.
        transport = str(self.runtime_config.get("transport") or self.runtime_config.get("mode") or "json").strip().lower()
        if transport not in {"json", "rpc"}:
            logger.warning("unknown_pi_transport_fallback_json", agent_id=self.agent_id, transport=transport)
            transport = "json"
        sdk_cfg = self.runtime_config.get("sdk_specific", {})
        thinking = str(sdk_cfg.get("thinking") or "").strip()
        tools = sdk_cfg.get("tools", "read,bash,edit,write")
        effective_model, raw_model, _legacy_provider = self._effective_model()
        allow_unbounded_framework_retry = transport != "rpc"
        api_max_retries = self._normalize_framework_retry_count(
            self.runtime_config.get(
                "api_max_retries",
                self.runtime_config.get("max_retries", -1 if allow_unbounded_framework_retry else 0),
            ),
            -1 if allow_unbounded_framework_retry else 0,
            allow_unbounded=allow_unbounded_framework_retry,
        )
        api_retry_delay = float(self.runtime_config.get("api_retry_delay", self.runtime_config.get("retry_delay", 10.0)))
        pi_max_retries = self._normalize_framework_retry_count(
            self.runtime_config.get("pi_max_retries", -1 if allow_unbounded_framework_retry else 0),
            -1 if allow_unbounded_framework_retry else 0,
            allow_unbounded=allow_unbounded_framework_retry,
        )
        pi_retry_delay = float(self.runtime_config.get("pi_retry_delay", 10.0))
        timeout_max_retries = self._runtime_retry_count("timeout_max_retries", _DEFAULT_TIMEOUT_MAX_RETRIES)
        timeout_retry_delay = self._runtime_non_negative_float(
            "timeout_retry_interval_seconds",
            self._runtime_non_negative_float(
                "timeout_retry_delay",
                _DEFAULT_TIMEOUT_RETRY_INTERVAL_SECONDS,
            ),
        )
        timeout_retry_fresh_session = bool(
            self.runtime_config.get("timeout_retry_fresh_session", self.reset_context)
        )
        max_stdout_bytes = self._runtime_int("max_stdout_bytes", _DEFAULT_MAX_STDOUT_BYTES)
        max_stderr_bytes = self._runtime_int("max_stderr_bytes", _DEFAULT_MAX_STDERR_BYTES)
        max_response_bytes = self._runtime_int("max_response_bytes", _DEFAULT_MAX_RESPONSE_BYTES)
        effective_rpc_stdout_trace_bytes = (
            int(rpc_stdout_trace_bytes)
            if rpc_stdout_trace_bytes is not None else
            self._runtime_int(
                "rpc_stdout_trace_bytes",
                min(max_stdout_bytes, _DEFAULT_RPC_STDOUT_TRACE_BYTES),
            )
        )
        effective_rpc_stdout_abort_bytes = (
            int(rpc_stdout_abort_bytes)
            if rpc_stdout_abort_bytes is not None else
            self._runtime_int("rpc_stdout_abort_bytes", 0)
        )
        max_event_count = self._runtime_int("max_event_count", _DEFAULT_MAX_PARSED_EVENTS)
        max_single_line_bytes = self._runtime_int("max_single_line_bytes", _DEFAULT_MAX_RPC_LINE_BYTES)
        # Pi internal turn count is an implementation detail, not a safe
        # progress signal for vuln scanning. Keep collecting the metric, but
        # never abort a running agent because this counter grows.
        effective_max_internal_turns = 0
        effective_no_progress_timeout_seconds: float | None = None
        effective_max_wall_seconds: float | None = None
        max_retry_wall_seconds: float | None = None
        if transport == "json":
            effective_no_progress_timeout_seconds = (
                float(no_progress_timeout_seconds)
                if no_progress_timeout_seconds is not None else
                self._runtime_float(
                    "no_progress_timeout_seconds",
                    _DEFAULT_NO_PROGRESS_TIMEOUT_SECONDS,
                )
            )
            effective_max_wall_seconds = (
                float(max_wall_seconds)
                if max_wall_seconds is not None else
                self._runtime_float("max_wall_seconds", _DEFAULT_MAX_WALL_SECONDS)
            )
            max_retry_wall_seconds = self._runtime_float(
                "max_retry_wall_seconds",
                _DEFAULT_MAX_RETRY_WALL_SECONDS,
            )
        heartbeat_interval_seconds = self._runtime_float(
            "heartbeat_interval_seconds",
            _DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
        )
        trace_limits = {
            "stdout_bytes": effective_rpc_stdout_trace_bytes if transport == "rpc" else max_stdout_bytes,
            "stderr_bytes": max_stderr_bytes,
            "response_bytes": max_response_bytes,
        }

        is_continuation = session["turns"] > 0
        turn_number = session["turns"] + 1
        trace_context = RuntimeTraceContext.create(
            runtime="pi_agent",
            agent_id=self.agent_id,
            session_id=session_id,
            turn_number=turn_number,
            working_dir=working_dir,
            user_prompt=message,
            system_prompt=system_prompt,
            write_system_prompt=not is_continuation,
        )

        def _build_cmd_args_for_session(
            *,
            attempt_session: dict[str, Any],
            attempt_session_dir: str | None,
        ) -> list[str]:
            attempt_is_continuation = int(attempt_session.get("turns") or 0) > 0
            args = [
                "pi",
                "--mode", transport,
                "--model", effective_model,
            ]
            if thinking:
                args.extend(["--thinking", thinking])
            args.extend(["--tools", tools])
            if transport == "json":
                args.append("-p")

            if trace_context.system_prompt_file and not attempt_is_continuation:
                args.extend(["--append-system-prompt", trace_context.system_prompt_file])

            if attempt_session_dir:
                args.extend(["--session-dir", attempt_session_dir])
                if attempt_is_continuation:
                    args.append("--continue")
            else:
                args.append("--no-session")

            if transport == "json":
                args.append(f"@{trace_context.user_prompt_file}")
            return args

        cmd_args = _build_cmd_args_for_session(
            attempt_session=session,
            attempt_session_dir=trace_context.session_dir,
        )
        cmd_display = command_display(cmd_args)

        attempts: list[dict[str, Any]] = []
        started_at = now_iso()
        runtime_limits_payload = {
            "max_stdout_bytes": max_stdout_bytes,
            "rpc_stdout_trace_bytes": effective_rpc_stdout_trace_bytes,
            "rpc_stdout_abort_bytes": effective_rpc_stdout_abort_bytes,
            "rpc_stdout_abort_mode": "soft_continue",
            "max_stderr_bytes": max_stderr_bytes,
            "max_response_bytes": max_response_bytes,
            "max_event_count": max_event_count,
            "max_single_line_bytes": max_single_line_bytes,
            "max_internal_turns": effective_max_internal_turns,
            "heartbeat_interval_seconds": heartbeat_interval_seconds,
            "timeout_max_retries": timeout_max_retries,
            "timeout_retry_delay": timeout_retry_delay,
            "timeout_retry_interval_seconds": timeout_retry_delay,
        }
        if transport == "json":
            runtime_limits_payload.update(
                {
                    "no_progress_timeout_seconds": effective_no_progress_timeout_seconds,
                    "max_wall_seconds": effective_max_wall_seconds,
                    "max_retry_wall_seconds": max_retry_wall_seconds,
                }
            )
        trace_context.write_request(
            {
                "agent_id": self.agent_id,
                "runtime": "pi_agent",
                "session_id": session_id,
                "turn_number": turn_number,
                "started_at": started_at,
                "working_dir": trace_context.working_dir,
                "session_dir": trace_context.session_dir,
                "call_dir": trace_context.call_dir,
                "mode": transport,
                "model": effective_model,
                "raw_model": raw_model,
                "thinking": thinking,
                "tools": tools,
                "api_max_retries": api_max_retries,
                "api_retry_delay": api_retry_delay,
                "pi_max_retries": pi_max_retries,
                "pi_retry_delay": pi_retry_delay,
                "timeout_max_retries": timeout_max_retries,
                "timeout_retry_delay": timeout_retry_delay,
                "timeout_retry_interval_seconds": timeout_retry_delay,
                "timeout_retry_fresh_session": timeout_retry_fresh_session,
                "runtime_limits": runtime_limits_payload,
                "is_continuation": is_continuation,
                "user_prompt_len": len(message),
                "sys_prompt_len": len(system_prompt) if system_prompt else 0,
                "has_system_prompt": trace_context.system_prompt_file is not None,
                "user_prompt_file": trace_context.user_prompt_file,
                "system_prompt_file": trace_context.system_prompt_file,
                "command_argv": cmd_args,
                "command_display": cmd_display,
            }
        )

        logger.info(
            "runtime_execute",
            runtime="pi_agent",
            agent_id=self.agent_id,
            mode=transport,
            model=effective_model,
            cwd=working_dir,
            user_prompt_len=len(message),
            sys_prompt_len=len(system_prompt) if system_prompt else 0,
            has_system_prompt=(trace_context.system_prompt_file is not None),
            is_continuation=is_continuation,
            session_turns=session["turns"],
            session_dir=trace_context.session_dir,
            call_dir=trace_context.call_dir,
            user_prompt_file=trace_context.user_prompt_file,
            system_prompt_file=trace_context.system_prompt_file,
            command=cmd_display,
        )

        api_failures = 0
        pi_failures = 0
        timeout_failures = 0
        timeout_retry_sessions: list[dict[str, Any]] = []
        active_session_id = session_id
        active_session = session
        active_session_dir = trace_context.session_dir
        final_result: _AttemptResult | None = None
        overall_started_monotonic = time.monotonic()

        try:
            def _retry_budget_exceeded() -> bool:
                if max_retry_wall_seconds is None:
                    return False
                return (
                    time.monotonic() - overall_started_monotonic
                    >= max_retry_wall_seconds
                )

            def _mark_retry_budget_exhausted(result: _AttemptResult) -> None:
                if max_retry_wall_seconds is None:
                    return
                elapsed = time.monotonic() - overall_started_monotonic
                result.status = "timeout"
                result.timeout = True
                result.error_code = "runtime_timeout"
                result.error = (
                    (result.error or "runtime retry budget exceeded")
                    + f" [runtime retry wall clock exceeded: {elapsed:.1f}s/"
                    f"{max_retry_wall_seconds:.1f}s]"
                )

            def _activate_fresh_timeout_retry_session(retry_index: int) -> None:
                nonlocal active_session_id, active_session, active_session_dir
                if not timeout_retry_fresh_session or not trace_context.working_dir:
                    return
                retry_session_id = self._reserve_session_id(
                    f"{session_id}_timeout_retry_{retry_index:03d}"
                )
                retry_session_dir = str(
                    Path(trace_context.working_dir) / "sessions" / retry_session_id
                )
                Path(retry_session_dir).mkdir(parents=True, exist_ok=True)
                active_session_id = retry_session_id
                active_session = {
                    "turns": 0,
                    "timeout_retry_parent": session_id,
                    "timeout_retry_index": retry_index,
                }
                active_session_dir = retry_session_dir
                self._sessions[retry_session_id] = active_session
                timeout_retry_sessions.append(
                    {
                        "retry_index": retry_index,
                        "session_id": retry_session_id,
                        "session_dir": retry_session_dir,
                    }
                )

            while True:
                # Cancel 检查
                if cancel_event and cancel_event.is_set():
                    final_result = _AttemptResult(error="cancelled", status="cancelled")
                    attempts.append({"attempt": len(attempts) + 1, "status": "cancelled", "error": "cancelled"})
                    break

                attempt_cmd_args = _build_cmd_args_for_session(
                    attempt_session=active_session,
                    attempt_session_dir=active_session_dir,
                )

                # 启动子进程（launch 失败用 pi_failures 重试）
                try:
                    if transport == "rpc":
                        result = await self._execute_once_rpc(
                            cmd_args=attempt_cmd_args,
                            message=message,
                            working_dir=working_dir,
                            session_id=active_session_id,
                            call_dir=trace_context.call_dir or "",
                            session=active_session,
                            max_stdout_bytes=effective_rpc_stdout_trace_bytes,
                            max_stderr_bytes=max_stderr_bytes,
                            max_event_count=max_event_count,
                            max_single_line_bytes=max_single_line_bytes,
                            max_internal_turns=effective_max_internal_turns,
                            heartbeat_interval_seconds=heartbeat_interval_seconds,
                            rpc_stdout_abort_bytes=effective_rpc_stdout_abort_bytes,
                            cancel_event=cancel_event,
                        )
                    else:
                        result = await self._execute_once(
                            cmd_args=attempt_cmd_args,
                            working_dir=working_dir,
                            session_id=active_session_id,
                            call_dir=trace_context.call_dir or "",
                            max_stdout_bytes=max_stdout_bytes,
                            max_stderr_bytes=max_stderr_bytes,
                            max_event_count=max_event_count,
                            max_single_line_bytes=max_single_line_bytes,
                            max_internal_turns=effective_max_internal_turns,
                            no_progress_timeout_seconds=effective_no_progress_timeout_seconds,
                            max_wall_seconds=effective_max_wall_seconds,
                            heartbeat_interval_seconds=heartbeat_interval_seconds,
                            cancel_event=cancel_event,
                        )
                except (FileNotFoundError, PermissionError, OSError) as exc:
                    pi_failures += 1
                    error_msg = (
                        "pi CLI 未安装" if isinstance(exc, FileNotFoundError)
                        else f"pi launch failed: {exc}"
                    )
                    final_result = _AttemptResult(
                        return_code=-1,
                        error=error_msg,
                        status="error",
                        launch_error=True,
                        error_code="runtime_launch_failed",
                    )
                    attempts.append({
                        "attempt": len(attempts) + 1,
                        "status": "launch_error",
                        "error": error_msg,
                        "error_code": "runtime_launch_failed",
                    })
                    logger.warning(
                        "runtime_pi_launch_failed",
                        runtime="pi_agent",
                        agent_id=self.agent_id,
                        attempt=pi_failures,
                        max_retries=pi_max_retries,
                        error=error_msg,
                    )
                    # Launch failures are environmental/configuration failures
                    # (missing binary, permissions, invalid executable).  They
                    # are terminal for this call; retrying with the same command
                    # just burns cycles and can loop forever with pi_max_retries=-1.
                    break

                final_result = result

                attempt_payload = {
                    "attempt": len(attempts) + 1,
                    "status": result.status,
                    "session_id": active_session_id,
                    "session_dir": active_session_dir,
                    "command_display": command_display(attempt_cmd_args),
                    "return_code": result.return_code,
                    "duration_ms": result.duration_ms,
                    "stdout_len": len(result.stdout_text),
                    "stderr_len": len(result.stderr_text),
                    "response_len": len(result.response_text),
                    "stdout_total_bytes": result.stdout_total_bytes,
                    "stderr_total_bytes": result.stderr_total_bytes,
                    "stdout_truncated": result.stdout_truncated,
                    "stderr_truncated": result.stderr_truncated,
                    "stdout_soft_limit_exceeded": result.stdout_soft_limit_exceeded,
                    "saw_json": result.parsed.saw_json,
                    "message_count": len(result.parsed.messages),
                    "event_count": len(result.parsed.events),
                    "event_total_count": result.parsed.total_event_count,
                    "events_truncated_count": result.parsed.events_truncated_count,
                    "internal_turns": result.internal_turns,
                    "error_code": (
                        result.error_code
                        or self._classify_error_code(result.error, status=result.status)
                        if result.error else ""
                    ),
                    "error": result.error,
                }
                attempts.append(attempt_payload)

                # 成功
                if result.status == "completed" and not result.error:
                    break

                # 0) 致命错误（配置/环境问题，绝不重试）
                if self._is_fatal_error(result.error):
                    break

                # 0.3) Pi/provider native timeout.
                # RPC mode no longer creates framework-side wait timeouts; this
                # branch is reached only after pi/provider reports a timeout as
                # the prompt result. Retry by resending the same prompt after a
                # fixed interval. RPC retries preserve the same session/process;
                # JSON retries start a new process as before.
                if result.timeout or result.error_code == "runtime_timeout":
                    timeout_failures += 1
                    timeout_attempt_limit = max(1, timeout_max_retries)
                    attempts[-1]["retry_kind"] = (
                        "pi_timeout_rpc_resend_same_process"
                        if transport == "rpc" else
                        "runtime_timeout_restart"
                    )
                    attempts[-1]["timeout_retry_index"] = timeout_failures
                    attempts[-1]["timeout_attempt_limit"] = timeout_attempt_limit
                    attempts[-1]["timeout_retry_limit"] = timeout_attempt_limit
                    if timeout_failures < timeout_attempt_limit:
                        attempts[-1]["will_retry"] = True
                        if transport == "rpc":
                            # RPC mode: a Pi-native timeout means the prompt has
                            # completed with an error.  Retry the same prompt on
                            # the same review/worker session and same long-lived
                            # RPC process.  Different advisor reviews still get
                            # their own sessions at the review scheduler layer;
                            # timeout retry within one review must not create a
                            # new session.
                            attempts[-1]["process_restarted"] = False
                            attempts[-1]["rpc_process_preserved"] = True
                            attempts[-1]["fresh_session"] = False
                            attempts[-1]["stale_agent_ends_to_skip"] = int(
                                active_session.get("rpc_stale_agent_ends_to_skip") or 0
                            )
                        else:
                            attempts[-1]["process_restarted"] = True
                            if timeout_retry_fresh_session:
                                _activate_fresh_timeout_retry_session(timeout_failures)
                                attempts[-1]["next_session_id"] = active_session_id
                                attempts[-1]["next_session_dir"] = active_session_dir
                        delay = timeout_retry_delay if timeout_retry_delay > 0 else 0.0
                        logger.warning(
                            "pi_timeout_retry",
                            runtime="pi_agent",
                            agent_id=self.agent_id,
                            transport=transport,
                            timeout_failures=timeout_failures,
                            max_retries=timeout_max_retries,
                            delay=delay,
                            session_id=active_session_id,
                            session_dir=active_session_dir,
                            rpc_process_preserved=bool(
                                attempts[-1].get("rpc_process_preserved", transport == "rpc")
                            ),
                            fresh_session=bool(attempts[-1].get("fresh_session", timeout_retry_fresh_session)),
                            error=result.error,
                        )
                        if delay > 0:
                            await asyncio.sleep(delay)
                        continue
                    result.error = (
                        result.error or "runtime timeout"
                    ) + (
                        f" [timeout 处理失败已达到上限: {timeout_failures} 次, "
                        f"上限 {timeout_attempt_limit} 次]"
                    )
                    attempts[-1]["error"] = result.error
                    attempts[-1]["will_retry"] = False
                    break

                # 0.5) 框架已分类的终态错误不进入 API/pi 无限重试。
                if result.error_code in _TERMINAL_ERROR_CODES:
                    break

                # 1) pi 进程级失败（崩溃、信号杀死、无输出）—— 先于 API 判断
                if self._is_pi_process_failure(result):
                    pi_failures += 1
                    if _retry_budget_exceeded():
                        _mark_retry_budget_exhausted(result)
                        attempts[-1]["status"] = result.status
                        attempts[-1]["error"] = result.error
                        attempts[-1]["error_code"] = result.error_code
                        break
                    if self._should_retry(pi_failures, pi_max_retries):
                        delay = self._backoff(pi_retry_delay, pi_failures)
                        logger.warning(
                            "runtime_pi_process_retry",
                            runtime="pi_agent",
                            agent_id=self.agent_id,
                            attempt=pi_failures,
                            max_retries=pi_max_retries,
                            delay=delay,
                            error=result.error,
                        )
                        await asyncio.sleep(delay)
                        continue
                    result.error = (result.error or "pi process error") + f" [pi 重试已耗尽: {pi_failures} 次失败]"
                    attempts[-1]["error"] = result.error
                    break

                # 2) API 级可重试错误（连接/限流/服务器错误）
                if self._is_retryable_api_error(result.error):
                    api_failures += 1
                    if _retry_budget_exceeded():
                        _mark_retry_budget_exhausted(result)
                        attempts[-1]["status"] = result.status
                        attempts[-1]["error"] = result.error
                        attempts[-1]["error_code"] = result.error_code
                        break
                    if self._should_retry(api_failures, api_max_retries):
                        delay = self._backoff(api_retry_delay, api_failures)
                        logger.warning(
                            "runtime_api_retry",
                            runtime="pi_agent",
                            agent_id=self.agent_id,
                            attempt=api_failures,
                            max_retries=api_max_retries,
                            delay=delay,
                            error=result.error,
                        )
                        await asyncio.sleep(delay)
                        continue
                    result.error = (result.error or "API error") + f" [API 重试已耗尽: {api_failures} 次失败]"
                    attempts[-1]["error"] = result.error
                    break

                # 3) 非零退出但有输出（可能是 pi 的非致命警告），记录但不重试
                if result.return_code and result.return_code != 0 and result.error:
                    logger.warning(
                        "runtime_nonzero_exit_with_output",
                        runtime="pi_agent",
                        agent_id=self.agent_id,
                        exit_code=result.return_code,
                        error=(result.error or "")[:200],
                    )
                break

            assert final_result is not None
            success = final_result.status == "completed" and not final_result.error

            if success:
                active_session["turns"] = int(active_session.get("turns") or 0) + 1
                self._sessions[active_session_id] = active_session
                if active_session_id == session_id:
                    session = active_session
                else:
                    session["turns"] = active_session["turns"]
                    session["timeout_retry_final_session_id"] = active_session_id
                self._sessions[session_id] = session

            response_status = "completed" if success else final_result.status
            if not success and response_status == "completed":
                response_status = "error"
            response_error_code = (
                ""
                if success else
                final_result.error_code
                or self._classify_error_code(final_result.error, status=response_status)
            )

            trace_context.write_result(
                stdout_text=final_result.stdout_text,
                stderr_text=final_result.stderr_text,
                response_text=final_result.response_text,
                payload={
                    "status": response_status,
                    "finished_at": now_iso(),
                    "duration_ms": final_result.duration_ms,
                    "return_code": final_result.return_code,
                    "output_len": len(final_result.stdout_text),
                    "stderr_len": len(final_result.stderr_text),
                    "response_len": len(final_result.response_text),
                    "conversation_id": session_id,
                    "effective_session_id": active_session_id,
                    "effective_session_dir": active_session_dir,
                    "turn_count": session["turns"],
                    "finished": success,
                    "error": final_result.error,
                    "error_code": response_error_code,
                    "mode": transport,
                    "model": effective_model,
                    "attempts": attempts,
                    "api_failures": api_failures,
                    "pi_failures": pi_failures,
                    "timeout_failures": timeout_failures,
                    "timeout_max_retries": timeout_max_retries,
                    "timeout_retry_delay": timeout_retry_delay,
                    "timeout_retry_interval_seconds": timeout_retry_delay,
                    "timeout_retry_fresh_session": timeout_retry_fresh_session,
                    "timeout_retry_sessions": timeout_retry_sessions,
                    "trace_limits": trace_limits,
                    "output_total_bytes": final_result.stdout_total_bytes,
                    "stderr_total_bytes": final_result.stderr_total_bytes,
                    "stdout_truncated": final_result.stdout_truncated,
                    "stderr_truncated": final_result.stderr_truncated,
                    "stdout_soft_limit_exceeded": final_result.stdout_soft_limit_exceeded,
                    "message_count": len(final_result.parsed.messages),
                    "event_count": len(final_result.parsed.events),
                    "event_total_count": final_result.parsed.total_event_count,
                    "events_truncated_count": final_result.parsed.events_truncated_count,
                    "internal_turn_count": final_result.internal_turns,
                    "messages_truncated_count": final_result.parsed.messages_truncated_count,
                    "non_json_truncated_count": final_result.parsed.non_json_truncated_count,
                    "token_usage": final_result.parsed.token_usage,
                },
            )
            if trace_context.call_dir and final_result.parsed.events:
                trace_context.write_text_artifact(
                    "stdout_events.json",
                    json.dumps(final_result.parsed.events, ensure_ascii=False, indent=2),
                )

            if success:
                logger.info(
                    "runtime_execute_done",
                    runtime="pi_agent",
                    agent_id=self.agent_id,
                    output_len=len(final_result.response_text),
                    return_code=final_result.return_code,
                    call_dir=trace_context.call_dir,
                    duration_ms=final_result.duration_ms,
                    attempts=len(attempts),
                )
                return AgentResponse(
                    content=final_result.response_text,
                    conversation_id=session_id,
                    turn_count=session["turns"],
                    finished=True,
                    token_usage=final_result.parsed.token_usage,
                    raw_response=final_result.parsed.events if final_result.parsed.events else final_result.stdout_text,
                    metadata={
                        "call_dir": trace_context.call_dir or "",
                        "mode": transport,
                        "output_total_bytes": final_result.stdout_total_bytes,
                        "stdout_soft_limit_exceeded": final_result.stdout_soft_limit_exceeded,
                        "event_total_count": final_result.parsed.total_event_count,
                        "events_truncated_count": final_result.parsed.events_truncated_count,
                        "internal_turn_count": final_result.internal_turns,
                    },
                )

            logger.warning(
                "runtime_execute_failed",
                runtime="pi_agent",
                agent_id=self.agent_id,
                error=final_result.error,
                status=response_status,
                return_code=final_result.return_code,
                call_dir=trace_context.call_dir,
                attempts=len(attempts),
            )
            return AgentResponse(
                content=final_result.response_text,
                error=final_result.error or "Pi Agent 执行失败",
                error_code=response_error_code,
                conversation_id=session_id,
                turn_count=session.get("turns", 0),
                finished=False,
                fatal=self._is_fatal_error(final_result.error),
                token_usage=final_result.parsed.token_usage,
                raw_response=final_result.parsed.events if final_result.parsed.events else final_result.stdout_text,
                metadata={
                    "call_dir": trace_context.call_dir or "",
                    "mode": transport,
                    "status": response_status,
                    "output_total_bytes": final_result.stdout_total_bytes,
                    "effective_session_id": active_session_id,
                    "timeout_failures": timeout_failures,
                    "timeout_max_retries": timeout_max_retries,
                    "timeout_retry_interval_seconds": timeout_retry_delay,
                    "timeout_retry_exhausted": (
                        response_error_code == "runtime_timeout"
                        and timeout_failures > 0
                    ),
                    "event_total_count": final_result.parsed.total_event_count,
                    "events_truncated_count": final_result.parsed.events_truncated_count,
                    "internal_turn_count": final_result.internal_turns,
                },
            )
        finally:
            if active_session_id != session_id:
                with contextlib.suppress(Exception):
                    await self._close_rpc_process_for_session(active_session)
            trace_context.cleanup()

    async def multi_turn_execute(
        self,
        system_prompt: str,
        user_prompt: str,
        working_dir: str,
        max_turns: int = 30,
        session_id: Optional[str] = None,
        cancel_event: Optional[asyncio.Event] = None,
    ) -> AgentResponse:
        if session_id is None:
            session_id = await self.create_session()
        return await self.send_message(
            message=user_prompt,
            system_prompt=system_prompt,
            session_id=session_id,
            working_dir=working_dir,
            cancel_event=cancel_event,
        )

    async def close_session(self, session_id: str) -> None:
        session = self._sessions.get(session_id)
        if session is not None:
            await self._close_rpc_process_for_session(session)
        self._sessions.pop(session_id, None)

    async def shutdown(self) -> None:
        await self.reset()
        self._initialized = False
