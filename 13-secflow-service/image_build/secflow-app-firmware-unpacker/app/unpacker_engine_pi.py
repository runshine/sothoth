"""Pi RPC client wrapper for firmware unpacking workflows."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

from app.logging_utils import log_event
from app.services.configcenter import get_configcenter_client
from app.unpacker_engine_config import (
    PI_AGENT_DIR_ENV,
    ROLE_CONFIG_FILE_KEYS,
    ROLE_MODEL_CONFIG_KEYS,
    build_settings_json,
    ensure_models_json_context_window,
    get_agent_thinking_level,
    get_agent_run_timeout_seconds,
    get_agent_timeout_max_retries,
    get_agent_timeout_retry_enabled,
    resolve_provider_selector,
)
from app.unpacker_engine_session import update_session_index


log = logging.getLogger("unpacker.engine")
_DEFAULT_CONTEXT_WINDOW = 128_000
_SINGLE_INPUT_CONTEXT_RATIO = 0.75
_PROMPT_TOKEN_OVERHEAD = 128
_COMPACTION_TRIGGER_PROMPT = (
    "请立即触发一次当前会话的自动压缩（compaction），"
    "仅保留后续继续执行任务所需的关键结论、约束和待办。"
    "不要继续业务分析，只回复 COMPACTION_OK。"
)


class PiPromptResult:
    def __init__(self) -> None:
        self.output = ""
        self.error: str | None = None
        self.provider_role: str | None = None
        self.runtime_dir: str | None = None
        self.context_window: int = 0
        self.proxy_reserved_tokens: int = 0
        self.compaction_requested = False
        self.compaction_completed = False
        self.context_budget_exceeded_preflight = False
        self.context_overflow_retrying = False
        self.context_overflow_failed_after_compaction = False


class PiRpcClient:
    RETRIES = 2

    @staticmethod
    def resolve_cwd(cwd: str | None) -> str:
        candidates = [
            cwd,
            os.environ.get("PI_RPC_CWD"),
            os.environ.get("WORKSPACE"),
            "/app",
            os.getcwd(),
            "/tmp",
        ]
        for candidate in candidates:
            if candidate and os.path.isdir(candidate):
                return candidate
        return "/"

    @staticmethod
    def build_args(
        *,
        system_prompt_file=None,
        model=None,
        tools=None,
        thinking_level=None,
        session_dir=None,
        session_path=None,
    ):
        args = ["pi", "--mode", "rpc"]
        if session_dir:
            args.extend(["--session-dir", str(session_dir)])
        if session_path:
            args.extend(["--session", str(session_path)])
        if system_prompt_file:
            args.extend(["--append-system-prompt", system_prompt_file])
        if model:
            args.extend(["--model", model])
        if thinking_level:
            args.extend(["--thinking", str(thinking_level)])
        if tools:
            args.extend(["--tools", ",".join(tools)])
        return args

    def __init__(
        self,
        *,
        system_prompt_file=None,
        model=None,
        tools=None,
        cwd=None,
        provider_role: str | None = None,
        llm_binding_snapshot: dict[str, Any] | None = None,
        session_dir: Path | None = None,
        session_path: Path | None = None,
        session_role: str | None = None,
        session_name: str | None = None,
        session_phase: str | None = None,
        session_round: int | None = None,
        session_skill_name: str | None = None,
        task_id: str | None = None,
    ):
        self._cwd = self.resolve_cwd(cwd)
        self._system_prompt_file = system_prompt_file
        self._model = model
        self._tools = tools
        self._provider_role = str(provider_role or "").strip() or None
        self._llm_binding_snapshot = llm_binding_snapshot or None
        self._provider_runtime: dict[str, Any] | None = None
        self._agent_dir: Path | None = None
        self._agent_tmp_root: Path | None = None
        self._runtime_dir: Path | None = None
        self._session_dir = session_dir
        self._session_path = session_path
        self._session_role = str(session_role or "").strip() or None
        self._session_name = str(session_name or "").strip() or None
        self._session_phase = str(session_phase or "").strip() or None
        self._session_round = session_round
        self._session_skill_name = str(session_skill_name or "").strip() or None
        self._task_id = str(task_id or "").strip() or None
        self._session_status = "created"
        self._register_session("created")
        self._start()

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        return max(1, len(str(text or "")) // 4)

    @staticmethod
    def _parse_context_overflow_details(error_text: str | None) -> dict[str, int]:
        text = str(error_text or "")
        details = {
            "actual_input_tokens": 0,
            "provider_reported_context_length": 0,
            "proxy_reserved_tokens": 0,
            "context_length": 0,
        }
        if not text:
            return details
        patterns = {
            "actual_input_tokens": r"input has\s+(\d[\d,]*)\s+tokens",
            "provider_reported_context_length": r"maximum context length is\s+(\d[\d,]*)\s+tokens",
            "proxy_reserved_tokens": r"reserves\s+(\d[\d,]*)\s+safety-buffer tokens",
        }
        for key, pattern in patterns.items():
            match = re.search(pattern, text, re.IGNORECASE)
            if not match:
                continue
            try:
                details[key] = int(match.group(1).replace(",", ""))
            except ValueError:
                continue
        details["context_length"] = details["provider_reported_context_length"]
        return details

    @classmethod
    def _is_context_overflow_error(cls, error_text: str | None) -> bool:
        if not error_text:
            return False
        lowered = str(error_text).lower()
        if cls._parse_context_overflow_details(error_text).get("context_length", 0) > 0:
            return True
        return any(
            marker in lowered
            for marker in (
                "maximum context length",
                "prefill_context_length_exceeded",
                "input has",
                "safety-buffer",
                "context length",
            )
        )

    def _context_window(self) -> int:
        runtime = self._provider_runtime or {}
        models_json = runtime.get("models_json") if isinstance(runtime.get("models_json"), dict) else {}
        providers = models_json.get("providers") if isinstance(models_json.get("providers"), dict) else {}
        for provider_payload in providers.values():
            if not isinstance(provider_payload, dict):
                continue
            models = provider_payload.get("models") if isinstance(provider_payload.get("models"), list) else []
            for item in models:
                if not isinstance(item, dict):
                    continue
                value = item.get("contextWindow") or item.get("contextLength")
                try:
                    parsed = int(value)
                except (TypeError, ValueError):
                    parsed = 0
                if parsed > 0:
                    return parsed
        return _DEFAULT_CONTEXT_WINDOW

    def _single_input_token_estimate(self, prompt: str) -> int:
        system_prompt = ""
        if self._system_prompt_file and Path(self._system_prompt_file).exists():
            try:
                system_prompt = Path(self._system_prompt_file).read_text(encoding="utf-8")
            except Exception:
                system_prompt = ""
        return self._estimate_tokens(system_prompt + "\n\n" + str(prompt or "")) + _PROMPT_TOKEN_OVERHEAD

    @staticmethod
    def _effective_context_limit(context_window: int, proxy_reserved_tokens: int = 0) -> int:
        reserve = max(int(proxy_reserved_tokens or 0), 4096)
        return max(1, int(context_window) - reserve - 4096)

    @classmethod
    def _preflight_limit(cls, context_window: int, proxy_reserved_tokens: int = 0) -> int:
        return max(1, int(cls._effective_context_limit(context_window, proxy_reserved_tokens) * _SINGLE_INPUT_CONTEXT_RATIO))

    def _register_session(self, status: str) -> None:
        if self._session_dir is None or self._session_path is None:
            return
        update_session_index(
            self._session_dir,
            role=self._session_role or "agent",
            name=self._session_name or "default",
            session_file=self._session_path.name,
            provider_role=self._provider_role,
            phase=self._session_phase or "unknown",
            status=status,
            round_id=self._session_round,
            skill_name=self._session_skill_name,
        )
        self._session_status = status

    def _mark_session_active(self) -> None:
        self._register_session("running")

    def _mark_session_failed(self) -> None:
        self._register_session("failed")

    def _mark_session_closed(self) -> None:
        self._register_session("closed")

    def _resolve_provider_runtime(self) -> dict[str, Any] | None:
        if self._provider_role is None:
            return None
        if self._provider_runtime is not None:
            return self._provider_runtime

        config_key = ROLE_CONFIG_FILE_KEYS.get(self._provider_role)
        if not config_key:
            raise ValueError(f"未知 LLM Provider 角色: {self._provider_role}")

        if self._llm_binding_snapshot:
            roles = self._llm_binding_snapshot.get("roles") if isinstance(self._llm_binding_snapshot.get("roles"), dict) else {}
            provider = roles.get(self._provider_role) if isinstance(roles.get(self._provider_role), dict) else None
            if provider is not None:
                provider_key = str(provider.get("config_file_key") or provider.get("provider_key") or "").strip()
                if provider_key:
                    configured_model = str(provider.get("model_selector") or provider.get("model") or "").strip()
                    selected_provider_key, resolved_model, cli_model = resolve_provider_selector(
                        provider_key,
                        configured_model,
                        self._model,
                    )
                    self._provider_runtime = {
                        "config_file_key": str(provider.get("config_file_key") or provider_key).strip() or provider_key,
                        "provider_key": provider_key,
                        "resolved_model": resolved_model,
                        "cli_model": cli_model,
                        "env": {},
                        "models_json": ensure_models_json_context_window(
                            provider.get("models_json") if isinstance(provider.get("models_json"), dict) else {},
                        ),
                        "settings_json": build_settings_json(selected_provider_key, resolved_model)
                        | (
                            provider.get("settings_json")
                            if isinstance(provider.get("settings_json"), dict)
                            else {}
                        ),
                        "runtime_dir": str(provider.get("runtime_dir") or "").strip() or None,
                    }
                    return self._provider_runtime
            log.warning(
                "llm binding snapshot missing usable provider for role %s, fallback to runtime defaults",
                self._provider_role,
            )
            return None

        from app.model import get_config_value, get_db_session

        db = get_db_session()
        try:
            provider_key = str(get_config_value(db, config_key, default="") or "").strip()
            configured_model = str(get_config_value(db, ROLE_MODEL_CONFIG_KEYS.get(self._provider_role, ""), default="") or "").strip()
        finally:
            db.close()
        if not provider_key:
            log.warning(
                "runtime llm provider for role %s is not configured, fallback to default agent runtime",
                self._provider_role,
            )
            return None

        provider = get_configcenter_client().get_llm_config_file(provider_key)
        selected_provider_key, resolved_model, cli_model = resolve_provider_selector(
            provider_key,
            configured_model or str(provider.get("default_model") or "").strip(),
            self._model,
        )
        self._provider_runtime = {
            "config_file_key": provider_key,
            "provider_key": selected_provider_key,
            "resolved_model": resolved_model,
            "cli_model": cli_model,
            "env": {},
            "models_json": ensure_models_json_context_window(
                provider.get("models_json") if isinstance(provider.get("models_json"), dict) else {},
            ),
            "settings_json": build_settings_json(selected_provider_key, resolved_model),
            "runtime_dir": None,
        }
        return self._provider_runtime

    def _prepare_agent_dir(self) -> tuple[Path | None, dict[str, str]]:
        runtime = self._resolve_provider_runtime()
        if runtime is None:
            return None, {}
        if not self._task_id or not isinstance(self._llm_binding_snapshot, dict):
            raise ValueError("PiRpcClient 需要 task_id 与任务级 llm_binding_snapshot 才能构造角色级 runtime")
        project_id = str(self._llm_binding_snapshot.get("project_id") or "").strip()
        if not project_id:
            project_id = str(self._llm_binding_snapshot.get("_project_id") or "").strip()
        if not project_id:
            raise ValueError("llm_binding_snapshot 缺少 project_id，无法构造角色级 runtime")
        role = str(self._provider_role or "").strip()
        from app.services.task_manager import role_runtime_dir_for_task
        agent_dir = Path(
            str(runtime.get("runtime_dir") or "").strip()
            or role_runtime_dir_for_task(project_id=project_id, task_id=self._task_id, role=role)
        )
        agent_dir.mkdir(parents=True, exist_ok=True)
        (agent_dir / "models.json").write_text(
            json.dumps(runtime["models_json"], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        (agent_dir / "settings.json").write_text(
            json.dumps(runtime["settings_json"], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        task_agent_key = None
        if isinstance(self._llm_binding_snapshot, dict):
            task_agent_key = self._llm_binding_snapshot.get("agent_task_key")
        auth_payload = (
            {
                "agent_task_key_id": str(task_agent_key.get("id") or "").strip() or None,
                "agent_task_key_name": str(task_agent_key.get("name") or "").strip() or None,
                "agent_task_key_prefix": str(task_agent_key.get("prefix") or "").strip() or None,
                "agent_task_key_secret": str(task_agent_key.get("secret") or "").strip() or None,
                "agent_task_key_source": str(task_agent_key.get("source") or "").strip() or None,
            }
            if isinstance(task_agent_key, dict)
            else {}
        )
        (agent_dir / "auth.json").write_text(
            json.dumps(auth_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        self._agent_tmp_root = agent_dir.parent
        self._agent_dir = agent_dir
        self._runtime_dir = agent_dir
        return agent_dir, dict(runtime["env"])

    def _start(self):
        try:
            agent_dir, runtime_env = self._prepare_agent_dir()
            resolved_model = self._provider_runtime["cli_model"] if self._provider_runtime else self._model
            args = self.build_args(
                system_prompt_file=self._system_prompt_file,
                model=resolved_model,
                tools=self._tools,
                thinking_level=get_agent_thinking_level(),
                session_dir=self._session_dir,
                session_path=self._session_path,
            )
            env = os.environ.copy()
            if agent_dir is not None:
                env[PI_AGENT_DIR_ENV] = str(agent_dir)
                env.update(runtime_env)
            log_event(
                log,
                logging.INFO,
                "starting pi rpc process",
                event="pi_process_start",
                command=" ".join(args),
                cwd=self._cwd,
                role=self._provider_role,
                provider_key=(self._provider_runtime or {}).get("provider_key"),
                model=resolved_model,
                pi_coding_agent_dir=str(agent_dir) if agent_dir is not None else None,
            )
            self.proc = subprocess.Popen(
                args,
                cwd=self._cwd,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            self._mark_session_active()
            self.send({"type": "set_auto_retry", "enabled": True})
        except Exception:
            self._mark_session_failed()
            self._cleanup_agent_dir()
            raise

    def _respawn(self):
        log_event(
            log,
            logging.WARNING,
            "respawning pi rpc process after termination",
            event="pi_process_respawn",
        )
        self.close()
        self._start()

    def send(self, command: dict):
        if self.proc.poll() is not None or self.proc.stdin is None:
            return
        self.proc.stdin.write(json.dumps(command) + "\n")
        self.proc.stdin.flush()

    def _process_exit_error(self, stop_type: str) -> RuntimeError:
        returncode = self.proc.poll()
        stderr_text = ""
        if returncode is not None:
            try:
                if self.proc.stderr is not None:
                    stderr_text = self.proc.stderr.read().strip()
            except Exception:
                stderr_text = ""
        detail = f"pi process exited before emitting {stop_type}"
        if returncode is not None:
            detail += f" (exit_code={returncode})"
        if stderr_text:
            detail += f": {stderr_text[-4000:]}"
        return RuntimeError(detail)

    def _read_until(self, stop_type: str):
        assert self.proc.stdout is not None
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise self._process_exit_error(stop_type)
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            yield event
            if event.get("type") == stop_type:
                return

    @staticmethod
    def extract_assistant_text(events: list[dict[str, Any]]) -> str:
        parts: list[str] = []
        for event in events:
            if event.get("type") != "message_end":
                continue
            message = event.get("message", {})
            if message.get("role") != "assistant":
                continue
            for block in message.get("content", []):
                if block.get("type") == "text":
                    parts.append(block["text"])
        return "\n".join(parts) if parts else ""

    def _drain_active_turn(self):
        log_event(
            log,
            logging.WARNING,
            "pi reported agent already processing; draining current turn",
            event="pi_prompt_busy_drain",
        )
        for _ in self._read_until("agent_end"):
            pass

    def _prompt_once(
        self,
        message: str,
        stream_callback: Optional[Callable[[dict[str, Any]], None]] = None,
        timeout_seconds: int | float | None = None,
    ) -> str:
        self._mark_session_active()
        timer: threading.Thread | None = None
        timed_out = threading.Event()
        watchdog_stop = threading.Event()
        last_activity_at = time.monotonic()

        def _mark_activity() -> None:
            nonlocal last_activity_at
            last_activity_at = time.monotonic()
        try:
            if timeout_seconds is not None and float(timeout_seconds) > 0:
                idle_timeout_seconds = float(timeout_seconds)

                def _kill_for_idle_timeout() -> None:
                    while not watchdog_stop.wait(timeout=1.0):
                        if self.proc.poll() is not None:
                            return
                        if (time.monotonic() - last_activity_at) < idle_timeout_seconds:
                            continue
                        timed_out.set()
                        try:
                            pgid = os.getpgid(self.proc.pid)
                            os.killpg(pgid, signal.SIGKILL)
                        except Exception:
                            try:
                                self.proc.kill()
                            except Exception:
                                pass
                        return

                timer = threading.Thread(target=_kill_for_idle_timeout, name="pi-rpc-idle-timeout", daemon=True)
                timer.start()
            self.send(
                {
                    "type": "prompt",
                    "message": message,
                    "streamingBehavior": "followUp",
                }
            )
            _mark_activity()

            events: list[dict[str, Any]] = []
            for event in self._read_until("agent_end"):
                _mark_activity()
                event_type = event.get("type", "")
                if (
                    event_type == "response"
                    and event.get("command") == "prompt"
                    and not event.get("success")
                ):
                    error = event.get("error", "unknown")
                    if "already processing" in str(error).lower():
                        self._drain_active_turn()
                        raise RuntimeError("__PI_BUSY__")
                    raise RuntimeError(f"Prompt failed: {error}")

                if stream_callback is not None:
                    try:
                        stream_callback(event)
                    except Exception:
                        pass

                events.append(event)

            self._mark_session_active()
            for event in reversed(events):
                if (
                    event.get("type") == "message_end"
                    and event.get("message", {}).get("role") == "assistant"
                    and event.get("message", {}).get("stopReason") == "error"
                ):
                    raise RuntimeError(
                        event.get("message", {}).get("errorMessage", "API error")
                    )
                if event.get("type") == "message_end":
                    break

            return self.extract_assistant_text(events)
        except RuntimeError:
            if timed_out.is_set() and self.proc.poll() is not None and timeout_seconds is not None and float(timeout_seconds) > 0:
                raise RuntimeError(f"Prompt idle timed out after {float(timeout_seconds):.0f}s")
            raise
        finally:
            watchdog_stop.set()
            if timer is not None:
                timer.join(timeout=0.1)

    def _run_compaction(self) -> bool:
        try:
            self._prompt_once(_COMPACTION_TRIGGER_PROMPT, stream_callback=None, timeout_seconds=get_agent_run_timeout_seconds())
            return True
        except Exception:
            return False

    def prompt(
        self,
        message: str,
        stream_callback: Optional[Callable[[dict[str, Any]], None]] = None,
    ) -> PiPromptResult:
        result = PiPromptResult()
        result.provider_role = self._provider_role
        result.runtime_dir = str(self._runtime_dir) if self._runtime_dir is not None else None
        result.context_window = self._context_window()
        estimated_tokens = self._single_input_token_estimate(message)
        if estimated_tokens > self._preflight_limit(result.context_window, 0):
            result.context_budget_exceeded_preflight = True
            if self._session_path is not None:
                result.compaction_requested = True
                result.compaction_completed = self._run_compaction()
                if result.compaction_completed and self._single_input_token_estimate(message) <= self._preflight_limit(result.context_window, 0):
                    pass
                else:
                    result.context_overflow_failed_after_compaction = True
                    result.error = "preflight_context_length_exceeded"
                    return result
            else:
                result.context_overflow_failed_after_compaction = True
                result.error = "preflight_context_length_exceeded"
                return result
        timeout_seconds = get_agent_run_timeout_seconds()
        timeout_retry_enabled = get_agent_timeout_retry_enabled()
        timeout_max_retries = get_agent_timeout_max_retries()
        busy_retries = 2
        timeout_failures = 0
        for attempt in range(1 + self.RETRIES):
            try:
                for busy_attempt in range(busy_retries + 1):
                    try:
                        result.output = self._prompt_once(
                            message,
                            stream_callback=stream_callback,
                            timeout_seconds=timeout_seconds,
                        )
                        return result
                    except RuntimeError as exc:
                        if self._is_context_overflow_error(str(exc)):
                            overflow = self._parse_context_overflow_details(str(exc))
                            result.context_window = overflow.get("context_length") or result.context_window
                            result.proxy_reserved_tokens = overflow.get("proxy_reserved_tokens", 0)
                            if self._session_path is None:
                                result.error = str(exc)
                                result.context_overflow_failed_after_compaction = True
                                return result
                            result.compaction_requested = True
                            result.compaction_completed = self._run_compaction()
                            if not result.compaction_completed:
                                result.error = str(exc)
                                result.context_overflow_failed_after_compaction = True
                                return result
                            if self._single_input_token_estimate(message) > self._preflight_limit(result.context_window, result.proxy_reserved_tokens):
                                result.error = str(exc)
                                result.context_overflow_failed_after_compaction = True
                                return result
                            result.context_overflow_retrying = True
                            result.output = self._prompt_once(
                                message,
                                stream_callback=stream_callback,
                                timeout_seconds=timeout_seconds,
                            )
                            return result
                        if "timed out after" in str(exc).lower():
                            timeout_failures += 1
                            can_retry = timeout_retry_enabled and (
                                timeout_max_retries < 0 or timeout_failures <= timeout_max_retries
                            )
                            if not can_retry:
                                self._mark_session_failed()
                                raise
                            log_event(
                                log,
                                logging.WARNING,
                                "retrying prompt after timeout",
                                event="pi_prompt_timeout_retry",
                                retry=timeout_failures,
                                max_retries=timeout_max_retries,
                                timeout_seconds=timeout_seconds,
                            )
                            self._respawn()
                            time.sleep(1)
                            continue
                        if str(exc) != "__PI_BUSY__" or busy_attempt >= busy_retries:
                            raise
                        log_event(
                            log,
                            logging.WARNING,
                            "retrying prompt after busy response",
                            event="pi_prompt_busy_retry",
                            retry=busy_attempt + 1,
                        )
            except RuntimeError:
                if self.proc.poll() is None:
                    raise
                if attempt >= self.RETRIES:
                    self._mark_session_failed()
                    raise
                self._respawn()

        result.error = "Prompt failed after exhausting retries"
        return result

    def get_messages(self):
        self.send({"id": "req-message", "type": "get_messages"})
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            event = json.loads(line.strip())
            if (
                event.get("type") == "response"
                and event.get("command") == "get_messages"
            ):
                return event["data"]["messages"]
        return None

    def get_token_stats(self):
        try:
            self.send({"id": "req-stats", "type": "get_session_stats"})
            assert self.proc.stdout is not None
            for line in self.proc.stdout:
                event = json.loads(line.strip())
                if event.get("type") == "error" and event.get("command") == "get_session_stats":
                    return None
                if (
                    event.get("type") == "response"
                    and event.get("command") == "get_session_stats"
                ):
                    data = event.get("data")
                    return data if isinstance(data, dict) else None
        except Exception:
            return None
        return None

    def close(self):
        try:
            if self.proc.poll() is not None:
                if self._session_status not in {"closed", "failed"}:
                    self._mark_session_closed()
                return
            try:
                pgid = os.getpgid(self.proc.pid)
            except Exception:
                pgid = None
            try:
                self.proc.stdin.close()
            except Exception:
                pass
            try:
                if pgid is not None:
                    os.killpg(pgid, signal.SIGTERM)
                else:
                    self.proc.terminate()
            except Exception:
                self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try:
                    if pgid is not None:
                        os.killpg(pgid, signal.SIGKILL)
                    else:
                        self.proc.kill()
                finally:
                    self.proc.wait()
        finally:
            if self._session_status not in {"closed", "failed"}:
                self._mark_session_closed()
            self._cleanup_agent_dir()

    def _cleanup_agent_dir(self) -> None:
        if self._agent_dir is None:
            return
        shutil.rmtree(self._agent_dir, ignore_errors=True)
        self._agent_tmp_root = None
        self._agent_dir = None
