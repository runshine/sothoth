"""Pi RPC client wrapper for firmware unpacking workflows."""

from __future__ import annotations

import json
import logging
import os
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
    get_agent_run_timeout_seconds,
    get_agent_timeout_max_retries,
    get_agent_timeout_retry_enabled,
    resolve_provider_selector,
)
from app.unpacker_engine_session import update_session_index


log = logging.getLogger("unpacker.engine")


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
                        "models_json": provider.get("models_json") if isinstance(provider.get("models_json"), dict) else {},
                        "settings_json": provider.get("settings_json") if isinstance(provider.get("settings_json"), dict) else build_settings_json(selected_provider_key, resolved_model),
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
            "models_json": provider.get("models_json") if isinstance(provider.get("models_json"), dict) else {},
            "settings_json": build_settings_json(selected_provider_key, "auto"),
        }
        return self._provider_runtime

    def _prepare_agent_dir(self) -> tuple[Path | None, dict[str, str]]:
        runtime = self._resolve_provider_runtime()
        if runtime is None:
            return None, {}
        agent_root = Path.home() / ".pi" / "agent"
        task_dir_name = self._task_id or f"adhoc-{os.getpid()}"
        config_file_key = str(runtime.get("config_file_key") or runtime.get("provider_key") or "default").replace("/", "_")
        agent_dir = agent_root / "secflow-app-firmware-unpacker" / "tasks" / task_dir_name / "configs" / config_file_key
        agent_dir.mkdir(parents=True, exist_ok=True)
        (agent_dir / "models.json").write_text(
            json.dumps(runtime["models_json"], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        (agent_dir / "settings.json").write_text(
            json.dumps(runtime["settings_json"], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        (agent_dir / "auth.json").write_text("{}", encoding="utf-8")
        self._agent_tmp_root = agent_dir.parent
        self._agent_dir = agent_dir
        return agent_dir, dict(runtime["env"])

    def _start(self):
        try:
            agent_dir, runtime_env = self._prepare_agent_dir()
            resolved_model = self._provider_runtime["cli_model"] if self._provider_runtime else self._model
            args = self.build_args(
                system_prompt_file=self._system_prompt_file,
                model=resolved_model,
                tools=self._tools,
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
        timer: threading.Timer | None = None
        timed_out = threading.Event()
        try:
            if timeout_seconds is not None and float(timeout_seconds) > 0:
                def _kill_for_timeout() -> None:
                    timed_out.set()
                    try:
                        if self.proc.poll() is None:
                            pgid = os.getpgid(self.proc.pid)
                            os.killpg(pgid, signal.SIGKILL)
                    except Exception:
                        try:
                            self.proc.kill()
                        except Exception:
                            pass
                timer = threading.Timer(float(timeout_seconds), _kill_for_timeout)
                timer.daemon = True
                timer.start()
            self.send(
                {
                    "type": "prompt",
                    "message": message,
                    "streamingBehavior": "followUp",
                }
            )

            events: list[dict[str, Any]] = []
            for event in self._read_until("agent_end"):
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
                raise RuntimeError(f"Prompt timed out after {float(timeout_seconds):.0f}s")
            raise
        finally:
            if timer is not None:
                timer.cancel()

    def prompt(
        self,
        message: str,
        stream_callback: Optional[Callable[[dict[str, Any]], None]] = None,
    ) -> str:
        timeout_seconds = get_agent_run_timeout_seconds()
        timeout_retry_enabled = get_agent_timeout_retry_enabled()
        timeout_max_retries = get_agent_timeout_max_retries()
        busy_retries = 2
        timeout_failures = 0
        for attempt in range(1 + self.RETRIES):
            try:
                for busy_attempt in range(busy_retries + 1):
                    try:
                        return self._prompt_once(
                            message,
                            stream_callback=stream_callback,
                            timeout_seconds=timeout_seconds,
                        )
                    except RuntimeError as exc:
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

        raise RuntimeError("Prompt failed after exhausting retries")

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
        self.send({"id": "req-stats", "type": "get_session_stats"})
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            event = json.loads(line.strip())
            if (
                event.get("type") == "response"
                and event.get("command") == "get_session_stats"
            ):
                return event["data"]
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
