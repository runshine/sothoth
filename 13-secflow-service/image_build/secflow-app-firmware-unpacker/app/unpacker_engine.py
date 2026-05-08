"""Firmware unpacking execution engine used by the task manager."""

from __future__ import annotations

import json
import logging
import os
import re
import signal
import shutil
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from app.logging_utils import log_event
from app.preprocess import detect_format, run_preprocess
from app.services.configcenter import get_configcenter_client
from app.skill_store import (
    DEFAULT_PROMOTION_THRESHOLD,
    compute_family_id,
    list_skills,
    match_skill,
    parse_skill_metadata,
    register_skill_success,
    save_candidate_skill,
)

log = logging.getLogger("unpacker.engine")
debug_mode = True

AGENT_DIR = Path(
    os.environ.get(
        "UNPACKER_AGENT_DIR",
        str(Path(__file__).resolve().parent / "agent"),
    )
)

EXEC_AGENT_DEF = str(AGENT_DIR / "firmware-unpacker.md")
VAL_AGENT_DEF = str(AGENT_DIR / "firmware-unpack-reviewer.md")
CLEAN_AGENT_DEF = str(AGENT_DIR / "firmware-extract-cleanup.md")
AUTHOR_AGENT_DEF = str(AGENT_DIR / "firmware-skill-author.md")

EXEC_FIRST_TMPL = AGENT_DIR / "prompt" / "unpack-firmware.md"
EXEC_RETRY_TMPL = AGENT_DIR / "prompt" / "retry-firmware-unpack.md"
VAL_PROMPT_TMPL = AGENT_DIR / "prompt" / "review-firmware-unpack.md"
CLEAN_PROMPT_TMPL = AGENT_DIR / "prompt" / "cleanup-firmware.md"
AUTHOR_PROMPT_TMPL = AGENT_DIR / "prompt" / "author-firmware-skill.md"

TOOLS_DIR = Path(os.environ.get("UNPACKER_TOOLS_DIR", "/data/secflow-app-firmware-unpacker/tools"))
LOG_OUTPUT_DIR = Path(os.environ.get("UNPACKER_LOG_DIR", "/workspace/log_output"))
PI_AGENT_DIR_ENV = "PI_CODING_AGENT_DIR"
PI_MODELS_JSON_ENV = "PI_MODELS_JSON"
ROLE_CONFIG_KEYS = {
    "executor": "llm_provider_key_executor",
    "reviewer": "llm_provider_key_reviewer",
    "cleaner": "llm_provider_key_cleaner",
    "skill_author": "llm_provider_key_skill_author",
    "skill_executor": "llm_provider_key_skill_executor",
}


def _get_max_retries() -> int:
    try:
        from app.model import get_config_value, get_db_session

        db = get_db_session()
        try:
            return get_config_value(db, "max_retries", default=5)
        finally:
            db.close()
    except Exception:
        return 5


def _preview_text(text: str, limit: int = 240) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[:limit] + "..."


def _provider_api(provider_type: str) -> str:
    normalized = str(provider_type or "").strip().lower()
    if normalized == "anthropic":
        return "anthropic-messages"
    return "openai-completions"


def _provider_base_env(provider: dict[str, Any]) -> dict[str, str]:
    provider_type = str(provider.get("provider_type") or "").strip().lower()
    api_base = str(provider.get("api_base") or "").strip()
    api_key = str(provider.get("api_key") or "").strip()
    model = str(provider.get("model") or "").strip()
    api_version = str(provider.get("api_version") or "").strip()

    if provider_type == "openai-compatible":
        return {"OPENAI_BASE_URL": api_base, "OPENAI_API_KEY": api_key, "OPENAI_MODEL": model}
    if provider_type == "azure-openai":
        return {
            "AZURE_OPENAI_ENDPOINT": api_base,
            "AZURE_OPENAI_API_KEY": api_key,
            "AZURE_OPENAI_API_VERSION": api_version,
            "AZURE_OPENAI_DEPLOYMENT": model,
        }
    if provider_type == "anthropic":
        return {"ANTHROPIC_BASE_URL": api_base, "ANTHROPIC_AUTH_TOKEN": api_key, "ANTHROPIC_MODEL": model}
    if provider_type == "deepseek":
        return {"DEEPSEEK_BASE_URL": api_base, "DEEPSEEK_API_KEY": api_key, "DEEPSEEK_MODEL": model}
    if provider_type == "qwen":
        return {"QWEN_BASE_URL": api_base, "QWEN_API_KEY": api_key, "QWEN_MODEL": model}
    if provider_type == "ollama":
        return {"OLLAMA_BASE_URL": api_base, "OLLAMA_MODEL": model}
    if provider_type == "moonshot":
        return {"MOONSHOT_BASE_URL": api_base, "MOONSHOT_API_KEY": api_key, "MOONSHOT_MODEL": model}
    return {"LLM_BASE_URL": api_base, "LLM_API_KEY": api_key, "LLM_MODEL": model}


def _normalize_provider_env_bindings(provider: dict[str, Any]) -> dict[str, str]:
    merged = {
        key: value
        for key, value in _provider_base_env(provider).items()
        if str(key or "").strip()
    }
    custom_bindings = provider.get("env_bindings") if isinstance(provider.get("env_bindings"), dict) else {}
    for raw_key, raw_value in custom_bindings.items():
        key = str(raw_key or "").strip()
        if not key:
            continue
        merged[key] = "" if raw_value is None else str(raw_value)
    return merged


def _detect_api_key_env_name(env_map: dict[str, str]) -> str:
    for key in (
        "OPENAI_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "AZURE_OPENAI_API_KEY",
        "DEEPSEEK_API_KEY",
        "QWEN_API_KEY",
        "MOONSHOT_API_KEY",
        "LLM_API_KEY",
    ):
        if key in env_map:
            return key
    return "OPENAI_API_KEY"


def _resolve_provider_model(provider_key: str, configured_model: str, explicit_model: str | None) -> str:
    requested = str(explicit_model or "").strip()
    provider_default_model = str(configured_model or "").strip()
    if not requested:
        if not provider_default_model:
            raise ValueError(f"LLM Provider {provider_key} 缺少默认 model")
        return provider_default_model
    if "/" in requested:
        prefix, _, model_id = requested.partition("/")
        if str(prefix).strip() != provider_key:
            raise ValueError(
                f"显式模型 {requested} 与当前角色绑定的 Provider {provider_key} 不一致"
            )
        normalized_model = str(model_id or "").strip()
        if not normalized_model:
            raise ValueError(f"显式模型 {requested} 缺少 model_id")
        return normalized_model
    return requested


def _build_models_json(provider: dict[str, Any], resolved_model: str) -> dict[str, Any]:
    provider_key = str(provider.get("provider_key") or "").strip()
    api_base = str(provider.get("api_base") or "").strip()
    if not provider_key or not api_base or not resolved_model:
        raise ValueError("LLM Provider缺少provider_key/api_base/model")
    api_key_env = _detect_api_key_env_name(_normalize_provider_env_bindings(provider))
    return {
        "providers": {
            provider_key: {
                "baseUrl": api_base.rstrip("/"),
                "api": _provider_api(str(provider.get("provider_type") or "")),
                "apiKey": api_key_env,
                "models": [
                    {
                        "id": resolved_model,
                        "name": resolved_model,
                        "reasoning": False,
                        "input": ["text"],
                        "contextWindow": 128000,
                        "maxTokens": provider.get("max_tokens") or 16384,
                        "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0},
                    }
                ],
            }
        }
    }


def _build_settings_json(provider_key: str, resolved_model: str) -> dict[str, Any]:
    return {
        "defaultProvider": provider_key,
        "defaultModel": resolved_model,
        "retry": {"enabled": True},
    }


def load_agent_def(md_path: str) -> dict:
    content = Path(md_path).read_text()
    match = re.match(r"^---\n(.*?)\n---\n(.*)$", content, re.DOTALL)
    if not match:
        raise ValueError(f"Invalid agent definition (missing frontmatter): {md_path}")

    fm: dict[str, str] = {}
    for line in match.group(1).split("\n"):
        if ":" in line:
            key, _, value = line.partition(":")
            fm[key.strip()] = value.strip()

    tools = [item.strip() for item in fm.get("tools", "").split(",") if item.strip()]
    return {
        "name": fm.get("name", Path(md_path).stem),
        "tools": tools,
        "model": fm.get("model") or None,
        "system_prompt": match.group(2).strip(),
    }


def render_prompt(template_path: Path, firmware_path: str, output_path: str) -> str:
    text = template_path.read_text()
    text = text.replace("$input", firmware_path)
    text = text.replace("$output", output_path)
    return text


def render_template(template_path: Path, replacements: dict[str, str]) -> str:
    text = template_path.read_text()
    for key, value in replacements.items():
        text = text.replace(key, value)
    return text


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
    def build_args(*, system_prompt_file=None, model=None, tools=None):
        args = ["pi", "--mode", "rpc", "--no-session"]
        if system_prompt_file:
            args.extend(["--append-system-prompt", system_prompt_file])
        if model:
            args.extend(["--model", model])
        if tools:
            args.extend(["--tools", ",".join(tools)])
        return args

    def __init__(self, *, system_prompt_file=None, model=None, tools=None, cwd=None, provider_role: str | None = None, llm_binding_snapshot: dict[str, Any] | None = None):
        self._cwd = self.resolve_cwd(cwd)
        self._system_prompt_file = system_prompt_file
        self._model = model
        self._tools = tools
        self._provider_role = str(provider_role or "").strip() or None
        self._llm_binding_snapshot = llm_binding_snapshot or None
        self._provider_runtime: dict[str, Any] | None = None
        self._agent_dir: Path | None = None
        self._agent_tmp_root: Path | None = None
        self._start()

    def _resolve_provider_runtime(self) -> dict[str, Any] | None:
        if self._provider_role is None:
            return None
        if self._provider_runtime is not None:
            return self._provider_runtime

        config_key = ROLE_CONFIG_KEYS.get(self._provider_role)
        if not config_key:
            raise ValueError(f"未知 LLM Provider 角色: {self._provider_role}")

        if self._llm_binding_snapshot:
            roles = self._llm_binding_snapshot.get("roles") if isinstance(self._llm_binding_snapshot.get("roles"), dict) else {}
            provider = roles.get(self._provider_role) if isinstance(roles.get(self._provider_role), dict) else None
            if provider is None:
                raise ValueError(f"任务 LLM 快照缺少角色 {self._provider_role} 的配置")
            provider_key = str(provider.get("provider_key") or "").strip()
            if not provider_key:
                raise ValueError(f"任务 LLM 快照中的角色 {self._provider_role} 缺少 provider_key")
            resolved_model = _resolve_provider_model(
                provider_key,
                str(provider.get("model") or "").strip(),
                self._model,
            )
            env_map = _normalize_provider_env_bindings(provider)
            env_map["SECFLOW_LLM_PROVIDER_KEY"] = provider_key
            env_map["SECFLOW_LLM_PROVIDER_TYPE"] = str(provider.get("provider_type") or "").strip()
            env_map["SECFLOW_LLM_MODEL"] = resolved_model
            self._provider_runtime = {
                "provider_key": provider_key,
                "provider_type": str(provider.get("provider_type") or "").strip(),
                "resolved_model": resolved_model,
                "env": env_map,
                "models_json": _build_models_json(provider, resolved_model),
                "settings_json": _build_settings_json(provider_key, resolved_model),
            }
            return self._provider_runtime

        from app.model import get_config_value, get_db_session

        db = get_db_session()
        try:
            provider_key = str(get_config_value(db, config_key, default="") or "").strip()
        finally:
            db.close()
        if not provider_key:
            raise ValueError(f"未配置角色 {self._provider_role} 的 LLM Provider")

        provider = get_configcenter_client().get_llm_provider(provider_key)
        resolved_model = _resolve_provider_model(
            provider_key,
            str(provider.get("model") or "").strip(),
            self._model,
        )
        env_map = _normalize_provider_env_bindings(provider)
        env_map["SECFLOW_LLM_PROVIDER_KEY"] = provider_key
        env_map["SECFLOW_LLM_PROVIDER_TYPE"] = str(provider.get("provider_type") or "").strip()
        env_map["SECFLOW_LLM_MODEL"] = resolved_model
        self._provider_runtime = {
            "provider_key": provider_key,
            "provider_type": str(provider.get("provider_type") or "").strip(),
            "resolved_model": resolved_model,
            "env": env_map,
            "models_json": _build_models_json(provider, resolved_model),
            "settings_json": _build_settings_json(provider_key, resolved_model),
        }
        return self._provider_runtime

    def _prepare_agent_dir(self) -> tuple[Path | None, dict[str, str]]:
        runtime = self._resolve_provider_runtime()
        if runtime is None:
            return None, {}
        tmp_root = Path(tempfile.mkdtemp(prefix=f"fw-pi-{self._provider_role or 'runtime'}-"))
        agent_dir = tmp_root / "agent"
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
        self._agent_tmp_root = tmp_root
        self._agent_dir = agent_dir
        return agent_dir, dict(runtime["env"])

    def _start(self):
        try:
            agent_dir, runtime_env = self._prepare_agent_dir()
            resolved_model = self._provider_runtime["resolved_model"] if self._provider_runtime else self._model
            args = self.build_args(
                system_prompt_file=self._system_prompt_file,
                model=resolved_model,
                tools=self._tools,
            )
            env = os.environ.copy()
            if agent_dir is not None:
                env[PI_AGENT_DIR_ENV] = str(agent_dir)
                env[PI_MODELS_JSON_ENV] = str(agent_dir / "models.json")
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
            self.send({"type": "set_auto_retry", "enabled": True})
        except Exception:
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

    def _read_until(self, stop_type: str):
        assert self.proc.stdout is not None
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError(f"pi process exited before emitting {stop_type}")
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
    ) -> str:
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

            if debug_mode and event_type == "message_update":
                delta_info = event.get("assistantMessageEvent", {})
                if delta_info.get("type") == "text_delta":
                    print(delta_info.get("delta", ""), end="", flush=True)
                elif delta_info.get("type") == "thinking_delta":
                    print(delta_info.get("delta", ""), end="", flush=True)
                elif delta_info.get("type") == "toolcall_delta":
                    print(delta_info.get("delta", ""), end="", flush=True)

            if stream_callback is not None:
                try:
                    stream_callback(event)
                except Exception:
                    pass

            events.append(event)

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

    def prompt(
        self,
        message: str,
        stream_callback: Optional[Callable[[dict[str, Any]], None]] = None,
    ) -> str:
        busy_retries = 2
        for attempt in range(1 + self.RETRIES):
            try:
                for busy_attempt in range(busy_retries + 1):
                    try:
                        return self._prompt_once(message, stream_callback=stream_callback)
                    except RuntimeError as exc:
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
            self._cleanup_agent_dir()

    def _cleanup_agent_dir(self) -> None:
        if self._agent_tmp_root is None:
            return
        shutil.rmtree(self._agent_tmp_root, ignore_errors=True)
        self._agent_tmp_root = None
        self._agent_dir = None


def get_log_dir(output_path: str) -> Path:
    output_dir = Path(output_path)
    if output_dir.name == "output":
        log_dir = output_dir.parent / "run"
    else:
        log_dir = LOG_OUTPUT_DIR / output_dir.name
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


def _stringify_message_content(block: Any) -> str:
    if isinstance(block, str):
        return block.strip()
    if not isinstance(block, dict):
        return ""

    block_type = str(block.get("type") or "").strip()
    if block_type in {"text", "input_text", "output_text"}:
        return str(block.get("text") or block.get("content") or "").strip()
    if block_type in {"thinking", "reasoning"}:
        text = str(block.get("text") or block.get("content") or "").strip()
        return f"[thinking]\n{text}" if text else ""
    if block_type in {"tool_call", "tool_use"}:
        tool_name = str(block.get("name") or block.get("tool_name") or block.get("tool") or "").strip()
        tool_input = block.get("input") or block.get("arguments") or block.get("args")
        rendered_input = ""
        if tool_input not in (None, ""):
            try:
                rendered_input = json.dumps(tool_input, ensure_ascii=False, indent=2)
            except Exception:
                rendered_input = str(tool_input)
        header = f"[tool_call] {tool_name}".strip()
        return f"{header}\n{rendered_input}".strip()
    if block_type in {"tool_result", "tool_output"}:
        tool_name = str(block.get("name") or block.get("tool_name") or block.get("tool") or "").strip()
        output = block.get("output") or block.get("content") or block.get("result")
        rendered_output = ""
        if output not in (None, ""):
            try:
                rendered_output = json.dumps(output, ensure_ascii=False, indent=2)
            except Exception:
                rendered_output = str(output)
        header = f"[tool_result] {tool_name}".strip()
        return f"{header}\n{rendered_output}".strip()

    for key in ("text", "content", "message"):
        value = block.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    try:
        return json.dumps(block, ensure_ascii=False, indent=2)
    except Exception:
        return str(block).strip()


def _render_messages_transcript(messages: Any) -> str:
    if not isinstance(messages, list):
        return ""

    sections: list[str] = []
    for index, message in enumerate(messages, start=1):
        if not isinstance(message, dict):
            continue
        role = str(message.get("role") or "unknown").strip() or "unknown"
        stop_reason = str(message.get("stopReason") or "").strip()
        header = f"[{index}] {role}"
        if stop_reason:
            header += f" stopReason={stop_reason}"

        contents = message.get("content")
        body_parts: list[str] = []
        if isinstance(contents, list):
            for block in contents:
                rendered = _stringify_message_content(block)
                if rendered:
                    body_parts.append(rendered)
        elif contents:
            rendered = _stringify_message_content(contents)
            if rendered:
                body_parts.append(rendered)
        elif message.get("text"):
            body_parts.append(str(message.get("text")).strip())

        body = "\n\n".join(part for part in body_parts if part)
        sections.append(header if not body else f"{header}\n{body}")

    return "\n\n".join(sections).strip()


def _save_agent_log(client: PiRpcClient, log_dir: Path | None, name: str) -> dict:
    if log_dir is None:
        return {}

    token_stats: dict[str, Any] = {}
    try:
        messages = client.get_messages()
        if messages is not None:
            (log_dir / f"{name}_messages.json").write_text(
                json.dumps(messages, ensure_ascii=False, indent=2)
            )
            transcript = _render_messages_transcript(messages)
            if transcript:
                (log_dir / f"{name}_transcript.log").write_text(
                    transcript,
                    encoding="utf-8",
                )
    except Exception as exc:
        log_event(
            log,
            logging.WARNING,
            "failed to save agent messages",
            event="agent_log_fail",
            name=name,
            error=str(exc),
        )

    try:
        stats = client.get_token_stats()
        if stats and "tokens" in stats:
            token_stats = stats["tokens"]
            (log_dir / f"{name}_tokens.json").write_text(
                json.dumps(token_stats, indent=2)
            )
    except Exception as exc:
        log_event(
            log,
            logging.WARNING,
            "failed to get token stats",
            event="token_stats_fail",
            name=name,
            error=str(exc),
        )

    return token_stats


def _write_token_summary(log_dir: Path | None) -> None:
    if log_dir is None:
        return

    total = {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0, "total": 0}
    by_agent: dict[str, dict[str, Any]] = {}
    for token_file in sorted(log_dir.glob("*_tokens.json")):
        key = token_file.stem.replace("_tokens", "")
        try:
            token_data = json.loads(token_file.read_text())
            by_agent[key] = token_data
            for field in total:
                total[field] = total.get(field, 0) + token_data.get(field, 0)
        except Exception:
            continue

    summary = {"by_agent": by_agent, "grand_total": total}
    output_file = log_dir / "tokens_summary.json"
    output_file.write_text(json.dumps(summary, indent=2))


def _kill_process_tree(proc: subprocess.Popen[Any]) -> None:
    try:
        pgid = os.getpgid(proc.pid)
    except Exception:
        pgid = None
    try:
        if pgid is not None:
            os.killpg(pgid, signal.SIGTERM)
        else:
            proc.terminate()
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass
    try:
        proc.wait(timeout=5)
    except Exception:
        try:
            if pgid is not None:
                os.killpg(pgid, signal.SIGKILL)
            else:
                proc.kill()
        except Exception:
            pass


def extract_firmware_features(
    firmware_path: str,
    cancel_check: Optional[Callable[[], bool]] = None,
    register_cancel_hook: Optional[Callable[[Callable[[], None] | None], None]] = None,
) -> dict:
    path = Path(firmware_path)
    info = detect_format(firmware_path)
    features = {
        "filename": path.name,
        "ext": info["ext"],
        "ext2": info["ext2"],
        "fmt": info["fmt"] or "unknown",
        "size": 0,
        "magic_hex": info["magic"].hex()[:8] if info["magic"] else "",
        "binwalk_sigs": [],
    }
    try:
        features["size"] = os.path.getsize(firmware_path)
    except RuntimeError:
        raise
    except Exception:
        pass
    try:
        proc = subprocess.Popen(
            ["binwalk", "-B", firmware_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        if register_cancel_hook is not None:
            register_cancel_hook(lambda: _kill_process_tree(proc))
        while True:
            if cancel_check and cancel_check():
                _kill_process_tree(proc)
                raise RuntimeError("__CANCELLED__")
            if proc.poll() is not None:
                stdout, _stderr = proc.communicate()
                break
            time.sleep(0.2)
        for line in stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("DECIMAL") and not line.startswith("-"):
                parts = line.split(None, 2)
                if len(parts) >= 3:
                    features["binwalk_sigs"].append(parts[2][:100].lower())
    except Exception:
        pass
    finally:
        if register_cancel_hook is not None:
            register_cancel_hook(None)
    return features


def _is_review_success(review_text: str) -> bool:
    lowered = str(review_text or "").strip().lower()
    return '"result":"success"' in lowered or '"result": "success"' in lowered


def _write_json_log(log_dir: Path | None, name: str, payload: dict[str, Any]) -> None:
    if log_dir is None:
        return
    (log_dir / name).write_text(json.dumps(payload, ensure_ascii=False, indent=2))


def _append_stage_log(log_dir: Path | None, filename: str, message: str, **fields: Any) -> None:
    if log_dir is None:
        return
    stamp = datetime.utcnow().isoformat()
    line = f"[{stamp}] {message}"
    if fields:
        rendered = " ".join(
            f"{key}={json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else value}"
            for key, value in fields.items()
            if value is not None
        )
        if rendered:
            line = f"{line} {rendered}"
    with (log_dir / filename).open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def _append_stream_delta(log_dir: Path | None, filename: str, actor: str, event: dict[str, Any]) -> None:
    if log_dir is None or event.get("type") != "message_update":
        return
    delta_info = event.get("assistantMessageEvent", {})
    delta_type = str(delta_info.get("type") or "").strip()
    delta = str(delta_info.get("delta") or "").rstrip()
    if not delta_type or not delta:
        return
    for line in delta.splitlines():
        text = line.rstrip()
        if not text:
            continue
        _append_stage_log(
            log_dir,
            filename,
            f"[stream][{actor}][{delta_type}] {text}",
        )


def _run_reviewer(
    firmware_path: str,
    output_path: str,
    log_dir: Path | None,
    suffix: str,
    val_def: dict[str, Any],
    val_sp: str,
    llm_binding_snapshot: dict[str, Any] | None = None,
    bind_cancel_client: Optional[Callable[[PiRpcClient | None], None]] = None,
) -> tuple[bool, str]:
    _append_stage_log(
        log_dir,
        "stage4_llm_review.log",
        "starting review round",
        suffix=suffix,
        firmware_path=firmware_path,
        output_path=output_path,
    )
    validator = PiRpcClient(
        system_prompt_file=val_sp,
        model=val_def["model"],
        tools=val_def["tools"],
        provider_role="reviewer",
        llm_binding_snapshot=llm_binding_snapshot,
    )
    if bind_cancel_client:
        bind_cancel_client(validator)
    try:
        verify_result = validator.prompt(
            render_prompt(VAL_PROMPT_TMPL, firmware_path, output_path),
            stream_callback=lambda event: _append_stream_delta(
                log_dir,
                "stage4_llm_review.log",
                f"reviewer:{suffix}",
                event,
            ),
        )
        _save_agent_log(validator, log_dir, f"verifier_{suffix}")
        return _is_review_success(verify_result), verify_result
    finally:
        if bind_cancel_client:
            bind_cancel_client(None)
        validator.close()


def _write_system_prompt(content: str, prefix: str) -> str:
    temp_file = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        prefix=prefix,
        suffix=".md",
        delete=False,
    )
    temp_file.write(content)
    temp_file.flush()
    temp_file.close()
    return temp_file.name


def _run_skill_unpack(
    skill_meta: dict[str, Any],
    firmware_path: str,
    output_path: str,
    log_dir: Path | None,
    val_def: dict[str, Any],
    val_sp: str,
    llm_binding_snapshot: dict[str, Any] | None = None,
    bind_cancel_client: Optional[Callable[[PiRpcClient | None], None]] = None,
) -> dict[str, Any]:
    _append_stage_log(
        log_dir,
        "stage3_skill_exec.log",
        "starting skill execution",
        skill=skill_meta.get("path"),
        family_id=skill_meta.get("family_id"),
        skill_version=skill_meta.get("skill_version"),
        firmware_path=firmware_path,
        output_path=output_path,
    )
    skill_sp = _write_system_prompt(str(skill_meta.get("system_prompt") or ""), "firmware-skill-")
    executor = PiRpcClient(
        system_prompt_file=skill_sp,
        model=skill_meta.get("model"),
        tools=skill_meta.get("tools"),
        provider_role="skill_executor",
        llm_binding_snapshot=llm_binding_snapshot,
    )
    if bind_cancel_client:
        bind_cancel_client(executor)
    try:
        exec_result = executor.prompt(render_prompt(EXEC_FIRST_TMPL, firmware_path, output_path))
        _save_agent_log(executor, log_dir, "skill_executor")
        passed, review_result = _run_reviewer(
            firmware_path,
            output_path,
            log_dir,
            "skill",
            val_def,
            val_sp,
            llm_binding_snapshot=llm_binding_snapshot,
            bind_cancel_client=bind_cancel_client,
        )
        result = {
            "success": passed,
            "method": f"skill:{skill_meta.get('filename')}",
            "response": exec_result,
            "review": review_result,
        }
        _append_stage_log(
            log_dir,
            "stage3_skill_exec.log",
            "skill execution completed",
            success=passed,
            response_preview=_preview_text(exec_result),
            review_preview=_preview_text(review_result),
        )
        _write_json_log(
            log_dir,
            "stage3_skill_exec.json",
            {
                "skill": skill_meta.get("path"),
                "family_id": skill_meta.get("family_id"),
                "skill_version": skill_meta.get("skill_version"),
                "success": passed,
                "response_preview": _preview_text(exec_result),
                "review_preview": _preview_text(review_result),
            },
        )
        return result
    finally:
        if bind_cancel_client:
            bind_cancel_client(None)
        executor.close()
        try:
            Path(skill_sp).unlink()
        except FileNotFoundError:
            pass


def _run_generic_unpack(
    firmware_path: str,
    output_path: str,
    log_dir: Path | None,
    cancel_check: Callable[[PiRpcClient | None], None],
    exec_def: dict[str, Any],
    val_def: dict[str, Any],
    exec_sp: str,
    val_sp: str,
    llm_binding_snapshot: dict[str, Any] | None = None,
    event_callback: Optional[Callable[[str, str], None]] = None,
) -> tuple[bool, int, str]:
    _append_stage_log(
        log_dir,
        "stage3_llm_unpack.log",
        "starting generic llm unpack",
        firmware_path=firmware_path,
        output_path=output_path,
    )
    max_retries = _get_max_retries()
    executor = PiRpcClient(
        system_prompt_file=exec_sp,
        model=exec_def["model"],
        tools=exec_def["tools"],
        provider_role="executor",
        llm_binding_snapshot=llm_binding_snapshot,
    )
    cancel_check(executor)
    passed = False
    final_round = 0
    last_reason = ""
    try:
        for attempt in range(1, max_retries + 1):
            cancel_check(executor)
            final_round = attempt
            exec_msg = render_prompt(
                EXEC_FIRST_TMPL if attempt == 1 else EXEC_RETRY_TMPL,
                firmware_path,
                output_path,
            )
            exec_result = executor.prompt(
                exec_msg,
                stream_callback=lambda event, round_id=attempt: _append_stream_delta(
                    log_dir,
                    "stage3_llm_unpack.log",
                    f"executor:round_{round_id}",
                    event,
                ),
            )
            _save_agent_log(executor, log_dir, f"executor_round_{attempt}")
            _append_stage_log(
                log_dir,
                "stage3_llm_unpack.log",
                "executor round completed",
                attempt=attempt,
                response_preview=_preview_text(exec_result),
            )
            if event_callback:
                event_callback(
                    "executor_round_completed",
                    f"执行轮次 {attempt} 已完成",
                    stage_key="llm_unpack",
                    status="running",
                    detail={
                        "round": attempt,
                        "response_preview": _preview_text(exec_result),
                    },
                )
            if log_dir is not None:
                transcript_path = log_dir / f"executor_round_{attempt}_transcript.log"
                if transcript_path.exists():
                    _append_stage_log(
                        log_dir,
                        "stage3_llm_unpack.log",
                        "executor conversation transcript captured",
                        attempt=attempt,
                        transcript_file=transcript_path.name,
                    )
            passed, verify_result = _run_reviewer(
                firmware_path,
                output_path,
                log_dir,
                f"round_{attempt}",
                val_def,
                val_sp,
                llm_binding_snapshot=llm_binding_snapshot,
                bind_cancel_client=cancel_check,
            )
            log_event(
                log,
                logging.INFO,
                "executor attempt completed",
                event="executor_attempt_complete",
                attempt=attempt,
                response_preview=_preview_text(exec_result),
            )
            log_event(
                log,
                logging.INFO,
                "verifier attempt completed",
                event="verifier_attempt_complete",
                attempt=attempt,
                response_preview=_preview_text(verify_result),
            )
            _append_stage_log(
                log_dir,
                "stage4_llm_review.log",
                "review round completed",
                attempt=attempt,
                passed=passed,
                review_preview=_preview_text(verify_result),
            )
            if event_callback:
                event_callback(
                    "review_round_completed",
                    f"评审轮次 {attempt} 已完成",
                    stage_key="review",
                    status="success" if passed else "running",
                    detail={
                        "round": attempt,
                        "passed": passed,
                        "review_preview": _preview_text(verify_result),
                    },
                )
            if log_dir is not None:
                reviewer_transcript_path = log_dir / f"verifier_round_{attempt}_transcript.log"
                if reviewer_transcript_path.exists():
                    _append_stage_log(
                        log_dir,
                        "stage4_llm_review.log",
                        "reviewer conversation transcript captured",
                        attempt=attempt,
                        transcript_file=reviewer_transcript_path.name,
                    )
            if passed:
                break
            last_reason = verify_result
        return passed, final_round, last_reason
    finally:
        cancel_check(None)
        executor.close()


def _extract_markdown_document(text: str) -> str:
    raw = str(text or "").strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```[a-zA-Z0-9_-]*\n", "", raw)
        raw = re.sub(r"\n```$", "", raw)
    return raw.strip()


def _generate_candidate_skill(
    firmware_path: str,
    output_path: str,
    features: dict[str, Any],
    review_result: str,
    log_dir: Path | None,
    llm_binding_snapshot: dict[str, Any] | None = None,
    bind_cancel_client: Optional[Callable[[PiRpcClient | None], None]] = None,
) -> dict[str, Any] | None:
    _append_stage_log(
        log_dir,
        "stage5_skill_generate.log",
        "starting candidate skill generation",
        firmware_path=firmware_path,
        output_path=output_path,
        family_id=compute_family_id(features),
    )
    try:
        author_def = load_agent_def(AUTHOR_AGENT_DEF)
        summary_path = Path(output_path) / "summary.txt"
        summary_text = summary_path.read_text(encoding="utf-8") if summary_path.exists() else ""
        prompt = render_template(
            AUTHOR_PROMPT_TMPL,
            {
                "$input": firmware_path,
                "$output": output_path,
                "$summary": summary_text,
                "$features": json.dumps(features, ensure_ascii=False, indent=2),
                "$review_result": review_result,
                "$family_id": compute_family_id(features),
                "$promotion_threshold": str(DEFAULT_PROMOTION_THRESHOLD),
            },
        )
        author_sp = _write_system_prompt(author_def["system_prompt"], "firmware-skill-author-")
        author = PiRpcClient(
            system_prompt_file=author_sp,
            model=author_def["model"],
            tools=author_def["tools"],
            provider_role="skill_author",
            llm_binding_snapshot=llm_binding_snapshot,
        )
        if bind_cancel_client:
            bind_cancel_client(author)
        try:
            raw_doc = author.prompt(prompt)
            _save_agent_log(author, log_dir, "skill_author")
        finally:
            if bind_cancel_client:
                bind_cancel_client(None)
            author.close()
            try:
                Path(author_sp).unlink()
            except FileNotFoundError:
                pass
        saved = save_candidate_skill(
            TOOLS_DIR,
            _extract_markdown_document(raw_doc),
            {"family_id": compute_family_id(features)},
        )
        _write_json_log(
            log_dir,
            "stage5_skill_generate.json",
            {
                "generated_skill_path": saved.get("path"),
                "family_id": saved.get("family_id"),
                "skill_version": saved.get("skill_version"),
                "skill_status": saved.get("skill_status"),
            },
        )
        _append_stage_log(
            log_dir,
            "stage5_skill_generate.log",
            "candidate skill generated",
            generated_skill_path=saved.get("path"),
            skill_status=saved.get("skill_status"),
            promotion_success_count=saved.get("promotion_success_count"),
        )
        return saved
    except Exception as exc:
        _write_json_log(
            log_dir,
            "stage5_skill_generate.json",
            {"error": str(exc), "family_id": compute_family_id(features)},
        )
        _append_stage_log(
            log_dir,
            "stage5_skill_generate.log",
            "candidate skill generation failed",
            error=str(exc),
        )
        return None


def _run_cleaner(
    output_path: str,
    log_dir: Path | None = None,
    llm_binding_snapshot: dict[str, Any] | None = None,
    bind_cancel_client: Optional[Callable[[PiRpcClient | None], None]] = None,
    event_callback: Optional[Callable[[str, str], None]] = None,
) -> str:
    _append_stage_log(
        log_dir,
        "cleaner.log",
        "starting cleanup",
        output_path=output_path,
    )
    clean_def = load_agent_def(CLEAN_AGENT_DEF)
    clean_sp = "/tmp/firmware-extract-cleanup.md"
    Path(clean_sp).write_text(clean_def["system_prompt"])
    cleaner = PiRpcClient(
        system_prompt_file=clean_sp,
        model=clean_def["model"],
        tools=clean_def["tools"],
        provider_role="cleaner",
        llm_binding_snapshot=llm_binding_snapshot,
    )
    if bind_cancel_client:
        bind_cancel_client(cleaner)
    try:
        clean_msg = render_prompt(CLEAN_PROMPT_TMPL, output_path, "")
        log_event(log, logging.INFO, "cleanup started", event="cleanup_start")
        if event_callback:
            event_callback(
                "cleanup_started",
                "开始执行清理收尾",
                stage_key="cleanup",
                status="running",
                detail={"output_path": output_path},
            )
        result = cleaner.prompt(clean_msg)
        _save_agent_log(cleaner, log_dir, "cleaner")
        log_event(
            log,
            logging.INFO,
            "cleanup completed",
            event="cleanup_complete",
            response_preview=_preview_text(result),
        )
        _append_stage_log(
            log_dir,
            "cleaner.log",
            "cleanup completed",
            response_preview=_preview_text(result),
        )
        if event_callback:
            event_callback(
                "cleanup_completed",
                "清理收尾已完成",
                stage_key="cleanup",
                status="success",
                detail={"response_preview": _preview_text(result)},
            )
        return result
    finally:
        if bind_cancel_client:
            bind_cancel_client(None)
        cleaner.close()


def run_unpack(
    firmware_path: str,
    output_path: str,
    llm_binding_snapshot: dict[str, Any] | None = None,
    cancel_check: Optional[Callable[[], bool]] = None,
    register_cancel_hook: Optional[Callable[[Callable[[], None] | None], None]] = None,
    progress_callback: Optional[Callable[[str], None]] = None,
    event_callback: Optional[Callable[..., None]] = None,
) -> dict:
    """Execute the firmware unpacking pipeline."""

    active_client: PiRpcClient | None = None

    def _bind_cancel_client(client: PiRpcClient | None) -> None:
        nonlocal active_client
        active_client = client
        if register_cancel_hook is None:
            return
        if client is None:
            register_cancel_hook(None)
            return
        register_cancel_hook(lambda: client.close())

    def _check_cancel(executor: PiRpcClient | None = None) -> None:
        if executor is not None:
            _bind_cancel_client(executor)
        elif executor is None and active_client is None:
            _bind_cancel_client(None)
        if cancel_check and cancel_check():
            target = executor or active_client
            if target is not None:
                target.close()
            _bind_cancel_client(None)
            raise RuntimeError("__CANCELLED__")

    def _report_progress(stage: str) -> None:
        if progress_callback is None:
            return
        try:
            progress_callback(stage)
        except Exception:
            pass

    os.makedirs(output_path, exist_ok=True)
    try:
        log_dir = get_log_dir(output_path)
    except Exception:
        log_dir = None

    _check_cancel()
    _report_progress("preprocess")

    try:
        pre_result = run_preprocess(
            firmware_path,
            output_path,
            log_dir=log_dir,
            cancel_check=cancel_check,
            register_cancel_hook=register_cancel_hook,
        )
    except Exception as exc:
        pre_result = {"success": False, "method": None}
        log_event(
            log,
            logging.WARNING,
            "quick pre-process exception",
            event="quick_preprocess_exception",
            error=str(exc),
        )

    if pre_result.get("success"):
        return {
            "status": "success",
            "message": f"Extracted by quick pre-process: {pre_result['method']}",
            "rounds": 0,
        }

    _check_cancel()
    _report_progress("feature_extract")

    try:
        features = extract_firmware_features(
            firmware_path,
            cancel_check=cancel_check,
            register_cancel_hook=register_cancel_hook,
        )
        features["family_id"] = compute_family_id(features)
        skill_meta, skill_score, skill_match = match_skill(features, TOOLS_DIR)
    except RuntimeError as exc:
        if str(exc) == "__CANCELLED__":
            raise
        skill_meta = None
        skill_score = 0
        skill_match = {"matched_status": None, "reasons": []}
        log_event(
            log,
            logging.WARNING,
            "fast mode feature extraction exception",
            event="fast_mode_exception",
            error=str(exc),
        )
    except Exception as exc:
        skill_meta = None
        skill_score = 0
        skill_match = {"matched_status": None, "reasons": []}
        log_event(
            log,
            logging.WARNING,
            "fast mode feature extraction exception",
            event="fast_mode_exception",
            error=str(exc),
        )
    _append_stage_log(
        log_dir,
        "stage2_skill_match.log",
        "feature extraction and skill match completed",
        features=features if "features" in locals() else {},
        matched_skill=skill_meta.get("path") if skill_meta else None,
        matched_skill_score=skill_score if "skill_score" in locals() else None,
        matched_status=skill_match.get("matched_status") if "skill_match" in locals() else None,
        reasons=skill_match.get("reasons") if "skill_match" in locals() else None,
    )

    _write_json_log(
        log_dir,
        "stage2_skill_match.json",
        {
            "features": features if "features" in locals() else {},
            "matched_skill": skill_meta.get("path") if skill_meta else None,
            "matched_skill_version": skill_meta.get("skill_version") if skill_meta else None,
            "matched_skill_score": skill_score,
            "matched_status": skill_match.get("matched_status"),
            "reasons": skill_match.get("reasons"),
        },
    )

    _check_cancel()
    _report_progress("skill_match")

    try:
        exec_def = load_agent_def(EXEC_AGENT_DEF)
        val_def = load_agent_def(VAL_AGENT_DEF)
    except Exception as exc:
        return {
            "status": "failed",
            "message": f"Agent definition load failed: {exc}",
            "rounds": 0,
        }

    exec_sp = "/tmp/firmware-unpacker.md"
    val_sp = "/tmp/firmware-unpack-reviewer.md"
    Path(exec_sp).write_text(exec_def["system_prompt"])
    Path(val_sp).write_text(val_def["system_prompt"])

    passed = False
    final_round = 0
    last_reason = ""
    fallback_to_llm = False
    generated_skill = None
    matched_skill = skill_meta
    promotion_success_count = None

    try:
        if skill_meta:
            if event_callback:
                event_callback(
                    "tool_matched",
                    f"命中工具：{Path(str(skill_meta.get('path') or '')).name}",
                    stage_key="tool_match",
                    status="running",
                    detail={
                        "matched_skill": skill_meta.get("path"),
                        "skill_version": skill_meta.get("skill_version"),
                        "matched_skill_score": skill_score,
                    },
                )
            _check_cancel()
            _report_progress("tool_match")
            _append_stage_log(
                log_dir,
                "stage2_skill_match.log",
                "matched skill selected for execution",
                skill=skill_meta.get("path"),
                skill_version=skill_meta.get("skill_version"),
                family_id=skill_meta.get("family_id"),
            )
            skill_result = _run_skill_unpack(
                skill_meta,
                firmware_path,
                output_path,
                log_dir,
                val_def,
                val_sp,
                llm_binding_snapshot=llm_binding_snapshot,
                bind_cancel_client=_bind_cancel_client,
            )
            if skill_result.get("success"):
                passed = True
                final_round = 0
                updated_skill = register_skill_success(TOOLS_DIR, str(skill_meta.get("path")))
                promotion_success_count = updated_skill.get("promotion_success_count")
                matched_skill = updated_skill
            else:
                fallback_to_llm = True
                last_reason = str(skill_result.get("review") or skill_result.get("response") or "")
                if event_callback:
                    event_callback(
                        "tool_fallback_to_llm",
                        "工具执行失败，已回退到 LLM 解包",
                        stage_key="tool_match",
                        status="running",
                        detail={
                            "matched_skill": skill_meta.get("path"),
                            "reason": _preview_text(last_reason, 400),
                        },
                    )
                _append_stage_log(
                    log_dir,
                    "stage3_llm_unpack.log",
                    "fallback to llm triggered after skill failure",
                    matched_skill=skill_meta.get("path"),
                    reason_preview=_preview_text(last_reason, 400),
                )
                _write_json_log(
                    log_dir,
                    "stage4_llm_fallback.json",
                    {
                        "matched_skill": skill_meta.get("path"),
                        "reason": _preview_text(last_reason, 400),
                    },
                )

        if not passed:
            _report_progress("llm_unpack")
            generic_passed, final_round, last_reason = _run_generic_unpack(
                firmware_path,
                output_path,
                log_dir,
                _check_cancel,
                exec_def,
                val_def,
                exec_sp,
                val_sp,
                llm_binding_snapshot=llm_binding_snapshot,
                event_callback=event_callback,
            )
            passed = generic_passed
            if passed:
                _report_progress("review")
                generated_skill = _generate_candidate_skill(
                    firmware_path,
                    output_path,
                    features,
                    last_reason or '{"result":"success"}',
                    log_dir,
                    llm_binding_snapshot=llm_binding_snapshot,
                    bind_cancel_client=_bind_cancel_client,
                )
            else:
                _append_stage_log(
                    log_dir,
                    "stage3_llm_unpack.log",
                    "generic llm unpack finished without verified success",
                    rounds=final_round,
                    last_reason_preview=_preview_text(last_reason, 400),
                )

        _check_cancel()
        _report_progress("cleanup")
        _run_cleaner(
            output_path,
            log_dir=log_dir,
            llm_binding_snapshot=llm_binding_snapshot,
            bind_cancel_client=_bind_cancel_client,
            event_callback=event_callback,
        )
        _write_token_summary(log_dir)

    except RuntimeError as exc:
        if str(exc) == "__CANCELLED__":
            return {
                "status": "cancelled",
                "message": "Task was cancelled",
                "rounds": final_round,
            }
        raise
    finally:
        _bind_cancel_client(None)

    return {
        "status": "success" if passed else "max_retries_reached",
        "message": (
            "Unpacking verified successfully"
            if passed
            else f"Max retries reached. Last reason: {last_reason}"
        ),
        "rounds": final_round,
        "matched_skill": matched_skill.get("path") if matched_skill else None,
        "matched_skill_version": matched_skill.get("skill_version") if matched_skill else None,
        "matched_skill_score": skill_score if matched_skill else None,
        "fallback_to_llm": fallback_to_llm,
        "generated_skill_path": generated_skill.get("path") if generated_skill else None,
        "generated_skill_status": generated_skill.get("skill_status") if generated_skill else None,
        "promotion_success_count": (
            promotion_success_count
            if promotion_success_count is not None
            else generated_skill.get("promotion_success_count") if generated_skill else None
        ),
    }
