"""Firmware unpacking execution engine used by the task manager."""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Callable, Optional

from app.logging_utils import log_event
from app.preprocess import detect_format, run_preprocess

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

EXEC_FIRST_TMPL = AGENT_DIR / "prompt" / "unpack-firmware.md"
EXEC_RETRY_TMPL = AGENT_DIR / "prompt" / "retry-firmware-unpack.md"
VAL_PROMPT_TMPL = AGENT_DIR / "prompt" / "review-firmware-unpack.md"
CLEAN_PROMPT_TMPL = AGENT_DIR / "prompt" / "cleanup-firmware.md"

TOOLS_DIR = Path(os.environ.get("UNPACKER_TOOLS_DIR", "/app/tools"))
LOG_OUTPUT_DIR = Path(os.environ.get("UNPACKER_LOG_DIR", "/workspace/log_output"))


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

    def __init__(self, *, system_prompt_file=None, model=None, tools=None, cwd=None):
        self._cwd = self.resolve_cwd(cwd)
        self._system_prompt_file = system_prompt_file
        self._model = model
        self._tools = tools
        self._start()

    def _start(self):
        args = self.build_args(
            system_prompt_file=self._system_prompt_file,
            model=self._model,
            tools=self._tools,
        )
        log_event(
            log,
            logging.INFO,
            "starting pi rpc process",
            event="pi_process_start",
            command=" ".join(args),
            cwd=self._cwd,
        )
        self.proc = subprocess.Popen(
            args,
            cwd=self._cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.send({"type": "set_auto_retry", "enabled": True})

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

    def _prompt_once(self, message: str) -> str:
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

    def prompt(self, message: str) -> str:
        busy_retries = 2
        for attempt in range(1 + self.RETRIES):
            try:
                for busy_attempt in range(busy_retries + 1):
                    try:
                        return self._prompt_once(message)
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
        if self.proc.poll() is not None:
            return
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


def get_log_dir(output_path: str) -> Path:
    output_dir = Path(output_path)
    if output_dir.name == "output":
        log_dir = output_dir.parent / "run"
    else:
        log_dir = LOG_OUTPUT_DIR / output_dir.name
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


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


def extract_firmware_features(firmware_path: str) -> dict:
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
    except Exception:
        pass
    try:
        proc = subprocess.run(
            ["binwalk", "-B", firmware_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("DECIMAL") and not line.startswith("-"):
                parts = line.split(None, 2)
                if len(parts) >= 3:
                    features["binwalk_sigs"].append(parts[2][:100].lower())
    except Exception:
        pass
    return features


def parse_tool_metadata(tool_path: Path) -> dict:
    meta = {
        "path": str(tool_path),
        "format_id": tool_path.stem,
        "description": "",
        "extensions": [],
        "magic_hex": "",
        "keywords": [],
        "binwalk_sigs": [],
    }
    try:
        in_meta = False
        for line in tool_path.read_text().splitlines():
            stripped = line.strip()
            if stripped == "# TOOL_META_START":
                in_meta = True
                continue
            if stripped == "# TOOL_META_END":
                break
            if in_meta and stripped.startswith("#"):
                kv = stripped[1:].strip()
                if ":" not in kv:
                    continue
                key, _, value = kv.partition(":")
                key = key.strip()
                value = value.strip()
                if key == "format_id":
                    meta["format_id"] = value
                elif key == "description":
                    meta["description"] = value
                elif key == "extensions":
                    meta["extensions"] = [
                        item.strip().lower() for item in value.split(",") if item.strip()
                    ]
                elif key == "magic_hex":
                    meta["magic_hex"] = value.lower().replace(" ", "")
                elif key == "keywords":
                    meta["keywords"] = [
                        item.strip().lower() for item in value.split(",") if item.strip()
                    ]
                elif key == "binwalk_sigs":
                    meta["binwalk_sigs"] = [
                        item.strip().lower() for item in value.split(",") if item.strip()
                    ]
    except Exception:
        pass
    return meta


def find_matching_tool(features: dict):
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    tools = list(TOOLS_DIR.glob("*.py"))
    if not tools:
        return None, {}

    feat_ext = features.get("ext", "")
    feat_ext2 = features.get("ext2", "")
    feat_magic = features.get("magic_hex", "")[:8]
    feat_fname = features.get("filename", "").lower()
    feat_sigs = features.get("binwalk_sigs", [])
    search_text = feat_fname + " " + " ".join(feat_sigs)

    best_tool = None
    best_meta = {}
    best_score = 0

    for tool_path in tools:
        meta = parse_tool_metadata(tool_path)
        score = 0
        if meta["magic_hex"] and feat_magic:
            magic = meta["magic_hex"]
            if feat_magic.startswith(magic) or magic.startswith(feat_magic[: len(magic)]):
                score += 50
        for ext in meta["extensions"]:
            if ext and (feat_ext == ext or feat_ext2 == ext or feat_ext2.endswith(ext)):
                score += 30
                break
        for keyword in meta["keywords"]:
            if keyword in search_text:
                score += 10
        for signature in meta["binwalk_sigs"]:
            for feature_sig in feat_sigs:
                if signature in feature_sig:
                    score += 15
                    break
        if score > best_score:
            best_score = score
            best_tool = tool_path
            best_meta = meta

    return (best_tool, best_meta) if best_score >= 30 else (None, {})


def run_tool(tool_path: Path, firmware_path: str, output_path: str, log_dir=None) -> dict:
    try:
        proc = subprocess.run(
            ["python3", str(tool_path), firmware_path, output_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=600,
        )
        result = {
            "success": proc.returncode == 0,
            "method": f"tool:{tool_path.name}",
            "stdout": proc.stdout[-2000:],
            "stderr": proc.stderr[-500:],
            "returncode": proc.returncode,
        }
        if log_dir is not None:
            (log_dir / f"stage2_tool_{tool_path.stem}.json").write_text(
                json.dumps(
                    {
                        "tool": tool_path.name,
                        "firmware": Path(firmware_path).name,
                        "returncode": proc.returncode,
                        "success": proc.returncode == 0,
                        "stdout": proc.stdout[-2000:] if proc.stdout else "",
                        "stderr": proc.stderr[-500:] if proc.stderr else "",
                    },
                    indent=2,
                )
            )
        return result
    except Exception as exc:
        result = {"success": False, "method": f"tool:{tool_path.name}", "error": str(exc)}
        if log_dir is not None:
            (log_dir / f"stage2_tool_{tool_path.stem}.json").write_text(
                json.dumps({"tool": tool_path.name, "error": str(exc)}, indent=2)
            )
        return result


def _run_cleaner(output_path: str, log_dir: Path | None = None) -> str:
    clean_def = load_agent_def(CLEAN_AGENT_DEF)
    clean_sp = "/tmp/firmware-extract-cleanup.md"
    Path(clean_sp).write_text(clean_def["system_prompt"])
    cleaner = PiRpcClient(
        system_prompt_file=clean_sp,
        model=clean_def["model"],
        tools=clean_def["tools"],
    )
    clean_msg = render_prompt(CLEAN_PROMPT_TMPL, output_path, "")
    log_event(log, logging.INFO, "cleanup started", event="cleanup_start")
    result = cleaner.prompt(clean_msg)
    _save_agent_log(cleaner, log_dir, "cleaner")
    cleaner.close()
    log_event(
        log,
        logging.INFO,
        "cleanup completed",
        event="cleanup_complete",
        response_preview=_preview_text(result),
    )
    return result


def run_unpack(
    firmware_path: str,
    output_path: str,
    cancel_check: Optional[Callable[[], bool]] = None,
) -> dict:
    """Execute the firmware unpacking pipeline."""

    def _check_cancel(executor: PiRpcClient | None = None) -> None:
        if cancel_check and cancel_check():
            if executor is not None:
                executor.close()
            raise RuntimeError("__CANCELLED__")

    os.makedirs(output_path, exist_ok=True)
    try:
        log_dir = get_log_dir(output_path)
    except Exception:
        log_dir = None

    _check_cancel()

    try:
        pre_result = run_preprocess(firmware_path, output_path, log_dir=log_dir)
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

    try:
        features = extract_firmware_features(firmware_path)
        tool_path, _tool_meta = find_matching_tool(features)
    except Exception as exc:
        tool_path = None
        log_event(
            log,
            logging.WARNING,
            "fast mode feature extraction exception",
            event="fast_mode_exception",
            error=str(exc),
        )

    if tool_path:
        _check_cancel()
        tool_result = run_tool(tool_path, firmware_path, output_path, log_dir=log_dir)
        if tool_result.get("success"):
            return {
                "status": "success",
                "message": f"Extracted by tool: {tool_path.name}",
                "rounds": 0,
            }

    _check_cancel()

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

    max_retries = _get_max_retries()
    executor = PiRpcClient(
        system_prompt_file=exec_sp,
        model=exec_def["model"],
        tools=exec_def["tools"],
    )

    passed = False
    final_round = 0
    last_reason = ""

    try:
        for attempt in range(1, max_retries + 1):
            _check_cancel(executor)
            final_round = attempt

            exec_msg = render_prompt(
                EXEC_FIRST_TMPL if attempt == 1 else EXEC_RETRY_TMPL,
                firmware_path,
                output_path,
            )
            exec_result = executor.prompt(exec_msg)
            _save_agent_log(executor, log_dir, f"executor_round_{attempt}")

            validator = PiRpcClient(
                system_prompt_file=val_sp,
                model=val_def["model"],
                tools=val_def["tools"],
            )
            verify_result = validator.prompt(
                render_prompt(VAL_PROMPT_TMPL, firmware_path, output_path)
            )
            _save_agent_log(validator, log_dir, f"verifier_round_{attempt}")
            validator.close()

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

            if "success" in verify_result.lower().strip():
                passed = True
                break
            last_reason = verify_result

        _check_cancel(executor)
        _run_cleaner(output_path, log_dir=log_dir)
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
        executor.close()

    return {
        "status": "success" if passed else "max_retries_reached",
        "message": (
            "Unpacking verified successfully"
            if passed
            else f"Max retries reached. Last reason: {last_reason}"
        ),
        "rounds": final_round,
    }
