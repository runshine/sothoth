"""Firmware unpacking engine — extracted from pi_service.py.
Supports cancel_check callback for graceful cancellation.
"""
import json
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Callable, Optional

from app.logging_utils import log_event

log = logging.getLogger("unpacker.engine")
debug_mode = True

AGENT_DIR = Path(
    os.environ.get(
        "UNPACKER_AGENT_DIR",
        str(Path(__file__).resolve().parent / "agent"),
    )
)
EXEC_AGENT_DEF  = str(AGENT_DIR / "firmware-unpacker.md")
VAL_AGENT_DEF   = str(AGENT_DIR / "firmware-unpack-reviewer.md")
CLEAN_AGENT_DEF = str(AGENT_DIR / "firmware-extract-cleanup.md")
EXEC_FIRST_TMPL = AGENT_DIR / "prompt" / "unpack-firmware.md"
EXEC_RETRY_TMPL = AGENT_DIR / "prompt" / "retry-firmware-unpack.md"
VAL_PROMPT_TMPL = AGENT_DIR / "prompt" / "review-firmware-unpack.md"
CLEAN_PROMPT_TMPL = AGENT_DIR / "prompt" / "cleanup-firmware.md"


def _get_max_retries() -> int:
    try:
        from app.model import get_db_session, get_config_value
        db = get_db_session()
        try:
            return get_config_value(db, "max_retries", default=5)
        finally:
            db.close()
    except Exception:
        return 5


def _preview_text(text: str, limit: int = 240) -> str:
    compact = " ".join(text.split())
    return compact[:limit] + "..." if len(compact) > limit else compact


def load_agent_def(md_path: str) -> dict:
    content = Path(md_path).read_text()
    match = re.match(r"^---\n(.*?)\n---\n(.*)$", content, re.DOTALL)
    if not match:
        raise ValueError(f"Invalid agent definition (missing frontmatter): {md_path}")
    fm: dict[str, str] = {}
    for line in match.group(1).split("\n"):
        if ":" in line:
            k, _, v = line.partition(":")
            fm[k.strip()] = v.strip()
    tools = [t.strip() for t in fm.get("tools", "").split(",") if t.strip()]
    return {"name": fm.get("name", Path(md_path).stem), "tools": tools,
            "model": fm.get("model") or None, "system_prompt": match.group(2).strip()}


def render_prompt(template_path: Path, firmware_path: str, output_path: str) -> str:
    text = template_path.read_text()
    text = text.replace("$input", firmware_path)
    text = text.replace("$output", output_path)
    return text


class PiRpcClient:
    RETRIES = 2

    @staticmethod
    def resolve_cwd(cwd):
        for candidate in [cwd, os.environ.get("PI_RPC_CWD"), "/app", os.getcwd(), "/tmp"]:
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
            model=self._model, tools=self._tools,
        )
        self.proc = subprocess.Popen(
            args, cwd=self._cwd,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        self.send({"type": "set_auto_retry", "enabled": True})

    def _respawn(self):
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
    def extract_assistant_text(events: list) -> str:
        parts = []
        for ev in events:
            if ev.get("type") != "message_end":
                continue
            msg = ev.get("message", {})
            if msg.get("role") != "assistant":
                continue
            for block in msg.get("content", []):
                if block.get("type") == "text":
                    parts.append(block["text"])
        return "\n".join(parts) if parts else ""

    def _drain_active_turn(self):
        for _ in self._read_until("agent_end"):
            pass

    def _prompt_once(self, message: str) -> str:
        self.send({"type": "prompt", "message": message, "streamingBehavior": "followUp"})
        events = []
        for ev in self._read_until("agent_end"):
            etype = ev.get("type", "")
            if (etype == "response" and ev.get("command") == "prompt" and not ev.get("success")):
                error = ev.get("error", "unknown")
                if "already processing" in str(error).lower():
                    self._drain_active_turn()
                    raise RuntimeError("__PI_BUSY__")
                raise RuntimeError(f"Prompt failed: {error}")
            if debug_mode and etype == "message_update":
                di = ev.get("assistantMessageEvent", {})
                if di.get("type") in ("text_delta", "thinking_delta", "toolcall_delta"):
                    print(di.get("delta", ""), end="", flush=True)
            events.append(ev)
        for ev in reversed(events):
            if (ev.get("type") == "message_end"
                    and ev.get("message", {}).get("role") == "assistant"
                    and ev.get("message", {}).get("stopReason") == "error"):
                raise RuntimeError(ev.get("message", {}).get("errorMessage", "API error"))
            if ev.get("type") == "message_end":
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
            except RuntimeError:
                if self.proc.poll() is None:
                    raise
                if attempt >= self.RETRIES:
                    raise
                self._respawn()
        raise RuntimeError("Prompt failed after exhausting retries")

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


def run_unpack(
    firmware_path: str,
    output_path: str,
    cancel_check: Optional[Callable[[], bool]] = None,
) -> dict:
    """Execute the firmware unpacking pipeline.
    
    cancel_check: callable that returns True when cancellation is requested.
    """
    def _check_cancel(executor=None):
        if cancel_check and cancel_check():
            if executor:
                executor.close()
            raise RuntimeError("__CANCELLED__")

    # Simple: gzip/tar detection
    file_proc = subprocess.run(
        ["file", firmware_path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    if file_proc.stdout and "gzip compressed data" in file_proc.stdout:
        _check_cancel()
        subprocess.run(
            ["tar", "zxvf", firmware_path, "-C", output_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        return {"status": "success", "message": "Extracted successfully (tar.gz)", "rounds": 0}

    # Load agent definitions
    try:
        exec_def  = load_agent_def(EXEC_AGENT_DEF)
        val_def   = load_agent_def(VAL_AGENT_DEF)
        clean_def = load_agent_def(CLEAN_AGENT_DEF)
    except Exception as e:
        return {"status": "failed", "message": f"Agent definition load failed: {e}", "rounds": 0}

    exec_sp  = "/tmp/firmware-unpacker.md"
    val_sp   = "/tmp/firmware-unpack-reviewer.md"
    clean_sp = "/tmp/firmware-extract-cleanup.md"
    Path(exec_sp).write_text(exec_def["system_prompt"])
    Path(val_sp).write_text(val_def["system_prompt"])
    Path(clean_sp).write_text(clean_def["system_prompt"])

    max_retries = _get_max_retries()
    executor = PiRpcClient(
        system_prompt_file=exec_sp, model=exec_def["model"], tools=exec_def["tools"]
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
                firmware_path, output_path,
            )
            execu_result = executor.prompt(exec_msg)
            _check_cancel(executor)

            validator = PiRpcClient(
                system_prompt_file=val_sp, model=val_def["model"], tools=val_def["tools"]
            )
            verify_result = validator.prompt(render_prompt(VAL_PROMPT_TMPL, firmware_path, output_path))
            validator.close()

            if "success" in verify_result.lower().strip():
                passed = True
                break
            last_reason = verify_result

        _check_cancel(executor)

        # Cleanup
        cleaner = PiRpcClient(
            system_prompt_file=clean_sp, model=clean_def["model"], tools=clean_def["tools"]
        )
        cleaner.prompt(render_prompt(CLEAN_PROMPT_TMPL, output_path, ""))
        cleaner.close()

    except RuntimeError as e:
        if str(e) == "__CANCELLED__":
            return {"status": "cancelled", "message": "Task was cancelled", "rounds": final_round}
        raise
    finally:
        executor.close()

    return {
        "status": "success" if passed else "max_retries_reached",
        "message": ("Verified successfully"
                    if passed
                    else f"Max retries reached. Last: {last_reason}"),
        "rounds": final_round,
    }
