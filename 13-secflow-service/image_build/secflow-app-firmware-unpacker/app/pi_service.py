#!/usr/bin/env python3
"""
Firmware Unpacking Microservice (RESTful)
==========================================
RESTful API wrapping pi coding agent for automated firmware extraction.

Endpoints:
    POST /unpack
        JSON body: {"firmware_path": "...", "output_path": "..."}
        Returns:   {"status": "...", "message": "...", "rounds": N}

    GET /health
        Returns:   {"status": "ok"}

Architecture (follows pi-re-agent pattern):
    - Executor (long-lived pi RPC process): performs firmware unpacking
    - Verifier (ephemeral pi RPC process): reviews unpacking results
    - Loop until verifier returns true or max retries reached
    - System prompts loaded from agent/*.md (YAML frontmatter parsed)
    - User prompts loaded from agent/prompt/*.md (template variables substituted)
"""

import json
import logging
import os
import re
import subprocess
from typing import Any
from pathlib import Path

from flask import Flask, request, jsonify

from logging_utils import configure_container_logging, log_event

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
configure_container_logging("00-pi-firmware-unpacker")
log = logging.getLogger("unpacker.service")

debug_mode = True
app = Flask(__name__)

# ---------------------------------------------------------------------------
# Paths — chain images keep application code outside the shared /app mount.
# ---------------------------------------------------------------------------
AGENT_DIR = Path(
    os.environ.get(
        "UNPACKER_AGENT_DIR",
        str(Path(__file__).resolve().parent / "agent"),
    )
)

# System prompt definitions (with YAML frontmatter)
EXEC_AGENT_DEF = str(AGENT_DIR / "firmware-unpacker.md")
VAL_AGENT_DEF = str(AGENT_DIR / "firmware-unpack-reviewer.md")
CLEAN_AGENT_DEF = str(AGENT_DIR / "firmware-extract-cleanup.md")

# User prompt templates
EXEC_FIRST_TMPL = AGENT_DIR / "prompt" / "unpack-firmware.md"
EXEC_RETRY_TMPL = AGENT_DIR / "prompt" / "retry-firmware-unpack.md"
VAL_PROMPT_TMPL = AGENT_DIR / "prompt" / "review-firmware-unpack.md"
CLEAN_PROMPT_TMPL = AGENT_DIR / "prompt" / "cleanup-firmware.md"

MAX_RETRIES = 5


def _preview_text(text: str, limit: int = 240) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[:limit] + "..."


# ---------------------------------------------------------------------------
# Agent definition loader  (pi-re-agent pattern)
# ---------------------------------------------------------------------------


def load_agent_def(md_path: str) -> dict:
    """Parse an agent .md file with YAML frontmatter.

    Returns dict with keys: name, tools, model, system_prompt
    """
    content = Path(md_path).read_text()
    match = re.match(r"^---\n(.*?)\n---\n(.*)$", content, re.DOTALL)
    if not match:
        raise ValueError(f"Invalid agent definition (missing frontmatter): {md_path}")

    fm: dict[str, str] = {}
    for line in match.group(1).split("\n"):
        if ":" in line:
            key, _, value = line.partition(":")
            fm[key.strip()] = value.strip()

    tools = [t.strip() for t in fm.get("tools", "").split(",") if t.strip()]

    return {
        "name": fm.get("name", Path(md_path).stem),
        "tools": tools,
        "model": fm.get("model") or None,
        "system_prompt": match.group(2).strip(),
    }


# ---------------------------------------------------------------------------
# User prompt template renderer
# ---------------------------------------------------------------------------


def render_prompt(template_path: Path, firmware_path: str, output_path: str) -> str:
    """Load a prompt template and substitute $input / $output variables."""
    text = template_path.read_text()
    text = text.replace("$input", firmware_path)
    text = text.replace("$output", output_path)
    return text


# ---------------------------------------------------------------------------
# Pi RPC Client  (pi-re-agent PiRpcClient pattern)
# ---------------------------------------------------------------------------


class PiRpcClient:
    """Manages a ``pi --mode rpc`` subprocess."""

    RETRIES = 2

    @staticmethod
    def resolve_cwd(cwd: str | None) -> str:
        """Prefer the app mount, but fall back safely."""
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
        # Let pi absorb transient upstream/API failures itself before they
        # propagate up to our orchestrator.
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
        """Yield parsed JSON events until the expected event type arrives."""
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
        """Extract assistant text from terminal message events."""
        parts: list[str] = []
        for event in events:
            if event.get("type") != "message_end":
                continue
            msg = event.get("message", {})
            if msg.get("role") != "assistant":
                continue
            for block in msg.get("content", []):
                if block.get("type") == "text":
                    parts.append(block["text"])
        return "\n".join(parts) if parts else ""

    def _drain_active_turn(self):
        """Wait for the in-flight turn to finish after a busy rejection."""
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
            etype = event.get("type", "")

            # Check for command-level error
            if (
                etype == "response"
                and event.get("command") == "prompt"
                and not event.get("success")
            ):
                error = event.get("error", "unknown")
                if "already processing" in str(error).lower():
                    self._drain_active_turn()
                    raise RuntimeError("__PI_BUSY__")
                raise RuntimeError(f"Prompt failed: {error}")

            # Collect streaming text deltas for debug mode
            if debug_mode and etype == "message_update":
                delta_info = event.get("assistantMessageEvent", {})
                if delta_info.get("type") == "text_delta":
                    print(delta_info.get("delta", ""), end="", flush=True)
                elif delta_info.get("type") == "thinking_delta":
                    print(f"{delta_info.get('delta', '')}", end="", flush=True)
                elif delta_info.get("type") == "toolcall_delta":
                    print(f"{delta_info.get('delta')}", end="", flush=True)

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
        """Send a user prompt and block until the agent finishes.

        Returns the concatenated assistant text.
        """
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
                # print(event["data"]["messages"])
                return event["data"]["messages"]

    def get_token_stats(self):
        self.send({"id": "req-stats", "type": "get_session_stats"})
        assert self.proc.stdout is not None

        for line in self.proc.stdout:
            event = json.loads(line.strip())
            if (
                event.get("type") == "response"
                and event.get("command") == "get_session_stats"
            ):
                data = event["data"]
                tokens = data["tokens"]
                print(f"输入 token:     {tokens['input']}")
                print(f"输出 token:     {tokens['output']}")
                print(f"缓存读取:       {tokens['cacheRead']}")
                print(f"缓存写入:       {tokens['cacheWrite']}")
                print(f"合计 token:     {tokens['total']}")
                return data

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


# ---------------------------------------------------------------------------
# Unpacking pipeline
# ---------------------------------------------------------------------------


def run_preprocess(firmware_path: str, output_path: str):
    cmd = ["tar", "zxvf", firmware_path, "-C", output_path]
    proc = subprocess.run(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    return

def run_unpack(firmware_path: str, output_path: str) -> dict:
    """Execute the firmware unpacking pipeline with executor-verifier loop."""

    # Load agent definitions (parses frontmatter for tools, model, system_prompt)
    exec_def = load_agent_def(EXEC_AGENT_DEF)
    val_def = load_agent_def(VAL_AGENT_DEF)
    clean_def = load_agent_def(CLEAN_AGENT_DEF)

    # Write system prompt body (without frontmatter) for --append-system-prompt
    exec_sp = "/tmp/firmware-unpacker.md"
    val_sp = "/tmp/firmware-unpack-reviewer.md"
    clean_sp = "/tmp/firmware-extract-cleanup.md"

    Path(exec_sp).write_text(exec_def["system_prompt"])
    Path(val_sp).write_text(val_def["system_prompt"])
    Path(clean_sp).write_text(clean_def["system_prompt"])

    # Spawn executor (long-lived across retries)
    executor = PiRpcClient(
        system_prompt_file=exec_sp,
        model=exec_def["model"],
        tools=exec_def["tools"],
    )

    passed = False
    final_round = 0
    last_reason = ""

    try:
        for attempt in range(1, MAX_RETRIES + 1):
            final_round = attempt

            # ── Executor turn ──────────────────────────────
            if attempt == 1:
                exec_msg = render_prompt(EXEC_FIRST_TMPL, firmware_path, output_path)
            else:
                exec_msg = render_prompt(EXEC_RETRY_TMPL, firmware_path, output_path)

            log_event(
                log,
                logging.INFO,
                "executor attempt started",
                event="executor_attempt_start",
                attempt=attempt,
                max_retries=MAX_RETRIES,
                firmware_path=firmware_path,
                output_path=output_path,
            )
            execu_result = executor.prompt(exec_msg)
            log_event(
                log,
                logging.INFO,
                "executor attempt completed",
                event="executor_attempt_complete",
                attempt=attempt,
                response_preview=_preview_text(execu_result),
            )

            # ── Verifier turn (ephemeral) ──────────────────
            validator = PiRpcClient(
                system_prompt_file=val_sp,
                model=val_def["model"],
                tools=val_def["tools"],
            )

            val_msg = render_prompt(VAL_PROMPT_TMPL, firmware_path, output_path)

            log_event(
                log,
                logging.INFO,
                "verifier attempt started",
                event="verifier_attempt_start",
                attempt=attempt,
                max_retries=MAX_RETRIES,
            )
            verify_result = validator.prompt(val_msg)
            validator.close()

            log_event(
                log,
                logging.INFO,
                "verifier attempt completed",
                event="verifier_attempt_complete",
                attempt=attempt,
                response_preview=_preview_text(verify_result),
            )

            # Judge result — original demo.py logic: check for "false"
            verify_lower = verify_result.lower().strip()
            if "success" in verify_lower:
                passed = True
                log_event(
                    log,
                    logging.INFO,
                    "verification passed",
                    event="verification_passed",
                    attempt=attempt,
                    firmware_path=firmware_path,
                )
                break

            # Failed — reason is in verify_result and/or reason.txt
            last_reason = verify_result
            log_event(
                log,
                logging.WARNING,
                "verification failed and will retry",
                event="verification_failed",
                attempt=attempt,
                reason_preview=_preview_text(verify_result),
            )

        # ── Clean turn ──────────────────
        cleanner = PiRpcClient(
            system_prompt_file=clean_sp,
            model=clean_def["model"],
            tools=clean_def["tools"],
        )

        clean_msg = render_prompt(CLEAN_PROMPT_TMPL, output_path, "")

        log_event(log, logging.INFO, "cleanup started", event="cleanup_start")
        clean_result = cleanner.prompt(clean_msg)
        cleanner.close()

        log_event(
            log,
            logging.INFO,
            "cleanup completed",
            event="cleanup_complete",
            response_preview=_preview_text(clean_result),
        )

    finally:
        executor.close()

    return {
        "status": "success" if passed else "max_retries_reached",
        "message": "Unpacking verified successfully"
        if passed
        else f"Max retries reached. Last reason: {last_reason}",
        "rounds": final_round,
    }


# ---------------------------------------------------------------------------
# REST endpoints
# ---------------------------------------------------------------------------


@app.route("/health", methods=["GET"])
@app.route("/api/app/firmware-unpacker/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/unpack", methods=["POST"])
@app.route("/api/app/firmware-unpacker/unpack", methods=["POST"])
def unpack():
    """
    POST /unpack
    Body: {"firmware_path": "/path/to/firmware.bin", "output_path": "/path/to/output/"}
    """
    data = request.get_json(force=True)

    firmware_path = data.get("firmware_path")
    output_path = data.get("output_path")

    if not firmware_path or not output_path:
        return jsonify(
            {
                "status": "error",
                "message": "Both 'firmware_path' and 'output_path' are required.",
            }
        ), 400

    if not os.path.exists(firmware_path):
        return jsonify(
            {
                "status": "error",
                "message": f"Firmware file not found: {firmware_path}",
            }
        ), 404

    # Ensure output directory exists
    os.makedirs(output_path, exist_ok=True)

    log_event(
        log,
        logging.INFO,
        "unpack request accepted",
        event="unpack_request",
        firmware_path=firmware_path,
        output_path=output_path,
        remote_addr=request.remote_addr,
    )

    cmd_1 = ["file", firmware_path]
    file_proc = subprocess.run(
        cmd_1,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # pre_process
    try:
        if file_proc.stdout and "gzip compressed data" in file_proc.stdout:
            cmd_2 = ["tar", "zxvf", firmware_path, "-C", output_path]
            proc = subprocess.run(
                cmd_2,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            result = {
                "status": "success",
                "message": "Firmware extracted successfully",
                "rounds": 0
            }

            log_event(
                log,
                logging.INFO,
                "unpack request finished",
                event="unpack_result",
                firmware_path=firmware_path,
                output_path=output_path,
                result_status=result.get("status"),
                rounds=result.get("rounds"),
            )
            return jsonify(result)

    except Exception as e:
        log_event(
            log,
            logging.ERROR,
            "unpack request failed",
            event="unpack_failed",
            firmware_path=firmware_path,
            output_path=output_path,
            error=str(e),
        )
        log.exception("unpack request failed")
        return jsonify(
            {
                "status": "error",
                "message": str(e),
            }
        ), 500

    try:
        result = run_unpack(firmware_path, output_path)
        log_event(
            log,
            logging.INFO,
            "unpack request finished",
            event="unpack_result",
            firmware_path=firmware_path,
            output_path=output_path,
            result_status=result.get("status"),
            rounds=result.get("rounds"),
        )
        return jsonify(result)
    except Exception as e:
        log_event(
            log,
            logging.ERROR,
            "unpack request failed",
            event="unpack_failed",
            firmware_path=firmware_path,
            output_path=output_path,
            error=str(e),
        )
        log.exception("unpack request failed")
        return jsonify(
            {
                "status": "error",
                "message": str(e),
            }
        ), 500


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    log_event(
        log,
        logging.INFO,
        "starting firmware unpack service",
        event="service_start",
        port=port,
    )
    app.run(host="0.0.0.0", port=port)
