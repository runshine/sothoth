from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Generator


class PiAgentError(RuntimeError):
    pass


def _find_pi_command() -> list[str]:
    pi_bin = os.environ.get("PI_BIN")
    if pi_bin and os.path.isfile(pi_bin):
        return [pi_bin]
    pi_path = shutil.which("pi")
    if pi_path:
        return [pi_path]
    npx = shutil.which("npx")
    if npx:
        return [npx, "pi"]
    raise PiAgentError("找不到 'pi' 可执行文件")


class _StdoutReader:
    def __init__(self, stdout) -> None:
        self.stdout = stdout
        self.line_queue: queue.Queue[str] = queue.Queue()
        self.done = threading.Event()

    def start(self) -> None:
        threading.Thread(target=self._read_loop, daemon=True).start()

    def _read_loop(self) -> None:
        try:
            import select

            fd = self.stdout.fileno()
            buf = b""
            while True:
                ready, _, _ = select.select([fd], [], [], 1.0)
                if not ready:
                    continue
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    self.line_queue.put(line.decode("utf-8", errors="replace"))
            if buf.strip():
                self.line_queue.put(buf.decode("utf-8", errors="replace"))
        finally:
            self.done.set()

    def read_line(self, timeout: float = 2.0) -> str | None:
        try:
            return self.line_queue.get(timeout=timeout)
        except queue.Empty:
            return None


class _StderrReader:
    def __init__(self, stderr) -> None:
        self.stderr = stderr
        self.result = threading.Event()
        self.data: bytes = b""

    def start(self) -> None:
        threading.Thread(target=self._read_loop, daemon=True).start()

    def _read_loop(self) -> None:
        try:
            import select

            fd = self.stderr.fileno()
            chunks: list[bytes] = []
            while True:
                ready, _, _ = select.select([fd], [], [], 1.0)
                if not ready:
                    continue
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                chunks.append(chunk)
            self.data = b"".join(chunks)
        finally:
            self.result.set()

    def get(self, timeout: float = 10.0) -> bytes:
        if self.result.wait(timeout=timeout):
            return self.data
        return b""


def _build_args(model_ref: str, session_path: str) -> list[str]:
    args = [*_find_pi_command(), "--mode", "rpc"]
    if session_path:
        args.extend(["--session", session_path])
    else:
        args.append("--no-session")
    if model_ref:
        args.extend(["--model", model_ref])
    args.extend(["--tools", "read,bash,edit,write,grep,find,ls"])
    return args


def stream_pi_agent(
    *,
    prompt: str,
    model_ref: str,
    session_path: str,
    runtime_dir: str,
    env: dict[str, str],
    idle_timeout_seconds: float = 600.0,
    cancel_event: threading.Event | None = None,
    on_process_started: Callable[[subprocess.Popen[bytes]], None] | None = None,
) -> Generator[dict[str, Any], None, dict[str, Any]]:
    args = _build_args(model_ref, session_path)
    proc = subprocess.Popen(
        args,
        cwd=runtime_dir,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        start_new_session=True,
        text=False,
    )
    stdout_reader = _StdoutReader(proc.stdout)
    stderr_reader = _StderrReader(proc.stderr)
    stdout_reader.start()
    stderr_reader.start()
    if callable(on_process_started):
        on_process_started(proc)

    response_id = f"pi-{int(time.time() * 1000)}"
    yield {
        "type": "response.created",
        "response": {
            "id": response_id,
            "object": "agent.response",
            "created": int(time.time()),
            "agent_id": "pi",
            "backend": "pi",
            "session_id": None,
            "mode": "invoke",
            "status": "in_progress",
        },
    }

    prompt_cmd = json.dumps({"type": "prompt", "message": prompt}, ensure_ascii=False) + "\n"
    if proc.stdin is None:
        raise PiAgentError("pi stdin 不可用")
    proc.stdin.write(prompt_cmd.encode("utf-8"))
    proc.stdin.flush()

    messages: list[dict[str, Any]] = []
    last_activity_at = time.monotonic()
    trace_id = 0
    try:
        while True:
            line = stdout_reader.read_line(timeout=1.0)
            if cancel_event is not None and cancel_event.is_set():
                proc.kill()
                yield {
                    "type": "response.failed",
                    "error_message": "agent run cancelled",
                    "response": {
                        "id": response_id,
                        "object": "agent.response",
                        "created": int(time.time()),
                        "agent_id": "pi",
                        "backend": "pi",
                        "session_id": None,
                        "mode": "invoke",
                        "status": "failed",
                        "output_text": "",
                    },
                }
                return {"status": "cancelled", "output_text": "", "messages": messages}
            if line is None:
                if proc.poll() is not None and stdout_reader.done.is_set():
                    break
                if idle_timeout_seconds and (time.monotonic() - last_activity_at) >= idle_timeout_seconds:
                    proc.kill()
                    yield {
                        "type": "response.failed",
                        "error_message": "pi invoke timeout",
                        "response": {
                            "id": response_id,
                            "object": "agent.response",
                            "created": int(time.time()),
                            "agent_id": "pi",
                            "backend": "pi",
                            "session_id": None,
                            "mode": "invoke",
                            "status": "failed",
                            "output_text": "",
                        },
                    }
                    return {"status": "failed", "output_text": "", "messages": messages}
                continue
            last_activity_at = time.monotonic()
            try:
                event = json.loads(line.strip())
            except json.JSONDecodeError:
                continue
            etype = event.get("type")
            yield {
                "type": "response.pi.event",
                "response_id": response_id,
                "session_id": None,
                "agent_id": "pi",
                "pi_event": event,
            }
            if etype in {"response", "session", "queue_update", "compaction_start", "compaction_end", "auto_retry_start", "auto_retry_end"}:
                continue
            if etype == "message_update":
                ae = event.get("assistantMessageEvent", {}) if isinstance(event.get("assistantMessageEvent"), dict) else {}
                if ae.get("type") == "text_delta":
                    delta = str(ae.get("delta") or "")
                    if delta:
                        yield {
                            "type": "response.output_text.delta",
                            "response_id": response_id,
                            "session_id": None,
                            "agent_id": "pi",
                            "delta": delta,
                        }
                elif ae.get("type") in {"thinking_delta", "reasoning_delta"}:
                    delta = str(ae.get("delta") or "")
                    if delta:
                        yield {
                            "type": "response.reasoning.delta",
                            "response_id": response_id,
                            "session_id": None,
                            "agent_id": "pi",
                            "delta": delta,
                        }
                continue
            if etype == "message_end" and isinstance(event.get("message"), dict):
                msg = event["message"]
                messages.append(msg)
                if msg.get("role") == "assistant":
                    usage = msg.get("usage") if isinstance(msg.get("usage"), dict) else {}
                    yield {
                        "type": "response.trace.item",
                        "response_id": response_id,
                        "session_id": None,
                        "agent_id": "pi",
                        "item": {
                            "id": f"trace_usage_{trace_id}",
                            "category": "pi.usage",
                            "message": "assistant message completed",
                            "severity": "info",
                            "created": int(time.time()),
                            "source": "pi",
                            "payload": usage,
                        },
                    }
                    trace_id += 1
                    if msg.get("stopReason") == "error":
                        error_message = str(msg.get("errorMessage") or "pi returned error")
                        yield {
                            "type": "response.failed",
                            "error_message": error_message,
                            "response": {
                                "id": response_id,
                                "object": "agent.response",
                                "created": int(time.time()),
                                "agent_id": "pi",
                                "backend": "pi",
                                "session_id": None,
                                "mode": "invoke",
                                "status": "failed",
                                "output_text": "",
                            },
                        }
                        return {"status": "failed", "output_text": "", "messages": messages}
                continue
            if etype == "agent_end":
                break

        try:
            if proc.stdin:
                proc.stdin.close()
        except Exception:
            pass
        try:
            proc.wait(timeout=15.0)
        except subprocess.TimeoutExpired:
            proc.kill()

        output_text = ""
        for msg in reversed(messages):
            if msg.get("role") != "assistant":
                continue
            content = msg.get("content")
            if not isinstance(content, list):
                continue
            texts = [str(item.get("text") or "") for item in content if isinstance(item, dict) and item.get("type") == "text"]
            output_text = "\n".join(part for part in texts if part).strip()
            if output_text:
                break

        stderr_text = stderr_reader.get(timeout=2.0).decode("utf-8", errors="replace").strip()
        if not output_text and stderr_text:
            yield {
                "type": "response.trace.item",
                "response_id": response_id,
                "session_id": None,
                "agent_id": "pi",
                "item": {
                    "id": f"trace_stderr_{trace_id}",
                    "category": "pi.stderr",
                    "message": "stderr output",
                    "severity": "warning",
                    "created": int(time.time()),
                    "source": "stderr",
                    "payload": {"text": stderr_text},
                },
            }
        yield {
            "type": "response.completed",
            "response": {
                "id": response_id,
                "object": "agent.response",
                "created": int(time.time()),
                "agent_id": "pi",
                "backend": "pi",
                "session_id": None,
                "mode": "invoke",
                "status": "completed",
                "output_text": output_text,
            },
        }
        return {"status": "completed", "output_text": output_text, "messages": messages}
    finally:
        try:
            if proc.poll() is None:
                proc.kill()
        except Exception:
            pass
