from __future__ import annotations

import json
import os
import subprocess
import uuid
from typing import Any, Dict, Generator

from agent_ai_service.config import settings
from agent_ai_service.models.agent_backend import BackendConfig
from agent_ai_service.a2a.session_store import SessionStore


class ClaudePipeSessionRuntime:
    def __init__(self, session_store: SessionStore):
        self.session_store = session_store

    @staticmethod
    def _build_base_args(config: BackendConfig) -> list[str]:
        args = [config.command, *(config.args or []), "-p"]
        return args

    @staticmethod
    def _session_id_from(session: Dict[str, Any]) -> str:
        existing = str(session.get("vendor_session_id") or "").strip()
        if existing:
            return existing
        return str(uuid.uuid4())

    def create_or_get_vendor_session(
        self,
        session: Dict[str, Any],
        config: BackendConfig,
    ) -> Dict[str, Any]:
        session_id = str(session.get("session_id") or "")
        if not session_id:
            raise RuntimeError("session_id missing")
        vendor_session_id = self._session_id_from(session)
        if str(session.get("vendor_session_id") or "").strip():
            return session
        return self.session_store.patch(
            session_id,
            {
                "vendor_session_id": vendor_session_id,
                "vendor_session_kind": "claude",
                "vendor_resume_mode": "resume_then_session_id",
                "claude_session_id": vendor_session_id,
                "claude_workdir": str(config.cwd or "/host"),
                "backend_pid": None,
                "pty_pid": None,
                "status": "ready",
            },
        )

    @staticmethod
    def _run_cli(
        config: BackendConfig,
        args: list[str],
    ) -> Dict[str, Any]:
        env = dict(**os.environ)
        env.update(config.env or {})
        try:
            completed = subprocess.run(
                args,
                cwd=config.cwd or None,
                env=env,
                text=True,
                capture_output=True,
                timeout=settings.backend_invoke_timeout_sec,
            )
            return {
                "success": completed.returncode == 0,
                "returncode": completed.returncode,
                "stdout": completed.stdout or "",
                "stderr": completed.stderr or "",
            }
        except FileNotFoundError:
            return {
                "success": False,
                "returncode": -127,
                "stdout": "",
                "stderr": f"backend command not found: {config.command}",
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "returncode": -124,
                "stdout": "",
                "stderr": "backend invoke timeout",
            }

    @staticmethod
    def _try_parse_json(text: str) -> Any:
        raw = str(text or "").strip()
        if not raw:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return None

    @staticmethod
    def _error_text_from_payload(payload: Any) -> str:
        if isinstance(payload, dict):
            errors = payload.get("errors")
            if isinstance(errors, list) and errors:
                joined = "; ".join(str(item) for item in errors if str(item).strip())
                if joined:
                    return joined
            for key in ("error", "message", "reason"):
                value = payload.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
        return ""

    def _detect_cli_error(self, result: Dict[str, Any]) -> tuple[bool, str, Dict[str, Any] | None]:
        returncode = int(result.get("returncode", 0))
        stdout = str(result.get("stdout") or "")
        stderr = str(result.get("stderr") or "")
        payload = self._try_parse_json(stdout)

        if isinstance(payload, dict):
            is_error = bool(payload.get("is_error")) or str(payload.get("subtype") or "") == "error_during_execution"
            if is_error:
                text = self._error_text_from_payload(payload) or stderr.strip() or stdout.strip() or "backend invoke failed"
                return True, text, payload

        if returncode != 0:
            text = stderr.strip() or stdout.strip() or "backend invoke failed"
            return True, text, payload if isinstance(payload, dict) else None

        return False, "", payload if isinstance(payload, dict) else None

    @staticmethod
    def _extract_text_from_stream_json(payload: Any) -> list[str]:
        fragments: list[str] = []

        if not isinstance(payload, dict):
            return fragments

        event_type = str(payload.get("type") or "").strip().lower()
        # Claude stream-json emits structured metadata lines.
        # Keep assistant-facing text and thinking, skip pure system/result wrappers.
        if event_type in ("system", "result"):
            return fragments

        # Anthropic/OpenAI-like delta payloads.
        delta_value = payload.get("delta")
        if isinstance(delta_value, dict):
            delta_text = delta_value.get("text")
            if isinstance(delta_text, str) and delta_text:
                fragments.append(delta_text)
        elif isinstance(delta_value, str) and delta_value and event_type in ("content_block_delta",):
            fragments.append(delta_value)

        message = payload.get("message")
        if isinstance(message, dict):
            content = message.get("content")
            if isinstance(content, list):
                for item in content:
                    if not isinstance(item, dict):
                        continue
                    item_type = str(item.get("type") or "").strip().lower()
                    if item_type == "text":
                        text = item.get("text")
                        if isinstance(text, str) and text:
                            fragments.append(text)
                    elif item_type == "thinking":
                        thinking = item.get("thinking")
                        if isinstance(thinking, str) and thinking.strip():
                            fragments.append(f"\n<reasoning_content>\n{thinking}\n</reasoning_content>\n")
                    elif item_type in ("output_text", "delta"):
                        text = item.get("text") if isinstance(item.get("text"), str) else item.get("delta")
                        if isinstance(text, str) and text:
                            fragments.append(text)
                    # Ignore other non-user-facing blocks.

        return fragments

    def _record_vendor_state(
        self,
        session_id: str,
        *,
        command: list[str] | None = None,
        error: str | None = None,
    ) -> None:
        patch_payload: Dict[str, Any] = {}
        if command is not None:
            patch_payload["vendor_last_cmd"] = command
        if error is not None:
            patch_payload["vendor_last_error"] = error
        if patch_payload:
            self.session_store.patch(session_id, patch_payload)

    def invoke_once(
        self,
        session: Dict[str, Any],
        config: BackendConfig,
        content: str,
    ) -> Dict[str, Any]:
        session = self.create_or_get_vendor_session(session, config)
        session_id = str(session["session_id"])
        vendor_session_id = str(session["vendor_session_id"])
        prompt = str(content or "")

        initialized = bool(session.get("vendor_session_initialized"))
        if initialized:
            resume_cmd = self._build_base_args(config) + ["--resume", vendor_session_id, prompt]
        else:
            resume_cmd = self._build_base_args(config) + ["--session-id", vendor_session_id, prompt]
        result = self._run_cli(config, resume_cmd)
        failed, error_text, error_raw = self._detect_cli_error(result)
        self._record_vendor_state(session_id, command=resume_cmd, error=error_text if failed else "")

        used_fallback = False
        if failed and initialized:
            used_fallback = True
            fallback_cmd = self._build_base_args(config) + ["--session-id", vendor_session_id, prompt]
            result = self._run_cli(config, fallback_cmd)
            failed, error_text, error_raw = self._detect_cli_error(result)
            self._record_vendor_state(session_id, command=fallback_cmd, error=error_text if failed else "")

        if not failed:
            self.session_store.patch(session_id, {"vendor_session_initialized": True, "vendor_last_mode": "resume" if initialized else "session-id"})

        output = str(result.get("stdout") or "").strip() or str(result.get("stderr") or "").strip()
        if failed:
            output = error_text or output

        return {
            "output": output,
            "success": not failed,
            "error": error_text if failed else "",
            "pid": None,
            "alive": False,
            "timed_out": bool(int(result.get("returncode", 0)) == -124),
            "raw": {
                **result,
                "used_fallback": used_fallback,
                "vendor_session_id": vendor_session_id,
                "error_raw": error_raw,
            },
        }

    def invoke_stream(
        self,
        session: Dict[str, Any],
        config: BackendConfig,
        content: str,
    ) -> Generator[Dict[str, Any], None, None]:
        session = self.create_or_get_vendor_session(session, config)
        session_id = str(session["session_id"])
        vendor_session_id = str(session["vendor_session_id"])
        prompt = str(content or "")

        def stream_with(resume_first: bool) -> Generator[Dict[str, Any], None, None]:
            initialized = bool(session.get("vendor_session_initialized"))
            if resume_first and initialized:
                cmd = self._build_base_args(config) + ["--verbose", "--output-format", "stream-json", "--resume", vendor_session_id, prompt]
            else:
                cmd = self._build_base_args(config) + ["--verbose", "--output-format", "stream-json", "--session-id", vendor_session_id, prompt]

            self._record_vendor_state(session_id, command=cmd)
            env = dict(**os.environ)
            env.update(config.env or {})
            try:
                proc = subprocess.Popen(
                    cmd,
                    cwd=config.cwd or None,
                    env=env,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            except FileNotFoundError:
                yield {
                    "type": "error",
                    "error": f"backend command not found: {config.command}",
                    "returncode": -127,
                }
                return

            assert proc.stdout is not None
            assert proc.stderr is not None
            collected_stdout: list[str] = []
            collected_stderr: list[str] = []
            try:
                for line in proc.stdout:
                    raw_line = str(line or "")
                    if not raw_line:
                        continue
                    collected_stdout.append(raw_line)
                    stripped = raw_line.strip()
                    if not stripped:
                        continue
                    try:
                        payload = json.loads(stripped)
                        is_error = bool(payload.get("is_error")) or str(payload.get("subtype") or "") == "error_during_execution"
                        if is_error:
                            err = self._error_text_from_payload(payload) or stripped
                            self._record_vendor_state(session_id, error=err)
                            try:
                                proc.kill()
                            except Exception:
                                pass
                            yield {"type": "error", "error": err, "error_raw": payload, "returncode": proc.poll() if proc.poll() is not None else -1}
                            return
                        fragments = self._extract_text_from_stream_json(payload)
                        if fragments:
                            for text in fragments:
                                yield {"type": "chunk", "source": "stdout", "text": text}
                        # JSON line parsed but produced no user-facing text; skip it.
                    except json.JSONDecodeError:
                        yield {"type": "chunk", "source": "stdout", "text": raw_line}

                stderr_text = proc.stderr.read() or ""
                if stderr_text:
                    collected_stderr.append(stderr_text)
                returncode = proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()
                yield {"type": "error", "error": "backend invoke timeout", "returncode": -124}
                return
            except Exception as exc:
                try:
                    proc.kill()
                except Exception:
                    pass
                yield {"type": "error", "error": str(exc), "returncode": -1}
                return

            stdout_joined = "".join(collected_stdout)
            stderr_joined = "".join(collected_stderr)
            if returncode != 0:
                err = stderr_joined.strip() or stdout_joined.strip() or "backend invoke failed"
                self._record_vendor_state(session_id, error=err)
                yield {
                    "type": "error",
                    "error": err,
                    "returncode": returncode,
                    "stdout": stdout_joined,
                    "stderr": stderr_joined,
                }
                return
            self._record_vendor_state(session_id, error="")
            self.session_store.patch(session_id, {"vendor_session_initialized": True, "vendor_last_mode": "resume" if (resume_first and initialized) else "session-id"})
            yield {
                "type": "done",
                "success": True,
                "returncode": returncode,
                "stdout": stdout_joined,
                "stderr": stderr_joined,
                "pid": None,
                "timed_out": False,
            }

        # resume first, then session-id fallback.
        emitted = False
        fallback_needed = False
        for event in stream_with(resume_first=True):
            emitted = True
            if event.get("type") == "error":
                fallback_needed = True
                continue
            yield event
            if event.get("type") == "done":
                return

        if fallback_needed or not emitted:
            for event in stream_with(resume_first=False):
                yield event
