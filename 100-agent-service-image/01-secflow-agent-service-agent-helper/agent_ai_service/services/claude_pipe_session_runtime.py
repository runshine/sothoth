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
    def _extract_text_from_stream_json(payload: Any) -> list[str]:
        fragments: list[str] = []

        def walk(node: Any) -> None:
            if isinstance(node, str):
                return
            if isinstance(node, list):
                for item in node:
                    walk(item)
                return
            if not isinstance(node, dict):
                return

            # Common shapes from Claude stream-json and message chunk payloads.
            text_value = node.get("text")
            if isinstance(text_value, str) and text_value:
                fragments.append(text_value)
            delta_value = node.get("delta")
            if isinstance(delta_value, str) and delta_value:
                fragments.append(delta_value)
            elif isinstance(delta_value, dict):
                delta_text = delta_value.get("text")
                if isinstance(delta_text, str) and delta_text:
                    fragments.append(delta_text)
            message = node.get("message")
            if isinstance(message, dict):
                walk(message)
            content = node.get("content")
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict):
                        text = item.get("text")
                        if isinstance(text, str) and text:
                            fragments.append(text)
                        delta = item.get("delta")
                        if isinstance(delta, str) and delta:
                            fragments.append(delta)
            output = node.get("output")
            if isinstance(output, str) and output:
                fragments.append(output)

        walk(payload)
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

        resume_cmd = self._build_base_args(config) + ["--resume", vendor_session_id, prompt]
        result = self._run_cli(config, resume_cmd)
        self._record_vendor_state(session_id, command=resume_cmd, error=result.get("stderr") if not result.get("success") else None)

        used_fallback = False
        if not result.get("success"):
            used_fallback = True
            fallback_cmd = self._build_base_args(config) + ["--session-id", vendor_session_id, prompt]
            result = self._run_cli(config, fallback_cmd)
            self._record_vendor_state(session_id, command=fallback_cmd, error=result.get("stderr") if not result.get("success") else None)

        output = str(result.get("stdout") or "").strip()
        if not output:
            output = str(result.get("stderr") or "").strip()

        return {
            "output": output,
            "pid": None,
            "alive": False,
            "timed_out": bool(int(result.get("returncode", 0)) == -124),
            "raw": {
                **result,
                "used_fallback": used_fallback,
                "vendor_session_id": vendor_session_id,
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
            if resume_first:
                cmd = self._build_base_args(config) + ["--output-format", "stream-json", "--resume", vendor_session_id, prompt]
            else:
                cmd = self._build_base_args(config) + ["--output-format", "stream-json", "--session-id", vendor_session_id, prompt]

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
                        fragments = self._extract_text_from_stream_json(payload)
                        if fragments:
                            for text in fragments:
                                yield {"type": "chunk", "source": "stdout", "text": text}
                        else:
                            yield {"type": "chunk", "source": "stdout", "text": stripped}
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
