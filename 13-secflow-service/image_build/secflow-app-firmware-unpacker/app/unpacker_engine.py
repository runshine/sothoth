"""Firmware unpacking execution engine used by the task manager."""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable, Optional

from app.logging_utils import log_event
from app.preprocess import detect_format, run_preprocess
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

TOOLS_DIR = Path(os.environ.get("UNPACKER_TOOLS_DIR", "/data/tools"))
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


def _is_review_success(review_text: str) -> bool:
    lowered = str(review_text or "").strip().lower()
    return '"result":"success"' in lowered or '"result": "success"' in lowered


def _write_json_log(log_dir: Path | None, name: str, payload: dict[str, Any]) -> None:
    if log_dir is None:
        return
    (log_dir / name).write_text(json.dumps(payload, ensure_ascii=False, indent=2))


def _run_reviewer(
    firmware_path: str,
    output_path: str,
    log_dir: Path | None,
    suffix: str,
    val_def: dict[str, Any],
    val_sp: str,
) -> tuple[bool, str]:
    validator = PiRpcClient(
        system_prompt_file=val_sp,
        model=val_def["model"],
        tools=val_def["tools"],
    )
    verify_result = validator.prompt(render_prompt(VAL_PROMPT_TMPL, firmware_path, output_path))
    _save_agent_log(validator, log_dir, f"verifier_{suffix}")
    validator.close()
    return _is_review_success(verify_result), verify_result


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
) -> dict[str, Any]:
    skill_sp = _write_system_prompt(str(skill_meta.get("system_prompt") or ""), "firmware-skill-")
    executor = PiRpcClient(
        system_prompt_file=skill_sp,
        model=skill_meta.get("model"),
        tools=skill_meta.get("tools"),
    )
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
        )
        result = {
            "success": passed,
            "method": f"skill:{skill_meta.get('filename')}",
            "response": exec_result,
            "review": review_result,
        }
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
) -> tuple[bool, int, str]:
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
            cancel_check(executor)
            final_round = attempt
            exec_msg = render_prompt(
                EXEC_FIRST_TMPL if attempt == 1 else EXEC_RETRY_TMPL,
                firmware_path,
                output_path,
            )
            exec_result = executor.prompt(exec_msg)
            _save_agent_log(executor, log_dir, f"executor_round_{attempt}")
            passed, verify_result = _run_reviewer(
                firmware_path,
                output_path,
                log_dir,
                f"round_{attempt}",
                val_def,
                val_sp,
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
            if passed:
                break
            last_reason = verify_result
        return passed, final_round, last_reason
    finally:
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
) -> dict[str, Any] | None:
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
        )
        try:
            raw_doc = author.prompt(prompt)
            _save_agent_log(author, log_dir, "skill_author")
        finally:
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
        return saved
    except Exception as exc:
        _write_json_log(
            log_dir,
            "stage5_skill_generate.json",
            {"error": str(exc), "family_id": compute_family_id(features)},
        )
        return None


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


def _get_unpack_engine_mode() -> str:
    try:
        from app.config import get_config

        return get_config().agentflow.engine_mode.strip().lower()
    except Exception:
        return os.environ.get("UNPACKER_ENGINE_MODE", "legacy").strip().lower()


def _agentflow_fallback_enabled() -> bool:
    try:
        from app.config import get_config

        return bool(get_config().agentflow.fallback_to_legacy)
    except Exception:
        return os.environ.get("AGENTFLOW_FALLBACK_TO_LEGACY", "true").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }


def run_unpack_legacy(
    firmware_path: str,
    output_path: str,
    cancel_check: Optional[Callable[[], bool]] = None,
) -> dict:
    """Execute the legacy Pi RPC firmware unpacking pipeline."""

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
        features["family_id"] = compute_family_id(features)
        skill_meta, skill_score, skill_match = match_skill(features, TOOLS_DIR)
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
            _check_cancel()
            skill_result = _run_skill_unpack(
                skill_meta,
                firmware_path,
                output_path,
                log_dir,
                val_def,
                val_sp,
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
                _write_json_log(
                    log_dir,
                    "stage4_llm_fallback.json",
                    {
                        "matched_skill": skill_meta.get("path"),
                        "reason": _preview_text(last_reason, 400),
                    },
                )

        if not passed:
            generic_passed, final_round, last_reason = _run_generic_unpack(
                firmware_path,
                output_path,
                log_dir,
                _check_cancel,
                exec_def,
                val_def,
                exec_sp,
                val_sp,
            )
            passed = generic_passed
            if passed:
                generated_skill = _generate_candidate_skill(
                    firmware_path,
                    output_path,
                    features,
                    last_reason or '{"result":"success"}',
                    log_dir,
                )

        _check_cancel()
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


def run_unpack(
    firmware_path: str,
    output_path: str,
    cancel_check: Optional[Callable[[], bool]] = None,
    task_id: str | None = None,
    project_id: str | None = None,
) -> dict:
    """Execute the configured firmware unpacking pipeline."""

    mode = _get_unpack_engine_mode()
    if mode == "agentflow":
        try:
            from app.agentflow_runner import run_unpack_agentflow

            return run_unpack_agentflow(
                firmware_path,
                output_path,
                cancel_check=cancel_check,
                task_id=task_id,
                project_id=project_id,
            )
        except Exception:
            if _agentflow_fallback_enabled():
                log.exception("agentflow engine failed, falling back to legacy")
                return run_unpack_legacy(
                    firmware_path,
                    output_path,
                    cancel_check=cancel_check,
                )
            raise

    if mode != "legacy":
        log_event(
            log,
            logging.WARNING,
            "unknown unpacker engine mode; using legacy",
            event="unpacker_engine_unknown_mode",
            engine_mode=mode,
        )
    return run_unpack_legacy(
        firmware_path,
        output_path,
        cancel_check=cancel_check,
    )
