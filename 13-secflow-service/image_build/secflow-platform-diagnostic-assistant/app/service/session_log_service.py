from __future__ import annotations

import json
from pathlib import Path
import shutil

from app.config import get_service_yaml
from app.models import DiagnosticAgentEventRecord, DiagnosticMessageRecord


def _runtime_root() -> Path:
    db_path = Path(get_service_yaml().database.sqlite_path)
    return db_path.parent


def _session_dir(session_id: int) -> Path:
    path = _runtime_root() / "session_logs" / f"session-{session_id}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _run_dir(run_id: int) -> Path:
    path = _runtime_root() / "run_logs" / f"run-{run_id}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def append_message_log(record: DiagnosticMessageRecord) -> None:
    path = _session_dir(record.session_id) / "messages.jsonl"
    payload = {
        "id": record.id,
        "session_id": record.session_id,
        "role": record.role,
        "content": record.content,
        "created_at": record.created_at.isoformat(),
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def _iter_message_payloads(payload: object) -> list[object]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("messages", "items", "records", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                nested = _iter_message_payloads(value)
                if nested:
                    return nested
        return [payload]
    return []


def read_message_log(session_id: int) -> list[DiagnosticMessageRecord]:
    path = _session_dir(session_id) / "messages.jsonl"
    if not path.is_file():
        return []
    rows: list[DiagnosticMessageRecord] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
            for item in _iter_message_payloads(payload):
                if isinstance(item, dict):
                    rows.append(DiagnosticMessageRecord.model_validate(item))
        except Exception:
            continue
    return rows


def append_event_log(record: DiagnosticAgentEventRecord) -> None:
    path = _run_dir(record.run_id) / "events.jsonl"
    payload = {
        "id": record.id,
        "run_id": record.run_id,
        "event_type": record.event_type,
        "payload_json": record.payload_json,
        "created_at": record.created_at.isoformat(),
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def read_event_log(run_id: int) -> list[DiagnosticAgentEventRecord]:
    path = _run_dir(run_id) / "events.jsonl"
    if not path.is_file():
        return []
    rows: list[DiagnosticAgentEventRecord] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
            rows.append(DiagnosticAgentEventRecord.model_validate(payload))
        except Exception:
            continue
    return rows


def delete_session_log(session_id: int) -> None:
    path = _runtime_root() / "session_logs" / f"session-{session_id}"
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)


def delete_run_log(run_id: int) -> None:
    path = _runtime_root() / "run_logs" / f"run-{run_id}"
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
