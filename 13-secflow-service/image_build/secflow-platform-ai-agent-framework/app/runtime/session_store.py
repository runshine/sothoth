from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class SessionRecord:
    session_id: str
    backend_id: str
    session_mode: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    pid: Optional[int] = None
    last_error: str = ""


class SessionStore:
    def __init__(self):
        self._sessions: Dict[str, SessionRecord] = {}

    def create(self, backend_id: str, session_mode: str, metadata: Optional[Dict[str, Any]] = None) -> SessionRecord:
        session = SessionRecord(
            session_id=uuid.uuid4().hex,
            backend_id=backend_id,
            session_mode=session_mode,
            metadata=metadata or {},
        )
        self._sessions[session.session_id] = session
        return session

    def get(self, session_id: str) -> SessionRecord | None:
        return self._sessions.get(session_id)

    def patch(self, session_id: str, **updates: Any) -> SessionRecord:
        session = self._sessions[session_id]
        for key, value in updates.items():
            setattr(session, key, value)
        session.updated_at = utc_now()
        return session

    def delete(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
