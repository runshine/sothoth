from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from agent_ai_service.config import settings
from agent_ai_service.persistence.file_store import JsonFileStore


class SessionStore:
    def __init__(self):
        self.store = JsonFileStore(settings.state_dir / 'sessions.json', lambda: {'sessions': {}})

    def create(self, backend: str, metadata: Dict[str, Any] | None = None) -> Dict[str, Any]:
        data = self.store.read()
        session_id = uuid.uuid4().hex
        now = datetime.now(timezone.utc).isoformat()
        session = {
            'session_id': session_id,
            'backend': backend,
            'messages': [],
            'metadata': metadata or {},
            'created_at': now,
            'updated_at': now,
        }
        data['sessions'][session_id] = session
        self.store.write(data)
        return session

    def get(self, session_id: str) -> Dict[str, Any] | None:
        return self.store.read().get('sessions', {}).get(session_id)

    def append_message(self, session_id: str, role: str, content: str) -> Dict[str, Any]:
        data = self.store.read()
        session = data.get('sessions', {}).get(session_id)
        if not session:
            raise KeyError(session_id)
        session['messages'].append({'role': role, 'content': content})
        session['updated_at'] = datetime.now(timezone.utc).isoformat()
        self.store.write(data)
        return session
