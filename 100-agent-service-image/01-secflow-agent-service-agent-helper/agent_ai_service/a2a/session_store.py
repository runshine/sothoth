from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from agent_ai_service.config import settings
from agent_ai_service.persistence.file_store import JsonFileStore


class SessionStore:
    def __init__(self):
        self.store = JsonFileStore(settings.state_dir / 'sessions.json', lambda: {'sessions': {}})

    def create(
        self,
        backend: str,
        metadata: Optional[Dict[str, Any]] = None,
        agent_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        data = self.store.read()
        session_id = uuid.uuid4().hex
        now = datetime.now(timezone.utc).isoformat()
        normalized_agent_ids = [str(agent_id).strip() for agent_id in (agent_ids or []) if str(agent_id).strip()]
        if not normalized_agent_ids and backend:
            normalized_agent_ids = [str(backend).strip()]
        session = {
            'session_id': session_id,
            'backend': backend,
            'agent_ids': normalized_agent_ids,
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

    def replace(self, session_id: str, updated_session: Dict[str, Any]) -> Dict[str, Any]:
        data = self.store.read()
        if session_id not in data.get('sessions', {}):
            raise KeyError(session_id)
        updated_session['updated_at'] = datetime.now(timezone.utc).isoformat()
        data['sessions'][session_id] = updated_session
        self.store.write(data)
        return updated_session

    def list(self) -> List[Dict[str, Any]]:
        sessions = self.store.read().get('sessions', {})
        return list(sessions.values())

    def delete(self, session_id: str) -> Dict[str, Any]:
        data = self.store.read()
        session = data.get('sessions', {}).get(session_id)
        if not session:
            raise KeyError(session_id)
        data['sessions'].pop(session_id, None)
        self.store.write(data)
        return session
