from __future__ import annotations

import json
from typing import Generator
from typing import Any, Dict

from agent_ai_service.a2a.session_store import SessionStore
from agent_ai_service.services.backend_runtime import BackendRuntimeService


class A2AService:
    def __init__(self, backend_runtime: BackendRuntimeService, session_store: SessionStore):
        self.backend_runtime = backend_runtime
        self.session_store = session_store

    def discovery(self) -> Dict[str, Any]:
        backends = self.backend_runtime.list_backends()
        return {
            'protocol': 'a2a',
            'version': 'v1alpha1',
            'default_backend': backends.get('default_backend'),
            'backends': backends.get('items', []),
        }

    def invoke(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        backend = payload.get('backend')
        task = payload.get('task') or payload.get('prompt') or ''
        messages = payload.get('messages') or []
        response = self.backend_runtime.invoke_backend(backend, task, messages)
        return {
            'success': bool(response.get('success', False)),
            'backend': response.get('backend'),
            'output': response.get('stdout', ''),
            'error': response.get('error') or response.get('stderr', ''),
            'raw': response,
        }

    def create_session(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        backend = payload.get('backend') or self.backend_runtime.list_backends().get('default_backend')
        return self.session_store.create(backend=backend, metadata=payload.get('metadata') or {})

    def send_session_message(self, session_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        role = payload.get('role', 'user')
        content = payload.get('content', '')
        session = self.session_store.append_message(session_id, role, content)
        result = self.backend_runtime.invoke_backend(session.get('backend'), content, session.get('messages', []))
        self.session_store.append_message(session_id, 'assistant', result.get('stdout') or result.get('error') or '')
        return {
            'session': self.session_store.get(session_id),
            'result': result,
        }

    def invoke_sse(self, payload: Dict[str, Any]) -> Generator[str, None, None]:
        backend = payload.get('backend') or self.backend_runtime.list_backends().get('default_backend')
        task = payload.get('task') or payload.get('prompt') or ''
        yield f"event: meta\ndata: {json.dumps({'backend': backend, 'status': 'started'}, ensure_ascii=False)}\n\n"
        result = self.backend_runtime.invoke_backend(backend, task, payload.get('messages') or [])
        output = result.get('stdout') or result.get('error') or ''
        if output:
            for line in str(output).splitlines():
                yield f"event: chunk\ndata: {json.dumps({'text': line}, ensure_ascii=False)}\n\n"
        yield f"event: done\ndata: {json.dumps({'success': bool(result.get('success', False)), 'backend': backend}, ensure_ascii=False)}\n\n"
