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
            'agents': backends.get('items', []),
        }

    def _resolve_agent_ids(self, payload: Dict[str, Any]) -> list[str]:
        agent_ids = payload.get('agent_ids')
        if isinstance(agent_ids, list):
            values = [str(item).strip() for item in agent_ids if str(item).strip()]
            if values:
                return values
        agent_id = str(payload.get('agent_id') or payload.get('backend') or '').strip()
        if agent_id:
            return [agent_id]
        default_backend = self.backend_runtime.list_backends().get('default_backend')
        return [str(default_backend).strip()] if default_backend else []

    def _invoke_for_agents(self, agent_ids: list[str], prompt: str, messages: list[dict[str, Any]] | None = None) -> Dict[str, Any]:
        results = []
        success_count = 0
        for agent_id in agent_ids:
            response = self.backend_runtime.invoke_backend(agent_id, prompt, messages)
            success = bool(response.get('success', False))
            success_count += 1 if success else 0
            results.append({
                'agent_id': agent_id,
                'backend': response.get('backend') or agent_id,
                'success': success,
                'output': response.get('stdout', ''),
                'error': response.get('error') or response.get('stderr', ''),
                'raw': response,
            })
        return {
            'success': success_count == len(agent_ids) and len(agent_ids) > 0,
            'partial_success': 0 < success_count < len(agent_ids),
            'agent_count': len(agent_ids),
            'success_count': success_count,
            'results': results,
        }

    def invoke(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        agent_ids = self._resolve_agent_ids(payload)
        task = payload.get('task') or payload.get('prompt') or ''
        messages = payload.get('messages') or []
        return self._invoke_for_agents(agent_ids, task, messages)

    def create_session(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        agent_ids = self._resolve_agent_ids(payload)
        backend = agent_ids[0] if agent_ids else self.backend_runtime.list_backends().get('default_backend')
        return self.session_store.create(
            backend=backend,
            metadata=payload.get('metadata') or {},
            agent_ids=agent_ids,
        )

    def send_session_message(self, session_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        role = payload.get('role', 'user')
        content = payload.get('content', '')
        session = self.session_store.append_message(session_id, role, content)
        agent_ids = session.get('agent_ids') or ([session.get('backend')] if session.get('backend') else [])
        result = self._invoke_for_agents(agent_ids, content, session.get('messages', []))
        assistant_content = '\n'.join(
            f"[{item.get('agent_id')}] {item.get('output') or item.get('error') or ''}".strip()
            for item in result.get('results', [])
        ).strip()
        self.session_store.append_message(session_id, 'assistant', assistant_content)
        return {
            'session': self.session_store.get(session_id),
            'result': result,
        }

    def send_session_message_sse(self, session_id: str, payload: Dict[str, Any]) -> Generator[str, None, None]:
        role = str(payload.get('role') or 'user').strip() or 'user'
        content = str(payload.get('content') or '')
        session = self.session_store.append_message(session_id, role, content)
        agent_ids = session.get('agent_ids') or ([session.get('backend')] if session.get('backend') else [])
        if not agent_ids:
            error_payload = {
                'type': 'error',
                'session_id': session_id,
                'error_message': 'no backend configured',
            }
            yield f"data: {json.dumps(error_payload, ensure_ascii=False)}\n\n"
            return

        start_payload = {
            'type': 'start',
            'session_id': session_id,
            'agent_ids': agent_ids,
        }
        yield f"data: {json.dumps(start_payload, ensure_ascii=False)}\n\n"

        results = []
        aggregated_lines = []
        success_count = 0
        history_messages = session.get('messages', [])

        for agent_id in agent_ids:
            assistant_text_parts = []
            last_done = None
            try:
                for event in self.backend_runtime.invoke_backend_stream(agent_id, content, history_messages):
                    event_type = str(event.get('type') or '')
                    if event_type == 'chunk':
                        text = str(event.get('text') or '')
                        if not text:
                            continue
                        assistant_text_parts.append(text)
                        delta_payload = {
                            'type': 'delta',
                            'session_id': session_id,
                            'agent_id': agent_id,
                            'delta': text,
                            'source': event.get('source') or 'stdout',
                        }
                        yield f"data: {json.dumps(delta_payload, ensure_ascii=False)}\n\n"
                    elif event_type == 'done':
                        last_done = event
                    elif event_type == 'error':
                        last_done = event
                        break
            except Exception as exc:
                last_done = {'type': 'error', 'error': str(exc)}

            output = ''.join(assistant_text_parts).strip()
            if not output and isinstance(last_done, dict):
                output = str(last_done.get('stdout') or last_done.get('stderr') or last_done.get('error') or '').strip()

            success = bool(isinstance(last_done, dict) and last_done.get('success'))
            success_count += 1 if success else 0
            results.append({
                'agent_id': agent_id,
                'backend': agent_id,
                'success': success,
                'output': output,
                'error': '' if success else str((last_done or {}).get('error') or (last_done or {}).get('stderr') or ''),
                'raw': last_done or {},
            })
            aggregated_lines.append(f"[{agent_id}] {output or ((last_done or {}).get('error') or '')}".strip())

        assistant_content = '\n'.join([line for line in aggregated_lines if line]).strip()
        self.session_store.append_message(session_id, 'assistant', assistant_content)
        final_result = {
            'success': success_count == len(agent_ids) and len(agent_ids) > 0,
            'partial_success': 0 < success_count < len(agent_ids),
            'agent_count': len(agent_ids),
            'success_count': success_count,
            'results': results,
        }
        done_payload = {
            'type': 'done',
            'session_id': session_id,
            'session': self.session_store.get(session_id),
            'result': final_result,
        }
        yield f"data: {json.dumps(done_payload, ensure_ascii=False)}\n\n"

    def invoke_sse(self, payload: Dict[str, Any]) -> Generator[str, None, None]:
        agent_ids = self._resolve_agent_ids(payload)
        task = payload.get('task') or payload.get('prompt') or ''
        yield f"event: meta\ndata: {json.dumps({'agent_ids': agent_ids, 'status': 'started'}, ensure_ascii=False)}\n\n"
        result = self._invoke_for_agents(agent_ids, task, payload.get('messages') or [])
        for item in result.get('results', []):
            output = item.get('output') or item.get('error') or ''
            if output:
                for line in str(output).splitlines():
                    yield f"event: chunk\ndata: {json.dumps({'agent_id': item.get('agent_id'), 'text': line}, ensure_ascii=False)}\n\n"
        yield f"event: done\ndata: {json.dumps(result, ensure_ascii=False)}\n\n"
