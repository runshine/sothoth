from __future__ import annotations

import json
from typing import Generator
from typing import Any, Dict

from agent_ai_service.config import settings
from agent_ai_service.a2a.session_store import SessionStore
from agent_ai_service.services.backend_runtime import BackendRuntimeService
from agent_ai_service.services.session_pty_manager import SessionPtyManager


class A2AService:
    def __init__(self, backend_runtime: BackendRuntimeService, session_store: SessionStore, session_pty_manager: SessionPtyManager):
        self.backend_runtime = backend_runtime
        self.session_store = session_store
        self.session_pty_manager = session_pty_manager

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
                return [values[0]]
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
        session = self.session_store.create(
            backend=backend,
            metadata=payload.get('metadata') or {},
            agent_ids=agent_ids[:1],
        )
        if not backend:
            return self.session_store.patch(session['session_id'], {
                'status': 'broken',
                'last_error': 'no backend configured',
            })
        try:
            model = self.backend_runtime.registry.to_model(str(backend))
            pty_state = self.session_pty_manager.create_session_pty(session['session_id'], model)
            return self.session_store.patch(session['session_id'], {
                'status': 'ready',
                'pty_pid': pty_state.get('pid'),
                'backend_pid': pty_state.get('pid'),
                'pty_started_at': pty_state.get('started_at'),
                'last_error': None,
            })
        except Exception as exc:
            return self.session_store.patch(session['session_id'], {
                'status': 'broken',
                'last_error': str(exc),
                'pty_pid': None,
                'backend_pid': None,
                'pty_started_at': None,
            })

    def _ensure_session_pty(self, session: Dict[str, Any], allow_recreate: bool = True) -> Dict[str, Any]:
        session_id = str(session.get('session_id') or '')
        backend = str(session.get('backend') or '')
        if not session_id:
            raise RuntimeError('session_id missing')
        if not backend:
            raise RuntimeError('no backend configured')
        if self.session_pty_manager.is_alive(session_id):
            pid = self.session_pty_manager.get_pid(session_id)
            return self.session_store.patch(session_id, {
                'status': 'ready',
                'pty_pid': pid,
                'backend_pid': pid,
                'last_error': None,
            })
        if not allow_recreate:
            raise RuntimeError('session PTY is not running')
        model = self.backend_runtime.registry.to_model(backend)
        pty_state = self.session_pty_manager.create_session_pty(session_id, model)
        return self.session_store.patch(session_id, {
            'status': 'ready',
            'pty_pid': pty_state.get('pid'),
            'pty_started_at': pty_state.get('started_at'),
            'last_error': None,
        })

    def _mark_session_broken(self, session_id: str, error_message: str) -> Dict[str, Any]:
        self.session_pty_manager.mark_broken(session_id, error_message)
        return self.session_store.patch(session_id, {
            'status': 'broken',
            'last_error': str(error_message or ''),
            'backend_pid': None,
        })

    def delete_session(self, session_id: str) -> Dict[str, Any]:
        self.session_pty_manager.close_session_pty(session_id)
        deleted = self.session_store.delete(session_id)
        deleted['status'] = 'closed'
        deleted['pty_pid'] = None
        deleted['backend_pid'] = None
        return deleted

    def send_session_message(self, session_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        role = payload.get('role', 'user')
        content = payload.get('content', '')
        session = self.session_store.append_message(session_id, role, content)
        backend = str(session.get('backend') or '')
        agent_ids = session.get('agent_ids') or ([backend] if backend else [])
        agent_ids = agent_ids[:1]
        try:
            session = self._ensure_session_pty(session, allow_recreate=True)
            self.session_pty_manager.write_stdin(session_id, str(content), append_newline=True)
            round_result = self.session_pty_manager.read_until_idle(
                session_id,
                quiet_window_ms=settings.session_pty_quiet_window_ms,
                max_window_ms=settings.session_pty_max_window_ms,
            )
            assistant_content = str(round_result.get('output') or '').strip()
            self.session_store.append_message(session_id, 'assistant', assistant_content)
            session = self.session_store.patch(session_id, {
                'status': 'ready',
                'pty_pid': round_result.get('pid'),
                'backend_pid': round_result.get('pid'),
                'last_error': None,
            })
            result = {
                'success': True,
                'partial_success': False,
                'agent_count': len(agent_ids),
                'success_count': len(agent_ids),
                'results': [{
                    'agent_id': agent_ids[0] if agent_ids else backend,
                    'backend': backend,
                    'success': True,
                    'output': assistant_content,
                    'error': '',
                    'raw': round_result,
                }],
            }
        except Exception as exc:
            session = self._mark_session_broken(session_id, str(exc))
            error_text = str(exc)
            self.session_store.append_message(session_id, 'assistant', error_text)
            result = {
                'success': False,
                'partial_success': False,
                'agent_count': len(agent_ids),
                'success_count': 0,
                'results': [{
                    'agent_id': agent_ids[0] if agent_ids else backend,
                    'backend': backend,
                    'success': False,
                    'output': '',
                    'error': error_text,
                    'raw': {'error': error_text},
                }],
            }
        return {
            'session': session,
            'result': result,
        }

    def send_session_message_sse(self, session_id: str, payload: Dict[str, Any]) -> Generator[str, None, None]:
        role = str(payload.get('role') or 'user').strip() or 'user'
        content = str(payload.get('content') or '')
        session = self.session_store.append_message(session_id, role, content)
        backend = str(session.get('backend') or '')
        agent_ids = session.get('agent_ids') or ([backend] if backend else [])
        agent_ids = agent_ids[:1]
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

        assistant_text_parts = []
        final_result = None
        try:
            session = self._ensure_session_pty(session, allow_recreate=True)
            self.session_pty_manager.write_stdin(session_id, content, append_newline=True)
            stream_done = {'timed_out': False, 'pid': None}
            for event in self.session_pty_manager.stream_round(
                session_id,
                quiet_window_ms=settings.session_pty_quiet_window_ms,
                max_window_ms=settings.session_pty_max_window_ms,
            ):
                event_type = str(event.get('type') or '')
                if event_type == 'chunk':
                    text = str(event.get('text') or '')
                    if not text:
                        continue
                    assistant_text_parts.append(text)
                    delta_payload = {
                        'type': 'delta',
                        'session_id': session_id,
                        'agent_id': agent_ids[0] if agent_ids else backend,
                        'delta': text,
                        'source': event.get('source') or 'stdout',
                    }
                    yield f"data: {json.dumps(delta_payload, ensure_ascii=False)}\n\n"
                elif event_type == 'done':
                    stream_done = event

            assistant_content = ''.join(assistant_text_parts).strip()
            self.session_store.append_message(session_id, 'assistant', assistant_content)
            session = self.session_store.patch(session_id, {
                'status': 'ready',
                'pty_pid': stream_done.get('pid'),
                'backend_pid': stream_done.get('pid'),
                'last_error': None,
            })
            final_result = {
                'success': True,
                'partial_success': False,
                'agent_count': len(agent_ids),
                'success_count': len(agent_ids),
                'results': [{
                    'agent_id': agent_ids[0] if agent_ids else backend,
                    'backend': backend,
                    'success': True,
                    'output': assistant_content,
                    'error': '',
                    'raw': stream_done,
                }],
            }
        except Exception as exc:
            error_message = str(exc)
            session = self._mark_session_broken(session_id, error_message)
            self.session_store.append_message(session_id, 'assistant', error_message)
            err_payload = {
                'type': 'error',
                'session_id': session_id,
                'error_message': error_message,
            }
            yield f"data: {json.dumps(err_payload, ensure_ascii=False)}\n\n"
            final_result = {
                'success': False,
                'partial_success': False,
                'agent_count': len(agent_ids),
                'success_count': 0,
                'results': [{
                    'agent_id': agent_ids[0] if agent_ids else backend,
                    'backend': backend,
                    'success': False,
                    'output': '',
                    'error': error_message,
                    'raw': {'error': error_message},
                }],
            }
        done_payload = {
            'type': 'done',
            'session_id': session_id,
            'session': session,
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
