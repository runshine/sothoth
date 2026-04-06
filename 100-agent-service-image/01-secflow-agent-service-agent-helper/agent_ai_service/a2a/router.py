from __future__ import annotations

import json
from typing import Generator
from typing import Any, Dict

from agent_ai_service.config import settings
from agent_ai_service.a2a.session_store import SessionStore
from agent_ai_service.services.backend_runtime import BackendRuntimeService
from agent_ai_service.services.session_pipe_manager import SessionPipeManager
from agent_ai_service.services.session_pty_manager import SessionPtyManager
from agent_ai_service.services.claude_pipe_session_runtime import ClaudePipeSessionRuntime


class A2AService:
    def __init__(
        self,
        backend_runtime: BackendRuntimeService,
        session_store: SessionStore,
        session_pty_manager: SessionPtyManager,
        session_pipe_manager: SessionPipeManager,
        claude_pipe_runtime: ClaudePipeSessionRuntime,
    ):
        self.backend_runtime = backend_runtime
        self.session_store = session_store
        self.session_pty_manager = session_pty_manager
        self.session_pipe_manager = session_pipe_manager
        self.claude_pipe_runtime = claude_pipe_runtime

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

    def _resolve_session_mode(self, value: Any, default: str = 'pipe') -> str:
        text = str(value or '').strip().lower()
        if text == 'once':
            return 'invoke'
        if text in ('pipe', 'pty', 'invoke'):
            return text
        return default

    def _session_mode(self, session: Dict[str, Any]) -> str:
        # Backward compatibility: old sessions without session_mode are treated as PTY sessions.
        return self._resolve_session_mode(session.get('session_mode'), default='pty')

    def _is_claude_backend(self, backend: str) -> bool:
        cfg = self.backend_runtime.registry.get(str(backend or '').strip()) or {}
        backend_type = str(cfg.get('backend_type') or backend or '').strip().lower()
        return backend_type == 'claude'

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
        session_mode = self._resolve_session_mode(payload.get('session_mode'), default='pipe')
        session = self.session_store.create(
            backend=backend,
            metadata=payload.get('metadata') or {},
            agent_ids=agent_ids[:1],
            session_mode=session_mode,
        )
        if not backend:
            return self.session_store.patch(session['session_id'], {
                'status': 'broken',
                'last_error': 'no backend configured',
            })
        try:
            model = self.backend_runtime.registry.to_model(str(backend))
            if session_mode == 'pty':
                pty_state = self.session_pty_manager.create_session_pty(session['session_id'], model)
                return self.session_store.patch(session['session_id'], {
                    'session_mode': 'pty',
                    'status': 'ready',
                    'pty_pid': pty_state.get('pid'),
                    'backend_pid': pty_state.get('pid'),
                    'pty_started_at': pty_state.get('started_at'),
                    'last_error': None,
                })
            if session_mode == 'pipe':
                if self._is_claude_backend(str(backend)):
                    created = self.session_store.patch(session['session_id'], {
                        'session_mode': 'pipe',
                        'status': 'ready',
                        'pty_pid': None,
                        'backend_pid': None,
                        'pty_started_at': None,
                        'last_error': None,
                    })
                    return self.claude_pipe_runtime.create_or_get_vendor_session(created, model)
                pipe_state = self.session_pipe_manager.create_session_pipe(session['session_id'], model)
                return self.session_store.patch(session['session_id'], {
                    'session_mode': 'pipe',
                    'status': 'ready',
                    'pty_pid': None,
                    'backend_pid': pipe_state.get('pid'),
                    'pty_started_at': pipe_state.get('started_at'),
                    'last_error': None,
                })
            return self.session_store.patch(session['session_id'], {
                'session_mode': 'invoke',
                'status': 'ready',
                'pty_pid': None,
                'backend_pid': None,
                'pty_started_at': None,
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

    def _ensure_session_runtime(self, session: Dict[str, Any], allow_recreate: bool = True) -> Dict[str, Any]:
        session_id = str(session.get('session_id') or '')
        backend = str(session.get('backend') or '')
        mode = self._session_mode(session)
        if not session_id:
            raise RuntimeError('session_id missing')
        if not backend:
            raise RuntimeError('no backend configured')

        if mode == 'pty':
            if self.session_pty_manager.is_alive(session_id):
                pid = self.session_pty_manager.get_pid(session_id)
                return self.session_store.patch(session_id, {
                    'session_mode': 'pty',
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
                'session_mode': 'pty',
                'status': 'ready',
                'pty_pid': pty_state.get('pid'),
                'backend_pid': pty_state.get('pid'),
                'pty_started_at': pty_state.get('started_at'),
                'last_error': None,
            })

        if mode == 'pipe':
            if self._is_claude_backend(backend):
                model = self.backend_runtime.registry.to_model(backend)
                patched = self.session_store.patch(session_id, {
                    'session_mode': 'pipe',
                    'status': 'ready',
                    'pty_pid': None,
                    'backend_pid': None,
                    'last_error': None,
                })
                return self.claude_pipe_runtime.create_or_get_vendor_session(patched, model)
            if self.session_pipe_manager.is_alive(session_id):
                pid = self.session_pipe_manager.get_pid(session_id)
                return self.session_store.patch(session_id, {
                    'session_mode': 'pipe',
                    'status': 'ready',
                    'pty_pid': None,
                    'backend_pid': pid,
                    'last_error': None,
                })
            if not allow_recreate:
                raise RuntimeError('session PIPE is not running')
            model = self.backend_runtime.registry.to_model(backend)
            pipe_state = self.session_pipe_manager.create_session_pipe(session_id, model)
            return self.session_store.patch(session_id, {
                'session_mode': 'pipe',
                'status': 'ready',
                'pty_pid': None,
                'backend_pid': pipe_state.get('pid'),
                'pty_started_at': pipe_state.get('started_at'),
                'last_error': None,
            })

        return self.session_store.patch(session_id, {
            'session_mode': 'invoke',
            'status': 'ready',
            'pty_pid': None,
            'backend_pid': None,
            'last_error': None,
        })

    def _mark_session_broken(self, session_id: str, error_message: str, mode: str = 'pty') -> Dict[str, Any]:
        session = self.session_store.get(session_id) or {}
        is_claude_pipe = mode == 'pipe' and self._is_claude_backend(str(session.get('backend') or ''))
        if mode == 'pipe':
            self.session_pipe_manager.mark_broken(session_id, error_message)
        elif mode == 'pty':
            self.session_pty_manager.mark_broken(session_id, error_message)
        patch_payload = {
            'status': 'broken',
            'last_error': str(error_message or ''),
            'backend_pid': None,
        }
        if is_claude_pipe:
            patch_payload['vendor_last_error'] = str(error_message or '')
        return self.session_store.patch(session_id, patch_payload)

    def delete_session(self, session_id: str) -> Dict[str, Any]:
        session = self.session_store.get(session_id)
        mode = self._session_mode(session or {}) if isinstance(session, dict) else 'pty'
        if mode == 'pipe':
            if self._is_claude_backend(str((session or {}).get('backend') or '')):
                pass
            else:
                self.session_pipe_manager.close_session_pipe(session_id)
        elif mode == 'pty':
            self.session_pty_manager.close_session_pty(session_id)
        # Best effort cleanup of the other runtime store in case of historical mismatch.
        self.session_pty_manager.close_session_pty(session_id)
        self.session_pipe_manager.close_session_pipe(session_id)

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
        mode = self._session_mode(session)
        agent_ids = session.get('agent_ids') or ([backend] if backend else [])
        agent_ids = agent_ids[:1]
        try:
            session = self._ensure_session_runtime(session, allow_recreate=True)
            if mode == 'pipe':
                if self._is_claude_backend(backend):
                    model = self.backend_runtime.registry.to_model(backend)
                    round_result = self.claude_pipe_runtime.invoke_once(session, model, str(content))
                else:
                    self.session_pipe_manager.write_stdin(session_id, str(content), append_newline=True)
                    round_result = self.session_pipe_manager.read_until_idle(
                        session_id,
                        quiet_window_ms=settings.session_pty_quiet_window_ms,
                        max_window_ms=settings.session_pty_max_window_ms,
                    )
            elif mode == 'pty':
                self.session_pty_manager.write_stdin(session_id, str(content), append_newline=True)
                round_result = self.session_pty_manager.read_until_idle(
                    session_id,
                    quiet_window_ms=settings.session_pty_quiet_window_ms,
                    max_window_ms=settings.session_pty_max_window_ms,
                )
            else:
                invoke_result = self.backend_runtime.invoke_backend(backend, prompt=str(content), messages=session.get('messages') or [])
                round_result = {
                    'output': invoke_result.get('stdout') or invoke_result.get('error') or invoke_result.get('stderr') or '',
                    'pid': None,
                    'alive': False,
                    'timed_out': False,
                    'raw': invoke_result,
                }
            assistant_content = str(round_result.get('output') or '').strip()
            round_success = bool(round_result.get('success', True))
            round_error = str(round_result.get('error') or '').strip()
            if round_success:
                self.session_store.append_message(session_id, 'assistant', assistant_content)
            else:
                if not round_error:
                    round_error = assistant_content or 'backend invoke failed'
                self.session_store.append_message(session_id, 'assistant', round_error)
            session = self.session_store.patch(session_id, {
                'status': 'ready' if round_success else 'broken',
                'session_mode': mode,
                'pty_pid': round_result.get('pid') if mode == 'pty' else None,
                'backend_pid': round_result.get('pid') if mode in ('pty', 'pipe') else None,
                'last_error': None if round_success else round_error,
            })
            result = {
                'success': round_success,
                'partial_success': False,
                'agent_count': len(agent_ids),
                'success_count': len(agent_ids) if round_success else 0,
                'results': [{
                    'agent_id': agent_ids[0] if agent_ids else backend,
                    'backend': backend,
                    'success': round_success,
                    'output': assistant_content if round_success else '',
                    'error': '' if round_success else round_error,
                    'raw': round_result,
                }],
            }
        except Exception as exc:
            session = self._mark_session_broken(session_id, str(exc), mode=mode)
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
        mode = self._session_mode(session)
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
        stream_error_payload = None
        try:
            session = self._ensure_session_runtime(session, allow_recreate=True)
            if mode == 'pipe':
                if self._is_claude_backend(backend):
                    model = self.backend_runtime.registry.to_model(backend)
                    stream_iter = self.claude_pipe_runtime.invoke_stream(session, model, content)
                else:
                    self.session_pipe_manager.write_stdin(session_id, content, append_newline=True)
                    stream_iter = self.session_pipe_manager.stream_round(
                        session_id,
                        quiet_window_ms=settings.session_pty_quiet_window_ms,
                        max_window_ms=settings.session_pty_max_window_ms,
                    )
            elif mode == 'pty':
                self.session_pty_manager.write_stdin(session_id, content, append_newline=True)
                stream_iter = self.session_pty_manager.stream_round(
                    session_id,
                    quiet_window_ms=settings.session_pty_quiet_window_ms,
                    max_window_ms=settings.session_pty_max_window_ms,
                )
            else:
                def _invoke_stream():
                    for event in self.backend_runtime.invoke_backend_stream(backend, prompt=content, messages=session.get('messages') or []):
                        event_type = str(event.get('type') or '')
                        if event_type == 'chunk':
                            yield {
                                'type': 'chunk',
                                'text': str(event.get('text') or ''),
                                'source': event.get('source') or 'stdout',
                            }
                        elif event_type == 'done':
                            yield {'type': 'done', 'pid': None, 'timed_out': False, 'raw': event}
                        elif event_type == 'error':
                            raise RuntimeError(str(event.get('error') or 'backend invoke stream failed'))
                stream_iter = _invoke_stream()

            stream_done = {'timed_out': False, 'pid': None}
            for event in stream_iter:
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
                elif event_type == 'error':
                    stream_error_payload = event if isinstance(event, dict) else {'error': str(event)}
                    error_message = str((stream_error_payload or {}).get('error') or 'backend invoke stream failed')
                    err_payload = {
                        'type': 'error',
                        'session_id': session_id,
                        'error_message': error_message,
                        'error_raw': stream_error_payload,
                    }
                    yield f"data: {json.dumps(err_payload, ensure_ascii=False)}\n\n"
                    raise RuntimeError(error_message)

            assistant_content = ''.join(assistant_text_parts).strip()
            self.session_store.append_message(session_id, 'assistant', assistant_content)
            session = self.session_store.patch(session_id, {
                'status': 'ready',
                'session_mode': mode,
                'pty_pid': stream_done.get('pid') if mode == 'pty' else None,
                'backend_pid': stream_done.get('pid') if mode in ('pty', 'pipe') else None,
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
            session = self._mark_session_broken(session_id, error_message, mode=mode)
            self.session_store.append_message(session_id, 'assistant', error_message)
            err_payload = {
                'type': 'error',
                'session_id': session_id,
                'error_message': error_message,
            }
            if isinstance(stream_error_payload, dict):
                err_payload['error_raw'] = stream_error_payload
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
                    'raw': stream_error_payload if isinstance(stream_error_payload, dict) else {'error': error_message},
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
