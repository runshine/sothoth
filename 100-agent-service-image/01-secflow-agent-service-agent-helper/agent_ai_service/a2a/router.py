from __future__ import annotations

import json
from typing import Generator, Iterable
from typing import Any, Dict

from agent_ai_service.config import settings
from agent_ai_service.a2a.session_store import SessionStore
from agent_ai_service.services.backend_runtime import BackendRuntimeService
from agent_ai_service.services.session_pipe_manager import SessionPipeManager
from agent_ai_service.services.session_pty_manager import SessionPtyManager
from agent_ai_service.services.claude_pipe_session_runtime import ClaudePipeSessionRuntime
from agent_ai_service.services.agent_response_protocol import (
    append_output_delta,
    append_reasoning_delta,
    append_trace_item,
    finalize_response,
    new_response_state,
    response_completed_event,
    response_created_event,
    response_failed_event,
    response_output_delta_event,
    response_reasoning_delta_event,
    response_trace_item_event,
    trace_item,
)


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

    @staticmethod
    def _resolve_include_trace(payload: Dict[str, Any]) -> bool:
        value = payload.get('include_trace', True)
        if isinstance(value, bool):
            return value
        text = str(value or '').strip().lower()
        if text in ('0', 'false', 'no', 'off'):
            return False
        return True

    @staticmethod
    def _sse_line(payload: Dict[str, Any]) -> str:
        return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"

    def _new_response_state(
        self,
        *,
        agent_id: str,
        backend: str,
        session_id: str | None,
        mode: str,
        prompt: str,
        include_trace: bool,
    ) -> Dict[str, Any]:
        return new_response_state(
            agent_id=agent_id,
            backend=backend,
            session_id=session_id,
            mode=mode,
            prompt=prompt,
            include_trace=include_trace,
            max_trace_events=settings.agent_trace_max_events,
            max_trace_bytes=settings.agent_trace_max_bytes,
        )

    def _response_payload(self, response: Dict[str, Any], session: Dict[str, Any] | None = None) -> Dict[str, Any]:
        payload = dict(response)
        if session is not None:
            payload['session'] = session
        return payload

    def _normalize_runtime_events(
        self,
        events: Iterable[Dict[str, Any]],
        *,
        backend: str,
        mode: str,
    ) -> Generator[Dict[str, Any], None, None]:
        for event in events:
            event_type = str((event or {}).get('type') or '').strip().lower()
            if event_type in ('output_text', 'reasoning', 'trace', 'done', 'error'):
                yield dict(event)
                continue
            if event_type == 'chunk':
                text = str(event.get('text') or '')
                source = str(event.get('source') or 'stdout').strip().lower() or 'stdout'
                if text:
                    if source == 'stderr':
                        yield {
                            'type': 'trace',
                            'item': trace_item(
                                'backend.stderr',
                                'stderr output',
                                {'text': text, 'backend': backend, 'mode': mode},
                                source=source,
                            ),
                        }
                    else:
                        yield {'type': 'output_text', 'text': text, 'source': source}
                        yield {
                            'type': 'trace',
                            'item': trace_item(
                                'backend.stdout' if mode == 'invoke' else 'agent.substep',
                                'output chunk',
                                {'text': text, 'backend': backend, 'mode': mode},
                                source=source,
                            ),
                        }
                continue
            if event_type:
                yield {
                    'type': 'trace',
                    'item': trace_item(
                        'agent.substep',
                        f'unhandled runtime event: {event_type}',
                        {'event': event, 'backend': backend, 'mode': mode},
                        source='runtime',
                    ),
                }

    def _collect_response_from_events(
        self,
        state: Dict[str, Any],
        events: Iterable[Dict[str, Any]],
    ) -> Dict[str, Any]:
        final_event: Dict[str, Any] | None = None
        error_message = ''
        error_raw: Dict[str, Any] | None = None
        for event in events:
            event_type = str((event or {}).get('type') or '').strip().lower()
            if event_type == 'output_text':
                append_output_delta(state, str(event.get('text') or ''))
                continue
            if event_type == 'reasoning':
                append_reasoning_delta(state, str(event.get('text') or ''))
                continue
            if event_type == 'trace':
                item = event.get('item')
                if isinstance(item, dict):
                    append_trace_item(state, item)
                continue
            if event_type == 'done':
                final_event = dict(event)
                break
            if event_type == 'error':
                final_event = dict(event)
                error_message = str(event.get('error') or 'backend invoke failed')
                error_raw = dict(event)
                break
        if error_message:
            return finalize_response(
                state,
                status='failed',
                error_message=error_message,
                legacy_raw=error_raw,
            )
        return finalize_response(
            state,
            status='completed',
            legacy_raw=final_event,
        )

    def _stream_response_events(
        self,
        state: Dict[str, Any],
        events: Iterable[Dict[str, Any]],
        *,
        session: Dict[str, Any] | None = None,
        emit_terminal: bool = True,
    ) -> Generator[str, None, Dict[str, Any]]:
        yield self._sse_line(response_created_event(state))
        final_event: Dict[str, Any] | None = None
        error_message = ''
        error_raw: Dict[str, Any] | None = None
        for event in events:
            event_type = str((event or {}).get('type') or '').strip().lower()
            if event_type == 'output_text':
                text = str(event.get('text') or '')
                if text:
                    append_output_delta(state, text)
                    yield self._sse_line(response_output_delta_event(state, text))
                continue
            if event_type == 'reasoning':
                text = str(event.get('text') or '')
                if text:
                    append_reasoning_delta(state, text)
                    yield self._sse_line(response_reasoning_delta_event(state, text))
                continue
            if event_type == 'trace':
                item = event.get('item')
                if isinstance(item, dict):
                    append_trace_item(state, item)
                    yield self._sse_line(response_trace_item_event(state, item))
                continue
            if event_type == 'done':
                final_event = dict(event)
                break
            if event_type == 'error':
                final_event = dict(event)
                error_message = str(event.get('error') or 'backend invoke failed')
                error_raw = dict(event)
                break
        if error_message:
            response = finalize_response(
                state,
                status='failed',
                error_message=error_message,
                legacy_raw=error_raw,
            )
            if emit_terminal:
                yield self._sse_line(response_failed_event(response, error_message, session))
            return response
        response = finalize_response(
            state,
            status='completed',
            legacy_raw=final_event,
        )
        if emit_terminal:
            yield self._sse_line(response_completed_event(response, session))
        return response

    def _invoke_backend_events(
        self,
        backend: str,
        prompt: str,
        messages: list[dict[str, Any]] | None = None,
    ) -> Generator[Dict[str, Any], None, None]:
        if self._is_claude_backend(backend):
            model = self.backend_runtime.registry.to_model(backend)
            yield from self.claude_pipe_runtime.invoke_stateless_stream(model, prompt)
            return
        yield from self._normalize_runtime_events(
            self.backend_runtime.invoke_backend_stream(backend, prompt=prompt, messages=messages),
            backend=backend,
            mode='invoke',
        )

    def _session_runtime_events(
        self,
        session: Dict[str, Any],
        content: str,
    ) -> Generator[Dict[str, Any], None, None]:
        session_id = str(session.get('session_id') or '')
        backend = str(session.get('backend') or '')
        mode = self._session_mode(session)
        if mode == 'pipe':
            if self._is_claude_backend(backend):
                model = self.backend_runtime.registry.to_model(backend)
                yield from self.claude_pipe_runtime.invoke_stream(session, model, content)
                return
            self.session_pipe_manager.write_stdin(session_id, content, append_newline=True)
            yield from self._normalize_runtime_events(
                self.session_pipe_manager.stream_round(
                    session_id,
                    quiet_window_ms=settings.session_pty_quiet_window_ms,
                    max_window_ms=settings.session_pty_max_window_ms,
                ),
                backend=backend,
                mode=mode,
            )
            return
        if mode == 'pty':
            self.session_pty_manager.write_stdin(session_id, content, append_newline=True)
            yield from self._normalize_runtime_events(
                self.session_pty_manager.stream_round(
                    session_id,
                    quiet_window_ms=settings.session_pty_quiet_window_ms,
                    max_window_ms=settings.session_pty_max_window_ms,
                ),
                backend=backend,
                mode=mode,
            )
            return
        yield from self._invoke_backend_events(
            backend,
            prompt=content,
            messages=session.get('messages') or [],
        )

    def invoke(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        agent_ids = self._resolve_agent_ids(payload)
        task = payload.get('task') or payload.get('prompt') or ''
        messages = payload.get('messages') or []
        include_trace = self._resolve_include_trace(payload)
        if not agent_ids:
            state = self._new_response_state(
                agent_id='',
                backend='',
                session_id=None,
                mode='invoke',
                prompt=str(task or ''),
                include_trace=include_trace,
            )
            return finalize_response(
                state,
                status='failed',
                error_message='no backend configured',
                legacy_raw={'error': 'no backend configured'},
            )
        agent_id = agent_ids[0]
        state = self._new_response_state(
            agent_id=agent_id,
            backend=agent_id,
            session_id=None,
            mode='invoke',
            prompt=str(task or ''),
            include_trace=include_trace,
        )
        return self._collect_response_from_events(
            state,
            self._invoke_backend_events(agent_id, str(task or ''), messages),
        )

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
        agent_ids = (session.get('agent_ids') or ([backend] if backend else []))[:1]
        include_trace = self._resolve_include_trace(payload)
        try:
            session = self._ensure_session_runtime(session, allow_recreate=True)
            state = self._new_response_state(
                agent_id=agent_ids[0] if agent_ids else backend,
                backend=backend,
                session_id=session_id,
                mode=mode,
                prompt=str(content or ''),
                include_trace=include_trace,
            )
            response = self._collect_response_from_events(
                state,
                self._session_runtime_events(session, str(content or '')),
            )
            assistant_content = str(response.get('output_text') or '').strip()
            round_success = str(response.get('status') or '') == 'completed'
            round_error = str(response.get('error') or '').strip()
            self.session_store.append_message(
                session_id,
                'assistant',
                assistant_content if round_success else (round_error or assistant_content or 'backend invoke failed'),
            )
            patch_payload = {
                'status': 'ready' if round_success else 'broken',
                'session_mode': mode,
                'last_error': None if round_success else round_error,
                'last_response': response,
            }
            if mode == 'pty':
                pid = self.session_pty_manager.get_pid(session_id)
                patch_payload['pty_pid'] = pid
                patch_payload['backend_pid'] = pid
            elif mode == 'pipe' and not self._is_claude_backend(backend):
                patch_payload['pty_pid'] = None
                patch_payload['backend_pid'] = self.session_pipe_manager.get_pid(session_id)
            else:
                patch_payload['pty_pid'] = None
                patch_payload['backend_pid'] = None
            session = self.session_store.patch(session_id, patch_payload)
        except Exception as exc:
            session = self._mark_session_broken(session_id, str(exc), mode=mode)
            error_text = str(exc)
            self.session_store.append_message(session_id, 'assistant', error_text)
            state = self._new_response_state(
                agent_id=agent_ids[0] if agent_ids else backend,
                backend=backend,
                session_id=session_id,
                mode=mode,
                prompt=str(content or ''),
                include_trace=include_trace,
            )
            response = finalize_response(
                state,
                status='failed',
                error_message=error_text,
                legacy_raw={'error': error_text},
            )
            session = self.session_store.patch(session_id, {'last_response': response})
        return self._response_payload(response, session)

    def send_session_message_sse(self, session_id: str, payload: Dict[str, Any]) -> Generator[str, None, None]:
        role = str(payload.get('role') or 'user').strip() or 'user'
        content = str(payload.get('content') or '')
        session = self.session_store.append_message(session_id, role, content)
        backend = str(session.get('backend') or '')
        mode = self._session_mode(session)
        agent_ids = (session.get('agent_ids') or ([backend] if backend else []))[:1]
        include_trace = self._resolve_include_trace(payload)
        if not agent_ids:
            state = self._new_response_state(
                agent_id='',
                backend='',
                session_id=session_id,
                mode=mode,
                prompt=content,
                include_trace=include_trace,
            )
            response = finalize_response(
                state,
                status='failed',
                error_message='no backend configured',
                legacy_raw={'error': 'no backend configured'},
            )
            yield self._sse_line(response_failed_event(response, 'no backend configured', session))
            return
        try:
            session = self._ensure_session_runtime(session, allow_recreate=True)
            state = self._new_response_state(
                agent_id=agent_ids[0] if agent_ids else backend,
                backend=backend,
                session_id=session_id,
                mode=mode,
                prompt=content,
                include_trace=include_trace,
            )
            response = yield from self._stream_response_events(
                state,
                self._session_runtime_events(session, content),
                emit_terminal=False,
            )
            assistant_content = str(response.get('output_text') or '').strip()
            round_success = str(response.get('status') or '') == 'completed'
            round_error = str(response.get('error') or '').strip()
            self.session_store.append_message(
                session_id,
                'assistant',
                assistant_content if round_success else (round_error or assistant_content or 'backend invoke failed'),
            )
            patch_payload = {
                'status': 'ready' if round_success else 'broken',
                'session_mode': mode,
                'last_error': None if round_success else round_error,
                'last_response': response,
            }
            if mode == 'pty':
                pid = self.session_pty_manager.get_pid(session_id)
                patch_payload['pty_pid'] = pid
                patch_payload['backend_pid'] = pid
            elif mode == 'pipe' and not self._is_claude_backend(backend):
                patch_payload['pty_pid'] = None
                patch_payload['backend_pid'] = self.session_pipe_manager.get_pid(session_id)
            else:
                patch_payload['pty_pid'] = None
                patch_payload['backend_pid'] = None
            session = self.session_store.patch(session_id, patch_payload)
            if round_success:
                yield self._sse_line(response_completed_event(response, session))
            else:
                yield self._sse_line(response_failed_event(response, round_error or 'backend invoke failed', session))
        except Exception as exc:
            error_message = str(exc)
            session = self._mark_session_broken(session_id, error_message, mode=mode)
            self.session_store.append_message(session_id, 'assistant', error_message)
            state = self._new_response_state(
                agent_id=agent_ids[0] if agent_ids else backend,
                backend=backend,
                session_id=session_id,
                mode=mode,
                prompt=content,
                include_trace=include_trace,
            )
            response = finalize_response(
                state,
                status='failed',
                error_message=error_message,
                legacy_raw={'error': error_message},
            )
            session = self.session_store.patch(session_id, {'last_response': response})
            yield self._sse_line(response_failed_event(response, error_message, session))

    def invoke_sse(self, payload: Dict[str, Any]) -> Generator[str, None, None]:
        agent_ids = self._resolve_agent_ids(payload)
        task = payload.get('task') or payload.get('prompt') or ''
        messages = payload.get('messages') or []
        include_trace = self._resolve_include_trace(payload)
        if not agent_ids:
            state = self._new_response_state(
                agent_id='',
                backend='',
                session_id=None,
                mode='invoke',
                prompt=str(task or ''),
                include_trace=include_trace,
            )
            response = finalize_response(
                state,
                status='failed',
                error_message='no backend configured',
                legacy_raw={'error': 'no backend configured'},
            )
            yield self._sse_line(response_failed_event(response, 'no backend configured'))
            return
        agent_id = agent_ids[0]
        state = self._new_response_state(
            agent_id=agent_id,
            backend=agent_id,
            session_id=None,
            mode='invoke',
            prompt=str(task or ''),
            include_trace=include_trace,
        )
        yield from self._stream_response_events(
            state,
            self._invoke_backend_events(agent_id, str(task or ''), messages),
        )
