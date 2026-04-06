import json

from flask import Blueprint, Response, jsonify, request

from agent_ai_service.a2a.router import A2AService
from agent_ai_service.a2a.session_store import SessionStore
from agent_ai_service.config import settings
from agent_ai_service.api.backends import runtime
from agent_ai_service.services.claude_pipe_session_runtime import ClaudePipeSessionRuntime
from agent_ai_service.services.session_pipe_manager import SessionPipeManager
from agent_ai_service.services.session_pty_manager import SessionPtyManager

bp = Blueprint('a2a', __name__)
session_store = SessionStore()
a2a = A2AService(
    runtime,
    session_store,
    SessionPtyManager(settings.state_dir),
    SessionPipeManager(settings.state_dir),
    ClaudePipeSessionRuntime(session_store),
)


@bp.get('/api/a2a/discovery')
def discovery():
    return jsonify(a2a.discovery())


@bp.post('/api/a2a/invoke')
def invoke():
    payload = request.get_json(silent=True) or {}
    return jsonify(a2a.invoke(payload))


@bp.post('/api/a2a/invoke/stream')
def invoke_stream():
    payload = request.get_json(silent=True) or {}
    return Response(a2a.invoke_sse(payload), mimetype='text/event-stream')


@bp.post('/api/a2a/sessions')
def create_session():
    payload = request.get_json(silent=True) or {}
    return jsonify(a2a.create_session(payload)), 201


@bp.get('/api/a2a/sessions/<session_id>')
def get_session(session_id: str):
    session = a2a.session_store.get(session_id)
    if not session:
        return jsonify({'error': 'session not found'}), 404
    return jsonify(session)


@bp.post('/api/a2a/sessions/<session_id>/messages')
def send_message(session_id: str):
    payload = request.get_json(silent=True) or {}
    try:
        return jsonify(a2a.send_session_message(session_id, payload))
    except KeyError:
        return jsonify({'error': 'session not found'}), 404


def register_ws_routes(sock) -> None:
    @sock.route('/api/a2a/ws')
    def a2a_ws(ws):
        while True:
            message = ws.receive()
            if message is None:
                break
            try:
                payload = json.loads(message)
            except Exception:
                ws.send(json.dumps({'success': False, 'error': 'invalid json'}))
                continue

            action = payload.get('action', 'invoke')
            try:
                if action == 'discovery':
                    ws.send(json.dumps(a2a.discovery(), ensure_ascii=False))
                elif action == 'invoke':
                    ws.send(json.dumps(a2a.invoke(payload), ensure_ascii=False))
                elif action == 'session.create':
                    ws.send(json.dumps(a2a.create_session(payload), ensure_ascii=False))
                elif action == 'session.message':
                    session_id = payload.get('session_id')
                    if not session_id:
                        ws.send(json.dumps({'success': False, 'error': 'session_id is required'}, ensure_ascii=False))
                        continue
                    ws.send(json.dumps(a2a.send_session_message(session_id, payload), ensure_ascii=False))
                else:
                    ws.send(json.dumps({'success': False, 'error': f'unsupported action: {action}'}, ensure_ascii=False))
            except KeyError:
                ws.send(json.dumps({'success': False, 'error': 'session not found'}, ensure_ascii=False))
            except Exception as exc:
                ws.send(json.dumps({'success': False, 'error': str(exc)}, ensure_ascii=False))
