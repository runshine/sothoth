from flask import Blueprint, jsonify, request

from agent_ai_service.api.backends import runtime
from agent_ai_service.api.a2a_api import a2a

bp = Blueprint('ai_agents', __name__)


def _to_agent(detail):
    if not detail:
        return detail
    return {
        'agent_id': detail.get('name'),
        'name': detail.get('name'),
        'backend_type': detail.get('backend_type') or detail.get('name'),
        'command': detail.get('command'),
        'args': detail.get('args', []),
        'env': detail.get('env', {}),
        'enabled': bool(detail.get('enabled', True)),
        'running': bool(detail.get('running', False)),
        'active': False,  # filled below for list/detail
        'installed': bool(detail.get('installed', False)),
        'pid': detail.get('pid'),
        'description': detail.get('description', ''),
        'llm_provider_key': detail.get('llm_provider_key'),
        'llm_provider_snapshot': detail.get('llm_provider_snapshot') if isinstance(detail.get('llm_provider_snapshot'), dict) else None,
        'llm_provider_applied_at': detail.get('llm_provider_applied_at'),
        'llm_provider_mapped_env_keys': list(detail.get('llm_provider_mapped_env_keys', []) or []),
        'health': {
            'status': 'healthy' if detail.get('installed') else 'unavailable',
            'running': bool(detail.get('running', False)),
            'installed': bool(detail.get('installed', False)),
            'pid': detail.get('pid'),
        },
        'capabilities': detail.get('capabilities', {}),
    }


def _decorate_active(detail):
    payload = _to_agent(detail)
    listing = runtime.list_backends()
    payload['active'] = payload.get('agent_id') == listing.get('default_backend')
    return payload


@bp.get('/api/ai-agents')
def list_ai_agents():
    listing = runtime.list_backends()
    items = []
    for item in listing.get('items', []):
        payload = _to_agent(item)
        payload['active'] = payload.get('agent_id') == listing.get('default_backend')
        items.append(payload)
    return jsonify({
        'default_agent_id': listing.get('default_backend'),
        'items': items,
        'total': len(items),
    })


@bp.get('/api/ai-agents/<agent_id>')
def get_ai_agent(agent_id: str):
    try:
        return jsonify(_decorate_active(runtime.get_backend(agent_id)))
    except KeyError:
        return jsonify({'error': 'ai agent not found'}), 404


@bp.post('/api/ai-agents')
def create_ai_agent():
    payload = request.get_json(silent=True) or {}
    agent_id = str(payload.get('agent_id') or payload.get('name') or '').strip()
    if not agent_id:
        return jsonify({'error': 'agent_id is required'}), 400
    backend_type = str(payload.get('backend_type') or '').strip()
    if not backend_type:
        return jsonify({'error': 'backend_type is required'}), 400
    payload['name'] = agent_id
    payload['backend_type'] = backend_type
    return jsonify(_decorate_active(runtime.upsert_backend(agent_id, payload))), 201


@bp.put('/api/ai-agents/<agent_id>')
def update_ai_agent(agent_id: str):
    payload = request.get_json(silent=True) or {}
    payload['name'] = agent_id
    return jsonify(_decorate_active(runtime.upsert_backend(agent_id, payload)))


@bp.delete('/api/ai-agents/<agent_id>')
def delete_ai_agent(agent_id: str):
    try:
        runtime.delete_backend(agent_id)
        return jsonify({'success': True, 'deleted': agent_id})
    except KeyError:
        return jsonify({'error': 'ai agent not found'}), 404
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 409


@bp.post('/api/ai-agents/<agent_id>/activate')
def activate_ai_agent(agent_id: str):
    try:
        return jsonify(_decorate_active(runtime.activate_backend(agent_id)))
    except KeyError:
        return jsonify({'error': 'ai agent not found'}), 404


@bp.post('/api/ai-agents/<agent_id>/start')
def start_ai_agent(agent_id: str):
    try:
        runtime.start_backend(agent_id)
        return jsonify(_decorate_active(runtime.get_backend(agent_id)))
    except KeyError:
        return jsonify({'error': 'ai agent not found'}), 404


@bp.post('/api/ai-agents/<agent_id>/stop')
def stop_ai_agent(agent_id: str):
    try:
        runtime.stop_backend(agent_id)
        return jsonify(_decorate_active(runtime.get_backend(agent_id)))
    except KeyError:
        return jsonify({'error': 'ai agent not found'}), 404


@bp.get('/api/ai-agents/<agent_id>/env')
def get_ai_agent_env(agent_id: str):
    try:
        return jsonify(runtime.get_backend_env(agent_id))
    except KeyError:
        return jsonify({'error': 'ai agent not found'}), 404


@bp.put('/api/ai-agents/<agent_id>/env')
def replace_ai_agent_env(agent_id: str):
    payload = request.get_json(silent=True) or {}
    env = payload.get('env')
    if not isinstance(env, dict):
        return jsonify({'error': 'env must be an object'}), 400
    try:
        return jsonify(runtime.replace_backend_env(agent_id, env))
    except KeyError:
        return jsonify({'error': 'ai agent not found'}), 404


@bp.delete('/api/ai-agents/<agent_id>/env')
def delete_ai_agent_env(agent_id: str):
    payload = request.get_json(silent=True) or {}
    keys = payload.get('keys') or []
    if not isinstance(keys, list):
        return jsonify({'error': 'keys must be a list'}), 400
    try:
        return jsonify(runtime.delete_backend_env(agent_id, [str(k) for k in keys]))
    except KeyError:
        return jsonify({'error': 'ai agent not found'}), 404


@bp.get('/api/ai-agents/<agent_id>/health')
def get_ai_agent_health(agent_id: str):
    try:
        detail = _decorate_active(runtime.get_backend(agent_id))
        return jsonify(detail.get('health', {}))
    except KeyError:
        return jsonify({'error': 'ai agent not found'}), 404


@bp.get('/api/ai-agents/<agent_id>/capabilities')
def get_ai_agent_capabilities(agent_id: str):
    try:
        detail = runtime.get_backend(agent_id)
        return jsonify(detail.get('capabilities', {}))
    except KeyError:
        return jsonify({'error': 'ai agent not found'}), 404


@bp.post('/api/ai-agents/sessions')
def create_ai_agent_session():
    payload = request.get_json(silent=True) or {}
    session = a2a.create_session(payload)
    return jsonify(session), 201


@bp.get('/api/ai-agents/sessions')
def list_ai_agent_sessions():
    return jsonify({
        'items': a2a.session_store.list(),
        'total': len(a2a.session_store.list()),
    })


@bp.get('/api/ai-agents/sessions/<session_id>')
def get_ai_agent_session(session_id: str):
    session = a2a.session_store.get(session_id)
    if not session:
        return jsonify({'error': 'session not found'}), 404
    return jsonify(session)


@bp.post('/api/ai-agents/sessions/<session_id>/messages')
def send_ai_agent_session_message(session_id: str):
    payload = request.get_json(silent=True) or {}
    try:
        return jsonify(a2a.send_session_message(session_id, payload))
    except KeyError:
        return jsonify({'error': 'session not found'}), 404
