from flask import Blueprint, jsonify, request

from agent_ai_service.services.backend_registry import BackendRegistry
from agent_ai_service.services.backend_runtime import BackendRuntimeService
from agent_ai_service.services.agent_process_manager import AgentProcessManager

bp = Blueprint('backends', __name__)
registry = BackendRegistry()
process_manager = AgentProcessManager()
runtime = BackendRuntimeService(registry, process_manager)


@bp.get('/api/agents/backends')
def list_backends():
    return jsonify(runtime.list_backends())


@bp.get('/api/agents/backends/<name>')
def get_backend(name: str):
    try:
        return jsonify(runtime.get_backend(name))
    except KeyError:
        return jsonify({'error': 'backend not found'}), 404


@bp.post('/api/agents/backends')
def create_backend():
    payload = request.get_json(silent=True) or {}
    name = (payload.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'name is required'}), 400
    return jsonify(runtime.upsert_backend(name, payload)), 201


@bp.put('/api/agents/backends/<name>')
def update_backend(name: str):
    payload = request.get_json(silent=True) or {}
    return jsonify(runtime.upsert_backend(name, payload))


@bp.delete('/api/agents/backends/<name>')
def delete_backend(name: str):
    try:
        runtime.delete_backend(name)
        return jsonify({'success': True, 'deleted': name})
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 409


@bp.post('/api/agents/backends/<name>/activate')
def activate_backend(name: str):
    try:
        return jsonify(runtime.activate_backend(name))
    except KeyError:
        return jsonify({'error': 'backend not found'}), 404


@bp.post('/api/agents/backends/<name>/start')
def start_backend(name: str):
    try:
        return jsonify(runtime.start_backend(name))
    except KeyError:
        return jsonify({'error': 'backend not found'}), 404


@bp.post('/api/agents/backends/<name>/stop')
def stop_backend(name: str):
    try:
        return jsonify(runtime.stop_backend(name))
    except KeyError:
        return jsonify({'error': 'backend not found'}), 404


@bp.get('/api/agents/backends/<name>/capabilities')
def backend_capabilities(name: str):
    try:
        detail = runtime.get_backend(name)
        return jsonify(detail.get('capabilities', {}))
    except KeyError:
        return jsonify({'error': 'backend not found'}), 404


@bp.get('/api/agents/backends/<name>/env')
def get_backend_env(name: str):
    try:
        return jsonify(runtime.get_backend_env(name))
    except KeyError:
        return jsonify({'error': 'backend not found'}), 404


@bp.put('/api/agents/backends/<name>/env')
def replace_backend_env(name: str):
    payload = request.get_json(silent=True) or {}
    env = payload.get('env')
    if not isinstance(env, dict):
        return jsonify({'error': 'env must be an object'}), 400
    try:
        return jsonify(runtime.replace_backend_env(name, env))
    except KeyError:
        return jsonify({'error': 'backend not found'}), 404


@bp.delete('/api/agents/backends/<name>/env')
def delete_backend_env(name: str):
    payload = request.get_json(silent=True) or {}
    keys = payload.get('keys') or []
    if not isinstance(keys, list):
        return jsonify({'error': 'keys must be a list'}), 400
    try:
        return jsonify(runtime.delete_backend_env(name, [str(k) for k in keys]))
    except KeyError:
        return jsonify({'error': 'backend not found'}), 404
