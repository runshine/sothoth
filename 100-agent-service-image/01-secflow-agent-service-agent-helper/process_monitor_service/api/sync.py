from __future__ import annotations

from flask import Blueprint, jsonify, request

from process_monitor_service.services.sync_runtime import sync_task_service
from process_monitor_service.services.path_mapper import HostPathMapper

bp = Blueprint('sync', __name__)
path_mapper = HostPathMapper()


def _json_error(message: str, status: int = 400):
    return jsonify({'status': 'error', 'error': message}), status


def _normalize_paths(items: list[str]) -> list[str]:
    normalized: list[str] = []
    for raw in items:
        normalized.append(path_mapper.canonicalize_input_path(str(raw)))
    return normalized


@bp.post('/api/sync/tasks')
def create_task():
    payload = request.get_json(silent=True) or {}
    mode = payload.get('mode')
    remote_root_url = (payload.get('remote_root_url') or '').strip()
    remote_path_prefix = payload.get('remote_path_prefix')
    if mode not in {'pid_files', 'path_files'}:
        return _json_error('invalid_mode')
    if not remote_root_url.startswith('http://') and not remote_root_url.startswith('https://'):
        return _json_error('invalid_remote_root_url')
    if mode == 'pid_files':
        pids = payload.get('pids') or []
        if not isinstance(pids, list) or not pids:
            return _json_error('pids_required')
        task = sync_task_service.create_task(
            mode,
            remote_root_url,
            pids=[int(item) for item in pids],
            remote_path_prefix=remote_path_prefix,
        )
    else:
        paths = payload.get('paths') or []
        if not isinstance(paths, list) or not paths:
            return _json_error('paths_required')
        try:
            normalized_paths = _normalize_paths([str(item) for item in paths])
        except ValueError as exc:
            return _json_error(str(exc), 400)
        task = sync_task_service.create_task(
            mode,
            remote_root_url,
            paths=normalized_paths,
            remote_path_prefix=remote_path_prefix,
        )
    return jsonify(task), 202


@bp.post('/api/sync/preview')
def preview_task():
    payload = request.get_json(silent=True) or {}
    mode = payload.get('mode')
    remote_root_url = (payload.get('remote_root_url') or '').strip()
    remote_path_prefix = payload.get('remote_path_prefix')
    preview_limit = int(payload.get('preview_limit') or 50)
    if mode not in {'pid_files', 'path_files'}:
        return _json_error('invalid_mode')
    if not remote_root_url.startswith('http://') and not remote_root_url.startswith('https://'):
        return _json_error('invalid_remote_root_url')
    try:
        if mode == 'pid_files':
            pids = payload.get('pids') or []
            if not isinstance(pids, list) or not pids:
                return _json_error('pids_required')
            result = sync_task_service.preview_sync(
                mode=mode,
                remote_root_url=remote_root_url,
                pids=[int(item) for item in pids],
                remote_path_prefix=remote_path_prefix,
                preview_limit=preview_limit,
            )
        else:
            paths = payload.get('paths') or []
            if not isinstance(paths, list) or not paths:
                return _json_error('paths_required')
            normalized_paths = _normalize_paths([str(item) for item in paths])
            result = sync_task_service.preview_sync(
                mode=mode,
                remote_root_url=remote_root_url,
                paths=normalized_paths,
                remote_path_prefix=remote_path_prefix,
                preview_limit=preview_limit,
            )
    except ValueError as exc:
        return _json_error(str(exc))
    return jsonify(result)


@bp.get('/api/sync/tasks')
def list_tasks():
    status = request.args.get('status')
    items = sync_task_service.list_tasks(status=status)
    return jsonify({'total': len(items), 'items': items})


@bp.get('/api/sync/tasks/<task_id>')
def get_task(task_id: str):
    task = sync_task_service.get_task(task_id)
    if not task:
        return _json_error('task_not_found', 404)
    return jsonify(task)


@bp.get('/api/sync/tasks/<task_id>/progress')
def get_progress(task_id: str):
    progress = sync_task_service.get_progress(task_id)
    if not progress:
        return _json_error('task_not_found', 404)
    return jsonify(progress)


@bp.get('/api/sync/tasks/<task_id>/events')
def get_events(task_id: str):
    cursor = int(request.args.get('cursor', 0))
    limit = min(int(request.args.get('limit', 200)), 1000)
    task = sync_task_service.get_task(task_id)
    if not task:
        return _json_error('task_not_found', 404)
    return jsonify(sync_task_service.get_events(task_id, cursor=cursor, limit=limit))


@bp.get('/api/sync/tasks/<task_id>/results')
def get_results(task_id: str):
    task = sync_task_service.get_task(task_id)
    if not task:
        return _json_error('task_not_found', 404)
    items = sync_task_service.get_results(task_id)
    return jsonify({'total': len(items), 'items': items})


@bp.post('/api/sync/tasks/<task_id>/retry')
def retry_task(task_id: str):
    try:
        task = sync_task_service.retry_task(task_id)
    except KeyError:
        return _json_error('task_not_found', 404)
    return jsonify(task), 202


@bp.delete('/api/sync/tasks')
def purge_tasks():
    payload = request.get_json(silent=True) or {}
    task_ids = payload.get('task_ids') if isinstance(payload.get('task_ids'), list) else None
    status = payload.get('status')
    include_running = bool(payload.get('include_running', False))
    result = sync_task_service.purge_tasks(
        task_ids=[str(item) for item in task_ids] if task_ids else None,
        status=str(status).strip() if status else None,
        include_running=include_running,
    )
    return jsonify(result)
