from __future__ import annotations

from flask import Blueprint, jsonify, request
import psutil

from process_monitor_service.services.process_service import process_service

bp = Blueprint('processes', __name__)


def _json_error(message: str, status: int = 400):
    return jsonify({'status': 'error', 'error': message}), status


@bp.get('/health')
def health():
    latest = process_service.latest()
    return jsonify({
        'status': 'healthy',
        'service': 'process-monitor-service',
        'port': process_service.settings.port,
        'snapshot_ts': latest.get('ts', 0),
        'summary': latest.get('summary', {}),
    })


@bp.get('/ready')
def ready():
    return jsonify({'status': 'ready', 'service': 'process-monitor-service'})


@bp.get('/api/processes')
def list_processes():
    name = request.args.get('name')
    keyword = request.args.get('keyword')
    items = process_service.list_processes(name=name, keyword=keyword)
    return jsonify({'total': len(items), 'items': items})


@bp.get('/api/processes/summary')
def process_summary():
    return jsonify(process_service.latest())


@bp.post('/api/processes/check')
def check_processes():
    return jsonify(process_service.snapshot())


@bp.get('/api/processes/<int:pid>')
def get_process(pid: int):
    try:
        details = process_service.get_process_details(pid)
        return jsonify(details)
    except psutil.NoSuchProcess:
        return _json_error('process_not_found', 404)
    except FileNotFoundError as exc:
        return _json_error(str(exc), 404)


@bp.post('/api/processes/<int:pid>/signal')
def signal_process(pid: int):
    payload = request.get_json(silent=True) or {}
    try:
        result = process_service.send_signal(
            pids=[pid],
            signal_value=payload.get('signal'),
            force=bool(payload.get('force', False)),
        )
        return jsonify(result)
    except ValueError as exc:
        return _json_error(str(exc))


@bp.post('/api/processes/signal')
def signal_processes():
    payload = request.get_json(silent=True) or {}
    pids = process_service.resolve_target_pids(
        pid=payload.get('pid'),
        pids=payload.get('pids'),
        name=payload.get('name'),
        keyword=payload.get('keyword'),
    )
    if not pids:
        return _json_error('no_target_processes')
    try:
        result = process_service.send_signal(
            pids=pids,
            signal_value=payload.get('signal'),
            force=bool(payload.get('force', False)),
        )
        result['targets'] = pids
        return jsonify(result)
    except ValueError as exc:
        return _json_error(str(exc))
