from __future__ import annotations

from flask import Blueprint, jsonify, request
import psutil

from process_monitor_service.services.process_service import process_service
from process_monitor_service.services.file_collectors import FileCollectorService

bp = Blueprint('processes', __name__)
collector_service = FileCollectorService()


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


def _build_path_tree(paths: list[str]) -> list[dict]:
    root: dict = {'name': '/', 'path': '/', 'type': 'dir', 'children': {}}
    for raw_path in sorted({str(item).strip() for item in paths if str(item).strip()}):
        if not raw_path.startswith('/'):
            continue
        segments = [item for item in raw_path.split('/') if item]
        cursor = root
        current_path = ''
        for index, segment in enumerate(segments):
            current_path += '/' + segment
            is_leaf = index == len(segments) - 1
            if segment not in cursor['children']:
                cursor['children'][segment] = {
                    'name': segment,
                    'path': current_path,
                    'type': 'file' if is_leaf else 'dir',
                    'children': {},
                }
            node = cursor['children'][segment]
            if is_leaf:
                node['type'] = 'file'
            cursor = node

    def to_list(node: dict) -> list[dict]:
        items: list[dict] = []
        for child_name in sorted(node.get('children', {}).keys()):
            child = node['children'][child_name]
            children = to_list(child)
            payload = {
                'name': child['name'],
                'path': child['path'],
                'type': 'dir' if children else child['type'],
            }
            if children:
                payload['children'] = children
            items.append(payload)
        return items

    return to_list(root)


@bp.get('/api/processes/<int:pid>/sync-candidates')
def get_process_sync_candidates(pid: int):
    candidates, pid_summary, pid_results = collector_service.collect_from_pids([int(pid)])
    paths = [item.host_path for item in candidates]
    issues = [item for item in pid_results if int(item.get('pid', -1)) == int(pid)]
    summary = pid_summary.get(str(pid), {})
    return jsonify({
        'pid': pid,
        'total_paths': len(paths),
        'paths': sorted(paths),
        'tree': _build_path_tree(paths),
        'summary': summary,
        'issues': issues,
    })
