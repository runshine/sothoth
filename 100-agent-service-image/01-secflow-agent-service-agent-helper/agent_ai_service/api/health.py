import copy
import subprocess
import threading
import time

from flask import Blueprint, jsonify, request

from agent_ai_service.config import settings
from agent_ai_service.api.backends import runtime, process_manager
from agent_ai_service.services.bin_resolver import binary_installed

bp = Blueprint('health', __name__)

_HEALTH_CACHE_LOCK = threading.Lock()
_HEALTH_CACHE = {
    'health': {'data': None, 'cached_at': 0.0, 'expires_at': 0.0},
    'ready': {'data': None, 'cached_at': 0.0, 'expires_at': 0.0},
    'details': {'data': None, 'cached_at': 0.0, 'expires_at': 0.0},
    'ai_agents_health': {'data': None, 'cached_at': 0.0, 'expires_at': 0.0},
}


def _truthy(value: str) -> bool:
    return str(value or '').strip().lower() in {'1', 'true', 'yes', 'y', 'on'}


def _cache_ttl_sec() -> int:
    try:
        return max(0, int(settings.health_cache_ttl_sec))
    except Exception:
        return 3600


def _use_cache(force_refresh: bool) -> bool:
    if force_refresh:
        return False
    return _cache_ttl_sec() > 0


def _cache_get(cache_key: str, *, force_refresh: bool = False):
    if not _use_cache(force_refresh):
        return None
    now = time.time()
    with _HEALTH_CACHE_LOCK:
        item = _HEALTH_CACHE.get(cache_key) or {}
        data = item.get('data')
        expires_at = float(item.get('expires_at') or 0.0)
        if data is not None and expires_at > now:
            return copy.deepcopy(data)
    return None


def _cache_set(cache_key: str, payload: dict):
    ttl = _cache_ttl_sec()
    if ttl <= 0:
        return
    now = time.time()
    with _HEALTH_CACHE_LOCK:
        _HEALTH_CACHE[cache_key] = {
            'data': copy.deepcopy(payload),
            'cached_at': now,
            'expires_at': now + ttl,
        }


def _cache_get_stale(cache_key: str):
    with _HEALTH_CACHE_LOCK:
        item = _HEALTH_CACHE.get(cache_key) or {}
        data = item.get('data')
        if data is not None:
            return copy.deepcopy(data)
    return None


@bp.get('/health')
def health_check():
    force_refresh = _truthy(request.args.get('refresh'))
    cached = _cache_get('health', force_refresh=force_refresh)
    if isinstance(cached, dict):
        return jsonify(cached)

    backend_health = runtime.service_health()
    ttyd_ok = binary_installed('ttyd')
    code_server_ok = binary_installed('code-server')
    payload = {
        'status': 'healthy',
        'service': 'agent-ai-service',
        'version': '2.0.0',
        'timeout': settings.timeout,
        'privileged': True,
        'default_backend': backend_health.get('default_backend'),
        'components': {
            'ttyd_installed': ttyd_ok,
            'code_server_installed': code_server_ok,
            'state_dir': str(settings.state_dir),
            'backend_registry': True,
            'housekeeping_interval_sec': settings.housekeeping_interval_sec,
        },
        'backends': {
            'total': backend_health.get('backend_total'),
            'installed': backend_health.get('backend_installed'),
            'running': backend_health.get('backend_running'),
        },
        'health_cache_ttl_sec': _cache_ttl_sec(),
    }
    _cache_set('health', payload)
    return jsonify(payload)


@bp.get('/ready')
def readiness_check():
    force_refresh = _truthy(request.args.get('refresh'))
    cached = _cache_get('ready', force_refresh=force_refresh)
    if isinstance(cached, dict):
        return jsonify(cached)

    payload = {
        'status': 'ready',
        'state_dir': str(settings.state_dir),
        'backend_total': runtime.service_health().get('backend_total', 0),
        'health_cache_ttl_sec': _cache_ttl_sec(),
    }
    _cache_set('ready', payload)
    return jsonify(payload)


@bp.get('/api/health/details')
def detailed_health():
    force_refresh = _truthy(request.args.get('refresh'))
    cached = _cache_get('details', force_refresh=force_refresh)
    if isinstance(cached, dict):
        return jsonify(cached)

    data = runtime.service_health()
    try:
        python_version = subprocess.getoutput('python3 --version')
    except Exception:
        python_version = 'unknown'
    payload = {
        'status': 'healthy',
        'python': python_version,
        'settings': {
            'rest_port': settings.rest_port,
            'state_dir': str(settings.state_dir),
            'backend_idle_timeout_sec': settings.backend_idle_timeout_sec,
            'backend_invoke_timeout_sec': settings.backend_invoke_timeout_sec,
            'housekeeping_interval_sec': settings.housekeeping_interval_sec,
            'health_cache_ttl_sec': _cache_ttl_sec(),
        },
        'runtime': data,
        'processes': process_manager.list_states(),
    }
    _cache_set('details', payload)
    return jsonify(payload)


@bp.get('/api/ai-agents/health')
def ai_agent_health():
    force_refresh = _truthy(request.args.get('refresh'))
    cached = _cache_get('ai_agents_health', force_refresh=force_refresh)
    if isinstance(cached, dict):
        return jsonify(cached)

    try:
        data = runtime.service_health()
        payload = {
            'status': 'healthy',
            'service': 'agent-ai-service',
            'default_agent_id': data.get('default_backend'),
            'agents': data.get('items', []),
            'backend_total': data.get('backend_total'),
            'backend_running': data.get('backend_running'),
            'backend_installed': data.get('backend_installed'),
            'health_cache_ttl_sec': _cache_ttl_sec(),
        }
        _cache_set('ai_agents_health', payload)
        return jsonify(payload)
    except Exception as exc:
        # 使用陈旧缓存兜底，避免短时抖动造成平台长时间误判 unhealthy。
        stale = _cache_get_stale('ai_agents_health')
        if isinstance(stale, dict):
            stale['cache_stale'] = True
            stale['cache_error'] = str(exc)
            return jsonify(stale)
        raise
