import shutil
import subprocess

from flask import Blueprint, jsonify

from agent_ai_service.config import settings
from agent_ai_service.api.backends import runtime, process_manager

bp = Blueprint('health', __name__)


@bp.get('/health')
def health_check():
    backend_health = runtime.service_health()
    ttyd_ok = shutil.which('ttyd') is not None
    code_server_ok = shutil.which('code-server') is not None or shutil.which('/root/.local/bin/code-server') is not None
    return jsonify({
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
    })


@bp.get('/ready')
def readiness_check():
    return jsonify({
        'status': 'ready',
        'state_dir': str(settings.state_dir),
        'backend_total': runtime.service_health().get('backend_total', 0),
    })


@bp.get('/api/health/details')
def detailed_health():
    data = runtime.service_health()
    try:
        python_version = subprocess.getoutput('python3 --version')
    except Exception:
        python_version = 'unknown'
    return jsonify({
        'status': 'healthy',
        'python': python_version,
        'settings': {
            'rest_port': settings.rest_port,
            'state_dir': str(settings.state_dir),
            'backend_idle_timeout_sec': settings.backend_idle_timeout_sec,
            'backend_invoke_timeout_sec': settings.backend_invoke_timeout_sec,
            'housekeeping_interval_sec': settings.housekeeping_interval_sec,
        },
        'runtime': data,
        'processes': process_manager.list_states(),
    })
