from __future__ import annotations

import atexit
import logging

from flask import Flask

from process_monitor_service.api.processes import bp as processes_bp
from process_monitor_service.api.sync import bp as sync_bp
from process_monitor_service.services.process_service import process_service
from process_monitor_service.services.sync_runtime import sync_task_service
from process_monitor_service.services.dns_bootstrap import bootstrap_dns
from process_monitor_service.config import settings

logger = logging.getLogger('process_monitor_service')
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')

dns_bootstrap_result = bootstrap_dns()
logger.info(
    'process_monitor_dns_bootstrap configured DNS_SERVER=%s dns_servers_before=%s dns_servers_after=%s dns_override_applied=%s reason=%s',
    dns_bootstrap_result.get('configured_dns_server', ''),
    dns_bootstrap_result.get('dns_servers_before', []),
    dns_bootstrap_result.get('dns_servers_after', []),
    dns_bootstrap_result.get('dns_override_applied', False),
    dns_bootstrap_result.get('reason', ''),
)
invalid_dns_entries = dns_bootstrap_result.get('invalid_dns_entries') or []
if invalid_dns_entries:
    logger.warning('process_monitor_dns_bootstrap invalid DNS entries ignored: %s', invalid_dns_entries)
if dns_bootstrap_result.get('error'):
    logger.warning('process_monitor_dns_bootstrap failed: %s', dns_bootstrap_result.get('error'))

app = Flask(__name__)
app.register_blueprint(processes_bp)
app.register_blueprint(sync_bp)

atexit.register(process_service.stop)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=settings.port, debug=False)
