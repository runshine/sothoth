from __future__ import annotations

import atexit

from flask import Flask

from process_monitor_service.api.processes import bp as processes_bp
from process_monitor_service.api.sync import bp as sync_bp
from process_monitor_service.services.process_service import process_service
from process_monitor_service.services.sync_runtime import sync_task_service
from process_monitor_service.config import settings

app = Flask(__name__)
app.register_blueprint(processes_bp)
app.register_blueprint(sync_bp)

atexit.register(process_service.stop)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=settings.port, debug=False)
