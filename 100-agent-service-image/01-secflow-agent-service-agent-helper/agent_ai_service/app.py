from flask import Flask
from flask_cors import CORS
from flask_sock import Sock

from agent_ai_service.api.a2a_api import bp as a2a_bp
from agent_ai_service.api.a2a_api import register_ws_routes
from agent_ai_service.api.ai_agents import bp as ai_agents_bp
from agent_ai_service.api.backends import bp as backends_bp
from agent_ai_service.api.commands import bp as commands_bp
from agent_ai_service.api.health import bp as health_bp
from agent_ai_service.api.openai_compat import bp as openai_compat_bp
from agent_ai_service.api.system import bp as system_bp
from agent_ai_service.logging_setup import configure_logging
from agent_ai_service.api.backends import process_manager

configure_logging()
process_manager.start_housekeeping()

app = Flask(__name__)
CORS(app)
sock = Sock(app)
app.register_blueprint(health_bp)
app.register_blueprint(commands_bp)
app.register_blueprint(system_bp)
app.register_blueprint(backends_bp)
app.register_blueprint(ai_agents_bp)
app.register_blueprint(a2a_bp)
app.register_blueprint(openai_compat_bp)
register_ws_routes(sock)


if __name__ == '__main__':
    from agent_ai_service.config import settings

    app.run(host='0.0.0.0', port=settings.rest_port, debug=False)
