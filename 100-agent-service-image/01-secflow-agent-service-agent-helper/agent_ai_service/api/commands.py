from flask import Blueprint, jsonify, request

from agent_ai_service.services.command_executor import CommandExecutor

bp = Blueprint('commands', __name__)
executor = CommandExecutor()


@bp.post('/api/execute')
def execute_command():
    data = request.get_json(silent=True) or {}
    if 'command' not in data:
        return jsonify({'success': False, 'error': 'No command provided'}), 400
    return jsonify(executor.execute(data['command'], data.get('env') or {}))
