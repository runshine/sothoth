from flask import Blueprint, jsonify

from agent_ai_service.services.system_info_service import SystemInfoService

bp = Blueprint('system', __name__)


@bp.get('/api/system/info')
def system_info():
    return jsonify(SystemInfoService.collect())


@bp.get('/api/debug/tools')
def debug_tools():
    return jsonify(SystemInfoService.debug_tools())
