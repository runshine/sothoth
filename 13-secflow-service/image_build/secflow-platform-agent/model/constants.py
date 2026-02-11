import os

# ===================== 配置和常量 =====================

# 支持的压缩格式
SUPPORTED_FORMATS = [
    '.zip', '.tar', '.tar.gz', '.tgz',
    '.tar.bz2', '.tbz', '.tbz2', '.tar.xz', '.txz'
]

# 压缩文件扩展名映射
COMPRESSION_EXT_MAPPING = {
    '.zip': 'zip',
    '.tar': 'tar',
    '.tar.gz': 'gz',
    '.tgz': 'gz',
    '.tar.bz2': 'bz2',
    '.tbz': 'bz2',
    '.tbz2': 'bz2',
    '.tar.xz': 'xz',
    '.txz': 'xz'
}

DEFAULT_CONFIG = {
    'port': 18080,
    'host': '0.0.0.0',
    'debug': False,
    'secret_key': 'change-this-secret-key-in-production',
    'services_root': './services',
    'templates_root': './templates',
    'database': {
        'type': 'sqlite',  # sqlite 或 mysql
        'path': './webapi_server.db',  # SQLite专用
        'host': 'localhost',  # MySQL专用
        'port': 3306,  # MySQL专用
        'user': 'root',  # MySQL专用
        'password': '',  # MySQL专用
        'database': 'webapi'  # MySQL专用
    },
    'redis_url': 'redis://localhost:6379/0',
    'redis_enabled': True,  # 是否启用Redis
    'nacos_url': 'http://localhost:8848',
    'nacos_namespace': 'public',
    'agent_api_port': 11187,
    'agent_auth_token': 'default_token_change_me',
    'refresh_interval': 30,
    'max_workers': 10,
    'upload_max_size': 100 * 1024 * 1024,
    'token_expiration': 24 * 3600,
    'log_level': 'INFO',
    'log_file': './webapi_server.log',
    'pod_id': os.environ.get('POD_NAME', 'webapi-server-1'),
    'lock_timeout': 30,
    'max_secflow_agent_task_logs': 1000,
    'task_log_retention_days': 7,
    'supported_formats': SUPPORTED_FORMATS,  # 添加支持的格式列表
    # ===================== 超时配置 =====================
    'agent_api_timeouts': {
        'default': (10, 30),           # 默认：连接10秒，读取30秒
        'health_check': (5, 10),       # 健康检查：连接5秒，读取10秒
        'deploy_create': (10, 60),     # 创建服务：连接10秒，读取60秒
        'deploy_start': (10, 300),     # 启动服务：连接10秒，读取300秒（5分钟）
        'deploy_stop': (10, 120),      # 停止服务：连接10秒，读取120秒
        'deploy_delete': (10, 60),     # 删除服务：连接10秒，读取60秒
        'undeploy': (10, 180),         # 卸载服务：连接10秒，读取180秒
        'file_upload': (10, 600),      # 文件上传：连接10秒，读取600秒（10分钟）
        'stream': (10, 3600),          # 流式响应：连接10秒，读取3600秒（1小时）
        'proxy': (10, 300),            # 代理请求：连接10秒，读取300秒
    },
}
