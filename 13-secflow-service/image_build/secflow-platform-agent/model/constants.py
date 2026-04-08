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
        'database': 'webapi',  # MySQL专用
        'table_prefix': 'secflow_agent_'  # 数据库表前缀
    },
    'redis_url': 'redis://localhost:6379/0',
    'redis_enabled': True,  # 是否启用Redis
    'redis_strict_mode': False,  # 多副本场景下要求Redis可用，否则分布式锁直接失败
    'nacos_url': 'http://localhost:8848',
    'nacos_namespace': 'public',
    'configcenter_service_url': 'http://secflow-platform-configcenter',
    'configcenter_service_timeout_sec': 15,
    'k8s_service_url': 'http://secflow-platform-k8s:10010',
    'k8s_service_timeout_sec': 15,
    'registry': {
        'enabled': True,
        'menu_service_url': 'http://secflow-platform-menu',
        'service_id': 'secflow-platform-agent',
        'service_name': 'Agent 中心',
        'api_prefix': '/api/agent',
        'maturity': '已上线',
        'description': '提供环境服务、Agent 管理、模板与任务调度能力',
        'heartbeat_interval_sec': 30,
        'health_timeout_seconds': 5,
        'health_interval_seconds': 30,
        'health_path': '/api/agent/health',
    },
    'agent_api_port': 11187,
    'daemon_api_port': 11188,
    'agent_ttyd_port': 11198,
    'agent_auth_token': 'default_token_change_me',
    # 11188 守护进程 API 鉴权配置（可与 agent_auth_token 不同）
    'daemon_auth_header': 'X-API-Token',
    'daemon_auth_token': 'default_token_change_me',
    'daemon_read_timeout_sec': 8,
    'refresh_interval': 30,
    'service_sync_interval': 30,
    'enable_background_refresh': True,
    'leader_lock_timeout_sec': 90,
    # Agent 缺失离线宽限期（秒）：避免多副本/多节点下瞬时发现不一致导致状态横跳
    'agent_offline_grace_sec': 120,
    # Agent在线状态陈旧提示阈值（秒），用于列表页面提示，不直接改写状态
    'agent_status_stale_hint_sec': 300,
    # Agent 刷新探测并发度（每轮refresh）
    'agent_refresh_probe_workers': 8,
    'max_workers': 10,
    'enable_task_workers': True,
    'task_worker_count': 5,
    'task_poll_interval_sec': 2,
    'task_lease_sec': 120,
    'task_heartbeat_interval_sec': 15,
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
        'deploy_create': (10, 7200),   # 创建服务：连接10秒，读取7200秒（2小时）
        'deploy_start': (10, 7200),    # 启动服务：连接10秒，读取7200秒（2小时）
        'deploy_stop': (10, 7200),     # 停止服务：连接10秒，读取7200秒（2小时）
        'deploy_delete': (10, 7200),   # 删除服务：连接10秒，读取7200秒（2小时）
        'undeploy': (10, 7200),        # 卸载服务：连接10秒，读取7200秒（2小时）
        'file_upload': (10, 7200),     # 部署文件上传：连接10秒，读取7200秒（2小时）
        'deploy_start_grace_sec': 7200,        # 启动超时后的状态轮询等待上限（秒）
        'deploy_start_poll_interval_sec': 15,  # 启动后状态轮询间隔（秒）
        'stream': (10, 3600),          # 流式响应：连接10秒，读取3600秒（1小时）
        'proxy': (10, 300),            # 代理请求：连接10秒，读取300秒
    },
}
