import logging
import os
import re
import threading
import time
import base64
import hashlib
import secrets
import uuid
from collections import OrderedDict
import requests
import websocket as ws_client
from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
from geventwebsocket import Resource, WebSocketApplication
from geventwebsocket.exceptions import WebSocketError
import io
import zipfile
from urllib.parse import quote, urlencode, parse_qs

from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union, Set
from datetime import datetime, timedelta
import json

from model.connection import ConnectionChecker
from model.redis_manager import RedisManager
from model.db import DatabaseManager, DatabaseConnection
from model.constants import SUPPORTED_FORMATS
from model.enhanced_template_manager import EnhancedTemplateManager
from model.agent_manager import AgentManager
from model.task_manager import TaskManager
from model.enhanced_proxy_manager import EnhancedProxyManager
from model.model import AgentInfo
from model.menu_registry import MenuRegistryService

from flask import send_file, redirect, Response
# ===================== Flask应用 =====================


def _build_random_host_prefix(base: str, suffix_len: int = 6) -> str:
    sanitized = ''.join(ch if str(ch).isalnum() else '-' for ch in str(base or '').lower()).strip('-') or 'route'
    random_part = secrets.token_hex(max(1, suffix_len // 2))[:suffix_len]
    return f"{sanitized[:28]}-{random_part}".strip('-')

class WebAPIServer:
    """WEB API服务器（支持多种压缩格式）"""

    def __init__(self, config: Dict):
        self.config = config
        self.logger = self._setup_logger()
        self.started_at = datetime.now()
        self.cached_component_health = {
            'database': 'unknown',
            'redis': 'unknown',
            'nacos': 'unknown',
        }
        self.cached_health_status = 'starting'
        self.health_state_lock = threading.Lock()

        # 1. 检查所有连接
        self._check_startup_connections()

        # 2. 初始化Flask应用
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = config['secret_key']
        self.app.config['MAX_CONTENT_LENGTH'] = config['upload_max_size']
        CORS(self.app)

        # 4. 初始化Redis管理器
        self.redis_manager = RedisManager(
            config.get('redis_url', 'redis://localhost:6379/0'),
            config.get('redis_enabled', True),
            config.get('redis_strict_mode', False)
        )

        # 5. 初始化数据库管理器
        self.db_manager = DatabaseManager(config['database'])

        # 7. 初始化模板管理器（传递支持的格式）
        supported_formats = config.get('supported_formats', SUPPORTED_FORMATS)
        self.template_manager = EnhancedTemplateManager(
            config['templates_root'],
            self.db_manager,
            supported_formats,
            self.redis_manager
        )

        # 8. 初始化Agent管理器（传递超时配置）
        agent_api_timeouts = config.get('agent_api_timeouts', {
            'default': (10, 30),
            'health_check': (5, 10),
            'deploy_create': (10, 7200),
            'deploy_start': (10, 7200),
            'deploy_stop': (10, 7200),
            'deploy_delete': (10, 7200),
            'undeploy': (10, 7200),
            'file_upload': (10, 7200),
            'deploy_start_grace_sec': 7200,
            'deploy_start_poll_interval_sec': 15,
            'stream': (10, 3600),
            'proxy': (10, 300),
        })

        self.agent_manager = AgentManager(
            config['nacos_url'],
            config.get('nacos_namespace', 'public'),
            config.get('agent_api_port', 11187),
            config.get('agent_auth_token', 'default_token_change_me'),
            self.db_manager,
            self.redis_manager,
            config['pod_id'],
            agent_api_timeouts,
            config.get('nacos_username'),  # 新增：Nacos用户名
            config.get('nacos_password'),  # 新增：Nacos密码
            config.get('daemon_api_port', 11188),  # 新增：守护进程API端口
            config.get('daemon_auth_header', 'X-API-Token'),
            config.get('daemon_auth_token') or config.get('agent_auth_token', 'default_token_change_me'),
            config.get('agent_offline_grace_sec', 120),
        )

        # 9. 初始化任务管理器（传递超时配置）
        self.task_manager = TaskManager(
            self.db_manager,
            self.agent_manager,
            self.template_manager,
            config['services_root'],
            self.redis_manager,
            config['pod_id'],
            config.get('max_secflow_agent_task_logs', 1000),
            agent_api_timeouts
        )
        self.task_manager.configure_runtime(
            worker_count=int(config.get('task_worker_count', config.get('max_workers', 5))),
            poll_interval_sec=int(config.get('task_poll_interval_sec', 2)),
            lease_sec=int(config.get('task_lease_sec', 120)),
            heartbeat_interval_sec=int(config.get('task_heartbeat_interval_sec', 15)),
            enable_task_workers=bool(config.get('enable_task_workers', True))
        )
        self.task_manager.set_service_sync_callback(self._sync_single_agent_services_by_key)

        # 10. 初始化代理管理器（新增，传递超时配置）
        self.proxy_manager = EnhancedProxyManager(self.agent_manager, agent_api_timeouts)
        # 11188 守护进程 API 读接口快速失败超时（秒）
        self.daemon_read_timeout_sec = int(config.get('daemon_read_timeout_sec', 8))
        self.agent_ttyd_port = int(config.get('agent_ttyd_port', 11198))
        self.ttyd_probe_timeout_sec = int(config.get('ttyd_probe_timeout_sec', 3))
        self.configcenter_service_url = (config.get('configcenter_service_url') or 'http://secflow-platform-configcenter').rstrip('/')
        self.configcenter_service_timeout_sec = int(config.get('configcenter_service_timeout_sec', 15))
        self.configcenter_service_retries = max(0, int(config.get('configcenter_service_retries', 1)))
        self.configcenter_service_retry_delay_sec = max(0.0, float(config.get('configcenter_service_retry_delay_sec', 0.2)))
        self.k8s_service_url = (config.get('k8s_service_url') or '').rstrip('/')
        self.k8s_service_timeout_sec = int(config.get('k8s_service_timeout_sec', 15))
        self.service_machine_token = config.get('service_machine_token')
        self.menu_registry = MenuRegistryService(config, self.logger)
        self.ingress_rebind_lock = threading.Lock()
        self.ingress_rebind_events: List[Dict[str, Any]] = []

        # 11. 注册路由
        self._register_routes()

        # 12. 后台刷新线程
        self.refresh_thread = None
        self.should_stop = False
        self.refresh_leader_lock_key = config.get('refresh_leader_lock_key', 'platform_agent_refresh_leader')

        self.logger.info(f"当前POD ID: {config['pod_id']}")
        self.logger.info(f"使用数据库: {config['database'].get('type', 'sqlite').upper()}")
        self.logger.info(f"Redis状态: {'已启用' if self.redis_manager.enabled else '已禁用'}")
        self.logger.info(f"支持的压缩格式: {', '.join(supported_formats)}")
        self.logger.info(f"Agent API超时配置: {agent_api_timeouts}")
        self.logger.info(f"Daemon API快速失败超时: {self.daemon_read_timeout_sec}s")
        self.logger.info(f"Agent TTYD端口: {self.agent_ttyd_port}, 探测超时: {self.ttyd_probe_timeout_sec}s")
        self.logger.info(f"AI Helper固定REST端口: {self.config.get('helper_rest_port', 20001)}")
        self.logger.info(
            f"AI Helper健康快照刷新间隔: {int(self.config.get('helper_health_refresh_interval_sec', self.config.get('refresh_interval', 30)))}s"
        )
        self.logger.info(
            f"ConfigCenter服务地址: {self.configcenter_service_url}, 超时: {self.configcenter_service_timeout_sec}s, "
            f"重试: {self.configcenter_service_retries}"
        )
        self.logger.info(f"K8S服务地址: {self.k8s_service_url}, 超时: {self.k8s_service_timeout_sec}s")
        self.logger.info(f"代理功能: 已启用")

    def _setup_logger(self) -> logging.Logger:
        """设置日志"""
        logger = logging.getLogger(__name__)
        logger.setLevel(getattr(logging, self.config['log_level'].upper()))

        # 文件处理器
        log_file = self.config.get('log_file', './webapi_server.log')
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(getattr(logging, self.config['log_level'].upper()))

        # 控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setLevel(getattr(logging, self.config['log_level'].upper()))

        # 格式化
        formatter = logging.Formatter(
            f'%(asctime)s - {self.config["pod_id"]} - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

        return logger

    def _check_startup_connections(self):
        """检查启动连接"""
        self.logger.info("开始检查启动连接...")

        results = ConnectionChecker.check_all_connections(self.config)

        # 检查数据库连接
        db_success, db_message = results.get('database', (False, '数据库检查失败'))
        if not db_success:
            self.logger.error(f"数据库连接失败: {db_message}")
            raise ConnectionError(f"数据库连接失败: {db_message}")

        self.logger.info(f"✓ {db_message}")

        # 检查Nacos连接
        nacos_success, nacos_message = results.get('nacos', (False, 'Nacos检查失败'))
        if not nacos_success:
            self.logger.error(f"Nacos连接失败: {nacos_message}")
            raise ConnectionError(f"Nacos连接失败: {nacos_message}")

        self.logger.info(f"✓ {nacos_message}")

        # 检查Auth连接与机机Token
        auth_url = (self.config.get('auth_service_url') or 'http://secflow-platform-auth').rstrip('/')
        machine_token = self.config.get('service_machine_token')
        if not machine_token:
            self.logger.error("未配置service_machine_token，拒绝启动")
            raise ConnectionError("未配置service_machine_token")

        try:
            health_resp = requests.get(f"{auth_url}/api/auth/health", timeout=(5, 10))
            if health_resp.status_code != 200:
                raise ConnectionError(f"Auth健康检查失败: {health_resp.status_code}")

            validate_resp = requests.post(
                f"{auth_url}/api/auth/validate-token",
                headers={"Authorization": f"Bearer {machine_token}"},
                timeout=(5, 10),
            )
            if validate_resp.status_code != 200:
                raise ConnectionError(f"机机Token校验失败: {validate_resp.status_code} {validate_resp.text}")
            payload = validate_resp.json() if validate_resp.text else {}
            if payload.get("token_type") != "machine":
                raise ConnectionError(f"机机Token类型异常: {payload.get('token_type')}")

            self.logger.info("✓ Auth连通性与机机Token校验通过")
        except Exception as e:
            self.logger.error(f"Auth检查失败: {e}")
            raise ConnectionError(f"Auth检查失败: {e}")

        # 检查Redis连接
        redis_success, redis_message = results.get('redis', (False, 'Redis检查失败'))
        if redis_success:
            self.logger.info(f"✓ {redis_message}")
        else:
            self.logger.warning(f"⚠ {redis_message}，Redis功能将禁用")

        with self.health_state_lock:
            self.cached_component_health = {
                'database': 'connected' if db_success else 'disconnected',
                'redis': 'connected' if redis_success else 'disconnected',
                'nacos': 'connected' if nacos_success else 'disconnected',
            }
            self.cached_health_status = 'healthy' if db_success and nacos_success else 'unhealthy'

        self.logger.info("所有启动连接检查完成")

    def _call_k8s_service(self, method: str, path: str, project_id: str,
                          payload: Optional[Dict] = None,
                          params: Optional[Dict] = None,
                          headers: Optional[Dict] = None) -> requests.Response:
        """调用platform-k8s服务"""
        if not self.k8s_service_url:
            raise ValueError("k8s_service_url未配置")

        url = f"{self.k8s_service_url}{path}"
        merged_params = dict(params or {})
        merged_params["project_id"] = project_id

        req_headers = {}
        if headers:
            req_headers.update(headers)
        if 'Authorization' not in req_headers and self.service_machine_token:
            req_headers['Authorization'] = f"Bearer {self.service_machine_token}"
        if payload is not None:
            req_headers.setdefault('Content-Type', 'application/json')

        return requests.request(
            method=method.upper(),
            url=url,
            params=merged_params,
            json=payload,
            headers=req_headers,
            timeout=(5, self.k8s_service_timeout_sec)
        )

    def _call_configcenter_service(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> requests.Response:
        if not self.configcenter_service_url:
            raise ValueError("configcenter_service_url未配置")
        url = f"{self.configcenter_service_url}{path}"
        headers: Dict[str, str] = {}
        if self.service_machine_token:
            headers['Authorization'] = f"Bearer {self.service_machine_token}"
        if payload is not None:
            headers['Content-Type'] = 'application/json'
        attempts = self.configcenter_service_retries + 1
        last_error: Optional[Exception] = None
        for attempt in range(1, attempts + 1):
            try:
                response = requests.request(
                    method=method.upper(),
                    url=url,
                    params=params or None,
                    json=payload,
                    headers=headers,
                    timeout=(5, self.configcenter_service_timeout_sec),
                )
                if response.status_code >= 500 and attempt < attempts:
                    self.logger.warning(
                        f"ConfigCenter请求返回{response.status_code}，准备重试 "
                        f"({attempt}/{attempts}) path={path}"
                    )
                    time.sleep(self.configcenter_service_retry_delay_sec * attempt)
                    continue
                return response
            except requests.RequestException as exc:
                last_error = exc
                if attempt >= attempts:
                    break
                self.logger.warning(
                    f"ConfigCenter请求异常，准备重试 ({attempt}/{attempts}) path={path}: {exc}"
                )
                time.sleep(self.configcenter_service_retry_delay_sec * attempt)

        if last_error:
            raise last_error
        raise RuntimeError("ConfigCenter请求失败")

    def _resolve_request_ws_scheme(self) -> str:
        """根据请求上下文推断前端应使用的WS协议。"""
        forwarded_proto = (request.headers.get('X-Forwarded-Proto') or '').split(',')[0].strip().lower()
        if forwarded_proto == 'https':
            return 'wss'
        if forwarded_proto == 'http':
            return 'ws'
        return 'wss' if (request.scheme or 'http').lower() == 'https' else 'ws'

    def _resolve_request_host(self) -> str:
        """优先使用反向代理头里的Host。"""
        forwarded_host = (request.headers.get('X-Forwarded-Host') or '').split(',')[0].strip()
        if forwarded_host:
            return forwarded_host
        return request.host

    def _normalize_service_ports(self, ports: Any) -> Dict[str, str]:
        if isinstance(ports, dict):
            return {str(k): str(v) for k, v in ports.items()}
        if isinstance(ports, list):
            normalized = {}
            for idx, item in enumerate(ports):
                if isinstance(item, dict):
                    key = str(item.get('protocol') or item.get('name') or f'port_{idx}')
                    val = str(item.get('port') or item.get('target') or item.get('published') or '')
                    normalized[key] = val
                else:
                    normalized[f'port_{idx}'] = str(item)
            return normalized
        return {}

    def _normalize_service_tags(self, tags: Any) -> List[str]:
        if isinstance(tags, str):
            try:
                parsed = json.loads(tags)
                if isinstance(parsed, list):
                    tags = parsed
                else:
                    tags = [item.strip() for item in tags.split(',')]
            except Exception:
                tags = [item.strip() for item in tags.split(',')]
        elif not isinstance(tags, (list, tuple, set)):
            tags = []

        seen = set()
        normalized: List[str] = []
        for item in tags:
            text = str(item).strip()
            if not text or text in seen:
                continue
            seen.add(text)
            normalized.append(text)
        return normalized

    def _normalize_agent_service_payload(self, agent: Any, service: Dict[str, Any], source: str = 'pull') -> Dict[str, Any]:
        service_name = str(service.get('name') or service.get('service_name') or service.get('id') or '').strip()
        if not service_name:
            return {}

        project_id = getattr(agent, 'project_id', '') or ''
        agent_key = getattr(agent, 'key', '') or ''
        service_uid_raw = f"{project_id}:{agent_key}:{service_name}"
        service_uid = hashlib.sha1(service_uid_raw.encode('utf-8')).hexdigest()

        ports = self._normalize_service_ports(service.get('ports'))
        tags = self._normalize_service_tags(service.get('tags'))
        images = self._extract_service_images(service)
        image = images[0] if images else ''
        status = service.get('status') or service.get('state') or 'unknown'

        return {
            'service_uid': service_uid,
            'project_id': project_id,
            'agent_key': agent_key,
            'agent_hostname': getattr(agent, 'hostname', '') or '',
            'agent_ip': getattr(agent, 'ip_address', '') or '',
            'service_name': service_name,
            'image': str(image),
            'images_json': json.dumps(images, ensure_ascii=False),
            'status': str(status),
            'tags_json': json.dumps(tags, ensure_ascii=False),
            'ports_json': json.dumps(ports, ensure_ascii=False),
            'raw_json': json.dumps(service, ensure_ascii=False),
            'source': source,
            'pod_id': self.config.get('pod_id', ''),
        }

    def _upsert_agent_services_snapshot(self, agent: Any, services: List[Dict[str, Any]], source: str = 'pull') -> Tuple[int, int]:
        table_name = self.db_manager.get_table_name('agent_services')
        now_ts = datetime.now().isoformat()
        seen = 0
        upserted = 0
        normalized_payloads: List[Dict[str, Any]] = []

        for service in services:
            payload = self._normalize_agent_service_payload(agent, service, source=source)
            if not payload:
                continue
            seen += 1
            normalized_payloads.append(payload)

            self._upsert_single_agent_service(payload, now_ts=now_ts)
            upserted += 1

        # pull_force 仅用于补充拉取，不参与缺失收敛，避免与 helper 全量上报语义冲突。
        # 缺失收敛统一由 report_full 驱动。
        source_name = str(source or '').strip().lower()
        if source_name == 'pull_force':
            if seen == 0:
                self.logger.warning(
                    f"pull_force 空快照（仅跳过，不标stale）: agent={getattr(agent, 'key', '')}, "
                    f"project={getattr(agent, 'project_id', '')}"
                )
            return seen, upserted

        # 标记本次快照里不存在的服务为 stale
        # 对 report_full 空快照增加宽限，避免瞬时抖动导致服务整机“消失”。
        if seen == 0 and source_name == 'report_full':
            self._mark_agent_services_stale_with_grace(agent.key, reason=f'{source_name}_empty_snapshot')
            return seen, upserted

        if self.db_manager.db_type == 'mysql':
            if seen == 0:
                self.db_manager.execute_query(
                    f"UPDATE {table_name} SET is_stale = 1, updated_at = NOW() WHERE agent_key = %s",
                    (agent.key,)
                )
            else:
                placeholders = ','.join(['%s'] * seen)
                service_uids = [item['service_uid'] for item in normalized_payloads]
                self.db_manager.execute_query(
                    f"UPDATE {table_name} SET is_stale = 1, updated_at = NOW() "
                    f"WHERE agent_key = %s AND service_uid NOT IN ({placeholders})",
                    tuple([agent.key] + service_uids)
                )
        else:
            if seen == 0:
                self.db_manager.execute_query(
                    f"UPDATE {table_name} SET is_stale = 1, updated_at = datetime('now') WHERE agent_key = ?",
                    (agent.key,)
                )
            else:
                service_uids = [item['service_uid'] for item in normalized_payloads]
                placeholders = ','.join(['?'] * seen)
                self.db_manager.execute_query(
                    f"UPDATE {table_name} SET is_stale = 1, updated_at = datetime('now') "
                    f"WHERE agent_key = ? AND service_uid NOT IN ({placeholders})",
                    tuple([agent.key] + service_uids)
                )

        return seen, upserted

    def _upsert_single_agent_service(self, payload: Dict[str, Any], now_ts: Optional[str] = None):
        table_name = self.db_manager.get_table_name('agent_services')
        now_ts = now_ts or datetime.now().isoformat()
        source_priority = {
            'report_full': 40,
            'report_delta': 30,
            'pull_force': 20,
            'pull': 10,
        }

        def _json_has_content(raw: Any) -> bool:
            if raw is None:
                return False
            if isinstance(raw, (dict, list, tuple, set)):
                return len(raw) > 0
            if isinstance(raw, str):
                text = raw.strip()
                if not text:
                    return False
                try:
                    parsed = json.loads(text)
                except Exception:
                    return bool(text)
                if isinstance(parsed, (dict, list, tuple, set)):
                    return len(parsed) > 0
                return parsed is not None and str(parsed).strip() != ''
            return True

        # 关键保护：如果本轮是低优先级来源且字段为空，不覆盖历史有效值。
        existing_row = None
        try:
            placeholder = "%s" if self.db_manager.db_type == 'mysql' else "?"
            existing_row = self.db_manager.fetch_one(
                f"SELECT image, images_json, status, tags_json, ports_json, raw_json, source FROM {table_name} WHERE service_uid = {placeholder}",
                (payload['service_uid'],)
            )
        except Exception:
            existing_row = None

        if isinstance(existing_row, dict):
            old_source = str(existing_row.get('source') or '').strip().lower()
            new_source = str(payload.get('source') or '').strip().lower()
            old_pri = source_priority.get(old_source, 0)
            new_pri = source_priority.get(new_source, 0)
            old_status = str(existing_row.get('status') or '').strip()
            new_status = str(payload.get('status') or '').strip()

            old_image = str(existing_row.get('image') or '')
            if not str(payload.get('image') or '').strip() and old_image.strip():
                payload['image'] = old_image
            if not _json_has_content(payload.get('images_json')) and _json_has_content(existing_row.get('images_json')):
                payload['images_json'] = existing_row.get('images_json')

            if not _json_has_content(payload.get('tags_json')) and _json_has_content(existing_row.get('tags_json')):
                payload['tags_json'] = existing_row.get('tags_json')
            if not _json_has_content(payload.get('ports_json')) and _json_has_content(existing_row.get('ports_json')):
                payload['ports_json'] = existing_row.get('ports_json')
            if not _json_has_content(payload.get('raw_json')) and _json_has_content(existing_row.get('raw_json')):
                payload['raw_json'] = existing_row.get('raw_json')

            if old_pri > new_pri:
                payload['source'] = existing_row.get('source') or payload.get('source')
                # 低优先级来源不覆盖高优先级来源的有效状态，减少刚拉起阶段抖动。
                if old_status and (not new_status or new_status.lower() in ('unknown', 'not_found')):
                    payload['status'] = old_status

        if self.db_manager.db_type == 'mysql':
            self.db_manager.execute_query(f'''
                INSERT INTO {table_name}
                (service_uid, project_id, agent_key, agent_hostname, agent_ip, service_name,
                 image, images_json, status, tags_json, ports_json, raw_json, source, is_stale, first_seen_at, last_seen_at, pod_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 0, NOW(), NOW(), %s)
                ON DUPLICATE KEY UPDATE
                    project_id = VALUES(project_id),
                    agent_hostname = VALUES(agent_hostname),
                    agent_ip = VALUES(agent_ip),
                    image = VALUES(image),
                    images_json = VALUES(images_json),
                    status = VALUES(status),
                    tags_json = VALUES(tags_json),
                    ports_json = VALUES(ports_json),
                    raw_json = VALUES(raw_json),
                    source = VALUES(source),
                    is_stale = 0,
                    last_seen_at = NOW(),
                    pod_id = VALUES(pod_id),
                    updated_at = NOW()
            ''', (
                payload['service_uid'], payload['project_id'], payload['agent_key'],
                payload['agent_hostname'], payload['agent_ip'], payload['service_name'],
                payload['image'], payload.get('images_json') or '[]', payload['status'], payload['tags_json'], payload['ports_json'], payload['raw_json'],
                payload['source'], payload['pod_id']
            ))
        else:
            self.db_manager.execute_query(f'''
                INSERT INTO {table_name}
                (service_uid, project_id, agent_key, agent_hostname, agent_ip, service_name,
                 image, images_json, status, tags_json, ports_json, raw_json, source, is_stale, first_seen_at, last_seen_at, updated_at, pod_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
                ON CONFLICT(service_uid) DO UPDATE SET
                    project_id=excluded.project_id,
                    agent_hostname=excluded.agent_hostname,
                    agent_ip=excluded.agent_ip,
                    image=excluded.image,
                    images_json=excluded.images_json,
                    status=excluded.status,
                    tags_json=excluded.tags_json,
                    ports_json=excluded.ports_json,
                    raw_json=excluded.raw_json,
                    source=excluded.source,
                    is_stale=0,
                    last_seen_at=excluded.last_seen_at,
                    updated_at=excluded.updated_at,
                    pod_id=excluded.pod_id
            ''', (
                payload['service_uid'], payload['project_id'], payload['agent_key'],
                payload['agent_hostname'], payload['agent_ip'], payload['service_name'],
                payload['image'], payload.get('images_json') or '[]', payload['status'], payload['tags_json'], payload['ports_json'], payload['raw_json'],
                payload['source'], now_ts, now_ts, now_ts, payload['pod_id']
            ))

    def _mark_agent_services_stale(self, agent_key: str):
        table_name = self.db_manager.get_table_name('agent_services')
        if self.db_manager.db_type == 'mysql':
            self.db_manager.execute_query(
                f"UPDATE {table_name} SET is_stale = 1, updated_at = NOW() WHERE agent_key = %s",
                (agent_key,)
            )
        else:
            self.db_manager.execute_query(
                f"UPDATE {table_name} SET is_stale = 1, updated_at = datetime('now') WHERE agent_key = ?",
                (agent_key,)
            )

    def _parse_db_datetime(self, value: Any) -> Optional[datetime]:
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        text = str(value).strip()
        if not text:
            return None
        normalized = text.replace('Z', '+00:00')
        try:
            return datetime.fromisoformat(normalized)
        except Exception:
            pass
        for fmt in ('%Y-%m-%d %H:%M:%S', '%a, %d %b %Y %H:%M:%S GMT'):
            try:
                return datetime.strptime(text, fmt)
            except Exception:
                continue
        return None

    def _get_service_stale_grace_seconds(self) -> int:
        raw = self.config.get('service_stale_grace_sec', 120)
        try:
            return max(0, int(raw))
        except Exception:
            return 120

    def _mark_agent_services_stale_with_grace(self, agent_key: str, reason: str = '') -> bool:
        grace_sec = self._get_service_stale_grace_seconds()
        if grace_sec <= 0:
            self._mark_agent_services_stale(agent_key)
            return True

        table_name = self.db_manager.get_table_name('agent_services')
        try:
            row = self.db_manager.fetch_one(
                f"SELECT MAX(last_seen_at) AS last_seen_at FROM {table_name} WHERE agent_key = %s AND is_stale = 0"
                if self.db_manager.db_type == 'mysql' else
                f"SELECT MAX(last_seen_at) AS last_seen_at FROM {table_name} WHERE agent_key = ? AND is_stale = 0",
                (agent_key,)
            )
            last_seen = self._parse_db_datetime((row or {}).get('last_seen_at'))
            if last_seen:
                now = datetime.now(last_seen.tzinfo) if last_seen.tzinfo else datetime.now()
                age_sec = (now - last_seen).total_seconds()
                if age_sec < grace_sec:
                    self.logger.info(
                        f"延迟标记服务stale: agent={agent_key}, age={age_sec:.1f}s < grace={grace_sec}s, reason={reason or '-'}"
                    )
                    return False
        except Exception as e:
            self.logger.warning(f"检查服务stale宽限失败，按原策略执行: agent={agent_key}, err={e}")

        self._mark_agent_services_stale(agent_key)
        return True

    def _resolve_or_auto_create_agent_for_report(self, agent_key: str):
        """服务上报场景下，允许未知agent自动发现并创建。"""
        agent = self.agent_manager.get_agent(agent_key)
        if agent:
            return agent

        try:
            agent = self.agent_manager.ensure_agent_exists(agent_key)
        except Exception as e:
            self.logger.warning(f"服务上报自动创建Agent失败: key={agent_key}, err={e}")
            agent = None

        return agent

    def _upsert_agent_from_report(self, agent_key: str, report_data: Dict[str, Any]):
        """根据Agent上报负载补齐/修正Agent主记录。"""
        if not agent_key:
            return None

        project_id = str(report_data.get('project_id') or report_data.get('workspace_id') or '').strip()
        hostname = str(report_data.get('hostname') or '').strip()
        ip_address = str(report_data.get('ip_address') or report_data.get('agent_ip') or '').strip()
        full_name = str(report_data.get('full_name') or '').strip()
        raw_system_info = report_data.get('system_info')
        raw_daemon_info = report_data.get('daemon_info')
        raw_services = report_data.get('services')

        def _parse_json_like(value: Any, default_value: Any) -> Any:
            if value is None:
                return default_value
            if isinstance(value, (dict, list)):
                return value
            if isinstance(value, str):
                text = value.strip()
                if not text:
                    return default_value
                try:
                    parsed = json.loads(text)
                    if isinstance(default_value, dict) and isinstance(parsed, dict):
                        return parsed
                    if isinstance(default_value, list) and isinstance(parsed, list):
                        return parsed
                except Exception:
                    return default_value
            return default_value

        report_system_info = _parse_json_like(raw_system_info, {})
        report_daemon_info = _parse_json_like(raw_daemon_info, {})
        report_services = _parse_json_like(raw_services, [])

        agent = self.agent_manager.get_agent(agent_key) or self.agent_manager.ensure_agent_exists(agent_key)
        if agent:
            if project_id:
                agent.project_id = project_id
            if hostname:
                agent.hostname = hostname
            if ip_address:
                agent.ip_address = ip_address

            if full_name:
                agent.full_name = full_name
            elif agent.project_id and agent.hostname and agent.ip_address:
                agent.full_name = f"{agent.project_id}-{agent.key}-{agent.hostname}-{agent.ip_address}"
            elif not agent.full_name:
                agent.full_name = agent_key

            agent.status = 'online'
            agent.last_seen = datetime.now()
            if isinstance(report_system_info, dict) and report_system_info:
                agent.system_info = report_system_info
            if isinstance(report_daemon_info, dict) and report_daemon_info:
                agent.daemon_info = report_daemon_info
            if isinstance(report_services, list):
                agent.services = report_services
            self.agent_manager._save_agent_to_db(agent)
            if agent.project_id:
                with self.agent_manager.lock:
                    self.agent_manager.agents[agent.key] = agent
                    self.agent_manager._update_project(agent.project_id, agent.key)
            return agent

        if not project_id:
            return None

        if not hostname:
            hostname = f"agent-{agent_key[:8]}"
        if not full_name:
            full_name = (
                f"{project_id}-{agent_key}-{hostname}-{ip_address}"
                if ip_address else f"{project_id}-{agent_key}-{hostname}"
            )
        created = AgentInfo(
            key=agent_key,
            ip_address=ip_address,
            hostname=hostname,
            project_id=project_id,
            full_name=full_name,
            status='online',
            pod_id=self.config.get('pod_id', '')
        )
        created.last_seen = datetime.now()
        if isinstance(report_system_info, dict) and report_system_info:
            created.system_info = report_system_info
        if isinstance(report_daemon_info, dict) and report_daemon_info:
            created.daemon_info = report_daemon_info
        if isinstance(report_services, list):
            created.services = report_services
        self.agent_manager._save_agent_to_db(created)
        ensured = self.agent_manager.ensure_agent_exists(agent_key)
        if ensured and ensured.project_id:
            with self.agent_manager.lock:
                self.agent_manager.agents[ensured.key] = ensured
                self.agent_manager._update_project(ensured.project_id, ensured.key)
        return ensured

    def _cleanup_agent_k8s_resources(self, project_id: str, agent_key: str) -> Dict[str, Any]:
        """清理agent关联的K8S资源（当前含动态Ingress路由）。"""
        result = {
            'agent_key': agent_key,
            'success': True,
            'deleted_ingress_routes': 0,
            'errors': []
        }
        if not project_id or not agent_key:
            return result

        try:
            list_resp = self._call_k8s_service(
                method='GET',
                path='/api/k8s/agent-ingress-routes',
                project_id=project_id,
                params={'agent_key': agent_key},
            )
            if list_resp.status_code >= 300:
                result['success'] = False
                result['errors'].append(f"list ingress routes failed: {list_resp.status_code}")
                return result

            payload = list_resp.json() if list_resp.content else {}
            items = []
            if isinstance(payload, dict):
                raw_items = payload.get('items') or payload.get('routes') or []
                if isinstance(raw_items, list):
                    items = raw_items
            elif isinstance(payload, list):
                items = payload

            for item in items:
                route_id = str((item or {}).get('route_id') or (item or {}).get('id') or '').strip()
                if not route_id:
                    continue
                del_resp = self._call_k8s_service(
                    method='DELETE',
                    path=f'/api/k8s/agent-ingress-routes/{route_id}',
                    project_id=project_id,
                    params={'agent_key': agent_key},
                )
                if del_resp.status_code < 300:
                    result['deleted_ingress_routes'] += 1
                else:
                    result['success'] = False
                    result['errors'].append(f"delete ingress route {route_id} failed: {del_resp.status_code}")
        except Exception as e:
            result['success'] = False
            result['errors'].append(str(e))

        return result

    def _get_stale_agent_keys(self, project_id: Optional[str] = None) -> set:
        table_name = self.db_manager.get_table_name('agent_services')
        if self.db_manager.db_type == 'mysql':
            if project_id:
                rows = self.db_manager.fetch_all(
                    f"SELECT DISTINCT agent_key FROM {table_name} WHERE is_stale = 1 AND project_id = %s",
                    (project_id,)
                )
            else:
                rows = self.db_manager.fetch_all(
                    f"SELECT DISTINCT agent_key FROM {table_name} WHERE is_stale = 1"
                )
        else:
            if project_id:
                rows = self.db_manager.fetch_all(
                    f"SELECT DISTINCT agent_key FROM {table_name} WHERE is_stale = 1 AND project_id = ?",
                    (project_id,)
                )
            else:
                rows = self.db_manager.fetch_all(
                    f"SELECT DISTINCT agent_key FROM {table_name} WHERE is_stale = 1"
                )
        return {str(row.get('agent_key')) for row in rows if row.get('agent_key')}

    def _list_project_ingress_routes(self, project_id: str, include_deleted: bool = False,
                                     auth_header: Optional[str] = None) -> List[Dict[str, Any]]:
        """查询项目下动态Ingress路由列表（来自platform-k8s）。"""
        resp = self._call_k8s_service(
            method='GET',
            path='/api/k8s/agent-ingress-routes',
            project_id=project_id,
            params={'include_deleted': str(include_deleted).lower()},
            headers={'Authorization': auth_header} if auth_header else None
        )
        if resp.status_code >= 300:
            raise RuntimeError(f"list ingress routes failed: {resp.status_code}, body={resp.text[:200]}")
        payload = resp.json() if resp.content else {}
        if isinstance(payload, dict):
            items = payload.get('items') or payload.get('routes') or []
            return items if isinstance(items, list) else []
        if isinstance(payload, list):
            return payload
        return []

    def _record_ingress_rebind_event(self, event: Dict[str, Any]):
        timestamp = datetime.now().isoformat()
        payload = {
            **(event or {}),
            'timestamp': timestamp,
        }
        with self.ingress_rebind_lock:
            self.ingress_rebind_events.append(payload)
            if len(self.ingress_rebind_events) > 200:
                self.ingress_rebind_events = self.ingress_rebind_events[-200:]

    def _get_recent_ingress_rebind_events(self, project_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        with self.ingress_rebind_lock:
            events = [item for item in self.ingress_rebind_events if str(item.get('project_id') or '') == str(project_id or '')]
            return events[-max(1, int(limit)):]

    def _get_latest_ingress_rebind_by_agent(self, project_id: str) -> Dict[str, Dict[str, Any]]:
        latest: Dict[str, Dict[str, Any]] = {}
        for event in self._get_recent_ingress_rebind_events(project_id=project_id, limit=200):
            agent_key = str(event.get('agent_key') or '').strip()
            if not agent_key:
                continue
            latest[agent_key] = event
        return latest

    def _rebind_agent_ingress_external_ip(
        self,
        project_id: str,
        agent_key: str,
        new_ip: str,
        auth_header: Optional[str] = None
    ) -> Dict[str, Any]:
        new_ip = str(new_ip or '').strip()
        agent_key = str(agent_key or '').strip()
        if not project_id or not agent_key or not new_ip:
            return {
                'project_id': project_id,
                'agent_key': agent_key,
                'new_ip': new_ip,
                'target_count': 0,
                'success_count': 0,
                'fail_count': 0,
                'details': [],
                'skipped': True,
                'reason': 'project_id/agent_key/new_ip is required',
            }

        routes = self._list_project_ingress_routes(
            project_id=project_id,
            include_deleted=False,
            auth_header=auth_header,
        )
        target_routes = []
        for route in routes:
            if str(route.get('agent_key') or '').strip() != agent_key:
                continue
            if str(route.get('status') or '').strip().lower() == 'deleted':
                continue
            if route.get('deleted_at'):
                continue
            target_routes.append(route)

        details: List[Dict[str, Any]] = []
        success_count = 0
        for route in target_routes:
            route_id = str(route.get('route_id') or '').strip()
            route_metadata = self._extract_route_metadata(route)
            payload = {
                'agent_key': agent_key,
                'external_ips': [new_ip],
                'target_port': int(route.get('target_port') or 0),
                'host': route.get('host'),
                'path': route.get('path') or '/',
                'path_type': route.get('path_type') or 'Prefix',
                'ingress_type': route.get('ingress_type'),
                'service_port': int(route.get('service_port') or route.get('target_port') or 0),
                'tls_enabled': route.get('tls_enabled'),
                'tls_secret_name': route.get('tls_secret_name'),
                'backend_protocol': route.get('backend_protocol') or route_metadata.get('backend_protocol'),
                'websocket_enabled': route.get('websocket_enabled', True),
                'owner_service': route.get('owner_service') or 'platform-agent',
                'created_by': route.get('created_by'),
                'metadata': route_metadata,
                'force_recreate': True,
            }
            try:
                resp = self._call_k8s_service(
                    method='POST',
                    path='/api/k8s/agent-ingress-routes',
                    project_id=project_id,
                    payload=payload,
                    headers={'Authorization': auth_header} if auth_header else None
                )
                if resp.status_code < 300:
                    success_count += 1
                    details.append({
                        'route_id': route_id,
                        'host': route.get('host'),
                        'path': route.get('path'),
                        'target_port': route.get('target_port'),
                        'status': 'ok',
                    })
                else:
                    details.append({
                        'route_id': route_id,
                        'host': route.get('host'),
                        'path': route.get('path'),
                        'target_port': route.get('target_port'),
                        'status': 'failed',
                        'status_code': resp.status_code,
                        'error': (resp.text or '')[:200],
                    })
            except Exception as inner:
                details.append({
                    'route_id': route_id,
                    'host': route.get('host'),
                    'path': route.get('path'),
                    'target_port': route.get('target_port'),
                    'status': 'failed',
                    'error': str(inner),
                })

        summary = {
            'project_id': project_id,
            'agent_key': agent_key,
            'new_ip': new_ip,
            'target_count': len(target_routes),
            'success_count': success_count,
            'fail_count': max(0, len(target_routes) - success_count),
            'details': details,
        }
        self._record_ingress_rebind_event(summary)
        return summary

    def _extract_route_metadata(self, route: Dict[str, Any]) -> Dict[str, Any]:
        metadata = route.get('metadata') or {}
        if isinstance(metadata, dict):
            return metadata
        if isinstance(metadata, str):
            try:
                parsed = json.loads(metadata)
                return parsed if isinstance(parsed, dict) else {}
            except Exception:
                return {}
        return {}

    def _is_agent_console_ingress_route(self, route: Dict[str, Any]) -> bool:
        metadata = self._extract_route_metadata(route)
        scope = str(metadata.get('ingress_scope') or '').strip().lower()
        if scope == 'agent_console':
            return True
        if scope == 'service_binding':
            return False

        source = str(metadata.get('source') or '').strip().lower()
        if source in ('agent-detail', 'agent-cluster', 'agent-mgmt', 'agent'):
            return True
        if source in ('service-mgmt', 'service-management', 'service'):
            return False

        target_port = int(route.get('target_port') or 0)
        if target_port in (11197, 11198):
            return True

        owner_service = str(route.get('owner_service') or '').strip().lower()
        if owner_service == 'platform-agent' and not self._is_service_bound_ingress_route(route):
            return True
        return False

    def _is_service_bound_ingress_route(self, route: Dict[str, Any]) -> bool:
        metadata = self._extract_route_metadata(route)
        scope = str(metadata.get('ingress_scope') or '').strip().lower()
        if scope == 'service_binding':
            return True
        if scope == 'agent_console':
            return False

        source = str(metadata.get('source') or '').strip().lower()
        if source in ('service-mgmt', 'service-management', 'service'):
            return True
        if source in ('agent-detail', 'agent-cluster', 'agent-mgmt', 'agent'):
            return False

        service_name = str(
            metadata.get('service_name')
            or metadata.get('associated_service_name')
            or metadata.get('bind_service_name')
            or ''
        ).strip()
        if service_name:
            return True
        return False

    def _find_agent_console_ingress_route(
        self,
        project_id: str,
        agent_key: str,
        target_port: int,
        auth_header: Optional[str] = None,
        include_deleted: bool = False
    ) -> Optional[Dict[str, Any]]:
        all_routes = self._list_project_ingress_routes(
            project_id=project_id,
            include_deleted=include_deleted,
            auth_header=auth_header
        )
        for route in all_routes:
            if str(route.get('agent_key') or '').strip() != agent_key:
                continue
            if int(route.get('target_port') or 0) != int(target_port):
                continue
            if not self._is_agent_console_ingress_route(route):
                continue
            if not include_deleted and str(route.get('status') or '').lower() == 'deleted':
                continue
            return route
        return None

    def _ensure_agent_console_ingress_route(
        self,
        project_id: str,
        agent: Any,
        target_port: int,
        auth_header: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        agent_key = str(getattr(agent, 'key', '') or '').strip()
        if not agent_key or not project_id:
            return None

        existing = self._find_agent_console_ingress_route(
            project_id=project_id,
            agent_key=agent_key,
            target_port=target_port,
            auth_header=auth_header,
            include_deleted=False
        )
        if existing and str(existing.get('status') or '').lower() == 'ready':
            return existing

        payload = {
            'agent_key': agent_key,
            'external_ips': [agent.ip_address],
            'target_port': int(target_port),
            'host_prefix': _build_random_host_prefix(f"{agent_key}-{int(target_port)}"),
            'path': '/',
            'path_type': 'Prefix',
            'service_port': int(target_port),
            'websocket_enabled': True,
            'owner_service': 'platform-agent',
            'metadata': {
                'agent_hostname': getattr(agent, 'hostname', ''),
                'source': 'agent-detail',
                'ingress_scope': 'agent_console',
                'source_api': '/api/agent/agent/<agent_key>/services/<service_name>/exec/ws-connection',
            }
        }
        resp = self._call_k8s_service(
            method='POST',
            path='/api/k8s/agent-ingress-routes',
            project_id=project_id,
            payload=payload,
            headers={'Authorization': auth_header} if auth_header else None
        )
        if resp.status_code >= 300:
            raise RuntimeError(f"create ingress route failed: {resp.status_code}, body={resp.text[:300]}")
        created = resp.json() if resp.content else {}
        if isinstance(created, dict) and created.get('route_id'):
            return created
        return self._find_agent_console_ingress_route(
            project_id=project_id,
            agent_key=agent_key,
            target_port=target_port,
            auth_header=auth_header,
            include_deleted=False
        )

    def _get_project_active_service_keys(self, project_id: str) -> set:
        """获取项目内当前有效服务键集合：{agent_key::service_name}。"""
        table_name = self.db_manager.get_table_name('agent_services')
        where_sql = "project_id = %s AND is_stale = 0" if self.db_manager.db_type == 'mysql' else "project_id = ? AND is_stale = 0"
        rows = self.db_manager.fetch_all(
            f"SELECT agent_key, service_name FROM {table_name} WHERE {where_sql}",
            (project_id,)
        ) or []
        keys = set()
        for row in rows:
            ak = str(row.get('agent_key') or '').strip()
            sn = str(row.get('service_name') or '').strip()
            if ak and sn:
                keys.add(f"{ak}::{sn}")
        return keys

    def _extract_service_binding_name(self, route: Dict[str, Any]) -> str:
        metadata = self._extract_route_metadata(route)
        return str(
            metadata.get('service_name')
            or metadata.get('associated_service_name')
            or metadata.get('bind_service_name')
            or route.get('associated_service_name')
            or ''
        ).strip()

    def _extract_service_runtime_state(self, payload: Any) -> str:
        if not isinstance(payload, dict):
            return ''

        candidates = [
            payload.get('status'),
            payload.get('state'),
            payload.get('service_status'),
            payload.get('effective_state'),
        ]
        real_status = payload.get('real_status')
        if isinstance(real_status, dict):
            candidates.extend([
                real_status.get('status'),
                real_status.get('state'),
            ])

        for value in candidates:
            text = str(value or '').strip().lower()
            if text:
                return text
        return ''

    def _parse_ports_json(self, raw_ports: Any) -> Dict[str, str]:
        if isinstance(raw_ports, dict):
            return {str(k): str(v) for k, v in raw_ports.items()}
        if isinstance(raw_ports, str):
            try:
                parsed = json.loads(raw_ports)
                if isinstance(parsed, dict):
                    return {str(k): str(v) for k, v in parsed.items()}
            except Exception:
                return {}
        return {}

    def _parse_images_json(self, raw_images: Any) -> List[str]:
        if isinstance(raw_images, list):
            return [str(item).strip() for item in raw_images if str(item).strip()]
        if isinstance(raw_images, str):
            text = raw_images.strip()
            if not text:
                return []
            try:
                parsed = json.loads(text)
                if isinstance(parsed, list):
                    return [str(item).strip() for item in parsed if str(item).strip()]
            except Exception:
                return [text]
        return []

    def _extract_service_images(self, service: Dict[str, Any]) -> List[str]:
        images: List[str] = []
        seen: Set[str] = set()

        def _append(value: Any):
            text = str(value or '').strip()
            if not text or text in seen:
                return
            seen.add(text)
            images.append(text)

        if isinstance(service.get('images'), list):
            for item in service.get('images') or []:
                _append(item)

        real_status = service.get('real_status')
        if isinstance(real_status, dict):
            containers = real_status.get('containers')
            if isinstance(containers, list):
                for container in containers:
                    if isinstance(container, dict):
                        _append(container.get('Image') or container.get('image'))

        _append(service.get('image'))
        return images

    def _has_ai_helper_tag(self, tags: Any) -> bool:
        return 'AI_AGENT_HELPER' in self._normalize_service_tags(tags)

    def _has_process_monitor_tag(self, tags: Any) -> bool:
        return 'PROCESS_MONITOR' in self._normalize_service_tags(tags)

    def _load_configcenter_payload(self, response: requests.Response) -> Dict[str, Any]:
        try:
            payload = response.json() if response.content else {}
        except Exception:
            payload = {'raw': response.text}
        if response.status_code >= 300:
            message = payload.get('detail') or payload.get('error') or payload.get('message') or payload.get('raw') or response.text
            raise ValueError(f'ConfigCenter请求失败: {response.status_code} {message}')
        return payload if isinstance(payload, dict) else {}

    def _list_service_llm_providers(self) -> Dict[str, Any]:
        response = self._call_configcenter_service('GET', '/api/configcenter/service/llm/providers')
        return self._load_configcenter_payload(response)

    def _get_service_llm_provider(self, provider_key: str) -> Dict[str, Any]:
        response = self._call_configcenter_service(
            'GET',
            f"/api/configcenter/service/llm/providers/{quote(provider_key, safe='')}",
        )
        return self._load_configcenter_payload(response)

    def _stringify_env_value(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, bool):
            return 'true' if value else 'false'
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, str):
            return value
        try:
            return json.dumps(value, ensure_ascii=False)
        except Exception:
            return str(value)

    def _build_llm_provider_snapshot(self, provider: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'provider_key': provider.get('provider_key'),
            'display_name': provider.get('display_name'),
            'provider_type': provider.get('provider_type'),
            'model': provider.get('model'),
            'api_base': provider.get('api_base'),
            'updated_at': provider.get('updated_at'),
            'description': provider.get('description'),
        }

    def _build_llm_provider_files(self, provider: Dict[str, Any]) -> List[Dict[str, Any]]:
        provider_key = str(provider.get('provider_key') or '').strip()
        raw_items = provider.get('file_bindings') if isinstance(provider.get('file_bindings'), list) else []
        files: List[Dict[str, Any]] = []
        for index, item in enumerate(raw_items):
            if not isinstance(item, dict):
                continue
            enabled = bool(item.get('enabled', True))
            if not enabled:
                continue
            path = str(item.get('path') or '').strip()
            content = item.get('content')
            if not path or not isinstance(content, str):
                continue
            name = str(item.get('name') or '').strip() or f"{provider_key or 'provider'}-file-{index + 1}"
            fmt = str(item.get('format') or 'other').strip().lower() or 'other'
            files.append({
                'name': name,
                'path': path,
                'content': content,
                'format': fmt,
                'enabled': True,
                'provider_key': provider_key,
            })
        return files

    def _build_llm_provider_env(
        self,
        provider: Dict[str, Any],
        backend_type: str,
    ) -> Dict[str, str]:
        env: Dict[str, str] = {}

        def put(key: str, value: Any):
            text = self._stringify_env_value(value)
            if text is not None and str(key or '').strip():
                env[str(key).strip()] = text

        env_bindings = provider.get('env_bindings') if isinstance(provider.get('env_bindings'), dict) else {}
        for key, value in env_bindings.items():
            put(str(key), value)

        return env

    def _normalize_llm_file_bindings(self, files: Any) -> List[Dict[str, Any]]:
        if not isinstance(files, list):
            return []
        normalized: List[Dict[str, Any]] = []
        for idx, item in enumerate(files):
            if not isinstance(item, dict):
                continue
            path = str(item.get('path') or '').strip()
            content = item.get('content')
            if not path or not isinstance(content, str):
                continue
            normalized.append({
                'name': str(item.get('name') or '').strip() or f'file-{idx + 1}',
                'path': path,
                'content': content,
                'format': str(item.get('format') or 'other').strip().lower() or 'other',
                'enabled': bool(item.get('enabled', True)),
                'provider_key': str(item.get('provider_key') or '').strip() or None,
            })
        return normalized

    def _configure_llm_for_ai_agent(
        self,
        project_id: str,
        agent_key: str,
        service_name: str,
        agent_id: str,
        provider_keys: List[str],
        env_overrides: Dict[str, Any],
        file_overrides: List[Dict[str, Any]],
        merge_strategy: str = 'overwrite',
    ) -> Dict[str, Any]:
        self._get_ai_helper_agent_detail(project_id, agent_key, service_name, agent_id)
        merged_binding = self._merge_llm_provider_binding(provider_keys, '*', source='ai_agent_batch')
        payload = {
            'provider_keys': merged_binding.get('provider_keys', []),
            'provider_snapshots': merged_binding.get('provider_snapshots', []),
            'resolved_env': merged_binding.get('merged_env', {}),
            'resolved_files': self._normalize_llm_file_bindings(merged_binding.get('merged_files', [])),
            'env_overrides': env_overrides if isinstance(env_overrides, dict) else {},
            'file_overrides': self._normalize_llm_file_bindings(file_overrides),
            'merge_strategy': merge_strategy if merge_strategy in ('overwrite', 'merge') else 'overwrite',
        }
        data, status_code = self._call_ai_helper_api(
            project_id,
            agent_key,
            service_name,
            'PUT',
            f"/api/ai-agents/{quote(agent_id, safe='')}/llm-config",
            payload,
            timeout=(5, 30),
        )
        if status_code >= 300 or not isinstance(data, dict):
            raise ValueError(f'AI Agent配置下发失败: {data}')
        return {
            'project_id': project_id,
            'agent_key': agent_key,
            'service_name': service_name,
            'agent_id': agent_id,
            'provider_keys': merged_binding.get('provider_keys', []),
            'merge_strategy': payload.get('merge_strategy'),
            'env_overrides': payload.get('env_overrides', {}),
            'file_overrides': payload.get('file_overrides', []),
            'updated_config': data,
        }

    def _merge_llm_provider_binding(
        self,
        provider_keys: List[str],
        target_services: Any = '*',
        source: str = 'deployment_override',
    ) -> Dict[str, Any]:
        normalized_provider_keys: List[str] = []
        seen = set()
        provider_snapshots: List[Dict[str, Any]] = []
        merged_env: Dict[str, str] = {}
        merged_files_by_path: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()

        for item in provider_keys or []:
            provider_key = str(item or '').strip()
            if not provider_key or provider_key in seen:
                continue
            seen.add(provider_key)
            provider = self._get_service_llm_provider(provider_key)
            normalized_provider_keys.append(provider_key)
            provider_files = self._build_llm_provider_files(provider)
            snapshot = self._build_llm_provider_snapshot(provider)
            snapshot['file_binding_count'] = len(provider_files)
            provider_snapshots.append(snapshot)
            merged_env.update(self._build_llm_provider_env(provider, ''))
            for file_item in provider_files:
                file_path = str(file_item.get('path') or '').strip()
                if not file_path:
                    continue
                if file_path in merged_files_by_path:
                    del merged_files_by_path[file_path]
                merged_files_by_path[file_path] = file_item

        if target_services == '*' or target_services is None:
            normalized_targets: Union[str, List[str]] = '*'
        else:
            target_seen = set()
            normalized_targets = []
            for item in target_services or []:
                text = str(item or '').strip()
                if not text or text in target_seen:
                    continue
                target_seen.add(text)
                normalized_targets.append(text)

        merged_files = list(merged_files_by_path.values())
        return {
            'provider_keys': normalized_provider_keys,
            'target_services': normalized_targets,
            'source': source,
            'provider_snapshots': provider_snapshots,
            'merged_env': merged_env,
            'mapped_env_keys': sorted(merged_env.keys()),
            'merged_files': merged_files,
            'mapped_file_paths': sorted([str(item.get('path') or '').strip() for item in merged_files if str(item.get('path') or '').strip()]),
            'updated_at': datetime.utcnow().isoformat(),
        }

    def _extract_template_service_names(self, template: Dict[str, Any]) -> List[str]:
        metadata = template.get('metadata') or {}
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except Exception:
                metadata = {}
        parsed_compose = metadata.get('parsed_compose') if isinstance(metadata, dict) else None
        services = parsed_compose.get('services') if isinstance(parsed_compose, dict) else None
        if isinstance(services, dict) and services:
            return [str(name) for name in services.keys()]
        return []

    def _normalize_template_llm_binding(
        self,
        raw_binding: Any,
        allowed_services: Optional[List[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        if not isinstance(raw_binding, dict):
            return None
        provider_keys_raw = raw_binding.get('provider_keys')
        if not isinstance(provider_keys_raw, list):
            provider_keys_raw = []
        provider_keys: List[str] = []
        seen = set()
        for item in provider_keys_raw:
            text = str(item or '').strip()
            if not text or text in seen:
                continue
            seen.add(text)
            provider_keys.append(text)
        if not provider_keys:
            return None

        target_services_raw = raw_binding.get('target_services', '*')
        if target_services_raw == '*' or target_services_raw is None:
            target_services: Union[str, List[str]] = '*'
        elif isinstance(target_services_raw, list):
            target_seen = set()
            target_services = []
            for item in target_services_raw:
                text = str(item or '').strip()
                if not text or text in target_seen:
                    continue
                target_seen.add(text)
                target_services.append(text)
        else:
            target_services = '*'

        if allowed_services is not None and target_services != '*':
            missing = [name for name in target_services if name not in allowed_services]
            if missing:
                raise ValueError(f"目标服务不存在: {', '.join(missing)}")

        return {
            'provider_keys': provider_keys,
            'target_services': target_services,
            'updated_at': datetime.utcnow().isoformat(),
        }

    def _prepare_deploy_extra_params(
        self,
        project_id: str,
        template_name: str,
        extra_params: Any,
    ) -> Dict[str, Any]:
        prepared = dict(extra_params or {}) if isinstance(extra_params, dict) else {}
        template = self.template_manager.get_template(template_name)
        if not template:
            return prepared

        override_binding = self._normalize_template_llm_binding(
            prepared.get('llm_provider_binding'),
            allowed_services=self._extract_template_service_names(template),
        )
        if override_binding:
            prepared['llm_provider_binding'] = {
                'provider_keys': override_binding.get('provider_keys', []),
                'target_services': override_binding.get('target_services', '*'),
                'source': 'deployment_override',
            }
            prepared['resolved_llm_provider_binding'] = self._merge_llm_provider_binding(
                override_binding.get('provider_keys', []),
                override_binding.get('target_services', '*'),
                source='deployment_override',
            )
        return prepared

    def _get_ai_helper_agent_detail(
        self,
        project_id: str,
        agent_key: str,
        service_name: str,
        agent_id: str,
    ) -> Dict[str, Any]:
        data, status_code = self._call_ai_helper_api(
            project_id,
            agent_key,
            service_name,
            'GET',
            f"/api/ai-agents/{quote(agent_id, safe='')}",
            None,
            timeout=(5, 30),
        )
        if status_code >= 300 or not isinstance(data, dict):
            raise ValueError(f'AI Agent读取失败: {data}')
        return data

    def _apply_llm_provider_to_ai_agent(
        self,
        project_id: str,
        agent_key: str,
        service_name: str,
        agent_id: str,
        provider_key: str,
        refresh: bool = False,
    ) -> Dict[str, Any]:
        current_agent = self._get_ai_helper_agent_detail(project_id, agent_key, service_name, agent_id)
        provider_key = str(provider_key or current_agent.get('llm_provider_key') or '').strip()
        if not provider_key:
            raise ValueError('provider_key is required')

        provider = self._get_service_llm_provider(provider_key)
        backend_type = str(current_agent.get('backend_type') or '').strip()
        mapped_env = self._build_llm_provider_env(provider, backend_type)
        previous_env = current_agent.get('env') if isinstance(current_agent.get('env'), dict) else {}
        previous_mapped_keys = [str(item) for item in (current_agent.get('llm_provider_mapped_env_keys') or []) if str(item).strip()]

        merged_env = {
            str(key): self._stringify_env_value(value) or ''
            for key, value in previous_env.items()
            if str(key) not in previous_mapped_keys
        }
        merged_env.update(mapped_env)

        update_result = self._configure_llm_for_ai_agent(
            project_id=project_id,
            agent_key=agent_key,
            service_name=service_name,
            agent_id=agent_id,
            provider_keys=[provider_key],
            env_overrides=merged_env,
            file_overrides=[],
            merge_strategy='overwrite',
        )
        return {
            'project_id': project_id,
            'agent_key': agent_key,
            'service_name': service_name,
            'agent_id': agent_id,
            'provider_key': provider_key,
            'refresh': bool(refresh),
            'mapped_env_preview': mapped_env,
            'mapped_env_keys': sorted(mapped_env.keys()),
            'updated_agent': update_result.get('updated_config', {}),
            'updated_config': update_result.get('updated_config', {}),
        }

    def _resolve_helper_rest_port(self, service_row: Dict[str, Any]) -> int:
        # Helper REST端口固定，不再从 ports_json 推断，避免误判 unhealthy。
        try:
            return int(self.config.get('helper_rest_port', 20001))
        except Exception:
            return 20001

    def _resolve_process_monitor_rest_port(self, service_row: Dict[str, Any]) -> int:
        try:
            return int(self.config.get('helper_process_monitor_port', 20004))
        except Exception:
            return 20004

    def _process_monitor_host_root(self) -> str:
        text = str(self.config.get('process_monitor_host_root', '/host') or '/host').strip()
        if not text.startswith('/'):
            text = '/' + text.lstrip('/')
        return text.rstrip('/') or '/host'

    def _process_monitor_sync_subproject_id(self) -> str:
        text = str(self.config.get('process_monitor_default_subproject_id', '__file__sync__') or '__file__sync__').strip()
        if not text:
            return '__file__sync__'
        if '/' in text or '\\' in text:
            # Keep fileserver path safe even if config is malformed.
            return '__file__sync__'
        return text

    def _normalize_process_monitor_public_path(self, value: Any) -> Any:
        text = str(value or '')
        if not text:
            return value
        suffix = ''
        if text.endswith(' (deleted)'):
            suffix = ' (deleted)'
            text = text[:-10]
        if not text.startswith('/'):
            return value
        normalized = os.path.normpath(text)
        host_root = self._process_monitor_host_root()
        if normalized == host_root:
            normalized = '/'
        elif normalized.startswith(host_root + '/'):
            rel = normalized[len(host_root) + 1:].lstrip('/')
            normalized = '/' + rel if rel else '/'
        if not normalized.startswith('/'):
            normalized = '/' + normalized.lstrip('/')
        return f'{normalized}{suffix}'

    def _canonicalize_process_monitor_input_path(self, value: Any) -> str:
        text = str(value or '').strip()
        if not text.startswith('/'):
            raise ValueError(f'path_must_be_absolute: {value}')
        normalized = self._normalize_process_monitor_public_path(text)
        if not str(normalized).startswith('/'):
            raise ValueError(f'path_must_be_absolute: {value}')
        return str(normalized)

    def _normalize_process_monitor_payload_paths(self, node: Any, key_name: str = '') -> Any:
        if isinstance(node, dict):
            return {key: self._normalize_process_monitor_payload_paths(value, str(key)) for key, value in node.items()}
        if isinstance(node, list):
            if key_name == 'paths':
                normalized_paths: List[Any] = []
                for item in node:
                    if isinstance(item, str) and item.startswith('/'):
                        normalized_paths.append(self._normalize_process_monitor_public_path(item))
                    else:
                        normalized_paths.append(item)
                return normalized_paths
            return [self._normalize_process_monitor_payload_paths(item, key_name) for item in node]
        if isinstance(node, str) and key_name in {
            'path', 'source_path', 'relative_path', 'host_path', 'procfs_root', 'cwd', 'exe', 'target', 'symlink_target'
        }:
            return self._normalize_process_monitor_public_path(node)
        return node

    def _get_ai_helper_service_row(self, project_id: str, agent_key: str, service_name: str) -> Optional[Dict[str, Any]]:
        table_name = self.db_manager.get_table_name('agent_services')
        row = self.db_manager.fetch_one(
            f"""
            SELECT service_uid, project_id, agent_key, agent_hostname, agent_ip,
                   service_name, image, status, tags_json, ports_json, raw_json, source, is_stale,
                   first_seen_at, last_seen_at, updated_at
            FROM {table_name}
            WHERE project_id = %s AND agent_key = %s AND service_name = %s
            LIMIT 1
            """ if self.db_manager.db_type == 'mysql' else
            f"""
            SELECT service_uid, project_id, agent_key, agent_hostname, agent_ip,
                   service_name, image, status, tags_json, ports_json, raw_json, source, is_stale,
                   first_seen_at, last_seen_at, updated_at
            FROM {table_name}
            WHERE project_id = ? AND agent_key = ? AND service_name = ?
            LIMIT 1
            """,
            (project_id, agent_key, service_name)
        )
        if not row:
            return None
        if not self._has_ai_helper_tag(row.get('tags_json')):
            return None
        return row

    def _get_process_monitor_service_row(
        self,
        project_id: str,
        agent_key: str,
        service_name: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        table_name = self.db_manager.get_table_name('agent_services')
        params: List[Any] = [project_id, agent_key]
        where_clause = "project_id = %s AND agent_key = %s" if self.db_manager.db_type == 'mysql' else "project_id = ? AND agent_key = ?"
        if service_name:
            where_clause += " AND service_name = %s" if self.db_manager.db_type == 'mysql' else " AND service_name = ?"
            params.append(service_name)
        rows = self.db_manager.fetch_all(
            f"""
            SELECT service_uid, project_id, agent_key, agent_hostname, agent_ip,
                   service_name, image, status, tags_json, ports_json, raw_json, source, is_stale,
                   first_seen_at, last_seen_at, updated_at
            FROM {table_name}
            WHERE {where_clause}
            ORDER BY last_seen_at DESC
            """,
            tuple(params)
        ) or []

        if not rows:
            return None

        # 首选服务自身 tags_json（兼容旧数据），再回退到模板 tags（与 /api/agent/services/global 逻辑一致）
        for row in rows:
            if self._has_process_monitor_tag(row.get('tags_json')):
                return row

        # 回退：根据模板绑定判断 PROCESS_MONITOR 能力
        service_names = [str((row or {}).get('service_name') or '').strip() for row in rows]
        service_names = [name for name in service_names if name]
        if not service_names:
            return None

        placeholders = ','.join(['%s'] * len(service_names)) if self.db_manager.db_type == 'mysql' else ','.join(['?'] * len(service_names))
        binding_table = self.db_manager.get_table_name('service_template_bindings')
        template_table = self.db_manager.get_table_name('service_templates')
        binding_rows = self.db_manager.fetch_all(
            f"""
            SELECT service_name, template_id, template_name
            FROM {binding_table}
            WHERE project_id = {'%s' if self.db_manager.db_type == 'mysql' else '?'}
              AND agent_key = {'%s' if self.db_manager.db_type == 'mysql' else '?'}
              AND service_name IN ({placeholders})
            """,
            tuple([project_id, agent_key] + service_names),
        ) or []

        template_rows = self.db_manager.fetch_all(
            f"SELECT id, name, metadata FROM {template_table}",
            tuple(),
        ) or []
        tags_by_template_id: Dict[str, List[str]] = {}
        tags_by_template_name: Dict[str, List[str]] = {}
        for tpl in template_rows:
            metadata = tpl.get('metadata')
            if isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except Exception:
                    metadata = {}
            elif not isinstance(metadata, dict):
                metadata = {}
            template_tags = self._normalize_service_tags((metadata or {}).get('tags'))
            tpl_id = str(tpl.get('id') or '').strip()
            tpl_name = str(tpl.get('name') or '').strip()
            if tpl_id:
                tags_by_template_id[tpl_id] = template_tags
            if tpl_name:
                tags_by_template_name[tpl_name] = template_tags

        tags_by_service_name: Dict[str, List[str]] = {}
        for binding in binding_rows:
            bound_service_name = str(binding.get('service_name') or '').strip()
            if not bound_service_name:
                continue
            template_id = str(binding.get('template_id') or '').strip()
            template_name = str(binding.get('template_name') or '').strip()
            template_tags = tags_by_template_id.get(template_id) or tags_by_template_name.get(template_name) or []
            tags_by_service_name[bound_service_name] = template_tags

        for row in rows:
            candidate_service_name = str((row or {}).get('service_name') or '').strip()
            if self._has_process_monitor_tag(tags_by_service_name.get(candidate_service_name) or []):
                return row
        return None

    def _call_ai_helper_api(
        self,
        project_id: str,
        agent_key: str,
        service_name: str,
        method: str,
        endpoint: str,
        payload: Optional[Dict[str, Any]] = None,
        timeout: Tuple[int, int] = (10, 300),
    ) -> Tuple[Dict[str, Any], int]:
        row = self._get_ai_helper_service_row(project_id, agent_key, service_name)
        if not row:
            raise ValueError(f'AI helper service not found: {agent_key}/{service_name}')

        agent_ip = str(row.get('agent_ip') or '').strip()
        if not agent_ip:
            raise ValueError(f'AI helper service has no agent IP: {agent_key}/{service_name}')

        rest_port = self._resolve_helper_rest_port(row)
        target = f"http://{agent_ip}:{rest_port}{endpoint}"
        self.logger.debug(
            f"call_ai_helper_api target={target} project={project_id} agent={agent_key} service={service_name}"
        )
        response = requests.request(method.upper(), target, json=payload, timeout=timeout)
        try:
            data = response.json() if response.content else {}
        except Exception:
            data = {'raw': response.text}
        return data, response.status_code

    def _call_process_monitor_api(
        self,
        project_id: str,
        agent_key: str,
        service_name: Optional[str],
        method: str,
        endpoint: str,
        payload: Optional[Dict[str, Any]] = None,
        timeout: Tuple[int, int] = (10, 300),
    ) -> Tuple[Dict[str, Any], int, Dict[str, Any]]:
        row = self._get_process_monitor_service_row(project_id, agent_key, service_name)
        if not row:
            raise ValueError(f'process_monitor service not found: {agent_key}/{service_name or "*"}')
        agent_ip = str(row.get('agent_ip') or '').strip()
        if not agent_ip:
            raise ValueError(f'process_monitor service has no agent IP: {agent_key}/{service_name or "*"}')
        rest_port = self._resolve_process_monitor_rest_port(row)
        target = f"http://{agent_ip}:{rest_port}{endpoint}"
        self.logger.debug(
            f"call_process_monitor_api target={target} project={project_id} agent={agent_key} service={row.get('service_name')}"
        )
        response = requests.request(method.upper(), target, json=payload, timeout=timeout)
        try:
            data = response.json() if response.content else {}
        except Exception:
            data = {'raw': response.text}
        return data if isinstance(data, dict) else {'raw': data}, response.status_code, row

    def _record_process_sync_log(
        self,
        project_id: str,
        agent_key: str,
        service_name: str,
        mode: str,
        status: str,
        request_payload: Dict[str, Any],
        node_task_payload: Dict[str, Any],
        message: str = '',
        sync_id: Optional[str] = None,
    ) -> str:
        sync_log_id = str(sync_id or uuid.uuid4().hex)
        table_name = self.db_manager.get_table_name('process_sync_logs')
        request_json = json.dumps(request_payload or {}, ensure_ascii=False)
        node_json = json.dumps(node_task_payload or {}, ensure_ascii=False)
        node_task_id = str((node_task_payload or {}).get('task_id') or '')
        if self.db_manager.db_type == 'mysql':
            self.db_manager.execute_query(
                f"""
                INSERT INTO {table_name}
                (sync_id, project_id, agent_key, service_name, node_task_id, mode, status, request_json, node_snapshot_json, message)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                  node_task_id=VALUES(node_task_id),
                  mode=VALUES(mode),
                  status=VALUES(status),
                  request_json=VALUES(request_json),
                  node_snapshot_json=VALUES(node_snapshot_json),
                  message=VALUES(message),
                  updated_at=NOW()
                """,
                (sync_log_id, project_id, agent_key, service_name, node_task_id, mode, status, request_json, node_json, message)
            )
        else:
            now_ts = datetime.now().isoformat()
            self.db_manager.execute_query(
                f"""
                INSERT INTO {table_name}
                (sync_id, project_id, agent_key, service_name, node_task_id, mode, status, request_json, node_snapshot_json, message, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(sync_id) DO UPDATE SET
                  node_task_id=excluded.node_task_id,
                  mode=excluded.mode,
                  status=excluded.status,
                  request_json=excluded.request_json,
                  node_snapshot_json=excluded.node_snapshot_json,
                  message=excluded.message,
                  updated_at=excluded.updated_at
                """,
                (sync_log_id, project_id, agent_key, service_name, node_task_id, mode, status, request_json, node_json, message, now_ts, now_ts)
            )
        return sync_log_id

    def _list_process_monitor_services(self, project_id: str, include_stale: bool = False) -> List[Dict[str, Any]]:
        services_table = self.db_manager.get_table_name('agent_services')
        template_table = self.db_manager.get_table_name('service_templates')
        binding_table = self.db_manager.get_table_name('service_template_bindings')
        where_sql = "project_id = %s" if self.db_manager.db_type == 'mysql' else "project_id = ?"
        params: List[Any] = [project_id]
        if not include_stale:
            where_sql += " AND is_stale = 0"
        rows = self.db_manager.fetch_all(
            f"""
            SELECT service_uid, project_id, agent_key, agent_hostname, agent_ip,
                   service_name, image, status, tags_json, ports_json, raw_json, source, is_stale,
                   first_seen_at, last_seen_at, updated_at
            FROM {services_table}
            WHERE {where_sql}
            ORDER BY last_seen_at DESC
            """,
            tuple(params)
        ) or []

        template_rows = self.db_manager.fetch_all(
            f"SELECT id, name, metadata FROM {template_table} ORDER BY id ASC",
            tuple()
        ) or []
        templates_by_name: Dict[str, Dict[str, Any]] = {}
        for tpl in template_rows:
            tpl_name = str(tpl.get('name') or '').strip()
            if not tpl_name:
                continue
            metadata = tpl.get('metadata')
            if isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except Exception:
                    metadata = {}
            elif not isinstance(metadata, dict):
                metadata = {}
            templates_by_name[tpl_name] = {
                'id': tpl.get('id'),
                'name': tpl_name,
                'template_tags': self._normalize_service_tags((metadata or {}).get('tags')),
            }

        binding_rows = self.db_manager.fetch_all(
            f"SELECT project_id, agent_key, service_name, template_id, template_name FROM {binding_table} WHERE project_id = %s"
            if self.db_manager.db_type == 'mysql' else
            f"SELECT project_id, agent_key, service_name, template_id, template_name FROM {binding_table} WHERE project_id = ?",
            (project_id,)
        ) or []
        bindings_map: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        for row in binding_rows:
            key = (
                str(row.get('project_id') or '').strip(),
                str(row.get('agent_key') or '').strip(),
                str(row.get('service_name') or '').strip(),
            )
            bindings_map[key] = {
                'template_id': row.get('template_id'),
                'template_name': str(row.get('template_name') or '').strip(),
            }

        items: List[Dict[str, Any]] = []
        for row in rows:
            key = (
                str(row.get('project_id') or '').strip(),
                str(row.get('agent_key') or '').strip(),
                str(row.get('service_name') or '').strip(),
            )
            binding = bindings_map.get(key) or {}
            template_name = str(binding.get('template_name') or '').strip()
            template_meta = templates_by_name.get(template_name) or {}
            template_tags = self._normalize_service_tags(template_meta.get('template_tags'))
            item = {
                'service_uid': row.get('service_uid'),
                'project_id': row.get('project_id'),
                'agent_key': row.get('agent_key'),
                'agent_hostname': row.get('agent_hostname'),
                'agent_ip': row.get('agent_ip'),
                'service_name': row.get('service_name'),
                'image': row.get('image') or '',
                'status': row.get('status') or 'unknown',
                'template_id': binding.get('template_id') or template_meta.get('id'),
                'template_name': template_name,
                'template_tags': template_tags,
                'tags': self._normalize_service_tags(row.get('tags_json')),
                'is_stale': bool(row.get('is_stale')),
                'last_seen_at': row.get('last_seen_at'),
                'updated_at': row.get('updated_at'),
            }
            if self._has_process_monitor_tag(template_tags):
                items.append(item)
        return items

    def _parse_ai_helper_health_payload(self, raw_payload: Any) -> Dict[str, Any]:
        if isinstance(raw_payload, dict):
            return raw_payload
        if isinstance(raw_payload, str):
            try:
                parsed = json.loads(raw_payload)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                return {}
        return {}

    def _get_ai_helper_health_snapshot(self, project_id: str, agent_key: str, service_name: str) -> Dict[str, Any]:
        table_name = self.db_manager.get_table_name('ai_helper_health_snapshots')
        row = self.db_manager.fetch_one(
            f"""
            SELECT project_id, agent_key, service_name, health_status, health_payload_json, last_error, checked_at, pod_id
            FROM {table_name}
            WHERE project_id = %s AND agent_key = %s AND service_name = %s
            LIMIT 1
            """ if self.db_manager.db_type == 'mysql' else
            f"""
            SELECT project_id, agent_key, service_name, health_status, health_payload_json, last_error, checked_at, pod_id
            FROM {table_name}
            WHERE project_id = ? AND agent_key = ? AND service_name = ?
            LIMIT 1
            """,
            (project_id, agent_key, service_name)
        )
        if not row:
            return {
                'health_status': 'unknown',
                'health_payload': {'status': 'unknown'},
                'last_error': '',
                'checked_at': None,
                'pod_id': None,
            }
        payload = self._parse_ai_helper_health_payload(row.get('health_payload_json'))
        last_error = str(row.get('last_error') or '').strip()
        if last_error:
            payload = dict(payload or {})
            payload['last_error'] = last_error
        return {
            'health_status': str(row.get('health_status') or 'unknown').strip().lower() or 'unknown',
            'health_payload': payload if isinstance(payload, dict) else {},
            'last_error': last_error,
            'checked_at': str(row.get('checked_at')) if row.get('checked_at') else None,
            'pod_id': row.get('pod_id'),
        }

    def _get_ai_helper_health_snapshot_map(self, project_id: str) -> Dict[Tuple[str, str], Dict[str, Any]]:
        table_name = self.db_manager.get_table_name('ai_helper_health_snapshots')
        rows = self.db_manager.fetch_all(
            f"""
            SELECT project_id, agent_key, service_name, health_status, health_payload_json, last_error, checked_at, pod_id
            FROM {table_name}
            WHERE project_id = %s
            """ if self.db_manager.db_type == 'mysql' else
            f"""
            SELECT project_id, agent_key, service_name, health_status, health_payload_json, last_error, checked_at, pod_id
            FROM {table_name}
            WHERE project_id = ?
            """,
            (project_id,)
        ) or []
        result: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for row in rows:
            key = (str(row.get('agent_key') or '').strip(), str(row.get('service_name') or '').strip())
            if not key[0] or not key[1]:
                continue
            payload = self._parse_ai_helper_health_payload(row.get('health_payload_json'))
            last_error = str(row.get('last_error') or '').strip()
            if last_error:
                payload = dict(payload or {})
                payload['last_error'] = last_error
            result[key] = {
                'health_status': str(row.get('health_status') or 'unknown').strip().lower() or 'unknown',
                'health_payload': payload if isinstance(payload, dict) else {},
                'last_error': last_error,
                'checked_at': str(row.get('checked_at')) if row.get('checked_at') else None,
                'pod_id': row.get('pod_id'),
            }
        return result

    def _upsert_ai_helper_health_snapshot(
        self,
        project_id: str,
        agent_key: str,
        service_name: str,
        health_status: str,
        health_payload: Dict[str, Any],
        last_error: str = '',
    ) -> None:
        table_name = self.db_manager.get_table_name('ai_helper_health_snapshots')
        status_text = str(health_status or 'unknown').strip().lower() or 'unknown'
        payload_json = json.dumps(health_payload or {}, ensure_ascii=False)
        if self.db_manager.db_type == 'mysql':
            self.db_manager.execute_query(
                f"""
                INSERT INTO {table_name}
                (project_id, agent_key, service_name, health_status, health_payload_json, last_error, checked_at, pod_id)
                VALUES (%s, %s, %s, %s, %s, %s, NOW(), %s)
                ON DUPLICATE KEY UPDATE
                  health_status = VALUES(health_status),
                  health_payload_json = VALUES(health_payload_json),
                  last_error = VALUES(last_error),
                  checked_at = NOW(),
                  pod_id = VALUES(pod_id),
                  updated_at = NOW()
                """,
                (project_id, agent_key, service_name, status_text, payload_json, str(last_error or ''), self.config.get('pod_id', ''))
            )
        else:
            now_ts = datetime.now().isoformat()
            self.db_manager.execute_query(
                f"""
                INSERT INTO {table_name}
                (project_id, agent_key, service_name, health_status, health_payload_json, last_error, checked_at, pod_id, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(project_id, agent_key, service_name) DO UPDATE SET
                  health_status=excluded.health_status,
                  health_payload_json=excluded.health_payload_json,
                  last_error=excluded.last_error,
                  checked_at=excluded.checked_at,
                  pod_id=excluded.pod_id,
                  updated_at=excluded.updated_at
                """,
                (
                    project_id, agent_key, service_name, status_text, payload_json, str(last_error or ''),
                    now_ts, self.config.get('pod_id', ''), now_ts
                )
            )

    def _refresh_ai_helper_health_snapshots(self) -> Dict[str, Any]:
        """周期刷新所有AI Helper健康快照（leader-only调用）。"""
        table_name = self.db_manager.get_table_name('agent_services')
        rows = self.db_manager.fetch_all(
            f"""
            SELECT project_id, agent_key, service_name, tags_json, is_stale
            FROM {table_name}
            WHERE is_stale = 0
            """ if self.db_manager.db_type == 'mysql' else
            f"""
            SELECT project_id, agent_key, service_name, tags_json, is_stale
            FROM {table_name}
            WHERE is_stale = 0
            """
        ) or []

        total = 0
        success = 0
        failed = 0
        for row in rows:
            project_id = str(row.get('project_id') or '').strip()
            agent_key = str(row.get('agent_key') or '').strip()
            service_name = str(row.get('service_name') or '').strip()
            if not project_id or not agent_key or not service_name:
                continue
            if not self._has_ai_helper_tag(row.get('tags_json')):
                continue
            total += 1
            try:
                payload, code = self._call_ai_helper_api(
                    project_id,
                    agent_key,
                    service_name,
                    'GET',
                    '/api/ai-agents/health',
                    None,
                    timeout=(5, 20),
                )
                status = 'healthy' if code < 300 else 'unhealthy'
                last_error = '' if code < 300 else f'upstream_status_{code}'
                self._upsert_ai_helper_health_snapshot(project_id, agent_key, service_name, status, payload, last_error)
                if code < 300:
                    success += 1
                else:
                    failed += 1
            except Exception as exc:
                failed += 1
                self._upsert_ai_helper_health_snapshot(
                    project_id,
                    agent_key,
                    service_name,
                    'unhealthy',
                    {'status': 'unreachable', 'error': str(exc)},
                    str(exc),
                )
        summary = {
            'total': total,
            'success': success,
            'failed': failed,
            'checked_at': datetime.now().isoformat(),
            'pod_id': self.config.get('pod_id'),
        }
        self.logger.info(f"AI helper健康快照刷新完成: total={total} success={success} failed={failed}")
        return summary

    def _serialize_ai_helper_item(self, row: Dict[str, Any], health_payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        tags = self._normalize_service_tags(row.get('tags_json'))
        health_payload = health_payload or {}
        summary = health_payload.get('summary') if isinstance(health_payload, dict) else {}
        agents = health_payload.get('agents') if isinstance(health_payload, dict) else []
        active_agent = None
        if isinstance(summary, dict):
            active_agent = summary.get('default_backend')
        if not active_agent and isinstance(health_payload, dict):
            active_agent = health_payload.get('default_agent_id')
        return {
            'id': row.get('service_uid'),
            'project_id': row.get('project_id'),
            'agent_key': row.get('agent_key'),
            'agent_hostname': row.get('agent_hostname'),
            'agent_ip': row.get('agent_ip'),
            'service_name': row.get('service_name'),
            'image': row.get('image') or '',
            'status': row.get('status') or 'unknown',
            'tags': tags,
            'active_agent_id': active_agent,
            'ai_agent_count': len(agents) if isinstance(agents, list) else 0,
            'health': health_payload,
            'last_seen_at': row.get('last_seen_at'),
            'updated_at': row.get('updated_at'),
        }

    def _create_ai_batch(self, project_id: str, created_by: str, payload: Dict[str, Any]) -> str:
        batch_id = uuid.uuid4().hex
        table_name = self.db_manager.get_table_name('ai_agent_session_batches')
        request_json = json.dumps(payload, ensure_ascii=False)
        now_ts = datetime.now().isoformat()
        self.db_manager.execute_query(
            f"INSERT INTO {table_name} (batch_id, project_id, created_by, status, request_json) VALUES (%s, %s, %s, 'running', %s)"
            if self.db_manager.db_type == 'mysql' else
            f"INSERT INTO {table_name} (batch_id, project_id, created_by, status, request_json, created_at, updated_at) VALUES (?, ?, ?, 'running', ?, ?, ?)",
            (batch_id, project_id, created_by, request_json)
            if self.db_manager.db_type == 'mysql' else
            (batch_id, project_id, created_by, request_json, now_ts, now_ts)
        )
        return batch_id

    def _upsert_ai_batch_item(
        self,
        batch_id: str,
        project_id: str,
        agent_key: str,
        service_name: str,
        helper_session_id: Optional[str],
        helper_agent_ids: List[str],
        status: str,
        last_error: str = '',
    ):
        table_name = self.db_manager.get_table_name('ai_agent_session_batch_items')
        helper_agent_ids_json = json.dumps(helper_agent_ids, ensure_ascii=False)
        now_ts = datetime.now().isoformat()
        self.db_manager.execute_query(
            f"""
            INSERT INTO {table_name}
            (batch_id, project_id, agent_key, service_name, helper_session_id, helper_agent_ids_json, status, last_error)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                helper_session_id = VALUES(helper_session_id),
                helper_agent_ids_json = VALUES(helper_agent_ids_json),
                status = VALUES(status),
                last_error = VALUES(last_error),
                updated_at = NOW()
            """ if self.db_manager.db_type == 'mysql' else
            f"""
            INSERT INTO {table_name}
            (batch_id, project_id, agent_key, service_name, helper_session_id, helper_agent_ids_json, status, last_error, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(batch_id, agent_key, service_name) DO UPDATE SET
                helper_session_id=excluded.helper_session_id,
                helper_agent_ids_json=excluded.helper_agent_ids_json,
                status=excluded.status,
                last_error=excluded.last_error,
                updated_at=excluded.updated_at
            """,
            (batch_id, project_id, agent_key, service_name, helper_session_id, helper_agent_ids_json, status, last_error)
            if self.db_manager.db_type == 'mysql' else
            (batch_id, project_id, agent_key, service_name, helper_session_id, helper_agent_ids_json, status, last_error, now_ts, now_ts)
        )

    def _append_ai_batch_round(self, batch_id: str, round_no: int, role: str, content: str, response_payload: Dict[str, Any]):
        table_name = self.db_manager.get_table_name('ai_agent_session_batch_messages')
        response_json = json.dumps(response_payload, ensure_ascii=False)
        self.db_manager.execute_query(
            f"INSERT INTO {table_name} (batch_id, round_no, role, content, response_json) VALUES (%s, %s, %s, %s, %s)"
            if self.db_manager.db_type == 'mysql' else
            f"INSERT INTO {table_name} (batch_id, round_no, role, content, response_json) VALUES (?, ?, ?, ?, ?)",
            (batch_id, round_no, role, content, response_json)
        )

    def _load_ai_batch(self, batch_id: str) -> Optional[Dict[str, Any]]:
        table_name = self.db_manager.get_table_name('ai_agent_session_batches')
        return self.db_manager.fetch_one(
            f"SELECT * FROM {table_name} WHERE batch_id = %s LIMIT 1"
            if self.db_manager.db_type == 'mysql' else
            f"SELECT * FROM {table_name} WHERE batch_id = ? LIMIT 1",
            (batch_id,)
        )

    def _normalize_single_session(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        session = dict(payload or {})
        session['session_id'] = str(session.get('session_id') or '').strip()
        session['backend'] = str(session.get('backend') or '').strip()
        session['agent_ids'] = list(session.get('agent_ids') or [])
        session_mode = str(session.get('session_mode') or '').strip().lower()
        session['session_mode'] = session_mode or 'invoke'
        session['status'] = str(session.get('status') or '').strip().lower() or 'ready'
        session['pty_pid'] = session.get('pty_pid')
        session['backend_pid'] = session.get('backend_pid')
        if session.get('backend_pid') is None:
            session['backend_pid'] = session.get('pty_pid')
        session['pty_started_at'] = session.get('pty_started_at')
        session['last_error'] = session.get('last_error')
        session['metadata'] = session.get('metadata') or {}
        session['messages'] = list(session.get('messages') or [])
        return session

    def _upsert_ai_single_session(
        self,
        project_id: str,
        agent_key: str,
        service_name: str,
        session: Dict[str, Any],
    ) -> None:
        table_name = self.db_manager.get_table_name('ai_agent_sessions_single')
        now_ts = datetime.now().isoformat()
        session_json = json.dumps(session, ensure_ascii=False)
        agent_ids_json = json.dumps(session.get('agent_ids') or [], ensure_ascii=False)
        metadata_json = json.dumps(session.get('metadata') or {}, ensure_ascii=False)
        values = (
            project_id,
            agent_key,
            service_name,
            str(session.get('session_id') or ''),
            str(session.get('backend') or ''),
            agent_ids_json,
            str(session.get('session_mode') or ''),
            str(session.get('status') or ''),
            session.get('pty_pid'),
            session.get('backend_pid'),
            session.get('pty_started_at'),
            session.get('last_error'),
            metadata_json,
            session_json,
        )
        if self.db_manager.db_type == 'mysql':
            self.db_manager.execute_query(
                f"""
                INSERT INTO {table_name}
                (project_id, agent_key, service_name, session_id, backend, agent_ids_json, session_mode, status,
                 pty_pid, backend_pid, pty_started_at, last_error, metadata_json, raw_json)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                  backend=VALUES(backend),
                  agent_ids_json=VALUES(agent_ids_json),
                  session_mode=VALUES(session_mode),
                  status=VALUES(status),
                  pty_pid=VALUES(pty_pid),
                  backend_pid=VALUES(backend_pid),
                  pty_started_at=VALUES(pty_started_at),
                  last_error=VALUES(last_error),
                  metadata_json=VALUES(metadata_json),
                  raw_json=VALUES(raw_json),
                  updated_at=NOW()
                """,
                values,
            )
        else:
            self.db_manager.execute_query(
                f"""
                INSERT INTO {table_name}
                (project_id, agent_key, service_name, session_id, backend, agent_ids_json, session_mode, status,
                 pty_pid, backend_pid, pty_started_at, last_error, metadata_json, raw_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(project_id, agent_key, service_name, session_id) DO UPDATE SET
                  backend=excluded.backend,
                  agent_ids_json=excluded.agent_ids_json,
                  session_mode=excluded.session_mode,
                  status=excluded.status,
                  pty_pid=excluded.pty_pid,
                  backend_pid=excluded.backend_pid,
                  pty_started_at=excluded.pty_started_at,
                  last_error=excluded.last_error,
                  metadata_json=excluded.metadata_json,
                  raw_json=excluded.raw_json,
                  updated_at=excluded.updated_at
                """,
                values + (now_ts, now_ts),
            )

    def _replace_ai_single_session_messages(
        self,
        project_id: str,
        agent_key: str,
        service_name: str,
        session_id: str,
        messages: List[Dict[str, Any]],
    ) -> None:
        table_name = self.db_manager.get_table_name('ai_agent_session_single_messages')
        self.db_manager.execute_query(
            f"DELETE FROM {table_name} WHERE project_id = %s AND agent_key = %s AND service_name = %s AND session_id = %s"
            if self.db_manager.db_type == 'mysql' else
            f"DELETE FROM {table_name} WHERE project_id = ? AND agent_key = ? AND service_name = ? AND session_id = ?",
            (project_id, agent_key, service_name, session_id),
        )
        if not messages:
            return
        for idx, item in enumerate(messages, start=1):
            role = str((item or {}).get('role') or 'assistant').strip() or 'assistant'
            content = str((item or {}).get('content') or '')
            if self.db_manager.db_type == 'mysql':
                self.db_manager.execute_query(
                    f"""
                    INSERT INTO {table_name}
                    (project_id, agent_key, service_name, session_id, seq_no, role, content)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                      role=VALUES(role),
                      content=VALUES(content)
                    """,
                    (project_id, agent_key, service_name, session_id, idx, role, content),
                )
            else:
                now_ts = datetime.now().isoformat()
                self.db_manager.execute_query(
                    f"""
                    INSERT INTO {table_name}
                    (project_id, agent_key, service_name, session_id, seq_no, role, content, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(project_id, agent_key, service_name, session_id, seq_no) DO UPDATE SET
                      role=excluded.role,
                      content=excluded.content
                    """,
                    (project_id, agent_key, service_name, session_id, idx, role, content, now_ts),
                )

    def _save_ai_single_session(
        self,
        project_id: str,
        agent_key: str,
        service_name: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        session = self._normalize_single_session(payload or {})
        session_id = str(session.get('session_id') or '').strip()
        if not session_id:
            return session
        self._upsert_ai_single_session(project_id, agent_key, service_name, session)
        if isinstance(payload, dict) and 'messages' in payload:
            self._replace_ai_single_session_messages(
                project_id,
                agent_key,
                service_name,
                session_id,
                list(session.get('messages') or []),
            )
        return self._load_ai_single_session(project_id, agent_key, service_name, session_id) or session

    def _load_ai_single_session(
        self,
        project_id: str,
        agent_key: str,
        service_name: str,
        session_id: str,
    ) -> Optional[Dict[str, Any]]:
        sessions_table = self.db_manager.get_table_name('ai_agent_sessions_single')
        messages_table = self.db_manager.get_table_name('ai_agent_session_single_messages')
        row = self.db_manager.fetch_one(
            f"""
            SELECT project_id, agent_key, service_name, session_id, backend, agent_ids_json, session_mode, status,
                   pty_pid, backend_pid, pty_started_at, last_error, metadata_json, raw_json, created_at, updated_at
            FROM {sessions_table}
            WHERE project_id = %s AND agent_key = %s AND service_name = %s AND session_id = %s
            LIMIT 1
            """ if self.db_manager.db_type == 'mysql' else
            f"""
            SELECT project_id, agent_key, service_name, session_id, backend, agent_ids_json, session_mode, status,
                   pty_pid, backend_pid, pty_started_at, last_error, metadata_json, raw_json, created_at, updated_at
            FROM {sessions_table}
            WHERE project_id = ? AND agent_key = ? AND service_name = ? AND session_id = ?
            LIMIT 1
            """,
            (project_id, agent_key, service_name, session_id),
        )
        if not row:
            return None
        messages_rows = self.db_manager.fetch_all(
            f"""
            SELECT seq_no, role, content, created_at
            FROM {messages_table}
            WHERE project_id = %s AND agent_key = %s AND service_name = %s AND session_id = %s
            ORDER BY seq_no ASC
            """ if self.db_manager.db_type == 'mysql' else
            f"""
            SELECT seq_no, role, content, created_at
            FROM {messages_table}
            WHERE project_id = ? AND agent_key = ? AND service_name = ? AND session_id = ?
            ORDER BY seq_no ASC
            """,
            (project_id, agent_key, service_name, session_id),
        ) or []
        agent_ids = []
        if row.get('agent_ids_json'):
            try:
                agent_ids = json.loads(row.get('agent_ids_json')) if isinstance(row.get('agent_ids_json'), str) else list(row.get('agent_ids_json') or [])
            except Exception:
                agent_ids = []
        metadata = {}
        if row.get('metadata_json'):
            try:
                metadata = json.loads(row.get('metadata_json')) if isinstance(row.get('metadata_json'), str) else (row.get('metadata_json') or {})
            except Exception:
                metadata = {}
        raw_payload: Dict[str, Any] = {}
        if row.get('raw_json'):
            try:
                raw_payload = json.loads(row.get('raw_json')) if isinstance(row.get('raw_json'), str) else (row.get('raw_json') or {})
            except Exception:
                raw_payload = {}

        def _pick_vendor_value(*keys: str) -> Any:
            for key in keys:
                if key in raw_payload and raw_payload.get(key) is not None:
                    return raw_payload.get(key)
            return None

        return {
            'session_id': row.get('session_id'),
            'backend': row.get('backend'),
            'agent_ids': agent_ids,
            'session_mode': row.get('session_mode') or 'invoke',
            'status': row.get('status') or 'ready',
            'pty_pid': row.get('pty_pid'),
            'backend_pid': row.get('backend_pid'),
            'pty_started_at': row.get('pty_started_at'),
            'last_error': row.get('last_error'),
            'metadata': metadata,
            'messages': [
                {
                    'role': msg.get('role') or 'assistant',
                    'content': msg.get('content') or '',
                } for msg in messages_rows
            ],
            'vendor_session_id': _pick_vendor_value('vendor_session_id', 'claude_session_id'),
            'vendor_session_kind': _pick_vendor_value('vendor_session_kind'),
            'vendor_resume_mode': _pick_vendor_value('vendor_resume_mode'),
            'vendor_session_initialized': _pick_vendor_value('vendor_session_initialized'),
            'vendor_last_mode': _pick_vendor_value('vendor_last_mode'),
            'vendor_last_cmd': _pick_vendor_value('vendor_last_cmd'),
            'vendor_last_error': _pick_vendor_value('vendor_last_error'),
            'claude_session_id': _pick_vendor_value('claude_session_id', 'vendor_session_id'),
            'claude_workdir': _pick_vendor_value('claude_workdir'),
            'created_at': row.get('created_at'),
            'updated_at': row.get('updated_at'),
        }

    def _list_ai_single_sessions(
        self,
        project_id: str,
        agent_key: str,
        service_name: str,
    ) -> List[Dict[str, Any]]:
        sessions_table = self.db_manager.get_table_name('ai_agent_sessions_single')
        rows = self.db_manager.fetch_all(
            f"""
            SELECT session_id
            FROM {sessions_table}
            WHERE project_id = %s AND agent_key = %s AND service_name = %s
            ORDER BY updated_at DESC, created_at DESC
            """ if self.db_manager.db_type == 'mysql' else
            f"""
            SELECT session_id
            FROM {sessions_table}
            WHERE project_id = ? AND agent_key = ? AND service_name = ?
            ORDER BY updated_at DESC, created_at DESC
            """,
            (project_id, agent_key, service_name),
        ) or []
        sessions: List[Dict[str, Any]] = []
        for row in rows:
            item = self._load_ai_single_session(project_id, agent_key, service_name, str(row.get('session_id') or ''))
            if item:
                sessions.append(item)
        return sessions

    def _delete_ai_single_session(
        self,
        project_id: str,
        agent_key: str,
        service_name: str,
        session_id: str,
    ) -> None:
        sessions_table = self.db_manager.get_table_name('ai_agent_sessions_single')
        messages_table = self.db_manager.get_table_name('ai_agent_session_single_messages')
        self.db_manager.execute_query(
            f"DELETE FROM {messages_table} WHERE project_id = %s AND agent_key = %s AND service_name = %s AND session_id = %s"
            if self.db_manager.db_type == 'mysql' else
            f"DELETE FROM {messages_table} WHERE project_id = ? AND agent_key = ? AND service_name = ? AND session_id = ?",
            (project_id, agent_key, service_name, session_id),
        )
        self.db_manager.execute_query(
            f"DELETE FROM {sessions_table} WHERE project_id = %s AND agent_key = %s AND service_name = %s AND session_id = %s"
            if self.db_manager.db_type == 'mysql' else
            f"DELETE FROM {sessions_table} WHERE project_id = ? AND agent_key = ? AND service_name = ? AND session_id = ?",
            (project_id, agent_key, service_name, session_id),
        )

    @staticmethod
    def _is_service_stopped_state(state: str) -> bool:
        return str(state or '').strip().lower() in {
            'stopped',
            'stopping',
            'exited',
            'dead',
            'inactive',
            'removed',
            'not_running',
        }

    def _can_ignore_stop_response(self, status_code: int, payload: Any) -> bool:
        if status_code in (200, 202, 204, 404):
            return True

        text_parts: List[str] = []
        if isinstance(payload, dict):
            text_parts.extend([
                str(payload.get('error') or ''),
                str(payload.get('message') or ''),
                str(payload.get('detail') or ''),
            ])
        elif payload is not None:
            text_parts.append(str(payload))

        text = ' '.join(text_parts).strip().lower()
        benign_markers = (
            'already stopped',
            'already stopping',
            'is not running',
            'not running',
            'service not found',
            'no such service',
            '已经停止',
            '已停止',
            '未运行',
            '不存在',
        )
        return any(marker in text for marker in benign_markers)

    def _delete_service_bound_ingress_routes(
        self,
        project_id: str,
        agent_key: str,
        service_name: str,
        auth_header: Optional[str] = None
    ) -> Dict[str, Any]:
        all_routes = self._list_project_ingress_routes(
            project_id=project_id,
            include_deleted=False,
            auth_header=auth_header
        )
        matched_routes = []
        for route in all_routes:
            if not self._is_service_bound_ingress_route(route):
                continue
            if str(route.get('agent_key') or '').strip() != str(agent_key or '').strip():
                continue
            if self._extract_service_binding_name(route) != str(service_name or '').strip():
                continue
            route_id = str(route.get('route_id') or '').strip()
            if not route_id:
                continue
            matched_routes.append(route)

        deleted = 0
        failed: List[Dict[str, Any]] = []
        for route in matched_routes:
            route_id = str(route.get('route_id') or '').strip()
            try:
                resp = self._call_k8s_service(
                    method='DELETE',
                    path=f'/api/k8s/agent-ingress-routes/{route_id}',
                    project_id=project_id,
                    headers={'Authorization': auth_header} if auth_header else None
                )
                if resp.status_code < 300:
                    deleted += 1
                else:
                    failed.append({
                        'route_id': route_id,
                        'status_code': resp.status_code,
                        'body': resp.text[:200]
                    })
            except Exception as e:
                failed.append({
                    'route_id': route_id,
                    'error': str(e)
                })

        return {
            'matched': len(matched_routes),
            'deleted': deleted,
            'failed': failed,
        }

    def _prepare_agent_exec_ws_tunnel(
        self,
        agent_key: str,
        service_name: str,
        project_id: str,
        container_name: str,
        shell: str,
        mode: str,
        user: str
    ) -> Tuple[Any, str, str]:
        agent = self.agent_manager.get_agent(agent_key)
        if not agent:
            raise RuntimeError(f'Agent {agent_key} not found')
        if project_id and agent.project_id != project_id:
            raise RuntimeError(f'Agent {agent_key} does not belong to project {project_id}')
        if agent.status != 'online':
            raise RuntimeError(f'Agent {agent_key} is {agent.status}')

        service_status, service_payload = self.agent_manager.call_agent_api(
            agent_key,
            'GET',
            f'/api/services/{quote(service_name, safe="")}',
            None,
            timeout_type='health_check'
        )
        if service_status != 200:
            detail = ''
            if isinstance(service_payload, dict):
                detail = str(service_payload.get('error') or service_payload.get('message') or '')
            elif isinstance(service_payload, str):
                detail = service_payload
            msg = f'服务不存在或不可访问: {service_name}'
            if detail:
                msg = f'{msg} ({detail})'
            raise RuntimeError(msg)

        supported, probe_status, probe_detail = self._probe_agent_exec_ws_capability(
            agent, service_name, container_name, shell, mode, user
        )
        if not supported:
            raise RuntimeError(
                f'当前Agent未提供服务终端WS接口: status={probe_status}, detail={probe_detail}'
            )

        query = {
            'token': self.agent_manager.agent_auth_token,
            'container': container_name,
            'shell': shell,
            'mode': mode
        }
        if user:
            query['user'] = user
        upstream_ws_url = (
            f"ws://{agent.ip_address}:{self.agent_manager.agent_api_port}"
            f"/api/services/{quote(service_name, safe='')}/exec/ws?{urlencode(query)}"
        )
        tunnel_tag = (
            f"agent={agent_key}, service={service_name}, project={project_id or '-'}, "
            f"container={container_name or '-'}, mode={mode}, shell={shell}, user={user or '-'}"
        )
        return agent, upstream_ws_url, tunnel_tag

    def _sync_all_agent_services(self):
        """从所有在线Agent拉取服务清单并写入聚合表。"""
        summary = {
            'total_agents': 0,
            'online_agents': 0,
            'offline_agents': 0,
            'ok_count': 0,
            'fail_count': 0,
            'synced_services': 0,
            'results': []
        }
        try:
            page = 1
            per_page = 1000
            agents: List[Dict[str, Any]] = []
            while True:
                batch, total = self.agent_manager.list_agents(page=page, per_page=per_page)
                if not batch:
                    break
                agents.extend(batch)
                if len(agents) >= total:
                    break
                page += 1

            summary['total_agents'] = len(agents)

            for agent_data in agents:
                agent_status = str(agent_data.get('status') or '').strip().lower()
                if agent_status != 'online':
                    summary['offline_agents'] += 1
                    if agent_data.get('key'):
                        self._mark_agent_services_stale_with_grace(
                            agent_data.get('key'),
                            reason='agent_offline_during_sync'
                        )
                    continue
                summary['online_agents'] += 1
                agent = self.agent_manager.get_agent(agent_data.get('key'))
                if not agent:
                    summary['fail_count'] += 1
                    summary['results'].append({
                        'ok': False,
                        'agent_key': agent_data.get('key', ''),
                        'reason_code': 'agent_not_loaded',
                        'reason': 'Agent对象未加载',
                        'status_code': 404
                    })
                    continue

                sync_result = self._sync_single_agent_services(agent)
                summary['results'].append(sync_result)
                if not sync_result.get('ok'):
                    summary['fail_count'] += 1
                    continue
                summary['ok_count'] += 1
                summary['synced_services'] += int(sync_result.get('upserted', 0))
                self.logger.debug(
                    f"服务聚合同步: agent={agent.key}, seen={sync_result.get('seen', 0)}, upserted={sync_result.get('upserted', 0)}"
                )

            self.logger.info(
                f"服务聚合同步完成: total={summary['total_agents']}, online={summary['online_agents']}, "
                f"ok={summary['ok_count']}, fail={summary['fail_count']}, services={summary['synced_services']}"
            )
        except Exception as e:
            self.logger.error(f"服务聚合同步失败: {e}", exc_info=True)
        return summary

    def _sync_single_agent_services(self, agent: Any) -> Dict[str, Any]:
        """强制同步单个Agent的服务状态。"""
        if not agent:
            return {
                'ok': False,
                'agent_key': '',
                'reason_code': 'agent_not_found',
                'reason': 'Agent对象不存在',
                'status_code': 404
            }

        begin = time.time()
        status_code, response = self.agent_manager.call_agent_api(
            agent.key, 'GET', '/api/services', timeout_type='proxy', log_connection_error=False
        )
        # 对节点 API 的瞬时连接抖动做一次轻量重试，避免前端在线状态频繁抖动。
        if status_code in (503, 504):
            time.sleep(0.2)
            retry_status, retry_response = self.agent_manager.call_agent_api(
                agent.key, 'GET', '/api/services', timeout_type='proxy', log_connection_error=False
            )
            if retry_status == 200:
                status_code, response = retry_status, retry_response

        if status_code != 200:
            self._mark_agent_services_stale_with_grace(
                agent.key,
                reason=f'pull_force_status_{status_code}'
            )
            reason = ''
            if isinstance(response, dict):
                reason = str(response.get('error') or response.get('message') or '')
            elif isinstance(response, str):
                reason = response
            if not reason:
                reason = f'Agent API返回状态码 {status_code}'
            return {
                'ok': False,
                'agent_key': agent.key,
                'reason_code': f'agent_api_status_{status_code}',
                'reason': reason,
                'status_code': status_code,
                'agent_status': getattr(agent, 'status', 'unknown'),
                'duration_ms': int((time.time() - begin) * 1000)
            }

        services = []
        if isinstance(response, list):
            services = response
        elif isinstance(response, dict):
            if isinstance(response.get('services'), list):
                services = response.get('services') or []
            elif isinstance(response.get('items'), list):
                services = response.get('items') or []
            else:
                return {
                    'ok': False,
                    'agent_key': agent.key,
                    'reason_code': 'invalid_services_payload',
                    'reason': 'Agent /api/services 返回格式不符合预期（缺少列表字段）',
                    'status_code': 200,
                    'agent_status': getattr(agent, 'status', 'unknown'),
                    'duration_ms': int((time.time() - begin) * 1000)
                }
        else:
            return {
                'ok': False,
                'agent_key': agent.key,
                'reason_code': 'invalid_services_payload',
                'reason': 'Agent /api/services 返回非JSON列表格式',
                'status_code': 200,
                'agent_status': getattr(agent, 'status', 'unknown'),
                'duration_ms': int((time.time() - begin) * 1000)
            }

        try:
            seen, upserted = self._upsert_agent_services_snapshot(agent, services, source='pull_force')
            return {
                'ok': True,
                'agent_key': agent.key,
                'seen': seen,
                'upserted': upserted,
                'reason_code': 'success',
                'reason': '同步成功',
                'status_code': 200,
                'agent_status': getattr(agent, 'status', 'unknown'),
                'duration_ms': int((time.time() - begin) * 1000)
            }
        except Exception as e:
            self.logger.error(f"写入服务聚合表失败: agent={agent.key}, err={e}", exc_info=True)
            return {
                'ok': False,
                'agent_key': agent.key,
                'reason_code': 'db_upsert_failed',
                'reason': f'服务状态入库失败: {str(e)}',
                'status_code': 500,
                'agent_status': getattr(agent, 'status', 'unknown'),
                'duration_ms': int((time.time() - begin) * 1000)
            }

    def _is_agent_report_authenticated(self) -> bool:
        token = request.headers.get('X-Auth-Token')
        expected = self.config.get('agent_auth_token') or ''
        return bool(token) and token == expected

    def _get_request_user_context(self) -> Dict[str, str]:
        """从请求中提取用户身份信息（优先JWT，其次透传头）"""
        user_id = ''
        username = ''
        token_type = ''

        try:
            auth_header = request.headers.get('Authorization', '')
            if auth_header.lower().startswith('bearer '):
                token = auth_header.split(' ', 1)[1].strip()
                token_parts = token.split('.')
                if len(token_parts) >= 2:
                    payload_b64 = token_parts[1]
                    padding = '=' * (-len(payload_b64) % 4)
                    decoded = base64.urlsafe_b64decode(payload_b64 + padding)
                    payload = json.loads(decoded.decode('utf-8'))
                    user_id = str(payload.get('sub') or '').strip()
                    username = str(payload.get('username') or '').strip()
                    token_type = str(payload.get('type') or '').strip().lower()
        except Exception:
            pass

        header_user_id = str(request.headers.get('X-User-Id') or '').strip()
        header_username = str(request.headers.get('X-Username') or '').strip()
        if not user_id and header_user_id:
            user_id = header_user_id
        # 用户名展示/归属需要保留原始大小写，优先使用透传头中的原值；
        # JWT payload 若已被其它链路归一化为小写，不应覆盖这里的展示语义。
        if header_username:
            username = header_username
        elif not username:
            username = header_username

        # 兜底兼容，避免空身份影响历史流程
        if not user_id:
            user_id = 'system'
        if not username:
            username = 'system'

        return {
            'user_id': user_id,
            'username': username,
            'token_type': token_type
        }

    def _check_template_visible(self, template: Optional[Dict], user_ctx: Dict[str, str]) -> bool:
        return self.template_manager.can_view_template(
            template,
            user_ctx.get('user_id', ''),
            user_ctx.get('username', '')
        )

    def _check_template_manageable(self, template: Optional[Dict], user_ctx: Dict[str, str]) -> bool:
        return self.template_manager.can_manage_template(
            template,
            user_ctx.get('user_id', ''),
            user_ctx.get('username', '')
        )

    def _with_template_write_lock(self, template_names: List[str], callback, timeout: int = 120):
        normalized = sorted({str(name).strip() for name in (template_names or []) if str(name).strip()})
        if not normalized:
            return callback()

        acquired_locks = []
        try:
            for name in normalized:
                lock = self.redis_manager.get_lock(f"template_write:{name}", timeout)
                if not lock.acquire(block=True, block_timeout=timeout):
                    raise BlockingIOError(f'模板 {name} 当前正在被其他副本修改，请稍后重试')
                acquired_locks.append(lock)
            return callback()
        finally:
            for lock in reversed(acquired_locks):
                try:
                    lock.release()
                except Exception:
                    pass

    def _sync_single_agent_services_by_key(self, agent_key: str, reason: str = '') -> Optional[Dict[str, Any]]:
        agent = self.agent_manager.get_agent(agent_key) or self.agent_manager.ensure_agent_exists(agent_key)
        if not agent:
            self.logger.warning(f"任务完成后同步服务状态失败，Agent不存在: agent={agent_key}, reason={reason}")
            return None
        result = self._sync_single_agent_services(agent)
        if result.get('ok'):
            self.logger.info(f"任务完成后已同步服务状态: agent={agent_key}, reason={reason}")
        else:
            self.logger.warning(
                f"任务完成后同步服务状态失败: agent={agent_key}, reason={reason}, result={result}"
            )
        return result

    def _service_exists_on_agent(self, agent_key: str, service_name: str) -> bool:
        """检查Agent上是否已存在同名服务。"""
        try:
            status_code, response = self.agent_manager.call_agent_api(
                agent_key, 'GET', f'/api/services/{service_name}', None, timeout_type='health_check'
            )
            if status_code == 200:
                return True

            # 兼容部分Agent不支持单服务查询，回退到列表查询
            list_code, list_resp = self.agent_manager.call_agent_api(
                agent_key, 'GET', '/api/services', None, timeout_type='health_check'
            )
            if list_code == 200:
                if isinstance(list_resp, list):
                    return any(isinstance(item, dict) and item.get('name') == service_name for item in list_resp)
                if isinstance(list_resp, dict):
                    services = list_resp.get('services') or list_resp.get('items') or []
                    if isinstance(services, list):
                        return any(isinstance(item, dict) and item.get('name') == service_name for item in services)
            return False
        except Exception as e:
            self.logger.warning(f"检查Agent服务是否重复失败: agent={agent_key}, service={service_name}, error={e}")
            # 无法确定时不阻断请求，交由后续流程处理
            return False

    def _service_exists_in_snapshot(self, agent_key: str, service_name: str) -> bool:
        """检查平台已同步的服务快照中是否存在同名服务。"""
        try:
            table_name = self.db_manager.get_table_name('agent_services')
            if self.db_manager.db_type == 'mysql':
                row = self.db_manager.fetch_one(
                    f"""
                    SELECT id
                    FROM {table_name}
                    WHERE agent_key = %s
                      AND service_name = %s
                      AND is_deleted = 0
                    ORDER BY updated_at DESC
                    LIMIT 1
                    """,
                    (agent_key, service_name)
                )
            else:
                row = self.db_manager.fetch_one(
                    f"""
                    SELECT id
                    FROM {table_name}
                    WHERE agent_key = ?
                      AND service_name = ?
                      AND is_deleted = 0
                    ORDER BY updated_at DESC
                    LIMIT 1
                    """,
                    (agent_key, service_name)
                )
            return bool(row)
        except Exception as e:
            self.logger.warning(
                f"检查平台服务快照是否重复失败: agent={agent_key}, service={service_name}, error={e}"
            )
            return False

    def _probe_agent_exec_ws_capability(self, agent: AgentInfo, service_name: str,
                                        container_name: str, shell: str, mode: str, user: str) -> Tuple[bool, int, str]:
        """
        预探测Agent是否支持服务终端WS接口。
        这里不能再用普通 HTTP GET 探测 Flask-Sock 路由。
        当前 nacos_client 的 `/api/services/<name>/exec/ws` 对非 Upgrade 请求会直接返回 404，
        但真实 WebSocket 握手是可用的。这里改为做一次短连接握手探测：
        - 握手成功: 视为支持
        - 握手失败且上游明确 404: 视为不支持
        - 其他状态码: 认为端点存在，但本次握手因参数/容器状态等原因失败
        """
        try:
            query = {
                'token': self.agent_manager.agent_auth_token,
                'container': container_name or '',
                'shell': shell or '/bin/sh',
                'mode': mode or 'shell'
            }
            if user:
                query['user'] = user

            probe_ws_url = (
                f"ws://{agent.ip_address}:{self.agent_manager.agent_api_port}"
                f"/api/services/{quote(service_name, safe='')}/exec/ws?{urlencode(query)}"
            )
            ws = None
            try:
                ws = ws_client.create_connection(
                    probe_ws_url,
                    timeout=5,
                    enable_multithread=True,
                    header=[f"X-Auth-Token: {self.agent_manager.agent_auth_token}"]
                )
                return True, 101, ''
            finally:
                if ws is not None:
                    try:
                        ws.close()
                    except Exception:
                        pass
        except ws_client.WebSocketBadStatusException as e:
            status_code = int(getattr(e, 'status_code', 500) or 500)
            detail = str(e)
            if status_code == 404:
                return False, 404, detail
            return True, status_code, detail
        except Exception as e:
            return False, 500, str(e)

    def _check_deploy_duplicate(self, service_name: str, agent_key: str, project_id: str) -> Optional[Dict[str, Any]]:
        """统一部署防重检查：进行中的部署任务 + Agent/平台快照中已存在服务。"""
        active_task = self.task_manager.find_active_task_for_service(
            'deploy', service_name, agent_key, project_id
        )
        if active_task:
            return {
                'reason': 'active_task',
                'message': f'服务 {service_name} 在节点 {agent_key} 上已有进行中的部署任务',
                'task_id': active_task.get('task_id'),
                'task_status': active_task.get('status'),
            }

        if self._service_exists_on_agent(agent_key, service_name):
            return {
                'reason': 'existing_service',
                'message': f'服务 {service_name} 在节点 {agent_key} 上已存在，禁止重复部署，请先手动删除后再部署'
            }

        if self._service_exists_in_snapshot(agent_key, service_name):
            return {
                'reason': 'existing_service_snapshot',
                'message': f'服务 {service_name} 在节点 {agent_key} 的平台快照中已存在，禁止重复部署，请先手动删除后再部署'
            }

        return None

    def _deploy_lock_key(self, project_id: str, agent_key: str, service_name: str, task_type: str = 'deploy') -> str:
        return f"{task_type}:{project_id}:{agent_key}:{service_name}"

    def _record_service_sync_log(self, scope: str, status: str = 'ok',
                                 project_id: Optional[str] = None, agent_key: Optional[str] = None,
                                 stale_only: bool = False, total: int = 0, ok_count: int = 0,
                                 fail_count: int = 0, message: str = '', details: Optional[List[Dict[str, Any]]] = None):
        table_name = self.db_manager.get_table_name('service_sync_logs')
        sync_id = uuid.uuid4().hex
        details_json = json.dumps(details or [], ensure_ascii=False)
        pod_id = self.config.get('pod_id', '')
        if self.db_manager.db_type == 'mysql':
            self.db_manager.execute_query(f'''
                INSERT INTO {table_name}
                (sync_id, scope, project_id, agent_key, stale_only, status, total, ok_count, fail_count, message, details_json, pod_id, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
            ''', (sync_id, scope, project_id, agent_key, int(stale_only), status, total, ok_count, fail_count, message, details_json, pod_id))
        else:
            self.db_manager.execute_query(f'''
                INSERT INTO {table_name}
                (sync_id, scope, project_id, agent_key, stale_only, status, total, ok_count, fail_count, message, details_json, pod_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            ''', (sync_id, scope, project_id, agent_key, int(stale_only), status, total, ok_count, fail_count, message, details_json, pod_id))

    def _register_routes(self):
        """注册路由"""

        @self.app.route('/api/agent/health', methods=['GET'])
        def health_check():
            """
            轻量健康检查端点。
            供 K8S liveness/readiness/startup probe 使用，不在探针路径中同步探测
            MySQL / Redis / Nacos，避免外部依赖抖动拖垮进程存活判断。
            深度连通性检查仍通过 /api/agent/system/connections 暴露。
            """
            with self.health_state_lock:
                status = self.cached_health_status
                components = dict(self.cached_component_health)
            return jsonify({
                'status': status,
                'timestamp': datetime.now().isoformat(),
                'started_at': self.started_at.isoformat(),
                'pod_id': self.config['pod_id'],
                'database_type': self.config['database'].get('type', 'sqlite'),
                'probe_mode': 'shallow',
                'components': components,
                'supported_formats': self.config.get('supported_formats', SUPPORTED_FORMATS)
            })

        @self.app.route('/api/agent/system/connections', methods=['GET'])
        def get_connection():
            """获取连接状态"""
            results = ConnectionChecker.check_all_connections(self.config)

            return jsonify({
                'timestamp': datetime.now().isoformat(),
                'connections': {
                    'database': {
                        'status': 'connected' if results['database'][0] else 'disconnected',
                        'message': results['database'][1],
                        'type': self.config['database'].get('type', 'sqlite')
                    },
                    'nacos': {
                        'status': 'connected' if results['nacos'][0] else 'disconnected',
                        'message': results['nacos'][1]
                    },
                    'redis': {
                        'status': 'connected' if results['redis'][0] else 'disabled',
                        'message': results['redis'][1],
                        'enabled': self.config.get('redis_enabled', True)
                    }
                },
                'supported_formats': self.config.get('supported_formats', SUPPORTED_FORMATS)
            })

        @self.app.route('/api/agent/system/external-agent-ips', methods=['GET'])
        def get_external_agent_ips():
            """获取外部Agent接入IP列表"""
            external_ips = self.config.get('external_agent_ips', [])
            return jsonify({
                'external_agent_ips': external_ips,
                'count': len(external_ips),
                'timestamp': datetime.now().isoformat()
            })

        @self.app.route('/api/agent/projects', methods=['GET'])
        def list_projects():
            projects = self.agent_manager.list_projects()
            return jsonify({
                'projects': projects,
                'total': len(projects)
            })

        @self.app.route('/api/agent/agents', methods=['GET'])
        def list_agents():
            page = max(int(request.args.get('page', 1) or 1), 1)
            per_page = int(request.args.get('per_page', 20) or 20)
            per_page = max(1, min(per_page, 1000))
            project_id = request.args.get('project_id')

            # project_id is required
            if not project_id:
                return jsonify({'error': 'project_id parameter is required'}), 400

            agents, total = self.agent_manager.list_agents(page, per_page, project_id)
            list_diag = self.agent_manager.get_last_list_diag()
            refresh_diag = self.agent_manager.get_last_refresh_diag()
            return jsonify({
                'agents': agents,
                'page': page,
                'per_page': per_page,
                'total': total,
                'project_id': project_id,
                'diagnostics': {
                    'list': list_diag,
                    'refresh': refresh_diag,
                    'redis': {
                        'enabled': bool(self.redis_manager.enabled),
                        'used_for_agent_list_cache': False,
                    },
                    'note': 'agent list reads DB snapshot only; redis currently used for distributed locks'
                }
            })

        @self.app.route('/api/agent/agents/refresh', methods=['POST'])
        def refresh_agents():
            executed, message = self._run_refresh_cycle(include_service_sync=True, include_helper_health_sync=True)
            status_code = 200 if executed else 202
            return jsonify({
                'executed': executed,
                'message': message
            }), status_code

        # 在_register_routes方法中添加以下路由
        @self.app.route('/api/agent/agents/cleanup', methods=['POST'])
        def cleanup_offline_agents():
            """清除指定project下掉线的agent"""
            try:
                # 获取清理参数
                data = request.get_json() or {}
                project_id = data.get('project_id')
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400
                dry_run = data.get('dry_run', False)  # 是否模拟运行
                force = data.get('force', False)  # 是否强制清理（不检查时间）
                cleanup_k8s_resources = bool(data.get('cleanup_k8s_resources', True))

                # 先获取统计信息（按project过滤）
                offline_count, total_count = self.agent_manager.get_offline_agents_count(project_id, force=force)

                if offline_count == 0:
                    return jsonify({
                        'message': '没有需要清理的掉线agent',
                        'offline_count': 0,
                        'total_count': total_count,
                        'project_id': project_id,
                        'timestamp': datetime.now().isoformat()
                    })

                if dry_run:
                    # 模拟运行，只返回统计信息
                    return jsonify({
                        'message': f'模拟清理：找到 {offline_count} 个掉线agent（超过5分钟未更新）',
                        'dry_run': True,
                        'offline_count': offline_count,
                        'total_count': total_count,
                        'would_clean': True,
                        'project_id': project_id,
                        'timestamp': datetime.now().isoformat()
                    })

                # 执行清理操作（按project过滤）
                success, message, cleanup_info = self.agent_manager.cleanup_offline_agents(project_id, force=force)

                if success:
                    k8s_cleanup = {
                        'enabled': cleanup_k8s_resources,
                        'processed': 0,
                        'ok': 0,
                        'failed': 0,
                        'details': []
                    }
                    if cleanup_k8s_resources:
                        for item in cleanup_info.get('cleaned_agents', []) or []:
                            cleaned_key = str(item.get('agent_key') or '').strip()
                            if not cleaned_key:
                                continue
                            detail = self._cleanup_agent_k8s_resources(project_id, cleaned_key)
                            k8s_cleanup['processed'] += 1
                            if detail.get('success'):
                                k8s_cleanup['ok'] += 1
                            else:
                                k8s_cleanup['failed'] += 1
                            k8s_cleanup['details'].append(detail)

                    return jsonify({
                        'message': message,
                        'success': True,
                        'cleanup_info': cleanup_info,
                        'k8s_cleanup': k8s_cleanup,
                        'offline_count_before': offline_count,
                        'total_count_before': total_count,
                        'project_id': project_id,
                        'timestamp': datetime.now().isoformat()
                    })
                else:
                    return jsonify({
                        'error': message,
                        'success': False,
                        'project_id': project_id,
                        'timestamp': datetime.now().isoformat()
                    }), 500

            except Exception as e:
                self.logger.error(f"清理掉线agent API失败: {str(e)}", exc_info=True)
                return jsonify({
                    'error': '清理操作失败',
                    'message': str(e),
                    'timestamp': datetime.now().isoformat()
                }), 500

        @self.app.route('/api/agent/agents/stats', methods=['GET'])
        def get_agent_stats():
            """获取agent统计信息"""
            try:
                # Get project_id from query parameter
                project_id = request.args.get('project_id')
                if not project_id:
                    return jsonify({'error': 'project_id parameter is required'}), 400

                # 获取各种状态的agent数量 (filtered by project_id)
                table_name = self.db_manager.get_table_name('agent_status')
                if self.db_manager.db_type == 'mysql':
                    status_stats = self.db_manager.fetch_all(f'''
                                                             SELECT status,
                                                                    COUNT(*) as count,
                            MAX(last_seen) as last_seen_max,
                            MIN(last_seen) as last_seen_min
                                                             FROM {table_name}
                                                             WHERE project_id = %s
                                                             GROUP BY status
                                                             ORDER BY count DESC
                                                             ''', (project_id,))
                else:
                    status_stats = self.db_manager.fetch_all(f'''
                                                             SELECT status,
                                                                    COUNT(*) as count,
                            MAX(last_seen) as last_seen_max,
                            MIN(last_seen) as last_seen_min
                                                             FROM {table_name}
                                                             WHERE project_id = ?
                                                             GROUP BY status
                                                             ORDER BY count DESC
                                                             ''', (project_id,))

                # 计算掉线agent（超过5分钟未更新）for this project
                if self.db_manager.db_type == 'mysql':
                    offline_result = self.db_manager.fetch_one(f'''
                                                               SELECT COUNT(*) as count
                                                               FROM {table_name}
                                                               WHERE project_id = %s
                                                                 AND status IN ('offline'
                                                                   , 'error'
                                                                   , 'timeout'
                                                                   , 'unknown')
                                                                 AND updated_at
                                                                   < NOW() - INTERVAL 5 MINUTE
                                                               ''', (project_id,))
                    total_result = self.db_manager.fetch_one(
                        f"SELECT COUNT(*) as count FROM {table_name} WHERE project_id = %s",
                        (project_id,)
                    )
                else:
                    offline_result = self.db_manager.fetch_one(f'''
                                                               SELECT COUNT(*) as count
                                                               FROM {table_name}
                                                               WHERE project_id = ?
                                                                 AND status IN ('offline'
                                                                   , 'error'
                                                                   , 'timeout'
                                                                   , 'unknown')
                                                                 AND updated_at
                                                                   < datetime('now'
                                                                   , '-5 minutes')
                                                               ''', (project_id,))
                    total_result = self.db_manager.fetch_one(
                        f"SELECT COUNT(*) as count FROM {table_name} WHERE project_id = ?",
                        (project_id,)
                    )

                total_count = total_result['count'] if total_result else 0
                offline_count = offline_result['count'] if offline_result else 0

                stats = {
                    'timestamp': datetime.now().isoformat(),
                    'project_id': project_id,
                    'summary': {
                        'total_agents': total_count,
                        'offline_agents': offline_count,
                        'status_distribution': {
                            item['status']: item['count'] for item in status_stats
                        }
                    },
                    'status_details': status_stats,
                    'cleanup_info': {
                        'can_cleanup': offline_count > 0,
                        'offline_count': offline_count,
                        'suggested_action': 'POST /api/agent/agents/cleanup 清理掉线agent'
                    }
                }

                return jsonify(stats)

            except Exception as e:
                self.logger.error(f"获取agent统计信息失败: {str(e)}")
                return jsonify({
                    'error': '获取统计信息失败',
                    'message': str(e)
                }), 500

        @self.app.route('/api/agent/agents/<agent_key>/status', methods=['PUT'])
        def update_secflow_agent_agent_status(agent_key):
            """手动更新agent状态"""
            try:
                data = request.get_json()
                if not data:
                    return jsonify({'error': '请求体必须为JSON'}), 400

                status = data.get('status')
                if status not in ['online', 'offline', 'error', 'timeout', 'unknown']:
                    return jsonify({'error': '无效的状态值'}), 400

                # Get project_id from request body
                project_id = data.get('project_id')
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400

                # 检查agent是否存在
                table_name = self.db_manager.get_table_name('agent_status')
                if self.db_manager.db_type == 'mysql':
                    agent = self.db_manager.fetch_one(
                        f"SELECT * FROM {table_name} WHERE agent_key = %s",
                        (agent_key,)
                    )
                else:
                    agent = self.db_manager.fetch_one(
                        f"SELECT * FROM {table_name} WHERE agent_key = ?",
                        (agent_key,)
                    )

                if not agent:
                    return jsonify({'error': f'Agent {agent_key} 不存在'}), 404

                # Verify the agent belongs to the requested project
                if agent.get('project_id') != project_id:
                    return jsonify({'error': f'Agent {agent_key} does not belong to project {project_id}'}), 403

                old_status = str(agent.get('status') or '')

                # 更新agent状态
                if self.db_manager.db_type == 'mysql':
                    self.db_manager.execute_query(f'''
                                                  UPDATE {table_name}
                                                  SET status     = %s,
                                                      updated_at = NOW()
                                                  WHERE agent_key = %s
                                                  ''', (status, agent_key))
                else:
                    self.db_manager.execute_query(f'''
                                                  UPDATE {table_name}
                                                  SET status     = ?,
                                                      updated_at = datetime('now')
                                                  WHERE agent_key = ?
                                                  ''', (status, agent_key))

                # 更新内存中的agent状态
                agent_info = self.agent_manager.get_agent(agent_key)
                if agent_info:
                    agent_info.status = status
                    agent_info.last_seen = datetime.now()

                self.agent_manager.record_manual_status_transition(
                    project_id=project_id,
                    agent_key=agent_key,
                    hostname=str(agent.get('hostname') or ''),
                    ip_address=str(agent.get('ip_address') or ''),
                    from_status=old_status,
                    to_status=status,
                    reason_message=f'manual status update: {old_status or "unknown"} -> {status}'
                )

                self.logger.info(f"手动更新agent {agent_key} 状态为 {status}")

                return jsonify({
                    'message': f'Agent {agent_key} 状态已更新为 {status}',
                    'agent_key': agent_key,
                    'project_id': project_id,
                    'new_status': status,
                    'updated_at': datetime.now().isoformat(),
                    'updated_by': 'system'
                })

            except Exception as e:
                self.logger.error(f"更新agent状态失败: {str(e)}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/agents/<agent_key>/status-history', methods=['GET', 'DELETE'])
        def get_agent_status_history(agent_key):
            """查询或清空指定Agent上下线事件历史"""
            try:
                project_id = str(request.args.get('project_id') or '').strip()
                if not project_id:
                    return jsonify({'error': 'project_id parameter is required'}), 400

                if request.method == 'DELETE':
                    deleted = self.agent_manager.clear_agent_status_history(project_id, agent_key)
                    if deleted < 0:
                        return jsonify({'error': 'clear agent status history failed'}), 500
                    return jsonify({
                        'project_id': project_id,
                        'agent_key': agent_key,
                        'deleted': deleted,
                        'message': f'已清空 {deleted} 条节点上下线记录'
                    })

                limit_raw = request.args.get('limit', '100')
                try:
                    limit = int(limit_raw)
                except Exception:
                    limit = 100
                limit = max(1, min(limit, 100))

                items = self.agent_manager.list_agent_status_history(project_id, agent_key, limit=limit)
                return jsonify({
                    'project_id': project_id,
                    'agent_key': agent_key,
                    'limit': limit,
                    'total': len(items),
                    'items': items,
                })
            except Exception as e:
                self.logger.error(f"获取Agent状态历史失败: {str(e)}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/agents/<agent_key>/diagnostics', methods=['GET'])
        def get_agent_diagnostics(agent_key):
            """获取指定Agent的稳定快照诊断信息，不触发主动探测。"""
            try:
                project_id = str(request.args.get('project_id') or '').strip()
                if not project_id:
                    return jsonify({'error': 'project_id parameter is required'}), 400

                table_name = self.db_manager.get_table_name('agent_status')
                if self.db_manager.db_type == 'mysql':
                    row = self.db_manager.fetch_one(
                        f"""
                        SELECT agent_key, ip_address, hostname, project_id, status, last_seen, updated_at, pod_id
                        FROM {table_name}
                        WHERE agent_key = %s AND project_id = %s
                        LIMIT 1
                        """,
                        (agent_key, project_id)
                    )
                else:
                    row = self.db_manager.fetch_one(
                        f"""
                        SELECT agent_key, ip_address, hostname, project_id, status, last_seen, updated_at, pod_id
                        FROM {table_name}
                        WHERE agent_key = ? AND project_id = ?
                        LIMIT 1
                        """,
                        (agent_key, project_id)
                    )

                if not row:
                    return jsonify({'error': f'Agent {agent_key} not found in project {project_id}'}), 404

                def _parse_dt(value: Any) -> Optional[datetime]:
                    if not value:
                        return None
                    try:
                        dt = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
                        if dt.tzinfo is not None:
                            dt = dt.astimezone().replace(tzinfo=None)
                        return dt
                    except Exception:
                        return None

                def _pick_ts(item: Dict[str, Any]) -> Optional[datetime]:
                    observed = _parse_dt(item.get('observed_at'))
                    if observed:
                        return observed
                    return _parse_dt(item.get('created_at'))

                status = str(row.get('status') or 'unknown').lower()
                last_seen_text = str(row.get('last_seen')) if row.get('last_seen') else None
                updated_at_text = str(row.get('updated_at')) if row.get('updated_at') else None
                status_reason = ''
                if status == 'online':
                    latest_ref = self.agent_manager._latest_stale_reference(last_seen_text, updated_at_text)
                    if latest_ref:
                        try:
                            if datetime.now() - latest_ref > timedelta(minutes=5):
                                status_reason = '节点超过5分钟未上报心跳（提示），状态以后端实际写库为准'
                        except Exception:
                            status_reason = ''

                agent_snapshot = {
                    'key': row.get('agent_key'),
                    'project_id': row.get('project_id'),
                    'status': status,
                    'ip_address': row.get('ip_address'),
                    'hostname': row.get('hostname'),
                    'last_seen': last_seen_text,
                    'updated_at': updated_at_text,
                    'pod_id': row.get('pod_id'),
                    'status_reason': status_reason or None,
                }

                events = self.agent_manager.list_agent_status_history(project_id, agent_key, limit=100)
                latest_event = events[0] if events else None
                now = datetime.now()
                window_start = now - timedelta(hours=24)
                ups_24h = 0
                downs_24h = 0
                for item in events:
                    ts = _pick_ts(item)
                    if not ts or ts < window_start:
                        continue
                    to_online = str(item.get('edge_state_to') or '').lower() == 'online'
                    if to_online:
                        ups_24h += 1
                    else:
                        downs_24h += 1

                diagnostics = {
                    'project_id': project_id,
                    'agent_key': agent_key,
                    'generated_at': datetime.now().isoformat(),
                    'agent_snapshot': agent_snapshot,
                    'refresh_diag': self.agent_manager.get_last_refresh_diag(),
                    'list_diag': self.agent_manager.get_last_list_diag(),
                    'event_diag': {
                        'window_hours': 24,
                        'up_count_24h': ups_24h,
                        'down_count_24h': downs_24h,
                        'latest_event': latest_event,
                        'total_events': len(events),
                    },
                }
                return jsonify(diagnostics)
            except Exception as e:
                self.logger.error(f"获取Agent诊断信息失败: {str(e)}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/agents/<agent_key>/ingress/rebind', methods=['POST'])
        def rebind_agent_ingress_external_ip(agent_key):
            """手动触发指定Agent的Ingress外部IP重绑。"""
            try:
                data = request.get_json(silent=True) or {}
                agent_key = str(agent_key or '').strip()
                if not agent_key:
                    return jsonify({'error': 'agent_key is required'}), 400

                agent = self.agent_manager.get_agent(agent_key) or self.agent_manager.ensure_agent_exists(agent_key)
                if not agent:
                    return jsonify({'error': f'Agent {agent_key} not found'}), 404

                project_id = str(data.get('project_id') or getattr(agent, 'project_id', '') or '').strip()
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400

                target_ip = str(data.get('ip') or getattr(agent, 'ip_address', '') or '').strip()
                if not target_ip:
                    return jsonify({'error': 'target ip is required'}), 400

                summary = self._rebind_agent_ingress_external_ip(
                    project_id=project_id,
                    agent_key=agent_key,
                    new_ip=target_ip,
                    auth_header=request.headers.get('Authorization'),
                )
                self.logger.info(
                    f"manual_ingress_rebind agent={agent_key} project={project_id} "
                    f"new_ip={target_ip} target={summary.get('target_count')} "
                    f"success={summary.get('success_count')} fail={summary.get('fail_count')}"
                )
                return jsonify({
                    'message': 'ingress rebind completed',
                    **summary,
                }), 200 if int(summary.get('fail_count') or 0) == 0 else 207
            except Exception as e:
                self.logger.error(f"手动重绑Agent Ingress失败: {str(e)}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        def _normalize_task_payload(task: Dict) -> Dict:
            """标准化任务字段，兼容不同前端字段命名。"""
            if not task:
                return {}

            return {
                'id': task.get('task_id') or task.get('id'),
                'task_id': task.get('task_id') or task.get('id'),
                'type': task.get('task_type') or task.get('type'),
                'task_type': task.get('task_type') or task.get('type'),
                'status': task.get('status'),
                'service_name': task.get('service_name'),
                'agent_key': task.get('agent_key'),
                'project_id': task.get('project_id'),
                'progress': task.get('progress', 0),
                'message': task.get('message', ''),
                'create_time': task.get('created_at') or task.get('create_time'),
                'created_at': task.get('created_at') or task.get('create_time'),
                'started_at': task.get('started_at'),
                'completed_at': task.get('completed_at'),
                'log_count': task.get('log_count', 0),
            }

        def _normalize_task_log_payload(log: Dict) -> Dict:
            """标准化任务日志字段，兼容 `log` / `logs` 两种返回结构。"""
            if not log:
                return {}
            return {
                'id': log.get('log_id') or log.get('id'),
                'log_id': log.get('log_id') or log.get('id'),
                'task_id': log.get('task_id'),
                'timestamp': log.get('timestamp'),
                'level': log.get('level'),
                'message': log.get('message', ''),
            }

        @self.app.route('/api/agent/task', methods=['GET'])
        def list_tasks():
            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 20))
            task_type = request.args.get('type')
            status = request.args.get('status')
            project_id = request.args.get('project_id')
            agent_key = request.args.get('agent_key')

            # project_id is required
            if not project_id:
                return jsonify({'error': 'project_id parameter is required'}), 400

            tasks, total = self.task_manager.list_tasks(
                page, per_page, task_type, status, project_id, agent_key
            )
            normalized_tasks = [_normalize_task_payload(task) for task in tasks]

            return jsonify({
                'secflow_agent_tasks': normalized_tasks,
                'tasks': normalized_tasks,
                'task': normalized_tasks,
                'page': page,
                'per_page': per_page,
                'total': total,
                'project_id': project_id
            })

        @self.app.route('/api/agent/task', methods=['DELETE'])
        def clear_tasks():
            """按项目清空全部任务记录。"""
            project_id = request.args.get('project_id')
            if not project_id:
                return jsonify({'error': 'project_id parameter is required'}), 400

            deleted_count = self.task_manager.delete_tasks_by_project(project_id)
            return jsonify({
                'message': f'项目任务记录已清空: {deleted_count}',
                'project_id': project_id,
                'deleted_count': deleted_count
            })

        @self.app.route('/api/agent/task/<task_id>', methods=['GET'])
        def get_task(task_id):
            # Get project_id from query parameter
            project_id = request.args.get('project_id')
            if not project_id:
                return jsonify({'error': 'project_id parameter is required'}), 400

            task = self.task_manager.get_task(task_id)
            if not task:
                return jsonify({'error': '任务不存在'}), 404

            # Verify the task belongs to the requested project
            if task.get('project_id') != project_id:
                return jsonify({'error': f'Task {task_id} does not belong to project {project_id}'}), 403

            task_data = _normalize_task_payload(task)
            task_data['requested_project_id'] = project_id
            return jsonify(task_data)

        @self.app.route('/api/agent/task/<task_id>/logs', methods=['GET'])
        def get_secflow_agent_task_logs(task_id):
            # Get project_id from query parameter
            project_id = request.args.get('project_id')
            if not project_id:
                return jsonify({'error': 'project_id parameter is required'}), 400

            # Verify the task belongs to the requested project
            task = self.task_manager.get_task(task_id)
            if not task:
                return jsonify({'error': '任务不存在'}), 404
            if task.get('project_id') != project_id:
                return jsonify({'error': f'Task {task_id} does not belong to project {project_id}'}), 403

            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 100))

            logs, total = self.task_manager.get_secflow_agent_task_logs(task_id, page, per_page)
            normalized_logs = [_normalize_task_log_payload(log) for log in logs]

            return jsonify({
                'logs': normalized_logs,
                'log': normalized_logs,
                'task_id': task_id,
                'project_id': project_id,
                'page': page,
                'per_page': per_page,
                'total': total
            })

        @self.app.route('/api/agent/task/<task_id>', methods=['DELETE'])
        def delete_task(task_id):
            # Get project_id from query parameter
            project_id = request.args.get('project_id')
            if not project_id:
                return jsonify({'error': 'project_id parameter is required'}), 400

            # Verify the task belongs to the requested project
            task = self.task_manager.get_task(task_id)
            if not task:
                return jsonify({'error': '任务不存在'}), 404
            if task.get('project_id') != project_id:
                return jsonify({'error': f'Task {task_id} does not belong to project {project_id}'}), 403

            if self.task_manager.delete_task(task_id):
                return jsonify({
                    'message': '任务删除成功',
                    'task_id': task_id,
                    'project_id': project_id
                })
            else:
                return jsonify({'error': '任务删除失败'}), 500

        @self.app.route('/api/agent/task/deploy', methods=['POST'])
        def deploy_service():
            data = request.get_json()
            if not data or 'service_name' not in data or 'agent_key' not in data or 'template_name' not in data:
                return jsonify({'error': '服务名称、Agent和模板名称不能为空'}), 400

            project_id = data.get('project_id')
            if not project_id:
                return jsonify({'error': 'project_id不能为空'}), 400

            # Validate that agent belongs to the project
            agent = self.agent_manager.get_agent(data['agent_key']) or self.agent_manager.ensure_agent_exists(data['agent_key'])
            if not agent:
                return jsonify({'error': f"Agent {data['agent_key']} 不存在"}), 404
            if agent.project_id != project_id:
                return jsonify({'error': f"Agent {data['agent_key']} 不属于项目 {project_id}"}), 403

            lock_key = self._deploy_lock_key(project_id, data['agent_key'], data['service_name'], 'deploy')
            with self.redis_manager.get_lock(lock_key, timeout=int(self.config.get('lock_timeout', 30))) as lock:
                if not lock.is_acquired():
                    return jsonify({'error': '部署请求正在处理中，请稍后重试', 'code': 'LOCK_NOT_ACQUIRED'}), 409

                duplicate = self._check_deploy_duplicate(
                    data['service_name'], data['agent_key'], project_id
                )
                if duplicate:
                    return jsonify({
                        'error': duplicate.get('message') or '重复部署被拒绝',
                        'code': 'DUPLICATE_DEPLOYMENT',
                        'details': duplicate
                    }), 409

                prepared_extra_params = self._prepare_deploy_extra_params(
                    project_id,
                    data['template_name'],
                    data.get('extra_params'),
                )
                task_id = self.task_manager.create_task(
                    'deploy', data['service_name'], data['agent_key'],
                    data['template_name'], prepared_extra_params, project_id
                )

            return jsonify({
                'task_id': task_id,
                'message': '部署任务已创建',
                'project_id': project_id
            }), 202

        @self.app.route('/api/agent/task/deploy/batch', methods=['POST'])
        def deploy_service_batch():
            data = request.get_json()
            if not data:
                return jsonify({'error': '请求体不能为空'}), 400

            project_id = data.get('project_id')
            if not project_id:
                return jsonify({'error': 'project_id不能为空'}), 400

            deployments = data.get('deployments')
            if not isinstance(deployments, list) or len(deployments) == 0:
                return jsonify({'error': 'deployments不能为空，且必须为数组'}), 400

            results = []
            errors = []
            request_level_seen = set()

            for idx, item in enumerate(deployments):
                if not isinstance(item, dict):
                    errors.append({
                        'index': idx,
                        'error': '部署项必须为对象'
                    })
                    continue

                service_name = item.get('service_name')
                agent_key = item.get('agent_key')
                template_name = item.get('template_name')
                extra_params = item.get('extra_params')

                if not service_name or not agent_key or not template_name:
                    errors.append({
                        'index': idx,
                        'service_name': service_name,
                        'agent_key': agent_key,
                        'template_name': template_name,
                        'error': 'service_name、agent_key、template_name不能为空'
                    })
                    continue

                # Validate that agent belongs to the project
                agent = self.agent_manager.get_agent(agent_key) or self.agent_manager.ensure_agent_exists(agent_key)
                if not agent:
                    errors.append({
                        'index': idx,
                        'service_name': service_name,
                        'agent_key': agent_key,
                        'template_name': template_name,
                        'error': f"Agent {agent_key} 不存在"
                    })
                    continue
                if agent.project_id != project_id:
                    errors.append({
                        'index': idx,
                        'service_name': service_name,
                        'agent_key': agent_key,
                        'template_name': template_name,
                        'error': f"Agent {agent_key} 不属于项目 {project_id}"
                    })
                    continue

                dedup_key = f"{project_id}::{agent_key}::{service_name}"
                if dedup_key in request_level_seen:
                    errors.append({
                        'index': idx,
                        'service_name': service_name,
                        'agent_key': agent_key,
                        'template_name': template_name,
                        'code': 'DUPLICATE_DEPLOYMENT',
                        'error': f"请求中存在重复部署项: {service_name} on {agent_key}"
                    })
                    continue
                request_level_seen.add(dedup_key)

                try:
                    lock_key = self._deploy_lock_key(project_id, agent_key, service_name, 'deploy')
                    with self.redis_manager.get_lock(lock_key, timeout=int(self.config.get('lock_timeout', 30))) as lock:
                        if not lock.is_acquired():
                            errors.append({
                                'index': idx,
                                'service_name': service_name,
                                'agent_key': agent_key,
                                'template_name': template_name,
                                'code': 'LOCK_NOT_ACQUIRED',
                                'error': '部署请求正在处理中，请稍后重试'
                            })
                            continue

                        duplicate = self._check_deploy_duplicate(service_name, agent_key, project_id)
                        if duplicate:
                            errors.append({
                                'index': idx,
                                'service_name': service_name,
                                'agent_key': agent_key,
                                'template_name': template_name,
                                'code': 'DUPLICATE_DEPLOYMENT',
                                'error': duplicate.get('message') or '重复部署被拒绝',
                                'details': duplicate
                            })
                            continue

                        prepared_extra_params = self._prepare_deploy_extra_params(
                            project_id,
                            template_name,
                            extra_params,
                        )
                        task_id = self.task_manager.create_task(
                            'deploy', service_name, agent_key, template_name, prepared_extra_params, project_id
                        )
                    results.append({
                        'index': idx,
                        'task_id': task_id,
                        'service_name': service_name,
                        'agent_key': agent_key,
                        'template_name': template_name
                    })
                except Exception as e:
                    errors.append({
                        'index': idx,
                        'service_name': service_name,
                        'agent_key': agent_key,
                        'template_name': template_name,
                        'error': str(e)
                    })

            success_count = len(results)
            failed_count = len(errors)
            total = len(deployments)
            status_code = 202 if failed_count == 0 else 207

            return jsonify({
                'message': f'批量部署请求处理完成: 成功 {success_count}，失败 {failed_count}',
                'project_id': project_id,
                'total': total,
                'success_count': success_count,
                'failed_count': failed_count,
                'tasks': results,
                'errors': errors
            }), status_code

        @self.app.route('/api/agent/task/undeploy', methods=['POST'])
        def undeploy_service():
            data = request.get_json()
            if not data or 'service_name' not in data or 'agent_key' not in data:
                return jsonify({'error': '服务名称和Agent不能为空'}), 400

            project_id = data.get('project_id')
            if not project_id:
                return jsonify({'error': 'project_id不能为空'}), 400

            # Validate that agent belongs to the project
            agent = self.agent_manager.get_agent(data['agent_key']) or self.agent_manager.ensure_agent_exists(data['agent_key'])
            if not agent:
                return jsonify({'error': f"Agent {data['agent_key']} 不存在"}), 404
            if agent.project_id != project_id:
                return jsonify({'error': f"Agent {data['agent_key']} 不属于项目 {project_id}"}), 403

            lock_key = self._deploy_lock_key(project_id, data['agent_key'], data['service_name'], 'undeploy')
            with self.redis_manager.get_lock(lock_key, timeout=int(self.config.get('lock_timeout', 30))) as lock:
                if not lock.is_acquired():
                    return jsonify({'error': '卸载请求正在处理中，请稍后重试', 'code': 'LOCK_NOT_ACQUIRED'}), 409

                task_id = self.task_manager.create_task(
                    'undeploy', data['service_name'], data['agent_key'],
                    None, None, project_id
                )

            return jsonify({
                'task_id': task_id,
                'message': '卸载任务已创建',
                'project_id': project_id
            }), 202

        # ===================== 代理路由（修复版，支持长超时） =====================
        @self.app.route('/api/agent/proxy/<agent_key>/<path:action_path>',
                        methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
        def proxy_to_agent(agent_key, action_path):
            """将请求代理到指定的Agent（修复版，支持长超时）"""
            try:
                # 获取请求方法
                method = request.method

                # 获取查询参数
                query_params = {}
                for key, value in request.args.items():
                    if key not in query_params:
                        query_params[key] = value
                    elif isinstance(query_params[key], list):
                        query_params[key].append(value)
                    else:
                        query_params[key] = [query_params[key], value]

                # 获取请求头（过滤敏感头）
                headers_to_forward = {}
                exclude_headers = [
                    'host', 'authorization', 'cookie', 'connection',
                    'content-length', 'content-type', 'accept-encoding',
                    'accept', 'user-agent'
                ]

                for key, value in request.headers:
                    key_lower = key.lower()
                    if key_lower not in exclude_headers:
                        headers_to_forward[key] = value

                # 处理请求数据 - 修复JSON解析问题
                request_data = None
                files_to_forward = {}

                content_type = request.headers.get('Content-Type', '').lower()

                # 检查是否是文件上传
                if 'multipart/form-data' in content_type and request.files:
                    # 处理文件上传
                    for key, file_storage in request.files.items():
                        file_content = file_storage.read()
                        files_to_forward[key] = (
                            file_storage.filename,
                            file_content,
                            file_storage.content_type
                        )
                        file_storage.seek(0)

                    # 处理普通表单字段
                    if request.form:
                        request_data = dict(request.form)

                # 检查是否有JSON数据
                elif 'application/json' in content_type:
                    # 安全地解析JSON，避免空请求体错误
                    if request.data:
                        try:
                            request_data = request.get_json()
                        except Exception as e:
                            self.logger.warning(f"JSON解析失败，使用原始数据: {e}")
                            try:
                                # 尝试直接解析
                                request_data = json.loads(request.data.decode('utf-8'))
                            except:
                                request_data = request.data.decode('utf-8')

                # 检查普通表单数据
                elif request.form:
                    request_data = dict(request.form)

                # 检查原始数据
                elif request.data:
                    try:
                        request_data = json.loads(request.data.decode('utf-8'))
                    except:
                        request_data = request.data.decode('utf-8')

                # 检查是否是流式请求
                stream = request.args.get('stream', '').lower() == 'true'

                # 构建endpoint
                if not action_path.startswith('/'):
                    action_path = '/' + action_path

                # 设置超时时间（优先使用查询参数中的timeout，否则使用默认）
                timeout = request.args.get('timeout', None)
                if timeout is not None:
                    try:
                        timeout = int(timeout)
                    except:
                        timeout = None

                # 调用代理管理器
                status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                    agent_key=agent_key,
                    method=method,
                    endpoint=action_path,
                    request_data=request_data,
                    query_params=query_params,
                    headers=headers_to_forward,
                    files=files_to_forward if files_to_forward else None,
                    stream=stream,
                    timeout=timeout
                )

                # 处理流式响应
                if stream and isinstance(response_data, bytes):
                    response = self.app.response_class(
                        response_data,
                        status=status_code,
                        headers=response_headers,
                        mimetype=response_headers.get('Content-Type', 'application/octet-stream')
                    )
                    return response

                # 构建普通响应
                if isinstance(response_data, bytes):
                    response = self.app.response_class(
                        response_data,
                        status=status_code,
                        headers=response_headers
                    )
                    return response
                elif isinstance(response_data, str):
                    response = self.app.response_class(
                        response_data,
                        status=status_code,
                        headers=response_headers,
                        content_type='text/plain'
                    )
                    return response
                else:
                    response = jsonify(response_data)
                    response.status_code = status_code
                    for key, value in response_headers.items():
                        if key.lower() == 'Content-Length'.lower():
                            continue
                        response.headers[key] = value

                    return response

            except Exception as e:
                self.logger.error(f"代理路由处理失败: {str(e)}", exc_info=True)
                return jsonify({
                    'error': 'Proxy request failed',
                    'message': str(e),
                    'timestamp': datetime.now().isoformat(),
                    'agent_key': agent_key,
                    'action_path': action_path
                }), 500

        # 简单代理端点 - 专门用于GET请求
        @self.app.route('/api/agent/proxy_simple/<agent_key>/<path:action_path>', methods=['GET'])
        def proxy_simple_to_agent(agent_key, action_path):
            """简单代理到指定的Agent（仅GET请求）"""
            try:
                # 获取Agent信息
                agent = self.agent_manager.get_agent(agent_key)
                if not agent:
                    return jsonify({'error': f'Agent {agent_key} not found'}), 404

                if not action_path.startswith('/'):
                    action_path = '/' + action_path

                # 构建URL
                url = f"http://{agent.ip_address}:{self.agent_manager.agent_api_port}{action_path}"

                # 发送GET请求
                response = requests.get(
                    url,
                    headers={'X-Auth-Token': self.agent_manager.agent_auth_token},
                    params=request.args,
                    timeout=10,
                    verify=False
                )

                # 处理响应
                try:
                    data = response.json()
                except:
                    data = {'content': response.text}

                return jsonify({
                    'status_code': response.status_code,
                    'data': data,
                    'agent': {
                        'key': agent_key,
                        'hostname': agent.hostname,
                        'ip': agent.ip_address
                    }
                })

            except Exception as e:
                self.logger.error(f"简单代理失败: {str(e)}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/agent/<agent_key>/<path:action_path>',
                        methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
        def agent_proxy_simple(agent_key, action_path):
            """简化版代理路由，自动添加/api前缀"""
            # 确保action_path以/开头
            if not action_path.startswith('/'):
                action_path = '/' + action_path

            # 添加/api前缀（如果还没有）
            if not action_path.startswith('/api/'):
                action_path = '/api' + action_path

            # 重定向到通用代理
            return proxy_to_agent(agent_key, action_path)

        @self.app.route('/api/agent/agent/<agent_key>/system/info', methods=['GET'])
        def agent_system_info(agent_key):
            """获取Agent的系统信息（快捷方式）"""
            status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                agent_key=agent_key,
                method='GET',
                endpoint='/api/system/info'
            )

            response = jsonify(response_data)
            for key, value in response_headers.items():
                if key.lower() == 'Content-Length'.lower():
                    continue
                response.headers[key] = value
            response.status_code = status_code

            return response

        @self.app.route('/api/agent/agent/<agent_key>/services', methods=['GET'])
        def agent_services(agent_key):
            """获取Agent的服务列表（快捷方式）"""
            status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                agent_key=agent_key,
                method='GET',
                endpoint='/api/services'
            )

            response = jsonify(response_data)
            for key, value in response_headers.items():
                if key.lower() == 'Content-Length'.lower():
                    continue
                response.headers[key] = value
            response.status_code = status_code

            return response

        @self.app.route('/api/agent/agent/<agent_key>/services/<service_name>', methods=['GET'])
        def agent_service_detail(agent_key, service_name):
            """获取Agent单个服务详情（快捷方式）"""
            status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                agent_key=agent_key,
                method='GET',
                endpoint=f'/api/services/{quote(service_name, safe="")}'
            )
            response = jsonify(response_data)
            for key, value in response_headers.items():
                if key.lower() == 'content-length':
                    continue
                response.headers[key] = value
            response.status_code = status_code
            return response

        @self.app.route('/api/agent/agent/<agent_key>/services/<service_name>/logs', methods=['GET'])
        def agent_service_logs(agent_key, service_name):
            """获取Agent服务日志（快捷方式）"""
            tail = int(request.args.get('tail', 200))
            status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                agent_key=agent_key,
                method='GET',
                endpoint=f'/api/services/{quote(service_name, safe="")}/logs',
                query_params={'tail': tail}
            )
            response = jsonify(response_data)
            for key, value in response_headers.items():
                if key.lower() == 'content-length':
                    continue
                response.headers[key] = value
            response.status_code = status_code
            return response

        @self.app.route('/api/agent/agent/<agent_key>/services/<service_name>/files', methods=['GET'])
        def agent_service_files(agent_key, service_name):
            """获取Agent服务文件列表（快捷方式）"""
            status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                agent_key=agent_key,
                method='GET',
                endpoint=f'/api/services/{quote(service_name, safe="")}/files'
            )
            response = jsonify(response_data)
            for key, value in response_headers.items():
                if key.lower() == 'content-length':
                    continue
                response.headers[key] = value
            response.status_code = status_code
            return response

        @self.app.route('/api/agent/agent/<agent_key>/services/<service_name>/start', methods=['POST'])
        def agent_service_start(agent_key, service_name):
            """启动Agent服务（快捷方式）"""
            status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                agent_key=agent_key,
                method='POST',
                endpoint=f'/api/services/{quote(service_name, safe="")}/start',
                request_data=request.get_json(silent=True) or {}
            )
            if status_code < 300:
                try:
                    self._sync_single_agent_services_by_key(agent_key, reason=f'api_start:{service_name}')
                except Exception:
                    self.logger.warning(f"启动服务后同步快照失败: agent={agent_key}, service={service_name}", exc_info=True)
            response = jsonify(response_data)
            for key, value in response_headers.items():
                if key.lower() == 'content-length':
                    continue
                response.headers[key] = value
            response.status_code = status_code
            return response

        @self.app.route('/api/agent/agent/<agent_key>/services/<service_name>/stop', methods=['POST'])
        def agent_service_stop(agent_key, service_name):
            """停止Agent服务（快捷方式）"""
            status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                agent_key=agent_key,
                method='POST',
                endpoint=f'/api/services/{quote(service_name, safe="")}/stop',
                request_data=request.get_json(silent=True) or {}
            )
            if status_code < 300 or self._can_ignore_stop_response(status_code, response_data):
                try:
                    self._sync_single_agent_services_by_key(agent_key, reason=f'api_stop:{service_name}')
                except Exception:
                    self.logger.warning(f"停止服务后同步快照失败: agent={agent_key}, service={service_name}", exc_info=True)
            response = jsonify(response_data)
            for key, value in response_headers.items():
                if key.lower() == 'content-length':
                    continue
                response.headers[key] = value
            response.status_code = status_code
            return response

        @self.app.route('/api/agent/agent/<agent_key>/services/<service_name>/update', methods=['POST'])
        def agent_service_update(agent_key, service_name):
            """更新Agent服务镜像并重启（快捷方式）"""
            request_data = request.get_json(silent=True) or {}
            encoded_service_name = quote(service_name, safe="")
            status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                agent_key=agent_key,
                method='POST',
                endpoint=f'/api/services/{encoded_service_name}/update',
                request_data=request_data
            )

            fallback_used = False
            if status_code == 404:
                # 兼容旧helper：无update接口时自动降级到restart。
                fallback_used = True
                status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                    agent_key=agent_key,
                    method='POST',
                    endpoint=f'/api/services/{encoded_service_name}/restart',
                    request_data=request_data
                )
                if isinstance(response_data, dict):
                    response_data = dict(response_data)
                    response_data['fallback'] = 'restart'
                    response_data['fallback_reason'] = 'helper_update_endpoint_not_found'

            if status_code < 300:
                try:
                    reason = f'api_update:{service_name}'
                    if fallback_used:
                        reason = f'api_update_fallback_restart:{service_name}'
                    self._sync_single_agent_services_by_key(agent_key, reason=reason)
                except Exception:
                    self.logger.warning(f"更新服务后同步快照失败: agent={agent_key}, service={service_name}", exc_info=True)

            response = jsonify(response_data)
            for key, value in response_headers.items():
                if key.lower() == 'content-length':
                    continue
                response.headers[key] = value
            response.status_code = status_code
            return response

        @self.app.route('/api/agent/agent/<agent_key>/services/<service_name>', methods=['DELETE'])
        def agent_service_delete(agent_key, service_name):
            """删除Agent服务：先停服务，再删服务，并同步删除绑定的Ingress。"""
            try:
                agent = self.agent_manager.get_agent(agent_key) or self.agent_manager.ensure_agent_exists(agent_key)
                if not agent:
                    return jsonify({'error': f'Agent {agent_key} not found'}), 404

                project_id = str(request.args.get('project_id') or getattr(agent, 'project_id', '') or '').strip()
                if not project_id:
                    return jsonify({'error': 'project_id parameter is required'}), 400
                if str(getattr(agent, 'project_id', '') or '').strip() != project_id:
                    return jsonify({'error': f'Agent {agent_key} does not belong to project {project_id}'}), 403

                encoded_service_name = quote(service_name, safe="")
                service_status_code, service_payload = self.agent_manager.call_agent_api(
                    agent_key,
                    'GET',
                    f'/api/services/{encoded_service_name}',
                    None,
                    timeout_type='health_check'
                )

                runtime_state = self._extract_service_runtime_state(service_payload)
                stop_result: Dict[str, Any] = {
                    'attempted': False,
                    'status_code': None,
                    'response': None,
                }
                if service_status_code == 200 and not self._is_service_stopped_state(runtime_state):
                    stop_result['attempted'] = True
                    stop_status_code, stop_payload = self.agent_manager.call_agent_api(
                        agent_key,
                        'POST',
                        f'/api/services/{encoded_service_name}/stop',
                        {},
                        timeout_type='undeploy'
                    )
                    stop_result['status_code'] = stop_status_code
                    stop_result['response'] = stop_payload
                    if not self._can_ignore_stop_response(stop_status_code, stop_payload):
                        return jsonify({
                            'error': f'停止服务失败，无法继续删除: {service_name}',
                            'code': 'STOP_BEFORE_DELETE_FAILED',
                            'details': stop_result
                        }), 409

                delete_status_code, delete_payload = self.agent_manager.call_agent_api(
                    agent_key,
                    'DELETE',
                    f'/api/services/{encoded_service_name}',
                    {},
                    timeout_type='undeploy'
                )
                if delete_status_code not in (200, 204, 404):
                    return jsonify({
                        'error': f'删除服务失败: {service_name}',
                        'code': 'DELETE_SERVICE_FAILED',
                        'details': {
                            'status_code': delete_status_code,
                            'response': delete_payload,
                        }
                    }), delete_status_code

                binding_table = self.db_manager.get_table_name('service_template_bindings')
                try:
                    self.db_manager.execute_query(
                        f"DELETE FROM {binding_table} WHERE project_id = %s AND agent_key = %s AND service_name = %s"
                        if self.db_manager.db_type == 'mysql' else
                        f"DELETE FROM {binding_table} WHERE project_id = ? AND agent_key = ? AND service_name = ?",
                        (project_id, agent_key, service_name)
                    )
                except Exception:
                    self.logger.warning(f"删除服务模板绑定失败: project={project_id}, agent={agent_key}, service={service_name}", exc_info=True)

                auth_header = request.headers.get('Authorization')
                ingress_cleanup = self._delete_service_bound_ingress_routes(
                    project_id=project_id,
                    agent_key=agent_key,
                    service_name=service_name,
                    auth_header=auth_header
                )

                try:
                    self._sync_single_agent_services_by_key(agent_key, reason=f'api_delete:{service_name}')
                except Exception:
                    self.logger.warning(f"删除服务后同步快照失败: agent={agent_key}, service={service_name}", exc_info=True)

                response_status = 200 if len(ingress_cleanup.get('failed', [])) == 0 else 207
                return jsonify({
                    'message': f'服务 {service_name} 删除完成',
                    'agent_key': agent_key,
                    'project_id': project_id,
                    'service_name': service_name,
                    'service_status_before_delete': runtime_state or ('missing' if service_status_code == 404 else 'unknown'),
                    'service_deleted': True,
                    'service_delete_status_code': delete_status_code,
                    'stop_result': stop_result,
                    'ingress_cleanup': ingress_cleanup,
                }), response_status
            except Exception as e:
                self.logger.error(f"删除Agent服务失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/agent/<agent_key>/services/<service_name>/exec', methods=['POST'])
        def agent_service_exec(agent_key, service_name):
            """在Agent服务容器内执行命令（快捷方式）"""
            payload = request.get_json(silent=True) or {}
            status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                agent_key=agent_key,
                method='POST',
                endpoint=f'/api/services/{quote(service_name, safe="")}/exec',
                request_data=payload
            )
            response = jsonify(response_data)
            for key, value in response_headers.items():
                if key.lower() == 'content-length':
                    continue
                response.headers[key] = value
            response.status_code = status_code
            return response

        @self.app.route('/api/agent/agent/<agent_key>/services/<service_name>/exec/ws-connection', methods=['GET'])
        def agent_service_exec_ws_connection(agent_key, service_name):
            """获取服务容器实时执行WS连接信息。"""
            try:
                project_id = request.args.get('project_id')
                container_name = request.args.get('container', '')
                shell = request.args.get('shell', '/bin/sh')
                mode = request.args.get('mode', 'shell')
                user = request.args.get('user', '')

                agent = self.agent_manager.get_agent(agent_key)
                if not agent:
                    return jsonify({'error': f'Agent {agent_key} not found'}), 404

                if project_id and agent.project_id != project_id:
                    return jsonify({'error': f'Agent {agent_key} does not belong to project {project_id}'}), 403

                if agent.status != 'online':
                    return jsonify({'error': f'Agent {agent_key} is {agent.status}'}), 503

                # 预先校验服务是否存在，避免前端拿到ws_url后立刻1005断开却看不到具体原因。
                service_status, service_payload = self.agent_manager.call_agent_api(
                    agent_key,
                    'GET',
                    f'/api/services/{quote(service_name, safe="")}',
                    None,
                    timeout_type='health_check'
                )
                if service_status != 200:
                    detail = ''
                    if isinstance(service_payload, dict):
                        detail = str(service_payload.get('error') or service_payload.get('message') or '')
                    elif isinstance(service_payload, str):
                        detail = service_payload
                    msg = f'服务不存在或不可访问: {service_name}'
                    if detail:
                        msg = f'{msg} ({detail})'
                    return jsonify({
                        'error': msg,
                        'agent_key': agent_key,
                        'service_name': service_name,
                        'upstream_status': service_status
                    }), 404

                supported, probe_status, probe_detail = self._probe_agent_exec_ws_capability(
                    agent, service_name, container_name, shell, mode, user
                )
                if not supported:
                    return jsonify({
                        'error': '当前Agent未提供服务终端WS接口，无法建立实时终端连接',
                        'agent_key': agent_key,
                        'service_name': service_name,
                        'agent_ip': agent.ip_address,
                        'upstream_status': probe_status,
                        'upstream_detail': probe_detail
                    }), 400

                tunnel_query = {
                    'project_id': project_id or '',
                    'container': container_name,
                    'shell': shell,
                    'mode': mode
                }
                if user:
                    tunnel_query['user'] = user

                ws_scheme = self._resolve_request_ws_scheme()
                host = self._resolve_request_host()
                tunnel_path = f"/api/agent/agent/{quote(agent_key, safe='')}/services/{quote(service_name, safe='')}/exec/ws-tunnel"
                tunnel_ws_url = f"{ws_scheme}://{host}{tunnel_path}?{urlencode(tunnel_query)}"

                direct_query = {
                    'token': self.agent_manager.agent_auth_token,
                    'container': container_name,
                    'shell': shell,
                    'mode': mode
                }
                if user:
                    direct_query['user'] = user

                direct_ws_url = (
                    f"ws://{agent.ip_address}:{self.agent_manager.agent_api_port}"
                    f"/api/services/{quote(service_name, safe='')}/exec/ws?{urlencode(direct_query)}"
                )

                ingress_ws_url = None
                ingress_http_url = None
                ingress_route = None
                auth_header = request.headers.get('Authorization')
                if project_id:
                    try:
                        ingress_route = self._ensure_agent_console_ingress_route(
                            project_id=project_id,
                            agent=agent,
                            target_port=int(self.agent_manager.agent_api_port),
                            auth_header=auth_header
                        )
                        if ingress_route and str(ingress_route.get('status') or '').lower() == 'ready':
                            route_host = str(ingress_route.get('host') or '').strip()
                            access_url = str(ingress_route.get('access_url') or '').strip()
                            route_path = str(ingress_route.get('path') or '/').strip() or '/'
                            ingress_http_url = access_url or (f"https://{route_host}{route_path}" if route_host else None)
                            if route_host:
                                route_ws_scheme = 'wss' if bool(ingress_route.get('tls_enabled')) or access_url.startswith('https://') else 'ws'
                                ingress_ws_url = (
                                    f"{route_ws_scheme}://{route_host}"
                                    f"/api/services/{quote(service_name, safe='')}/exec/ws?{urlencode(direct_query)}"
                                )
                    except Exception as e:
                        self.logger.warning(f"查询/创建Agent ingress路由失败，回退平台WS中转: agent={agent_key}, err={e}")

                ws_url = ingress_ws_url or tunnel_ws_url
                note = (
                    '终端连接优先使用Agent Ingress直连通道（browser -> agent ingress -> agent）。'
                    if ingress_ws_url else
                    '终端连接使用平台内置WS中转通道（browser -> platform-agent -> agent），支持HTTP/HTTPS。'
                )

                return jsonify({
                    'agent_key': agent_key,
                    'agent_ip': agent.ip_address,
                    'agent_status': agent.status,
                    'service_name': service_name,
                    'project_id': project_id,
                    'container': container_name,
                    'shell': shell,
                    'mode': mode,
                    'user': user,
                    'ws_url': ws_url,
                    'direct_ws_url': direct_ws_url,
                    'ingress_ws_url': ingress_ws_url,
                    'ingress_http_url': ingress_http_url,
                    'ingress_route': ingress_route,
                    'rest_exec_url': f"/api/agent/agent/{agent_key}/services/{quote(service_name, safe='')}/exec",
                    'note': note
                })
            except Exception as e:
                self.logger.error(f"获取服务Exec WS连接信息失败: {str(e)}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/agent/<agent_key>/services/<service_name>/exec/ws-tunnel', methods=['GET'])
        def agent_service_exec_ws_tunnel(agent_key, service_name):
            """服务终端WebSocket中转说明入口（真正的WS升级由专用WebSocket应用处理）"""
            return jsonify({
                'error': 'WebSocket upgrade required',
                'message': '请通过WebSocket连接访问该地址',
                'path': f"/api/agent/agent/{agent_key}/services/{service_name}/exec/ws-tunnel"
            }), 426

        @self.app.route('/api/agent/services/global', methods=['GET'])
        def list_global_services():
            """聚合查询项目下所有Agent服务（不再前端逐个Agent拉取）。"""
            try:
                project_id = request.args.get('project_id')
                if not project_id:
                    return jsonify({'error': 'project_id parameter is required'}), 400

                page = max(int(request.args.get('page', 1)), 1)
                per_page = min(max(int(request.args.get('per_page', 50)), 1), 1000)
                status = request.args.get('status')
                agent_key = request.args.get('agent_key')
                q = (request.args.get('q') or '').strip()
                include_stale = request.args.get('include_stale', 'false').lower() == 'true'

                table_name = self.db_manager.get_table_name('agent_services')
                where_clauses = ["project_id = " + ("%s" if self.db_manager.db_type == 'mysql' else "?")]
                params: List[Any] = [project_id]

                if status:
                    where_clauses.append("status = " + ("%s" if self.db_manager.db_type == 'mysql' else "?"))
                    params.append(status)
                if agent_key:
                    where_clauses.append("agent_key = " + ("%s" if self.db_manager.db_type == 'mysql' else "?"))
                    params.append(agent_key)
                if q:
                    keyword = f"%{q}%"
                    like_placeholder = "%s" if self.db_manager.db_type == 'mysql' else "?"
                    where_clauses.append(
                        f"(service_name LIKE {like_placeholder} OR images_json LIKE {like_placeholder} OR agent_hostname LIKE {like_placeholder})"
                    )
                    params.extend([keyword, keyword, keyword])
                if not include_stale:
                    where_clauses.append("is_stale = 0")

                where_sql = " AND ".join(where_clauses)
                count_sql = f"SELECT COUNT(*) as count FROM {table_name} WHERE {where_sql}"
                count_result = self.db_manager.fetch_one(count_sql, tuple(params))
                total = int(count_result.get('count', 0) if count_result else 0)

                query_sql = f'''
                    SELECT service_uid, project_id, agent_key, agent_hostname, agent_ip,
                           service_name, images_json, status, tags_json, ports_json, raw_json, source, is_stale,
                           first_seen_at, last_seen_at, updated_at
                    FROM {table_name}
                    WHERE {where_sql}
                    ORDER BY last_seen_at DESC
                '''
                offset = (page - 1) * per_page
                if self.db_manager.db_type == 'mysql':
                    query_sql += " LIMIT %s OFFSET %s"
                else:
                    query_sql += " LIMIT ? OFFSET ?"
                rows = self.db_manager.fetch_all(query_sql, tuple(params + [per_page, offset]))

                # 预加载模板映射：只使用部署时记录或Agent显式上报的模板信息，不再依赖名称/镜像猜测
                template_table = self.db_manager.get_table_name('service_templates')
                template_rows = self.db_manager.fetch_all(
                    f"SELECT id, name, metadata FROM {template_table} ORDER BY id ASC",
                    tuple()
                ) or []
                templates_by_name: Dict[str, Dict[str, Any]] = {}
                for tpl in template_rows:
                    tpl_name = str(tpl.get('name') or '').strip()
                    if not tpl_name:
                        continue
                    metadata = tpl.get('metadata')
                    if isinstance(metadata, str):
                        try:
                            metadata = json.loads(metadata)
                        except Exception:
                            metadata = {}
                    elif not isinstance(metadata, dict):
                        metadata = {}
                    template_tags = self._normalize_service_tags((metadata or {}).get('tags'))
                    templates_by_name[tpl_name] = {
                        'id': tpl.get('id'),
                        'name': tpl_name,
                        'template_tags': template_tags,
                    }

                binding_table = self.db_manager.get_table_name('service_template_bindings')
                binding_rows = self.db_manager.fetch_all(
                    f"SELECT project_id, agent_key, service_name, template_id, template_name FROM {binding_table} WHERE project_id = %s"
                    if self.db_manager.db_type == 'mysql' else
                    f"SELECT project_id, agent_key, service_name, template_id, template_name FROM {binding_table} WHERE project_id = ?",
                    (project_id,)
                ) or []
                bindings_map: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
                for row in binding_rows:
                    key = (
                        str(row.get('project_id') or '').strip(),
                        str(row.get('agent_key') or '').strip(),
                        str(row.get('service_name') or '').strip()
                    )
                    bindings_map[key] = {
                        'template_id': row.get('template_id'),
                        'template_name': str(row.get('template_name') or '').strip()
                    }

                task_table = self.db_manager.get_table_name('tasks')

                def _resolve_template(project_id_value: str, agent_key_value: str, service_name: str, raw_payload: Any = None) -> Dict[str, Any]:
                    key = (
                        str(project_id_value or '').strip(),
                        str(agent_key_value or '').strip(),
                        str(service_name or '').strip()
                    )

                    binding = bindings_map.get(key)
                    if binding and str(binding.get('template_name') or '').strip():
                        template_name = str(binding.get('template_name') or '').strip()
                        known_template = templates_by_name.get(template_name) or {}
                        return {
                            'template_id': binding.get('template_id'),
                            'template_name': template_name,
                            'template_tags': self._normalize_service_tags(known_template.get('template_tags')),
                        }

                    payload = raw_payload if isinstance(raw_payload, dict) else {}
                    payload_template_name = str(payload.get('template_name') or '').strip()
                    payload_template_id = payload.get('template_id')
                    if payload_template_name:
                        known_template = templates_by_name.get(payload_template_name)
                        resolved = {
                            'template_id': payload_template_id if payload_template_id not in (None, '') else (known_template or {}).get('id'),
                            'template_name': payload_template_name,
                            'template_tags': self._normalize_service_tags((known_template or {}).get('template_tags')),
                        }
                        bindings_map[key] = resolved
                        try:
                            self.db_manager.execute_query(
                                f"""
                                INSERT INTO {binding_table}
                                (project_id, agent_key, service_name, template_id, template_name, source)
                                VALUES (%s, %s, %s, %s, %s, 'agent_report')
                                ON DUPLICATE KEY UPDATE
                                    template_id = VALUES(template_id),
                                    template_name = VALUES(template_name),
                                    source = VALUES(source),
                                    updated_at = NOW()
                                """ if self.db_manager.db_type == 'mysql' else
                                f"""
                                INSERT INTO {binding_table}
                                (project_id, agent_key, service_name, template_id, template_name, source, created_at, updated_at)
                                VALUES (?, ?, ?, ?, ?, 'agent_report', ?, ?)
                                ON CONFLICT(project_id, agent_key, service_name) DO UPDATE SET
                                    template_id=excluded.template_id,
                                    template_name=excluded.template_name,
                                    source=excluded.source,
                                    updated_at=excluded.updated_at
                                """,
                                (
                                    key[0], key[1], key[2], resolved.get('template_id'), resolved.get('template_name')
                                ) if self.db_manager.db_type == 'mysql' else
                                (
                                    key[0], key[1], key[2], resolved.get('template_id'), resolved.get('template_name'),
                                    datetime.now().isoformat(), datetime.now().isoformat()
                                )
                            )
                        except Exception:
                            self.logger.warning(f"写入Agent上报模板绑定失败: {key}", exc_info=True)
                        return resolved

                    task_row = self.db_manager.fetch_one(
                        f"""
                        SELECT template_name
                        FROM {task_table}
                        WHERE project_id = %s AND agent_key = %s AND service_name = %s
                          AND task_type = 'deploy' AND status = 'success' AND template_name IS NOT NULL AND template_name <> ''
                        ORDER BY completed_at DESC, created_at DESC
                        LIMIT 1
                        """ if self.db_manager.db_type == 'mysql' else
                        f"""
                        SELECT template_name
                        FROM {task_table}
                        WHERE project_id = ? AND agent_key = ? AND service_name = ?
                          AND task_type = 'deploy' AND status = 'success' AND template_name IS NOT NULL AND template_name <> ''
                        ORDER BY completed_at DESC, created_at DESC
                        LIMIT 1
                        """,
                        key
                    )
                    if task_row:
                        template_name = str(task_row.get('template_name') if isinstance(task_row, dict) else task_row['template_name'] or '').strip()
                        if template_name:
                            known_template = templates_by_name.get(template_name)
                            resolved = {
                                'template_id': (known_template or {}).get('id'),
                                'template_name': template_name,
                                'template_tags': self._normalize_service_tags((known_template or {}).get('template_tags')),
                            }
                            bindings_map[key] = resolved
                            try:
                                self.db_manager.execute_query(
                                    f"""
                                    INSERT INTO {binding_table}
                                    (project_id, agent_key, service_name, template_id, template_name, source)
                                    VALUES (%s, %s, %s, %s, %s, 'task_history')
                                    ON DUPLICATE KEY UPDATE
                                        template_id = VALUES(template_id),
                                        template_name = VALUES(template_name),
                                        source = VALUES(source),
                                        updated_at = NOW()
                                    """ if self.db_manager.db_type == 'mysql' else
                                    f"""
                                    INSERT INTO {binding_table}
                                    (project_id, agent_key, service_name, template_id, template_name, source, created_at, updated_at)
                                    VALUES (?, ?, ?, ?, ?, 'task_history', ?, ?)
                                    ON CONFLICT(project_id, agent_key, service_name) DO UPDATE SET
                                        template_id=excluded.template_id,
                                        template_name=excluded.template_name,
                                        source=excluded.source,
                                        updated_at=excluded.updated_at
                                    """,
                                    (
                                        key[0], key[1], key[2], resolved.get('template_id'), resolved.get('template_name')
                                    ) if self.db_manager.db_type == 'mysql' else
                                    (
                                        key[0], key[1], key[2], resolved.get('template_id'), resolved.get('template_name'),
                                        datetime.now().isoformat(), datetime.now().isoformat()
                                    )
                                )
                            except Exception:
                                self.logger.warning(f"回填服务模板绑定失败: {key}", exc_info=True)
                            return resolved

                    return {'template_id': None, 'template_name': '', 'template_tags': []}

                items = []
                for row in rows:
                    ports = {}
                    tags = []
                    raw_ports = row.get('ports_json')
                    if raw_ports:
                        if isinstance(raw_ports, str):
                            try:
                                ports = json.loads(raw_ports)
                            except Exception:
                                ports = {}
                        elif isinstance(raw_ports, dict):
                            ports = raw_ports

                    raw_tags = row.get('tags_json')
                    if raw_tags:
                        tags = self._normalize_service_tags(raw_tags)

                    raw_payload = {}
                    raw_json = row.get('raw_json')
                    if raw_json:
                        if isinstance(raw_json, str):
                            try:
                                raw_payload = json.loads(raw_json)
                            except Exception:
                                raw_payload = {}
                        elif isinstance(raw_json, dict):
                            raw_payload = raw_json

                    resolved_template = _resolve_template(
                        str(row.get('project_id') or ''),
                        str(row.get('agent_key') or ''),
                        str(row.get('service_name') or ''),
                        raw_payload
                    )

                    image_versions = self._parse_images_json(row.get('images_json'))
                    items.append({
                        'id': row.get('service_uid'),
                        'service_uid': row.get('service_uid'),
                        'project_id': row.get('project_id'),
                        'agent_key': row.get('agent_key'),
                        'agent_hostname': row.get('agent_hostname'),
                        'agent_ip': row.get('agent_ip'),
                        'name': row.get('service_name'),
                        'service_name': row.get('service_name'),
                        'image_versions': image_versions,
                        'template_id': resolved_template.get('template_id'),
                        'template_name': resolved_template.get('template_name'),
                        'template_tags': self._normalize_service_tags(resolved_template.get('template_tags')),
                        'status': row.get('status') or 'unknown',
                        'tags': tags,
                        'ports': ports,
                        'is_stale': bool(row.get('is_stale')),
                        'source': row.get('source'),
                        'first_seen_at': row.get('first_seen_at'),
                        'last_seen_at': row.get('last_seen_at'),
                        'updated_at': row.get('updated_at'),
                    })

                return jsonify({
                    'project_id': project_id,
                    'items': items,
                    'page': page,
                    'per_page': per_page,
                    'total': total
                })
            except Exception as e:
                self.logger.error(f"聚合服务查询失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/services/global/cleanup-offline', methods=['POST'])
        def cleanup_offline_global_services():
            """一键清理 OFFLINE 状态服务（仅节点离线/孤儿服务）。"""
            try:
                data = request.get_json(silent=True) or {}
                project_id = str(data.get('project_id') or '').strip()
                dry_run = bool(data.get('dry_run', False))
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400

                services_table = self.db_manager.get_table_name('agent_services')
                agents_table = self.db_manager.get_table_name('agent_status')
                placeholder = '%s' if self.db_manager.db_type == 'mysql' else '?'

                offline_clause = (
                    f"s.agent_key IN (SELECT a.agent_key FROM {agents_table} a "
                    f"WHERE a.project_id = {placeholder} AND COALESCE(a.status, 'unknown') <> 'online')"
                )
                orphan_clause = (
                    f"s.agent_key IS NULL OR s.agent_key = '' OR "
                    f"s.agent_key NOT IN (SELECT a.agent_key FROM {agents_table} a WHERE a.project_id = {placeholder})"
                )
                target_where = f"s.project_id = {placeholder} AND ({offline_clause} OR {orphan_clause})"

                preview_sql = f"""
                    SELECT s.service_uid, s.agent_key, s.service_name, s.is_stale,
                           CASE
                               WHEN {orphan_clause} THEN 'orphan_agent'
                               ELSE 'offline_agent'
                           END AS offline_reason
                    FROM {services_table} s
                    WHERE {target_where}
                """
                preview_params = (project_id, project_id, project_id, project_id)
                preview_rows = self.db_manager.fetch_all(preview_sql, preview_params) or []

                reason_stats = {'offline_agent': 0, 'orphan_agent': 0}
                sample_items = []
                for row in preview_rows:
                    reason = str(row.get('offline_reason') or 'offline_agent')
                    reason_stats[reason] = reason_stats.get(reason, 0) + 1
                    if len(sample_items) < 100:
                        sample_items.append({
                            'service_uid': row.get('service_uid'),
                            'agent_key': row.get('agent_key'),
                            'service_name': row.get('service_name'),
                            'reason': reason,
                        })

                if dry_run:
                    return jsonify({
                        'project_id': project_id,
                        'dry_run': True,
                        'target_count': len(preview_rows),
                        'reason_stats': reason_stats,
                        'items': sample_items,
                    })

                delete_sql = (
                    f"DELETE FROM {services_table} WHERE project_id = %s AND ("
                    f"agent_key IS NULL OR agent_key = '' OR "
                    f"agent_key IN (SELECT agent_key FROM {agents_table} WHERE project_id = %s AND COALESCE(status, 'unknown') <> 'online') OR "
                    f"agent_key NOT IN (SELECT agent_key FROM {agents_table} WHERE project_id = %s)"
                    f")"
                    if self.db_manager.db_type == 'mysql' else
                    f"DELETE FROM {services_table} WHERE project_id = ? AND ("
                    f"agent_key IS NULL OR agent_key = '' OR "
                    f"agent_key IN (SELECT agent_key FROM {agents_table} WHERE project_id = ? AND COALESCE(status, 'unknown') <> 'online') OR "
                    f"agent_key NOT IN (SELECT agent_key FROM {agents_table} WHERE project_id = ?)"
                    f")"
                )
                delete_params = (project_id, project_id, project_id)

                conn = self.db_manager.get_connection()
                try:
                    cursor = conn.execute(delete_sql, delete_params)
                    deleted = int(cursor.rowcount or 0)
                    cursor.close()
                finally:
                    conn.close()

                return jsonify({
                    'project_id': project_id,
                    'dry_run': False,
                    'target_count': len(preview_rows),
                    'deleted': deleted,
                    'reason_stats': reason_stats,
                })
            except Exception as e:
                self.logger.error(f"清理OFFLINE服务失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/process-monitor/nodes', methods=['GET'])
        def list_process_monitor_nodes():
            try:
                project_id = str(request.args.get('project_id') or '').strip()
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400
                include_stale = str(request.args.get('include_stale', 'false')).lower() == 'true'
                q = str(request.args.get('q') or '').strip().lower()
                agent_key_filter = str(request.args.get('agent_key') or '').strip()
                items = self._list_process_monitor_services(project_id, include_stale=include_stale)
                if agent_key_filter:
                    items = [item for item in items if str(item.get('agent_key') or '') == agent_key_filter]
                if q:
                    items = [
                        item for item in items
                        if q in str(item.get('agent_key') or '').lower()
                        or q in str(item.get('service_name') or '').lower()
                        or q in str(item.get('agent_hostname') or '').lower()
                        or q in str(item.get('agent_ip') or '').lower()
                    ]
                items.sort(key=lambda item: str(item.get('last_seen_at') or ''), reverse=True)
                return jsonify({'project_id': project_id, 'total': len(items), 'items': items})
            except Exception as e:
                self.logger.error(f"查询process-monitor节点列表失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/process-monitor/nodes/<agent_key>/services/<service_name>/processes', methods=['GET'])
        def list_node_processes(agent_key, service_name):
            try:
                project_id = str(request.args.get('project_id') or '').strip()
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400
                name = str(request.args.get('name') or '').strip()
                keyword = str(request.args.get('keyword') or '').strip()
                endpoint = '/api/processes'
                query_params = {}
                if name:
                    query_params['name'] = name
                if keyword:
                    query_params['keyword'] = keyword
                if query_params:
                    endpoint = f"{endpoint}?{urlencode(query_params)}"
                data, status_code, row = self._call_process_monitor_api(
                    project_id, agent_key, service_name, 'GET', endpoint, None, timeout=(5, 30)
                )
                payload = data if isinstance(data, dict) else {'items': [], 'total': 0}
                payload['service_name'] = row.get('service_name')
                payload['agent_key'] = row.get('agent_key')
                return jsonify(payload), status_code
            except ValueError as exc:
                return jsonify({'error': str(exc)}), 404
            except Exception as e:
                self.logger.error(f"查询节点进程列表失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/process-monitor/nodes/<agent_key>/services/<service_name>/processes/<int:pid>', methods=['GET'])
        def get_node_process_detail(agent_key, service_name, pid):
            try:
                project_id = str(request.args.get('project_id') or '').strip()
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400
                data, status_code, row = self._call_process_monitor_api(
                    project_id,
                    agent_key,
                    service_name,
                    'GET',
                    f'/api/processes/{int(pid)}',
                    None,
                    timeout=(5, 30),
                )
                payload = self._normalize_process_monitor_payload_paths(data if isinstance(data, dict) else {})
                payload['service_name'] = row.get('service_name')
                payload['agent_key'] = row.get('agent_key')
                return jsonify(payload), status_code
            except ValueError as exc:
                return jsonify({'error': str(exc)}), 404
            except Exception as e:
                self.logger.error(f"查询节点进程详情失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/process-monitor/nodes/<agent_key>/services/<service_name>/processes/<int:pid>/sync-candidates', methods=['GET'])
        def get_node_process_sync_candidates(agent_key, service_name, pid):
            try:
                project_id = str(request.args.get('project_id') or '').strip()
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400
                data, status_code, row = self._call_process_monitor_api(
                    project_id,
                    agent_key,
                    service_name,
                    'GET',
                    f'/api/processes/{int(pid)}/sync-candidates',
                    None,
                    timeout=(5, 30),
                )
                payload = self._normalize_process_monitor_payload_paths(data if isinstance(data, dict) else {})
                payload['service_name'] = row.get('service_name')
                payload['agent_key'] = row.get('agent_key')
                return jsonify(payload), status_code
            except ValueError as exc:
                return jsonify({'error': str(exc)}), 404
            except Exception as e:
                self.logger.error(f"查询节点进程同步候选失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/process-monitor/nodes/<agent_key>/services/<service_name>/filesystem/tree', methods=['GET'])
        def get_node_filesystem_tree(agent_key, service_name):
            try:
                project_id = str(request.args.get('project_id') or '').strip()
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400
                raw_path = str(request.args.get('path') or '/').strip() or '/'
                path = self._canonicalize_process_monitor_input_path(raw_path)
                include_hidden = str(request.args.get('include_hidden') or 'false').strip().lower() == 'true'
                try:
                    limit = int(request.args.get('limit') or 500)
                except Exception:
                    limit = 500
                query = urlencode({
                    'path': path,
                    'include_hidden': 'true' if include_hidden else 'false',
                    'limit': max(1, min(limit, 2000)),
                })
                data, status_code, row = self._call_process_monitor_api(
                    project_id,
                    agent_key,
                    service_name,
                    'GET',
                    f'/api/filesystem/tree?{query}',
                    None,
                    timeout=(5, 30),
                )
                payload = self._normalize_process_monitor_payload_paths(data if isinstance(data, dict) else {})
                payload['service_name'] = row.get('service_name')
                payload['agent_key'] = row.get('agent_key')
                return jsonify(payload), status_code
            except ValueError as exc:
                error_text = str(exc)
                if error_text.startswith('path_must_be_absolute'):
                    return jsonify({'error': error_text}), 400
                return jsonify({'error': error_text}), 404
            except Exception as e:
                self.logger.error(f"查询节点文件系统树失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/process-monitor/sync/tasks', methods=['POST'])
        def create_process_monitor_sync_task():
            try:
                data = request.get_json(silent=True) or {}
                project_id = str(data.get('project_id') or '').strip()
                agent_key = str(data.get('agent_key') or '').strip()
                service_name = str(data.get('service_name') or '').strip()
                mode = str(data.get('mode') or '').strip()
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400
                if not agent_key:
                    return jsonify({'error': 'agent_key is required'}), 400
                if mode not in ('pid_files', 'path_files'):
                    return jsonify({'error': 'mode must be pid_files or path_files'}), 400
                if mode == 'pid_files':
                    pids = data.get('pids') or []
                    if not isinstance(pids, list) or not pids:
                        return jsonify({'error': 'pids is required for pid_files mode'}), 400
                else:
                    paths = data.get('paths') or []
                    if not isinstance(paths, list) or not paths:
                        return jsonify({'error': 'paths is required for path_files mode'}), 400

                selected_row = self._get_process_monitor_service_row(project_id, agent_key, service_name or None)
                if not selected_row:
                    return jsonify({'error': f'process_monitor service not found: {agent_key}/{service_name or "*"}'}), 404
                resolved_service_name = str(selected_row.get('service_name') or '').strip()

                remote_root_url = str(data.get('remote_root_url') or '').strip()
                if not remote_root_url:
                    fileserver_base = str(
                        self.config.get('process_monitor_fileserver_base_url') or
                        'http://secflow-platform-fileserver/api/fileserver'
                    ).rstrip('/')
                    subproject_id = self._process_monitor_sync_subproject_id()
                    remote_root_url = f"{fileserver_base}/sync/root/{quote(project_id, safe='')}/{quote(subproject_id, safe='')}"
                remote_path_prefix = f"/__file__sync__/{agent_key}"

                payload = {
                    'mode': mode,
                    'remote_root_url': remote_root_url,
                    'remote_path_prefix': remote_path_prefix,
                }
                if mode == 'pid_files':
                    payload['pids'] = [int(item) for item in (data.get('pids') or [])]
                else:
                    payload['paths'] = [self._canonicalize_process_monitor_input_path(item) for item in (data.get('paths') or [])]

                node_resp, status_code, _ = self._call_process_monitor_api(
                    project_id,
                    agent_key,
                    resolved_service_name,
                    'POST',
                    '/api/sync/tasks',
                    payload,
                    timeout=(10, 120),
                )
                if status_code >= 300:
                    return jsonify(node_resp if isinstance(node_resp, dict) else {'error': 'upstream_error'}), status_code

                node_payload = self._normalize_process_monitor_payload_paths(node_resp if isinstance(node_resp, dict) else {})
                platform_sync_id = self._record_process_sync_log(
                    project_id=project_id,
                    agent_key=agent_key,
                    service_name=resolved_service_name,
                    mode=mode,
                    status=str(node_payload.get('status') or 'created'),
                    request_payload=payload,
                    node_task_payload=node_payload,
                    message='process monitor sync task created',
                )
                return jsonify({
                    'sync_id': platform_sync_id,
                    'project_id': project_id,
                    'agent_key': agent_key,
                    'service_name': resolved_service_name,
                    'node_task': node_payload,
                    'remote_root_url': remote_root_url,
                    'remote_path_prefix': remote_path_prefix,
                }), 202
            except ValueError as exc:
                error_text = str(exc)
                if error_text.startswith('path_must_be_absolute'):
                    return jsonify({'error': error_text}), 400
                return jsonify({'error': error_text}), 404
            except Exception as e:
                self.logger.error(f"创建process-monitor同步任务失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/process-monitor/sync/preview', methods=['POST'])
        def preview_process_monitor_sync():
            try:
                data = request.get_json(silent=True) or {}
                project_id = str(data.get('project_id') or '').strip()
                agent_key = str(data.get('agent_key') or '').strip()
                service_name = str(data.get('service_name') or '').strip()
                mode = str(data.get('mode') or '').strip()
                preview_limit = int(data.get('preview_limit') or 50)
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400
                if not agent_key:
                    return jsonify({'error': 'agent_key is required'}), 400
                if mode not in ('pid_files', 'path_files'):
                    return jsonify({'error': 'mode must be pid_files or path_files'}), 400
                if mode == 'pid_files':
                    pids = data.get('pids') or []
                    if not isinstance(pids, list) or not pids:
                        return jsonify({'error': 'pids is required for pid_files mode'}), 400
                else:
                    paths = data.get('paths') or []
                    if not isinstance(paths, list) or not paths:
                        return jsonify({'error': 'paths is required for path_files mode'}), 400

                selected_row = self._get_process_monitor_service_row(project_id, agent_key, service_name or None)
                if not selected_row:
                    return jsonify({'error': f'process_monitor service not found: {agent_key}/{service_name or "*"}'}), 404
                resolved_service_name = str(selected_row.get('service_name') or '').strip()

                remote_root_url = str(data.get('remote_root_url') or '').strip()
                if not remote_root_url:
                    fileserver_base = str(
                        self.config.get('process_monitor_fileserver_base_url') or
                        'http://secflow-platform-fileserver/api/fileserver'
                    ).rstrip('/')
                    subproject_id = self._process_monitor_sync_subproject_id()
                    remote_root_url = f"{fileserver_base}/sync/root/{quote(project_id, safe='')}/{quote(subproject_id, safe='')}"
                remote_path_prefix = f"/__file__sync__/{agent_key}"

                payload = {
                    'mode': mode,
                    'remote_root_url': remote_root_url,
                    'remote_path_prefix': remote_path_prefix,
                    'preview_limit': max(1, min(preview_limit, 200)),
                }
                if mode == 'pid_files':
                    payload['pids'] = [int(item) for item in (data.get('pids') or [])]
                else:
                    payload['paths'] = [self._canonicalize_process_monitor_input_path(item) for item in (data.get('paths') or [])]

                node_resp, status_code, _ = self._call_process_monitor_api(
                    project_id,
                    agent_key,
                    resolved_service_name,
                    'POST',
                    '/api/sync/preview',
                    payload,
                    timeout=(10, 120),
                )
                if status_code >= 300:
                    return jsonify(node_resp if isinstance(node_resp, dict) else {'error': 'upstream_error'}), status_code

                preview_payload = self._normalize_process_monitor_payload_paths(node_resp if isinstance(node_resp, dict) else {})
                preview_payload['service_name'] = resolved_service_name
                preview_payload['agent_key'] = agent_key
                preview_payload['project_id'] = project_id
                preview_payload['target'] = {
                    **(preview_payload.get('target') if isinstance(preview_payload.get('target'), dict) else {}),
                    'remote_root_url': remote_root_url,
                    'remote_path_prefix': remote_path_prefix,
                }
                return jsonify(preview_payload)
            except ValueError as exc:
                error_text = str(exc)
                if error_text.startswith('path_must_be_absolute'):
                    return jsonify({'error': error_text}), 400
                return jsonify({'error': error_text}), 404
            except Exception as e:
                self.logger.error(f"预览process-monitor同步任务失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/process-monitor/sync/tasks/history', methods=['GET', 'DELETE'])
        def process_monitor_sync_history():
            table_name = self.db_manager.get_table_name('process_sync_logs')
            try:
                if request.method == 'GET':
                    project_id = str(request.args.get('project_id') or '').strip()
                    if not project_id:
                        return jsonify({'error': 'project_id is required'}), 400
                    page = max(int(request.args.get('page', 1)), 1)
                    per_page = min(max(int(request.args.get('per_page', 50)), 1), 500)
                    status_filter = str(request.args.get('status') or '').strip()
                    mode_filter = str(request.args.get('mode') or '').strip()
                    agent_key_filter = str(request.args.get('agent_key') or '').strip()

                    where = ["project_id = %s" if self.db_manager.db_type == 'mysql' else "project_id = ?"]
                    params: List[Any] = [project_id]
                    if status_filter:
                        where.append("status = %s" if self.db_manager.db_type == 'mysql' else "status = ?")
                        params.append(status_filter)
                    if mode_filter:
                        where.append("mode = %s" if self.db_manager.db_type == 'mysql' else "mode = ?")
                        params.append(mode_filter)
                    if agent_key_filter:
                        where.append("agent_key = %s" if self.db_manager.db_type == 'mysql' else "agent_key = ?")
                        params.append(agent_key_filter)
                    where_sql = " AND ".join(where)

                    count_row = self.db_manager.fetch_one(
                        f"SELECT COUNT(*) as count FROM {table_name} WHERE {where_sql}",
                        tuple(params),
                    )
                    total = int((count_row or {}).get('count', 0))
                    offset = (page - 1) * per_page
                    query_sql = f"""
                        SELECT sync_id, project_id, agent_key, service_name, node_task_id,
                               mode, status, request_json, node_snapshot_json, message, created_at, updated_at
                        FROM {table_name}
                        WHERE {where_sql}
                        ORDER BY created_at DESC
                    """
                    if self.db_manager.db_type == 'mysql':
                        query_sql += " LIMIT %s OFFSET %s"
                    else:
                        query_sql += " LIMIT ? OFFSET ?"
                    rows = self.db_manager.fetch_all(query_sql, tuple(params + [per_page, offset])) or []
                    items: List[Dict[str, Any]] = []
                    for row in rows:
                        request_json = row.get('request_json')
                        node_json = row.get('node_snapshot_json')
                        if isinstance(request_json, str):
                            try:
                                request_json = json.loads(request_json)
                            except Exception:
                                request_json = {}
                        if isinstance(node_json, str):
                            try:
                                node_json = json.loads(node_json)
                            except Exception:
                                node_json = {}
                        items.append({
                            'sync_id': row.get('sync_id'),
                            'project_id': row.get('project_id'),
                            'agent_key': row.get('agent_key'),
                            'service_name': row.get('service_name'),
                            'node_task_id': row.get('node_task_id'),
                            'mode': row.get('mode'),
                            'status': row.get('status'),
                            'request': request_json if isinstance(request_json, dict) else {},
                            'node_snapshot': node_json if isinstance(node_json, dict) else {},
                            'message': row.get('message'),
                            'created_at': row.get('created_at'),
                            'updated_at': row.get('updated_at'),
                        })
                    return jsonify({
                        'project_id': project_id,
                        'page': page,
                        'per_page': per_page,
                        'total': total,
                        'items': items,
                    })

                payload = request.get_json(silent=True) or {}
                project_id = str(payload.get('project_id') or '').strip()
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400
                sync_ids = payload.get('sync_ids') if isinstance(payload.get('sync_ids'), list) else []
                include_running = bool(payload.get('include_running', False))
                ended_statuses = {'success', 'partial_success', 'failed', 'cancelled', 'cleared'}
                rows = self.db_manager.fetch_all(
                    f"SELECT sync_id, status FROM {table_name} WHERE project_id = %s"
                    if self.db_manager.db_type == 'mysql' else
                    f"SELECT sync_id, status FROM {table_name} WHERE project_id = ?",
                    (project_id,),
                ) or []
                selected_rows = rows
                if sync_ids:
                    selected = {str(item).strip() for item in sync_ids if str(item).strip()}
                    selected_rows = [item for item in rows if str(item.get('sync_id') or '') in selected]
                to_delete: List[str] = []
                skipped: List[Dict[str, Any]] = []
                for row in selected_rows:
                    sync_id = str(row.get('sync_id') or '').strip()
                    status_value = str(row.get('status') or '').strip().lower()
                    if not include_running and status_value not in ended_statuses:
                        skipped.append({'sync_id': sync_id, 'reason': f'status_not_allowed:{status_value or "unknown"}'})
                        continue
                    to_delete.append(sync_id)
                deleted = 0
                for sync_id in to_delete:
                    self.db_manager.execute_query(
                        f"DELETE FROM {table_name} WHERE sync_id = %s"
                        if self.db_manager.db_type == 'mysql' else
                        f"DELETE FROM {table_name} WHERE sync_id = ?",
                        (sync_id,),
                    )
                    deleted += 1
                return jsonify({'project_id': project_id, 'deleted': deleted, 'deleted_sync_ids': to_delete, 'skipped': skipped})
            except Exception as e:
                self.logger.error(f"处理process-monitor同步历史失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/process-monitor/sync/tasks/live', methods=['GET', 'DELETE'])
        def process_monitor_sync_live():
            try:
                if request.method == 'GET':
                    project_id = str(request.args.get('project_id') or '').strip()
                    if not project_id:
                        return jsonify({'error': 'project_id is required'}), 400
                    agent_key_raw = str(request.args.get('agent_keys') or request.args.get('agent_key') or '').strip()
                    requested_keys = {item.strip() for item in agent_key_raw.split(',') if item.strip()} if agent_key_raw else set()
                    services = self._list_process_monitor_services(project_id, include_stale=False)
                    if requested_keys:
                        services = [item for item in services if str(item.get('agent_key') or '') in requested_keys]
                    dedup_map: Dict[str, Dict[str, Any]] = {}
                    for item in services:
                        key = str(item.get('agent_key') or '')
                        if not key:
                            continue
                        prev = dedup_map.get(key)
                        if prev is None or str(item.get('last_seen_at') or '') > str(prev.get('last_seen_at') or ''):
                            dedup_map[key] = item
                    selected_services = list(dedup_map.values())
                    items: List[Dict[str, Any]] = []
                    errors: List[Dict[str, Any]] = []
                    for svc in selected_services:
                        agent_key = str(svc.get('agent_key') or '')
                        service_name = str(svc.get('service_name') or '')
                        try:
                            node_data, status_code, _ = self._call_process_monitor_api(
                                project_id, agent_key, service_name, 'GET', '/api/sync/tasks', None, timeout=(5, 30)
                            )
                            if status_code >= 300:
                                errors.append({'agent_key': agent_key, 'service_name': service_name, 'error': f'upstream_status_{status_code}', 'response': node_data})
                                continue
                            task_items = node_data.get('items') if isinstance(node_data, dict) else []
                            if not isinstance(task_items, list):
                                task_items = []
                            for task in task_items:
                                if not isinstance(task, dict):
                                    continue
                                table_name = self.db_manager.get_table_name('process_sync_logs')
                                node_task_id = str(task.get('task_id') or '').strip()
                                if node_task_id:
                                    self.db_manager.execute_query(
                                        f"""
                                        UPDATE {table_name}
                                        SET status = %s, node_snapshot_json = %s, updated_at = NOW()
                                        WHERE project_id = %s AND agent_key = %s AND service_name = %s AND node_task_id = %s
                                        """ if self.db_manager.db_type == 'mysql' else
                                        f"""
                                        UPDATE {table_name}
                                        SET status = ?, node_snapshot_json = ?, updated_at = ?
                                        WHERE project_id = ? AND agent_key = ? AND service_name = ? AND node_task_id = ?
                                        """,
                                        (
                                            str(task.get('status') or 'unknown'),
                                            json.dumps(task, ensure_ascii=False),
                                            project_id,
                                            agent_key,
                                            service_name,
                                            node_task_id,
                                        ) if self.db_manager.db_type == 'mysql' else
                                        (
                                            str(task.get('status') or 'unknown'),
                                            json.dumps(task, ensure_ascii=False),
                                            datetime.now().isoformat(),
                                            project_id,
                                            agent_key,
                                            service_name,
                                            node_task_id,
                                        )
                                    )
                                items.append({
                                    'agent_key': agent_key,
                                    'service_name': service_name,
                                    'node_task_id': node_task_id or task.get('task_id'),
                                    'task': task,
                                })
                        except Exception as exc:
                            errors.append({'agent_key': agent_key, 'service_name': service_name, 'error': str(exc)})
                    return jsonify({
                        'project_id': project_id,
                        'total_nodes': len(selected_services),
                        'total_tasks': len(items),
                        'items': items,
                        'errors': errors,
                    })

                payload = request.get_json(silent=True) or {}
                project_id = str(payload.get('project_id') or '').strip()
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400
                task_ids = payload.get('task_ids') if isinstance(payload.get('task_ids'), list) else []
                include_running = bool(payload.get('include_running', False))
                target_agents = payload.get('agent_keys') if isinstance(payload.get('agent_keys'), list) else []
                requested_keys = {str(item).strip() for item in target_agents if str(item).strip()}
                services = self._list_process_monitor_services(project_id, include_stale=False)
                if requested_keys:
                    services = [item for item in services if str(item.get('agent_key') or '') in requested_keys]
                dedup_map: Dict[str, Dict[str, Any]] = {}
                for item in services:
                    key = str(item.get('agent_key') or '')
                    if not key:
                        continue
                    prev = dedup_map.get(key)
                    if prev is None or str(item.get('last_seen_at') or '') > str(prev.get('last_seen_at') or ''):
                        dedup_map[key] = item
                selected_services = list(dedup_map.values())
                outputs: List[Dict[str, Any]] = []
                for svc in selected_services:
                    agent_key = str(svc.get('agent_key') or '')
                    service_name = str(svc.get('service_name') or '')
                    try:
                        node_data, status_code, _ = self._call_process_monitor_api(
                            project_id,
                            agent_key,
                            service_name,
                            'DELETE',
                            '/api/sync/tasks',
                            {
                                'task_ids': [str(item) for item in task_ids],
                                'include_running': include_running,
                            },
                            timeout=(5, 30),
                        )
                        outputs.append({
                            'agent_key': agent_key,
                            'service_name': service_name,
                            'status_code': status_code,
                            'result': node_data,
                        })
                        deleted_task_ids = node_data.get('deleted_task_ids') if isinstance(node_data, dict) else []
                        if status_code < 300 and isinstance(deleted_task_ids, list):
                            table_name = self.db_manager.get_table_name('process_sync_logs')
                            for node_task_id in [str(item).strip() for item in deleted_task_ids if str(item).strip()]:
                                self.db_manager.execute_query(
                                    f"""
                                    UPDATE {table_name}
                                    SET status = %s, message = %s, updated_at = NOW()
                                    WHERE project_id = %s AND agent_key = %s AND service_name = %s AND node_task_id = %s
                                    """ if self.db_manager.db_type == 'mysql' else
                                    f"""
                                    UPDATE {table_name}
                                    SET status = ?, message = ?, updated_at = ?
                                    WHERE project_id = ? AND agent_key = ? AND service_name = ? AND node_task_id = ?
                                    """,
                                    ('cleared', 'cleared from live node', project_id, agent_key, service_name, node_task_id)
                                    if self.db_manager.db_type == 'mysql' else
                                    ('cleared', 'cleared from live node', datetime.now().isoformat(), project_id, agent_key, service_name, node_task_id)
                                )
                    except Exception as exc:
                        outputs.append({
                            'agent_key': agent_key,
                            'service_name': service_name,
                            'status_code': 500,
                            'result': {'error': str(exc)},
                        })
                return jsonify({'project_id': project_id, 'total_nodes': len(selected_services), 'results': outputs})
            except Exception as e:
                self.logger.error(f"处理process-monitor实时任务失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/process-monitor/sync/tasks/live/<agent_key>/<service_name>/<task_id>', methods=['GET'])
        def process_monitor_sync_live_task_detail(agent_key, service_name, task_id):
            try:
                project_id = str(request.args.get('project_id') or '').strip()
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400
                task_data, task_status, _ = self._call_process_monitor_api(
                    project_id, agent_key, service_name, 'GET', f'/api/sync/tasks/{quote(task_id, safe="")}', None, timeout=(5, 30)
                )
                progress_data, progress_status, _ = self._call_process_monitor_api(
                    project_id, agent_key, service_name, 'GET', f'/api/sync/tasks/{quote(task_id, safe="")}/progress', None, timeout=(5, 30)
                )
                events_data, events_status, _ = self._call_process_monitor_api(
                    project_id, agent_key, service_name, 'GET', f'/api/sync/tasks/{quote(task_id, safe="")}/events', None, timeout=(5, 30)
                )
                results_data, results_status, _ = self._call_process_monitor_api(
                    project_id, agent_key, service_name, 'GET', f'/api/sync/tasks/{quote(task_id, safe="")}/results', None, timeout=(5, 30)
                )
                status_code = max(task_status, progress_status, events_status, results_status)
                return jsonify({
                    'project_id': project_id,
                    'agent_key': agent_key,
                    'service_name': service_name,
                    'task_id': task_id,
                    'task': task_data,
                    'progress': progress_data,
                    'events': events_data,
                    'results': results_data,
                }), status_code
            except Exception as e:
                self.logger.error(f"查询process-monitor实时任务详情失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/ai-helpers', methods=['GET'])
        def list_ai_helpers():
            try:
                project_id = str(request.args.get('project_id') or '').strip()
                if not project_id:
                    return jsonify({'error': 'project_id parameter is required'}), 400

                target_agent_key = str(request.args.get('agent_key') or '').strip()
                health_status = str(request.args.get('health_status') or '').strip().lower()
                table_name = self.db_manager.get_table_name('agent_services')
                rows = self.db_manager.fetch_all(
                    f"""
                    SELECT service_uid, project_id, agent_key, agent_hostname, agent_ip,
                           service_name, image, status, tags_json, ports_json, raw_json, source, is_stale,
                           first_seen_at, last_seen_at, updated_at
                    FROM {table_name}
                    WHERE project_id = %s AND is_stale = 0
                    ORDER BY last_seen_at DESC
                    """ if self.db_manager.db_type == 'mysql' else
                    f"""
                    SELECT service_uid, project_id, agent_key, agent_hostname, agent_ip,
                           service_name, image, status, tags_json, ports_json, raw_json, source, is_stale,
                           first_seen_at, last_seen_at, updated_at
                    FROM {table_name}
                    WHERE project_id = ? AND is_stale = 0
                    ORDER BY last_seen_at DESC
                    """,
                    (project_id,)
                ) or []
                health_map = self._get_ai_helper_health_snapshot_map(project_id)

                items = []
                for row in rows:
                    if target_agent_key and str(row.get('agent_key') or '').strip() != target_agent_key:
                        continue
                    if not self._has_ai_helper_tag(row.get('tags_json')):
                        continue
                    helper_key = (
                        str(row.get('agent_key') or '').strip(),
                        str(row.get('service_name') or '').strip(),
                    )
                    snapshot = health_map.get(helper_key) or {
                        'health_status': 'unknown',
                        'health_payload': {'status': 'unknown'},
                        'checked_at': None,
                    }
                    health_payload = snapshot.get('health_payload') if isinstance(snapshot.get('health_payload'), dict) else {}
                    health_label = str(snapshot.get('health_status') or 'unknown').strip().lower() or 'unknown'
                    if health_status and health_status != health_label:
                        continue
                    item = self._serialize_ai_helper_item(row, health_payload=health_payload)
                    item['health_status'] = health_label
                    item['health_checked_at'] = snapshot.get('checked_at')
                    item['health_source'] = 'snapshot'
                    items.append(item)

                return jsonify({
                    'project_id': project_id,
                    'items': items,
                    'total': len(items),
                })
            except Exception as e:
                self.logger.error(f"查询AI helper列表失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/ai-agents', methods=['GET'])
        def list_project_ai_agents():
            try:
                project_id = str(request.args.get('project_id') or '').strip()
                if not project_id:
                    return jsonify({'error': 'project_id parameter is required'}), 400

                page = max(int(request.args.get('page', 1) or 1), 1)
                per_page = int(request.args.get('per_page', 100) or 100)
                per_page = max(1, min(per_page, 1000))
                target_agent_key = str(request.args.get('agent_key') or '').strip()
                target_helper_health = str(request.args.get('health_status') or '').strip().lower()
                target_backend_type = str(request.args.get('backend_type') or '').strip().lower()
                installed_filter_raw = str(request.args.get('installed') or '').strip().lower()
                installed_filter: Optional[bool] = None
                if installed_filter_raw in ('true', '1', 'yes'):
                    installed_filter = True
                elif installed_filter_raw in ('false', '0', 'no'):
                    installed_filter = False

                table_name = self.db_manager.get_table_name('agent_services')
                rows = self.db_manager.fetch_all(
                    f"""
                    SELECT service_uid, project_id, agent_key, agent_hostname, agent_ip,
                           service_name, image, status, tags_json, ports_json, raw_json, source, is_stale,
                           first_seen_at, last_seen_at, updated_at
                    FROM {table_name}
                    WHERE project_id = %s AND is_stale = 0
                    ORDER BY last_seen_at DESC
                    """ if self.db_manager.db_type == 'mysql' else
                    f"""
                    SELECT service_uid, project_id, agent_key, agent_hostname, agent_ip,
                           service_name, image, status, tags_json, ports_json, raw_json, source, is_stale,
                           first_seen_at, last_seen_at, updated_at
                    FROM {table_name}
                    WHERE project_id = ? AND is_stale = 0
                    ORDER BY last_seen_at DESC
                    """,
                    (project_id,)
                ) or []
                health_map = self._get_ai_helper_health_snapshot_map(project_id)

                items = []
                for row in rows:
                    helper_agent_key = str(row.get('agent_key') or '').strip()
                    helper_service_name = str(row.get('service_name') or '').strip()
                    helper_tags = self._normalize_service_tags(row.get('tags_json'))

                    if target_agent_key and helper_agent_key != target_agent_key:
                        continue
                    if not self._has_ai_helper_tag(helper_tags):
                        continue

                    snapshot = health_map.get((helper_agent_key, helper_service_name)) or {
                        'health_status': 'unknown',
                        'health_payload': {'status': 'unknown'},
                        'checked_at': None,
                    }
                    helper_health_payload = snapshot.get('health_payload') if isinstance(snapshot.get('health_payload'), dict) else {}
                    helper_health_status = str(snapshot.get('health_status') or 'unknown').strip().lower() or 'unknown'
                    helper_health_checked_at = snapshot.get('checked_at')

                    if target_helper_health and target_helper_health != helper_health_status:
                        continue

                    try:
                        agents_payload, agents_code = self._call_ai_helper_api(
                            project_id,
                            helper_agent_key,
                            helper_service_name,
                            'GET',
                            '/api/ai-agents',
                            None,
                            timeout=(5, 30),
                        )
                    except Exception as exc:
                        self.logger.warning(
                            f"查询AI Agent列表失败，helper={helper_agent_key}/{helper_service_name}: {exc}"
                        )
                        continue

                    if agents_code >= 300 or not isinstance(agents_payload, dict):
                        continue

                    helper_agents = agents_payload.get('items') or []
                    for agent in helper_agents:
                        if not isinstance(agent, dict):
                            continue
                        backend_type = str(agent.get('backend_type') or '').strip().lower()
                        installed = bool(agent.get('installed'))
                        if target_backend_type and backend_type != target_backend_type:
                            continue
                        if installed_filter is not None and installed != installed_filter:
                            continue

                        items.append({
                            'project_id': project_id,
                            'agent_key': helper_agent_key,
                            'agent_hostname': row.get('agent_hostname'),
                            'agent_ip': row.get('agent_ip'),
                            'service_name': helper_service_name,
                            'image': row.get('image') or '',
                            'status': row.get('status') or 'unknown',
                            'health_status': helper_health_status,
                            'helper_tags': helper_tags,
                            'helper_health': helper_health_payload,
                            'health_checked_at': helper_health_checked_at,
                            'health_source': 'snapshot',
                            'agent_id': agent.get('agent_id'),
                            'name': agent.get('name'),
                            'backend_type': agent.get('backend_type'),
                            'command': agent.get('command'),
                            'args': agent.get('args') if isinstance(agent.get('args'), list) else [],
                            'cwd': agent.get('cwd'),
                            'env': agent.get('env') if isinstance(agent.get('env'), dict) else {},
                            'enabled': bool(agent.get('enabled')),
                            'running': bool(agent.get('running')),
                            'active': bool(agent.get('active')),
                            'installed': installed,
                            'pid': agent.get('pid'),
                            'description': agent.get('description'),
                            'health': agent.get('health') if isinstance(agent.get('health'), dict) else agent.get('health'),
                            'capabilities': agent.get('capabilities') if isinstance(agent.get('capabilities'), dict) else agent.get('capabilities'),
                            'llm_provider_key': agent.get('llm_provider_key'),
                            'llm_provider_snapshot': agent.get('llm_provider_snapshot') if isinstance(agent.get('llm_provider_snapshot'), dict) else None,
                            'llm_provider_applied_at': agent.get('llm_provider_applied_at'),
                            'llm_provider_mapped_env_keys': agent.get('llm_provider_mapped_env_keys') if isinstance(agent.get('llm_provider_mapped_env_keys'), list) else [],
                            'last_seen_at': row.get('last_seen_at'),
                            'updated_at': row.get('updated_at'),
                        })

                total = len(items)
                start = (page - 1) * per_page
                end = start + per_page
                paged_items = items[start:end] if start < total else []

                return jsonify({
                    'project_id': project_id,
                    'page': page,
                    'per_page': per_page,
                    'items': paged_items,
                    'total': total,
                })
            except Exception as e:
                self.logger.error(f"查询项目级AI Agent列表失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/ai-agents/llm-providers', methods=['GET'])
        def list_ai_agent_llm_providers():
            try:
                project_id = str(request.args.get('project_id') or '').strip()
                payload = self._list_service_llm_providers()
                return jsonify({
                    'project_id': project_id,
                    'default_provider_key': payload.get('default_provider_key'),
                    'items': payload.get('items') if isinstance(payload.get('items'), list) else [],
                    'total': int(payload.get('total') or 0),
                })
            except Exception as e:
                self.logger.error(f"查询AI Agent LLM Provider列表失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/ai-agents/llm-providers/<provider_key>', methods=['GET'])
        def get_ai_agent_llm_provider(provider_key):
            try:
                detail = self._get_service_llm_provider(provider_key)
                backend_type = str(request.args.get('backend_type') or '').strip()
                if backend_type:
                    detail['mapped_env_preview'] = self._build_llm_provider_env(detail, backend_type)
                return jsonify(detail)
            except Exception as e:
                self.logger.error(f"查询AI Agent LLM Provider详情失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/ai-agents/<agent_key>/<service_name>/<agent_id>/apply-llm-provider', methods=['POST'])
        def apply_llm_provider_to_ai_agent(agent_key, service_name, agent_id):
            try:
                payload = request.get_json(silent=True) or {}
                project_id = str(payload.get('project_id') or request.args.get('project_id') or '').strip()
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400
                provider_key = str(payload.get('provider_key') or '').strip()
                refresh = bool(payload.get('refresh', False))
                if not provider_key:
                    return jsonify({'error': 'provider_key is required'}), 400
                result = self._apply_llm_provider_to_ai_agent(project_id, agent_key, service_name, agent_id, provider_key, refresh)
                return jsonify(result)
            except Exception as e:
                self.logger.error(f"单个AI Agent应用LLM Provider失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/ai-agents/apply-llm-provider/batch', methods=['POST'])
        def batch_apply_llm_provider_to_ai_agents():
            try:
                payload = request.get_json(silent=True) or {}
                project_id = str(payload.get('project_id') or '').strip()
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400
                provider_key = str(payload.get('provider_key') or '').strip()
                if not provider_key:
                    return jsonify({'error': 'provider_key is required'}), 400
                refresh = bool(payload.get('refresh', False))
                targets = payload.get('targets') if isinstance(payload.get('targets'), list) else []
                if not targets:
                    return jsonify({'error': 'targets is required'}), 400

                results = []
                success_count = 0
                for target in targets:
                    if not isinstance(target, dict):
                        continue
                    target_agent_key = str(target.get('agent_key') or '').strip()
                    target_service_name = str(target.get('service_name') or '').strip()
                    target_agent_id = str(target.get('agent_id') or '').strip()
                    if not target_agent_key or not target_service_name or not target_agent_id:
                        results.append({
                            'agent_key': target_agent_key,
                            'service_name': target_service_name,
                            'agent_id': target_agent_id,
                            'success': False,
                            'error': 'invalid target',
                        })
                        continue
                    try:
                        result = self._apply_llm_provider_to_ai_agent(
                            project_id,
                            target_agent_key,
                            target_service_name,
                            target_agent_id,
                            provider_key,
                            refresh,
                        )
                        success_count += 1
                        results.append({
                            'agent_key': target_agent_key,
                            'service_name': target_service_name,
                            'agent_id': target_agent_id,
                            'success': True,
                            **result,
                        })
                    except Exception as exc:
                        results.append({
                            'agent_key': target_agent_key,
                            'service_name': target_service_name,
                            'agent_id': target_agent_id,
                            'success': False,
                            'error': str(exc),
                        })
                status = 'success' if results and success_count == len(results) else ('partial_success' if success_count > 0 else 'failed')
                return jsonify({
                    'project_id': project_id,
                    'provider_key': provider_key,
                    'refresh': refresh,
                    'status': status,
                    'results': results,
                    'total': len(results),
                    'success_count': success_count,
                })
            except Exception as e:
                self.logger.error(f"批量应用LLM Provider失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/ai-agents/configure/batch', methods=['POST'])
        def batch_configure_ai_agents():
            try:
                payload = request.get_json(silent=True) or {}
                project_id = str(payload.get('project_id') or '').strip()
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400
                provider_keys_raw = payload.get('provider_keys') if isinstance(payload.get('provider_keys'), list) else []
                provider_keys = []
                seen = set()
                for item in provider_keys_raw:
                    text = str(item or '').strip()
                    if not text or text in seen:
                        continue
                    seen.add(text)
                    provider_keys.append(text)
                if not provider_keys:
                    return jsonify({'error': 'provider_keys is required'}), 400
                merge_strategy = str(payload.get('merge_strategy') or 'overwrite').strip().lower()
                if merge_strategy not in ('overwrite', 'merge'):
                    merge_strategy = 'overwrite'
                env_overrides = payload.get('env_overrides') if isinstance(payload.get('env_overrides'), dict) else {}
                file_overrides = payload.get('file_overrides') if isinstance(payload.get('file_overrides'), list) else []
                targets = payload.get('targets') if isinstance(payload.get('targets'), list) else []
                if not targets:
                    return jsonify({'error': 'targets is required'}), 400

                results = []
                success_count = 0
                for target in targets:
                    if not isinstance(target, dict):
                        continue
                    target_agent_key = str(target.get('agent_key') or '').strip()
                    target_service_name = str(target.get('service_name') or '').strip()
                    target_agent_id = str(target.get('agent_id') or '').strip()
                    if not target_agent_key or not target_service_name or not target_agent_id:
                        results.append({
                            'agent_key': target_agent_key,
                            'service_name': target_service_name,
                            'agent_id': target_agent_id,
                            'success': False,
                            'error': 'invalid target',
                        })
                        continue
                    try:
                        result = self._configure_llm_for_ai_agent(
                            project_id,
                            target_agent_key,
                            target_service_name,
                            target_agent_id,
                            provider_keys,
                            env_overrides,
                            file_overrides,
                            merge_strategy,
                        )
                        success_count += 1
                        results.append({
                            'agent_key': target_agent_key,
                            'service_name': target_service_name,
                            'agent_id': target_agent_id,
                            'success': True,
                            **result,
                        })
                    except Exception as exc:
                        results.append({
                            'agent_key': target_agent_key,
                            'service_name': target_service_name,
                            'agent_id': target_agent_id,
                            'success': False,
                            'error': str(exc),
                        })

                status = 'success' if results and success_count == len(results) else ('partial_success' if success_count > 0 else 'failed')
                return jsonify({
                    'project_id': project_id,
                    'provider_keys': provider_keys,
                    'merge_strategy': merge_strategy,
                    'status': status,
                    'results': results,
                    'total': len(results),
                    'success_count': success_count,
                })
            except Exception as e:
                self.logger.error(f"批量配置AI Agent失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/ai-agents/<agent_key>/<service_name>/<agent_id>/config', methods=['GET'])
        def get_ai_agent_config(agent_key, service_name, agent_id):
            try:
                project_id = str(request.args.get('project_id') or '').strip()
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400
                data, status_code = self._call_ai_helper_api(
                    project_id,
                    agent_key,
                    service_name,
                    'GET',
                    f"/api/ai-agents/{quote(agent_id, safe='')}/llm-config",
                    None,
                    timeout=(5, 20),
                )
                return jsonify(data), status_code
            except ValueError as exc:
                return jsonify({'error': str(exc)}), 404
            except Exception as e:
                self.logger.error(f"读取AI Agent配置失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/ai-helpers/<agent_key>/<service_name>', methods=['GET'])
        def get_ai_helper_detail(agent_key, service_name):
            try:
                project_id = str(request.args.get('project_id') or '').strip()
                if not project_id:
                    return jsonify({'error': 'project_id parameter is required'}), 400
                realtime = str(request.args.get('realtime') or '').strip().lower() == 'true'
                row = self._get_ai_helper_service_row(project_id, agent_key, service_name)
                if not row:
                    return jsonify({'error': 'AI helper service not found'}), 404
                if realtime:
                    health_payload, health_code = self._call_ai_helper_api(
                        project_id, agent_key, service_name, 'GET', '/api/ai-agents/health', None, timeout=(5, 20)
                    )
                    health_status = 'healthy' if health_code < 300 else 'unhealthy'
                    health_checked_at = datetime.now().isoformat()
                else:
                    snapshot = self._get_ai_helper_health_snapshot(project_id, agent_key, service_name)
                    health_payload = snapshot.get('health_payload') if isinstance(snapshot.get('health_payload'), dict) else {}
                    health_code = 200 if str(snapshot.get('health_status') or '').lower() == 'healthy' else 503
                    health_status = str(snapshot.get('health_status') or 'unknown').lower() or 'unknown'
                    health_checked_at = snapshot.get('checked_at')
                detail = self._serialize_ai_helper_item(row, health_payload=health_payload)
                detail['health_status'] = health_status
                detail['health_checked_at'] = health_checked_at
                detail['health_source'] = 'snapshot' if not realtime else 'realtime'
                agents_payload, agents_code = self._call_ai_helper_api(project_id, agent_key, service_name, 'GET', '/api/ai-agents', None, timeout=(5, 30))
                detail['agents'] = agents_payload.get('items', []) if agents_code < 300 and isinstance(agents_payload, dict) else []
                return jsonify(detail)
            except Exception as e:
                self.logger.error(f"查询AI helper详情失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/ai-helpers/<agent_key>/<service_name>/agents', methods=['GET', 'POST'])
        def ai_helper_agents(agent_key, service_name):
            project_id = str(request.args.get('project_id') or (request.get_json(silent=True) or {}).get('project_id') or '').strip()
            if not project_id:
                return jsonify({'error': 'project_id is required'}), 400
            try:
                if request.method == 'GET':
                    data, status_code = self._call_ai_helper_api(project_id, agent_key, service_name, 'GET', '/api/ai-agents')
                else:
                    payload = request.get_json(silent=True) or {}
                    data, status_code = self._call_ai_helper_api(project_id, agent_key, service_name, 'POST', '/api/ai-agents', payload)
                return jsonify(data), status_code
            except ValueError as exc:
                return jsonify({'error': str(exc)}), 404
            except Exception as e:
                self.logger.error(f"AI helper agents代理失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/ai-helpers/<agent_key>/<service_name>/agents/<agent_id>', methods=['GET', 'PUT', 'DELETE'])
        def ai_helper_agent_detail(agent_key, service_name, agent_id):
            payload = request.get_json(silent=True) or {}
            project_id = str(request.args.get('project_id') or payload.get('project_id') or '').strip()
            if not project_id:
                return jsonify({'error': 'project_id is required'}), 400
            endpoint = f"/api/ai-agents/{quote(agent_id, safe='')}"
            method = request.method
            try:
                data, status_code = self._call_ai_helper_api(
                    project_id,
                    agent_key,
                    service_name,
                    method,
                    endpoint,
                    payload if method in ('PUT', 'DELETE') else None,
                )
                return jsonify(data), status_code
            except ValueError as exc:
                return jsonify({'error': str(exc)}), 404
            except Exception as e:
                self.logger.error(f"AI helper单Agent代理失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/ai-helpers/<agent_key>/<service_name>/agents/<agent_id>/<action>', methods=['POST'])
        def ai_helper_agent_actions(agent_key, service_name, agent_id, action):
            if action not in ('activate', 'start', 'stop'):
                return jsonify({'error': 'unsupported action'}), 404
            payload = request.get_json(silent=True) or {}
            project_id = str(request.args.get('project_id') or payload.get('project_id') or '').strip()
            if not project_id:
                return jsonify({'error': 'project_id is required'}), 400
            try:
                data, status_code = self._call_ai_helper_api(
                    project_id,
                    agent_key,
                    service_name,
                    'POST',
                    f"/api/ai-agents/{quote(agent_id, safe='')}/{action}",
                    payload,
                )
                return jsonify(data), status_code
            except ValueError as exc:
                return jsonify({'error': str(exc)}), 404
            except Exception as e:
                self.logger.error(f"AI helper Agent动作失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/ai-helpers/<agent_key>/<service_name>/agents/<agent_id>/env', methods=['GET', 'PUT', 'DELETE'])
        def ai_helper_agent_env(agent_key, service_name, agent_id):
            payload = request.get_json(silent=True) or {}
            project_id = str(request.args.get('project_id') or payload.get('project_id') or '').strip()
            if not project_id:
                return jsonify({'error': 'project_id is required'}), 400
            try:
                data, status_code = self._call_ai_helper_api(
                    project_id,
                    agent_key,
                    service_name,
                    request.method,
                    f"/api/ai-agents/{quote(agent_id, safe='')}/env",
                    payload if request.method in ('PUT', 'DELETE') else None,
                )
                return jsonify(data), status_code
            except ValueError as exc:
                return jsonify({'error': str(exc)}), 404
            except Exception as e:
                self.logger.error(f"AI helper Agent env代理失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/ai-helpers/<agent_key>/<service_name>/helper-env', methods=['GET'])
        def ai_helper_runtime_env(agent_key, service_name):
            project_id = str(request.args.get('project_id') or '').strip()
            if not project_id:
                return jsonify({'error': 'project_id is required'}), 400
            try:
                data, status_code = self._call_ai_helper_api(
                    project_id,
                    agent_key,
                    service_name,
                    'GET',
                    '/api/ai-agents/helper-env',
                    None,
                    timeout=(5, 20),
                )
                return jsonify(data), status_code
            except ValueError as exc:
                return jsonify({'error': str(exc)}), 404
            except Exception as e:
                self.logger.error(f"AI helper运行环境变量代理失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/ai-helpers/<agent_key>/<service_name>/sessions', methods=['GET', 'POST'])
        def ai_helper_sessions(agent_key, service_name):
            payload = request.get_json(silent=True) or {}
            project_id = str(payload.get('project_id') or request.args.get('project_id') or '').strip()
            if not project_id:
                return jsonify({'error': 'project_id is required'}), 400
            try:
                if request.method == 'GET':
                    sessions = self._list_ai_single_sessions(project_id, agent_key, service_name)
                    # Best effort bootstrap from helper for legacy sessions not yet persisted in platform.
                    if not sessions:
                        try:
                            data, status_code = self._call_ai_helper_api(
                                project_id,
                                agent_key,
                                service_name,
                                'GET',
                                '/api/ai-agents/sessions',
                                None,
                            )
                            if status_code < 300 and isinstance(data, dict):
                                for item in (data.get('items') or []):
                                    if isinstance(item, dict):
                                        self._save_ai_single_session(project_id, agent_key, service_name, item)
                                sessions = self._list_ai_single_sessions(project_id, agent_key, service_name)
                        except Exception:
                            # Keep platform-first semantics; helper unavailable should not break history reads.
                            pass
                    return jsonify({'items': sessions, 'total': len(sessions)})
                data, status_code = self._call_ai_helper_api(
                    project_id,
                    agent_key,
                    service_name,
                    'POST',
                    '/api/ai-agents/sessions',
                    payload,
                )
                if status_code < 300 and isinstance(data, dict):
                    saved = self._save_ai_single_session(project_id, agent_key, service_name, data)
                    return jsonify(saved), status_code
                return jsonify(data), status_code
            except Exception as e:
                self.logger.error(f"AI helper会话代理失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/ai-helpers/<agent_key>/<service_name>/sessions/<session_id>', methods=['GET', 'DELETE'])
        def get_ai_helper_session(agent_key, service_name, session_id):
            payload = request.get_json(silent=True) or {}
            project_id = str(request.args.get('project_id') or payload.get('project_id') or '').strip()
            if not project_id:
                return jsonify({'error': 'project_id is required'}), 400
            try:
                if request.method == 'DELETE':
                    helper_result = {'deleted': True, 'session_id': session_id}
                    status_code = 200
                    try:
                        helper_result, status_code = self._call_ai_helper_api(
                            project_id,
                            agent_key,
                            service_name,
                            'DELETE',
                            f"/api/ai-agents/sessions/{quote(session_id, safe='')}",
                            payload if isinstance(payload, dict) else None,
                        )
                    except Exception as exc:
                        helper_result = {'deleted': False, 'session_id': session_id, 'helper_error': str(exc)}
                        status_code = 207
                    self._delete_ai_single_session(project_id, agent_key, service_name, session_id)
                    return jsonify(helper_result), status_code
                session = self._load_ai_single_session(project_id, agent_key, service_name, session_id)
                if session:
                    return jsonify(session)
                data, status_code = self._call_ai_helper_api(
                    project_id,
                    agent_key,
                    service_name,
                    'GET',
                    f"/api/ai-agents/sessions/{quote(session_id, safe='')}",
                    None,
                )
                if status_code < 300 and isinstance(data, dict):
                    saved = self._save_ai_single_session(project_id, agent_key, service_name, data)
                    return jsonify(saved), status_code
                return jsonify(data), status_code
            except Exception as e:
                self.logger.error(f"查询AI helper会话失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/ai-helpers/<agent_key>/<service_name>/sessions/<session_id>/messages', methods=['POST'])
        def send_ai_helper_session_message(agent_key, service_name, session_id):
            payload = request.get_json(silent=True) or {}
            project_id = str(payload.get('project_id') or request.args.get('project_id') or '').strip()
            if not project_id:
                return jsonify({'error': 'project_id is required'}), 400
            stream = str(request.args.get('stream') or '').lower() == 'true'
            try:
                if stream:
                    row = self._get_ai_helper_service_row(project_id, agent_key, service_name)
                    if not row:
                        return jsonify({'error': f'AI helper service not found: {agent_key}/{service_name}'}), 404
                    agent_ip = str(row.get('agent_ip') or '').strip()
                    if not agent_ip:
                        return jsonify({'error': f'AI helper service has no agent IP: {agent_key}/{service_name}'}), 400
                    rest_port = self._resolve_helper_rest_port(row)
                    target = f"http://{agent_ip}:{rest_port}/api/ai-agents/sessions/{quote(session_id, safe='')}/messages/stream"

                    upstream = requests.request('POST', target, json=payload, timeout=(10, 300), stream=True)
                    if upstream.status_code >= 400:
                        try:
                            err_payload = upstream.json()
                        except Exception:
                            err_payload = {'error': upstream.text or f'upstream status {upstream.status_code}'}
                        upstream.close()
                        return jsonify(err_payload), upstream.status_code

                    stream_capture = {
                        'buffer': '',
                        'done_session': None,
                    }

                    def _proxy_stream():
                        try:
                            for chunk in upstream.iter_content(chunk_size=1):
                                if not chunk:
                                    continue
                                try:
                                    text = chunk.decode('utf-8', errors='ignore')
                                    if text:
                                        stream_capture['buffer'] += text
                                        parts = stream_capture['buffer'].split('\n\n')
                                        stream_capture['buffer'] = parts.pop() if parts else ''
                                        for part in parts:
                                            if not part.strip():
                                                continue
                                            data_lines = [
                                                line[5:].strip()
                                                for line in part.split('\n')
                                                if line.startswith('data:')
                                            ]
                                            joined = '\n'.join(data_lines).strip()
                                            if not joined or joined == '[DONE]':
                                                continue
                                            try:
                                                event_payload = json.loads(joined)
                                            except Exception:
                                                event_payload = None
                                            if isinstance(event_payload, dict) and str(event_payload.get('type') or '') == 'done':
                                                if isinstance(event_payload.get('session'), dict):
                                                    stream_capture['done_session'] = event_payload.get('session')
                                except Exception:
                                    pass
                                yield chunk
                        finally:
                            upstream.close()
                            if isinstance(stream_capture.get('done_session'), dict):
                                try:
                                    self._save_ai_single_session(
                                        project_id,
                                        agent_key,
                                        service_name,
                                        stream_capture.get('done_session') or {},
                                    )
                                except Exception as persist_exc:
                                    self.logger.warning(
                                        f"流式会话完成后持久化失败: {project_id}/{agent_key}/{service_name}/{session_id}: {persist_exc}"
                                    )

                    return Response(
                        _proxy_stream(),
                        status=upstream.status_code,
                        mimetype='text/event-stream',
                        headers={
                            'Cache-Control': 'no-cache',
                            'Connection': 'keep-alive',
                            'X-Accel-Buffering': 'no',
                        },
                    )

                data, status_code = self._call_ai_helper_api(
                    project_id,
                    agent_key,
                    service_name,
                    'POST',
                    f"/api/ai-agents/sessions/{quote(session_id, safe='')}/messages",
                    payload,
                )
                if status_code < 300 and isinstance(data, dict):
                    session_payload = data.get('session') if isinstance(data.get('session'), dict) else None
                    if session_payload:
                        self._save_ai_single_session(project_id, agent_key, service_name, session_payload)
                return jsonify(data), status_code
            except Exception as e:
                self.logger.error(f"发送AI helper会话消息失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/ai-helpers/sessions/global', methods=['GET'])
        def list_project_ai_agent_sessions_global():
            try:
                project_id = str(request.args.get('project_id') or '').strip()
                if not project_id:
                    return jsonify({'error': 'project_id parameter is required'}), 400
                try:
                    page = max(1, int(request.args.get('page', 1)))
                except Exception:
                    page = 1
                try:
                    per_page = max(1, min(200, int(request.args.get('per_page', 100))))
                except Exception:
                    per_page = 100
                q = str(request.args.get('q') or '').strip().lower()
                node_filter = str(request.args.get('node') or '').strip()
                service_name_filter = str(request.args.get('service_name') or '').strip()
                status_filter = str(request.args.get('status') or '').strip().lower()
                invalid_filter = str(request.args.get('invalid_filter') or 'all').strip().lower()
                invalid_reason_filter = str(request.args.get('invalid_reason') or '').strip()

                table_name = self.db_manager.get_table_name('agent_services')
                rows = self.db_manager.fetch_all(
                    f"""
                    SELECT service_uid, project_id, agent_key, agent_hostname, agent_ip,
                           service_name, image, status, tags_json, ports_json, raw_json, source, is_stale,
                           first_seen_at, last_seen_at, updated_at
                    FROM {table_name}
                    WHERE project_id = %s AND is_stale = 0
                    ORDER BY last_seen_at DESC
                    """ if self.db_manager.db_type == 'mysql' else
                    f"""
                    SELECT service_uid, project_id, agent_key, agent_hostname, agent_ip,
                           service_name, image, status, tags_json, ports_json, raw_json, source, is_stale,
                           first_seen_at, last_seen_at, updated_at
                    FROM {table_name}
                    WHERE project_id = ? AND is_stale = 0
                    ORDER BY last_seen_at DESC
                    """,
                    (project_id,)
                ) or []

                helper_rows = [row for row in rows if self._has_ai_helper_tag(row.get('tags_json'))]

                items: List[Dict[str, Any]] = []
                helper_unreachable: List[Dict[str, Any]] = []

                def _normalize_session_agent_ids(session_payload: Dict[str, Any]) -> List[str]:
                    values: List[str] = []
                    raw_agent_ids = session_payload.get('agent_ids')
                    if isinstance(raw_agent_ids, list):
                        values = [str(item).strip() for item in raw_agent_ids if str(item).strip()]
                    elif isinstance(raw_agent_ids, str):
                        raw_text = raw_agent_ids.strip()
                        if raw_text:
                            try:
                                parsed = json.loads(raw_text)
                                if isinstance(parsed, list):
                                    values = [str(item).strip() for item in parsed if str(item).strip()]
                                else:
                                    values = [raw_text]
                            except Exception:
                                values = [raw_text]
                    backend_text = str(session_payload.get('backend') or '').strip()
                    if backend_text and backend_text not in values:
                        values.append(backend_text)
                    return values

                for row in helper_rows:
                    helper_agent_key = str(row.get('agent_key') or '').strip()
                    helper_service_name = str(row.get('service_name') or '').strip()
                    helper_context = {
                        'agent_key': helper_agent_key,
                        'service_name': helper_service_name,
                        'agent_hostname': row.get('agent_hostname') or helper_agent_key,
                        'agent_ip': row.get('agent_ip') or '',
                    }

                    try:
                        sessions_data, sessions_code = self._call_ai_helper_api(
                            project_id,
                            helper_agent_key,
                            helper_service_name,
                            'GET',
                            '/api/ai-agents/sessions',
                            None,
                            timeout=(5, 30),
                        )
                        agents_data, agents_code = self._call_ai_helper_api(
                            project_id,
                            helper_agent_key,
                            helper_service_name,
                            'GET',
                            '/api/ai-agents',
                            None,
                            timeout=(5, 30),
                        )
                        if sessions_code >= 300:
                            raise ValueError(f'sessions status {sessions_code}: {sessions_data}')
                        if agents_code >= 300:
                            raise ValueError(f'ai-agents status {agents_code}: {agents_data}')
                    except Exception as helper_exc:
                        helper_unreachable.append({
                            **helper_context,
                            'health_status': 'unreachable',
                            'error': str(helper_exc),
                        })
                        continue

                    session_list = sessions_data.get('items') if isinstance(sessions_data, dict) else []
                    if not isinstance(session_list, list):
                        session_list = []
                    helper_agents = agents_data.get('items') if isinstance(agents_data, dict) else []
                    if not isinstance(helper_agents, list):
                        helper_agents = []
                    helper_agent_id_set = {
                        str(item.get('agent_id') or item.get('name') or '').strip()
                        for item in helper_agents if isinstance(item, dict)
                    }
                    helper_agent_id_set = {item for item in helper_agent_id_set if item}

                    for session in session_list:
                        if not isinstance(session, dict):
                            continue
                        session_mode = str(session.get('session_mode') or '').strip().lower()
                        if session_mode not in ('pipe', 'pty', 'invoke'):
                            session_mode = 'pty'
                        status = str(session.get('status') or 'unknown').strip().lower()
                        backend = str(session.get('backend') or '').strip()
                        agent_ids = _normalize_session_agent_ids(session)

                        invalid_reasons: List[str] = []
                        if status != 'ready':
                            invalid_reasons.append(f'status_not_ready:{status or "unknown"}')
                        pty_pid = session.get('pty_pid')
                        backend_pid = session.get('backend_pid')
                        if backend_pid is None:
                            backend_pid = pty_pid
                        if status == 'ready':
                            if session_mode == 'pipe':
                                has_backend_pid = isinstance(backend_pid, int) and backend_pid > 0
                                if not has_backend_pid:
                                    invalid_reasons.append('backend_pid_missing')
                            elif session_mode == 'pty':
                                has_pty_pid = isinstance(pty_pid, int) and pty_pid > 0
                                if not has_pty_pid:
                                    invalid_reasons.append('pty_missing')

                        if backend and backend not in helper_agent_id_set:
                            invalid_reasons.append('backend_not_found_in_helper_agents')
                        missing_agent_ids = [agent_id for agent_id in agent_ids if agent_id not in helper_agent_id_set]
                        if missing_agent_ids:
                            invalid_reasons.append(f'agent_ids_not_found:{",".join(missing_agent_ids)}')

                        items.append({
                            'project_id': project_id,
                            **helper_context,
                            'health_status': 'healthy',
                            'session_id': session.get('session_id'),
                            'backend': backend or None,
                            'agent_ids': agent_ids,
                            'status': session.get('status'),
                            'session_mode': session_mode,
                            'pty_pid': pty_pid,
                            'backend_pid': backend_pid,
                            'pty_started_at': session.get('pty_started_at'),
                            'last_error': session.get('last_error'),
                            'metadata': session.get('metadata') if isinstance(session.get('metadata'), dict) else {},
                            'created_at': session.get('created_at'),
                            'updated_at': session.get('updated_at'),
                            'is_invalid': len(invalid_reasons) > 0,
                            'invalid_reasons': invalid_reasons,
                        })

                overall_total = len(items)
                invalid_count = len([item for item in items if item.get('is_invalid')])
                normal_count = overall_total - invalid_count

                filtered_items = []
                for item in items:
                    node_text = str(item.get('agent_hostname') or item.get('agent_key') or '')
                    service_name_text = str(item.get('service_name') or '')
                    status_text = str(item.get('status') or 'unknown').strip().lower()
                    is_invalid = bool(item.get('is_invalid'))
                    invalid_reasons = item.get('invalid_reasons') if isinstance(item.get('invalid_reasons'), list) else []
                    invalid_reasons = [str(reason) for reason in invalid_reasons]
                    search_text = ' '.join([
                        str(item.get('session_id') or ''),
                        str(item.get('backend') or ''),
                        str(item.get('agent_key') or ''),
                        node_text,
                        service_name_text,
                        ','.join(item.get('agent_ids') or []),
                    ]).lower()

                    if q and q not in search_text:
                        continue
                    if node_filter and node_text != node_filter:
                        continue
                    if service_name_filter and service_name_text != service_name_filter:
                        continue
                    if status_filter and status_text != status_filter:
                        continue
                    if invalid_filter == 'invalid' and not is_invalid:
                        continue
                    if invalid_filter == 'normal' and is_invalid:
                        continue
                    if invalid_reason_filter and invalid_reason_filter not in invalid_reasons:
                        continue
                    filtered_items.append(item)

                filtered_total = len(filtered_items)
                node_options = sorted({
                    str(item.get('agent_hostname') or item.get('agent_key') or '').strip()
                    for item in items
                    if str(item.get('agent_hostname') or item.get('agent_key') or '').strip()
                })
                service_name_options = sorted({
                    str(item.get('service_name') or '').strip()
                    for item in items
                    if str(item.get('service_name') or '').strip()
                })
                status_options = sorted({
                    str(item.get('status') or 'unknown').strip()
                    for item in items
                })
                invalid_reason_options = sorted({
                    str(reason).strip()
                    for item in items
                    for reason in (item.get('invalid_reasons') if isinstance(item.get('invalid_reasons'), list) else [])
                    if str(reason).strip()
                })
                start = (page - 1) * per_page
                end = start + per_page
                paginated_items = filtered_items[start:end]
                return jsonify({
                    'project_id': project_id,
                    'items': paginated_items,
                    'total': filtered_total,
                    'filtered_total': filtered_total,
                    'page': page,
                    'per_page': per_page,
                    'stats': {
                        'total_sessions': overall_total,
                        'normal_count': normal_count,
                        'invalid_count': invalid_count,
                        'helper_total': len(helper_rows),
                        'helper_reachable_count': len(helper_rows) - len(helper_unreachable),
                        'helper_unreachable_count': len(helper_unreachable),
                    },
                    'filters': {
                        'nodes': node_options,
                        'service_names': service_name_options,
                        'statuses': status_options,
                        'invalid_reasons': invalid_reason_options,
                    },
                    'helper_unreachable': helper_unreachable,
                })
            except Exception as e:
                self.logger.error(f"查询AI helper全局会话失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/ai-helpers/sessions/global/delete-batch', methods=['POST'])
        def batch_delete_project_ai_agent_sessions_global():
            try:
                payload = request.get_json(silent=True) or {}
                project_id = str(payload.get('project_id') or '').strip()
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400
                targets = payload.get('targets') or []
                if not isinstance(targets, list) or len(targets) == 0:
                    return jsonify({'error': 'targets is required'}), 400

                results = []
                success_count = 0
                for item in targets:
                    target = item if isinstance(item, dict) else {}
                    agent_key = str(target.get('agent_key') or '').strip()
                    service_name = str(target.get('service_name') or '').strip()
                    session_id = str(target.get('session_id') or '').strip()
                    if not agent_key or not service_name or not session_id:
                        results.append({
                            'agent_key': agent_key,
                            'service_name': service_name,
                            'session_id': session_id,
                            'success': False,
                            'status_code': 400,
                            'error': 'agent_key/service_name/session_id are required',
                        })
                        continue
                    try:
                        response_payload, status_code = self._call_ai_helper_api(
                            project_id,
                            agent_key,
                            service_name,
                            'DELETE',
                            f"/api/ai-agents/sessions/{quote(session_id, safe='')}",
                            {'project_id': project_id},
                            timeout=(5, 30),
                        )
                        success = status_code < 300
                        if success:
                            success_count += 1
                        results.append({
                            'agent_key': agent_key,
                            'service_name': service_name,
                            'session_id': session_id,
                            'success': success,
                            'status_code': status_code,
                            'response': response_payload,
                            'error': '' if success else str(response_payload),
                        })
                    except Exception as item_exc:
                        results.append({
                            'agent_key': agent_key,
                            'service_name': service_name,
                            'session_id': session_id,
                            'success': False,
                            'status_code': 500,
                            'error': str(item_exc),
                        })

                total = len(results)
                failed_count = total - success_count
                status_text = 'success' if failed_count == 0 else ('failed' if success_count == 0 else 'partial_success')
                return jsonify({
                    'project_id': project_id,
                    'status': status_text,
                    'total': total,
                    'success_count': success_count,
                    'failed_count': failed_count,
                    'results': results,
                })
            except Exception as e:
                self.logger.error(f"批量终止AI helper全局会话失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/ai-helpers/sessions/batch', methods=['GET', 'POST'])
        def create_ai_helper_batch_session():
            try:
                if request.method == 'GET':
                    project_id = str(request.args.get('project_id') or '').strip()
                    if not project_id:
                        return jsonify({'error': 'project_id is required'}), 400
                    batches_table = self.db_manager.get_table_name('ai_agent_session_batches')
                    items_table = self.db_manager.get_table_name('ai_agent_session_batch_items')
                    rows = self.db_manager.fetch_all(
                        f"SELECT batch_id, project_id, created_by, status, request_json, created_at, updated_at FROM {batches_table} WHERE project_id = %s ORDER BY updated_at DESC, created_at DESC"
                        if self.db_manager.db_type == 'mysql' else
                        f"SELECT batch_id, project_id, created_by, status, request_json, created_at, updated_at FROM {batches_table} WHERE project_id = ? ORDER BY updated_at DESC, created_at DESC",
                        (project_id,)
                    ) or []
                    items = []
                    for row in rows:
                        batch_id = str(row.get('batch_id') or '')
                        summary_rows = self.db_manager.fetch_all(
                            f"""
                            SELECT
                              COUNT(*) AS helper_total,
                              SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) AS success_count,
                              SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed_count,
                              SUM(CASE WHEN status NOT IN ('success', 'failed') THEN 1 ELSE 0 END) AS pending_count
                            FROM {items_table}
                            WHERE batch_id = %s
                            """ if self.db_manager.db_type == 'mysql' else
                            f"""
                            SELECT
                              COUNT(*) AS helper_total,
                              SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) AS success_count,
                              SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed_count,
                              SUM(CASE WHEN status NOT IN ('success', 'failed') THEN 1 ELSE 0 END) AS pending_count
                            FROM {items_table}
                            WHERE batch_id = ?
                            """,
                            (batch_id,)
                        ) or []
                        summary = summary_rows[0] if summary_rows else {}
                        request_payload = {}
                        raw_request = row.get('request_json')
                        if raw_request:
                            try:
                                request_payload = json.loads(raw_request) if isinstance(raw_request, str) else (raw_request or {})
                            except Exception:
                                request_payload = {}
                        items.append({
                            'batch_id': batch_id,
                            'project_id': row.get('project_id'),
                            'created_by': row.get('created_by'),
                            'status': row.get('status') or 'pending',
                            'session_mode': (request_payload.get('session_mode') if isinstance(request_payload, dict) else None) or 'invoke',
                            'created_at': row.get('created_at'),
                            'updated_at': row.get('updated_at'),
                            'helper_total': int(summary.get('helper_total') or 0),
                            'success_count': int(summary.get('success_count') or 0),
                            'failed_count': int(summary.get('failed_count') or 0),
                            'pending_count': int(summary.get('pending_count') or 0),
                        })
                    return jsonify({'project_id': project_id, 'items': items, 'total': len(items)})

                payload = request.get_json(silent=True) or {}
                project_id = str(payload.get('project_id') or '').strip()
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400

                table_name = self.db_manager.get_table_name('agent_services')
                rows = self.db_manager.fetch_all(
                    f"SELECT service_uid, project_id, agent_key, agent_hostname, agent_ip, service_name, image, status, tags_json, ports_json, raw_json, source, is_stale, first_seen_at, last_seen_at, updated_at FROM {table_name} WHERE project_id = %s AND is_stale = 0"
                    if self.db_manager.db_type == 'mysql' else
                    f"SELECT service_uid, project_id, agent_key, agent_hostname, agent_ip, service_name, image, status, tags_json, ports_json, raw_json, source, is_stale, first_seen_at, last_seen_at, updated_at FROM {table_name} WHERE project_id = ? AND is_stale = 0",
                    (project_id,)
                ) or []
                requested_helpers = payload.get('helpers') or []
                requested_map = {
                    f"{str(item.get('agent_key') or '').strip()}::{str(item.get('service_name') or '').strip()}": item
                    for item in requested_helpers if isinstance(item, dict)
                }

                helper_rows = []
                for row in rows:
                    if not self._has_ai_helper_tag(row.get('tags_json')):
                        continue
                    key = f"{str(row.get('agent_key') or '').strip()}::{str(row.get('service_name') or '').strip()}"
                    if requested_map and key not in requested_map:
                        continue
                    helper_rows.append(row)

                user_ctx = self._get_request_user_context()
                batch_id = self._create_ai_batch(project_id, user_ctx.get('username', 'system'), payload)
                results = []
                success_count = 0
                for row in helper_rows:
                    helper_request = requested_map.get(f"{row.get('agent_key')}::{row.get('service_name')}", {})
                    helper_payload = {
                        'agent_id': helper_request.get('agent_id'),
                        'agent_ids': helper_request.get('agent_ids') or payload.get('agent_ids'),
                        'session_mode': helper_request.get('session_mode') or payload.get('session_mode'),
                        'metadata': payload.get('metadata') or {},
                    }
                    try:
                        data, status_code = self._call_ai_helper_api(
                            project_id,
                            str(row.get('agent_key') or ''),
                            str(row.get('service_name') or ''),
                            'POST',
                            '/api/ai-agents/sessions',
                            helper_payload,
                        )
                        ok = status_code < 300 and isinstance(data, dict) and bool(data.get('session_id'))
                        if ok:
                            success_count += 1
                        agent_ids = data.get('agent_ids') if isinstance(data, dict) else []
                        self._upsert_ai_batch_item(
                            batch_id,
                            project_id,
                            str(row.get('agent_key') or ''),
                            str(row.get('service_name') or ''),
                            data.get('session_id') if isinstance(data, dict) else None,
                            agent_ids if isinstance(agent_ids, list) else [],
                            'success' if ok else 'failed',
                            '' if ok else str(data),
                        )
                        results.append({
                            'agent_key': row.get('agent_key'),
                            'service_name': row.get('service_name'),
                            'success': ok,
                            'status_code': status_code,
                            'helper_session_id': data.get('session_id') if isinstance(data, dict) else None,
                            'helper_agent_ids': agent_ids if isinstance(agent_ids, list) else [],
                            'response': data,
                        })
                    except Exception as exc:
                        self._upsert_ai_batch_item(
                            batch_id,
                            project_id,
                            str(row.get('agent_key') or ''),
                            str(row.get('service_name') or ''),
                            None,
                            [],
                            'failed',
                            str(exc),
                        )
                        results.append({
                            'agent_key': row.get('agent_key'),
                            'service_name': row.get('service_name'),
                            'success': False,
                            'error': str(exc),
                        })

                batch_table = self.db_manager.get_table_name('ai_agent_session_batches')
                final_status = 'success' if results and success_count == len(results) else ('partial_success' if success_count > 0 or not results else 'failed')
                self.db_manager.execute_query(
                    f"UPDATE {batch_table} SET status = %s WHERE batch_id = %s"
                    if self.db_manager.db_type == 'mysql' else
                    f"UPDATE {batch_table} SET status = ? , updated_at = ? WHERE batch_id = ?",
                    (final_status, batch_id)
                    if self.db_manager.db_type == 'mysql' else
                    (final_status, datetime.now().isoformat(), batch_id)
                )
                return jsonify({
                    'batch_id': batch_id,
                    'project_id': project_id,
                    'status': final_status,
                    'results': results,
                }), 201
            except Exception as e:
                self.logger.error(f"创建AI helper批量会话失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/ai-helpers/sessions/batch/<batch_id>', methods=['GET', 'DELETE'])
        def get_ai_helper_batch(batch_id):
            try:
                batch = self._load_ai_batch(batch_id)
                if not batch:
                    return jsonify({'error': 'batch not found'}), 404
                if request.method == 'DELETE':
                    project_id = str(batch.get('project_id') or '')
                    items_table = self.db_manager.get_table_name('ai_agent_session_batch_items')
                    messages_table = self.db_manager.get_table_name('ai_agent_session_batch_messages')
                    batch_table = self.db_manager.get_table_name('ai_agent_session_batches')
                    items = self.db_manager.fetch_all(
                        f"SELECT agent_key, service_name, helper_session_id FROM {items_table} WHERE batch_id = %s ORDER BY agent_key, service_name"
                        if self.db_manager.db_type == 'mysql' else
                        f"SELECT agent_key, service_name, helper_session_id FROM {items_table} WHERE batch_id = ? ORDER BY agent_key, service_name",
                        (batch_id,)
                    ) or []
                    helper_cleanup = []
                    for item in items:
                        helper_session_id = str(item.get('helper_session_id') or '').strip()
                        if not helper_session_id:
                            helper_cleanup.append({
                                'agent_key': item.get('agent_key'),
                                'service_name': item.get('service_name'),
                                'session_id': helper_session_id,
                                'deleted': False,
                                'status_code': 0,
                                'error': 'missing helper_session_id',
                            })
                            continue
                        try:
                            cleanup_data, cleanup_code = self._call_ai_helper_api(
                                project_id,
                                str(item.get('agent_key') or ''),
                                str(item.get('service_name') or ''),
                                'DELETE',
                                f"/api/ai-agents/sessions/{quote(helper_session_id, safe='')}",
                                None,
                                timeout=(5, 30),
                            )
                            helper_cleanup.append({
                                'agent_key': item.get('agent_key'),
                                'service_name': item.get('service_name'),
                                'session_id': helper_session_id,
                                'deleted': cleanup_code < 300,
                                'status_code': cleanup_code,
                                'response': cleanup_data,
                            })
                        except Exception as cleanup_exc:
                            helper_cleanup.append({
                                'agent_key': item.get('agent_key'),
                                'service_name': item.get('service_name'),
                                'session_id': helper_session_id,
                                'deleted': False,
                                'status_code': 500,
                                'error': str(cleanup_exc),
                            })

                    self.db_manager.execute_query(
                        f"DELETE FROM {messages_table} WHERE batch_id = %s"
                        if self.db_manager.db_type == 'mysql' else
                        f"DELETE FROM {messages_table} WHERE batch_id = ?",
                        (batch_id,)
                    )
                    self.db_manager.execute_query(
                        f"DELETE FROM {items_table} WHERE batch_id = %s"
                        if self.db_manager.db_type == 'mysql' else
                        f"DELETE FROM {items_table} WHERE batch_id = ?",
                        (batch_id,)
                    )
                    self.db_manager.execute_query(
                        f"DELETE FROM {batch_table} WHERE batch_id = %s"
                        if self.db_manager.db_type == 'mysql' else
                        f"DELETE FROM {batch_table} WHERE batch_id = ?",
                        (batch_id,)
                    )
                    return jsonify({
                        'batch_id': batch_id,
                        'deleted': True,
                        'helper_cleanup': helper_cleanup,
                    })
                items_table = self.db_manager.get_table_name('ai_agent_session_batch_items')
                items = self.db_manager.fetch_all(
                    f"SELECT * FROM {items_table} WHERE batch_id = %s ORDER BY agent_key, service_name"
                    if self.db_manager.db_type == 'mysql' else
                    f"SELECT * FROM {items_table} WHERE batch_id = ? ORDER BY agent_key, service_name",
                    (batch_id,)
                ) or []
                normalized_items = []
                request_payload = {}
                raw_request = batch.get('request_json')
                if raw_request:
                    try:
                        request_payload = json.loads(raw_request) if isinstance(raw_request, str) else (raw_request or {})
                    except Exception:
                        request_payload = {}
                for item in items:
                    agent_ids = []
                    raw = item.get('helper_agent_ids_json')
                    if raw:
                        try:
                            agent_ids = json.loads(raw) if isinstance(raw, str) else list(raw or [])
                        except Exception:
                            agent_ids = []
                    normalized_items.append({
                        'agent_key': item.get('agent_key'),
                        'service_name': item.get('service_name'),
                        'helper_session_id': item.get('helper_session_id'),
                        'helper_agent_ids': agent_ids,
                        'status': item.get('status'),
                        'last_error': item.get('last_error') or '',
                        'updated_at': item.get('updated_at'),
                    })
                return jsonify({
                    'batch_id': batch.get('batch_id'),
                    'project_id': batch.get('project_id'),
                    'status': batch.get('status'),
                    'session_mode': (request_payload.get('session_mode') if isinstance(request_payload, dict) else None) or 'invoke',
                    'created_by': batch.get('created_by'),
                    'created_at': batch.get('created_at'),
                    'updated_at': batch.get('updated_at'),
                    'items': normalized_items,
                })
            except Exception as e:
                self.logger.error(f"查询AI helper批次详情失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/ai-helpers/sessions/batch/<batch_id>/messages', methods=['GET', 'POST'])
        def ai_helper_batch_messages(batch_id):
            try:
                batch = self._load_ai_batch(batch_id)
                if not batch:
                    return jsonify({'error': 'batch not found'}), 404

                items_table = self.db_manager.get_table_name('ai_agent_session_batch_items')
                messages_table = self.db_manager.get_table_name('ai_agent_session_batch_messages')

                if request.method == 'GET':
                    rows = self.db_manager.fetch_all(
                        f"SELECT round_no, role, content, response_json, created_at FROM {messages_table} WHERE batch_id = %s ORDER BY round_no ASC"
                        if self.db_manager.db_type == 'mysql' else
                        f"SELECT round_no, role, content, response_json, created_at FROM {messages_table} WHERE batch_id = ? ORDER BY round_no ASC",
                        (batch_id,)
                    ) or []
                    rounds = []
                    for row in rows:
                        payload = {}
                        raw = row.get('response_json')
                        if raw:
                            try:
                                payload = json.loads(raw) if isinstance(raw, str) else raw
                            except Exception:
                                payload = {'raw': raw}
                        rounds.append({
                            'round_no': row.get('round_no'),
                            'role': row.get('role'),
                            'content': row.get('content') or '',
                            'response': payload,
                            'created_at': row.get('created_at'),
                        })
                    return jsonify({'batch_id': batch_id, 'items': rounds, 'total': len(rounds)})

                payload = request.get_json(silent=True) or {}
                content = str(payload.get('content') or '').strip()
                role = str(payload.get('role') or 'user').strip() or 'user'
                if not content:
                    return jsonify({'error': 'content is required'}), 400
                stream = str(request.args.get('stream') or '').lower() == 'true'

                item_rows = self.db_manager.fetch_all(
                    f"SELECT * FROM {items_table} WHERE batch_id = %s ORDER BY agent_key, service_name"
                    if self.db_manager.db_type == 'mysql' else
                    f"SELECT * FROM {items_table} WHERE batch_id = ? ORDER BY agent_key, service_name",
                    (batch_id,)
                ) or []
                round_rows = self.db_manager.fetch_all(
                    f"SELECT MAX(round_no) as max_round FROM {messages_table} WHERE batch_id = %s"
                    if self.db_manager.db_type == 'mysql' else
                    f"SELECT MAX(round_no) as max_round FROM {messages_table} WHERE batch_id = ?",
                    (batch_id,)
                ) or []
                next_round = int((round_rows[0].get('max_round') if round_rows else 0) or 0) + 1

                if stream:
                    def _batch_stream():
                        try:
                            start_payload = {
                                'type': 'start',
                                'batch_id': batch_id,
                                'round_no': next_round,
                                'total_items': len(item_rows),
                                'role': role,
                            }
                            yield f"data: {json.dumps(start_payload, ensure_ascii=False)}\n\n"

                            results = []
                            success_count = 0
                            for item in item_rows:
                                helper_session_id = str(item.get('helper_session_id') or '').strip()
                                item_key = {
                                    'agent_key': item.get('agent_key'),
                                    'service_name': item.get('service_name'),
                                }
                                if not helper_session_id:
                                    item_result = {
                                        **item_key,
                                        'success': False,
                                        'error': item.get('last_error') or 'missing helper_session_id',
                                    }
                                    results.append(item_result)
                                    yield f"data: {json.dumps({'type': 'item', 'batch_id': batch_id, **item_result}, ensure_ascii=False)}\n\n"
                                    continue
                                try:
                                    helper_agent_ids = []
                                    raw_helper_agent_ids = item.get('helper_agent_ids_json')
                                    if raw_helper_agent_ids:
                                        try:
                                            helper_agent_ids = json.loads(raw_helper_agent_ids) if isinstance(raw_helper_agent_ids, str) else list(raw_helper_agent_ids or [])
                                        except Exception:
                                            helper_agent_ids = []
                                    data, status_code = self._call_ai_helper_api(
                                        str(batch.get('project_id') or ''),
                                        str(item.get('agent_key') or ''),
                                        str(item.get('service_name') or ''),
                                        'POST',
                                        f"/api/ai-agents/sessions/{quote(helper_session_id, safe='')}/messages",
                                        {'role': role, 'content': content},
                                    )
                                    ok = status_code < 300
                                    success_count += 1 if ok else 0
                                    self._upsert_ai_batch_item(
                                        batch_id,
                                        str(batch.get('project_id') or ''),
                                        str(item.get('agent_key') or ''),
                                        str(item.get('service_name') or ''),
                                        helper_session_id,
                                        helper_agent_ids,
                                        'success' if ok else 'failed',
                                        '' if ok else str(data),
                                    )
                                    item_result = {
                                        **item_key,
                                        'success': ok,
                                        'status_code': status_code,
                                        'response': data,
                                    }
                                    results.append(item_result)
                                    yield f"data: {json.dumps({'type': 'item', 'batch_id': batch_id, **item_result}, ensure_ascii=False)}\n\n"
                                except Exception as exc:
                                    self._upsert_ai_batch_item(
                                        batch_id,
                                        str(batch.get('project_id') or ''),
                                        str(item.get('agent_key') or ''),
                                        str(item.get('service_name') or ''),
                                        helper_session_id,
                                        [],
                                        'failed',
                                        str(exc),
                                    )
                                    item_result = {
                                        **item_key,
                                        'success': False,
                                        'error': str(exc),
                                    }
                                    results.append(item_result)
                                    yield f"data: {json.dumps({'type': 'item', 'batch_id': batch_id, **item_result}, ensure_ascii=False)}\n\n"

                            aggregate = {
                                'batch_id': batch_id,
                                'round_no': next_round,
                                'role': role,
                                'content': content,
                                'results': results,
                                'partial_success': 0 < success_count < len(results),
                                'success': bool(results) and success_count == len(results),
                            }
                            self._append_ai_batch_round(batch_id, next_round, role, content, aggregate)
                            batch_table = self.db_manager.get_table_name('ai_agent_session_batches')
                            new_status = 'success' if results and success_count == len(results) else ('partial_success' if success_count > 0 else 'failed')
                            self.db_manager.execute_query(
                                f"UPDATE {batch_table} SET status = %s WHERE batch_id = %s"
                                if self.db_manager.db_type == 'mysql' else
                                f"UPDATE {batch_table} SET status = ?, updated_at = ? WHERE batch_id = ?",
                                (new_status, batch_id)
                                if self.db_manager.db_type == 'mysql' else
                                (new_status, datetime.now().isoformat(), batch_id)
                            )
                            done_payload = {
                                'type': 'done',
                                **aggregate,
                                'status': new_status,
                            }
                            yield f"data: {json.dumps(done_payload, ensure_ascii=False)}\n\n"
                            yield "data: [DONE]\n\n"
                        except Exception as stream_exc:
                            err_payload = {'type': 'error', 'batch_id': batch_id, 'error_message': str(stream_exc)}
                            yield f"data: {json.dumps(err_payload, ensure_ascii=False)}\n\n"
                            yield "data: [DONE]\n\n"

                    return Response(
                        _batch_stream(),
                        mimetype='text/event-stream',
                        headers={
                            'Cache-Control': 'no-cache',
                            'Connection': 'keep-alive',
                            'X-Accel-Buffering': 'no',
                        },
                    )

                results = []
                success_count = 0
                for item in item_rows:
                    helper_session_id = str(item.get('helper_session_id') or '').strip()
                    if not helper_session_id:
                        results.append({
                            'agent_key': item.get('agent_key'),
                            'service_name': item.get('service_name'),
                            'success': False,
                            'error': item.get('last_error') or 'missing helper_session_id',
                        })
                        continue
                    try:
                        helper_agent_ids = []
                        raw_helper_agent_ids = item.get('helper_agent_ids_json')
                        if raw_helper_agent_ids:
                            try:
                                helper_agent_ids = json.loads(raw_helper_agent_ids) if isinstance(raw_helper_agent_ids, str) else list(raw_helper_agent_ids or [])
                            except Exception:
                                helper_agent_ids = []
                        data, status_code = self._call_ai_helper_api(
                            str(batch.get('project_id') or ''),
                            str(item.get('agent_key') or ''),
                            str(item.get('service_name') or ''),
                            'POST',
                            f"/api/ai-agents/sessions/{quote(helper_session_id, safe='')}/messages",
                            {'role': role, 'content': content},
                        )
                        ok = status_code < 300
                        success_count += 1 if ok else 0
                        self._upsert_ai_batch_item(
                            batch_id,
                            str(batch.get('project_id') or ''),
                            str(item.get('agent_key') or ''),
                            str(item.get('service_name') or ''),
                            helper_session_id,
                            helper_agent_ids,
                            'success' if ok else 'failed',
                            '' if ok else str(data),
                        )
                        results.append({
                            'agent_key': item.get('agent_key'),
                            'service_name': item.get('service_name'),
                            'success': ok,
                            'status_code': status_code,
                            'response': data,
                        })
                    except Exception as exc:
                        self._upsert_ai_batch_item(
                            batch_id,
                            str(batch.get('project_id') or ''),
                            str(item.get('agent_key') or ''),
                            str(item.get('service_name') or ''),
                            helper_session_id,
                            [],
                            'failed',
                            str(exc),
                        )
                        results.append({
                            'agent_key': item.get('agent_key'),
                            'service_name': item.get('service_name'),
                            'success': False,
                            'error': str(exc),
                        })

                aggregate = {
                    'batch_id': batch_id,
                    'round_no': next_round,
                    'role': role,
                    'content': content,
                    'results': results,
                    'partial_success': 0 < success_count < len(results),
                    'success': bool(results) and success_count == len(results),
                }
                self._append_ai_batch_round(batch_id, next_round, role, content, aggregate)
                batch_table = self.db_manager.get_table_name('ai_agent_session_batches')
                new_status = 'success' if results and success_count == len(results) else ('partial_success' if success_count > 0 else 'failed')
                self.db_manager.execute_query(
                    f"UPDATE {batch_table} SET status = %s WHERE batch_id = %s"
                    if self.db_manager.db_type == 'mysql' else
                    f"UPDATE {batch_table} SET status = ?, updated_at = ? WHERE batch_id = ?",
                    (new_status, batch_id)
                    if self.db_manager.db_type == 'mysql' else
                    (new_status, datetime.now().isoformat(), batch_id)
                )
                return jsonify(aggregate)
            except Exception as e:
                self.logger.error(f"处理AI helper批次消息失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/services/global/ingress', methods=['GET'])
        def list_global_service_ingress():
            """查询项目级服务Ingress视图（含统计、可批量管理）。"""
            try:
                project_id = request.args.get('project_id')
                if not project_id:
                    return jsonify({'error': 'project_id parameter is required'}), 400
                include_deleted = request.args.get('include_deleted', 'false').lower() == 'true'
                auth_header = request.headers.get('Authorization')

                all_items = self._list_project_ingress_routes(
                    project_id=project_id,
                    include_deleted=include_deleted,
                    auth_header=auth_header
                )
                items = [item for item in all_items if self._is_service_bound_ingress_route(item)]
                active_service_keys = self._get_project_active_service_keys(project_id)
                latest_rebind_by_agent = self._get_latest_ingress_rebind_by_agent(project_id)

                enhanced_items: List[Dict[str, Any]] = []
                stale_count = 0
                deleted_count = 0
                ready_count = 0
                error_count = 0

                for item in items:
                    metadata = self._extract_route_metadata(item)
                    assoc_service = str(metadata.get('service_name') or '').strip()
                    assoc_key = f"{item.get('agent_key', '')}::{assoc_service}" if assoc_service else ''
                    service_exists = bool(assoc_service) and assoc_key in active_service_keys
                    is_deleted = bool(item.get('deleted_at')) or str(item.get('status') or '').lower() == 'deleted'
                    is_stale = (not is_deleted) and (not service_exists)

                    if is_deleted:
                        deleted_count += 1
                    if str(item.get('status') or '').lower() == 'ready':
                        ready_count += 1
                    if str(item.get('status') or '').lower() == 'error':
                        error_count += 1
                    if is_stale:
                        stale_count += 1

                    enhanced_items.append({
                        **item,
                        'associated_service_name': assoc_service,
                        'service_exists': service_exists,
                        'is_stale_service_ingress': is_stale,
                        'last_rebind_summary': latest_rebind_by_agent.get(str(item.get('agent_key') or '').strip()),
                    })

                return jsonify({
                    'project_id': project_id,
                    'items': enhanced_items,
                    'recent_rebind_events': self._get_recent_ingress_rebind_events(project_id, limit=20),
                    'stats': {
                        'total': len(enhanced_items),
                        'ready': ready_count,
                        'error': error_count,
                        'deleted': deleted_count,
                        'stale_service_ingress': stale_count,
                    }
                })
            except Exception as e:
                self.logger.error(f"查询服务Ingress视图失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/services/global/ingress/delete-batch', methods=['POST'])
        def delete_global_service_ingress_batch():
            """批量删除项目Ingress路由。"""
            try:
                data = request.get_json(silent=True) or {}
                project_id = str(data.get('project_id') or '').strip()
                route_ids = data.get('route_ids') or []
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400
                if not isinstance(route_ids, list) or len(route_ids) == 0:
                    return jsonify({'error': 'route_ids must be a non-empty array'}), 400

                auth_header = request.headers.get('Authorization')
                deleted = 0
                failed: List[Dict[str, Any]] = []
                for rid in route_ids:
                    route_id = str(rid or '').strip()
                    if not route_id:
                        continue
                    try:
                        resp = self._call_k8s_service(
                            method='DELETE',
                            path=f'/api/k8s/agent-ingress-routes/{route_id}',
                            project_id=project_id,
                            headers={'Authorization': auth_header} if auth_header else None
                        )
                        if resp.status_code < 300:
                            deleted += 1
                        else:
                            failed.append({'route_id': route_id, 'status_code': resp.status_code, 'body': resp.text[:200]})
                    except Exception as inner:
                        failed.append({'route_id': route_id, 'error': str(inner)})

                return jsonify({
                    'project_id': project_id,
                    'requested': len(route_ids),
                    'deleted': deleted,
                    'failed': failed,
                }), 200 if len(failed) == 0 else 207
            except Exception as e:
                self.logger.error(f"批量删除服务Ingress失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/services/global/ingress/cleanup-stale', methods=['POST'])
        def cleanup_stale_service_ingress():
            """一键删除所有不在位服务关联的Ingress。"""
            try:
                data = request.get_json(silent=True) or {}
                project_id = str(data.get('project_id') or '').strip()
                dry_run = bool(data.get('dry_run', False))
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400

                auth_header = request.headers.get('Authorization')
                all_routes = self._list_project_ingress_routes(project_id=project_id, include_deleted=False, auth_header=auth_header)
                routes = [item for item in all_routes if self._is_service_bound_ingress_route(item)]
                active_service_keys = self._get_project_active_service_keys(project_id)

                stale_routes: List[Dict[str, Any]] = []
                for item in routes:
                    route_status = str(item.get('status') or '').strip().lower()
                    if route_status == 'error':
                        stale_routes.append(item)
                        continue
                    metadata = self._extract_route_metadata(item)
                    assoc_service = str(metadata.get('service_name') or '').strip()
                    if not assoc_service:
                        stale_routes.append(item)
                        continue
                    assoc_key = f"{item.get('agent_key', '')}::{assoc_service}"
                    if assoc_key not in active_service_keys:
                        stale_routes.append(item)

                if dry_run:
                    return jsonify({
                        'project_id': project_id,
                        'dry_run': True,
                        'to_delete_count': len(stale_routes),
                        'items': stale_routes,
                    })

                deleted = 0
                failed: List[Dict[str, Any]] = []
                for route in stale_routes:
                    route_id = str(route.get('route_id') or '').strip()
                    if not route_id:
                        continue
                    try:
                        resp = self._call_k8s_service(
                            method='DELETE',
                            path=f'/api/k8s/agent-ingress-routes/{route_id}',
                            project_id=project_id,
                            headers={'Authorization': auth_header} if auth_header else None
                        )
                        if resp.status_code < 300:
                            deleted += 1
                        else:
                            failed.append({'route_id': route_id, 'status_code': resp.status_code, 'body': resp.text[:200]})
                    except Exception as inner:
                        failed.append({'route_id': route_id, 'error': str(inner)})

                return jsonify({
                    'project_id': project_id,
                    'dry_run': False,
                    'target_count': len(stale_routes),
                    'deleted': deleted,
                    'failed': failed,
                }), 200 if len(failed) == 0 else 207
            except Exception as e:
                self.logger.error(f"清理无效服务Ingress失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/services/global/ingress/clear-all', methods=['POST'])
        def clear_all_service_ingress():
            """清空项目所有Ingress路由（可选包含已删除记录）。"""
            try:
                data = request.get_json(silent=True) or {}
                project_id = str(data.get('project_id') or '').strip()
                include_deleted = bool(data.get('include_deleted', False))
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400

                auth_header = request.headers.get('Authorization')
                all_routes = self._list_project_ingress_routes(project_id=project_id, include_deleted=include_deleted, auth_header=auth_header)
                routes = [item for item in all_routes if self._is_service_bound_ingress_route(item)]
                deleted = 0
                failed: List[Dict[str, Any]] = []
                for route in routes:
                    route_id = str(route.get('route_id') or '').strip()
                    if not route_id:
                        continue
                    try:
                        resp = self._call_k8s_service(
                            method='DELETE',
                            path=f'/api/k8s/agent-ingress-routes/{route_id}',
                            project_id=project_id,
                            headers={'Authorization': auth_header} if auth_header else None
                        )
                        if resp.status_code < 300:
                            deleted += 1
                        else:
                            failed.append({'route_id': route_id, 'status_code': resp.status_code, 'body': resp.text[:200]})
                    except Exception as inner:
                        failed.append({'route_id': route_id, 'error': str(inner)})

                return jsonify({
                    'project_id': project_id,
                    'requested': len(routes),
                    'deleted': deleted,
                    'failed': failed
                }), 200 if len(failed) == 0 else 207
            except Exception as e:
                self.logger.error(f"清空服务Ingress失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/agents/global/ingress', methods=['GET'])
        def list_global_agent_ingress():
            """查询项目级 Agent 节点入口 Ingress（仅11197/11198）。"""
            try:
                project_id = request.args.get('project_id')
                if not project_id:
                    return jsonify({'error': 'project_id parameter is required'}), 400
                page = max(int(request.args.get('page', 1) or 1), 1)
                per_page = int(request.args.get('per_page', 10) or 10)
                per_page = max(1, min(per_page, 1000))
                include_deleted = request.args.get('include_deleted', 'false').lower() == 'true'
                auth_header = request.headers.get('Authorization')

                all_items = self._list_project_ingress_routes(
                    project_id=project_id,
                    include_deleted=include_deleted,
                    auth_header=auth_header
                )
                items = [item for item in all_items if self._is_agent_console_ingress_route(item)]
                latest_rebind_by_agent = self._get_latest_ingress_rebind_by_agent(project_id)

                agents, _ = self.agent_manager.list_agents(page=1, per_page=5000, project_id=project_id)
                online_keys = {str(a.get('key') or '').strip() for a in agents if str(a.get('status') or '').lower() == 'online'}

                enhanced_items: List[Dict[str, Any]] = []
                stale_count = 0
                deleted_count = 0
                ready_count = 0
                error_count = 0
                port_11197_count = 0
                port_11198_count = 0

                for item in items:
                    target_port = int(item.get('target_port') or 0)
                    agent_key = str(item.get('agent_key') or '').strip()
                    is_deleted = bool(item.get('deleted_at')) or str(item.get('status') or '').lower() == 'deleted'
                    is_online = agent_key in online_keys if agent_key else False
                    is_stale = (not is_deleted) and (not is_online)

                    if target_port == 11197:
                        port_11197_count += 1
                    elif target_port == 11198:
                        port_11198_count += 1
                    if is_deleted:
                        deleted_count += 1
                    if str(item.get('status') or '').lower() == 'ready':
                        ready_count += 1
                    if str(item.get('status') or '').lower() == 'error':
                        error_count += 1
                    if is_stale:
                        stale_count += 1

                    enhanced_items.append({
                        **item,
                        'agent_online': is_online,
                        'is_stale_agent_ingress': is_stale,
                        'last_rebind_summary': latest_rebind_by_agent.get(agent_key),
                    })

                total = len(enhanced_items)
                start = (page - 1) * per_page
                end = start + per_page
                paged_items = enhanced_items[start:end]

                return jsonify({
                    'project_id': project_id,
                    'items': paged_items,
                    'page': page,
                    'per_page': per_page,
                    'total': total,
                    'recent_rebind_events': self._get_recent_ingress_rebind_events(project_id, limit=20),
                    'stats': {
                        'total': total,
                        'ready': ready_count,
                        'error': error_count,
                        'deleted': deleted_count,
                        'stale_agent_ingress': stale_count,
                        'port_11197': port_11197_count,
                        'port_11198': port_11198_count,
                    }
                })
            except Exception as e:
                self.logger.error(f"查询Agent节点Ingress视图失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/agents/global/ingress/delete-batch', methods=['POST'])
        def delete_global_agent_ingress_batch():
            """批量删除 Agent 节点入口 Ingress。"""
            try:
                data = request.get_json(silent=True) or {}
                project_id = str(data.get('project_id') or '').strip()
                route_ids = data.get('route_ids') or []
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400
                if not isinstance(route_ids, list) or len(route_ids) == 0:
                    return jsonify({'error': 'route_ids must be a non-empty array'}), 400

                auth_header = request.headers.get('Authorization')
                deleted = 0
                failed: List[Dict[str, Any]] = []
                for rid in route_ids:
                    route_id = str(rid or '').strip()
                    if not route_id:
                        continue
                    try:
                        resp = self._call_k8s_service(
                            method='DELETE',
                            path=f'/api/k8s/agent-ingress-routes/{route_id}',
                            project_id=project_id,
                            headers={'Authorization': auth_header} if auth_header else None
                        )
                        if resp.status_code < 300:
                            deleted += 1
                        else:
                            failed.append({'route_id': route_id, 'status_code': resp.status_code, 'body': resp.text[:200]})
                    except Exception as inner:
                        failed.append({'route_id': route_id, 'error': str(inner)})

                return jsonify({
                    'project_id': project_id,
                    'requested': len(route_ids),
                    'deleted': deleted,
                    'failed': failed
                }), 200 if len(failed) == 0 else 207
            except Exception as e:
                self.logger.error(f"批量删除Agent节点Ingress失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/agents/global/ingress/cleanup-stale', methods=['POST'])
        def cleanup_stale_agent_ingress():
            """一键删除所有离线节点关联的Agent入口Ingress。"""
            try:
                data = request.get_json(silent=True) or {}
                project_id = str(data.get('project_id') or '').strip()
                dry_run = bool(data.get('dry_run', False))
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400

                auth_header = request.headers.get('Authorization')
                all_routes = self._list_project_ingress_routes(project_id=project_id, include_deleted=False, auth_header=auth_header)
                routes = [item for item in all_routes if self._is_agent_console_ingress_route(item)]
                agents, _ = self.agent_manager.list_agents(page=1, per_page=5000, project_id=project_id)
                online_keys = {str(a.get('key') or '').strip() for a in agents if str(a.get('status') or '').lower() == 'online'}

                stale_routes: List[Dict[str, Any]] = []
                for item in routes:
                    agent_key = str(item.get('agent_key') or '').strip()
                    if not agent_key or agent_key not in online_keys:
                        stale_routes.append(item)

                if dry_run:
                    return jsonify({
                        'project_id': project_id,
                        'dry_run': True,
                        'to_delete_count': len(stale_routes),
                        'items': stale_routes,
                    })

                deleted = 0
                failed: List[Dict[str, Any]] = []
                for route in stale_routes:
                    route_id = str(route.get('route_id') or '').strip()
                    if not route_id:
                        continue
                    try:
                        resp = self._call_k8s_service(
                            method='DELETE',
                            path=f'/api/k8s/agent-ingress-routes/{route_id}',
                            project_id=project_id,
                            headers={'Authorization': auth_header} if auth_header else None
                        )
                        if resp.status_code < 300:
                            deleted += 1
                        else:
                            failed.append({'route_id': route_id, 'status_code': resp.status_code, 'body': resp.text[:200]})
                    except Exception as inner:
                        failed.append({'route_id': route_id, 'error': str(inner)})

                return jsonify({
                    'project_id': project_id,
                    'dry_run': False,
                    'target_count': len(stale_routes),
                    'deleted': deleted,
                    'failed': failed,
                }), 200 if len(failed) == 0 else 207
            except Exception as e:
                self.logger.error(f"清理无效Agent入口Ingress失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/agents/global/ingress/clear-all', methods=['POST'])
        def clear_all_agent_ingress():
            """清空项目所有Agent入口Ingress（仅11197/11198）。"""
            try:
                data = request.get_json(silent=True) or {}
                project_id = str(data.get('project_id') or '').strip()
                include_deleted = bool(data.get('include_deleted', False))
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400

                auth_header = request.headers.get('Authorization')
                all_routes = self._list_project_ingress_routes(project_id=project_id, include_deleted=include_deleted, auth_header=auth_header)
                routes = [item for item in all_routes if self._is_agent_console_ingress_route(item)]
                deleted = 0
                failed: List[Dict[str, Any]] = []
                for route in routes:
                    route_id = str(route.get('route_id') or '').strip()
                    if not route_id:
                        continue
                    try:
                        resp = self._call_k8s_service(
                            method='DELETE',
                            path=f'/api/k8s/agent-ingress-routes/{route_id}',
                            project_id=project_id,
                            headers={'Authorization': auth_header} if auth_header else None
                        )
                        if resp.status_code < 300:
                            deleted += 1
                        else:
                            failed.append({'route_id': route_id, 'status_code': resp.status_code, 'body': resp.text[:200]})
                    except Exception as inner:
                        failed.append({'route_id': route_id, 'error': str(inner)})

                return jsonify({
                    'project_id': project_id,
                    'requested': len(routes),
                    'deleted': deleted,
                    'failed': failed
                }), 200 if len(failed) == 0 else 207
            except Exception as e:
                self.logger.error(f"清空Agent入口Ingress失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/services/global/sync', methods=['POST'])
        def sync_global_services_now():
            """手动触发聚合同步（支持全量/项目/单Agent强制同步）。"""
            try:
                data = request.get_json(silent=True) or {}
                project_id = data.get('project_id')
                agent_key = data.get('agent_key')
                stale_only = bool(data.get('stale_only', False))

                # 1) 单Agent强制同步
                if agent_key:
                    agent = self.agent_manager.get_agent(agent_key) or self.agent_manager.ensure_agent_exists(agent_key)
                    if not agent:
                        return jsonify({'error': f'Agent {agent_key} not found'}), 404
                    result = self._sync_single_agent_services(agent)
                    self._record_service_sync_log(
                        scope='agent',
                        status='ok' if result.get('ok') else 'failed',
                        agent_key=agent_key,
                        stale_only=False,
                        total=1,
                        ok_count=1 if result.get('ok') else 0,
                        fail_count=0 if result.get('ok') else 1,
                        message='agent service sync completed',
                        details=[result]
                    )
                    return jsonify({
                        'message': 'agent service sync triggered',
                        'status': 'ok' if result.get('ok') else 'failed',
                        'result': result
                    }), 200 if result.get('ok') else 502

                # 2) 项目范围强制同步
                if project_id:
                    agents, _ = self.agent_manager.list_agents(page=1, per_page=5000, project_id=project_id)
                    stale_keys = self._get_stale_agent_keys(project_id) if stale_only else set()
                    results = []
                    candidate_total = 0
                    for item in agents:
                        item_status = str(item.get('status') or '').strip().lower()
                        item_key = str(item.get('key') or '').strip()
                        if item_status != 'online':
                            continue
                        if stale_only and item_key not in stale_keys:
                            continue
                        candidate_total += 1
                        agent = self.agent_manager.get_agent(item_key)
                        if not agent:
                            continue
                        results.append(self._sync_single_agent_services(agent))
                    ok_count = len([r for r in results if r.get('ok')])
                    fail_count = len(results) - ok_count
                    status_label = 'ok' if fail_count == 0 else 'partial'
                    message = 'project service sync completed'
                    if candidate_total == 0:
                        status_label = 'empty'
                        message = 'no online agents matched current sync scope'
                    self._record_service_sync_log(
                        scope='project',
                        status=status_label,
                        project_id=project_id,
                        stale_only=stale_only,
                        total=len(results),
                        ok_count=ok_count,
                        fail_count=fail_count,
                        message=message,
                        details=results
                    )
                    return jsonify({
                        'message': message,
                        'status': status_label,
                        'project_id': project_id,
                        'stale_only': stale_only,
                        'candidate_total': candidate_total,
                        'total': len(results),
                        'ok_count': ok_count,
                        'fail_count': fail_count,
                        'results': results
                    })

                # 3) 全量同步（默认）
                if stale_only:
                    agents = []
                    page = 1
                    per_page = 1000
                    while True:
                        batch, total = self.agent_manager.list_agents(page=page, per_page=per_page)
                        if not batch:
                            break
                        agents.extend(batch)
                        if len(agents) >= total:
                            break
                        page += 1

                    stale_keys = self._get_stale_agent_keys()
                    results = []
                    candidate_total = 0
                    for item in agents:
                        item_status = str(item.get('status') or '').strip().lower()
                        item_key = str(item.get('key') or '').strip()
                        if item_status != 'online':
                            continue
                        if item_key not in stale_keys:
                            continue
                        candidate_total += 1
                        agent = self.agent_manager.get_agent(item_key)
                        if not agent:
                            continue
                        results.append(self._sync_single_agent_services(agent))
                    ok_count = len([r for r in results if r.get('ok')])
                    fail_count = len(results) - ok_count
                    status_label = 'ok' if fail_count == 0 else 'partial'
                    message = 'global stale-agent service sync completed'
                    if candidate_total == 0:
                        status_label = 'empty'
                        message = 'no online stale agents found'
                    self._record_service_sync_log(
                        scope='global',
                        status=status_label,
                        stale_only=True,
                        total=len(results),
                        ok_count=ok_count,
                        fail_count=fail_count,
                        message=message,
                        details=results
                    )
                    return jsonify({
                        'message': message,
                        'status': status_label,
                        'stale_only': True,
                        'candidate_total': candidate_total,
                        'total': len(results),
                        'ok_count': ok_count,
                        'fail_count': fail_count,
                        'results': results
                    })
                else:
                    summary = self._sync_all_agent_services()
                    details = summary.get('results') or []
                    total = int(summary.get('online_agents') or 0)
                    ok_count = int(summary.get('ok_count') or 0)
                    fail_count = int(summary.get('fail_count') or 0)
                    self._record_service_sync_log(
                        scope='global',
                        status='ok' if fail_count == 0 else 'partial',
                        stale_only=False,
                        total=total,
                        ok_count=ok_count,
                        fail_count=fail_count,
                        message='global service sync completed',
                        details=details
                    )
                    return jsonify({
                        'message': 'global service sync completed',
                        'status': 'ok' if fail_count == 0 else 'partial',
                        'total': total,
                        'ok_count': ok_count,
                        'fail_count': fail_count,
                        'results': details
                    })
            except Exception as e:
                self.logger.error(f"手动触发服务聚合同步失败: {e}", exc_info=True)
                try:
                    self._record_service_sync_log(
                        scope='global',
                        status='failed',
                        message=f'service sync failed: {e}'
                    )
                except Exception:
                    pass
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/services/global/sync/history', methods=['GET', 'DELETE'])
        def get_global_service_sync_history():
            """查询服务强制同步历史记录。"""
            try:
                table_name = self.db_manager.get_table_name('service_sync_logs')

                if request.method == 'DELETE':
                    project_id = request.args.get('project_id')
                    where = []
                    params: List[Any] = []
                    if project_id:
                        where.append("project_id = " + ("%s" if self.db_manager.db_type == 'mysql' else "?"))
                        params.append(project_id)
                    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

                    count_sql = f"SELECT COUNT(*) as count FROM {table_name} {where_sql}"
                    count_result = self.db_manager.fetch_one(count_sql, tuple(params))
                    target_count = int(count_result.get('count', 0) if count_result else 0)

                    delete_sql = f"DELETE FROM {table_name} {where_sql}"
                    self.db_manager.execute_query(delete_sql, tuple(params))
                    return jsonify({
                        'message': 'sync history cleared',
                        'project_id': project_id,
                        'deleted_count': target_count
                    })

                page = max(int(request.args.get('page', 1)), 1)
                per_page = min(max(int(request.args.get('per_page', 20)), 1), 200)
                project_id = request.args.get('project_id')

                where = []
                params: List[Any] = []
                if project_id:
                    where.append("project_id = " + ("%s" if self.db_manager.db_type == 'mysql' else "?"))
                    params.append(project_id)
                where_sql = ("WHERE " + " AND ".join(where)) if where else ""

                count_sql = f"SELECT COUNT(*) as count FROM {table_name} {where_sql}"
                count_result = self.db_manager.fetch_one(count_sql, tuple(params))
                total = int(count_result.get('count', 0) if count_result else 0)

                query = f'''
                    SELECT sync_id, scope, project_id, agent_key, stale_only, status, total, ok_count, fail_count,
                           message, details_json, pod_id, created_at
                    FROM {table_name}
                    {where_sql}
                    ORDER BY created_at DESC
                '''
                offset = (page - 1) * per_page
                if self.db_manager.db_type == 'mysql':
                    query += " LIMIT %s OFFSET %s"
                else:
                    query += " LIMIT ? OFFSET ?"
                rows = self.db_manager.fetch_all(query, tuple(params + [per_page, offset]))

                items = []
                for row in rows:
                    details_raw = row.get('details_json')
                    details = []
                    if details_raw:
                        if isinstance(details_raw, str):
                            try:
                                details = json.loads(details_raw)
                            except Exception:
                                details = []
                        elif isinstance(details_raw, list):
                            details = details_raw

                    items.append({
                        'sync_id': row.get('sync_id'),
                        'scope': row.get('scope'),
                        'project_id': row.get('project_id'),
                        'agent_key': row.get('agent_key'),
                        'stale_only': bool(row.get('stale_only')),
                        'status': row.get('status'),
                        'total': int(row.get('total') or 0),
                        'ok_count': int(row.get('ok_count') or 0),
                        'fail_count': int(row.get('fail_count') or 0),
                        'message': row.get('message') or '',
                        'details': details,
                        'details_count': len(details) if isinstance(details, list) else 0,
                        'pod_id': row.get('pod_id'),
                        'created_at': row.get('created_at'),
                    })

                return jsonify({
                    'items': items,
                    'page': page,
                    'per_page': per_page,
                    'total': total
                })
            except Exception as e:
                self.logger.error(f"查询服务同步历史失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/services/global/sync/history/<sync_id>', methods=['DELETE'])
        def delete_global_service_sync_history_item(sync_id):
            """删除单条服务强制同步历史记录。"""
            try:
                sync_id = str(sync_id or '').strip()
                if not sync_id:
                    return jsonify({'error': 'sync_id is required'}), 400

                table_name = self.db_manager.get_table_name('service_sync_logs')
                placeholder = "%s" if self.db_manager.db_type == 'mysql' else "?"
                count_row = self.db_manager.fetch_one(
                    f"SELECT COUNT(*) as count FROM {table_name} WHERE sync_id = {placeholder}",
                    (sync_id,)
                )
                exists = int(count_row.get('count', 0) if count_row else 0) > 0
                if not exists:
                    return jsonify({'error': 'sync history not found'}), 404

                self.db_manager.execute_query(
                    f"DELETE FROM {table_name} WHERE sync_id = {placeholder}",
                    (sync_id,)
                )
                return jsonify({'message': 'sync history deleted', 'sync_id': sync_id})
            except Exception as e:
                self.logger.error(f"删除服务同步历史失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/report/services/full', methods=['POST'])
        def report_agent_services_full():
            """Agent全量上报服务状态。"""
            try:
                if not self._is_agent_report_authenticated():
                    return jsonify({'error': 'unauthorized'}), 401

                data = request.get_json() or {}
                agent_key = data.get('agent_key')
                services = data.get('services') or []

                if not agent_key:
                    return jsonify({'error': 'agent_key is required'}), 400
                if not isinstance(services, list):
                    return jsonify({'error': 'services must be an array'}), 400

                existing_agent = self.agent_manager.get_agent(agent_key)
                old_ip = str(getattr(existing_agent, 'ip_address', '') or '').strip()
                agent = self._upsert_agent_from_report(agent_key, data) or self._resolve_or_auto_create_agent_for_report(agent_key)
                if not agent:
                    return jsonify({'error': f'Agent {agent_key} not found'}), 404
                new_ip = str(getattr(agent, 'ip_address', '') or '').strip()

                rebind_summary = None
                if old_ip and new_ip and old_ip != new_ip:
                    try:
                        rebind_summary = self._rebind_agent_ingress_external_ip(
                            project_id=str(getattr(agent, 'project_id', '') or '').strip(),
                            agent_key=agent_key,
                            new_ip=new_ip,
                            auth_header=request.headers.get('Authorization')
                        )
                        self.logger.info(
                            f"ingress_rebind_on_ip_change agent={agent_key} project={getattr(agent, 'project_id', '')} "
                            f"old_ip={old_ip} new_ip={new_ip} target={rebind_summary.get('target_count')} "
                            f"success={rebind_summary.get('success_count')} fail={rebind_summary.get('fail_count')}"
                        )
                    except Exception as rebind_err:
                        self.logger.error(
                            f"ingress_rebind_on_ip_change_failed agent={agent_key} old_ip={old_ip} new_ip={new_ip}: {rebind_err}",
                            exc_info=True
                        )

                seen, upserted = self._upsert_agent_services_snapshot(agent, services, source='report_full')
                if seen == 0:
                    self.logger.warning(
                        f"收到空服务全量上报: agent={agent_key}, project={getattr(agent, 'project_id', '')}, "
                        f"source_ip={request.remote_addr}, services_len={len(services) if isinstance(services, list) else -1}"
                    )
                return jsonify({
                    'message': 'service snapshot accepted',
                    'agent_key': agent_key,
                    'seen': seen,
                    'upserted': upserted,
                    'ip_changed': bool(old_ip and new_ip and old_ip != new_ip),
                    'old_ip': old_ip,
                    'new_ip': new_ip,
                    'ingress_rebind': rebind_summary,
                }), 202
            except Exception as e:
                self.logger.error(f"处理Agent全量上报失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/report/services/delta', methods=['POST'])
        def report_agent_services_delta():
            """Agent增量上报（当前按upsert处理，未上报项不标记stale）。"""
            try:
                if not self._is_agent_report_authenticated():
                    return jsonify({'error': 'unauthorized'}), 401

                data = request.get_json() or {}
                agent_key = data.get('agent_key')
                services = data.get('services') or []

                if not agent_key:
                    return jsonify({'error': 'agent_key is required'}), 400
                if not isinstance(services, list):
                    return jsonify({'error': 'services must be an array'}), 400

                existing_agent = self.agent_manager.get_agent(agent_key)
                old_ip = str(getattr(existing_agent, 'ip_address', '') or '').strip()
                agent = self._upsert_agent_from_report(agent_key, data) or self._resolve_or_auto_create_agent_for_report(agent_key)
                if not agent:
                    return jsonify({'error': f'Agent {agent_key} not found'}), 404
                new_ip = str(getattr(agent, 'ip_address', '') or '').strip()

                rebind_summary = None
                if old_ip and new_ip and old_ip != new_ip:
                    try:
                        rebind_summary = self._rebind_agent_ingress_external_ip(
                            project_id=str(getattr(agent, 'project_id', '') or '').strip(),
                            agent_key=agent_key,
                            new_ip=new_ip,
                            auth_header=request.headers.get('Authorization')
                        )
                        self.logger.info(
                            f"ingress_rebind_on_ip_change agent={agent_key} project={getattr(agent, 'project_id', '')} "
                            f"old_ip={old_ip} new_ip={new_ip} target={rebind_summary.get('target_count')} "
                            f"success={rebind_summary.get('success_count')} fail={rebind_summary.get('fail_count')}"
                        )
                    except Exception as rebind_err:
                        self.logger.error(
                            f"ingress_rebind_on_ip_change_failed agent={agent_key} old_ip={old_ip} new_ip={new_ip}: {rebind_err}",
                            exc_info=True
                        )

                upserted = 0
                for service in services:
                    payload = self._normalize_agent_service_payload(agent, service, source='report_delta')
                    if not payload:
                        continue
                    # 增量上报只更新出现的条目
                    self._upsert_single_agent_service(payload)
                    upserted += 1

                return jsonify({
                    'message': 'service delta accepted',
                    'agent_key': agent_key,
                    'upserted': upserted,
                    'ip_changed': bool(old_ip and new_ip and old_ip != new_ip),
                    'old_ip': old_ip,
                    'new_ip': new_ip,
                    'ingress_rebind': rebind_summary,
                }), 202
            except Exception as e:
                self.logger.error(f"处理Agent增量上报失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        # 代理调试端点
        @self.app.route('/api/agent/proxy/debug/<agent_key>', methods=['GET'])
        def debug_agent_proxy(agent_key):
            """调试Agent代理连接"""
            try:
                agent = self.agent_manager.get_agent(agent_key)
                if not agent:
                    return jsonify({'error': f'Agent {agent_key} not found'}), 404

                # 测试多个端点
                endpoints_to_test = [
                    '/api/health',
                    '/api/system/info',
                    '/api/system/metrics',
                    '/api/services'
                ]

                results = []

                for endpoint in endpoints_to_test:
                    try:
                        url = f"http://{agent.ip_address}:{self.agent_manager.agent_api_port}{endpoint}"
                        response = requests.get(
                            url,
                            headers={'X-Auth-Token': self.agent_manager.agent_auth_token},
                            timeout=5,
                            verify=False
                        )

                        results.append({
                            'endpoint': endpoint,
                            'status_code': response.status_code,
                            'response_time': f"{response.elapsed.total_seconds() * 1000:.2f}ms",
                            'success': response.status_code == 200
                        })
                    except Exception as e:
                        results.append({
                            'endpoint': endpoint,
                            'status_code': 0,
                            'error': str(e),
                            'success': False
                        })

                # 总结
                success_count = sum(1 for r in results if r['success'])

                return jsonify({
                    'agent': {
                        'key': agent_key,
                        'hostname': agent.hostname,
                        'ip_address': agent.ip_address,
                        'status': agent.status,
                        'last_seen': agent.last_seen.isoformat() if agent.last_seen else None
                    },
                    'test_results': results,
                    'summary': {
                        'total_tests': len(results),
                        'successful_tests': success_count,
                        'success_rate': f"{(success_count / len(results)) * 100:.1f}%",
                        'agent_available': success_count > 0
                    }
                })

            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/agent/<agent_key>/health', methods=['GET'])
        def agent_health(agent_key):
            """获取Agent的健康状态（快捷方式）"""
            status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                agent_key=agent_key,
                method='GET',
                endpoint='/api/health'
            )

            response = jsonify(response_data)
            for key, value in response_headers.items():
                if key.lower() == 'Content-Length'.lower():
                    continue
                response.headers[key] = value
            response.status_code = status_code

            return response

        @self.app.route('/api/agent/agent/<agent_key>/daemon-agent-info', methods=['GET'])
        def daemon_agent_info(agent_key):
            """获取Agent守护进程综合信息（11188）"""
            status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                agent_key=agent_key,
                method='GET',
                endpoint='/api/v1/agent/info',
                port=self.agent_manager.daemon_api_port,
                timeout=self.daemon_read_timeout_sec
            )

            response = jsonify(response_data)
            for key, value in response_headers.items():
                if key.lower() == 'Content-Length'.lower():
                    continue
                response.headers[key] = value
            response.status_code = status_code
            return response

        @self.app.route('/api/agent/agent/<agent_key>/daemon-agent-health', methods=['GET'])
        def daemon_agent_health(agent_key):
            """获取Agent守护进程健康状态（11188）"""
            status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                agent_key=agent_key,
                method='GET',
                endpoint='/api/v1/agent/health',
                port=self.agent_manager.daemon_api_port,
                timeout=self.daemon_read_timeout_sec
            )

            response = jsonify(response_data)
            for key, value in response_headers.items():
                if key.lower() == 'Content-Length'.lower():
                    continue
                response.headers[key] = value
            response.status_code = status_code
            return response

        @self.app.route('/api/agent/agent/<agent_key>/ttyd/connection', methods=['GET'])
        def agent_ttyd_connection(agent_key):
            """获取 Agent TTYD 连接信息（用于前端终端转发，支持 WebSocket）"""
            try:
                agent = self.agent_manager.get_agent(agent_key)
                if not agent:
                    return jsonify({'error': f'Agent {agent_key} not found'}), 404

                if agent.status != 'online':
                    return jsonify({'error': f'Agent {agent_key} is {agent.status}'}), 503

                scheme = request.scheme or 'http'
                ws_scheme = 'wss' if scheme == 'https' else 'ws'
                ttyd_base = f"{scheme}://{agent.ip_address}:{self.agent_ttyd_port}"

                reachable = False
                probe_error = None
                try:
                    probe = requests.get(
                        ttyd_base,
                        timeout=(min(3, self.ttyd_probe_timeout_sec), self.ttyd_probe_timeout_sec),
                        verify=False
                    )
                    reachable = probe.status_code < 500
                except Exception as e:
                    probe_error = str(e)

                return jsonify({
                    'agent_key': agent_key,
                    'agent_ip': agent.ip_address,
                    'agent_status': agent.status,
                    'ttyd_port': self.agent_ttyd_port,
                    'reachable': reachable,
                    'probe_error': probe_error,
                    'http_url': ttyd_base,
                    'ws_url': f"{ws_scheme}://{agent.ip_address}:{self.agent_ttyd_port}/ws",
                    'open_path': f"/api/agent/agent/{agent_key}/ttyd/open"
                })
            except Exception as e:
                self.logger.error(f"获取TTYD连接信息失败: {str(e)}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/agent/<agent_key>/ttyd/open', methods=['GET'])
        def open_agent_ttyd(agent_key):
            """跳转到 Agent TTYD 页面（浏览器将直接与目标节点建立 WS 连接）"""
            agent = self.agent_manager.get_agent(agent_key)
            if not agent:
                return jsonify({'error': f'Agent {agent_key} not found'}), 404
            if agent.status != 'online':
                return jsonify({'error': f'Agent {agent_key} is {agent.status}'}), 503

            target = f"http://{agent.ip_address}:{self.agent_ttyd_port}"
            return redirect(target, code=302)

        @self.app.route('/api/agent/agent/<agent_key>/ingress-routes', methods=['GET'])
        def list_agent_ingress_routes(agent_key):
            """列出 Agent 节点入口 Ingress 路由（仅 agent_console）。"""
            try:
                project_id = request.args.get('project_id')
                if not project_id:
                    return jsonify({'error': 'project_id parameter is required'}), 400

                agent = self.agent_manager.get_agent(agent_key)
                if not agent:
                    return jsonify({'error': f'Agent {agent_key} not found'}), 404
                if agent.project_id != project_id:
                    return jsonify({'error': f'Agent {agent_key} does not belong to project {project_id}'}), 403

                auth_header = request.headers.get('Authorization')
                resp = self._call_k8s_service(
                    method='GET',
                    path='/api/k8s/agent-ingress-routes',
                    project_id=project_id,
                    params={'agent_key': agent_key},
                    headers={'Authorization': auth_header} if auth_header else None
                )
                payload = resp.json() if resp.content else {}
                if resp.status_code >= 300:
                    return jsonify(payload), resp.status_code

                items = payload.get('items') or []
                filtered_items = [item for item in items if self._is_agent_console_ingress_route(item)]
                return jsonify({
                    **payload,
                    'items': filtered_items,
                    'total': len(filtered_items),
                }), resp.status_code
            except requests.RequestException as e:
                self.logger.error(f"查询动态Ingress路由失败: {e}")
                return jsonify({'error': f'k8s service unavailable: {e}'}), 502
            except Exception as e:
                self.logger.error(f"查询动态Ingress路由失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/agent/<agent_key>/ingress-routes', methods=['POST'])
        def create_agent_ingress_route(agent_key):
            """创建/更新Agent动态Ingress路由"""
            try:
                data = request.get_json() or {}
                project_id = data.get('project_id')
                if not project_id:
                    return jsonify({'error': 'project_id is required'}), 400

                agent = self.agent_manager.get_agent(agent_key)
                if not agent:
                    return jsonify({'error': f'Agent {agent_key} not found'}), 404
                if agent.project_id != project_id:
                    return jsonify({'error': f'Agent {agent_key} does not belong to project {project_id}'}), 403

                target_port = int(data.get('target_port', self.agent_ttyd_port))
                external_ips = data.get('external_ips') or [agent.ip_address]
                metadata = {
                    **(data.get('metadata') or {}),
                    'agent_hostname': agent.hostname,
                    'source_api': '/api/agent/agent/<agent_key>/ingress-routes'
                }
                ingress_scope = str(metadata.get('ingress_scope') or '').strip().lower()
                if not ingress_scope:
                    if target_port in (11197, 11198):
                        ingress_scope = 'agent_console'
                    elif str(metadata.get('service_name') or '').strip():
                        ingress_scope = 'service_binding'
                    else:
                        ingress_scope = 'agent_console'
                metadata['ingress_scope'] = ingress_scope
                payload = {
                    'agent_key': agent_key,
                    'external_ips': external_ips,
                    'target_port': target_port,
                    'host': data.get('host'),
                    'host_prefix': data.get('host_prefix') or _build_random_host_prefix(f"{agent_key}-{target_port}"),
                    'path': data.get('path', '/'),
                    'path_type': data.get('path_type', 'Prefix'),
                    'ingress_type': data.get('ingress_type'),
                    # Agent动态转发默认应回源到目标端口，避免未传时落到80端口
                    'service_port': int(data.get('service_port') or target_port),
                    'tls_enabled': data.get('tls_enabled'),
                    'tls_secret_name': data.get('tls_secret_name'),
                    'backend_protocol': data.get('backend_protocol') or metadata.get('backend_protocol'),
                    'websocket_enabled': data.get('websocket_enabled', True),
                    'proxy_body_size': data.get('proxy_body_size'),
                    'proxy_connect_timeout': data.get('proxy_connect_timeout'),
                    'proxy_send_timeout': data.get('proxy_send_timeout'),
                    'proxy_read_timeout': data.get('proxy_read_timeout'),
                    'ssl_redirect': data.get('ssl_redirect'),
                    'owner_service': 'platform-agent',
                    'created_by': data.get('created_by'),
                    'force_recreate': bool(data.get('force_recreate', False)),
                    'metadata': metadata
                }

                auth_header = request.headers.get('Authorization')
                resp = self._call_k8s_service(
                    method='POST',
                    path='/api/k8s/agent-ingress-routes',
                    project_id=project_id,
                    payload=payload,
                    headers={'Authorization': auth_header} if auth_header else None
                )
                return jsonify(resp.json()), resp.status_code
            except requests.RequestException as e:
                self.logger.error(f"创建动态Ingress路由失败: {e}")
                return jsonify({'error': f'k8s service unavailable: {e}'}), 502
            except Exception as e:
                self.logger.error(f"创建动态Ingress路由失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/agent/<agent_key>/ingress-routes/<route_id>', methods=['DELETE'])
        def delete_agent_ingress_route(agent_key, route_id):
            """删除 Agent 节点入口 Ingress 路由（仅 agent_console）。"""
            try:
                project_id = request.args.get('project_id')
                if not project_id:
                    return jsonify({'error': 'project_id parameter is required'}), 400

                agent = self.agent_manager.get_agent(agent_key)
                if not agent:
                    return jsonify({'error': f'Agent {agent_key} not found'}), 404
                if agent.project_id != project_id:
                    return jsonify({'error': f'Agent {agent_key} does not belong to project {project_id}'}), 403

                auth_header = request.headers.get('Authorization')
                list_resp = self._call_k8s_service(
                    method='GET',
                    path='/api/k8s/agent-ingress-routes',
                    project_id=project_id,
                    params={'agent_key': agent_key},
                    headers={'Authorization': auth_header} if auth_header else None
                )
                if list_resp.status_code >= 300:
                    return jsonify(list_resp.json()), list_resp.status_code

                items = (list_resp.json() or {}).get('items') or []
                target_item = next((item for item in items if str(item.get('route_id') or '') == str(route_id)), None)
                if not target_item:
                    return jsonify({'error': f'Ingress route {route_id} not found'}), 404
                if not self._is_agent_console_ingress_route(target_item):
                    return jsonify({'error': '该路由属于服务 Ingress，请前往集群服务发现页面管理'}), 403

                resp = self._call_k8s_service(
                    method='DELETE',
                    path=f'/api/k8s/agent-ingress-routes/{route_id}',
                    project_id=project_id,
                    params={'agent_key': agent_key},
                    headers={'Authorization': auth_header} if auth_header else None
                )
                return jsonify(resp.json()), resp.status_code
            except requests.RequestException as e:
                self.logger.error(f"删除动态Ingress路由失败: {e}")
                return jsonify({'error': f'k8s service unavailable: {e}'}), 502
            except Exception as e:
                self.logger.error(f"删除动态Ingress路由失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        # ===================== 守护进程服务代理路由 =====================

        @self.app.route('/api/agent/agent/<agent_key>/daemon-services', methods=['GET'])
        def get_daemon_services(agent_key):
            """获取 Agent 守护进程服务列表"""
            try:
                status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                    agent_key=agent_key,
                    method='GET',
                    endpoint='/api/v1/services',
                    port=self.agent_manager.daemon_api_port,
                    timeout=self.daemon_read_timeout_sec
                )

                response = jsonify(response_data)
                for key, value in response_headers.items():
                    if key.lower() == 'Content-Length'.lower():
                        continue
                    response.headers[key] = value
                response.status_code = status_code
                return response

            except Exception as e:
                self.logger.error(f"获取守护进程服务失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/agent/<agent_key>/daemon-services/<service_name>', methods=['GET'])
        def get_daemon_service_detail(agent_key, service_name):
            """获取单个守护进程服务详情"""
            try:
                status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                    agent_key=agent_key,
                    method='GET',
                    endpoint=f'/api/v1/services/{service_name}',
                    port=self.agent_manager.daemon_api_port,
                    timeout=self.daemon_read_timeout_sec
                )

                response = jsonify(response_data)
                for key, value in response_headers.items():
                    if key.lower() == 'Content-Length'.lower():
                        continue
                    response.headers[key] = value
                response.status_code = status_code
                return response

            except Exception as e:
                self.logger.error(f"获取守护进程服务详情失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/agent/<agent_key>/daemon-services/<service_name>/start', methods=['POST'])
        def start_daemon_service(agent_key, service_name):
            """启动守护进程服务"""
            try:
                status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                    agent_key=agent_key,
                    method='POST',
                    endpoint=f'/api/v1/services/{service_name}/start',
                    port=self.agent_manager.daemon_api_port,
                    timeout=60
                )

                response = jsonify(response_data)
                for key, value in response_headers.items():
                    if key.lower() == 'Content-Length'.lower():
                        continue
                    response.headers[key] = value
                response.status_code = status_code
                return response

            except Exception as e:
                self.logger.error(f"启动守护进程服务失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/agent/<agent_key>/daemon-services/<service_name>/stop', methods=['POST'])
        def stop_daemon_service(agent_key, service_name):
            """停止守护进程服务"""
            try:
                status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                    agent_key=agent_key,
                    method='POST',
                    endpoint=f'/api/v1/services/{service_name}/stop',
                    port=self.agent_manager.daemon_api_port,
                    timeout=60
                )

                response = jsonify(response_data)
                for key, value in response_headers.items():
                    if key.lower() == 'Content-Length'.lower():
                        continue
                    response.headers[key] = value
                response.status_code = status_code
                return response

            except Exception as e:
                self.logger.error(f"停止守护进程服务失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/agent/<agent_key>/daemon-services/<service_name>/restart', methods=['POST'])
        def restart_daemon_service(agent_key, service_name):
            """重启守护进程服务"""
            try:
                status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                    agent_key=agent_key,
                    method='POST',
                    endpoint=f'/api/v1/services/{service_name}/restart',
                    port=self.agent_manager.daemon_api_port,
                    timeout=120
                )

                response = jsonify(response_data)
                for key, value in response_headers.items():
                    if key.lower() == 'Content-Length'.lower():
                        continue
                    response.headers[key] = value
                response.status_code = status_code
                return response

            except Exception as e:
                self.logger.error(f"重启守护进程服务失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/agent/<agent_key>/daemon-services/<service_name>/logs', methods=['GET'])
        def get_daemon_service_logs(agent_key, service_name):
            """获取守护进程服务日志"""
            try:
                # 获取查询参数
                log_type = request.args.get('type', 'stdout')
                lines = request.args.get('lines', '100')

                query_params = {
                    'type': log_type,
                    'lines': lines
                }

                status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                    agent_key=agent_key,
                    method='GET',
                    endpoint=f'/api/v1/services/{service_name}/logs',
                    query_params=query_params,
                    port=self.agent_manager.daemon_api_port,
                    timeout=self.daemon_read_timeout_sec
                )

                response = jsonify(response_data)
                for key, value in response_headers.items():
                    if key.lower() == 'Content-Length'.lower():
                        continue
                    response.headers[key] = value
                response.status_code = status_code
                return response

            except Exception as e:
                self.logger.error(f"获取守护进程服务日志失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        # ===================== 守护进程服务代理路由结束 =====================

        @self.app.route('/api/agent/proxy/info', methods=['GET'])
        def get_proxy_info():
            """获取代理API信息"""
            # 获取可用的Agent列表
            agents = self.agent_manager.list_agents()[0]

            proxy_info = {
                'available_agents': [
                    {
                        'key': agent['key'],
                        'hostname': agent['hostname'],
                        'ip_address': agent['ip_address'],
                        'project': agent['project_id'],
                        'status': agent['status'],
                        'last_seen': agent.get('last_seen')
                    }
                    for agent in agents
                ],
                'supported_formats': self.config.get('supported_formats', SUPPORTED_FORMATS)
            }

            return jsonify(proxy_info)

        @self.app.route('/api/agent/proxy/test/<agent_key>', methods=['GET'])
        def test_proxy_connection(agent_key):
            """测试代理连接"""
            try:
                # 首先尝试直接调用Agent的健康检查
                status_code, response_data, response_headers = self.proxy_manager.proxy_request(
                    agent_key=agent_key,
                    method='GET',
                    endpoint='/api/health'
                )

                agent = self.agent_manager.get_agent(agent_key)
                agent_info = agent.to_dict() if agent else None

                return jsonify({
                    'agent_key': agent_key,
                    'connection_test': 'success' if status_code == 200 else 'failed',
                    'status_code': status_code,
                    'response': response_data,
                    'agent_info': agent_info,
                    'timestamp': datetime.now().isoformat()
                })

            except Exception as e:
                return jsonify({
                    'agent_key': agent_key,
                    'connection_test': 'failed',
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                }), 500

        @self.app.route('/api/agent/agents/<agent_key>', methods=['GET'])
        def get_agent_by_key(agent_key):
            """根据agent_key获取Agent信息"""
            try:
                # Get project_id from query parameter
                project_id = request.args.get('project_id')
                if not project_id:
                    return jsonify({'error': 'project_id parameter is required'}), 400

                # 从数据库查询Agent
                table_name = self.db_manager.get_table_name('agent_status')
                if self.db_manager.db_type == 'mysql':
                    agent_data = self.db_manager.fetch_one(
                        f"SELECT * FROM {table_name} WHERE agent_key = %s",
                        (agent_key,)
                    )
                else:
                    agent_data = self.db_manager.fetch_one(
                        f"SELECT * FROM {table_name} WHERE agent_key = ?",
                        (agent_key,)
                    )

                if not agent_data:
                    # 尝试从内存中获取
                    agent = self.agent_manager.get_agent(agent_key)
                    if agent:
                        agent_data = agent.to_dict()
                    else:
                        return jsonify({'error': f'Agent {agent_key} not found'}), 404
                else:
                    # 转换数据格式
                    agent_data = {
                        'key': agent_data['agent_key'],
                        'ip_address': agent_data['ip_address'],
                        'hostname': agent_data['hostname'],
                        'project_id': agent_data['project_id'],
                        'full_name': agent_data['full_name'],
                        'status': agent_data['status'],
                        'pod_id': agent_data['pod_id']
                    }

                # Verify the agent belongs to the requested project
                if agent_data.get('project_id') != project_id:
                    return jsonify({'error': f'Agent {agent_key} does not belong to project {project_id}'}), 403

                # Add additional fields if from database
                if 'last_seen' in agent_data:
                    pass
                else:
                    # Fetch from database for additional fields
                    if self.db_manager.db_type == 'mysql':
                        full_data = self.db_manager.fetch_one(
                            f"SELECT * FROM {table_name} WHERE agent_key = %s",
                            (agent_key,)
                        )
                    else:
                        full_data = self.db_manager.fetch_one(
                            f"SELECT * FROM {table_name} WHERE agent_key = ?",
                            (agent_key,)
                        )
                    if full_data:
                        if full_data['last_seen']:
                            if isinstance(full_data['last_seen'], str):
                                agent_data['last_seen'] = full_data['last_seen']
                            else:
                                agent_data['last_seen'] = full_data['last_seen'].isoformat()

                        if full_data['system_info']:
                            if isinstance(full_data['system_info'], str):
                                try:
                                    agent_data['system_info'] = json.loads(full_data['system_info'])
                                except:
                                    agent_data['system_info'] = full_data['system_info']
                            else:
                                agent_data['system_info'] = full_data['system_info']

                        daemon_info_raw = full_data.get('daemon_info')
                        if daemon_info_raw:
                            if isinstance(daemon_info_raw, str):
                                try:
                                    agent_data['daemon_info'] = json.loads(daemon_info_raw)
                                except:
                                    agent_data['daemon_info'] = daemon_info_raw
                            else:
                                agent_data['daemon_info'] = daemon_info_raw

                        if full_data['services']:
                            if isinstance(full_data['services'], str):
                                try:
                                    agent_data['services'] = json.loads(full_data['services'])
                                except:
                                    agent_data['services'] = full_data['services']
                            else:
                                agent_data['services'] = full_data['services']

                # Include project_id in response
                agent_data['requested_project_id'] = project_id

                return jsonify(agent_data)

            except Exception as e:
                self.logger.error(f"获取Agent信息失败: {str(e)}")
                return jsonify({'error': str(e)}), 500

        # 在_register_routes方法中添加示例文档端点
        @self.app.route('/api/agent/proxy/examples', methods=['GET'])
        def get_proxy_examples():
            """获取代理使用示例"""
            examples = {
                'description': '代理API允许通过Server访问Agent的所有API',
                'basic_usage': {
                    'pattern': '/api/proxy/{agent_key}/{action_path}',
                    'methods': ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'],
                    'note': 'action_path可以是任意路径，包括多层路径'
                },
                'simple_usage': {
                    'pattern': '/api/agent/{agent_key}/{action_path}',
                    'methods': ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
                    'note': '自动添加/api前缀，action_path不需要包含/api'
                },
                'quick_access': {
                    '/api/agent/{agent_key}/system/info': 'GET - 获取Agent系统信息',
                    '/api/agent/{agent_key}/services': 'GET - 获取Agent服务列表',
                    '/api/agent/{agent_key}/health': 'GET - 检查Agent健康状态'
                },
                'examples': [
                    {
                        'description': '获取Agent系统信息',
                        'method': 'GET',
                        'url': '/api/agent/proxy/abc123def456/api/system/info',
                        'curl': 'curl -X GET -H "Authorization: Bearer YOUR_TOKEN" http://server:18080/api/agent/proxy/abc123def456/api/system/info'
                    },
                    {
                        'description': '获取Agent服务列表',
                        'method': 'GET',
                        'url': '/api/agent/proxy/abc123def456/api/services',
                        'curl': 'curl -X GET -H "Authorization: Bearer YOUR_TOKEN" http://server:18080/api/agent/proxy/abc123def456/api/services'
                    },
                    {
                        'description': '启动Agent上的服务',
                        'method': 'POST',
                        'url': '/api/agent/proxy/abc123def456/api/services/myservice/start',
                        'curl': 'curl -X POST -H "Authorization: Bearer YOUR_TOKEN" http://server:18080/api/agent/proxy/abc123def456/api/services/myservice/start'
                    },
                    {
                        'description': '获取服务日志',
                        'method': 'GET',
                        'url': '/api/agent/proxy/abc123def456/api/services/myservice/logs?tail=100',
                        'curl': 'curl -X GET -H "Authorization: Bearer YOUR_TOKEN" "http://server:18080/api/agent/proxy/abc123def456/api/services/myservice/logs?tail=100"'
                    },
                    {
                        'description': '上传压缩文件创建服务',
                        'method': 'POST',
                        'url': '/api/agent/proxy/abc123def456/api/services/zip',
                        'content_type': 'multipart/form-data',
                        'form_data': {
                            'name': 'myapp',
                            'file': 'myapp.zip'  # 支持多种压缩格式
                        },
                        'curl': 'curl -X POST -H "Authorization: Bearer YOUR_TOKEN" -F "name=myapp" -F "file=@myapp.zip" http://server:18080/api/agent/proxy/abc123def456/api/services/zip'
                    },
                    {
                        'description': '从YAML创建服务',
                        'method': 'POST',
                        'url': '/api/agent/proxy/abc123def456/api/services/yaml',
                        'content_type': 'application/json',
                        'body': {
                            'name': 'myservice',
                            'yaml': 'version: "3"\nservices:\n  web:\n    image: nginx:latest'
                        },
                        'curl': 'curl -X POST -H "Authorization: Bearer YOUR_TOKEN" -H "Content-Type: application/json" -d \'{"name":"myservice","yaml":"version: \\"3\\"\\nservices:\\n  web:\\n    image: nginx:latest"}\' http://server:18080/api/agent/proxy/abc123def456/api/services/yaml'
                    }
                ],
                'tips': [
                    '使用 /api/agent/proxy/info 获取所有可用Agent',
                    '使用 /api/agent/proxy/test/{agent_key} 测试代理连接',
                    '文件上传需要设置 Content-Type: multipart/form-data',
                    '支持流式响应，添加 ?stream=true 参数',
                    '所有原始请求头（除敏感头外）都会转发到Agent',
                    f'支持多种压缩格式: {", ".join(self.config.get("supported_formats", SUPPORTED_FORMATS))}'
                ]
            }

            return jsonify(examples)

        # ===================== 模板管理API（完整版，支持多种压缩格式） =====================

        def _resolve_template_by_id(template_id: int) -> Optional[Dict]:
            return self.template_manager.get_template_by_id(template_id)

        @self.app.route('/api/agent/templates', methods=['GET'])
        def list_templates():
            """列出所有模板（包含文件大小信息）"""
            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 20))
            user_ctx = self._get_request_user_context()
            templates, total = self.template_manager.list_templates(
                page, per_page,
                user_ctx.get('user_id', ''),
                user_ctx.get('username', '')
            )
            return jsonify({
                'templates': templates,
                'page': page,
                'per_page': per_page,
                'total': total,
                'supported_formats': self.config.get('supported_formats', SUPPORTED_FORMATS)
            })

        @self.app.route('/api/agent/templates', methods=['POST'])
        def upload_template():
            """上传模板（支持多种压缩格式）"""
            if 'file' not in request.files:
                return jsonify({'error': '未找到文件'}), 400

            file = request.files['file']
            name = request.form.get('name')
            description = request.form.get('description', '')
            template_type = request.form.get('type', 'auto')  # 默认为自动检测
            visibility = (request.form.get('visibility', 'shared') or 'shared').strip().lower()
            web_port_presets_raw = request.form.get('web_port_presets')
            tags_raw = request.form.get('tags')
            web_port_presets = None
            tags = None
            if visibility not in ('shared', 'private'):
                return jsonify({'error': 'visibility 仅支持 shared 或 private'}), 400
            if web_port_presets_raw:
                try:
                    web_port_presets = json.loads(web_port_presets_raw)
                    if not isinstance(web_port_presets, list):
                        return jsonify({'error': 'web_port_presets 必须是JSON数组'}), 400
                except Exception:
                    return jsonify({'error': 'web_port_presets JSON格式错误'}), 400
            if tags_raw:
                try:
                    tags = json.loads(tags_raw)
                    if not isinstance(tags, list):
                        return jsonify({'error': 'tags 必须是JSON数组'}), 400
                except Exception:
                    return jsonify({'error': 'tags JSON格式错误'}), 400

            if not name:
                return jsonify({'error': '模板名称不能为空'}), 400

            if not file.filename:
                return jsonify({'error': '文件名不能为空'}), 400

            # 检查文件扩展名
            filename = file.filename
            file_ext = Path(filename).suffix.lower()

            # 自动检测模板类型
            if template_type == 'auto':
                if file_ext in ['.yaml', '.yml']:
                    template_type = 'yaml'
                elif any(filename.lower().endswith(ext) for ext in
                         self.config.get('supported_formats', SUPPORTED_FORMATS)):
                    template_type = 'archive'
                else:
                    return jsonify({'error': f'不支持的文件格式: {filename}'}), 400

            # 验证压缩格式
            if template_type == 'archive':
                is_supported = False
                for ext in self.config.get('supported_formats', SUPPORTED_FORMATS):
                    if filename.lower().endswith(ext):
                        is_supported = True
                        break

                if not is_supported:
                    return jsonify({
                        'error': f'不支持的压缩格式: {filename}',
                        'supported_formats': self.config.get('supported_formats', SUPPORTED_FORMATS)
                    }), 400

            # 读取文件内容
            file_content = file.read()
            user_ctx = self._get_request_user_context()
            created_by = user_ctx.get('username', 'system')

            def _create_template():
                return self.template_manager.create_template(
                    name, description, template_type, file_content, filename,
                    created_by,
                    visibility=visibility,
                    owner_id=user_ctx.get('user_id', ''),
                    owner_name=user_ctx.get('username', ''),
                    web_port_presets=web_port_presets,
                    tags=tags,
                )

            try:
                success, message = self._with_template_write_lock([name], _create_template)
            except BlockingIOError as e:
                return jsonify({'error': str(e)}), 409

            if success:
                return jsonify({
                    'message': message,
                    'template_name': name,
                    'template_type': template_type,
                    'filename': filename,
                    'visibility': visibility,
                    'owner_id': user_ctx.get('user_id', ''),
                    'owner_name': user_ctx.get('username', ''),
                    'tags': tags or []
                }), 201
            else:
                return jsonify({'error': message}), 400

        @self.app.route('/api/agent/templates/<name>', methods=['GET'])
        def get_template_detail(name):
            """获取模板详细信息（包含解析数据和文件大小）"""
            if name == 'llm-providers':
                return list_template_llm_providers()

            user_ctx = self._get_request_user_context()
            template = self.template_manager.get_template(name)

            if template:
                if not self._check_template_visible(template, user_ctx):
                    return jsonify({'error': '无权限访问该模板'}), 403

                # 获取文件详细信息
                file_info = self.template_manager.get_template_file_info(name)
                if file_info:
                    template['file_info'] = file_info

                # 获取目录中的文件列表
                template_dir = self.template_manager.templates_root / name
                if template_dir.exists():
                    files = []
                    for file_path in template_dir.rglob('*'):
                        if file_path.is_file():
                            rel_path = file_path.relative_to(template_dir)
                            if self.template_manager._is_internal_template_path(rel_path):
                                continue
                            file_stat = file_path.stat()
                            files.append({
                                'name': file_path.name,
                                'path': str(rel_path),
                                'size': file_stat.st_size,
                                'modified': datetime.fromtimestamp(file_stat.st_mtime).isoformat()
                            })
                    template['directory_files'] = files

                # 处理 metadata 并检查解析数据是否过期
                metadata = template.get('metadata', {})
                if isinstance(metadata, str):
                    try:
                        metadata = json.loads(metadata)
                        template['metadata'] = metadata
                    except:
                        template['metadata'] = {}

                # 检查解析数据是否过期
                if metadata and metadata.get('parsed_compose'):
                    success, is_stale, msg = self.template_manager.check_parse_staleness(name)
                    if success and is_stale:
                        metadata['parse_status'] = 'stale'
                        template['metadata'] = metadata
                template = self.template_manager.decorate_template_permissions(
                    template,
                    user_ctx.get('user_id', ''),
                    user_ctx.get('username', '')
                )

                return jsonify(template)
            else:
                return jsonify({'error': '模板不存在'}), 404

        @self.app.route('/api/agent/templates/by-name/<name>', methods=['GET'])
        def get_template_detail_by_name(name):
            """根据名称查询模板"""
            return get_template_detail(name)

        @self.app.route('/api/agent/templates/id/<int:template_id>', methods=['GET'])
        def get_template_detail_by_id(template_id):
            """根据ID获取模板详情"""
            template = _resolve_template_by_id(template_id)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            return get_template_detail(template['name'])

        @self.app.route('/api/agent/templates/id/<int:template_id>', methods=['PUT'])
        def update_template_basic_by_id(template_id):
            """根据ID更新模板基础信息（支持改名）"""
            user_ctx = self._get_request_user_context()
            template = _resolve_template_by_id(template_id)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            if not self._check_template_manageable(template, user_ctx):
                return jsonify({'error': '无权限更新该模板，仅拥有者可更新'}), 403

            data = request.get_json(silent=True) or {}
            new_name = data.get('name')
            description = data.get('description') if 'description' in data else None
            visibility = data.get('visibility') if 'visibility' in data else None
            web_port_presets = data.get('web_port_presets') if 'web_port_presets' in data else None
            tags = data.get('tags') if 'tags' in data else None
            if visibility is not None and str(visibility).strip().lower() not in ('shared', 'private'):
                return jsonify({'error': 'visibility 仅支持 shared 或 private'}), 400
            if web_port_presets is not None and not isinstance(web_port_presets, list):
                return jsonify({'error': 'web_port_presets 必须是数组'}), 400
            if tags is not None and not isinstance(tags, list):
                return jsonify({'error': 'tags 必须是数组'}), 400

            def _update_template_basic():
                return self.template_manager.update_template_basic(
                    template_id=template_id,
                    new_name=new_name,
                    description=description,
                    visibility=visibility,
                    web_port_presets=web_port_presets,
                    tags=tags,
                    updated_by=user_ctx.get('username', 'system')
                )

            try:
                success, message, updated = self._with_template_write_lock(
                    [template.get('name'), new_name],
                    _update_template_basic
                )
            except BlockingIOError as e:
                return jsonify({'error': str(e)}), 409
            if not success:
                return jsonify({'error': message}), 400
            updated = self.template_manager.decorate_template_permissions(
                updated,
                user_ctx.get('user_id', ''),
                user_ctx.get('username', '')
            )
            return jsonify({'message': message, 'template': updated, 'status': 'success'})

        @self.app.route('/api/agent/templates/id/<int:template_id>/web-ports', methods=['GET', 'PUT'])
        def manage_template_web_ports_by_id(template_id):
            """按模板ID查询/更新WEB端口预设。"""
            user_ctx = self._get_request_user_context()
            template = _resolve_template_by_id(template_id)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            if not self._check_template_visible(template, user_ctx):
                return jsonify({'error': '无权限访问该模板'}), 403

            if request.method == 'GET':
                metadata = template.get('metadata') or {}
                if isinstance(metadata, str):
                    try:
                        metadata = json.loads(metadata)
                    except Exception:
                        metadata = {}
                raw_presets = metadata.get('web_port_presets') if isinstance(metadata, dict) else []
                presets = self.template_manager._normalize_web_port_presets(raw_presets)
                return jsonify({
                    'template_id': template_id,
                    'template_name': template.get('name'),
                    'web_port_presets': presets,
                    'permissions': {
                        'can_manage': self._check_template_manageable(template, user_ctx)
                    }
                })

            # PUT
            if not self._check_template_manageable(template, user_ctx):
                return jsonify({'error': '无权限更新该模板，仅拥有者可更新'}), 403

            data = request.get_json(silent=True) or {}
            web_port_presets = data.get('web_port_presets')
            if web_port_presets is None:
                return jsonify({'error': 'web_port_presets is required'}), 400
            if not isinstance(web_port_presets, list):
                return jsonify({'error': 'web_port_presets 必须是数组'}), 400

            def _update_web_ports():
                return self.template_manager.update_template_basic(
                    template_id=template_id,
                    web_port_presets=web_port_presets,
                    updated_by=user_ctx.get('username', 'system')
                )

            try:
                success, message, updated = self._with_template_write_lock(
                    [template.get('name')],
                    _update_web_ports
                )
            except BlockingIOError as e:
                return jsonify({'error': str(e)}), 409
            if not success:
                return jsonify({'error': message}), 400

            updated = self.template_manager.decorate_template_permissions(
                updated,
                user_ctx.get('user_id', ''),
                user_ctx.get('username', '')
            )
            metadata = updated.get('metadata') or {}
            if isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except Exception:
                    metadata = {}
            normalized = self.template_manager._normalize_web_port_presets(
                metadata.get('web_port_presets') if isinstance(metadata, dict) else []
            )
            return jsonify({
                'message': 'WEB端口已更新',
                'status': 'success',
                'template': updated,
                'web_port_presets': normalized
            })

        @self.app.route('/api/agent/templates/llm-providers', methods=['GET'])
        def list_template_llm_providers():
            try:
                project_id = str(request.args.get('project_id') or '').strip()
                payload = self._list_service_llm_providers()
                return jsonify({
                    'project_id': project_id,
                    'default_provider_key': payload.get('default_provider_key'),
                    'items': payload.get('items') if isinstance(payload.get('items'), list) else [],
                    'total': int(payload.get('total') or 0),
                })
            except Exception as e:
                self.logger.error(f"查询模板LLM Provider列表失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/templates/llm-providers/<provider_key>', methods=['GET'])
        def get_template_llm_provider(provider_key):
            try:
                return jsonify(self._get_service_llm_provider(provider_key))
            except Exception as e:
                self.logger.error(f"查询模板LLM Provider详情失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/templates/llm-providers/preview', methods=['POST'])
        def preview_template_llm_binding():
            try:
                data = request.get_json(silent=True) or {}
                project_id = str(data.get('project_id') or '').strip()

                provider_keys = data.get('provider_keys')
                if not isinstance(provider_keys, list):
                    return jsonify({'error': 'provider_keys must be a list'}), 400

                target_services = data.get('target_services', '*')
                if target_services != '*' and not isinstance(target_services, list):
                    target_services = '*'

                merged = self._merge_llm_provider_binding(
                    provider_keys,
                    target_services=target_services,
                    source='preview',
                )
                return jsonify({
                    'project_id': project_id,
                    **merged,
                })
            except Exception as e:
                self.logger.error(f"预览模板LLM Provider绑定失败: {e}", exc_info=True)
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/templates/id/<int:template_id>/regenerate-with-llm-providers', methods=['POST'])
        def regenerate_template_with_llm_providers(template_id):
            user_ctx = self._get_request_user_context()
            template = _resolve_template_by_id(template_id)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            if not self._check_template_manageable(template, user_ctx):
                return jsonify({'error': '无权限重新生成该模板，仅拥有者可更新'}), 403

            data = request.get_json(silent=True) or {}
            raw_binding = {
                'provider_keys': data.get('provider_keys'),
                'target_services': data.get('target_services', '*'),
            }

            try:
                normalized_binding = self._normalize_template_llm_binding(
                    raw_binding,
                    allowed_services=self._extract_template_service_names(template) or None,
                )
            except Exception as e:
                return jsonify({'error': str(e)}), 400

            resolved_binding = self._merge_llm_provider_binding(
                normalized_binding.get('provider_keys', []),
                normalized_binding.get('target_services', '*'),
                source='template_regeneration',
            )

            def _regenerate_template():
                return self.template_manager.regenerate_template_with_llm_providers(
                    template_id=template_id,
                    binding=resolved_binding,
                    generated_by=user_ctx.get('username', 'system')
                )

            try:
                success, message, updated = self._with_template_write_lock(
                    [template.get('name')],
                    _regenerate_template
                )
            except BlockingIOError as e:
                return jsonify({'error': str(e)}), 409

            if not success:
                return jsonify({'error': message}), 400
            updated = self.template_manager.decorate_template_permissions(
                updated,
                user_ctx.get('user_id', ''),
                user_ctx.get('username', '')
            )
            return jsonify({'message': message, 'template': updated, 'resolved_binding': resolved_binding, 'status': 'success'})

        @self.app.route('/api/agent/templates/id/<int:template_id>/restore-original-compose', methods=['POST'])
        def restore_template_original_compose(template_id):
            user_ctx = self._get_request_user_context()
            template = _resolve_template_by_id(template_id)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            if not self._check_template_manageable(template, user_ctx):
                return jsonify({'error': '无权限恢复该模板，仅拥有者可更新'}), 403

            def _restore_template():
                return self.template_manager.restore_template_original_compose(
                    template_id=template_id,
                    restored_by=user_ctx.get('username', 'system')
                )

            try:
                success, message, updated = self._with_template_write_lock(
                    [template.get('name')],
                    _restore_template
                )
            except BlockingIOError as e:
                return jsonify({'error': str(e)}), 409

            if not success:
                return jsonify({'error': message}), 400
            updated = self.template_manager.decorate_template_permissions(
                updated,
                user_ctx.get('user_id', ''),
                user_ctx.get('username', '')
            )
            return jsonify({'message': message, 'template': updated, 'status': 'success'})

        @self.app.route('/api/agent/templates/id/<int:template_id>/compose-source', methods=['GET'])
        def get_template_compose_source(template_id):
            user_ctx = self._get_request_user_context()
            template = _resolve_template_by_id(template_id)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            if not self._check_template_visible(template, user_ctx):
                return jsonify({'error': '无权限访问该模板'}), 403
            success, message, payload = self.template_manager.get_template_compose_source(template_id)
            if not success:
                return jsonify({'error': message}), 400
            return jsonify(payload)

        @self.app.route('/api/agent/templates/<name>/yaml', methods=['GET'])
        def get_template_yaml(name):
            """获取模板的YAML内容"""
            user_ctx = self._get_request_user_context()
            template = self.template_manager.get_template(name)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            if not self._check_template_visible(template, user_ctx):
                return jsonify({'error': '无权限访问该模板'}), 403
            success, content, message = self.template_manager.get_yaml_content(name)

            if success:
                return jsonify({
                    'name': name,
                    'yaml_content': content,
                    'status': 'success'
                })
            else:
                return jsonify({
                    'error': content,
                    'details': message,
                    'status': 'failed'
                }), 400

        @self.app.route('/api/agent/templates/<name>/yaml', methods=['PUT'])
        def update_template_yaml(name):
            """更新模板的YAML内容"""
            user_ctx = self._get_request_user_context()
            template = self.template_manager.get_template(name)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            if not self._check_template_manageable(template, user_ctx):
                return jsonify({'error': '无权限更新该模板，仅拥有者可更新'}), 403
            data = request.get_json()
            if not data:
                return jsonify({'error': '请求体必须为JSON'}), 400

            yaml_content = data.get('yaml_content')
            if not yaml_content:
                return jsonify({'error': 'YAML内容不能为空'}), 400

            def _update_yaml():
                return self.template_manager.update_yaml_content(
                    name, yaml_content, user_ctx.get('username', 'system')
                )

            try:
                success, message = self._with_template_write_lock([name], _update_yaml)
            except BlockingIOError as e:
                return jsonify({'error': str(e)}), 409

            if success:
                # 返回更新后的模板信息
                template = self.template_manager.get_template(name)
                return jsonify({
                    'message': message,
                    'template': template,
                    'status': 'success'
                })
            else:
                return jsonify({'error': message}), 400

        @self.app.route('/api/agent/templates/<name>/download', methods=['GET'])
        def download_template(name):
            """下载模板文件"""
            try:
                user_ctx = self._get_request_user_context()
                format_param = request.args.get('format', 'original')
                as_zip = request.args.get('as_zip', '').lower() == 'true'
                include_all = request.args.get('include_all', 'true').lower() == 'true'
                disposition = request.args.get('disposition', 'attachment')

                self.logger.info(f"下载模板请求: {name}, format={format_param}, as_zip={as_zip}")

                # 检查模板是否存在
                template = self.template_manager.get_template(name)
                if not template:
                    return jsonify({'error': f'模板 {name} 不存在'}), 404
                if not self._check_template_visible(template, user_ctx):
                    return jsonify({'error': '无权限访问该模板'}), 403

                # 处理下载请求
                if as_zip:
                    # 下载为ZIP包（包含所有文件）
                    success, content, content_type = self.template_manager.get_template_as_zip(
                        name, include_all
                    )
                    filename = f"{name}.zip"
                else:
                    # 根据指定格式下载
                    export_format = format_param
                    if export_format == 'original':
                        export_format = template['type']

                    success, content, content_type, filename = self.template_manager.export_template(
                        name, export_format
                    )

                if not success:
                    return jsonify({'error': content}), 400

                # 设置响应头
                response_headers = {
                    'Content-Type': content_type,
                    'Content-Disposition': f'{disposition}; filename="{filename}"',
                    'X-Template-Name': name,
                    'X-Template-Type': template['type'],
                    'X-File-Size': str(len(content) if isinstance(content, bytes) else 0)
                }

                # 创建响应
                response = self.app.response_class(
                    response=content,
                    status=200,
                    headers=response_headers
                )

                self.logger.info(
                    f"模板下载成功: {name}, 文件大小: {len(content) if isinstance(content, bytes) else 'N/A'} 字节")

                return response

            except Exception as e:
                self.logger.error(f"模板下载失败: {str(e)}", exc_info=True)
                return jsonify({'error': f'下载失败: {str(e)}'}), 500

        @self.app.route('/api/agent/templates/<name>/file', methods=['GET'])
        def get_template_file(name):
            """获取模板原始文件"""
            try:
                user_ctx = self._get_request_user_context()
                template = self.template_manager.get_template(name)
                if not template:
                    return jsonify({'error': f'模板 {name} 不存在'}), 404
                if not self._check_template_visible(template, user_ctx):
                    return jsonify({'error': '无权限访问该模板'}), 403
                file_info = self.template_manager.get_template_file_info(name)

                if not file_info:
                    return jsonify({'error': f'模板 {name} 不存在或文件已丢失'}), 404

                file_path = Path(file_info['file_path'])

                if not file_path.exists():
                    return jsonify({'error': '模板文件不存在'}), 404

                # 设置内容类型
                if file_info['type'] == 'yaml':
                    mimetype = 'text/yaml'
                    as_attachment = False
                elif file_info['type'] == 'archive':
                    mimetype = self.template_manager._get_content_type(file_path.name)
                    as_attachment = True
                else:
                    mimetype = 'application/octet-stream'
                    as_attachment = True

                # 确定文件名
                if as_attachment:
                    filename = f"{name}{Path(file_path).suffix}"
                else:
                    filename = None

                self.logger.info(f"发送模板文件: {name}, 路径: {file_path}")

                return send_file(
                    file_path,
                    mimetype=mimetype,
                    as_attachment=as_attachment,
                    download_name=filename
                )

            except Exception as e:
                self.logger.error(f"获取模板文件失败: {str(e)}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/templates/<name>/content', methods=['GET'])
        def get_template_content(name):
            """获取模板内容（JSON格式）"""
            try:
                user_ctx = self._get_request_user_context()
                template = self.template_manager.get_template(name)

                if not template:
                    return jsonify({'error': f'模板 {name} 不存在'}), 404
                if not self._check_template_visible(template, user_ctx):
                    return jsonify({'error': '无权限访问该模板'}), 403

                success, content, content_type = self.template_manager.get_template_file_content(
                    name, 'bytes'
                )

                if not success:
                    return jsonify({'error': content}), 400

                # 编码内容
                if template['type'] == 'yaml':
                    content_str = content.decode('utf-8')
                    encoded_content = content_str
                    encoding = 'utf-8'
                else:
                    encoded_content = base64.b64encode(content).decode('utf-8')
                    encoding = 'base64'

                return jsonify({
                    'name': name,
                    'type': template['type'],
                    'content_type': content_type,
                    'content_encoding': encoding,
                    'content': encoded_content,
                    'size': len(content),
                    'file_size': template.get('file_size', 0),
                    'directory_size': template.get('directory_size', 0),
                    'created_at': template.get('created_at'),
                    'updated_at': template.get('updated_at')
                })

            except Exception as e:
                self.logger.error(f"获取模板内容失败: {str(e)}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/templates/<name>/info', methods=['GET'])
        def get_template_info(name):
            """获取模板详细信息（包含文件列表）"""
            try:
                user_ctx = self._get_request_user_context()
                template = self.template_manager.get_template(name)

                if not template:
                    return jsonify({'error': f'模板 {name} 不存在'}), 404
                if not self._check_template_visible(template, user_ctx):
                    return jsonify({'error': '无权限访问该模板'}), 403

                file_info = self.template_manager.get_template_file_info(name)

                response = dict(template)

                if file_info:
                    response['file_info'] = file_info

                # 获取模板目录中的文件列表
                template_dir = self.template_manager.templates_root / name
                if template_dir.exists():
                    files = []
                    total_size = 0

                    for file_path in template_dir.rglob('*'):
                        if file_path.is_file():
                            file_stat = file_path.stat()
                            files.append({
                                'name': file_path.name,
                                'path': str(file_path.relative_to(template_dir)),
                                'size': file_stat.st_size,
                                'modified': datetime.fromtimestamp(file_stat.st_mtime).isoformat()
                            })
                            total_size += file_stat.st_size

                    response['directory_info'] = {
                        'path': str(template_dir),
                        'total_files': len(files),
                        'total_size': total_size,
                        'files': files
                    }

                return jsonify(response)

            except Exception as e:
                self.logger.error(f"获取模板信息失败: {str(e)}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/agent/templates/<name>', methods=['DELETE'])
        def delete_template(name):
            """删除模板"""
            user_ctx = self._get_request_user_context()
            template = self.template_manager.get_template(name)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            if not self._check_template_manageable(template, user_ctx):
                return jsonify({'error': '无权限删除该模板，仅拥有者可删除'}), 403
            try:
                success, message = self._with_template_write_lock(
                    [name],
                    lambda: self.template_manager.delete_template(name)
                )
            except BlockingIOError as e:
                return jsonify({'error': str(e)}), 409

            if success:
                return jsonify({'message': message})
            else:
                return jsonify({'error': message}), 400

        @self.app.route('/api/agent/templates/<name>/copy', methods=['POST'])
        def copy_template(name):
            """复制模板"""
            user_ctx = self._get_request_user_context()
            source = self.template_manager.get_template(name)
            if not source:
                return jsonify({'error': '源模板不存在'}), 404
            if not self._check_template_visible(source, user_ctx):
                return jsonify({'error': '无权限复制该模板'}), 403

            data = request.get_json(silent=True) or {}
            target_name = (data.get('target_name') or '').strip()
            if not target_name:
                return jsonify({'error': 'target_name 不能为空'}), 400
            visibility = (data.get('visibility', 'private') or 'private').strip().lower()
            if visibility not in ('shared', 'private'):
                return jsonify({'error': 'visibility 仅支持 shared 或 private'}), 400
            description = data.get('description', '')

            try:
                success, message = self._with_template_write_lock(
                    [name, target_name],
                    lambda: self.template_manager.copy_template(
                        source_name=name,
                        target_name=target_name,
                        created_by=user_ctx.get('username', 'system'),
                        owner_id=user_ctx.get('user_id', ''),
                        owner_name=user_ctx.get('username', ''),
                        visibility=visibility,
                        description=description
                    )
                )
            except BlockingIOError as e:
                return jsonify({'error': str(e)}), 409

            if success:
                return jsonify({
                    'message': message,
                    'source_name': name,
                    'target_name': target_name,
                    'visibility': visibility
                }), 201
            return jsonify({'error': message}), 400

        @self.app.route('/api/agent/templates/download/batch', methods=['POST'])
        def download_templates_batch():
            """批量下载模板"""
            try:
                user_ctx = self._get_request_user_context()
                data = request.get_json()
                if not data:
                    return jsonify({'error': '请求体必须为JSON'}), 400

                template_names = data.get('templates', [])
                format_type = data.get('format', 'original')
                include_all = data.get('include_all', True)

                if not template_names:
                    return jsonify({'error': '未指定要下载的模板'}), 400

                # 检查模板是否存在
                missing_templates = []
                for name in template_names:
                    template = self.template_manager.get_template(name)
                    if not template or not self._check_template_visible(template, user_ctx):
                        missing_templates.append(name)

                if missing_templates:
                    return jsonify({
                        'error': '以下模板不存在',
                        'missing_templates': missing_templates
                    }), 400

                # 如果只有一个模板，直接下载
                if len(template_names) == 1:
                    return redirect(
                        f'/api/templates/{template_names[0]}/download?format={format_type}&include_all={include_all}')

                # 多个模板，创建ZIP包
                zip_buffer = io.BytesIO()

                with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                    for name in template_names:
                        template = self.template_manager.get_template(name)
                        template_dir = self.template_manager.templates_root / name

                        if template_dir.exists():
                            for file_path in template_dir.rglob('*'):
                                if file_path.is_file():
                                    rel_path = file_path.relative_to(self.template_manager.templates_root)
                                    zip_file.write(file_path, rel_path)

                zip_content = zip_buffer.getvalue()
                zip_buffer.close()

                # 设置响应头
                response_headers = {
                    'Content-Type': 'application/zip',
                    'Content-Disposition': f'attachment; filename="templates_batch_{datetime.now().strftime("%Y%m%d_%H%M%S")}.zip"',
                    'X-Templates-Count': str(len(template_names)),
                    'X-Templates-List': ','.join(template_names)
                }

                response = self.app.response_class(
                    response=zip_content,
                    status=200,
                    headers=response_headers
                )

                self.logger.info(f"批量下载模板成功: {len(template_names)} 个模板")

                return response

            except Exception as e:
                self.logger.error(f"批量下载模板失败: {str(e)}")
                return jsonify({'error': str(e)}), 500

        # ===================== 新增：模板文件管理API =====================

        @self.app.route('/api/agent/templates/<name>/files', methods=['GET'])
        def list_template_files(name):
            """列出模板目录下的所有文件和目录"""
            user_ctx = self._get_request_user_context()
            template = self.template_manager.get_template(name)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            if not self._check_template_visible(template, user_ctx):
                return jsonify({'error': '无权限访问该模板'}), 403
            path = request.args.get('path', '')

            success, result = self.template_manager.list_template_files(name, path)

            if success:
                return jsonify({
                    'template_name': name,
                    'path': path,
                    'files': result,
                    'status': 'success'
                })
            else:
                return jsonify({'error': result}), 404

        @self.app.route('/api/agent/templates/<name>/files/content', methods=['GET'])
        def get_template_file_content(name):
            """获取模板目录下指定文件的内容"""
            user_ctx = self._get_request_user_context()
            template = self.template_manager.get_template(name)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            if not self._check_template_visible(template, user_ctx):
                return jsonify({'error': '无权限访问该模板'}), 403
            file_path = request.args.get('path', '')
            encoding = request.args.get('encoding', 'utf-8')
            preview = request.args.get('preview', 'false').lower() == 'true'
            max_size = int(request.args.get('max_size', 1024 * 1024))  # 默认1MB

            if not file_path:
                return jsonify({'error': '文件路径不能为空'}), 400

            success, content, content_type, file_info = self.template_manager.get_template_file_by_path(
                name, file_path, encoding
            )

            if not success:
                return jsonify({'error': content}), 404

            # 如果是预览模式且文件较大，进行截断
            if preview and isinstance(content, str) and len(content) > max_size:
                content = content[:max_size] + f"\n\n... (文件过大，已截断，完整大小: {file_info['size']} 字节)"
                file_info['truncated'] = True
                file_info['original_size'] = file_info['size']
                file_info['preview_size'] = len(content)
            elif preview and isinstance(content, bytes) and len(content) > max_size:
                # 对于二进制文件，只返回基本信息
                content = None
                file_info['binary_preview'] = True
                file_info['original_size'] = file_info['size']

            response_data = {
                'template_name': name,
                'file_info': file_info,
                'content_type': content_type,
                'is_text': file_info.get('is_text', True),
                'status': 'success'
            }

            # 根据内容类型返回不同格式
            if content is not None:
                if isinstance(content, str):
                    response_data['content'] = content
                    response_data['encoding'] = encoding
                else:
                    # 二进制内容进行base64编码
                    response_data['content'] = base64.b64encode(content).decode('ascii')
                    response_data['encoding'] = 'base64'
            else:
                response_data['content'] = None

            return jsonify(response_data)

        @self.app.route('/api/agent/templates/<name>/files/content', methods=['PUT'])
        def update_template_file_content(name):
            """更新模板目录下指定文件的内容"""
            try:
                user_ctx = self._get_request_user_context()
                template = self.template_manager.get_template(name)
                if not template:
                    return jsonify({'error': '模板不存在'}), 404
                if not self._check_template_manageable(template, user_ctx):
                    return jsonify({'error': '无权限更新该模板，仅拥有者可更新'}), 403
                data = request.get_json()
                if not data:
                    return jsonify({'error': '请求体必须为JSON'}), 400

                file_path = data.get('path', '')
                content = data.get('content', '')
                encoding = data.get('encoding', 'utf-8')

                if not file_path:
                    return jsonify({'error': '文件路径不能为空'}), 400

                if content is None:
                    return jsonify({'error': '文件内容不能为空'}), 400

                # 处理内容编码
                actual_content = content
                content_encoding = data.get('content_encoding', '')

                if content_encoding == 'base64':
                    try:
                        actual_content = base64.b64decode(content)
                    except Exception as e:
                        return jsonify({'error': f'Base64解码失败: {str(e)}'}), 400

                # 获取当前用户
                updated_by = user_ctx.get('username', 'system')

                try:
                    success, message, update_info = self._with_template_write_lock(
                        [name],
                        lambda: self.template_manager.update_template_file(
                            name, file_path, actual_content, encoding, updated_by
                        )
                    )
                except BlockingIOError as e:
                    return jsonify({'error': str(e)}), 409

                if success:
                    # 获取更新后的文件信息
                    file_success, file_content, file_content_type, file_info = self.template_manager.get_template_file_by_path(
                        name, file_path, encoding
                    )

                    response_data = {
                        'message': message,
                        'update_info': update_info,
                        'status': 'success'
                    }

                    if file_success:
                        response_data['file_info'] = file_info

                    return jsonify(response_data)
                else:
                    return jsonify({'error': message}), 400

            except Exception as e:
                self.logger.error(f"更新模板文件失败: {str(e)}", exc_info=True)
                return jsonify({'error': f'更新失败: {str(e)}'}), 500

        @self.app.route('/api/agent/templates/<name>/files/download', methods=['GET'])
        def download_template_file(name):
            """下载模板目录下的单个文件"""
            user_ctx = self._get_request_user_context()
            template = self.template_manager.get_template(name)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            if not self._check_template_visible(template, user_ctx):
                return jsonify({'error': '无权限访问该模板'}), 403
            file_path = request.args.get('path', '')

            if not file_path:
                return jsonify({'error': '文件路径不能为空'}), 400

            success, content, content_type, file_info = self.template_manager.get_template_file_by_path(
                name, file_path, 'utf-8'
            )

            if not success:
                return jsonify({'error': content}), 404

            # 构建响应
            if isinstance(content, str):
                # 文本文件
                response = self.app.response_class(
                    response=content,
                    status=200,
                    mimetype=content_type,
                    headers={
                        'Content-Disposition': f'attachment; filename="{file_info["name"]}"',
                        'X-File-Path': file_path,
                        'X-Template-Name': name
                    }
                )
            else:
                # 二进制文件
                response = self.app.response_class(
                    response=content,
                    status=200,
                    mimetype=content_type,
                    headers={
                        'Content-Disposition': f'attachment; filename="{file_info["name"]}"',
                        'X-File-Path': file_path,
                        'X-Template-Name': name,
                        'X-File-Size': str(file_info['size'])
                    }
                )

            return response

        @self.app.route('/api/agent/templates/<name>/files/upload', methods=['POST'])
        def upload_template_file(name):
            """上传文件到模板目录"""
            user_ctx = self._get_request_user_context()
            template = self.template_manager.get_template(name)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            if not self._check_template_manageable(template, user_ctx):
                return jsonify({'error': '无权限更新该模板，仅拥有者可更新'}), 403
            if 'file' not in request.files:
                return jsonify({'error': '未找到文件'}), 400

            file = request.files['file']
            target_path = request.form.get('path', '')
            overwrite = request.form.get('overwrite', 'false').lower() == 'true'

            if not file.filename:
                return jsonify({'error': '文件名不能为空'}), 400

            # 如果没有指定路径，使用文件名
            if not target_path:
                target_path = file.filename

            # 获取当前用户
            updated_by = user_ctx.get('username', 'system')

            # 读取文件内容
            file_content = file.read()

            # 检查文件编码（尝试作为文本文件处理）
            try:
                # 尝试解码为UTF-8
                decoded_content = file_content.decode('utf-8')
                # 如果是文本文件，使用字符串
                content = decoded_content
                encoding = 'utf-8'
            except UnicodeDecodeError:
                # 如果是二进制文件，使用字节
                content = file_content
                encoding = 'binary'

            try:
                success, message, update_info = self._with_template_write_lock(
                    [name],
                    lambda: self.template_manager.update_template_file(
                        name, target_path, content, encoding, updated_by
                    )
                )
            except BlockingIOError as e:
                return jsonify({'error': str(e)}), 409

            if not success and not overwrite:
                # 检查是否是文件已存在的错误
                if "already exists" in message.lower() or "文件已存在" in message:
                    return jsonify({
                        'error': '文件已存在',
                        'message': message,
                        'suggestion': '使用 overwrite=true 参数覆盖文件'
                    }), 409
                else:
                    return jsonify({'error': message}), 400

            # 如果是覆盖模式，强制更新
            if not success and overwrite:
                # 这里可以添加强制更新的逻辑
                # 目前我们假设update_template_file已经处理了覆盖
                pass

            if success:
                return jsonify({
                    'message': message,
                    'update_info': update_info,
                    'filename': file.filename,
                    'path': target_path,
                    'size': len(file_content),
                    'status': 'success'
                }), 201
            else:
                return jsonify({'error': message}), 400

        @self.app.route('/api/agent/templates/<name>/files', methods=['DELETE'])
        def delete_template_file(name):
            """删除模板目录下的指定文件"""
            try:
                user_ctx = self._get_request_user_context()
                template = self.template_manager.get_template(name)
                if not template:
                    return jsonify({'error': '模板不存在'}), 404
                if not self._check_template_manageable(template, user_ctx):
                    return jsonify({'error': '无权限删除模板文件，仅拥有者可删除'}), 403
                data = request.get_json()
                if not data:
                    return jsonify({'error': '请求体必须为JSON'}), 400

                file_path = data.get('path', '')
                if not file_path:
                    return jsonify({'error': '文件路径不能为空'}), 400

                # 获取当前用户
                deleted_by = user_ctx.get('username', 'system')

                try:
                    success, message, delete_info = self._with_template_write_lock(
                        [name],
                        lambda: self.template_manager.delete_template_file(
                            name, file_path, deleted_by
                        )
                    )
                except BlockingIOError as e:
                    return jsonify({'error': str(e)}), 409

                if success:
                    return jsonify({
                        'message': message,
                        'delete_info': delete_info,
                        'status': 'success'
                    })
                else:
                    return jsonify({'error': message}), 400

            except Exception as e:
                self.logger.error(f"删除模板文件失败: {str(e)}", exc_info=True)
                return jsonify({'error': f'删除失败: {str(e)}'}), 500

        @self.app.route('/api/agent/templates/<name>/directories', methods=['DELETE'])
        def delete_template_directory(name):
            """删除模板目录下的指定目录"""
            try:
                user_ctx = self._get_request_user_context()
                template = self.template_manager.get_template(name)
                if not template:
                    return jsonify({'error': '模板不存在'}), 404
                if not self._check_template_manageable(template, user_ctx):
                    return jsonify({'error': '无权限删除模板目录，仅拥有者可删除'}), 403
                data = request.get_json()
                if not data:
                    return jsonify({'error': '请求体必须为JSON'}), 400

                dir_path = data.get('path', '')
                force = data.get('force', False)

                if len(dir_path) == 0:
                    return jsonify({'error': '目录路径不能为空'}), 400

                # 获取当前用户
                deleted_by = user_ctx.get('username', 'system')

                try:
                    success, message, delete_info = self._with_template_write_lock(
                        [name],
                        lambda: self.template_manager.delete_template_directory(
                            name, dir_path, deleted_by, force
                        )
                    )
                except BlockingIOError as e:
                    return jsonify({'error': str(e)}), 409

                if success:
                    return jsonify({
                        'message': message,
                        'delete_info': delete_info,
                        'status': 'success'
                    })
                else:
                    return jsonify({'error': message}), 400

            except Exception as e:
                self.logger.error(f"删除模板目录失败: {str(e)}", exc_info=True)
                return jsonify({'error': f'删除失败: {str(e)}'}), 500

        @self.app.route('/api/agent/templates/<name>/parsed', methods=['GET'])
        def get_parsed_compose(name):
            """
            获取模板的解析数据（专用接口）

            返回 docker-compose 结构化信息
            """
            try:
                user_ctx = self._get_request_user_context()
                template = self.template_manager.get_template(name)
                if not template:
                    return jsonify({'error': f'模板 {name} 不存在'}), 404
                if not self._check_template_visible(template, user_ctx):
                    return jsonify({'error': '无权限访问该模板'}), 403

                metadata = template.get('metadata', {})
                if isinstance(metadata, str):
                    metadata = json.loads(metadata)

                def reload_template_metadata() -> None:
                    nonlocal template, metadata
                    template = self.template_manager.get_template(name)
                    metadata = template.get('metadata', {})
                    if isinstance(metadata, str):
                        metadata = json.loads(metadata)

                def parse_under_lock():
                    try:
                        return self._with_template_write_lock(
                            [name],
                            lambda: self.template_manager.parse_template_compose(name)
                        )
                    except BlockingIOError as e:
                        return None, str(e)

                parsed_compose = metadata.get('parsed_compose')

                # 检查是否过期；如果已过期则自动重新解析，而不是继续返回旧缓存。
                stale_check_ok, is_stale, _ = self.template_manager.check_parse_staleness(name)
                needs_parse = not parsed_compose or (stale_check_ok and is_stale)

                if needs_parse:
                    success, msg = parse_under_lock()
                    if success is None:
                        return jsonify({'error': msg}), 409
                    if success:
                        reload_template_metadata()
                        parsed_compose = metadata.get('parsed_compose')
                        stale_check_ok, is_stale, _ = self.template_manager.check_parse_staleness(name)
                    else:
                        reload_template_metadata()
                        return jsonify({
                            'error': '解析失败',
                            'details': metadata.get('parse_error', msg),
                            'parse_status': 'error'
                        }), 400

                return jsonify({
                    'template_name': name,
                    'parsed_compose': parsed_compose,
                    'parse_status': 'stale' if (stale_check_ok and is_stale) else metadata.get('parse_status', 'success'),
                    'parsed_at': metadata.get('parsed_at'),
                    'parse_error': metadata.get('parse_error'),
                    'is_stale': is_stale if stale_check_ok else None
                })

            except Exception as e:
                self.logger.error(f"获取解析数据失败: {str(e)}")
                return jsonify({'error': f'获取失败: {str(e)}'}), 500

        @self.app.route('/api/agent/templates/<name>/parse', methods=['POST'])
        def parse_template(name):
            """
            手动触发模板解析

            适用于：
            1. 解析失败后重试
            2. 文件手动修改后刷新
            3. 强制重新解析
            """
            try:
                user_ctx = self._get_request_user_context()
                # 检查模板是否存在
                template = self.template_manager.get_template(name)
                if not template:
                    return jsonify({'error': f'模板 {name} 不存在'}), 404
                if not self._check_template_manageable(template, user_ctx):
                    return jsonify({'error': '无权限重新解析该模板，仅拥有者可操作'}), 403

                # 执行解析
                try:
                    success, message = self._with_template_write_lock(
                        [name],
                        lambda: self.template_manager.parse_template_compose(name)
                    )
                except BlockingIOError as e:
                    return jsonify({'error': str(e)}), 409

                if success:
                    # 返回更新后的模板信息
                    template = self.template_manager.get_template(name)
                    metadata = template.get('metadata', {})
                    if isinstance(metadata, str):
                        metadata = json.loads(metadata)

                    return jsonify({
                        'message': message,
                        'template_name': name,
                        'parsed_compose': metadata.get('parsed_compose'),
                        'parse_status': metadata.get('parse_status'),
                        'parsed_at': metadata.get('parsed_at'),
                        'status': 'success'
                    })
                else:
                    return jsonify({
                        'error': message,
                        'template_name': name,
                        'status': 'failed'
                    }), 400

            except Exception as e:
                self.logger.error(f"解析模板 {name} 失败: {str(e)}")
                return jsonify({'error': f'解析失败: {str(e)}'}), 500

        # ===================== 模板管理ID路由（唯一引用） =====================

        @self.app.route('/api/agent/templates/id/<int:template_id>/yaml', methods=['GET'])
        def get_template_yaml_by_id(template_id):
            template = _resolve_template_by_id(template_id)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            return get_template_yaml(template['name'])

        @self.app.route('/api/agent/templates/id/<int:template_id>/yaml', methods=['PUT'])
        def update_template_yaml_by_id(template_id):
            template = _resolve_template_by_id(template_id)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            return update_template_yaml(template['name'])

        @self.app.route('/api/agent/templates/id/<int:template_id>/download', methods=['GET'])
        def download_template_by_id(template_id):
            template = _resolve_template_by_id(template_id)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            return download_template(template['name'])

        @self.app.route('/api/agent/templates/id/<int:template_id>/file', methods=['GET'])
        def get_template_file_by_id(template_id):
            template = _resolve_template_by_id(template_id)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            return get_template_file(template['name'])

        @self.app.route('/api/agent/templates/id/<int:template_id>/content', methods=['GET'])
        def get_template_content_by_id(template_id):
            template = _resolve_template_by_id(template_id)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            return get_template_content(template['name'])

        @self.app.route('/api/agent/templates/id/<int:template_id>/info', methods=['GET'])
        def get_template_info_by_id(template_id):
            template = _resolve_template_by_id(template_id)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            return get_template_info(template['name'])

        @self.app.route('/api/agent/templates/id/<int:template_id>', methods=['DELETE'])
        def delete_template_by_id(template_id):
            template = _resolve_template_by_id(template_id)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            return delete_template(template['name'])

        @self.app.route('/api/agent/templates/id/<int:template_id>/copy', methods=['POST'])
        def copy_template_by_id(template_id):
            template = _resolve_template_by_id(template_id)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            return copy_template(template['name'])

        @self.app.route('/api/agent/templates/id/<int:template_id>/files', methods=['GET'])
        def list_template_files_by_id(template_id):
            template = _resolve_template_by_id(template_id)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            return list_template_files(template['name'])

        @self.app.route('/api/agent/templates/id/<int:template_id>/files/content', methods=['GET'])
        def get_template_file_content_by_id(template_id):
            template = _resolve_template_by_id(template_id)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            return get_template_file_content(template['name'])

        @self.app.route('/api/agent/templates/id/<int:template_id>/files/content', methods=['PUT'])
        def update_template_file_content_by_id(template_id):
            template = _resolve_template_by_id(template_id)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            return update_template_file_content(template['name'])

        @self.app.route('/api/agent/templates/id/<int:template_id>/files/download', methods=['GET'])
        def download_template_file_by_id(template_id):
            template = _resolve_template_by_id(template_id)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            return download_template_file(template['name'])

        @self.app.route('/api/agent/templates/id/<int:template_id>/files/upload', methods=['POST'])
        def upload_template_file_by_id(template_id):
            template = _resolve_template_by_id(template_id)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            return upload_template_file(template['name'])

        @self.app.route('/api/agent/templates/id/<int:template_id>/files', methods=['DELETE'])
        def delete_template_file_by_id(template_id):
            template = _resolve_template_by_id(template_id)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            return delete_template_file(template['name'])

        @self.app.route('/api/agent/templates/id/<int:template_id>/directories', methods=['DELETE'])
        def delete_template_directory_by_id(template_id):
            template = _resolve_template_by_id(template_id)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            return delete_template_directory(template['name'])

        @self.app.route('/api/agent/templates/id/<int:template_id>/parsed', methods=['GET'])
        def get_parsed_compose_by_id(template_id):
            template = _resolve_template_by_id(template_id)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            return get_parsed_compose(template['name'])

        @self.app.route('/api/agent/templates/id/<int:template_id>/parse', methods=['POST'])
        def parse_template_by_id(template_id):
            template = _resolve_template_by_id(template_id)
            if not template:
                return jsonify({'error': '模板不存在'}), 404
            return parse_template(template['name'])

    def _run_refresh_cycle(
        self,
        include_service_sync: bool = False,
        include_helper_health_sync: bool = False,
    ) -> Tuple[bool, str]:
        """执行一次leader-only刷新周期。"""
        try:
            lock_timeout = int(self.config.get('leader_lock_timeout_sec', 90))
            with self.redis_manager.get_lock(self.refresh_leader_lock_key, timeout=lock_timeout) as lock:
                if not lock.is_acquired():
                    msg = f"POD {self.config.get('pod_id')} 未获得刷新领导锁，跳过本轮"
                    self.logger.debug(msg)
                    return False, msg

                self.agent_manager.refresh_agents(use_distributed_lock=False)
                if include_service_sync:
                    self._sync_all_agent_services()
                if include_helper_health_sync:
                    self._refresh_ai_helper_health_snapshots()
                return True, "Agent列表刷新完成"
        except Exception as e:
            self.logger.error(f"执行刷新周期失败: {str(e)}")
            return False, f"刷新失败: {str(e)}"

    def _refresh_loop(self):
        """后台刷新循环"""
        service_sync_interval = int(self.config.get('service_sync_interval', self.config.get('refresh_interval', 30)))
        helper_health_sync_interval = int(
            self.config.get('helper_health_refresh_interval_sec', self.config.get('refresh_interval', 30))
        )
        service_sync_elapsed = service_sync_interval
        helper_health_sync_elapsed = helper_health_sync_interval
        while not self.should_stop:
            try:
                include_service_sync = service_sync_elapsed >= service_sync_interval
                include_helper_health_sync = helper_health_sync_elapsed >= helper_health_sync_interval
                executed, _ = self._run_refresh_cycle(
                    include_service_sync=include_service_sync,
                    include_helper_health_sync=include_helper_health_sync,
                )
                if executed and include_service_sync:
                    service_sync_elapsed = 0
                if executed and include_helper_health_sync:
                    helper_health_sync_elapsed = 0
            except Exception as e:
                self.logger.error(f"后台刷新循环失败: {str(e)}")

            # 等待下一次刷新
            for _ in range(self.config['refresh_interval']):
                if self.should_stop:
                    break
                time.sleep(1)
                service_sync_elapsed += 1
                helper_health_sync_elapsed += 1

    def start_refresh_thread(self):
        """启动后台刷新线程"""
        if not self.config.get('enable_background_refresh', True):
            self.logger.info("后台刷新线程已禁用")
            return
        self.should_stop = False
        self.refresh_thread = threading.Thread(target=self._refresh_loop, daemon=True)
        self.refresh_thread.start()
        self.logger.info("后台刷新线程已启动")

    def stop_refresh_thread(self):
        """停止后台刷新线程"""
        self.should_stop = True
        if self.refresh_thread:
            self.refresh_thread.join(timeout=5)
            self.logger.info("后台刷新线程已停止")

    def shutdown(self):
        """停止后台组件。"""
        self.menu_registry.stop()
        self.stop_refresh_thread()
        self.task_manager.stop_workers()

    def run(self):
        """运行服务器"""
        # 启动后台刷新线程
        self.start_refresh_thread()
        self.task_manager.start_workers()
        self.menu_registry.start()

        # 运行Flask应用
        self.logger.info(f"启动WEB API服务器，监听 {self.config['host']}:{self.config['port']}")
        if not self.config.get('enable_platform_ws_tunnel_server', False):
            self.logger.info("使用线程化Flask/Werkzeug服务器提供HTTP API；平台内置ws-tunnel专用服务默认关闭")
            self.app.run(
                host=self.config['host'],
                port=self.config['port'],
                debug=self.config['debug'],
                use_reloader=False,
                threaded=True
            )
            return

        try:
            from gevent import pywsgi
            from geventwebsocket.handler import WebSocketHandler

            server_ref = self

            class AgentExecWsTunnelApplication(WebSocketApplication):
                _path_re = re.compile(
                    r'^/api/agent/agent/(?P<agent_key>[^/]+)/services/(?P<service_name>[^/]+)/exec/ws-tunnel$'
                )

                def __init__(self, ws):
                    super().__init__(ws)
                    self.server = server_ref
                    self.upstream = None
                    self.upstream_thread = None
                    self.stop_event = threading.Event()
                    self.close_lock = threading.Lock()
                    self.tunnel_tag = 'agent=-, service=-'

                def _close_both(self):
                    with self.close_lock:
                        try:
                            if self.upstream is not None:
                                self.upstream.close()
                        except Exception:
                            pass
                        try:
                            if self.ws is not None:
                                self.ws.close()
                        except Exception:
                            pass

                def on_open(self):
                    environ = self.ws.environ or {}
                    path = str(environ.get('PATH_INFO') or '')
                    match = self._path_re.match(path)
                    if not match:
                        raise RuntimeError(f'invalid ws tunnel path: {path}')

                    agent_key = match.group('agent_key')
                    service_name = match.group('service_name')
                    query = parse_qs(str(environ.get('QUERY_STRING') or ''), keep_blank_values=True)
                    project_id = (query.get('project_id') or [''])[0]
                    container_name = (query.get('container') or [''])[0]
                    shell = (query.get('shell') or ['/bin/sh'])[0]
                    mode = (query.get('mode') or ['shell'])[0]
                    user = (query.get('user') or [''])[0]

                    _, upstream_ws_url, tunnel_tag = self.server._prepare_agent_exec_ws_tunnel(
                        agent_key=agent_key,
                        service_name=service_name,
                        project_id=project_id,
                        container_name=container_name,
                        shell=shell,
                        mode=mode,
                        user=user
                    )
                    self.tunnel_tag = tunnel_tag
                    self.server.logger.info(f"终端中转WS打开: {self.tunnel_tag}, upstream={upstream_ws_url}")

                    self.upstream = ws_client.create_connection(
                        upstream_ws_url,
                        timeout=15,
                        enable_multithread=True
                    )

                    def _pump_upstream():
                        try:
                            while not self.stop_event.is_set():
                                data = self.upstream.recv()
                                if data is None:
                                    break
                                if data == '':
                                    continue
                                self.ws.send(data)
                        except Exception as e:
                            if not self.stop_event.is_set():
                                self.server.logger.info(f"终端中转WS上行关闭: {self.tunnel_tag}, err={e!r}")
                        finally:
                            self.stop_event.set()
                            self._close_both()

                    self.upstream_thread = threading.Thread(target=_pump_upstream, daemon=True)
                    self.upstream_thread.start()

                def on_message(self, message, *args, **kwargs):
                    if self.stop_event.is_set():
                        return
                    if message is None or message == '':
                        return
                    try:
                        self.upstream.send(message)
                    except Exception as e:
                        self.server.logger.info(f"终端中转WS下行关闭: {self.tunnel_tag}, err={e!r}")
                        self.stop_event.set()
                        self._close_both()
                        raise

                def on_close(self, *args, **kwargs):
                    self.server.logger.info(f"终端中转WS关闭: {self.tunnel_tag}")
                    self.stop_event.set()
                    self._close_both()

            application = Resource(OrderedDict([
                (r'^/api/agent/agent/[^/]+/services/[^/]+/exec/ws-tunnel$', AgentExecWsTunnelApplication),
                (r'^/.*', self.app),
            ]))

            server = pywsgi.WSGIServer(
                (self.config['host'], self.config['port']),
                application,
                handler_class=WebSocketHandler
            )
            server.serve_forever()
        except Exception as e:
            self.logger.warning(f"gevent WebSocket server不可用，回退Flask开发服务器: {e}")
            self.app.run(
                host=self.config['host'],
                port=self.config['port'],
                debug=self.config['debug'],
                use_reloader=False,
                threaded=True
            )


def adjust_timeout_config(config: Dict) -> Dict:
    """调整超时配置以确保合理性"""
    default_timeouts = {
        'default': (10, 30),
        'health_check': (5, 10),
        'deploy_create': (10, 7200),
        'deploy_start': (10, 7200),
        'deploy_stop': (10, 7200),
        'deploy_delete': (10, 7200),
        'undeploy': (10, 7200),
        'file_upload': (10, 7200),
        'deploy_start_grace_sec': 7200,
        'deploy_start_poll_interval_sec': 15,
        'stream': (10, 3600),
        'proxy': (10, 300),
    }

    # 获取用户配置的超时设置
    user_timeouts = config.get('agent_api_timeouts', {})

    # 合并配置，用户配置优先
    final_timeouts = default_timeouts.copy()
    for key, value in user_timeouts.items():
        if isinstance(value, (list, tuple)) and len(value) == 2:
            final_timeouts[key] = tuple(value)
        elif isinstance(value, (int, float)):
            final_timeouts[key] = (10, int(value))

    config['agent_api_timeouts'] = final_timeouts
    return config
