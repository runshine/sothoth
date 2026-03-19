import logging
import os
import threading
import time
import base64
import hashlib
import uuid
import requests
from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
import io
import zipfile

from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime
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

from flask import send_file, redirect, Response
# ===================== Flask应用 =====================

class WebAPIServer:
    """WEB API服务器（支持多种压缩格式）"""

    def __init__(self, config: Dict):
        self.config = config
        self.logger = self._setup_logger()

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
            config.get('redis_enabled', True)
        )

        # 5. 初始化数据库管理器
        self.db_manager = DatabaseManager(config['database'])

        # 7. 初始化模板管理器（传递支持的格式）
        supported_formats = config.get('supported_formats', SUPPORTED_FORMATS)
        self.template_manager = EnhancedTemplateManager(
            config['templates_root'],
            self.db_manager,
            supported_formats
        )

        # 8. 初始化Agent管理器（传递超时配置）
        agent_api_timeouts = config.get('agent_api_timeouts', {
            'default': (10, 30),
            'health_check': (5, 10),
            'deploy_create': (10, 60),
            'deploy_start': (10, 900),
            'deploy_stop': (10, 120),
            'deploy_delete': (10, 60),
            'undeploy': (10, 180),
            'file_upload': (10, 600),
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
            config.get('daemon_auth_token') or config.get('agent_auth_token', 'default_token_change_me')
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

        # 10. 初始化代理管理器（新增，传递超时配置）
        self.proxy_manager = EnhancedProxyManager(self.agent_manager, agent_api_timeouts)
        # 11188 守护进程 API 读接口快速失败超时（秒）
        self.daemon_read_timeout_sec = int(config.get('daemon_read_timeout_sec', 8))
        self.agent_ttyd_port = int(config.get('agent_ttyd_port', 11198))
        self.ttyd_probe_timeout_sec = int(config.get('ttyd_probe_timeout_sec', 3))
        self.k8s_service_url = (config.get('k8s_service_url') or '').rstrip('/')
        self.k8s_service_timeout_sec = int(config.get('k8s_service_timeout_sec', 15))

        # 11. 注册路由
        self._register_routes()

        # 12. 后台刷新线程
        self.refresh_thread = None
        self.should_stop = False

        self.logger.info(f"当前POD ID: {config['pod_id']}")
        self.logger.info(f"使用数据库: {config['database'].get('type', 'sqlite').upper()}")
        self.logger.info(f"Redis状态: {'已启用' if self.redis_manager.enabled else '已禁用'}")
        self.logger.info(f"支持的压缩格式: {', '.join(supported_formats)}")
        self.logger.info(f"Agent API超时配置: {agent_api_timeouts}")
        self.logger.info(f"Daemon API快速失败超时: {self.daemon_read_timeout_sec}s")
        self.logger.info(f"Agent TTYD端口: {self.agent_ttyd_port}, 探测超时: {self.ttyd_probe_timeout_sec}s")
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

        # 检查Redis连接
        redis_success, redis_message = results.get('redis', (False, 'Redis检查失败'))
        if redis_success:
            self.logger.info(f"✓ {redis_message}")
        else:
            self.logger.warning(f"⚠ {redis_message}，Redis功能将禁用")

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

    def _normalize_agent_service_payload(self, agent: Any, service: Dict[str, Any], source: str = 'pull') -> Dict[str, Any]:
        service_name = str(service.get('name') or service.get('service_name') or service.get('id') or '').strip()
        if not service_name:
            return {}

        project_id = getattr(agent, 'project_id', '') or ''
        agent_key = getattr(agent, 'key', '') or ''
        service_uid_raw = f"{project_id}:{agent_key}:{service_name}"
        service_uid = hashlib.sha1(service_uid_raw.encode('utf-8')).hexdigest()

        ports = self._normalize_service_ports(service.get('ports'))
        image = service.get('image') or ''
        status = service.get('status') or service.get('state') or 'unknown'

        return {
            'service_uid': service_uid,
            'project_id': project_id,
            'agent_key': agent_key,
            'agent_hostname': getattr(agent, 'hostname', '') or '',
            'agent_ip': getattr(agent, 'ip_address', '') or '',
            'service_name': service_name,
            'image': str(image),
            'status': str(status),
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

        # 标记本次快照里不存在的服务为 stale
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

        if self.db_manager.db_type == 'mysql':
            self.db_manager.execute_query(f'''
                INSERT INTO {table_name}
                (service_uid, project_id, agent_key, agent_hostname, agent_ip, service_name,
                 image, status, ports_json, raw_json, source, is_stale, first_seen_at, last_seen_at, pod_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 0, NOW(), NOW(), %s)
                ON DUPLICATE KEY UPDATE
                    project_id = VALUES(project_id),
                    agent_hostname = VALUES(agent_hostname),
                    agent_ip = VALUES(agent_ip),
                    image = VALUES(image),
                    status = VALUES(status),
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
                payload['image'], payload['status'], payload['ports_json'], payload['raw_json'],
                payload['source'], payload['pod_id']
            ))
        else:
            self.db_manager.execute_query(f'''
                INSERT INTO {table_name}
                (service_uid, project_id, agent_key, agent_hostname, agent_ip, service_name,
                 image, status, ports_json, raw_json, source, is_stale, first_seen_at, last_seen_at, updated_at, pod_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
                ON CONFLICT(service_uid) DO UPDATE SET
                    project_id=excluded.project_id,
                    agent_hostname=excluded.agent_hostname,
                    agent_ip=excluded.agent_ip,
                    image=excluded.image,
                    status=excluded.status,
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
                payload['image'], payload['status'], payload['ports_json'], payload['raw_json'],
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
                agent.full_name = f"{agent.project_id}-{agent.hostname}-{agent.ip_address}"
            elif not agent.full_name:
                agent.full_name = agent_key

            agent.status = 'online'
            agent.last_seen = datetime.now()
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
            full_name = f"{project_id}-{hostname}-{ip_address}" if ip_address else f"{project_id}-{hostname}"
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

    def _sync_all_agent_services(self):
        """从所有在线Agent拉取服务清单并写入聚合表。"""
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

            synced_agents = 0
            synced_services = 0
            stale_agents = 0

            for agent_data in agents:
                if agent_data.get('status') != 'online':
                    if agent_data.get('key'):
                        self._mark_agent_services_stale(agent_data.get('key'))
                    continue
                agent = self.agent_manager.get_agent(agent_data.get('key'))
                if not agent:
                    continue

                sync_result = self._sync_single_agent_services(agent)
                if not sync_result.get('ok'):
                    stale_agents += 1
                    continue
                synced_agents += 1
                synced_services += int(sync_result.get('upserted', 0))
                self.logger.debug(
                    f"服务聚合同步: agent={agent.key}, seen={sync_result.get('seen', 0)}, upserted={sync_result.get('upserted', 0)}"
                )

            self.logger.info(
                f"服务聚合同步完成: agents={synced_agents}, services={synced_services}, stale_agents={stale_agents}"
            )
        except Exception as e:
            self.logger.error(f"服务聚合同步失败: {e}", exc_info=True)

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
            agent.key, 'GET', '/api/services', timeout_type='proxy'
        )
        if status_code != 200:
            self._mark_agent_services_stale(agent.key)
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
        if not username and header_username:
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

    def _check_deploy_duplicate(self, service_name: str, agent_key: str, project_id: str) -> Optional[Dict[str, Any]]:
        """统一部署防重检查：进行中的部署任务 + Agent已存在服务。"""
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
                'message': f'服务 {service_name} 在节点 {agent_key} 上已存在，禁止重复部署'
            }

        return None

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
            """健康检查端点"""
            db_ok = False
            try:
                db = self.db_manager.get_connection()
                db.fetch_one("SELECT 1")
                db_ok = True
            except:
                pass

            redis_ok = False
            if self.redis_manager.enabled:
                redis_ok = self.redis_manager.test_connection()

            nacos_ok = False
            try:
                result, _ = ConnectionChecker.check_nacos(
                    self.config['nacos_url'],
                    self.config.get('nacos_namespace', 'public')
                )
                nacos_ok = result
            except:
                pass

            # 计算总体状态
            status = 'healthy' if db_ok and nacos_ok else 'unhealthy'

            return jsonify({
                'status': status,
                'timestamp': datetime.now().isoformat(),
                'pod_id': self.config['pod_id'],
                'database_type': self.config['database'].get('type', 'sqlite'),
                'components': {
                    'database': 'connected' if db_ok else 'disconnected',
                    'redis': 'connected' if redis_ok else 'disconnected',
                    'nacos': 'connected' if nacos_ok else 'disconnected'
                },
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
            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 20))
            project_id = request.args.get('project_id')

            # project_id is required
            if not project_id:
                return jsonify({'error': 'project_id parameter is required'}), 400

            agents, total = self.agent_manager.list_agents(page, per_page, project_id)
            return jsonify({
                'agents': agents,
                'page': page,
                'per_page': per_page,
                'total': total,
                'project_id': project_id
            })

        @self.app.route('/api/agent/agents/refresh', methods=['POST'])
        def refresh_agents():
            self.agent_manager.refresh_agents()
            return jsonify({'message': 'Agent列表刷新完成'})

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
                offline_count, total_count = self.agent_manager.get_offline_agents_count(project_id)

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
                success, message, cleanup_info = self.agent_manager.cleanup_offline_agents(project_id)

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
            agent = self.agent_manager.get_agent(data['agent_key'])
            if not agent:
                return jsonify({'error': f"Agent {data['agent_key']} 不存在"}), 404
            if agent.project_id != project_id:
                return jsonify({'error': f"Agent {data['agent_key']} 不属于项目 {project_id}"}), 403

            duplicate = self._check_deploy_duplicate(
                data['service_name'], data['agent_key'], project_id
            )
            if duplicate:
                return jsonify({
                    'error': duplicate.get('message') or '重复部署被拒绝',
                    'code': 'DUPLICATE_DEPLOYMENT',
                    'details': duplicate
                }), 409

            task_id = self.task_manager.create_task(
                'deploy', data['service_name'], data['agent_key'],
                data['template_name'], data.get('extra_params'), project_id
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
                agent = self.agent_manager.get_agent(agent_key)
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

                try:
                    task_id = self.task_manager.create_task(
                        'deploy', service_name, agent_key, template_name, extra_params, project_id
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
            agent = self.agent_manager.get_agent(data['agent_key'])
            if not agent:
                return jsonify({'error': f"Agent {data['agent_key']} 不存在"}), 404
            if agent.project_id != project_id:
                return jsonify({'error': f"Agent {data['agent_key']} 不属于项目 {project_id}"}), 403

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
                        f"(service_name LIKE {like_placeholder} OR image LIKE {like_placeholder} OR agent_hostname LIKE {like_placeholder})"
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
                           service_name, image, status, ports_json, raw_json, source, is_stale,
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

                # 预加载模板映射：通过服务名推断模板（service_name 规则通常为 <normalized_template_name>-<agent_suffix>）
                template_table = self.db_manager.get_table_name('service_templates')
                template_rows = self.db_manager.fetch_all(
                    f"SELECT id, name FROM {template_table} ORDER BY id ASC",
                    tuple()
                ) or []

                def _normalize_template_name(name: str) -> str:
                    text = (name or '').strip().lower()
                    text = re.sub(r'[^a-z0-9-_]', '-', text)
                    text = re.sub(r'-+', '-', text).strip('-')
                    return text[:48]

                normalized_templates: List[Dict[str, Any]] = []
                for tpl in template_rows:
                    tpl_name = str(tpl.get('name') or '').strip()
                    if not tpl_name:
                        continue
                    normalized_templates.append({
                        'id': tpl.get('id'),
                        'name': tpl_name,
                        'normalized': _normalize_template_name(tpl_name)
                    })

                def _resolve_template(service_name: str) -> Dict[str, Any]:
                    svc = (service_name or '').strip().lower()
                    if not svc:
                        return {'template_id': None, 'template_name': ''}

                    # 优先最长前缀匹配，避免短模板名误匹配
                    best = None
                    best_len = -1
                    for tpl in normalized_templates:
                        prefix = tpl.get('normalized') or ''
                        if not prefix:
                            continue
                        if svc == prefix or svc.startswith(prefix + '-'):
                            if len(prefix) > best_len:
                                best = tpl
                                best_len = len(prefix)
                    if not best:
                        return {'template_id': None, 'template_name': ''}
                    return {
                        'template_id': best.get('id'),
                        'template_name': best.get('name') or ''
                    }

                items = []
                for row in rows:
                    ports = {}
                    raw_ports = row.get('ports_json')
                    if raw_ports:
                        if isinstance(raw_ports, str):
                            try:
                                ports = json.loads(raw_ports)
                            except Exception:
                                ports = {}
                        elif isinstance(raw_ports, dict):
                            ports = raw_ports

                    resolved_template = _resolve_template(str(row.get('service_name') or ''))

                    items.append({
                        'id': row.get('service_uid'),
                        'service_uid': row.get('service_uid'),
                        'project_id': row.get('project_id'),
                        'agent_key': row.get('agent_key'),
                        'agent_hostname': row.get('agent_hostname'),
                        'agent_ip': row.get('agent_ip'),
                        'name': row.get('service_name'),
                        'service_name': row.get('service_name'),
                        'image': row.get('image') or '',
                        'template_id': resolved_template.get('template_id'),
                        'template_name': resolved_template.get('template_name'),
                        'status': row.get('status') or 'unknown',
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
                    for item in agents:
                        if item.get('status') != 'online':
                            continue
                        if stale_only and item.get('key') not in stale_keys:
                            continue
                        agent = self.agent_manager.get_agent(item.get('key'))
                        if not agent:
                            continue
                        results.append(self._sync_single_agent_services(agent))
                    ok_count = len([r for r in results if r.get('ok')])
                    fail_count = len(results) - ok_count
                    self._record_service_sync_log(
                        scope='project',
                        status='ok' if fail_count == 0 else 'partial',
                        project_id=project_id,
                        stale_only=stale_only,
                        total=len(results),
                        ok_count=ok_count,
                        fail_count=fail_count,
                        message='project service sync completed',
                        details=results
                    )
                    return jsonify({
                        'message': 'project service sync completed',
                        'status': 'ok',
                        'project_id': project_id,
                        'stale_only': stale_only,
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
                    for item in agents:
                        if item.get('status') != 'online':
                            continue
                        if item.get('key') not in stale_keys:
                            continue
                        agent = self.agent_manager.get_agent(item.get('key'))
                        if not agent:
                            continue
                        results.append(self._sync_single_agent_services(agent))
                    ok_count = len([r for r in results if r.get('ok')])
                    fail_count = len(results) - ok_count
                    self._record_service_sync_log(
                        scope='global',
                        status='ok' if fail_count == 0 else 'partial',
                        stale_only=True,
                        total=len(results),
                        ok_count=ok_count,
                        fail_count=fail_count,
                        message='global stale-agent service sync completed',
                        details=results
                    )
                    return jsonify({
                        'message': 'global stale-agent service sync completed',
                        'status': 'ok',
                        'stale_only': True,
                        'total': len(results),
                        'ok_count': ok_count,
                        'fail_count': fail_count,
                        'results': results
                    })
                else:
                    self._sync_all_agent_services()
                    self._record_service_sync_log(
                        scope='global',
                        status='ok',
                        stale_only=False,
                        message='global service sync triggered'
                    )
                    return jsonify({'message': 'global service sync triggered', 'status': 'ok'})
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

        @self.app.route('/api/agent/services/global/sync/history', methods=['GET'])
        def get_global_service_sync_history():
            """查询服务强制同步历史记录。"""
            try:
                page = max(int(request.args.get('page', 1)), 1)
                per_page = min(max(int(request.args.get('per_page', 20)), 1), 200)
                project_id = request.args.get('project_id')
                table_name = self.db_manager.get_table_name('service_sync_logs')

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

                agent = self._upsert_agent_from_report(agent_key, data) or self._resolve_or_auto_create_agent_for_report(agent_key)
                if not agent:
                    return jsonify({'error': f'Agent {agent_key} not found'}), 404

                seen, upserted = self._upsert_agent_services_snapshot(agent, services, source='report_full')
                return jsonify({
                    'message': 'service snapshot accepted',
                    'agent_key': agent_key,
                    'seen': seen,
                    'upserted': upserted
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

                agent = self._upsert_agent_from_report(agent_key, data) or self._resolve_or_auto_create_agent_for_report(agent_key)
                if not agent:
                    return jsonify({'error': f'Agent {agent_key} not found'}), 404

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
                    'upserted': upserted
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
            """列出Agent动态Ingress路由"""
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
                return jsonify(resp.json()), resp.status_code
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
                payload = {
                    'agent_key': agent_key,
                    'external_ips': external_ips,
                    'target_port': target_port,
                    'host': data.get('host'),
                    'host_prefix': data.get('host_prefix') or f"{agent_key}-{target_port}",
                    'path': data.get('path', '/'),
                    'path_type': data.get('path_type', 'Prefix'),
                    'ingress_type': data.get('ingress_type'),
                    # Agent动态转发默认应回源到目标端口，避免未传时落到80端口
                    'service_port': int(data.get('service_port') or target_port),
                    'tls_enabled': data.get('tls_enabled'),
                    'tls_secret_name': data.get('tls_secret_name'),
                    'websocket_enabled': data.get('websocket_enabled', True),
                    'proxy_body_size': data.get('proxy_body_size'),
                    'proxy_connect_timeout': data.get('proxy_connect_timeout'),
                    'proxy_send_timeout': data.get('proxy_send_timeout'),
                    'proxy_read_timeout': data.get('proxy_read_timeout'),
                    'ssl_redirect': data.get('ssl_redirect'),
                    'owner_service': 'platform-agent',
                    'created_by': data.get('created_by'),
                    'force_recreate': bool(data.get('force_recreate', False)),
                    'metadata': {
                        **(data.get('metadata') or {}),
                        'agent_hostname': agent.hostname,
                        'source_api': '/api/agent/agent/<agent_key>/ingress-routes'
                    }
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
            """删除Agent动态Ingress路由"""
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
            if visibility not in ('shared', 'private'):
                return jsonify({'error': 'visibility 仅支持 shared 或 private'}), 400

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

            # 获取当前用户
            success, message = self.template_manager.create_template(
                name, description, template_type, file_content, filename,
                created_by,
                visibility=visibility,
                owner_id=user_ctx.get('user_id', ''),
                owner_name=user_ctx.get('username', '')
            )

            if success:
                return jsonify({
                    'message': message,
                    'template_name': name,
                    'template_type': template_type,
                    'filename': filename,
                    'visibility': visibility,
                    'owner_id': user_ctx.get('user_id', ''),
                    'owner_name': user_ctx.get('username', '')
                }), 201
            else:
                return jsonify({'error': message}), 400

        @self.app.route('/api/agent/templates/<name>', methods=['GET'])
        def get_template_detail(name):
            """获取模板详细信息（包含解析数据和文件大小）"""
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
                            file_stat = file_path.stat()
                            files.append({
                                'name': file_path.name,
                                'path': str(file_path.relative_to(template_dir)),
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
            if visibility is not None and str(visibility).strip().lower() not in ('shared', 'private'):
                return jsonify({'error': 'visibility 仅支持 shared 或 private'}), 400

            success, message, updated = self.template_manager.update_template_basic(
                template_id=template_id,
                new_name=new_name,
                description=description,
                visibility=visibility,
                updated_by=user_ctx.get('username', 'system')
            )
            if not success:
                return jsonify({'error': message}), 400
            updated = self.template_manager.decorate_template_permissions(
                updated,
                user_ctx.get('user_id', ''),
                user_ctx.get('username', '')
            )
            return jsonify({'message': message, 'template': updated, 'status': 'success'})

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

            success, message = self.template_manager.update_yaml_content(
                name, yaml_content, user_ctx.get('username', 'system')
            )

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
            success, message = self.template_manager.delete_template(name)

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

            success, message = self.template_manager.copy_template(
                source_name=name,
                target_name=target_name,
                created_by=user_ctx.get('username', 'system'),
                owner_id=user_ctx.get('user_id', ''),
                owner_name=user_ctx.get('username', ''),
                visibility=visibility,
                description=description
            )

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

                success, message, update_info = self.template_manager.update_template_file(
                    name, file_path, actual_content, encoding, updated_by
                )

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

            success, message, update_info = self.template_manager.update_template_file(
                name, target_path, content, encoding, updated_by
            )

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

                success, message, delete_info = self.template_manager.delete_template_file(
                    name, file_path, deleted_by
                )

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

                success, message, delete_info = self.template_manager.delete_template_directory(
                    name, dir_path, deleted_by, force
                )

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

                # 检查是否已解析
                parsed_compose = metadata.get('parsed_compose')
                if not parsed_compose:
                    # 尝试解析
                    success, msg = self.template_manager.parse_template_compose(name)
                    if success:
                        # 重新获取
                        template = self.template_manager.get_template(name)
                        metadata = template.get('metadata', {})
                        if isinstance(metadata, str):
                            metadata = json.loads(metadata)
                        parsed_compose = metadata.get('parsed_compose')
                    else:
                        return jsonify({
                            'error': '解析失败',
                            'details': metadata.get('parse_error', msg),
                            'parse_status': 'error'
                        }), 400

                # 检查是否过期
                success, is_stale, _ = self.template_manager.check_parse_staleness(name)

                return jsonify({
                    'template_name': name,
                    'parsed_compose': parsed_compose,
                    'parse_status': 'stale' if is_stale else metadata.get('parse_status', 'success'),
                    'parsed_at': metadata.get('parsed_at'),
                    'parse_error': metadata.get('parse_error'),
                    'is_stale': is_stale if success else None
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
                success, message = self.template_manager.parse_template_compose(name)

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

    def _refresh_loop(self):
        """后台刷新循环"""
        service_sync_interval = int(self.config.get('service_sync_interval', self.config.get('refresh_interval', 30)))
        service_sync_elapsed = service_sync_interval
        while not self.should_stop:
            try:
                self.agent_manager.refresh_agents()
            except Exception as e:
                self.logger.error(f"刷新Agent列表失败: {str(e)}")

            try:
                if service_sync_elapsed >= service_sync_interval:
                    self._sync_all_agent_services()
                    service_sync_elapsed = 0
            except Exception as e:
                self.logger.error(f"刷新服务聚合失败: {str(e)}")

            # 等待下一次刷新
            for _ in range(self.config['refresh_interval']):
                if self.should_stop:
                    break
                time.sleep(1)
                service_sync_elapsed += 1

    def start_refresh_thread(self):
        """启动后台刷新线程"""
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

    def run(self):
        """运行服务器"""
        # 启动后台刷新线程
        self.start_refresh_thread()

        # 运行Flask应用
        self.logger.info(f"启动WEB API服务器，监听 {self.config['host']}:{self.config['port']}")
        self.app.run(
            host=self.config['host'],
            port=self.config['port'],
            debug=self.config['debug'],
            use_reloader=False
        )


def adjust_timeout_config(config: Dict) -> Dict:
    """调整超时配置以确保合理性"""
    default_timeouts = {
        'default': (10, 30),
        'health_check': (5, 10),
        'deploy_create': (10, 60),
        'deploy_start': (10, 900),
        'deploy_stop': (10, 120),
        'deploy_delete': (10, 60),
        'undeploy': (10, 180),
        'file_upload': (10, 600),
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
