import os
import sys
import json
import re
import time
import uuid
import hashlib
import shutil
import subprocess
import zipfile
import tarfile
import tempfile
import threading
import logging
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, asdict, field
import redis
import requests
import base64

from .db import DatabaseManager
from .redis_manager import RedisManager
from .connection import ConnectionChecker
from .model import AgentInfo, TaskInfo, ProjectInfo
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime
import json
import yaml
from flask import send_file, redirect, Response
# ===================== Agent管理器（修复分布式锁问题） =====================

class AgentManager:
    """Agent管理器"""
    def __init__(self, nacos_url: str, nacos_namespace: str,
                 agent_api_port: int, agent_auth_token: str,
                 db_manager: DatabaseManager, redis_manager: RedisManager,
                 pod_id: str, agent_api_timeouts: Dict = None,
                 nacos_username: str = None, nacos_password: str = None,
                 daemon_api_port: int = 11188,
                 daemon_auth_header: str = 'X-API-Token',
                 daemon_auth_token: str = None,
                 agent_offline_grace_sec: int = 120):
        self.nacos_url = nacos_url.rstrip('/')
        self.nacos_namespace = nacos_namespace
        self.agent_api_port = agent_api_port
        self.daemon_api_port = daemon_api_port  # 新增：守护进程端口
        self.agent_auth_token = agent_auth_token
        self.daemon_auth_header = daemon_auth_header or 'X-API-Token'
        self.daemon_auth_token = daemon_auth_token or agent_auth_token
        self.db = db_manager
        self.redis_manager = redis_manager
        self.pod_id = pod_id
        self.agent_offline_grace_sec = max(int(agent_offline_grace_sec or 0), 0)

        # 新增：Nacos认证信息
        self.nacos_username = nacos_username
        self.nacos_password = nacos_password
        self.nacos_auth = None
        if self.nacos_username and self.nacos_password:
            self.nacos_auth = (self.nacos_username, self.nacos_password)

        # 设置超时配置
        self.timeouts = agent_api_timeouts or {
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

        self.agents: Dict[str, AgentInfo] = {}
        self.projects: Dict[str, ProjectInfo] = {}
        self.lock = threading.Lock()
        self.logger = logging.getLogger(__name__)

        # 检查Nacos连接
        if not self._test_nacos_connection():
            self.logger.warning("Nacos连接测试失败，Agent刷新功能可能不可用")

        # 从数据库加载Agent状态
        self._load_agents_from_db()
        # 新增：缓存nacos-client的uuid值
        self.nacos_client_uuid_cache = {}
        self.nacos_client_cache_time = 0
        self.nacos_client_cache_ttl = 60  # 缓存60秒


    def _test_nacos_connection(self) -> bool:
        """测试Nacos连接"""
        try:
            result, message = ConnectionChecker.check_nacos(self.nacos_url, self.nacos_namespace)
            if result:
                self.logger.info("Nacos连接测试通过")
                return True
            else:
                self.logger.warning(f"Nacos连接测试失败: {message}")
                return False
        except Exception as e:
            self.logger.error(f"Nacos连接测试异常: {str(e)}")
            return False

    def _load_agents_from_db(self):
        try:
            with self.lock:
                table_name = self.db.get_table_name('agent_status')
                if self.db.db_type == 'mysql':
                    agents_data = self.db.fetch_all(
                        f"SELECT * FROM {table_name} WHERE updated_at > NOW() - INTERVAL 5 MINUTE"
                    )
                else:
                    agents_data = self.db.fetch_all(
                        f"SELECT * FROM {table_name} WHERE updated_at > datetime('now', '-5 minutes')"
                    )

                for agent_data in agents_data:
                    agent = AgentInfo(
                        key=agent_data['agent_key'],
                        ip_address=agent_data['ip_address'],
                        hostname=agent_data['hostname'],
                        project_id=agent_data['project_id'],
                        full_name=agent_data['full_name'],
                        status=agent_data['status'],
                        pod_id=agent_data['pod_id']
                    )

                    if agent_data['last_seen']:
                        agent.last_seen = datetime.fromisoformat(str(agent_data['last_seen']))

                    if agent_data['system_info']:
                        if isinstance(agent_data['system_info'], str):
                            agent.system_info = json.loads(agent_data['system_info'])
                        else:
                            agent.system_info = agent_data['system_info']

                    daemon_info_data = agent_data.get('daemon_info')
                    if daemon_info_data:
                        if isinstance(daemon_info_data, str):
                            try:
                                agent.daemon_info = json.loads(daemon_info_data)
                            except Exception:
                                agent.daemon_info = {}
                        else:
                            agent.daemon_info = daemon_info_data

                    if agent_data['services']:
                        if isinstance(agent_data['services'], str):
                            agent.services = json.loads(agent_data['services'])
                        else:
                            agent.services = agent_data['services']

                    self.agents[agent.key] = agent
                    self._update_project(agent.project_id, agent.key)

                self.logger.info(f"从数据库加载了 {len(agents_data)} 个Agent状态")

        except Exception as e:
            self.logger.error(f"从数据库加载Agent状态失败: {str(e)}")

    def _update_project(self, project_id: str, agent_key: str):
        if project_id not in self.projects:
            self.projects[project_id] = ProjectInfo(
                id=project_id,
                last_refresh=datetime.now()
            )

        project = self.projects[project_id]
        if agent_key not in project.agents:
            project.agents.append(agent_key)

        online_count = 0
        for key in project.agents:
            agent = self.agents.get(key)
            if agent and agent.status == 'online':
                online_count += 1

        project.agent_count = len(project.agents)
        project.online_agents = online_count
        project.last_refresh = datetime.now()

    def _parse_agent_name(self, service_name: str) -> Optional[Tuple[str, str, str]]:
        # 找到第一个连字符，它分隔 project_id 和 hostname
        first_dash = service_name.find('-')
        if first_dash == -1:
            return None

        project_id = service_name[:first_dash]

        # 确保 project_id 不为空且不包含连字符
        if not project_id or '-' in project_id:
            return None

        # 找到最后一个连字符，它分隔 hostname 和 IP
        last_dash = service_name.rfind('-')
        if last_dash == -1 or last_dash <= first_dash:
            return None

        ip_address = service_name[last_dash + 1:]
        hostname = service_name[first_dash + 1:last_dash]

        # 确保 hostname 不为空
        if not hostname:
            return None

        # 验证 IP 地址
        if not self._is_ip_address(ip_address):
            return None

        return project_id, hostname, ip_address

    def _get_agent_key(self, hostname: str, ip_address: str, service_name: str) -> Optional[str]:
        """
        从nacos service中获取agent_key
        根据服务名称获取对应的集群，然后从该集群的metadata中获取key为uuid的值
        如果获取不到，则不认为是一个有效的agent，忽略即可
        """
        try:
            # 检查缓存
            current_time = time.time()
            cache_key = f"{service_name}_nacos-client"
            if current_time - self.nacos_client_cache_time < self.nacos_client_cache_ttl:
                uuid_value = self.nacos_client_uuid_cache.get(cache_key)
                if uuid_value:
                    self.logger.debug(f"使用缓存的uuid: {uuid_value} for service: {service_name}")
                    return uuid_value

            # 方法1: 尝试使用新的API路径
            try:
                # 新的API路径: /v3/admin/ns/service
                url = f"{self.nacos_url}/nacos/v3/admin/ns/service"
                params = {
                    'serviceName': service_name,  # 使用agent的服务名称
                    'groupName': 'DEFAULT_GROUP',
                    'namespaceId': self.nacos_namespace
                }

                # 使用认证信息
                response = requests.get(url, params=params, timeout=5, auth=self.nacos_auth)

                if response.status_code == 200:
                    service_data = response.json()
                    self.logger.debug(f"使用新API获取服务 {service_name} 成功")

                    # 尝试解析新的API返回格式，查找名为nacos-client的集群
                    uuid_value = self._parse_nacos_v3_response_for_cluster(service_data, 'nacos-client')
                    if uuid_value:
                        # 更新缓存
                        self.nacos_client_uuid_cache[cache_key] = uuid_value
                        self.nacos_client_cache_time = current_time

                        #self.logger.debug(f"从服务 {service_name} 的nacos-client集群获取到uuid: {uuid_value}")
                        return uuid_value
                    else:
                        self.logger.debug(f"服务 {service_name} 中没有找到名为nacos-client的集群")

            except Exception as e:
                self.logger.debug(f"使用新API获取服务 {service_name} 失败: {str(e)}")

            # 方法2: 尝试使用实例列表API（指定集群名称）
            try:
                # 实例列表API，可以指定集群名称
                url = f"{self.nacos_url}/nacos/v1/ns/instance/list"
                params = {
                    'serviceName': service_name,
                    'groupName': 'DEFAULT_GROUP',
                    'namespaceId': self.nacos_namespace,
                    'clusters': 'nacos-client'  # 指定集群名称
                }

                # 使用认证信息
                response = requests.get(url, params=params, timeout=5, auth=self.nacos_auth)

                if response.status_code == 200:
                    instances_data = response.json()

                    # 查找实例的metadata
                    if 'hosts' in instances_data and instances_data['hosts']:
                        for instance in instances_data['hosts']:
                            if 'metadata' in instance:
                                uuid_value = instance['metadata'].get('uuid')
                                if uuid_value:
                                    # 更新缓存
                                    self.nacos_client_uuid_cache[cache_key] = uuid_value
                                    self.nacos_client_cache_time = current_time

                                    self.logger.debug(f"从服务 {service_name} 的nacos-client集群实例获取到uuid: {uuid_value}")
                                    return uuid_value

                        self.logger.debug(f"服务 {service_name} 的nacos-client集群实例中没有找到uuid")
                    else:
                        self.logger.debug(f"服务 {service_name} 没有nacos-client集群的实例")
                else:
                    self.logger.debug(f"获取服务 {service_name} 的实例列表失败: HTTP {response.status_code}")

            except Exception as e:
                self.logger.debug(f"使用实例列表API获取服务 {service_name} 失败: {str(e)}")

            # 方法3: 尝试使用旧API路径（如果新API不可用）
            try:
                url = f"{self.nacos_url}/v1/ns/service"
                params = {
                    'serviceName': service_name,
                    'groupName': 'DEFAULT_GROUP',
                    'namespaceId': self.nacos_namespace
                }

                # 使用认证信息
                response = requests.get(url, params=params, timeout=5, auth=self.nacos_auth)

                if response.status_code == 200:
                    service_data = response.json()
                    self.logger.debug(f"使用旧API获取服务 {service_name} 成功")

                    # 查找名为nacos-client的集群
                    if 'hosts' in service_data and service_data['hosts']:
                        for host in service_data['hosts']:
                            # 检查集群名称是否为nacos-client
                            cluster_name = host.get('clusterName', '')
                            if cluster_name == 'nacos-client' and 'metadata' in host:
                                metadata = host['metadata']
                                uuid_value = metadata.get('uuid')

                                if uuid_value:
                                    # 更新缓存
                                    self.nacos_client_uuid_cache[cache_key] = uuid_value
                                    self.nacos_client_cache_time = current_time

                                    self.logger.debug(f"从服务 {service_name} 的nacos-client集群获取到uuid: {uuid_value}")
                                    return uuid_value

                        self.logger.debug(f"服务 {service_name} 中没有找到名为nacos-client的集群")
                    else:
                        self.logger.debug(f"服务 {service_name} 没有找到集群信息")
                else:
                    self.logger.debug(f"获取服务 {service_name} 失败: HTTP {response.status_code}")

            except Exception as e:
                self.logger.debug(f"使用旧API获取服务 {service_name} 失败: {str(e)}")

        except requests.exceptions.ConnectionError:
            self.logger.debug("连接Nacos失败，无法获取服务信息")
        except requests.exceptions.Timeout:
            self.logger.debug("获取服务信息超时")
        except Exception as e:
            self.logger.debug(f"获取服务信息异常: {str(e)}")

        # 如果获取不到uuid，打印调试信息并返回None
        self.logger.debug(f"无法从服务 {service_name} 的nacos-client集群获取有效的uuid，忽略agent: {hostname}-{ip_address}")
        return None

    def _parse_nacos_v3_response_for_cluster(self, service_data: Dict, cluster_name: str) -> Optional[str]:
        """
        解析Nacos v3 API的响应，查找指定集群名称的metadata中的uuid
        """
        try:
            # 尝试不同的响应格式
            if isinstance(service_data, dict):
                # 格式1: 直接包含service字段
                if 'service' in service_data:
                    service = service_data['service']
                    if 'clusters' in service and service['clusters']:
                        for cluster in service['clusters']:
                            if cluster.get('name') == cluster_name and 'metadata' in cluster:
                                uuid_value = cluster['metadata'].get('uuid')
                                if uuid_value:
                                    return uuid_value

                # 格式2: 包含data字段
                if 'data' in service_data:
                    data = service_data['data']
                    if isinstance(data, dict) and 'clusters' in data and data['clusters']:
                        for cluster in data['clusters']:
                            if cluster.get('name') == cluster_name and 'metadata' in cluster:
                                uuid_value = cluster['metadata'].get('uuid')
                                if uuid_value:
                                    return uuid_value

                # 格式3: 直接是集群列表
                if 'clusters' in service_data and service_data['clusters']:
                    for cluster in service_data['clusters']:
                        if cluster.get('name') == cluster_name and 'metadata' in cluster:
                            uuid_value = cluster['metadata'].get('uuid')
                            if uuid_value:
                                return uuid_value

                # 格式4: 尝试查找任何包含metadata的字段
                for key, value in service_data.items():
                    if isinstance(value, dict):
                        result = self._parse_nacos_v3_response_for_cluster(value, cluster_name)
                        if result:
                            return result
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict):
                                result = self._parse_nacos_v3_response_for_cluster(item, cluster_name)
                                if result:
                                    return result

            self.logger.debug(f"无法从响应中找到集群 {cluster_name} 的uuid，响应格式: {service_data}")
            return None

        except Exception as e:
            self.logger.debug(f"解析Nacos v3响应失败: {str(e)}")
            return None

    def _fetch_nacos_services(self) -> List[Dict]:
        try:
            url = f"{self.nacos_url}/nacos/v1/ns/service/list"
            params = {
                'pageNo': 1,
                'pageSize': 1000000,
                'namespaceId': self.nacos_namespace
            }

            # 使用认证信息
            response = requests.get(url, params=params, timeout=10, auth=self.nacos_auth)
            if response.status_code == 200:
                data = response.json()
                return data.get('doms', [])
            elif response.status_code == 401:
                # 尝试v3 API
                v3_url = f"{self.nacos_url}/nacos/v3/ns/service/list"
                v3_response = requests.get(v3_url, params=params, timeout=10, auth=self.nacos_auth)
                if v3_response.status_code == 200:
                    v3_data = v3_response.json()
                    # 解析v3 API返回格式
                    if 'data' in v3_data and 'list' in v3_data['data']:
                        return [service['name'] for service in v3_data['data']['list']]
                    elif 'list' in v3_data:
                        return [service['name'] for service in v3_data['list']]
                    else:
                        self.logger.error(f"Nacos v3 API返回格式异常: {v3_data}")
                        return []
                else:
                    self.logger.error(f"获取Nacos服务列表失败 (v3): {v3_response.status_code}")
                    return []
            else:
                self.logger.error(f"获取Nacos服务列表失败: {response.status_code}")
                return []

        except requests.exceptions.ConnectionError as e:
            self.logger.error(f"Nacos连接失败: {str(e)}")
            return []
        except requests.exceptions.Timeout as e:
            self.logger.error(f"Nacos请求超时: {str(e)}")
            return []
        except Exception as e:
            self.logger.error(f"获取Nacos服务列表异常: {str(e)}")
            return []

    def _has_healthy_nacos_client_instance(self, service_name: str, expected_ip: str = None) -> bool:
        """检查服务在 nacos-client 集群下是否仍有健康实例，避免残留 service name 重新带回失效 Agent。"""
        try:
            url = f"{self.nacos_url}/nacos/v1/ns/instance/list"
            params = {
                'serviceName': service_name,
                'groupName': 'DEFAULT_GROUP',
                'namespaceId': self.nacos_namespace,
                'clusters': 'nacos-client'
            }
            response = requests.get(url, params=params, timeout=5, auth=self.nacos_auth)
            if response.status_code != 200:
                self.logger.debug(f"检查Nacos健康实例失败: service={service_name}, status={response.status_code}")
                return False

            payload = response.json() if response.content else {}
            healthy_hosts = []
            for host in payload.get('hosts') or []:
                if host.get('healthy') is False:
                    continue
                if host.get('enabled') is False:
                    continue
                healthy_hosts.append(host)
                if expected_ip and str(host.get('ip') or '').strip() != expected_ip:
                    continue
                return True
            # 多网卡或注册地址切换场景：expected_ip 不匹配时，只要 nacos-client 集群存在健康实例也视为可用
            if healthy_hosts:
                if expected_ip:
                    host_ips = [str(h.get('ip') or '').strip() for h in healthy_hosts]
                    self.logger.debug(
                        f"Nacos健康实例IP与服务名IP不一致，按健康实例保留可用: "
                        f"service={service_name}, expected_ip={expected_ip}, host_ips={host_ips}"
                    )
                return True
            return False
        except Exception as e:
            self.logger.debug(f"检查Nacos健康实例异常: service={service_name}, err={e}")
            return False

    def _should_keep_online_on_transient_probe_failure(self, agent_key: str) -> bool:
        """探测瞬时失败时的在线保留策略，避免多节点场景状态横跳。"""
        if self.agent_offline_grace_sec <= 0:
            return False

        now = datetime.now()
        cached = self.agents.get(agent_key)
        if cached and str(cached.status or '').lower() == 'online' and cached.last_seen:
            if (now - cached.last_seen).total_seconds() <= self.agent_offline_grace_sec:
                return True

        try:
            table_name = self.db.get_table_name('agent_status')
            row = self.db.fetch_one(
                f"SELECT status, last_seen, updated_at FROM {table_name} WHERE agent_key = %s LIMIT 1"
                if self.db.db_type == 'mysql' else
                f"SELECT status, last_seen, updated_at FROM {table_name} WHERE agent_key = ? LIMIT 1",
                (agent_key,),
            )
            if not row:
                return False
            if str(row.get('status') or '').lower() != 'online':
                return False
            stale_ref = self._latest_stale_reference(row.get('last_seen'), row.get('updated_at'))
            if not stale_ref:
                return False
            return (now - stale_ref).total_seconds() <= self.agent_offline_grace_sec
        except Exception:
            return False

    def _check_secflow_agent_agent_status(self, agent: AgentInfo) -> bool:
        try:
            # 首先检查是否有有效的agent_key
            if not agent.key:
                self.logger.debug(f"Agent {agent.full_name} 没有有效的agent_key，跳过状态检查")
                agent.status = 'invalid'
                return False

            url = f"http://{agent.ip_address}:{self.agent_api_port}/api/health"
            headers = {'X-Auth-Token': self.agent_auth_token}

            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                agent.status = 'online'
                agent.last_seen = datetime.now()
                agent.pod_id = self.pod_id

                try:
                    sys_url = f"http://{agent.ip_address}:{self.agent_api_port}/api/system/info"
                    sys_response = requests.get(sys_url, headers=headers, timeout=5)
                    if sys_response.status_code == 200:
                        agent.system_info = sys_response.json()
                except:
                    pass

                try:
                    services_url = f"http://{agent.ip_address}:{self.agent_api_port}/api/services"
                    services_response = requests.get(services_url, headers=headers, timeout=5)
                    if services_response.status_code == 200:
                        agent.services = services_response.json()
                except:
                    pass

                # 守护进程Agent信息（11188）
                daemon_headers = {
                    self.daemon_auth_header: self.daemon_auth_token
                }
                try:
                    daemon_info_url = f"http://{agent.ip_address}:{self.daemon_api_port}/api/v1/agent/info"
                    daemon_info_response = requests.get(daemon_info_url, headers=daemon_headers, timeout=5)
                    if daemon_info_response.status_code == 200:
                        daemon_payload = daemon_info_response.json()
                        if isinstance(daemon_payload, dict):
                            if 'data' in daemon_payload and isinstance(daemon_payload['data'], dict):
                                agent.daemon_info = daemon_payload['data']
                            else:
                                agent.daemon_info = daemon_payload
                except:
                    pass

                return True
            else:
                if self._should_keep_online_on_transient_probe_failure(agent.key):
                    agent.status = 'online'
                    agent.pod_id = self.pod_id
                    self.logger.debug(
                        f"Agent健康检查返回HTTP {response.status_code}，命中宽限期({self.agent_offline_grace_sec}s)保留online: {agent.key}"
                    )
                    return True
                agent.status = 'error'
                return False

        except requests.exceptions.ConnectionError:
            if self._should_keep_online_on_transient_probe_failure(agent.key):
                agent.status = 'online'
                agent.pod_id = self.pod_id
                self.logger.debug(
                    f"Agent健康检查连接失败，命中宽限期({self.agent_offline_grace_sec}s)保留online: {agent.key}"
                )
                return True
            agent.status = 'offline'
            return False
        except requests.exceptions.Timeout:
            if self._should_keep_online_on_transient_probe_failure(agent.key):
                agent.status = 'online'
                agent.pod_id = self.pod_id
                self.logger.debug(
                    f"Agent健康检查超时，命中宽限期({self.agent_offline_grace_sec}s)保留online: {agent.key}"
                )
                return True
            agent.status = 'timeout'
            return False
        except Exception:
            if self._should_keep_online_on_transient_probe_failure(agent.key):
                agent.status = 'online'
                agent.pod_id = self.pod_id
                self.logger.debug(
                    f"Agent健康检查异常，命中宽限期({self.agent_offline_grace_sec}s)保留online: {agent.key}"
                )
                return True
            agent.status = 'error'
            return False

    def refresh_agents(self, use_distributed_lock: bool = True):
        """刷新Agent列表（使用分布式锁确保只有一个POD执行刷新）"""
        lock_key = "agent_refresh_lock"

        try:
            if use_distributed_lock:
                # 获取分布式锁（如果Redis不可用，会返回虚拟锁）
                with self.redis_manager.get_lock(lock_key, timeout=30) as lock:
                    if not lock.is_acquired():
                        self.logger.warning(f"POD {self.pod_id} 无法获取锁，跳过本次刷新...")
                        return
                    self._refresh_agents_without_lock()
            else:
                self._refresh_agents_without_lock()
        except Exception as e:
            self.logger.error(f"刷新Agent列表异常: {str(e)}")

    def _refresh_agents_without_lock(self):
        services = self._fetch_nacos_services()
        if not services:
            self.logger.warning("本轮未从Nacos获取到任何Agent服务，跳过缺失Agent下线收敛")
            return

        new_agents = {}

        for service in services:
            result = self._parse_agent_name(service)
            if result:
                project_id, hostname, ip_address = result

                if not self._has_healthy_nacos_client_instance(service, ip_address):
                    self.logger.debug(f"跳过无健康实例的agent服务: {service}")
                    continue

                # 使用新方法获取agent_key，传入service_name
                agent_key = self._get_agent_key(hostname, ip_address, service)

                # 如果没有获取到有效的agent_key，跳过这个agent
                if not agent_key:
                    self.logger.debug(f"跳过无效的agent: {hostname} ({ip_address}), 服务: {service}")
                    continue

                agent = AgentInfo(
                    key=agent_key,
                    ip_address=ip_address,
                    hostname=hostname,
                    project_id=project_id,
                    full_name=service,
                    status='unknown',
                    pod_id=self.pod_id
                )

                self._check_secflow_agent_agent_status(agent)
                reason_code = {
                    'online': 'health_ok',
                    'offline': 'health_connection_error',
                    'timeout': 'health_timeout',
                    'error': 'health_http_or_runtime_error',
                    'unknown': 'health_unknown',
                    'invalid': 'health_invalid_agent_key',
                }.get(str(agent.status or '').lower(), 'health_unknown')
                self._save_agent_to_db(
                    agent,
                    reason_code=reason_code,
                    reason_message=f"refresh probe result: {agent.status}",
                    source='refresh_probe'
                )
                new_agents[agent_key] = agent

        self._mark_missing_agents_offline(set(new_agents.keys()))

        with self.lock:
            for key, new_agent in new_agents.items():
                self.agents[key] = new_agent
                self._update_project(new_agent.project_id, key)

            removed_keys = [k for k in self.agents.keys() if k not in new_agents]
            for key in removed_keys:
                del self.agents[key]

        self.logger.info(f"Agent列表刷新完成，共 {len(new_agents)} 个有效Agent")

    def _parse_stale_reference(self, value: Any) -> Optional[datetime]:
        if not value:
            return None
        try:
            stale_ref = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
            if stale_ref.tzinfo is not None:
                stale_ref = stale_ref.astimezone().replace(tzinfo=None)
            return stale_ref
        except Exception:
            return None

    def _latest_stale_reference(self, last_seen: Any, updated_at: Any) -> Optional[datetime]:
        candidates = [
            self._parse_stale_reference(last_seen),
            self._parse_stale_reference(updated_at),
        ]
        candidates = [item for item in candidates if item is not None]
        if not candidates:
            return None
        return max(candidates)

    def _mark_missing_agents_offline(self, active_keys: set):
        """将本轮Nacos未发现但数据库中仍标记在线的Agent收敛为离线。"""
        try:
            now = datetime.now()
            table_name = self.db.get_table_name('agent_status')
            rows = self.db.fetch_all(
                f"SELECT agent_key, project_id, status, last_seen, updated_at FROM {table_name}"
            ) or []

            missing_online_keys: List[str] = []
            grace_skipped_keys: List[str] = []
            for row in rows:
                agent_key = row.get('agent_key')
                if not agent_key or agent_key in active_keys:
                    continue
                if (row.get('status') or '').lower() != 'online':
                    continue

                stale_ref = self._latest_stale_reference(row.get('last_seen'), row.get('updated_at'))
                if stale_ref is None:
                    missing_online_keys.append(agent_key)
                    continue

                missing_for_sec = (now - stale_ref).total_seconds()
                if missing_for_sec >= self.agent_offline_grace_sec:
                    missing_online_keys.append(agent_key)
                else:
                    grace_skipped_keys.append(agent_key)

            if grace_skipped_keys:
                self.logger.debug(
                    f"跳过 {len(grace_skipped_keys)} 个暂时缺失Agent离线收敛（宽限期{self.agent_offline_grace_sec}s内）"
                )

            if not missing_online_keys:
                return

            self.logger.info(
                f"将 {len(missing_online_keys)} 个未在Nacos中发现且超过宽限期({self.agent_offline_grace_sec}s)的在线Agent标记为offline"
            )

            if self.db.db_type == 'mysql':
                placeholders = ','.join(['%s'] * len(missing_online_keys))
                self.db.execute_query(
                    f"UPDATE {table_name} "
                    f"SET status = 'offline', pod_id = %s, updated_at = NOW() "
                    f"WHERE agent_key IN ({placeholders})",
                    (self.pod_id, *missing_online_keys)
                )
            else:
                placeholders = ','.join(['?'] * len(missing_online_keys))
                self.db.execute_query(
                    f"UPDATE {table_name} "
                    f"SET status = 'offline', pod_id = ?, updated_at = datetime('now') "
                    f"WHERE agent_key IN ({placeholders})",
                    (self.pod_id, *missing_online_keys)
                )

            for agent_key in missing_online_keys:
                row = next((r for r in rows if r.get('agent_key') == agent_key), None) or {}
                self._record_agent_status_transition(
                    project_id=str(row.get('project_id') or ''),
                    agent_key=agent_key,
                    hostname='',
                    ip_address='',
                    from_status=str(row.get('status') or ''),
                    to_status='offline',
                    reason_code='nacos_missing_exceed_grace',
                    reason_message=f'Agent not found in nacos and exceeded grace({self.agent_offline_grace_sec}s)',
                    source='refresh_missing',
                    observed_at=now,
                )

            with self.lock:
                for agent_key in missing_online_keys:
                    agent = self.agents.get(agent_key)
                    if agent:
                        agent.status = 'offline'
                        agent.pod_id = self.pod_id
                    for project in self.projects.values():
                        if agent_key in project.agents:
                            self._update_project(project.id, agent_key)

        except Exception as e:
            self.logger.error(f"收敛缺失Agent离线状态失败: {str(e)}")

    def cleanup_offline_agents(self, project_id: str = None, force: bool = False) -> Tuple[bool, str, Dict]:
        """
        清除指定project下掉线的agent

        Args:
            project_id: 项目ID，如果为None则清理所有项目的掉线agent

        Returns:
            (success, message, cleanup_info)
        """
        try:
            # 获取分布式锁，确保只有一个POD执行清理
            lock_key = f"agent_cleanup_lock_{project_id}" if project_id else "agent_cleanup_lock"
            with self.redis_manager.get_lock(lock_key, timeout=60) as lock:
                if lock.is_acquired():
                    self.logger.info(f"成功获取清理锁，开始清除{('project ' + project_id) if project_id else '全部'}掉线agent")
                else:
                    self.logger.warning("无法获取清理锁，跳过本次清理")
                    return False, "其他POD正在执行清理操作，请稍后重试", {}

                # 构建查询条件
                if project_id:
                    if force:
                        where_clause = " WHERE project_id = %s AND status IN ('offline', 'error', 'timeout', 'unknown')"
                        where_clause_sqlite = " WHERE project_id = ? AND status IN ('offline', 'error', 'timeout', 'unknown')"
                    else:
                        where_clause = " WHERE project_id = %s AND status IN ('offline', 'error', 'timeout', 'unknown') AND updated_at < NOW() - INTERVAL 5 MINUTE"
                        where_clause_sqlite = " WHERE project_id = ? AND status IN ('offline', 'error', 'timeout', 'unknown') AND updated_at < datetime('now', '-5 minutes')"
                else:
                    if force:
                        where_clause = " WHERE status IN ('offline', 'error', 'timeout', 'unknown')"
                        where_clause_sqlite = " WHERE status IN ('offline', 'error', 'timeout', 'unknown')"
                    else:
                        where_clause = " WHERE status IN ('offline', 'error', 'timeout', 'unknown') AND updated_at < NOW() - INTERVAL 5 MINUTE"
                        where_clause_sqlite = " WHERE status IN ('offline', 'error', 'timeout', 'unknown') AND updated_at < datetime('now', '-5 minutes')"

                # 查询所有掉线的agent
                table_name = self.db.get_table_name('agent_status')
                if self.db.db_type == 'mysql':
                    offline_agents = self.db.fetch_all(f'''
                                                       SELECT agent_key, hostname, ip_address, project_id, status,
                                                              last_seen, updated_at
                                                       FROM {table_name}
                                                       {where_clause}
                                                       ORDER BY updated_at ASC
                                                       ''', (project_id,) if project_id else None)
                else:
                    offline_agents = self.db.fetch_all(f'''
                                                       SELECT agent_key, hostname, ip_address, project_id, status,
                                                              last_seen, updated_at
                                                       FROM {table_name}
                                                       {where_clause_sqlite}
                                                       ORDER BY updated_at ASC
                                                       ''', (project_id,) if project_id else None)

                if not offline_agents:
                    return True, "没有需要清理的掉线agent", {
                        'cleaned_count': 0,
                        'offline_count': 0,
                        'timestamp': datetime.now().isoformat()
                    }

                self.logger.info(f"找到 {len(offline_agents)} 个掉线agent需要清理 force={force}")

                # 记录清理信息
                cleaned_agents = []
                cleaned_count = 0

                with self.lock:
                    # 删除数据库中的掉线agent记录
                    for agent_data in offline_agents:
                        agent_key = agent_data['agent_key']

                        try:
                            # 从数据库中删除
                            table_name = self.db.get_table_name('agent_status')
                            if self.db.db_type == 'mysql':
                                self.db.execute_query(
                                    f"DELETE FROM {table_name} WHERE agent_key = %s",
                                    (agent_key,)
                                )
                            else:
                                self.db.execute_query(
                                    f"DELETE FROM {table_name} WHERE agent_key = ?",
                                    (agent_key,)
                                )

                            # 从内存中移除
                            if agent_key in self.agents:
                                del self.agents[agent_key]

                            # 从工作空间中移除
                            for project in self.projects.values():
                                if agent_key in project.agents:
                                    project.agents.remove(agent_key)

                            # 记录清理的agent信息
                            cleaned_agents.append({
                                'agent_key': agent_key,
                                'hostname': agent_data['hostname'],
                                'ip_address': agent_data['ip_address'],
                                'project_id': agent_data['project_id'],
                                'status': agent_data['status'],
                                'last_seen': agent_data['last_seen'].isoformat() if agent_data['last_seen'] else None,
                                'cleaned_at': datetime.now().isoformat()
                            })
                            cleaned_count += 1

                            self.logger.info(f"已清理掉线agent: {agent_key} ({agent_data['hostname']})")

                        except Exception as e:
                            self.logger.error(f"清理agent {agent_key} 失败: {str(e)}")
                            continue

                # 更新项目统计
                for project_id, project in self.projects.items():
                    # 重新计算在线agent数量
                    online_count = 0
                    for agent_key in project.agents:
                        agent = self.agents.get(agent_key)
                        if agent and agent.status == 'online':
                            online_count += 1

                    project.agent_count = len(project.agents)
                    project.online_agents = online_count
                    project.last_refresh = datetime.now()

                # 准备清理信息
                cleanup_info = {
                    'cleaned_count': cleaned_count,
                    'offline_count': len(offline_agents),
                    'force': force,
                    'timestamp': datetime.now().isoformat(),
                    'pod_id': self.pod_id,
                    'cleaned_agents': cleaned_agents,
                    'remaining_agents': len(self.agents),
                    'project_count': len(self.projects)
                }

                self.logger.info(f"清理完成: 已清理 {cleaned_count} 个掉线agent")
                return True, f"成功清理 {cleaned_count} 个掉线agent", cleanup_info

        except Exception as e:
            self.logger.error(f"清除掉线agent失败: {str(e)}", exc_info=True)
            return False, f"清理失败: {str(e)}", {}

    def get_offline_agents_count(self, project_id: str = None, force: bool = False) -> Tuple[int, int]:
        """
        获取掉线agent的统计信息

        Args:
            project_id: 项目ID，如果为None则统计所有项目

        Returns:
            (offline_count, total_count)
        """
        try:
            # 构建过滤条件
            table_name = self.db.get_table_name('agent_status')
            params = []
            if project_id:
                params.append(project_id)

            # 获取总agent数
            if self.db.db_type == 'mysql':
                project_filter = " WHERE project_id = %s" if project_id else ""
                total_result = self.db.fetch_one(
                    f"SELECT COUNT(*) as count FROM {table_name}{project_filter}",
                    tuple(params) if params else None
                )
                offline_filter = " WHERE status IN ('offline', 'error', 'timeout', 'unknown')"
                if project_id:
                    offline_filter = " WHERE project_id = %s AND status IN ('offline', 'error', 'timeout', 'unknown')"
                if not force:
                    offline_filter += " AND updated_at < NOW() - INTERVAL 5 MINUTE"
                offline_result = self.db.fetch_one(
                    f"SELECT COUNT(*) as count FROM {table_name}{offline_filter}",
                    tuple(params) if params else None
                )
            else:
                project_filter_sql = " WHERE project_id = ?" if project_id else ""
                total_result = self.db.fetch_one(
                    f"SELECT COUNT(*) as count FROM {table_name}{project_filter_sql}",
                    tuple(params) if params else None
                )
                offline_filter_sql = " WHERE status IN ('offline', 'error', 'timeout', 'unknown')"
                if project_id:
                    offline_filter_sql = " WHERE project_id = ? AND status IN ('offline', 'error', 'timeout', 'unknown')"
                if not force:
                    offline_filter_sql += " AND updated_at < datetime('now', '-5 minutes')"
                offline_result = self.db.fetch_one(
                    f"SELECT COUNT(*) as count FROM {table_name}{offline_filter_sql}",
                    tuple(params) if params else None
                )

            total_count = total_result['count'] if total_result else 0
            offline_count = offline_result['count'] if offline_result else 0

            return offline_count, total_count

        except Exception as e:
            self.logger.error(f"获取掉线agent统计失败: {str(e)}")
            return 0, 0

    def _is_ip_address(self, s: str) -> bool:
        import socket
        try:
            socket.inet_aton(s)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, s)
                return True
            except socket.error:
                return False

    @staticmethod
    def _status_to_edge_state(status: Any) -> str:
        return 'online' if str(status or '').lower() == 'online' else 'offline'

    def _trim_agent_status_events(self, project_id: str, agent_key: str, keep: int = 100):
        if not project_id or not agent_key:
            return
        table_name = self.db.get_table_name('agent_status_events')
        keep = max(int(keep or 100), 1)
        try:
            if self.db.db_type == 'mysql':
                self.db.execute_query(
                    f'''
                    DELETE FROM {table_name}
                    WHERE project_id = %s
                      AND agent_key = %s
                      AND id NOT IN (
                        SELECT id FROM (
                          SELECT id FROM {table_name}
                          WHERE project_id = %s AND agent_key = %s
                          ORDER BY id DESC
                          LIMIT %s
                        ) AS keep_rows
                      )
                    ''',
                    (project_id, agent_key, project_id, agent_key, keep)
                )
            else:
                self.db.execute_query(
                    f'''
                    DELETE FROM {table_name}
                    WHERE project_id = ?
                      AND agent_key = ?
                      AND id NOT IN (
                        SELECT id FROM {table_name}
                        WHERE project_id = ? AND agent_key = ?
                        ORDER BY id DESC
                        LIMIT ?
                      )
                    ''',
                    (project_id, agent_key, project_id, agent_key, keep)
                )
        except Exception as e:
            self.logger.warning(f"裁剪Agent状态事件失败: agent={agent_key}, err={e}")

    def _record_agent_status_transition(
        self,
        *,
        project_id: str,
        agent_key: str,
        hostname: str = '',
        ip_address: str = '',
        from_status: str,
        to_status: str,
        reason_code: str,
        reason_message: str = '',
        source: str = 'refresh',
        observed_at: Optional[datetime] = None,
    ) -> bool:
        edge_from = self._status_to_edge_state(from_status)
        edge_to = self._status_to_edge_state(to_status)
        if edge_from == edge_to:
            return False

        table_name = self.db.get_table_name('agent_status_events')
        observed = observed_at or datetime.now()
        observed_text = observed.isoformat()
        try:
            if self.db.db_type == 'mysql':
                self.db.execute_query(
                    f'''
                    INSERT INTO {table_name}
                    (project_id, agent_key, hostname, ip_address, from_status, to_status,
                     edge_state_from, edge_state_to, reason_code, reason_message, source, pod_id, observed_at, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                    ''',
                    (
                        project_id,
                        agent_key,
                        hostname or '',
                        ip_address or '',
                        str(from_status or ''),
                        str(to_status or ''),
                        edge_from,
                        edge_to,
                        str(reason_code or ''),
                        str(reason_message or ''),
                        str(source or 'refresh'),
                        self.pod_id,
                        observed_text,
                    )
                )
            else:
                self.db.execute_query(
                    f'''
                    INSERT INTO {table_name}
                    (project_id, agent_key, hostname, ip_address, from_status, to_status,
                     edge_state_from, edge_state_to, reason_code, reason_message, source, pod_id, observed_at, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                    ''',
                    (
                        project_id,
                        agent_key,
                        hostname or '',
                        ip_address or '',
                        str(from_status or ''),
                        str(to_status or ''),
                        edge_from,
                        edge_to,
                        str(reason_code or ''),
                        str(reason_message or ''),
                        str(source or 'refresh'),
                        self.pod_id,
                        observed_text,
                    )
                )
            self._trim_agent_status_events(project_id, agent_key, keep=100)
            return True
        except Exception as e:
            self.logger.error(f"记录Agent状态切换失败: agent={agent_key}, err={e}")
            return False


    def _save_agent_to_db(
        self,
        agent: AgentInfo,
        reason_code: str = 'refresh_probe',
        reason_message: str = '',
        source: str = 'refresh',
    ):
        prev_status = ''
        table_name = self.db.get_table_name('agent_status')
        try:
            if self.db.db_type == 'mysql':
                prev_row = self.db.fetch_one(
                    f"SELECT status FROM {table_name} WHERE agent_key = %s LIMIT 1",
                    (agent.key,)
                )
            else:
                prev_row = self.db.fetch_one(
                    f"SELECT status FROM {table_name} WHERE agent_key = ? LIMIT 1",
                    (agent.key,)
                )
            prev_status = str((prev_row or {}).get('status') or '')
        except Exception:
            prev_status = ''

        try:
            system_info_json = json.dumps(agent.system_info) if agent.system_info else '{}'
            daemon_info_json = json.dumps(agent.daemon_info) if agent.daemon_info else '{}'
            services_json = json.dumps(agent.services) if agent.services else '[]'
            last_seen_str = agent.last_seen.isoformat() if agent.last_seen else None

            if self.db.db_type == 'mysql':
                self.db.execute_query(f'''
                                      INSERT INTO {table_name}
                                      (agent_key, ip_address, hostname, project_id, full_name, status,
                                       last_seen, system_info, daemon_info, services, pod_id, updated_at)
                                      VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                                          ON DUPLICATE KEY UPDATE
                                                               ip_address = VALUES(ip_address),
                                                               hostname = VALUES(hostname),
                                                               project_id = VALUES(project_id),
                                                               full_name = VALUES(full_name),
                                                               status = VALUES(status),
                                                               last_seen = VALUES(last_seen),
                                                               system_info = VALUES(system_info),
                                                               daemon_info = VALUES(daemon_info),
                                                               services = VALUES(services),
                                                               pod_id = VALUES(pod_id),
                                                               updated_at = NOW()
                                      ''', (
                                          agent.key,
                                          agent.ip_address,
                                          agent.hostname,
                                          agent.project_id,
                                          agent.full_name,
                                          agent.status,
                                          last_seen_str,
                                          system_info_json,
                                          daemon_info_json,
                                          services_json,
                                          self.pod_id
                                      ))
            else:
                self.db.execute_query(f'''
                    INSERT OR REPLACE INTO {table_name}
                    (agent_key, ip_address, hostname, project_id, full_name, status,
                     last_seen, system_info, daemon_info, services, pod_id, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                ''', (
                    agent.key,
                    agent.ip_address,
                    agent.hostname,
                    agent.project_id,
                    agent.full_name,
                    agent.status,
                    last_seen_str,
                    system_info_json,
                    daemon_info_json,
                    services_json,
                    self.pod_id
                ))

            self._record_agent_status_transition(
                project_id=agent.project_id,
                agent_key=agent.key,
                hostname=agent.hostname,
                ip_address=agent.ip_address,
                from_status=prev_status,
                to_status=agent.status,
                reason_code=reason_code,
                reason_message=reason_message,
                source=source,
                observed_at=agent.last_seen or datetime.now(),
            )
        except Exception as e:
            self.logger.error(f"保存Agent状态到数据库失败: {str(e)}")

    def record_manual_status_transition(
        self,
        *,
        project_id: str,
        agent_key: str,
        hostname: str,
        ip_address: str,
        from_status: str,
        to_status: str,
        reason_message: str = '',
    ) -> bool:
        return self._record_agent_status_transition(
            project_id=project_id,
            agent_key=agent_key,
            hostname=hostname,
            ip_address=ip_address,
            from_status=from_status,
            to_status=to_status,
            reason_code='manual_update',
            reason_message=reason_message,
            source='manual',
            observed_at=datetime.now(),
        )

    def list_agent_status_history(self, project_id: str, agent_key: str, limit: int = 100) -> List[Dict]:
        table_name = self.db.get_table_name('agent_status_events')
        q_limit = max(1, min(int(limit or 100), 100))
        try:
            if self.db.db_type == 'mysql':
                rows = self.db.fetch_all(
                    f'''
                    SELECT id, project_id, agent_key, hostname, ip_address,
                           from_status, to_status, edge_state_from, edge_state_to,
                           reason_code, reason_message, source, pod_id, observed_at, created_at
                    FROM {table_name}
                    WHERE project_id = %s AND agent_key = %s
                    ORDER BY id DESC
                    LIMIT %s
                    ''',
                    (project_id, agent_key, q_limit)
                ) or []
            else:
                rows = self.db.fetch_all(
                    f'''
                    SELECT id, project_id, agent_key, hostname, ip_address,
                           from_status, to_status, edge_state_from, edge_state_to,
                           reason_code, reason_message, source, pod_id, observed_at, created_at
                    FROM {table_name}
                    WHERE project_id = ? AND agent_key = ?
                    ORDER BY id DESC
                    LIMIT ?
                    ''',
                    (project_id, agent_key, q_limit)
                ) or []

            items: List[Dict] = []
            for row in rows:
                item = dict(row)
                item['direction'] = '上线' if str(item.get('edge_state_to') or '').lower() == 'online' else '下线'
                observed = item.get('observed_at')
                created = item.get('created_at')
                item['observed_at'] = str(observed) if observed is not None else None
                item['created_at'] = str(created) if created is not None else None
                items.append(item)
            return items
        except Exception as e:
            self.logger.error(f"查询Agent状态历史失败: agent={agent_key}, err={e}")
            return []

    def clear_agent_status_history(self, project_id: str, agent_key: str) -> int:
        table_name = self.db.get_table_name('agent_status_events')
        try:
            if self.db.db_type == 'mysql':
                count_row = self.db.fetch_one(
                    f"SELECT COUNT(*) AS count FROM {table_name} WHERE project_id = %s AND agent_key = %s",
                    (project_id, agent_key)
                )
            else:
                count_row = self.db.fetch_one(
                    f"SELECT COUNT(*) AS count FROM {table_name} WHERE project_id = ? AND agent_key = ?",
                    (project_id, agent_key)
                )
            affected = int((count_row or {}).get('count') or 0)

            if self.db.db_type == 'mysql':
                self.db.execute_query(
                    f"DELETE FROM {table_name} WHERE project_id = %s AND agent_key = %s",
                    (project_id, agent_key)
                )
            else:
                self.db.execute_query(
                    f"DELETE FROM {table_name} WHERE project_id = ? AND agent_key = ?",
                    (project_id, agent_key)
                )
            return affected
        except Exception as e:
            self.logger.error(f"清空Agent状态历史失败: agent={agent_key}, err={e}")
            return -1

    def get_project(self, project_id: str) -> Optional[ProjectInfo]:
        with self.lock:
            return self.projects.get(project_id)

    def list_projects(self) -> List[Dict]:
        table_name = self.db.get_table_name('agent_status')
        try:
            rows = self.db.fetch_all(
                f"SELECT project_id, COUNT(*) AS agent_count, "
                f"SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END) AS online_agents, "
                f"MAX(updated_at) AS last_refresh "
                f"FROM {table_name} GROUP BY project_id ORDER BY project_id ASC"
            ) or []
            return [
                {
                    'id': row.get('project_id') or '',
                    'agent_count': int(row.get('agent_count') or 0),
                    'online_agents': int(row.get('online_agents') or 0),
                    'last_refresh': str(row.get('last_refresh')) if row.get('last_refresh') else None,
                    'agents': []
                }
                for row in rows if row.get('project_id') is not None
            ]
        except Exception:
            with self.lock:
                return [project.to_dict() for project in self.projects.values()]

    def get_project_agents(self, project_id: str) -> List[Dict]:
        agents, _ = self.list_agents(1, 10000, project_id)
        return agents

    def get_agent(self, key: str) -> Optional[AgentInfo]:
        with self.lock:
            agent = self.agents.get(key)
        if agent:
            return agent
        return self.ensure_agent_exists(key)

    def ensure_agent_exists(self, agent_key: str) -> Optional[AgentInfo]:
        """
        确保指定agent存在：
        1. 先查内存
        2. 再查数据库
        3. 最后从Nacos扫描并按agent_key反查创建
        """
        if not agent_key:
            return None

        # 1) 内存命中
        with self.lock:
            cached = self.agents.get(agent_key)
        if cached:
            return cached

        # 2) DB命中并回填内存
        try:
            table_name = self.db.get_table_name('agent_status')
            if self.db.db_type == 'mysql':
                row = self.db.fetch_one(
                    f"SELECT * FROM {table_name} WHERE agent_key = %s LIMIT 1",
                    (agent_key,)
                )
            else:
                row = self.db.fetch_one(
                    f"SELECT * FROM {table_name} WHERE agent_key = ? LIMIT 1",
                    (agent_key,)
                )
            if row:
                restored = AgentInfo(
                    key=row.get('agent_key') or agent_key,
                    ip_address=row.get('ip_address') or '',
                    hostname=row.get('hostname') or '',
                    project_id=row.get('project_id') or '',
                    full_name=row.get('full_name') or '',
                    status=row.get('status') or 'unknown',
                    pod_id=row.get('pod_id') or self.pod_id
                )
                last_seen = row.get('last_seen')
                if last_seen:
                    try:
                        restored.last_seen = datetime.fromisoformat(str(last_seen))
                    except Exception:
                        restored.last_seen = datetime.now()

                system_info = row.get('system_info')
                if system_info:
                    if isinstance(system_info, str):
                        try:
                            restored.system_info = json.loads(system_info)
                        except Exception:
                            restored.system_info = {}
                    elif isinstance(system_info, dict):
                        restored.system_info = system_info

                daemon_info = row.get('daemon_info')
                if daemon_info:
                    if isinstance(daemon_info, str):
                        try:
                            restored.daemon_info = json.loads(daemon_info)
                        except Exception:
                            restored.daemon_info = {}
                    elif isinstance(daemon_info, dict):
                        restored.daemon_info = daemon_info

                services = row.get('services')
                if services:
                    if isinstance(services, str):
                        try:
                            restored.services = json.loads(services)
                        except Exception:
                            restored.services = []
                    elif isinstance(services, list):
                        restored.services = services

                with self.lock:
                    self.agents[restored.key] = restored
                    if restored.project_id:
                        self._update_project(restored.project_id, restored.key)

                self.logger.info(f"通过数据库恢复Agent成功: {agent_key}")
                return restored
        except Exception as e:
            self.logger.warning(f"数据库恢复Agent失败: key={agent_key}, err={e}")

        # 3) Nacos反查发现并创建
        try:
            services = self._fetch_nacos_services()
            for service in services:
                parsed = self._parse_agent_name(service)
                if not parsed:
                    continue
                project_id, hostname, ip_address = parsed
                discovered_key = self._get_agent_key(hostname, ip_address, service)
                if discovered_key != agent_key:
                    continue

                discovered = AgentInfo(
                    key=agent_key,
                    ip_address=ip_address,
                    hostname=hostname,
                    project_id=project_id,
                    full_name=service,
                    status='unknown',
                    pod_id=self.pod_id
                )

                # 尽量更新在线状态（失败也不阻塞自动创建）
                try:
                    self._check_secflow_agent_agent_status(discovered)
                except Exception:
                    pass

                self._save_agent_to_db(
                    discovered,
                    reason_code='auto_discover',
                    reason_message='agent discovered from nacos by key lookup',
                    source='auto_discover'
                )
                with self.lock:
                    self.agents[discovered.key] = discovered
                    self._update_project(discovered.project_id, discovered.key)

                self.logger.info(
                    f"通过Nacos自动创建Agent成功: key={agent_key}, project={project_id}, ip={ip_address}, host={hostname}"
                )
                return discovered
        except Exception as e:
            self.logger.warning(f"Nacos反查自动创建Agent失败: key={agent_key}, err={e}")

        return None

    def list_agents(self, page: int = 1, per_page: int = 20,
                    project_id: str = None) -> Tuple[List[Dict], int]:
        table_name = self.db.get_table_name('agent_status')

        def _decode_row(row: Dict) -> Optional[Dict]:
            key = row.get('agent_key')
            if not key:
                return None

            data = {
                'key': key,
                'ip_address': row.get('ip_address'),
                'hostname': row.get('hostname'),
                'project_id': row.get('project_id'),
                'full_name': row.get('full_name'),
                'status': row.get('status') or 'unknown',
                'pod_id': row.get('pod_id'),
                'updated_at': str(row.get('updated_at')) if row.get('updated_at') else None,
            }

            last_seen = row.get('last_seen')
            if last_seen:
                data['last_seen'] = str(last_seen)

            system_info = row.get('system_info')
            if system_info:
                if isinstance(system_info, str):
                    try:
                        data['system_info'] = json.loads(system_info)
                    except Exception:
                        data['system_info'] = {}
                else:
                    data['system_info'] = system_info

            daemon_info = row.get('daemon_info')
            if daemon_info:
                if isinstance(daemon_info, str):
                    try:
                        data['daemon_info'] = json.loads(daemon_info)
                    except Exception:
                        data['daemon_info'] = {}
                else:
                    data['daemon_info'] = daemon_info

            services = row.get('services')
            if services:
                if isinstance(services, str):
                    try:
                        data['services'] = json.loads(services)
                    except Exception:
                        data['services'] = []
                else:
                    data['services'] = services

            return data

        memory_agents: Dict[str, Dict] = {}
        lock_acquired = self.lock.acquire(timeout=0.2)
        try:
            if lock_acquired:
                memory_agents = {
                    key: agent.to_dict()
                    for key, agent in self.agents.items()
                    if (not project_id) or agent.project_id == project_id
                }
            else:
                self.logger.warning(
                    f"list_agents 获取内存锁超时，回退到数据库快照: project_id={project_id or '*'}"
                )
        finally:
            if lock_acquired:
                self.lock.release()

        if project_id:
            if self.db.db_type == 'mysql':
                rows = self.db.fetch_all(
                    f"SELECT * FROM {table_name} WHERE project_id = %s ORDER BY updated_at DESC",
                    (project_id,)
                )
            else:
                rows = self.db.fetch_all(
                    f"SELECT * FROM {table_name} WHERE project_id = ? ORDER BY updated_at DESC",
                    (project_id,)
                )

            agents_map: Dict[str, Dict] = {}
            for row in rows or []:
                decoded = _decode_row(row)
                if decoded:
                    agents_map[decoded['key']] = decoded

            for key, agent_data in memory_agents.items():
                existing = agents_map.get(key)
                if not existing:
                    agents_map[key] = agent_data
                    continue
                # 多副本部署下以数据库快照为主，避免不同POD内存态覆盖导致前端状态横跳；
                # 仅在数据库缺失时使用内存字段做补齐。
                for field_name in ('system_info', 'daemon_info', 'services'):
                    if not existing.get(field_name) and agent_data.get(field_name):
                        existing[field_name] = agent_data.get(field_name)
                agents_map[key] = existing

            agents_list = list(agents_map.values())
            for item in agents_list:
                status = (item.get('status') or 'unknown').lower()
                stale_ref = self._latest_stale_reference(item.get('last_seen'), item.get('updated_at'))
                if status == 'online' and stale_ref:
                    try:
                        # 优先使用较新的时间基准，避免 last_seen 旧值覆盖 updated_at 新值导致误判离线。
                        if datetime.now() - stale_ref > timedelta(minutes=5):
                            status = 'offline'
                            item['status'] = 'offline'
                            item['status_reason'] = '节点超过5分钟未上报心跳，已自动视为离线'
                    except Exception:
                        pass
                item['is_allowed'] = status == 'online'
                item['is_offline'] = status in {'offline', 'error', 'timeout', 'unknown'}
                item['allow_reason'] = '在线可调度' if item['is_allowed'] else f"状态为 {status}，不可调度"

            total = len(agents_list)
            start_idx = (page - 1) * per_page
            end_idx = start_idx + per_page
            return agents_list[start_idx:end_idx], total

        if self.db.db_type == 'mysql':
            rows = self.db.fetch_all(
                f"SELECT * FROM {table_name} ORDER BY updated_at DESC"
            )
        else:
            rows = self.db.fetch_all(
                f"SELECT * FROM {table_name} ORDER BY updated_at DESC"
            )

        agents_map: Dict[str, Dict] = {}
        for row in rows or []:
            decoded = _decode_row(row)
            if decoded:
                agents_map[decoded['key']] = decoded

        for key, agent_data in memory_agents.items():
            existing = agents_map.get(key)
            if not existing:
                agents_map[key] = agent_data
                continue
            # 多副本部署下以数据库快照为主，避免不同POD内存态覆盖导致状态抖动。
            for field_name in ('system_info', 'daemon_info', 'services'):
                if not existing.get(field_name) and agent_data.get(field_name):
                    existing[field_name] = agent_data.get(field_name)
            agents_map[key] = existing

        agents_list = list(agents_map.values())
        total = len(agents_list)
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        return agents_list[start_idx:end_idx], total

    def call_agent_api(self, agent_key: str, method: str, endpoint: str,
                       data: Any = None, params: Dict = None,
                       headers: Dict = None, files: Dict = None,
                       stream: bool = False, timeout_type: str = 'default',
                       log_connection_error: bool = True) -> Tuple[int, Any]:
        """
        调用Agent API（增强版，支持文件上传和可配置超时）

        Args:
            agent_key: Agent标识符
            method: HTTP方法
            endpoint: API端点
            data: 请求数据
            params: 查询参数
            headers: 请求头
            files: 上传的文件
            stream: 是否流式响应
            timeout_type: 超时类型，对应配置中的超时设置
        """
        agent = self.get_agent(agent_key)
        if not agent:
            return 404, {'error': 'Agent not found'}

        try:
            url = f"http://{agent.ip_address}:{self.agent_api_port}{endpoint}"

            # 获取超时设置
            if timeout_type in self.timeouts:
                timeout = self.timeouts[timeout_type]
            else:
                timeout = self.timeouts['default']

            self.logger.debug(f"调用Agent API: {method} {url}, 超时设置: {timeout}, 类型: {timeout_type}")

            # 构建请求头
            request_headers = {
                'X-Auth-Token': self.agent_auth_token,
            }

            # 添加自定义请求头
            if headers:
                request_headers.update(headers)

            # 准备请求参数
            request_kwargs = {
                'headers': request_headers,
                'params': params,
                'timeout': timeout,
                'stream': stream
            }

            # 处理文件上传
            if files:
                # 文件上传时不设置Content-Type，让requests自动设置multipart/form-data
                if 'Content-Type' in request_headers:
                    del request_headers['Content-Type']

                # 处理文件数据
                files_to_send = {}
                for key, file_info in files.items():
                    if isinstance(file_info, tuple) and len(file_info) == 3:
                        # 已经是(filename, content, content_type)格式
                        filename, content, content_type = file_info
                        if isinstance(content, bytes):
                            files_to_send[key] = (filename, content, content_type)
                        else:
                            # 如果是路径，读取文件
                            if isinstance(content, (str, Path)):
                                file_path = Path(content)
                                if file_path.exists():
                                    with open(file_path, 'rb') as f:
                                        file_content = f.read()
                                    files_to_send[key] = (filename, file_content, content_type)
                                else:
                                    self.logger.warning(f"文件不存在: {content}")
                                    continue
                            else:
                                self.logger.warning(f"不支持的文件内容类型: {type(content)}")
                                continue
                    elif isinstance(file_info, dict):
                        # 字典格式
                        filename = file_info.get('filename', 'file')
                        content = file_info.get('content', b'')
                        content_type = file_info.get('content_type', 'application/octet-stream')

                        if isinstance(content, bytes):
                            files_to_send[key] = (filename, content, content_type)
                        else:
                            self.logger.warning(f"文件内容不是字节类型: {type(content)}")
                            continue
                    else:
                        self.logger.warning(f"不支持的文件格式: {type(file_info)}")
                        continue

                if files_to_send:
                    request_kwargs['files'] = files_to_send

                    # 如果有其他数据，作为multipart表单字段
                    if data:
                        request_kwargs['data'] = data
                else:
                    self.logger.warning("没有有效的文件可上传")
                    return 400, {'error': 'No valid files to upload'}

            elif data is not None and method.upper() in ['POST', 'PUT', 'PATCH', 'DELETE']:
                # 非文件上传时，设置JSON内容
                request_kwargs['json'] = data
                if 'Content-Type' not in request_headers:
                    request_headers['Content-Type'] = 'application/json'

            # 发送请求。对同步类GET请求做一次短重试，降低瞬时网络抖动导致的误失败。
            method_upper = method.upper()
            max_attempts = 4 if method_upper == 'GET' and timeout_type in ('proxy', 'health_check') else 1
            response = None
            last_request_exc = None
            for attempt in range(max_attempts):
                try:
                    if method_upper == 'GET':
                        response = requests.get(url, **request_kwargs)
                    elif method_upper == 'POST':
                        response = requests.post(url, **request_kwargs)
                    elif method_upper == 'PUT':
                        response = requests.put(url, **request_kwargs)
                    elif method_upper == 'DELETE':
                        response = requests.delete(url, **request_kwargs)
                    elif method_upper == 'PATCH':
                        response = requests.patch(url, **request_kwargs)
                    else:
                        return 400, {'error': f'Unsupported method: {method}'}
                    break
                except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as req_exc:
                    last_request_exc = req_exc
                    if attempt >= max_attempts - 1:
                        raise
                    time.sleep(0.2 * (2 ** attempt))

            # 处理响应
            content_type = response.headers.get('Content-Type', '').lower()

            if stream:
                # 返回原始响应对象，由调用者处理
                return response.status_code, response.raw

            # 解析响应
            if 'application/json' in content_type:
                try:
                    response_data = response.json() if response.content else {}
                except json.JSONDecodeError:
                    response_data = {'raw_response': response.text}
            elif 'text/' in content_type:
                response_data = response.text
            else:
                # 二进制响应
                response_data = response.content

            self.logger.debug(f"Agent API响应: 状态码={response.status_code}, 耗时={response.elapsed.total_seconds():.2f}秒")
            return response.status_code, response_data

        except requests.exceptions.Timeout:
            self.logger.error(f"请求Agent {agent_key} 超时 (超时设置: {timeout})")
            return 504, {'error': f'Request timeout to agent (timeout: {timeout})'}
        except requests.exceptions.ConnectionError:
            if log_connection_error:
                self.logger.error(f"连接Agent {agent_key} 失败")
            else:
                self.logger.debug(f"连接Agent {agent_key} 失败 (method={method}, endpoint={endpoint})")
            return 503, {'error': 'Connection failed to agent'}
        except Exception as e:
            self.logger.error(f"调用Agent API失败: {str(e)}", exc_info=True)
            return 500, {'error': f'API call failed: {str(e)}'}
