import os
import sys
import json
import yaml
import time
import uuid
import hashlib
import shutil
import zipfile
import threading
import logging
import argparse
import tempfile
import mimetypes
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, asdict, field
from concurrent.futures import ThreadPoolExecutor, Future
import redis
import requests
from urllib.parse import urlparse
import base64
import io
from flask import send_file, redirect
import tarfile
import traceback

import redis
from .db import DatabaseManager
from .agent_manager import AgentManager
from .enhanced_template_manager import EnhancedTemplateManager
from .redis_manager import RedisManager
from .model import TaskInfo

import json
import logging
import time

from concurrent.futures import ThreadPoolExecutor

import base64
import requests

# ===================== 任务管理器（支持多种压缩格式） =====================
# ===================== 任务管理器（支持多种压缩格式） =====================

class TaskManager:
    """任务管理器（支持多种压缩格式）"""
    def __init__(self, db_manager: DatabaseManager, agent_manager: AgentManager,
                 template_manager: EnhancedTemplateManager, services_root: str,
                 redis_manager: RedisManager, pod_id: str, max_secflow_agent_task_logs: int = 1000,
                 agent_api_timeouts: Dict = None):
        self.db = db_manager
        self.agent_manager = agent_manager
        self.template_manager = template_manager
        self.services_root = Path(services_root)
        self.redis_manager = redis_manager
        self.pod_id = pod_id
        self.max_secflow_agent_task_logs = max_secflow_agent_task_logs

        # 设置超时配置
        self.timeouts = agent_api_timeouts or {
            'default': (10, 30),
            'health_check': (5, 10),
            'deploy_create': (10, 60),
            'deploy_start': (10, 300),
            'deploy_stop': (10, 120),
            'deploy_delete': (10, 60),
            'undeploy': (10, 180),
            'file_upload': (10, 600),
            'stream': (10, 3600),
            'proxy': (10, 300),
        }

        self.services_root.mkdir(parents=True, exist_ok=True)
        self.executor = ThreadPoolExecutor(max_workers=5)
        self.active_tasks: Dict[str, Future] = {}
        self.logger = logging.getLogger(__name__)

        self._cleanup_old_logs()

    def _cleanup_old_logs(self):
        try:
            cutoff_date = (datetime.now() - timedelta(days=7)).isoformat()
            table_name = self.db.get_table_name('task_logs')
            if self.db.db_type == 'mysql':
                self.db.execute_query(f'''
                                      DELETE FROM {table_name}
                                      WHERE timestamp < %s
                                      ''', (cutoff_date,))
            else:
                self.db.execute_query(f'''
                                      DELETE FROM {table_name}
                                      WHERE timestamp < ?
                                      ''', (cutoff_date,))

            self.logger.info("已清理过期任务日志")

        except Exception as e:
            self.logger.error(f"清理过期任务日志失败: {str(e)}")

    def create_task(self, task_type: str, service_name: str, agent_key: str,
                    template_name: str = None, extra_params: Dict = None,
                    project_id: str = None) -> str:
        task_id = str(uuid.uuid4())
        table_tasks = self.db.get_table_name('tasks')

        # Use provided project_id or get from agent
        if not project_id:
            agent = self.agent_manager.get_agent(agent_key)
            project_id = agent.project_id if agent else ''

        if self.db.db_type == 'mysql':
            self.db.execute_query('''
                                  INSERT INTO {}
                                  (task_id, task_type, service_name, agent_key, project_id,
                                   status, progress, message, created_at, pod_id)
                                  VALUES (%s, %s, %s, %s, %s, 'pending', 0, '', NOW(), %s)
                                  '''.format(table_tasks), (task_id, task_type, service_name, agent_key, project_id, self.pod_id))
        else:
            self.db.execute_query('''
                                  INSERT INTO {}
                                  (task_id, task_type, service_name, agent_key, project_id,
                                   status, progress, message, created_at, pod_id)
                                  VALUES (?, ?, ?, ?, ?, 'pending', 0, '', datetime('now'), ?)
                                  '''.format(table_tasks), (task_id, task_type, service_name, agent_key, project_id, self.pod_id))

        # 添加任务日志
        self._add_task_log(task_id, 'INFO', f"任务创建: {task_type} {service_name} on agent {agent_key}")

        future = self.executor.submit(
            self._execute_task, task_id, task_type, service_name,
            agent_key, template_name, extra_params
        )

        self.active_tasks[task_id] = future
        future.add_done_callback(lambda f: self.active_tasks.pop(task_id, None))

        return task_id

    def _execute_task(self, task_id: str, task_type: str, service_name: str,
                      agent_key: str, template_name: str, extra_params: Dict):
        if task_type == 'deploy':
            self._deploy_service(task_id, service_name, agent_key, template_name, extra_params)
        elif task_type == 'undeploy':
            self._undeploy_service(task_id, service_name, agent_key)
        else:
            self._update_task_status(task_id, 'failed', 0, f'未知的任务类型: {task_type}')

    def _add_task_log(self, task_id: str, level: str, message: str):
        try:
            log_id = str(uuid.uuid4())
            table_name = self.db.get_table_name('task_logs')

            if self.db.db_type == 'mysql':
                self.db.execute_query(f'''
                                      INSERT INTO {table_name}
                                          (log_id, task_id, level, message, timestamp, pod_id)
                                      VALUES (%s, %s, %s, %s, NOW(), %s)
                                      ''', (log_id, task_id, level, message, self.pod_id))

                # 限制日志数量
                self.db.execute_query(f'''
                    DELETE tl FROM {table_name} tl
                    JOIN (
                        SELECT id FROM {table_name}
                        WHERE task_id = %s
                        ORDER BY timestamp DESC
                        LIMIT 1 OFFSET %s
                    ) t ON tl.id = t.id
                ''', (task_id, self.max_secflow_agent_task_logs))

            else:
                self.db.execute_query(f'''
                                      INSERT INTO {table_name}
                                          (log_id, task_id, level, message, timestamp, pod_id)
                                      VALUES (?, ?, ?, ?, datetime('now'), ?)
                                      ''', (log_id, task_id, level, message, self.pod_id))

                # 限制日志数量
                self.db.execute_query(f'''
                                      DELETE FROM {table_name}
                                      WHERE id IN (
                                          SELECT id FROM {table_name}
                                          WHERE task_id = ?
                                          ORDER BY timestamp DESC
                                          LIMIT -1 OFFSET ?
                                          )
                                      ''', (task_id, self.max_secflow_agent_task_logs))

        except Exception as e:
            self.logger.error(f"添加任务日志失败: {str(e)}")

    def _update_task_status(self, task_id: str, status: str, progress: int = 0,
                            message: str = ''):
        table_tasks = self.db.get_table_name('tasks')
        update_fields = []
        params = []

        if status:
            update_fields.append("status = %s" if self.db.db_type == 'mysql' else "status = ?")
            params.append(status)

        if progress is not None:
            update_fields.append("progress = %s" if self.db.db_type == 'mysql' else "progress = ?")
            params.append(progress)

        if message is not None:
            update_fields.append("message = %s" if self.db.db_type == 'mysql' else "message = ?")
            params.append(message)

        if status == 'running':
            update_fields.append("started_at = NOW()" if self.db.db_type == 'mysql' else "started_at = datetime('now')")
        elif status in ['success', 'failed', 'cancelled']:
            update_fields.append("completed_at = NOW()" if self.db.db_type == 'mysql' else "completed_at = datetime('now')")

        if update_fields:
            query = f"UPDATE {table_tasks} SET {', '.join(update_fields)} WHERE task_id = "
            query += "%s" if self.db.db_type == 'mysql' else "?"
            params.append(task_id)
            self.db.execute_query(query, tuple(params))

        log_level = 'INFO'
        if status == 'failed':
            log_level = 'ERROR'
        elif status == 'cancelled':
            log_level = 'WARNING'

        if message:
            self._add_task_log(task_id, log_level, message)

    def _get_content_type(self, filename: str) -> str:
        """根据文件名获取Content-Type"""
        filename_lower = filename.lower()

        if filename_lower.endswith('.zip'):
            return 'application/zip'
        elif filename_lower.endswith('.tar'):
            return 'application/x-tar'
        elif filename_lower.endswith('.tar.gz') or filename_lower.endswith('.tgz'):
            return 'application/gzip'
        elif filename_lower.endswith('.tar.bz2') or filename_lower.endswith('.tbz') or filename_lower.endswith('.tbz2'):
            return 'application/x-bzip2'
        elif filename_lower.endswith('.tar.xz') or filename_lower.endswith('.txz'):
            return 'application/x-xz'
        else:
            return 'application/octet-stream'

    def _deploy_service(self, task_id: str, service_name: str, agent_key: str,
                        template_name: str, extra_params: Dict = None):
        """部署服务（支持多种压缩格式）"""
        try:
            self._update_task_status(task_id, 'running', 10, '开始部署')

            # 1. 检查Agent是否存在
            agent = self.agent_manager.get_agent(agent_key)
            if not agent:
                self._update_task_status(task_id, 'failed', 0, f'Agent {agent_key} 不存在')
                return

            self._add_task_log(task_id, 'INFO', f"目标Agent: {agent.hostname} ({agent.ip_address})")
            self._add_task_log(task_id, 'INFO', f"服务名称: {service_name}")
            self._add_task_log(task_id, 'INFO', f"使用模板: {template_name}")

            # 2. 检查模板是否存在
            if not template_name:
                self._update_task_status(task_id, 'failed', 0, '未指定模板名称')
                return

            self._update_task_status(task_id, 'running', 20, '检查模板')

            template = self.template_manager.get_template(template_name)
            if not template:
                self._update_task_status(task_id, 'failed', 0, f'模板 {template_name} 不存在')
                return

            template_type = template['type']
            self._add_task_log(task_id, 'INFO', f"模板类型: {template_type}")

            # 3. 根据模板类型处理
            if template_type == 'yaml':
                # YAML模板部署
                self._deploy_yaml_template(task_id, service_name, agent_key, template_name, extra_params)

            elif template_type == 'archive':
                # 压缩模板部署（支持多种格式）
                self._deploy_archive_template(task_id, service_name, agent_key, template_name, extra_params)

            else:
                error_msg = f'不支持的模板类型: {template_type}'
                self._update_task_status(task_id, 'failed', 0, error_msg)

        except Exception as e:
            self.logger.error(f"部署服务失败: {str(e)}", exc_info=True)
            self._update_task_status(task_id, 'failed', 0, f'部署失败: {str(e)}')
            self._add_task_log(task_id, 'ERROR', f"异常详情: {traceback.format_exc()}")
    def _deploy_yaml_template(self, task_id: str, service_name: str, agent_key: str,
                              template_name: str, extra_params: Dict = None):
        """部署YAML模板"""
        # 获取YAML内容
        success, yaml_content, error_msg = self.template_manager.get_yaml_content(template_name)
        if not success:
            self._update_task_status(task_id, 'failed', 30, f'获取YAML内容失败: {yaml_content}')
            return

        self._add_task_log(task_id, 'INFO', f"YAML内容大小: {len(yaml_content)} 字符")

        # 准备部署数据
        data = {
            'name': service_name,
            'yaml': yaml_content
        }

        # 添加额外参数（如果有）
        if extra_params:
            data.update(extra_params)

        self._add_task_log(task_id, 'INFO', f"调用Agent API创建服务: {service_name}")

        # 调用Agent API创建服务（使用较长的超时）
        self._add_task_log(task_id, 'INFO', f"创建服务，超时设置: {self.timeouts['deploy_create']}")
        status_code, response = self.agent_manager.call_agent_api(
            agent_key, 'POST', '/api/services/yaml', data,
            timeout_type='deploy_create'
        )

        self._add_task_log(task_id, 'INFO', f"Agent响应状态码: {status_code}")
        self._add_task_log(task_id, 'DEBUG', f"Agent响应内容: {json.dumps(response)[:200]}...")

        # 处理响应
        if status_code == 201:
            self._update_task_status(task_id, 'running', 70, '服务创建成功，正在启动')
            time.sleep(2)

            # 启动服务（使用更长的超时，因为可能需要下载镜像）
            self._add_task_log(task_id, 'INFO', f"启动服务，超时设置: {self.timeouts['deploy_start']}")
            start_status_code, start_response = self.agent_manager.call_agent_api(
                agent_key, 'POST', f'/api/services/{service_name}/start', {},
                timeout_type='deploy_start'
            )

            if start_status_code == 200:
                self._update_task_status(task_id, 'success', 100, '服务部署成功')
                self._add_task_log(task_id, 'INFO', '服务部署完成')
            else:
                error_msg = f'启动服务失败: {start_response}'
                self._update_task_status(task_id, 'failed', 70, error_msg)
                self._add_task_log(task_id, 'ERROR', error_msg)

                # 尝试清理创建的服务
                self._add_task_log(task_id, 'WARN', '尝试清理已创建的服务')
                self._add_task_log(task_id, 'INFO', f"停止服务，超时设置: {self.timeouts['deploy_stop']}")
                self.agent_manager.call_agent_api(
                    agent_key, 'POST', f'/api/services/{service_name}/stop', {},
                    timeout_type='deploy_stop'
                )

                time.sleep(2)

                self._add_task_log(task_id, 'INFO', f"删除服务，超时设置: {self.timeouts['deploy_delete']}")
                self.agent_manager.call_agent_api(
                    agent_key, 'DELETE', f'/api/services/{service_name}', {},
                    timeout_type='deploy_delete'
                )

        elif status_code == 409:
            # 服务已存在，重新创建
            self._update_task_status(task_id, 'running', 70, '服务已存在，尝试重新创建')
            self._add_task_log(task_id, 'INFO', '停止现有服务')

            # 先停止并删除现有服务
            self.agent_manager.call_agent_api(
                agent_key, 'POST', f'/api/services/{service_name}/stop', {},
                timeout_type='deploy_stop'
            )

            time.sleep(3)

            self._add_task_log(task_id, 'INFO', '删除现有服务')
            self.agent_manager.call_agent_api(
                agent_key, 'DELETE', f'/api/services/{service_name}', {},
                timeout_type='deploy_delete'
            )

            time.sleep(2)

            # 重新创建服务
            self._add_task_log(task_id, 'INFO', '重新创建服务')
            status_code, response = self.agent_manager.call_agent_api(
                agent_key, 'POST', '/api/services/yaml', data,
                timeout_type='deploy_create'
            )

            if status_code == 201:
                # 启动服务
                time.sleep(2)
                start_status_code, start_response = self.agent_manager.call_agent_api(
                    agent_key, 'POST', f'/api/services/{service_name}/start', {},
                    timeout_type='deploy_start'
                )

                if start_status_code == 200:
                    self._update_task_status(task_id, 'success', 100, '服务重新部署成功')
                else:
                    error_msg = f'重新部署后启动服务失败: {start_response}'
                    self._update_task_status(task_id, 'failed', 70, error_msg)
            else:
                error_msg = f'重新创建服务失败: {response}'
                self._update_task_status(task_id, 'failed', 70, error_msg)

        else:
            error_msg = f'创建服务失败 (HTTP {status_code}): {response}'
            self._update_task_status(task_id, 'failed', 30, error_msg)
            self._add_task_log(task_id, 'ERROR', error_msg)

    def _deploy_archive_template(self, task_id: str, service_name: str, agent_key: str,
                                 template_name: str, extra_params: Dict = None):
        """部署压缩模板（支持多种格式）"""
        self._update_task_status(task_id, 'running', 30, '处理压缩模板')

        # 获取模板文件路径
        template_file = self.template_manager.get_template_file(template_name)
        if not template_file:
            self._update_task_status(task_id, 'failed', 30, '压缩模板文件不存在')
            return

        self._add_task_log(task_id, 'INFO', f"压缩文件: {template_file}")

        # 读取压缩文件内容
        with open(template_file, 'rb') as f:
            file_content = f.read()

        # 获取文件扩展名
        filename = Path(template_file).name

        # 创建文件字典（符合call_agent_api的文件格式）
        files = {
            'file': (filename, file_content, self._get_content_type(filename))
        }

        data = {
            'name': service_name
        }

        # 添加额外参数
        if extra_params:
            data.update(extra_params)

        self._add_task_log(task_id, 'INFO', f"上传压缩文件到Agent: {filename}")

        # 调用Agent的压缩文件部署接口（使用文件上传的超时）
        self._add_task_log(task_id, 'INFO', f"上传文件，超时设置: {self.timeouts['file_upload']}")
        status_code, response = self.agent_manager.call_agent_api(
            agent_key, 'POST', '/api/services/zip', data=data, files=files,
            timeout_type='file_upload'
        )

        self._add_task_log(task_id, 'INFO', f"Agent响应状态码: {status_code}")
        self._add_task_log(task_id, 'DEBUG', f"Agent响应内容: {json.dumps(response)[:200]}...")

        if status_code == 201:
            self._update_task_status(task_id, 'running', 70, '压缩服务创建成功，正在启动')

            # 等待几秒让服务创建完成
            time.sleep(3)

            self._add_task_log(task_id, 'INFO', f"启动服务: {service_name}")

            # 启动服务（使用较长的超时）
            self._add_task_log(task_id, 'INFO', f"启动服务，超时设置: {self.timeouts['deploy_start']}")
            start_status_code, start_response = self.agent_manager.call_agent_api(
                agent_key, 'POST', f'/api/services/{service_name}/start', {},
                timeout_type='deploy_start'
            )

            if start_status_code == 200:
                self._update_task_status(task_id, 'success', 100, '压缩服务部署成功')
                self._add_task_log(task_id, 'INFO', '压缩服务部署完成')
            else:
                error_msg = f'启动压缩服务失败: {start_response}'
                self._update_task_status(task_id, 'failed', 70, error_msg)
                self._add_task_log(task_id, 'ERROR', error_msg)
        else:
            error_msg = f'创建压缩服务失败 (HTTP {status_code}): {response}'
            self._update_task_status(task_id, 'failed', 30, error_msg)
            self._add_task_log(task_id, 'ERROR', error_msg)

    def _undeploy_service(self, task_id: str, service_name: str, agent_key: str):
        """卸载服务"""
        try:
            self._update_task_status(task_id, 'running', 10, '开始卸载服务')

            agent = self.agent_manager.get_agent(agent_key)
            if not agent:
                self._update_task_status(task_id, 'failed', 0, f'Agent {agent_key} 不存在')
                return

            self._add_task_log(task_id, 'INFO', f"目标Agent: {agent.hostname} ({agent.ip_address})")
            self._add_task_log(task_id, 'INFO', f"服务名称: {service_name}")

            # 停止服务（使用较长的超时）
            self._add_task_log(task_id, 'INFO', '停止服务')
            self._add_task_log(task_id, 'INFO', f"超时设置: {self.timeouts['undeploy']}")
            stop_status_code, stop_response = self.agent_manager.call_agent_api(
                agent_key, 'POST', f'/api/services/{service_name}/stop', {},
                timeout_type='undeploy'
            )

            if stop_status_code not in [200, 404]:
                self._update_task_status(task_id, 'failed', 30, f'停止服务失败: {stop_response}')
                return

            time.sleep(2)

            # 删除服务
            self._add_task_log(task_id, 'INFO', '删除服务')
            delete_status_code, delete_response = self.agent_manager.call_agent_api(
                agent_key, 'DELETE', f'/api/services/{service_name}', {},
                timeout_type='undeploy'
            )

            if delete_status_code in [200, 204, 404]:
                self._update_task_status(task_id, 'success', 100, '服务卸载成功')
                self._add_task_log(task_id, 'INFO', '服务卸载完成')
            else:
                error_msg = f'删除服务失败 (HTTP {delete_status_code}): {delete_response}'
                self._update_task_status(task_id, 'failed', 50, error_msg)
                self._add_task_log(task_id, 'ERROR', error_msg)

        except Exception as e:
            self.logger.error(f"卸载服务失败: {str(e)}")
            self._update_task_status(task_id, 'failed', 0, f'卸载失败: {str(e)}')


    def get_task(self, task_id: str) -> Optional[Dict]:
        table_tasks = self.db.get_table_name('tasks')
        table_logs = self.db.get_table_name('task_logs')
        task = self.db.fetch_one(
            f"SELECT * FROM {table_tasks} WHERE task_id = %s"
            if self.db.db_type == 'mysql' else
            f"SELECT * FROM {table_tasks} WHERE task_id = ?",
            (task_id,)
        )

        if task:
            log_count = self.db.fetch_one(
                f"SELECT COUNT(*) as count FROM {table_logs} WHERE task_id = %s"
                if self.db.db_type == 'mysql' else
                f"SELECT COUNT(*) as count FROM {table_logs} WHERE task_id = ?",
                (task_id,)
            )
            task['log_count'] = log_count['count'] if log_count else 0

        return task

    def get_secflow_agent_task_logs(self, task_id: str, page: int = 1, per_page: int = 100) -> Tuple[List[Dict], int]:
        offset = (page - 1) * per_page
        table_name = self.db.get_table_name('task_logs')

        if self.db.db_type == 'mysql':
            logs = self.db.fetch_all(f'''
                                     SELECT * FROM {table_name}
                                     WHERE task_id = %s
                                     ORDER BY timestamp ASC
                                         LIMIT %s OFFSET %s
                                     ''', (task_id, per_page, offset))

            count_result = self.db.fetch_one(
                f"SELECT COUNT(*) as count FROM {table_name} WHERE task_id = %s",
                (task_id,)
            )
        else:
            logs = self.db.fetch_all(f'''
                                     SELECT * FROM {table_name}
                                     WHERE task_id = ?
                                     ORDER BY timestamp ASC
                                         LIMIT ? OFFSET ?
                                     ''', (task_id, per_page, offset))

            count_result = self.db.fetch_one(
                f"SELECT COUNT(*) as count FROM {table_name} WHERE task_id = ?",
                (task_id,)
            )

        total = count_result.get('count', 0) if count_result else 0
        return logs, total

    def list_tasks(self, page: int = 1, per_page: int = 20,
                   task_type: str = None, status: str = None,
                   project_id: str = None, agent_key: str = None) -> Tuple[List[Dict], int]:
        table_tasks = self.db.get_table_name('tasks')
        table_logs = self.db.get_table_name('task_logs')
        query = f"SELECT * FROM {table_tasks} WHERE 1=1"
        params = []

        if task_type:
            query += " AND task_type = "
            query += "%s" if self.db.db_type == 'mysql' else "?"
            params.append(task_type)

        if status:
            query += " AND status = "
            query += "%s" if self.db.db_type == 'mysql' else "?"
            params.append(status)

        if project_id:
            query += " AND project_id = "
            query += "%s" if self.db.db_type == 'mysql' else "?"
            params.append(project_id)

        if agent_key:
            query += " AND agent_key = "
            query += "%s" if self.db.db_type == 'mysql' else "?"
            params.append(agent_key)

        query += " ORDER BY created_at DESC"

        count_query = query.replace("SELECT *", "SELECT COUNT(*) as count")
        count_result = self.db.fetch_one(count_query, tuple(params))
        total = count_result.get('count', 0) if count_result else 0

        query += " LIMIT "
        query += "%s OFFSET %s" if self.db.db_type == 'mysql' else "? OFFSET ?"
        offset = (page - 1) * per_page
        params.extend([per_page, offset])

        tasks = self.db.fetch_all(query, tuple(params))

        for task in tasks:
            log_count = self.db.fetch_one(
                f"SELECT COUNT(*) as count FROM {table_logs} WHERE task_id = " +
                ("%s" if self.db.db_type == 'mysql' else "?"),
                (task['task_id'],)
            )
            task['log_count'] = log_count['count'] if log_count else 0

        return tasks, total

    def delete_task(self, task_id: str) -> bool:
        try:
            table_tasks = self.db.get_table_name('tasks')
            table_logs = self.db.get_table_name('task_logs')
            if self.db.db_type == 'mysql':
                self.db.execute_transaction([
                    (f"DELETE FROM {table_logs} WHERE task_id = %s", (task_id,)),
                    (f"DELETE FROM {table_tasks} WHERE task_id = %s", (task_id,))
                ])
            else:
                self.db.execute_transaction([
                    (f"DELETE FROM {table_logs} WHERE task_id = ?", (task_id,)),
                    (f"DELETE FROM {table_tasks} WHERE task_id = ?", (task_id,))
                ])

            future = self.active_tasks.pop(task_id, None)
            if future and not future.done():
                future.cancel()

            self.logger.info(f"任务 {task_id} 删除成功")
            return True
        except Exception as e:
            self.logger.error(f"删除任务失败: {str(e)}")
            return False
