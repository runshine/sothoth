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

        self.services_root.mkdir(parents=True, exist_ok=True)
        self.executor = ThreadPoolExecutor(max_workers=5)
        self.active_tasks: Dict[str, Future] = {}
        self.active_task_lock = threading.Lock()
        self.logger = logging.getLogger(__name__)
        self.worker_id = f"{self.pod_id}:{uuid.uuid4().hex[:8]}"
        self.worker_poll_interval_sec = 2
        self.task_lease_sec = 120
        self.task_heartbeat_interval_sec = 15
        self.enable_task_workers = True
        self.worker_dispatch_thread: Optional[threading.Thread] = None
        self.worker_heartbeat_thread: Optional[threading.Thread] = None
        self.worker_stop_event = threading.Event()
        self.service_sync_callback = None

        self._cleanup_old_logs()

    @staticmethod
    def _is_timeout_error(status_code: int, response: Any) -> bool:
        if status_code != 504:
            return False
        if isinstance(response, dict):
            err = str(response.get('error', '')).lower()
            return 'timeout' in err
        return 'timeout' in str(response).lower()

    @staticmethod
    def _is_running_state(state: str) -> bool:
        return state in {'running', 'active', 'healthy', 'started', 'up'}

    @staticmethod
    def _is_transitional_state(state: str) -> bool:
        return state in {'pulling', 'starting', 'pending', 'creating', 'downloading', 'restarting', 'activating'}

    @staticmethod
    def _is_failed_state(state: str) -> bool:
        return state in {'failed', 'error', 'exited', 'stopped', 'dead'}

    @staticmethod
    def _normalize_service_state(payload: Any) -> str:
        if not isinstance(payload, dict):
            return ''
        real_status = payload.get('real_status')
        if isinstance(real_status, dict):
            operation = real_status.get('operation')
            if isinstance(operation, dict) and operation.get('active'):
                phase = str(operation.get('phase') or '').strip().lower()
                if phase:
                    return phase
            state = real_status.get('status') or real_status.get('state')
            if isinstance(state, str) and state.strip():
                return state.strip().lower()

        state = payload.get('status') or payload.get('state') or payload.get('service_status')
        if isinstance(state, str):
            return state.strip().lower()
        if payload.get('is_running') is True:
            return 'running'
        return ''

    def _get_service_status(self, agent_key: str, service_name: str) -> Tuple[int, Any, str]:
        """查询Agent上服务状态，优先单服务接口，失败时回退到列表接口。"""
        code, resp = self.agent_manager.call_agent_api(
            agent_key, 'GET', f'/api/services/{service_name}', None, timeout_type='health_check'
        )
        if code == 200:
            return code, resp, self._normalize_service_state(resp)

        list_code, list_resp = self.agent_manager.call_agent_api(
            agent_key, 'GET', '/api/services', None, timeout_type='health_check'
        )
        if list_code == 200 and isinstance(list_resp, list):
            target = next((s for s in list_resp if isinstance(s, dict) and s.get('name') == service_name), None)
            if target:
                return 200, target, self._normalize_service_state(target)
            return 404, {'error': 'service not found in list'}, ''
        return code, resp, ''

    def _fail_if_service_already_exists(self, task_id: str, agent_key: str, service_name: str) -> bool:
        """部署前做严格防重检查：若目标节点已有同名服务，直接失败。"""
        try:
            code, payload, _ = self._get_service_status(agent_key, service_name)
            if code == 200:
                message = f'服务 {service_name} 在节点 {agent_key} 上已存在，请先手动删除后再部署'
                self._update_task_status(task_id, 'failed', 20, message)
                self._add_task_log(
                    task_id, 'ERROR',
                    f"{message}; duplicate_payload={str(payload)[:300]}"
                )
                return True
        except Exception as e:
            self._add_task_log(task_id, 'WARN', f"部署前重复检查异常，继续后续流程: {e}")
        return False

    def _wait_service_ready_after_start_timeout(self, task_id: str, agent_key: str, service_name: str) -> bool:
        """
        start接口超时后的兜底检查。
        轮询服务状态，若服务最终进入running则判定成功；若明确失败则判定失败。
        """
        max_wait_sec = int(self.timeouts.get('deploy_start_grace_sec', 7200))
        poll_interval_sec = int(self.timeouts.get('deploy_start_poll_interval_sec', 15))
        deadline = time.time() + max_wait_sec
        next_log_at = 0.0

        self._add_task_log(
            task_id, 'WARN',
            f"启动接口超时，进入状态轮询兜底: 最长等待{max_wait_sec}秒，间隔{poll_interval_sec}秒"
        )

        while time.time() < deadline:
            code, payload, state = self._get_service_status(agent_key, service_name)
            now = time.time()
            if now >= next_log_at:
                self._add_task_log(
                    task_id, 'INFO',
                    f"轮询服务状态: http={code}, state={state or 'unknown'}"
                )
                next_log_at = now + 60

            if code == 200 and self._is_running_state(state):
                self._add_task_log(task_id, 'INFO', "服务在超时后已就绪，判定部署成功")
                return True

            if code == 200 and self._is_transitional_state(state):
                time.sleep(poll_interval_sec)
                continue

            if code == 200 and self._is_failed_state(state):
                self._add_task_log(task_id, 'ERROR', f"服务状态异常: {state}")
                return False

            time.sleep(poll_interval_sec)

        self._add_task_log(task_id, 'ERROR', f"轮询超时，服务仍未进入running: {service_name}")
        return False

    def _get_template_id_by_name(self, template_name: str) -> Optional[int]:
        template_name = str(template_name or '').strip()
        if not template_name:
            return None
        table_name = self.db.get_table_name('service_templates')
        row = self.db.fetch_one(
            f"SELECT id FROM {table_name} WHERE name = %s" if self.db.db_type == 'mysql' else
            f"SELECT id FROM {table_name} WHERE name = ?",
            (template_name,)
        )
        if not row:
            return None
        try:
            return int(row.get('id') if isinstance(row, dict) else row['id'])
        except Exception:
            return None

    def _upsert_service_template_binding(
        self,
        project_id: str,
        agent_key: str,
        service_name: str,
        template_name: str,
        template_id: Optional[int] = None,
        source_task_id: str = ''
    ):
        project_id = str(project_id or '').strip()
        agent_key = str(agent_key or '').strip()
        service_name = str(service_name or '').strip()
        template_name = str(template_name or '').strip()
        if not project_id or not agent_key or not service_name or not template_name:
            return

        table_name = self.db.get_table_name('service_template_bindings')
        if self.db.db_type == 'mysql':
            self.db.execute_query(
                f"""
                INSERT INTO {table_name}
                (project_id, agent_key, service_name, template_id, template_name, source_task_id, source)
                VALUES (%s, %s, %s, %s, %s, %s, 'deploy')
                ON DUPLICATE KEY UPDATE
                    template_id = VALUES(template_id),
                    template_name = VALUES(template_name),
                    source_task_id = VALUES(source_task_id),
                    source = VALUES(source),
                    updated_at = NOW()
                """,
                (project_id, agent_key, service_name, template_id, template_name, source_task_id)
            )
        else:
            now_ts = datetime.now().isoformat()
            self.db.execute_query(
                f"""
                INSERT INTO {table_name}
                (project_id, agent_key, service_name, template_id, template_name, source_task_id, source, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 'deploy', ?, ?)
                ON CONFLICT(project_id, agent_key, service_name) DO UPDATE SET
                    template_id=excluded.template_id,
                    template_name=excluded.template_name,
                    source_task_id=excluded.source_task_id,
                    source=excluded.source,
                    updated_at=excluded.updated_at
                """,
                (project_id, agent_key, service_name, template_id, template_name, source_task_id, now_ts, now_ts)
            )

    def _delete_service_template_binding(self, project_id: str, agent_key: str, service_name: str):
        project_id = str(project_id or '').strip()
        agent_key = str(agent_key or '').strip()
        service_name = str(service_name or '').strip()
        if not project_id or not agent_key or not service_name:
            return
        table_name = self.db.get_table_name('service_template_bindings')
        self.db.execute_query(
            f"DELETE FROM {table_name} WHERE project_id = %s AND agent_key = %s AND service_name = %s"
            if self.db.db_type == 'mysql' else
            f"DELETE FROM {table_name} WHERE project_id = ? AND agent_key = ? AND service_name = ?",
            (project_id, agent_key, service_name)
        )

    def _get_project_id(self, agent_key: str) -> str:
        try:
            agent = self.agent_manager.get_agent(agent_key) or self.agent_manager.ensure_agent_exists(agent_key)
            return str(getattr(agent, 'project_id', '') or '').strip()
        except Exception:
            return ''

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

    def configure_runtime(self, worker_count: int = 5, poll_interval_sec: int = 2,
                          lease_sec: int = 120, heartbeat_interval_sec: int = 15,
                          enable_task_workers: bool = True):
        """配置任务 worker 运行时参数。"""
        worker_count = max(1, int(worker_count or 1))
        if getattr(self.executor, '_max_workers', worker_count) != worker_count:
            self.executor.shutdown(wait=False, cancel_futures=True)
            self.executor = ThreadPoolExecutor(max_workers=worker_count)
        self.worker_poll_interval_sec = max(1, int(poll_interval_sec or 2))
        self.task_lease_sec = max(30, int(lease_sec or 120))
        self.task_heartbeat_interval_sec = max(5, int(heartbeat_interval_sec or 15))
        self.enable_task_workers = bool(enable_task_workers)

    def start_workers(self):
        """启动数据库驱动的任务 worker。"""
        if not self.enable_task_workers:
            self.logger.info("任务 worker 已禁用")
            return
        if self.worker_dispatch_thread and self.worker_dispatch_thread.is_alive():
            return
        self.worker_stop_event.clear()
        self.worker_dispatch_thread = threading.Thread(target=self._worker_dispatch_loop, daemon=True)
        self.worker_heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.worker_dispatch_thread.start()
        self.worker_heartbeat_thread.start()
        self.logger.info(
            f"任务 worker 已启动: worker_id={self.worker_id}, max_workers={getattr(self.executor, '_max_workers', 5)}, "
            f"lease={self.task_lease_sec}s"
        )

    def set_service_sync_callback(self, callback):
        """注册任务完成后的服务状态同步回调。"""
        self.service_sync_callback = callback

    def stop_workers(self):
        """停止任务 worker。"""
        self.worker_stop_event.set()
        if self.worker_dispatch_thread:
            self.worker_dispatch_thread.join(timeout=5)
        if self.worker_heartbeat_thread:
            self.worker_heartbeat_thread.join(timeout=5)
        self.executor.shutdown(wait=False, cancel_futures=False)
        self.logger.info("任务 worker 已停止")

    def _db_now_plus_expr(self, seconds: int) -> str:
        if self.db.db_type == 'mysql':
            return f"DATE_ADD(NOW(), INTERVAL {int(seconds)} SECOND)"
        return f"datetime('now', '+{int(seconds)} seconds')"

    def _db_now_minus_expr(self, seconds: int) -> str:
        if self.db.db_type == 'mysql':
            return f"DATE_SUB(NOW(), INTERVAL {int(seconds)} SECOND)"
        return f"datetime('now', '-{int(seconds)} seconds')"

    def _claim_runnable_task(self) -> Optional[Dict]:
        """从数据库中原子领取一个待执行任务。"""
        table_tasks = self.db.get_table_name('tasks')
        conn = self.db.get_connection()
        try:
            placeholder = '%s' if self.db.db_type == 'mysql' else '?'
            now_sql = 'NOW()' if self.db.db_type == 'mysql' else "datetime('now')"
            candidates_query = (
                f"SELECT task_id FROM {table_tasks} "
                f"WHERE completed_at IS NULL "
                f"AND (status = {placeholder} "
                f"OR (status = {placeholder} "
                f"AND (lease_until IS NULL OR lease_until < {now_sql}))) "
                f"ORDER BY created_at ASC LIMIT 10"
            )
            params = ('pending', 'running')
            candidates = conn.fetch_all(candidates_query, params) or []
            for row in candidates:
                task_id = row.get('task_id')
                if not task_id:
                    continue
                if self.db.db_type == 'mysql':
                    cursor = conn.execute(
                        f"UPDATE {table_tasks} SET "
                        "status = %s, "
                        "worker_id = %s, "
                        "worker_pod_id = %s, "
                        f"lease_until = {self._db_now_plus_expr(self.task_lease_sec)}, "
                        "heartbeat_at = NOW(), "
                        "started_at = COALESCE(started_at, NOW()), "
                        "attempt_count = COALESCE(attempt_count, 0) + 1 "
                        "WHERE task_id = %s AND completed_at IS NULL AND "
                        "(status = %s OR (status = %s AND (lease_until IS NULL OR lease_until < NOW())))",
                        ( 'running', self.worker_id, self.pod_id, task_id, 'pending', 'running')
                    )
                else:
                    cursor = conn.execute(
                        f"UPDATE {table_tasks} SET "
                        "status = ?, "
                        "worker_id = ?, "
                        "worker_pod_id = ?, "
                        f"lease_until = {self._db_now_plus_expr(self.task_lease_sec)}, "
                        "heartbeat_at = datetime('now'), "
                        "started_at = COALESCE(started_at, datetime('now')), "
                        "attempt_count = COALESCE(attempt_count, 0) + 1 "
                        "WHERE task_id = ? AND completed_at IS NULL AND "
                        "(status = ? OR (status = ? AND (lease_until IS NULL OR lease_until < datetime('now'))))",
                        ('running', self.worker_id, self.pod_id, task_id, 'pending', 'running')
                    )
                if getattr(cursor, 'rowcount', 0) == 1:
                    claimed = conn.fetch_one(
                        f"SELECT * FROM {table_tasks} WHERE task_id = {'%s' if self.db.db_type == 'mysql' else '?'}",
                        (task_id,)
                    )
                    if claimed:
                        return claimed
            return None
        finally:
            conn.close()

    def _touch_active_task_leases(self):
        """续约当前 Pod 正在执行的任务。"""
        with self.active_task_lock:
            task_ids = [task_id for task_id, future in self.active_tasks.items() if not future.done()]
        if not task_ids:
            return

        table_tasks = self.db.get_table_name('tasks')
        conn = self.db.get_connection()
        try:
            for task_id in task_ids:
                if self.db.db_type == 'mysql':
                    conn.execute(
                        f"UPDATE {table_tasks} SET heartbeat_at = NOW(), "
                        f"lease_until = {self._db_now_plus_expr(self.task_lease_sec)} "
                        "WHERE task_id = %s AND worker_id = %s AND status = 'running'",
                        (task_id, self.worker_id)
                    )
                else:
                    conn.execute(
                        f"UPDATE {table_tasks} SET heartbeat_at = datetime('now'), "
                        f"lease_until = {self._db_now_plus_expr(self.task_lease_sec)} "
                        "WHERE task_id = ? AND worker_id = ? AND status = 'running'",
                        (task_id, self.worker_id)
                    )
        finally:
            conn.close()

    def _heartbeat_loop(self):
        while not self.worker_stop_event.is_set():
            try:
                self._touch_active_task_leases()
            except Exception as e:
                self.logger.error(f"任务 heartbeat 失败: {e}")
            self.worker_stop_event.wait(self.task_heartbeat_interval_sec)

    def _worker_dispatch_loop(self):
        while not self.worker_stop_event.is_set():
            try:
                with self.active_task_lock:
                    running = sum(1 for future in self.active_tasks.values() if not future.done())
                    capacity = max(0, getattr(self.executor, '_max_workers', 5) - running)
                for _ in range(capacity):
                    task = self._claim_runnable_task()
                    if not task:
                        break
                    task_id = task.get('task_id')
                    future = self.executor.submit(
                        self._run_claimed_task,
                        task_id,
                        task.get('task_type'),
                        task.get('service_name'),
                        task.get('agent_key'),
                        task.get('project_id')
                    )
                    with self.active_task_lock:
                        self.active_tasks[task_id] = future
                    future.add_done_callback(lambda _f, tid=task_id: self._on_task_future_done(tid))
            except Exception as e:
                self.logger.error(f"任务 worker 调度失败: {e}", exc_info=True)
            self.worker_stop_event.wait(self.worker_poll_interval_sec)

    def _on_task_future_done(self, task_id: str):
        with self.active_task_lock:
            self.active_tasks.pop(task_id, None)

    def _notify_service_state_changed(self, agent_key: str, reason: str):
        if not agent_key or not self.service_sync_callback:
            return
        try:
            self.service_sync_callback(agent_key, reason)
        except Exception as e:
            self.logger.warning(f"任务完成后同步服务状态失败: agent={agent_key}, reason={reason}, err={e}")

    def _run_claimed_task(self, task_id: str, task_type: str, service_name: str,
                          agent_key: str, project_id: Optional[str]):
        try:
            task = self.get_task(task_id)
            if not task:
                return
            template_name = task.get('template_name')
            extra_params_raw = task.get('extra_params')
            extra_params = None
            if extra_params_raw:
                if isinstance(extra_params_raw, str):
                    try:
                        extra_params = json.loads(extra_params_raw)
                    except Exception:
                        extra_params = None
                elif isinstance(extra_params_raw, dict):
                    extra_params = extra_params_raw
            self._execute_task(task_id, task_type, service_name, agent_key, template_name, extra_params)
        except Exception as e:
            self.logger.error(f"执行领取任务失败: {task_id}, err={e}", exc_info=True)
            self._update_task_status(task_id, 'failed', 0, f'任务执行异常: {str(e)}')

    def create_task(self, task_type: str, service_name: str, agent_key: str,
                    template_name: str = None, extra_params: Dict = None,
                    project_id: str = None) -> str:
        task_id = str(uuid.uuid4())
        table_tasks = self.db.get_table_name('tasks')
        extra_params_json = json.dumps(extra_params, ensure_ascii=False) if extra_params is not None else None

        # Use provided project_id or get from agent
        if not project_id:
            agent = self.agent_manager.get_agent(agent_key) or self.agent_manager.ensure_agent_exists(agent_key)
            project_id = agent.project_id if agent else ''

        if self.db.db_type == 'mysql':
            self.db.execute_query('''
                                  INSERT INTO {}
                                  (task_id, task_type, service_name, agent_key, project_id, template_name, extra_params,
                                   status, progress, message, created_at, pod_id)
                                  VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending', 0, '', NOW(), %s)
                                  '''.format(table_tasks), (
                                      task_id, task_type, service_name, agent_key, project_id,
                                      template_name, extra_params_json, self.pod_id
                                  ))
        else:
            self.db.execute_query('''
                                  INSERT INTO {}
                                  (task_id, task_type, service_name, agent_key, project_id, template_name, extra_params,
                                   status, progress, message, created_at, pod_id)
                                  VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', 0, '', datetime('now'), ?)
                                  '''.format(table_tasks), (
                                      task_id, task_type, service_name, agent_key, project_id,
                                      template_name, extra_params_json, self.pod_id
                                  ))

        # 添加任务日志
        self._add_task_log(task_id, 'INFO', f"任务创建: {task_type} {service_name} on agent {agent_key}")

        return task_id

    def find_active_task_for_service(self, task_type: str, service_name: str, agent_key: str,
                                     project_id: Optional[str] = None) -> Optional[Dict]:
        """
        查询同项目/同Agent/同服务名是否存在进行中的任务（pending/running）。
        用于部署防重。
        """
        table_tasks = self.db.get_table_name('tasks')
        if self.db.db_type == 'mysql':
            query = f'''
                SELECT * FROM {table_tasks}
                WHERE task_type = %s
                  AND service_name = %s
                  AND agent_key = %s
                  AND project_id = %s
                  AND status IN ('pending', 'running')
                ORDER BY created_at DESC
                LIMIT 1
            '''
        else:
            query = f'''
                SELECT * FROM {table_tasks}
                WHERE task_type = ?
                  AND service_name = ?
                  AND agent_key = ?
                  AND project_id = ?
                  AND status IN ('pending', 'running')
                ORDER BY created_at DESC
                LIMIT 1
            '''
        return self.db.fetch_one(query, (task_type, service_name, agent_key, project_id or ''))

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
            update_fields.append("lease_until = NULL")
            update_fields.append("heartbeat_at = NULL")
            update_fields.append("worker_id = NULL")
            update_fields.append("worker_pod_id = NULL")

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
            agent = self.agent_manager.get_agent(agent_key) or self.agent_manager.ensure_agent_exists(agent_key)
            if not agent:
                self._update_task_status(task_id, 'failed', 0, f'Agent {agent_key} 不存在')
                return

            self._add_task_log(task_id, 'INFO', f"目标Agent: {agent.hostname} ({agent.ip_address})")
            self._add_task_log(task_id, 'INFO', f"服务名称: {service_name}")
            self._add_task_log(task_id, 'INFO', f"使用模板: {template_name}")

            if self._fail_if_service_already_exists(task_id, agent_key, service_name):
                return

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
            template_id = template.get('id')
            self._add_task_log(task_id, 'INFO', f"模板类型: {template_type}")

            # 3. 根据模板类型处理
            if template_type == 'yaml':
                # YAML模板部署
                self._deploy_yaml_template(task_id, service_name, agent_key, template_name, template_id, extra_params)

            elif template_type == 'archive':
                # 压缩模板部署（支持多种格式）
                self._deploy_archive_template(task_id, service_name, agent_key, template_name, template_id, extra_params)

            else:
                error_msg = f'不支持的模板类型: {template_type}'
                self._update_task_status(task_id, 'failed', 0, error_msg)

        except Exception as e:
            self.logger.error(f"部署服务失败: {str(e)}", exc_info=True)
            self._update_task_status(task_id, 'failed', 0, f'部署失败: {str(e)}')
            self._add_task_log(task_id, 'ERROR', f"异常详情: {traceback.format_exc()}")
    def _deploy_yaml_template(self, task_id: str, service_name: str, agent_key: str,
                              template_name: str, template_id: Optional[int] = None,
                              extra_params: Dict = None):
        """部署YAML模板"""
        try:
            # 获取YAML内容
            success, yaml_content, error_msg = self.template_manager.get_yaml_content(template_name)
            if not success:
                self._update_task_status(task_id, 'failed', 30, f'获取YAML内容失败: {yaml_content}')
                return

            self._add_task_log(task_id, 'INFO', f"YAML内容大小: {len(yaml_content)} 字符")

            # 准备部署数据
            data = {
                'name': service_name,
                'yaml': yaml_content,
                'template_name': template_name,
                'template_id': template_id
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
                    self._upsert_service_template_binding(
                        self._get_project_id(agent_key),
                        agent_key,
                        service_name,
                        template_name,
                        template_id=template_id,
                        source_task_id=task_id
                    )
                    self._update_task_status(task_id, 'success', 100, '服务部署成功')
                    self._add_task_log(task_id, 'INFO', '服务部署完成')
                elif self._is_timeout_error(start_status_code, start_response):
                    # start接口超时不等于服务启动失败：避免误清理，先轮询服务实际状态
                    self._add_task_log(task_id, 'WARN', f"启动请求超时: {start_response}")
                    if self._wait_service_ready_after_start_timeout(task_id, agent_key, service_name):
                        self._upsert_service_template_binding(
                            self._get_project_id(agent_key),
                            agent_key,
                            service_name,
                            template_name,
                            template_id=template_id,
                            source_task_id=task_id
                        )
                        self._update_task_status(task_id, 'success', 100, '服务部署成功（超时后状态确认）')
                    else:
                        error_msg = f'启动服务超时，且轮询未就绪: {start_response}'
                        self._update_task_status(task_id, 'failed', 70, error_msg)
                        self._add_task_log(task_id, 'ERROR', error_msg)
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
                error_msg = f'服务已存在，禁止重复部署，请先手动删除后再部署: {service_name}'
                self._update_task_status(task_id, 'failed', 30, error_msg)
                self._add_task_log(task_id, 'ERROR', f"{error_msg}; agent_response={response}")

            else:
                error_msg = f'创建服务失败 (HTTP {status_code}): {response}'
                self._update_task_status(task_id, 'failed', 30, error_msg)
                self._add_task_log(task_id, 'ERROR', error_msg)
        finally:
            self._notify_service_state_changed(agent_key, f"deploy_yaml:{service_name}")

    def _deploy_archive_template(self, task_id: str, service_name: str, agent_key: str,
                                 template_name: str, template_id: Optional[int] = None,
                                 extra_params: Dict = None):
        """部署压缩模板（支持多种格式）"""
        try:
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
                'name': service_name,
                'template_name': template_name,
                'template_id': template_id
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
                    self._upsert_service_template_binding(
                        self._get_project_id(agent_key),
                        agent_key,
                        service_name,
                        template_name,
                        template_id=template_id,
                        source_task_id=task_id
                    )
                    self._update_task_status(task_id, 'success', 100, '压缩服务部署成功')
                    self._add_task_log(task_id, 'INFO', '压缩服务部署完成')
                elif self._is_timeout_error(start_status_code, start_response):
                    self._add_task_log(task_id, 'WARN', f"启动压缩服务请求超时: {start_response}")
                    if self._wait_service_ready_after_start_timeout(task_id, agent_key, service_name):
                        self._upsert_service_template_binding(
                            self._get_project_id(agent_key),
                            agent_key,
                            service_name,
                            template_name,
                            template_id=template_id,
                            source_task_id=task_id
                        )
                        self._update_task_status(task_id, 'success', 100, '压缩服务部署成功（超时后状态确认）')
                    else:
                        error_msg = f'启动压缩服务超时，且轮询未就绪: {start_response}'
                        self._update_task_status(task_id, 'failed', 70, error_msg)
                        self._add_task_log(task_id, 'ERROR', error_msg)
                else:
                    error_msg = f'启动压缩服务失败: {start_response}'
                    self._update_task_status(task_id, 'failed', 70, error_msg)
                    self._add_task_log(task_id, 'ERROR', error_msg)
            elif status_code == 409:
                error_msg = f'服务已存在，禁止重复部署，请先手动删除后再部署: {service_name}'
                self._update_task_status(task_id, 'failed', 30, error_msg)
                self._add_task_log(task_id, 'ERROR', f"{error_msg}; agent_response={response}")
            else:
                error_msg = f'创建压缩服务失败 (HTTP {status_code}): {response}'
                self._update_task_status(task_id, 'failed', 30, error_msg)
                self._add_task_log(task_id, 'ERROR', error_msg)
        finally:
            self._notify_service_state_changed(agent_key, f"deploy_archive:{service_name}")

    def _undeploy_service(self, task_id: str, service_name: str, agent_key: str):
        """卸载服务"""
        try:
            self._update_task_status(task_id, 'running', 10, '开始卸载服务')

            agent = self.agent_manager.get_agent(agent_key) or self.agent_manager.ensure_agent_exists(agent_key)
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
                self._delete_service_template_binding(
                    self._get_project_id(agent_key),
                    agent_key,
                    service_name
                )
                self._update_task_status(task_id, 'success', 100, '服务卸载成功')
                self._add_task_log(task_id, 'INFO', '服务卸载完成')
            else:
                error_msg = f'删除服务失败 (HTTP {delete_status_code}): {delete_response}'
                self._update_task_status(task_id, 'failed', 50, error_msg)
                self._add_task_log(task_id, 'ERROR', error_msg)

        except Exception as e:
            self.logger.error(f"卸载服务失败: {str(e)}")
            self._update_task_status(task_id, 'failed', 0, f'卸载失败: {str(e)}')
        finally:
            self._notify_service_state_changed(agent_key, f"undeploy:{service_name}")


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
            task = self.get_task(task_id)
            if task and str(task.get('status') or '').lower() == 'running':
                self.logger.warning(f"拒绝删除运行中的任务: {task_id}")
                return False
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

            with self.active_task_lock:
                future = self.active_tasks.pop(task_id, None)
                if future and not future.done():
                    future.cancel()

            self.logger.info(f"任务 {task_id} 删除成功")
            return True
        except Exception as e:
            self.logger.error(f"删除任务失败: {str(e)}")
            return False

    def delete_tasks_by_project(self, project_id: str) -> int:
        """按项目清空全部任务记录（含日志）。返回删除的任务数。"""
        if not project_id:
            return 0

        try:
            table_tasks = self.db.get_table_name('tasks')
            table_logs = self.db.get_table_name('task_logs')

            # 先查出任务ID，用于取消内存中的活跃任务
            if self.db.db_type == 'mysql':
                rows = self.db.fetch_all(
                    f"SELECT task_id FROM {table_tasks} WHERE project_id = %s",
                    (project_id,)
                ) or []
            else:
                rows = self.db.fetch_all(
                    f"SELECT task_id FROM {table_tasks} WHERE project_id = ?",
                    (project_id,)
                ) or []

            task_ids = [str(r.get('task_id')) for r in rows if r.get('task_id')]
            if not task_ids:
                return 0

            running_ids = set()
            for task_id in task_ids:
                task = self.get_task(task_id)
                if task and str(task.get('status') or '').lower() == 'running':
                    running_ids.add(task_id)
            deletable_ids = [task_id for task_id in task_ids if task_id not in running_ids]
            if not deletable_ids:
                self.logger.warning(f"项目任务清空跳过，全部为运行中任务: project_id={project_id}")
                return 0

            # 批量删除日志和任务
            if self.db.db_type == 'mysql':
                placeholders = ','.join(['%s'] * len(deletable_ids))
                self.db.execute_transaction([
                    (f"DELETE FROM {table_logs} WHERE task_id IN ({placeholders})", tuple(deletable_ids)),
                    (f"DELETE FROM {table_tasks} WHERE task_id IN ({placeholders})", tuple(deletable_ids))
                ])
            else:
                placeholders = ','.join(['?'] * len(deletable_ids))
                self.db.execute_transaction([
                    (f"DELETE FROM {table_logs} WHERE task_id IN ({placeholders})", tuple(deletable_ids)),
                    (f"DELETE FROM {table_tasks} WHERE task_id IN ({placeholders})", tuple(deletable_ids))
                ])

            # 取消活跃任务future
            with self.active_task_lock:
                for task_id in deletable_ids:
                    future = self.active_tasks.pop(task_id, None)
                    if future and not future.done():
                        future.cancel()

            self.logger.info(
                f"项目任务清空成功: project_id={project_id}, deleted={len(deletable_ids)}, skipped_running={len(running_ids)}"
            )
            return len(deletable_ids)
        except Exception as e:
            self.logger.error(f"按项目清空任务失败: project_id={project_id}, err={str(e)}", exc_info=True)
            return 0
