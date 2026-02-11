import logging
import os
import threading
import time
import base64
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
            'deploy_start': (10, 300),
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
            config.get('nacos_password')  # 新增：Nacos密码
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
                    return jsonify({
                        'message': message,
                        'success': True,
                        'cleanup_info': cleanup_info,
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
                if self.db_manager.db_type == 'mysql':
                    status_stats = self.db_manager.fetch_all('''
                                                             SELECT status,
                                                                    COUNT(*) as count,
                            MAX(last_seen) as last_seen_max,
                            MIN(last_seen) as last_seen_min
                                                             FROM secflow_agent_agent_status
                                                             WHERE project_id = %s
                                                             GROUP BY status
                                                             ORDER BY count DESC
                                                             ''', (project_id,))
                else:
                    status_stats = self.db_manager.fetch_all('''
                                                             SELECT status,
                                                                    COUNT(*) as count,
                            MAX(last_seen) as last_seen_max,
                            MIN(last_seen) as last_seen_min
                                                             FROM secflow_agent_agent_status
                                                             WHERE project_id = ?
                                                             GROUP BY status
                                                             ORDER BY count DESC
                                                             ''', (project_id,))

                # 计算掉线agent（超过5分钟未更新）for this project
                if self.db_manager.db_type == 'mysql':
                    offline_result = self.db_manager.fetch_one('''
                                                               SELECT COUNT(*) as count
                                                               FROM secflow_agent_agent_status
                                                               WHERE project_id = %s
                                                                 AND status IN ('offline'
                                                                   , 'error'
                                                                   , 'timeout'
                                                                   , 'unknown')
                                                                 AND updated_at
                                                                   < NOW() - INTERVAL 5 MINUTE
                                                               ''', (project_id,))
                    total_result = self.db_manager.fetch_one(
                        "SELECT COUNT(*) as count FROM secflow_agent_agent_status WHERE project_id = %s",
                        (project_id,)
                    )
                else:
                    offline_result = self.db_manager.fetch_one('''
                                                               SELECT COUNT(*) as count
                                                               FROM secflow_agent_agent_status
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
                        "SELECT COUNT(*) as count FROM secflow_agent_agent_status WHERE project_id = ?",
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
                if self.db_manager.db_type == 'mysql':
                    agent = self.db_manager.fetch_one(
                        "SELECT * FROM secflow_agent_agent_status WHERE agent_key = %s",
                        (agent_key,)
                    )
                else:
                    agent = self.db_manager.fetch_one(
                        "SELECT * FROM secflow_agent_agent_status WHERE agent_key = ?",
                        (agent_key,)
                    )

                if not agent:
                    return jsonify({'error': f'Agent {agent_key} 不存在'}), 404

                # Verify the agent belongs to the requested project
                if agent.get('project_id') != project_id:
                    return jsonify({'error': f'Agent {agent_key} does not belong to project {project_id}'}), 403

                # 更新agent状态
                if self.db_manager.db_type == 'mysql':
                    self.db_manager.execute_query('''
                                                  UPDATE secflow_agent_agent_status
                                                  SET status     = %s,
                                                      updated_at = NOW()
                                                  WHERE agent_key = %s
                                                  ''', (status, agent_key))
                else:
                    self.db_manager.execute_query('''
                                                  UPDATE secflow_agent_agent_status
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

            return jsonify({
                'secflow_agent_tasks': tasks,
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

            # Include project_id in response
            task['requested_project_id'] = project_id
            return jsonify(task)

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

            return jsonify({
                'logs': logs,
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

            task_id = self.task_manager.create_task(
                'deploy', data['service_name'], data['agent_key'],
                data['template_name'], data.get('extra_params'), project_id
            )

            return jsonify({
                'task_id': task_id,
                'message': '部署任务已创建',
                'project_id': project_id
            }), 202

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
                if self.db_manager.db_type == 'mysql':
                    agent_data = self.db_manager.fetch_one(
                        "SELECT * FROM secflow_agent_agent_status WHERE agent_key = %s",
                        (agent_key,)
                    )
                else:
                    agent_data = self.db_manager.fetch_one(
                        "SELECT * FROM secflow_agent_agent_status WHERE agent_key = ?",
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
                            "SELECT * FROM secflow_agent_agent_status WHERE agent_key = %s",
                            (agent_key,)
                        )
                    else:
                        full_data = self.db_manager.fetch_one(
                            "SELECT * FROM secflow_agent_agent_status WHERE agent_key = ?",
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

        @self.app.route('/api/agent/templates', methods=['GET'])
        def list_templates():
            """列出所有模板（包含文件大小信息）"""
            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 20))

            templates, total = self.template_manager.list_templates(page, per_page)
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

            # 获取当前用户
            success, message = self.template_manager.create_template(
                name, description, template_type, file_content, filename,
                'system'
            )

            if success:
                return jsonify({
                    'message': message,
                    'template_name': name,
                    'template_type': template_type,
                    'filename': filename
                }), 201
            else:
                return jsonify({'error': message}), 400

        @self.app.route('/api/agent/templates/<name>', methods=['GET'])
        def get_template_detail(name):
            """获取模板详细信息（包含文件大小）"""
            template = self.template_manager.get_template(name)

            if template:
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

                return jsonify(template)
            else:
                return jsonify({'error': '模板不存在'}), 404

        @self.app.route('/api/agent/templates/<name>/yaml', methods=['GET'])
        def get_template_yaml(name):
            """获取模板的YAML内容"""
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
            data = request.get_json()
            if not data:
                return jsonify({'error': '请求体必须为JSON'}), 400

            yaml_content = data.get('yaml_content')
            if not yaml_content:
                return jsonify({'error': 'YAML内容不能为空'}), 400

            success, message = self.template_manager.update_yaml_content(
                name, yaml_content, 'system'
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
                format_param = request.args.get('format', 'original')
                as_zip = request.args.get('as_zip', '').lower() == 'true'
                include_all = request.args.get('include_all', 'true').lower() == 'true'
                disposition = request.args.get('disposition', 'attachment')

                self.logger.info(f"下载模板请求: {name}, format={format_param}, as_zip={as_zip}")

                # 检查模板是否存在
                template = self.template_manager.get_template(name)
                if not template:
                    return jsonify({'error': f'模板 {name} 不存在'}), 404

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
                template = self.template_manager.get_template(name)

                if not template:
                    return jsonify({'error': f'模板 {name} 不存在'}), 404

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
                template = self.template_manager.get_template(name)

                if not template:
                    return jsonify({'error': f'模板 {name} 不存在'}), 404

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
            success, message = self.template_manager.delete_template(name)

            if success:
                return jsonify({'message': message})
            else:
                return jsonify({'error': message}), 400

        @self.app.route('/api/agent/templates/download/batch', methods=['POST'])
        def download_templates_batch():
            """批量下载模板"""
            try:
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
                    if not self.template_manager.get_template(name):
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
                updated_by = 'system'

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
            updated_by = 'system'

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
                data = request.get_json()
                if not data:
                    return jsonify({'error': '请求体必须为JSON'}), 400

                file_path = data.get('path', '')
                if not file_path:
                    return jsonify({'error': '文件路径不能为空'}), 400

                # 获取当前用户
                deleted_by = 'system'

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
                data = request.get_json()
                if not data:
                    return jsonify({'error': '请求体必须为JSON'}), 400

                dir_path = data.get('path', '')
                force = data.get('force', False)

                if len(dir_path) == 0:
                    return jsonify({'error': '目录路径不能为空'}), 400

                # 获取当前用户
                deleted_by = 'system'

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

    def _refresh_loop(self):
        """后台刷新循环"""
        while not self.should_stop:
            try:
                self.agent_manager.refresh_agents()
            except Exception as e:
                self.logger.error(f"刷新Agent列表失败: {str(e)}")

            # 等待下一次刷新
            for _ in range(self.config['refresh_interval']):
                if self.should_stop:
                    break
                time.sleep(1)

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
        'deploy_start': (10, 300),
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