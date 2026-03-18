from typing import Dict, List, Any, Optional, Tuple, Union

from .agent_manager import AgentManager

import json
import logging
import base64
import requests

# ===================== 代理管理器增强版 =====================

class EnhancedProxyManager:
    """增强版代理管理器"""

    def __init__(self, agent_manager: AgentManager, timeouts: Dict = None):
        self.agent_manager = agent_manager
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        self.session.verify = False  # 临时禁用SSL验证

        # 设置超时配置
        self.timeouts = timeouts or {
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

    def proxy_request(self, agent_key: str, method: str, endpoint: str,
                      request_data: Any = None, query_params: Dict = None,
                      headers: Dict = None, files: Dict = None,
                      stream: bool = False, timeout: int = None,
                      port: int = None) -> Tuple[int, Any, Dict]:
        """
        代理请求到指定的Agent（增强版）

        Args:
            port: 指定请求端口，默认使用 agent_api_port
        """
        try:
            # 获取Agent信息
            agent = self.agent_manager.get_agent(agent_key)
            if not agent:
                return 404, {'error': f'Agent {agent_key} not found'}, {}

            # 检查Agent状态
            if agent.status != 'online':
                return 503, {'error': f'Agent {agent_key} is {agent.status}'}, {}

            # 确定使用的端口
            target_port = port if port is not None else self.agent_manager.agent_api_port

            # 构建完整的URL
            url = f"http://{agent.ip_address}:{target_port}{endpoint}"

            # 准备请求头
            if target_port == self.agent_manager.daemon_api_port:
                # 11188 鉴权头统一走可配置项
                request_headers = {
                    self.agent_manager.daemon_auth_header: self.agent_manager.daemon_auth_token
                }
            else:
                request_headers = {
                    'X-Auth-Token': self.agent_manager.agent_auth_token,
                }

            # 只有当有JSON数据时才添加Content-Type
            if request_data and isinstance(request_data, dict):
                request_headers['Content-Type'] = 'application/json'

            # 添加自定义请求头（过滤敏感头）
            if headers:
                for key, value in headers.items():
                    key_lower = key.lower()
                    if key_lower not in ['host', 'authorization', 'cookie', 'connection']:
                        request_headers[key] = value

            # 确定超时时间
            if timeout is None:
                # 根据端点类型确定默认超时
                if stream:
                    timeout_tuple = self.timeouts.get('stream', (10, 3600))
                elif files:
                    timeout_tuple = self.timeouts.get('file_upload', (10, 600))
                elif 'start' in endpoint.lower():
                    timeout_tuple = self.timeouts.get('deploy_start', (10, 300))
                elif 'stop' in endpoint.lower():
                    timeout_tuple = self.timeouts.get('deploy_stop', (10, 120))
                elif 'delete' in endpoint.lower():
                    timeout_tuple = self.timeouts.get('deploy_delete', (10, 60))
                elif 'health' in endpoint.lower():
                    timeout_tuple = self.timeouts.get('health_check', (5, 10))
                else:
                    timeout_tuple = self.timeouts.get('proxy', (10, 300))
            else:
                # 使用指定的超时时间（秒）
                # 自定义超时时，连接超时同步收敛，避免长时间卡在建立连接阶段
                connect_timeout = min(5, max(1, int(timeout)))
                timeout_tuple = (connect_timeout, timeout)

            # 准备请求参数
            request_kwargs = {
                'headers': request_headers,
                'params': query_params,
                'timeout': timeout_tuple,
                'stream': stream,
                'verify': False  # 禁用SSL验证
            }

            self.logger.info(f"代理请求: {method} {url} 到Agent {agent.hostname}, 超时: {timeout_tuple}")

            # 发送请求
            response = None
            try:
                if method.upper() == 'GET':
                    response = self.session.get(url, **request_kwargs)
                elif method.upper() == 'POST':
                    if files:
                        request_kwargs['files'] = files
                        if request_data:
                            request_kwargs['data'] = request_data
                    elif request_data:
                        request_kwargs['json'] = request_data
                    response = self.session.post(url, **request_kwargs)
                elif method.upper() == 'PUT':
                    if request_data:
                        request_kwargs['json'] = request_data
                    response = self.session.put(url, **request_kwargs)
                elif method.upper() == 'DELETE':
                    if request_data:
                        request_kwargs['json'] = request_data
                    response = self.session.delete(url, **request_kwargs)
                elif method.upper() == 'PATCH':
                    if request_data:
                        request_kwargs['json'] = request_data
                    response = self.session.patch(url, **request_kwargs)
                elif method.upper() == 'HEAD':
                    response = self.session.head(url, **request_kwargs)
                elif method.upper() == 'OPTIONS':
                    response = self.session.options(url, **request_kwargs)
                else:
                    return 400, {'error': f'Unsupported method: {method}'}, {}
            except requests.exceptions.Timeout:
                return 504, {'error': f'Request timeout to agent {agent.hostname} (timeout: {timeout_tuple})'}, {}
            except requests.exceptions.ConnectionError:
                return 503, {'error': f'Connection failed to agent {agent.hostname}'}, {}
            except Exception as e:
                self.logger.error(f"发送请求失败: {str(e)}")
                return 500, {'error': f'Failed to send request: {str(e)}'}, {}

            if response is None:
                return 500, {'error': 'No response received from agent'}, {}

            # 构建响应头
            response_headers = {
                'Content-Type': response.headers.get('Content-Type', 'application/json'),
                'X-Proxied-From-Agent': agent_key,
                'X-Proxied-Agent-IP': agent.ip_address,
                'X-Proxied-Agent-Name': agent.hostname,
                'X-Proxied-Response-Code': str(response.status_code),
                'X-Proxied-Response-Time': str(response.elapsed.total_seconds() * 1000) + 'ms'
            }

            # 复制所有响应头（除了敏感头）
            for key, value in response.headers.items():
                key_lower = key.lower()
                if key_lower not in ['server', 'date', 'connection', 'transfer-encoding']:
                    response_headers[key] = value

            # 处理响应数据
            try:
                content_type = response.headers.get('Content-Type', '').lower()

                if stream:
                    # 流式响应
                    return response.status_code, response.content, response_headers
                elif 'application/json' in content_type:
                    # JSON响应
                    try:
                        response_data = response.json() if response.content else {}
                    except json.JSONDecodeError as e:
                        self.logger.warning(f"Agent响应JSON解析失败: {e}, 返回文本")
                        response_data = {'raw_response': response.text}
                elif 'text/' in content_type:
                    # 文本响应
                    response_data = response.text
                elif response.content:
                    # 二进制响应
                    try:
                        response_data = json.loads(response.text)
                    except:
                        response_data = {'content': 'binary data', 'size': len(response.content)}
                else:
                    response_data = {}
            except Exception as e:
                self.logger.error(f"处理响应失败: {str(e)}")
                response_data = {'error': 'Failed to process response', 'status_code': response.status_code}

            self.logger.debug(f"代理响应: 状态码={response.status_code}, 耗时={response.elapsed.total_seconds():.2f}秒")
            return response.status_code, response_data, response_headers

        except Exception as e:
            self.logger.error(f"代理请求失败: {str(e)}", exc_info=True)
            return 500, {'error': f'Proxy request failed: {str(e)}'}, {}
