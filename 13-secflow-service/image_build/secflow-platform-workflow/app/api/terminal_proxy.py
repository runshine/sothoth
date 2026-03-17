"""
终端代理 API - 将前端 WebSocket 连接转发到 K8s 微服务
实现微服务架构下的终端访问
"""

import asyncio
import logging
from typing import Optional

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from fastapi.websockets import WebSocketState

import websockets
from websockets.asyncio.client import connect as ws_connect

from app.config import get_config
from app.services.auth import get_auth_service
from app.services.k8s_service_client import get_k8s_service_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="", tags=["终端代理"])


class TerminalProxyConnectionManager:
    """终端代理连接管理器"""

    def __init__(self):
        # 存储活跃的上游连接 (client_id -> upstream_websocket)
        self.active_connections = {}

    async def connect(self, client_id: str, upstream_ws):
        """建立代理连接"""
        self.active_connections[client_id] = upstream_ws
        logger.info(f"Terminal proxy connected: {client_id}")

    def disconnect(self, client_id: str):
        """断开代理连接"""
        if client_id in self.active_connections:
            del self.active_connections[client_id]
            logger.info(f"Terminal proxy disconnected: {client_id}")

    def get_connection(self, client_id: str):
        """获取上游连接"""
        return self.active_connections.get(client_id)


# 全局连接管理器
proxy_manager = TerminalProxyConnectionManager()


def get_upstream_websocket_url(
    project_id: str,
    pod_name: str,
    container: Optional[str] = None,
    command: str = "/bin/bash"
) -> str:
    """构建 K8s 微服务的 WebSocket URL"""
    config = get_config()
    k8s_base_url = config.k8s_service.base_url.replace("http://", "").replace("https://", "")

    # 构建 URL
    url = f"ws://{k8s_base_url}/api/k8s/ws/pods/{pod_name}/exec?project_id={project_id}&command={command}"
    if container:
        url += f"&container={container}"

    return url


async def proxy_terminal_stream(
    client_id: str,
    downstream_ws: WebSocket,
    upstream_ws
):
    """代理终端数据流 - 从上游(K8s)到下游(前端)"""
    try:
        async for message in upstream_ws:
            if downstream_ws.client_state == WebSocketState.CONNECTED:
                await downstream_ws.send_bytes(message) if isinstance(message, bytes) else await downstream_ws.send_text(message)
            else:
                break
    except websockets.exceptions.ConnectionClosed as e:
        logger.debug(f"Upstream connection closed for {client_id}: {e}")
    except Exception as e:
        logger.debug(f"Upstream stream ended for {client_id}: {e}")
    finally:
        proxy_manager.disconnect(client_id)
        # 尝试关闭上游连接
        try:
            await upstream_ws.close()
        except Exception:
            pass


async def proxy_terminal_input(
    client_id: str,
    downstream_ws: WebSocket,
    upstream_ws
):
    """代理终端输入 - 从下游(前端)到上游(K8s)"""
    try:
        while True:
            # 接收前端的消息
            data = await downstream_ws.receive_text()

            # 检查是否是 JSON 格式 (resize 命令)
            import json
            try:
                msg_data = json.loads(data)
                if "resize" in msg_data:
                    # 转发 resize 命令
                    await upstream_ws.send(data)
                    continue
            except (json.JSONDecodeError, Exception):
                pass

            # 转发普通输入
            await upstream_ws.send(data)

    except WebSocketDisconnect:
        logger.info(f"Frontend disconnected for {client_id}")
    except websockets.exceptions.ConnectionClosed as e:
        logger.debug(f"Downstream connection closed for {client_id}: {e}")
    except Exception as e:
        logger.debug(f"Downstream stream ended for {client_id}: {e}")
    finally:
        proxy_manager.disconnect(client_id)
        # 尝试关闭上游连接
        try:
            await upstream_ws.close()
        except Exception:
            pass


@router.websocket("/api/workflow/ws/pods/{pod_name}/exec")
async def websocket_terminal_proxy(
    websocket: WebSocket,
    pod_name: str,
    project_id: str = Query(..., description="项目ID"),
    container: Optional[str] = Query(None, description="容器名"),
    command: Optional[str] = Query("/bin/bash", description="执行的命令"),
    token: Optional[str] = Query(None, description="认证Token")
):
    """
    终端代理 WebSocket 接口

    前端连接此接口后，服务端会:
    1. 验证用户 Token 和项目权限
    2. 建立与 K8s 微服务的上游 WebSocket 连接
    3. 双向代理终端数据流

    路由: /api/workflow/ws/pods/{pod_name}/exec
    """
    # 1. 验证 Token
    if not token:
        token = websocket.query_params.get("token")

    if not token:
        await websocket.accept()
        await websocket.send_text("\x1b[31mError: 未提供认证Token\x1b[0m\r\n")
        await websocket.close()
        return

    try:
        auth_service = get_auth_service()
        current_user = auth_service.verify_token(token)
        if not current_user:
            await websocket.accept()
            await websocket.send_text("\x1b[31mError: Token无效或已过期\x1b[0m\r\n")
            await websocket.close()
            return
    except Exception as e:
        logger.error(f"Token验证失败: {e}")
        await websocket.accept()
        await websocket.send_text(f"\x1b[31mError: Token验证失败 - {str(e)}\x1b[0m\r\n")
        await websocket.close()
        return

    # 2. 验证项目权限
    try:
        k8s_client = get_k8s_service_client()
        # 检查项目 namespace 是否存在
        exists, error = k8s_client.ensure_namespace(project_id)
        if not exists:
            await websocket.accept()
            await websocket.send_text(f"\x1b[31mError: 项目不存在或无权限访问\x1b[0m\r\n")
            await websocket.close()
            return
    except Exception as e:
        logger.error(f"项目权限验证失败: {e}")
        await websocket.accept()
        await websocket.send_text(f"\x1b[31mError: 项目权限验证失败 - {str(e)}\x1b[0m\r\n")
        await websocket.close()
        return

    # 3. 接受前端连接
    await websocket.accept()

    # 4. 构建上游 K8s 服务的 WebSocket URL
    upstream_url = get_upstream_websocket_url(project_id, pod_name, container, command or "/bin/bash")
    # 添加 token
    upstream_url += f"&token={token}"

    logger.info(f"Proxying terminal to: {upstream_url}")

    # 5. 建立与 K8s 服务的上游连接
    upstream_ws = None
    client_id = f"proxy_{pod_name}_{id(websocket)}"

    try:
        # 使用 websockets 库建立上游 WebSocket 连接
        upstream_ws = await asyncio.wait_for(
            ws_connect(upstream_url, max_size=None),
            timeout=10
        )

        logger.info(f"Terminal proxy established for {pod_name}")

        # 注册连接
        await proxy_manager.connect(client_id, upstream_ws)

        # 6. 双向代理数据流
        # 同时运行两个协程：一个处理上游到下游，一个处理下游到上游
        await asyncio.gather(
            proxy_terminal_stream(client_id, websocket, upstream_ws),
            proxy_terminal_input(client_id, websocket, upstream_ws),
            return_exceptions=True
        )

    except asyncio.TimeoutError:
        logger.error(f"建立上游连接超时: {pod_name}")
        await websocket.send_text(f"\x1b[31mError: 连接K8s服务超时\x1b[0m\r\n")
        await websocket.close()
    except websockets.exceptions.InvalidURI as e:
        logger.error(f"无效的WebSocket URI: {e}")
        await websocket.send_text(f"\x1b[31mError: 无效的连接地址\x1b[0m\r\n")
        await websocket.close()
    except Exception as e:
        logger.error(f"Terminal proxy error: {e}")
        try:
            await websocket.send_text(f"\x1b[31mError: 代理错误 - {str(e)}\x1b[0m\r\n")
            await websocket.close()
        except Exception:
            pass
    finally:
        # 清理连接
        proxy_manager.disconnect(client_id)
        if upstream_ws:
            try:
                await upstream_ws.close()
            except Exception:
                pass


# 获取终端 WebSocket 连接地址（备用方案）
@router.get("/api/workflow/ws/pods/{pod_name}/exec-addr")
async def get_terminal_websocket_address(
    pod_name: str,
    project_id: str = Query(..., description="项目ID"),
    container: Optional[str] = Query(None, description="容器名"),
    command: Optional[str] = Query("/bin/bash", description="执行的命令")
):
    """
    获取终端 WebSocket 连接地址

    返回 K8s 服务的 WebSocket 地址，前端直接连接
    这样可以避免复杂的代理逻辑，同时保证微服务架构
    """
    config = get_config()

    # 获取当前服务的协议和主机
    ws_protocol = "ws"
    # 如果前端通过 HTTPS 访问，则使用 wss

    # 构建地址
    k8s_base_url = config.k8s_service.base_url.replace("http://", "ws://").replace("https://", "wss://")

    ws_url = f"{k8s_base_url}/api/k8s/ws/pods/{pod_name}/exec?project_id={project_id}&command={command or '/bin/bash'}"
    if container:
        ws_url += f"&container={container}"

    return {
        "ws_url": ws_url,
        "pod_name": pod_name,
        "project_id": project_id
    }