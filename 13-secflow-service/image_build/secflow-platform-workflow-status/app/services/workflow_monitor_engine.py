"""
工作流监控引擎
负责管理工作流的监控会话，后台轮询节点状态并保存到数据库
"""

import asyncio
import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from app.models.database import get_db_session
from app.services.status_sync_service import get_status_sync_service

logger = logging.getLogger(__name__)


@dataclass
class MonitorSession:
    """监控会话"""
    id: str
    instance_id: str
    project_id: str
    nodes: List[Dict[str, Any]]
    status: str = "active"  # active, paused, stopped
    started_at: datetime = field(default_factory=datetime.utcnow)
    stopped_at: Optional[datetime] = None
    poll_interval: int = 10  # 默认10秒轮询一次
    last_poll_at: Optional[datetime] = None
    poll_count: int = 0


class WorkflowMonitorEngine:
    """
    工作流监控引擎

    功能:
    1. 管理多个工作流的监控会话
    2. 后台任务定期轮询节点状态
    3. 状态变化时自动保存到数据库
    4. JOB节点完成时自动获取并保存日志
    5. 支持暂停/恢复监控
    """

    def __init__(self):
        self._sessions: Dict[str, MonitorSession] = {}
        self._background_task: Optional[asyncio.Task] = None
        self._running: bool = False
        self._sync_service = get_status_sync_service()
        self._lock = asyncio.Lock()

    async def start(self):
        """启动监控引擎"""
        if self._running:
            logger.warning("监控引擎已在运行中")
            return

        self._running = True
        self._background_task = asyncio.create_task(self._run_background_monitor())
        logger.info("工作流监控引擎已启动")

    async def stop(self):
        """停止监控引擎"""
        self._running = False
        if self._background_task:
            self._background_task.cancel()
            try:
                await self._background_task
            except asyncio.CancelledError:
                pass
            self._background_task = None

        # 停止所有活跃的监控会话
        async with self._lock:
            for instance_id, session in self._sessions.items():
                if session.status == "active":
                    session.status = "stopped"
                    session.stopped_at = datetime.utcnow()
            self._sessions.clear()

        logger.info("工作流监控引擎已停止")

    async def start_monitoring(
        self,
        instance_id: str,
        project_id: str,
        nodes: List[Dict[str, Any]],
        poll_interval: int = 10
    ) -> str:
        """
        启动工作流监控

        Args:
            instance_id: 工作流实例ID
            project_id: 项目ID
            nodes: 节点信息列表
                - node_id: 节点ID
                - node_type: 节点类型 (app/job)
                - k8s_resource_name: K8S资源名称
                - timeout_seconds: 超时时间
            poll_interval: 轮询间隔(秒)

        Returns:
            监控会话ID
        """
        session_id = str(uuid.uuid4())

        async with self._lock:
            # 如果已存在该实例的监控会话，先停止旧的
            if instance_id in self._sessions:
                old_session = self._sessions[instance_id]
                old_session.status = "stopped"
                old_session.stopped_at = datetime.utcnow()
                logger.info(f"停止旧的监控会话: {instance_id}")

            session = MonitorSession(
                id=session_id,
                instance_id=instance_id,
                project_id=project_id,
                nodes=nodes,
                poll_interval=poll_interval
            )

            self._sessions[instance_id] = session

        logger.info(f"启动监控会话: instance_id={instance_id}, nodes_count={len(nodes)}")
        return session_id

    async def stop_monitoring(self, instance_id: str) -> bool:
        """停止工作流监控"""
        async with self._lock:
            session = self._sessions.pop(instance_id, None)
            if session:
                session.status = "stopped"
                session.stopped_at = datetime.utcnow()
                logger.info(f"停止监控会话: {instance_id}, 轮询次数: {session.poll_count}")
                return True
            return False

    async def pause_monitoring(self, instance_id: str) -> bool:
        """暂停监控"""
        async with self._lock:
            session = self._sessions.get(instance_id)
            if session and session.status == "active":
                session.status = "paused"
                logger.info(f"暂停监控会话: {instance_id}")
                return True
            return False

    async def resume_monitoring(self, instance_id: str) -> bool:
        """恢复监控"""
        async with self._lock:
            session = self._sessions.get(instance_id)
            if session and session.status == "paused":
                session.status = "active"
                logger.info(f"恢复监控会话: {instance_id}")
                return True
            return False

    def get_monitor_status(self, instance_id: str) -> Optional[Dict]:
        """获取监控状态"""
        session = self._sessions.get(instance_id)
        if session:
            return {
                "id": session.id,
                "instance_id": session.instance_id,
                "project_id": session.project_id,
                "status": session.status,
                "started_at": session.started_at.isoformat(),
                "stopped_at": session.stopped_at.isoformat() if session.stopped_at else None,
                "last_poll_at": session.last_poll_at.isoformat() if session.last_poll_at else None,
                "poll_count": session.poll_count,
                "nodes_count": len(session.nodes)
            }
        return None

    def get_all_sessions(self) -> List[Dict]:
        """获取所有监控会话状态"""
        return [
            self.get_monitor_status(instance_id)
            for instance_id in self._sessions.keys()
        ]

    async def _run_background_monitor(self):
        """后台监控任务主循环"""
        logger.info("后台监控任务启动")

        while self._running:
            try:
                await self._poll_all_sessions()
            except Exception as e:
                logger.error(f"后台监控任务执行错误: {e}", exc_info=True)

            # 每5秒检查一次是否有会话需要轮询
            await asyncio.sleep(5)

        logger.info("后台监控任务结束")

    async def _poll_all_sessions(self):
        """轮询所有活跃会话"""
        sessions_to_poll = []

        async with self._lock:
            for instance_id, session in list(self._sessions.items()):
                if session.status != "active":
                    continue

                # 检查是否需要轮询（根据轮询间隔）
                if session.last_poll_at:
                    elapsed = (datetime.utcnow() - session.last_poll_at).total_seconds()
                    if elapsed < session.poll_interval:
                        continue

                sessions_to_poll.append(session)

        # 并发轮询所有需要轮询的会话
        if sessions_to_poll:
            tasks = [self._poll_session(session) for session in sessions_to_poll]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for session, result in zip(sessions_to_poll, results):
                if isinstance(result, Exception):
                    logger.error(f"轮询会话 {session.instance_id} 失败: {result}")

    async def _poll_session(self, session: MonitorSession):
        """轮询单个会话的节点状态"""
        logger.debug(f"轮询会话: {session.instance_id}, 节点数: {len(session.nodes)}")

        for node in session.nodes:
            try:
                node_id = node.get("node_id")
                node_type = node.get("node_type")
                k8s_resource_name = node.get("k8s_resource_name")
                timeout_seconds = node.get("timeout_seconds")
                task_id = node.get("task_id")

                if not node_id:
                    continue

                # 同步节点状态
                result = await self._sync_service.sync_node_status(
                    node_id=node_id,
                    project_id=session.project_id,
                    instance_id=session.instance_id,
                    node_type=node_type,
                    k8s_resource_name=k8s_resource_name,
                    timeout_seconds=timeout_seconds,
                    task_id=task_id,
                )

                if node_type and node_type.lower() == "app":
                    await self._backfill_app_init_logs(session, node)

                # 如果是JOB节点且已完成，尝试获取并保存日志
                if node_type and node_type.lower() == "job":
                    current_status = result.get("status", "")
                    if current_status in ["Succeeded", "Failed"]:
                        await self._save_job_logs(session, node)

            except Exception as e:
                logger.error(f"同步节点 {node.get('node_id')} 状态失败: {e}")

        # 更新会话状态
        session.last_poll_at = datetime.utcnow()
        session.poll_count += 1

        # 同步工作流整体状态
        try:
            await self._sync_service.sync_all_nodes(
                instance_id=session.instance_id,
                project_id=session.project_id,
                nodes=session.nodes
            )
        except Exception as e:
            logger.error(f"同步工作流整体状态失败: {e}")

    async def _backfill_app_init_logs(self, session: MonitorSession, node: Dict):
        """Use real Pod logs to replace APP init summaries or empty init logs."""
        node_id = node.get("node_id")
        task_id = node.get("task_id")
        if not node_id or not task_id:
            return

        try:
            stored_logs = await self._sync_service.get_stored_logs(node_id=node_id, task_id=task_id)
            init_logs = stored_logs.get("init_logs") or {}
            if init_logs.get("logs") and init_logs.get("pod_name"):
                return

            await self._sync_service.get_task_logs(
                task_id=task_id,
                project_id=session.project_id,
                tail_lines=500,
                persist=True,
            )
        except Exception as e:
            logger.debug(f"APP 节点初始化日志补抓失败: node_id={node_id}, error={e}")

    async def _save_job_logs(self, session: MonitorSession, node: Dict):
        """保存JOB节点执行日志"""
        node_id = node.get("node_id")
        k8s_resource_name = node.get("k8s_resource_name")
        task_id = node.get("task_id")
        try:
            # 检查是否已经保存过日志
            stored_logs = await self._sync_service.get_stored_logs(node_id=node_id, task_id=task_id)
            if stored_logs and stored_logs.get("execution_logs") and stored_logs.get("execution_logs", {}).get("logs"):
                logger.debug(f"节点 {node_id} 已有执行日志，跳过保存")
                return

            # 获取Pod列表
            from app.services.k8s_client import get_k8s_client
            k8s_client = get_k8s_client()
            pods = k8s_client.get_job_pods(session.project_id, k8s_resource_name)

            if not pods:
                logger.warning(f"节点 {node_id} 没有找到 Job Pod")
                return

            # 获取第一个Pod的日志
            pod_name = pods[0].get("name") or pods[0].get("metadata", {}).get("name")
            if not pod_name:
                logger.warning(f"节点 {node_id} 无法获取 Pod 名称")
                return

            # 获取日志
            logs = k8s_client.get_pod_logs(
                project_id=session.project_id,
                pod_name=pod_name,
                tail_lines=500
            )

            if logs:
                await self._sync_service.save_execution_logs(
                    node_id=node_id,
                    logs=logs,
                    pod_name=pod_name,
                    task_id=task_id,
                )
                logger.info(f"已保存节点 {node_id} 执行日志 (Pod: {pod_name})")

        except Exception as e:
            logger.error(f"保存节点 {node_id} 日志失败: {e}")


# 单例实例
_monitor_engine: Optional[WorkflowMonitorEngine] = None


def get_workflow_monitor_engine() -> WorkflowMonitorEngine:
    """获取监控引擎实例"""
    global _monitor_engine
    if _monitor_engine is None:
        _monitor_engine = WorkflowMonitorEngine()
    return _monitor_engine
