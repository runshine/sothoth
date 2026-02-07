"""Async task management service."""

import asyncio
import logging
import aiofiles
from datetime import datetime
from typing import Optional, Dict, Any, List
from pathlib import Path
from collections.abc import Coroutine

from app.models import database
from app.models.database import (
    Resource, AsyncTaskLog, TaskStatus, TaskType, init_database_engine
)

logger = logging.getLogger(__name__)


def _get_session():
    """获取数据库会话，确保引擎已初始化。"""
    if database.SessionLocal is None:
        init_database_engine()
    return database.SessionLocal()


class AsyncTaskManager:
    """异步任务管理器。"""

    def __init__(self, log_dir: str, max_concurrent: int = 10):
        """
        初始化任务管理器.

        Args:
            log_dir: 任务日志目录
            max_concurrent: 最大并发任务数
        """
        self.log_dir = Path(log_dir)
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.running_tasks: Dict[str, asyncio.Task] = {}
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def generate_task_id(self) -> str:
        """生成任务ID。"""
        import uuid
        return f"task_{uuid.uuid4().hex[:16]}"

    async def create_task(
        self,
        task_type: TaskType,
        project_id: str,
        resource_id: Optional[int] = None,
        input_params: Optional[Dict[str, Any]] = None
    ) -> AsyncTaskLog:
        """
        创建新任务记录.

        Returns:
            AsyncTaskLog: 创建的任务记录
        """
        session = _get_session()
        try:
            task = AsyncTaskLog(
                task_id=self.generate_task_id(),
                project_id=project_id,
                resource_id=resource_id,
                task_type=task_type,
                status=TaskStatus.PENDING,
                progress=0,
                message="Task created",
                input_params=input_params,
                created_k8s_resources=[]
            )
            session.add(task)
            session.commit()
            session.refresh(task)
            return task
        finally:
            session.close()

    async def start_task(
        self,
        task_id: str,
        coro: Coroutine
    ):
        """
        启动异步任务。

        Args:
            task_id: 任务ID
            coro: 协程函数
        """
        async with self.semaphore:
            task = asyncio.create_task(self._run_task(task_id, coro))
            self.running_tasks[task_id] = task

    async def _run_task(self, task_id: str, coro: Coroutine):
        """
        执行任务的具体逻辑。

        Args:
            task_id: 任务ID
            coro: 要执行的协程
        """
        session = _get_session()
        created_resources = []

        try:
            # 更新任务状态为运行中
            task = session.query(AsyncTaskLog).filter(
                AsyncTaskLog.task_id == task_id
            ).first()

            if not task:
                return

            task.status = TaskStatus.RUNNING
            task.started_at = datetime.utcnow()
            task.message = "Task started"
            session.commit()

            # 执行任务
            result = await coro

            # 更新任务状态为成功
            task.status = TaskStatus.SUCCEEDED
            task.progress = 100
            task.message = "Task completed successfully"
            task.result = result
            task.finished_at = datetime.utcnow()
            session.commit()

            logger.info(f"Task {task_id} completed successfully")

        except asyncio.CancelledError:
            # 任务被取消
            session.rollback()
            await self._update_task_status(task_id, TaskStatus.CANCELLED, "Task cancelled")
            logger.info(f"Task {task_id} was cancelled")

        except Exception as e:
            logger.error(f"Task {task_id} failed: {e}")

            # 清理创建的K8S资源
            if created_resources:
                await self._cleanup_resource(task_id, created_resources)

            await self._update_task_status(
                task_id,
                TaskStatus.FAILED,
                "Task failed",
                str(e)
            )

        finally:
            session.close()
            self.running_tasks.pop(task_id, None)

    async def _cleanup_resource(self, task_id: str, created_resources: List[Dict[str, str]]):
        """清理任务创建的K8S资源。"""
        from app.services.k8s import get_k8s_service

        k8s_service = get_k8s_service()
        success = k8s_service.cleanup_created_resources(created_resources)

        logger.info(
            f"Task {task_id} cleanup: "
            f"{'success' if success else 'partial/failed'}, "
            f"resources: {created_resources}"
        )

    async def _update_task_status(
        self,
        task_id: str,
        status: TaskStatus,
        message: str,
        error_message: str = None
    ):
        """更新任务状态。"""
        session = _get_session()
        try:
            task = session.query(AsyncTaskLog).filter(
                AsyncTaskLog.task_id == task_id
            ).first()

            if task:
                task.status = status
                task.message = message
                if error_message:
                    task.error_message = error_message
                task.finished_at = datetime.utcnow()
                session.commit()
        finally:
            session.close()

    async def get_task_status(self, task_id: str) -> Optional[AsyncTaskLog]:
        """获取任务状态。"""
        session = _get_session()
        try:
            task = session.query(AsyncTaskLog).filter(
                AsyncTaskLog.task_id == task_id
            ).first()
            return task
        finally:
            session.close()

    async def update_task_progress(self, task_id: str, progress: int, message: str = None):
        """更新任务进度。"""
        session = _get_session()
        try:
            task = session.query(AsyncTaskLog).filter(
                AsyncTaskLog.task_id == task_id
            ).first()

            if task:
                task.progress = progress
                if message:
                    task.message = message
                session.commit()
        except Exception as e:
            logger.error(f"Failed to update task progress: {e}")
            session.rollback()
        finally:
            session.close()

    async def append_task_log(self, task_id: str, message: str):
        """追加任务日志。"""
        log_path = self.log_dir / f"{task_id}.log"
        timestamp = datetime.utcnow().isoformat()
        async with aiofiles.open(str(log_path), "a") as f:
            await f.write(f"[{timestamp}] {message}\n")

    async def get_task_logs(self, task_id: str) -> List[str]:
        """获取任务完整日志。"""
        log_path = self.log_dir / f"{task_id}.log"
        if not log_path.exists():
            return []
        content = log_path.read_text()
        return content.split("\n")

    async def delete_task(self, task_id: str) -> bool:
        """删除任务记录和日志。"""
        session = _get_session()
        try:
            task = session.query(AsyncTaskLog).filter(
                AsyncTaskLog.task_id == task_id
            ).first()

            if not task:
                return False

            # 如果任务正在运行，取消它
            if task_id in self.running_tasks:
                self.running_tasks[task_id].cancel()

            # 删除任务记录
            session.delete(task)
            session.commit()

            # 删除日志文件
            log_path = self.log_dir / f"{task_id}.log"
            if log_path.exists():
                log_path.unlink()

            return True

        except Exception as e:
            logger.error(f"Failed to delete task {task_id}: {e}")
            session.rollback()
            return False

        finally:
            session.close()

    async def list_tasks(
        self,
        project_id: str = None,
        resource_id: int = None,
        task_type: Optional[TaskType] = None,
        status: Optional[TaskStatus] = None,
        limit: int = 50,
        offset: int = 0
    ) -> tuple[List[AsyncTaskLog], int]:
        """列出任务。"""
        session = _get_session()
        try:
            query = session.query(AsyncTaskLog)

            if project_id:
                query = query.filter(AsyncTaskLog.project_id == project_id)
            if resource_id:
                query = query.filter(AsyncTaskLog.resource_id == resource_id)
            if task_type:
                query = query.filter(AsyncTaskLog.task_type == task_type)
            if status:
                query = query.filter(AsyncTaskLog.status == status)

            total = query.count()

            tasks = query.order_by(AsyncTaskLog.created_at.desc()) \
                .offset(offset).limit(limit).all()

            return tasks, total

        finally:
            session.close()


# 全局任务管理器实例
_task_manager: Optional[AsyncTaskManager] = None


def get_task_manager() -> AsyncTaskManager:
    """获取任务管理器实例。"""
    global _task_manager
    if _task_manager is None:
        raise RuntimeError("Task manager not initialized")
    return _task_manager


def init_task_manager(log_dir: str, max_concurrent: int = 10) -> AsyncTaskManager:
    """初始化任务管理器实例。"""
    global _task_manager
    _task_manager = AsyncTaskManager(log_dir=log_dir, max_concurrent=max_concurrent)
    logger.info(f"Task manager initialized with max_concurrent={max_concurrent}")
    return _task_manager