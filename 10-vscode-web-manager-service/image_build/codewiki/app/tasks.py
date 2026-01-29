# app/tasks.py
import asyncio
import subprocess
import signal
import os
from datetime import datetime
from typing import Optional, List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import threading
from loguru import logger

from app.database import AsyncSessionLocal
from app import models

# 全局任务管理器
class TaskManager:
    """任务管理器"""
    _instance = None
    _lock = threading.Lock()

    def __init__(self):
        self.tasks = {}  # task_id -> (process, thread)
        self.executor = ThreadPoolExecutor(max_workers=5)
        self.running_tasks = {}

    @classmethod
    async def init(cls):
        """初始化任务管理器"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    async def shutdown(cls):
        """关闭任务管理器"""
        if cls._instance:
            cls._instance.executor.shutdown(wait=True)

    async def add_task(self, task_id: str, coro):
        """添加任务"""
        future = asyncio.create_task(coro)
        self.running_tasks[task_id] = future
        return future

    async def stop_task(self, task_id: str) -> bool:
        """停止任务"""
        if task_id in self.running_tasks:
            future = self.running_tasks[task_id]
            future.cancel()
            try:
                await future
            except asyncio.CancelledError:
                pass
            del self.running_tasks[task_id]
            return True
        return False

    def get_task(self, task_id: str):
        """获取任务"""
        return self.running_tasks.get(task_id)


async def execute_codewiki_task(
        task_id: str,
        include_patterns: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
        folder: str = ".",
        config_overrides: Optional[Dict[str, Any]] = None
):
    """执行CodeWiki任务"""
    # 更新任务状态为运行中
    async with AsyncSessionLocal() as db:
        task = await models.Task.get(db, task_id)
        if task:
            task.status = "running"
            task.started_at = datetime.utcnow()
            await db.commit()

    # 创建日志文件
    log_file = f"logs/{task_id}.log"
    os.makedirs("logs", exist_ok=True)

    try:
        # 构建codewiki命令
        cmd = ["codewiki", "generate"]

        # 添加包含模式
        if include_patterns:
            cmd.extend(["--include", ",".join(include_patterns)])

        # 添加排除模式
        if exclude_patterns:
            cmd.extend(["--exclude", ",".join(exclude_patterns)])

        # 添加其他选项
        cmd.extend(["--verbose"])  # 启用详细日志

        cmd.extend(["--github-pages"])

        # 设置工作目录
        workspace_dir = "/config/workspace"
        if folder and folder != ".":
            workspace_dir = os.path.join(workspace_dir, folder)

        logger.info(f"Executing command: {' '.join(cmd)}")
        logger.info(f"Working directory: {workspace_dir}")

        # 在单独的线程中执行命令
        def run_command():
            with open(log_file, 'w', encoding='utf-8') as log:
                # 写入命令信息
                log.write(f"Command: {' '.join(cmd)}\n")
                log.write(f"Working directory: {workspace_dir}\n")
                log.write(f"Started at: {datetime.utcnow().isoformat()}\n")
                log.write("=" * 80 + "\n\n")

                try:
                    # 执行命令
                    process = subprocess.Popen(
                        cmd,
                        cwd=workspace_dir,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        encoding='utf-8',
                        bufsize=1,
                        universal_newlines=True
                    )

                    # 实时读取输出
                    for line in process.stdout:
                        log.write(line)
                        log.flush()

                    # 等待进程结束
                    process.wait()

                    return process.returncode

                except Exception as e:
                    log.write(f"Error executing command: {str(e)}\n")
                    return 1

        # 在线程池中执行
        loop = asyncio.get_event_loop()
        return_code = await loop.run_in_executor(
            TaskManager._instance.executor,
            run_command
        )

        # 更新任务状态
        async with AsyncSessionLocal() as db:
            task = await models.Task.get(db, task_id)
            if task:
                task.status = "completed" if return_code == 0 else "failed"
                task.completed_at = datetime.utcnow()
                if return_code != 0:
                    task.error_message = f"Process exited with code {return_code}"
                await db.commit()

        logger.info(f"Task {task_id} completed with return code {return_code}")

    except Exception as e:
        logger.error(f"Task {task_id} failed: {str(e)}")

        # 更新任务状态为失败
        async with AsyncSessionLocal() as db:
            task = await models.Task.get(db, task_id)
            if task:
                task.status = "failed"
                task.completed_at = datetime.utcnow()
                task.error_message = str(e)
                await db.commit()


async def apply_config_overrides(config_overrides: Dict[str, Any]):
    """应用配置覆盖"""
    if not config_overrides:
        return

    # 构建配置命令
    for key, value in config_overrides.items():
        # 这里需要根据codewiki的配置格式进行调整
        # 例如: codewiki config set --api-key value
        cmd = ["codewiki", "config", "set", f"--{key.replace('_', '-')}", str(value)]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                logger.warning(f"Failed to set config {key}: {stderr.decode()}")
            else:
                logger.info(f"Config {key} set successfully")

        except Exception as e:
            logger.error(f"Error setting config {key}: {str(e)}")