"""
任务管理器
"""
import time
import uuid
import logging
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional

from config import Config
from utils.errors import CodeServerError, ProjectError

logger = logging.getLogger(__name__)

class TaskManager:
    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=Config.MAX_WORKERS)
        self.tasks = {}

        # 启动一个空任务来初始化线程池
        self._init_thread_pool()

        logger.info(f"任务管理器初始化成功，最大线程数: {Config.MAX_WORKERS}")

    def _init_thread_pool(self):
        """初始化线程池，确保线程池在启动时就运行"""
        try:
            # 提交一个空任务来启动线程池
            def init_task():
                logger.info("线程池初始化任务执行完成")
                return "initialized"

            future = self.executor.submit(init_task)
            # 等待一小段时间让任务开始执行
            time.sleep(0.1)
            logger.info("线程池初始化完成")
        except Exception as e:
            logger.warning(f"线程池初始化时出现警告: {e}")
            # 即使初始化有警告，也继续运行

    def submit(self, task_type: str, func, *args, **kwargs) -> str:
        """提交任务"""
        task_id = str(uuid.uuid4())

        def task_wrapper():
            try:
                result = func(*args, **kwargs)
                self.tasks[task_id] = {
                    "status": "completed",
                    "result": result,
                    "completed_at": datetime.now(timezone.utc)
                }
                return result
            except CodeServerError as e:
                self.tasks[task_id] = {
                    "status": "failed",
                    "error": {
                        "message": e.message,
                        "details": e.details,
                        "status_code": e.status_code
                    },
                    "completed_at": datetime.now(timezone.utc)
                }
                logger.error(f"任务 {task_id} 失败: {e.message}")
                raise
            except ProjectError as e:
                self.tasks[task_id] = {
                    "status": "failed",
                    "error": {
                        "message": e.message,
                        "details": e.details,
                        "status_code": e.status_code
                    },
                    "completed_at": datetime.now(timezone.utc)
                }
                logger.error(f"任务 {task_id} 失败: {e.message}")
                raise
            except Exception as e:
                self.tasks[task_id] = {
                    "status": "failed",
                    "error": {
                        "message": str(e),
                        "details": {"type": type(e).__name__},
                        "status_code": 500
                    },
                    "completed_at": datetime.now(timezone.utc)
                }
                logger.error(f"任务 {task_id} 失败: {e}")
                raise

        future = self.executor.submit(task_wrapper)
        self.tasks[task_id] = {
            "status": "running",
            "future": future,
            "task_type": task_type,
            "started_at": datetime.now(timezone.utc)
        }

        logger.info(f"提交任务: {task_id}, 类型: {task_type}")
        return task_id

    def get_status(self, task_id: str) -> Dict[str, Any]:
        """获取任务状态"""
        task_info = self.tasks.get(task_id, {"status": "not_found"})

        if task_info["status"] == "running":
            future = task_info.get("future")
            if future and future.done():
                try:
                    result = future.result()
                    task_info["status"] = "completed"
                    task_info["result"] = result
                except Exception as e:
                    task_info["status"] = "failed"
                    if not task_info.get("error"):
                        task_info["error"] = {
                            "message": str(e),
                            "details": {"type": type(e).__name__},
                            "status_code": 500
                        }

        return task_info

    def is_healthy(self) -> bool:
        """检查任务管理器是否健康"""
        try:
            # 检查线程池是否已关闭
            if self.executor._shutdown:
                return False

            # 检查是否有可用的工作线程
            # 注意：ThreadPoolExecutor 没有直接的方法检查活跃线程数
            # 但我们可以检查是否有线程在运行或等待
            if hasattr(self.executor, '_threads'):
                # 检查是否有活跃线程
                return len(self.executor._threads) > 0
            else:
                # 如果无法检查线程状态，假设健康
                return True
        except Exception as e:
            logger.warning(f"检查任务管理器健康状态失败: {e}")
            return True  # 即使检查失败，也假设健康，避免误报