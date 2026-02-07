"""
Code Server Manager - 任务管理服务
"""

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Callable

from sqlalchemy.orm import Session

from app.config import get_config
from app.model import (
    get_db_session, generate_id, CodeServer, Task,
    CodeServerStatus, TaskStatus, TaskType
)
from app.services.k8s import get_k8s_service

logger = logging.getLogger(__name__)


class TaskManager:
    """任务管理器"""

    def __init__(self):
        self.config = get_config()
        self.executor = ThreadPoolExecutor(max_workers=self.config.tasks.max_concurrent_tasks)
        self.running_tasks: Dict[str, Any] = {}  # task_id -> Future
        self.lock = threading.Lock()
        self.cleanup_thread: Optional[threading.Thread] = None
        self.running = False

    def start(self):
        """启动任务管理器"""
        self.running = True

        # 恢复运行中的任务状态
        self._recover_tasks()

        # 启动清理线程
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()

        logger.info("任务管理器启动成功")

    def stop(self):
        """停止任务管理器"""
        self.running = False

        # 等待所有任务完成
        with self.lock:
            for task_id, future in list(self.running_tasks.items()):
                if not future.done():
                    logger.warning(f"等待任务 {task_id} 完成...")

        self.executor.shutdown(wait=True)
        logger.info("任务管理器已停止")

    def _recover_tasks(self):
        """恢复运行中的任务（服务重启时）"""
        db = get_db_session()
        try:
            running_tasks = db.query(Task).filter(
                Task.status.in_([TaskStatus.PENDING.value, TaskStatus.RUNNING.value])
            ).all()

            for task in running_tasks:
                # 标记为失败
                task.status = TaskStatus.FAILED.value
                task.error_message = "服务重启，任务中断"
                task.completed_at = datetime.utcnow()
                logger.info(f"恢复任务 {task.id}，标记为失败")

            db.commit()
        finally:
            db.close()

    def _cleanup_loop(self):
        """清理任务循环"""
        while self.running:
            try:
                self._cleanup_old_tasks()
                time.sleep(self.config.tasks.cleanup_interval_hours * 3600)
            except Exception as e:
                logger.error(f"清理任务失败: {e}")
                time.sleep(3600)  # 出错后1小时再尝试

    def _cleanup_old_tasks(self):
        """清理旧的任务记录"""
        cutoff_date = datetime.utcnow() - timedelta(days=self.config.tasks.retention_days)

        db = get_db_session()
        try:
            old_tasks = db.query(Task).filter(
                Task.status.in_([TaskStatus.COMPLETED.value, TaskStatus.FAILED.value, TaskStatus.CANCELLED.value]),
                Task.completed_at < cutoff_date
            ).all()

            for task in old_tasks:
                db.delete(task)

            db.commit()
            logger.info(f"清理了 {len(old_tasks)} 个旧任务")
        finally:
            db.close()

    def create_task(self, project_id: str, task_type: str, params: Dict[str, Any],
                   code_server_id: str = None, code_server_name: str = None) -> Task:
        """创建任务"""
        db = get_db_session()
        try:
            task = Task(
                id=generate_id(),
                project_id=project_id,
                type=task_type,
                status=TaskStatus.PENDING.value,
                code_server_id=code_server_id,
                code_server_name=code_server_name,
                params=params
            )
            db.add(task)
            db.commit()

            # 提交到线程池执行
            future = self.executor.submit(self._execute_task, task.id)

            with self.lock:
                self.running_tasks[task.id] = future

            return task
        finally:
            db.close()

    def _execute_task(self, task_id: str):
        """执行任务"""
        db = get_db_session()
        try:
            task = db.query(Task).filter(Task.id == task_id).first()
            if not task:
                logger.error(f"任务 {task_id} 不存在")
                return

            # 更新状态为运行中
            task.status = TaskStatus.RUNNING.value
            task.started_at = datetime.utcnow()
            db.commit()

            logger.info(f"开始执行任务 {task_id}: {task.type}")

            try:
                # 根据任务类型执行
                if task.type == TaskType.CREATE.value:
                    result = self._handle_create_task(task, db)
                elif task.type == TaskType.DELETE.value:
                    result = self._handle_delete_task(task, db)
                elif task.type == TaskType.RESTART.value:
                    result = self._handle_restart_task(task, db)
                else:
                    raise ValueError(f"未知任务类型: {task.type}")

                # 标记为完成
                task.status = TaskStatus.COMPLETED.value
                task.result = str(result) if result else None
                task.completed_at = datetime.utcnow()
                logger.info(f"任务 {task_id} 完成")

            except Exception as e:
                logger.error(f"任务 {task_id} 执行失败: {e}")
                task.status = TaskStatus.FAILED.value
                task.error_message = str(e)
                task.completed_at = datetime.utcnow()

            db.commit()

        finally:
            with self.lock:
                if task_id in self.running_tasks:
                    del self.running_tasks[task_id]
            db.close()

    def _handle_create_task(self, task: Task, db: Session) -> str:
        """处理创建任务"""
        params = task.params or {}
        code_server_id = params.get("code_server_id")
        namespace = params.get("namespace")
        name = params.get("name")
        custom_env = params.get("custom_env", {})
        # 注入PROJECT_ID环境变量
        custom_env["PROJECT_ID"] = task.project_id
        code_server_env = params.get("code_server_env", {})
        image = params.get("image")  # 获取自定义镜像参数

        k8s_service = get_k8s_service()

        # 获取Code Server记录
        code_server = db.query(CodeServer).filter(CodeServer.id == code_server_id).first()
        if not code_server:
            raise ValueError(f"Code Server {code_server_id} 不存在")

        try:
            # 更新状态
            code_server.status = CodeServerStatus.CREATING.value
            db.commit()

            # 1. 创建输出PVC（如果不存在）
            output_pvcs_config = []
            for pvc_info in code_server.output_pvcs or []:
                pvc_name = pvc_info.get("pvc_name")
                storage_size = pvc_info.get("storage_size") or self.config.pvc.storage_size

                if not pvc_name:
                    # 生成PVC名称
                    pvc_name = f"{name}-output-{len(output_pvcs_config)}"

                # 检查并创建PVC
                if not k8s_service.check_pvc_exists(namespace, pvc_name):
                    if not k8s_service.create_pvc(namespace, pvc_name, storage_size):
                        raise RuntimeError(f"创建PVC {pvc_name} 失败")

                output_pvcs_config.append({
                    "pvc_name": pvc_name,
                    "mount_path": pvc_info.get("mount_path", "/output"),
                    "created": True
                })

            # 更新PVC信息
            code_server.output_pvcs = output_pvcs_config
            db.commit()

            # 2. 创建Deployment
            deployment_name = f"code-server-{name}"
            success, final_env = k8s_service.create_deployment(
                namespace=namespace,
                name=deployment_name,
                code_server_id=code_server_id,
                source_pvcs=code_server.source_pvcs or [],
                output_pvcs=output_pvcs_config,
                custom_env=custom_env,
                code_server_env=code_server_env,
                image=image  # 传递自定义镜像参数
            )
            if not success:
                raise RuntimeError(f"创建Deployment {deployment_name} 失败")

            code_server.deployment_name = deployment_name
            # 保存实际使用的环境变量（包含密码）
            code_server.code_server_env = final_env
            db.commit()

            # 3. 创建Service
            service_name = f"code-server-{name}"
            cluster_ip = k8s_service.create_service(namespace, service_name, code_server_id)
            if not cluster_ip:
                raise RuntimeError(f"创建Service {service_name} 失败")

            code_server.service_name = service_name
            db.commit()

            # 4. 创建Ingress
            ingress_name = f"code-server-{name}"
            host = k8s_service.create_ingress(namespace, ingress_name, code_server_id, service_name)
            if not host:
                raise RuntimeError(f"创建Ingress {ingress_name} 失败")

            code_server.ingress_name = ingress_name
            code_server.access_url = f"https://{host}" if self.config.ingress.tls_enabled else f"http://{host}"

            # 5. 获取Pod名称
            pod_info = k8s_service.get_pod_by_deployment(namespace, deployment_name)
            if pod_info:
                code_server.pod_name = pod_info.get("name")

            # 6. 更新状态为运行中
            code_server.status = CodeServerStatus.RUNNING.value
            db.commit()

            return f"Code Server {name} 创建成功，访问地址: {code_server.access_url}"

        except Exception as e:
            code_server.status = CodeServerStatus.ERROR.value
            db.commit()
            raise

    def _handle_delete_task(self, task: Task, db: Session) -> str:
        """处理删除任务"""
        params = task.params or {}
        code_server_id = params.get("code_server_id")
        delete_output_pvcs = params.get("delete_output_pvcs", False)

        k8s_service = get_k8s_service()

        # 获取Code Server记录
        code_server = db.query(CodeServer).filter(CodeServer.id == code_server_id).first()
        if not code_server:
            raise ValueError(f"Code Server {code_server_id} 不存在")

        namespace = code_server.namespace

        try:
            # 1. 删除Ingress
            if code_server.ingress_name:
                k8s_service.delete_ingress(namespace, code_server.ingress_name)

            # 2. 删除Service
            if code_server.service_name:
                k8s_service.delete_service(namespace, code_server.service_name)

            # 3. 删除Deployment
            if code_server.deployment_name:
                k8s_service.delete_deployment(namespace, code_server.deployment_name)

            # 4. 删除PVC（如果需要）
            if delete_output_pvcs:
                for pvc_info in code_server.output_pvcs or []:
                    pvc_name = pvc_info.get("pvc_name")
                    if pvc_name:
                        k8s_service.delete_pvc(namespace, pvc_name)

            # 5. 更新状态为已删除
            code_server.status = CodeServerStatus.DELETED.value
            code_server.access_url = None
            code_server.pod_name = None
            code_server.deleted_at = datetime.utcnow()
            db.commit()

            return f"Code Server {code_server.name} 删除成功"

        except Exception as e:
            code_server.status = CodeServerStatus.ERROR.value
            db.commit()
            raise

    def _handle_restart_task(self, task: Task, db: Session) -> str:
        """处理重建任务"""
        params = task.params or {}
        code_server_id = params.get("code_server_id")

        k8s_service = get_k8s_service()

        # 获取Code Server记录
        code_server = db.query(CodeServer).filter(CodeServer.id == code_server_id).first()
        if not code_server:
            raise ValueError(f"Code Server {code_server_id} 不存在")

        if not code_server.deployment_name:
            raise ValueError("Code Server没有关联的Deployment")

        try:
            # 保存当前状态
            old_status = code_server.status
            code_server.status = CodeServerStatus.PENDING.value
            db.commit()

            # 1. 缩容到0
            if not k8s_service.scale_deployment(
                code_server.namespace, code_server.deployment_name, 0
            ):
                raise RuntimeError("缩容Deployment失败")

            # 等待Pod终止
            time.sleep(5)

            # 2. 扩容到1
            if not k8s_service.scale_deployment(
                code_server.namespace, code_server.deployment_name, 1
            ):
                raise RuntimeError("扩容Deployment失败")

            # 3. 更新Pod名称
            pod_info = k8s_service.get_pod_by_deployment(
                code_server.namespace, code_server.deployment_name
            )
            if pod_info:
                code_server.pod_name = pod_info.get("name")

            code_server.status = CodeServerStatus.RUNNING.value
            db.commit()

            return f"Code Server {code_server.name} 重建成功"

        except Exception as e:
            code_server.status = old_status if 'old_status' in locals() else CodeServerStatus.ERROR.value
            db.commit()
            raise

    def delete_task(self, task_id: str) -> bool:
        """删除任务"""
        db = get_db_session()
        try:
            task = db.query(Task).filter(Task.id == task_id).first()
            if not task:
                return False

            # 如果在运行中，取消它
            with self.lock:
                if task_id in self.running_tasks:
                    future = self.running_tasks[task_id]
                    if not future.done():
                        future.cancel()
                    del self.running_tasks[task_id]

            db.delete(task)
            db.commit()
            return True
        finally:
            db.close()


# 单例实例
_task_manager: Optional[TaskManager] = None


def get_task_manager() -> TaskManager:
    """获取任务管理器实例"""
    global _task_manager
    if _task_manager is None:
        _task_manager = TaskManager()
    return _task_manager
