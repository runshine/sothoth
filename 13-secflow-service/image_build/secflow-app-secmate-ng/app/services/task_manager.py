"""
Secmate-NG Manager - 任务管理服务
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
    get_db_session, generate_id, SecmateNg, Task,
    SecmateNgStatus, TaskStatus, TaskType
)
from app.services.k8s_api_client import get_k8s_api_client

logger = logging.getLogger(__name__)


class TaskManager:
    """任务管理器"""

    def __init__(self):
        self.config = get_config()
        self.executor = ThreadPoolExecutor(max_workers=self.config.tasks.max_concurrent_tasks)
        self.running_tasks: Dict[str, Any] = {}
        self.lock = threading.Lock()
        self.cleanup_thread: Optional[threading.Thread] = None
        self.running = False

    def start(self):
        """启动任务管理器"""
        self.running = True
        self._recover_tasks()
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()
        logger.info("任务管理器启动成功")

    def stop(self):
        """停止任务管理器"""
        self.running = False
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
                time.sleep(3600)

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
                   secmate_id: str = None, secmate_name: str = None) -> Task:
        """创建任务"""
        db = get_db_session()
        try:
            task = Task(
                id=generate_id(),
                project_id=project_id,
                type=task_type,
                status=TaskStatus.PENDING.value,
                secmate_id=secmate_id,
                secmate_name=secmate_name,
                params=params
            )
            db.add(task)
            db.commit()

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

            task.status = TaskStatus.RUNNING.value
            task.started_at = datetime.utcnow()
            db.commit()

            logger.info(f"开始执行任务 {task_id}: {task.type}")

            try:
                if task.type == TaskType.CREATE.value:
                    result = self._handle_create_task(task, db)
                elif task.type == TaskType.DELETE.value:
                    result = self._handle_delete_task(task, db)
                elif task.type == TaskType.RESTART.value:
                    result = self._handle_restart_task(task, db)
                else:
                    raise ValueError(f"未知任务类型: {task.type}")

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
        secmate_id = params.get("secmate_id")
        custom_env = params.get("custom_env") or {}
        custom_env["PROJECT_ID"] = task.project_id
        secmate_env = params.get("secmate_env") or {}
        image = params.get("image")
        user_token = params.get("user_token")
        project_id = task.project_id

        k8s_client = get_k8s_api_client()

        secmate = db.query(SecmateNg).filter(SecmateNg.id == secmate_id).first()
        if not secmate:
            raise ValueError(f"SecmateNg {secmate_id} 不存在")

        try:
            secmate.status = SecmateNgStatus.CREATING.value
            db.commit()

            # 1. 创建输出PVC
            output_pvcs_config = []
            for pvc_info in secmate.output_pvcs or []:
                pvc_name = pvc_info.get("pvc_name")
                storage_size = pvc_info.get("storage_size") or self.config.pvc.storage_size

                if not pvc_name:
                    pvc_name = f"{secmate.name}-output-{len(output_pvcs_config)}"

                pvc_manifest = self._build_pvc_manifest(pvc_name, storage_size)
                
                try:
                    k8s_client.create_pvc(project_id, pvc_manifest, user_token)
                except Exception as e:
                    if "already exists" not in str(e).lower():
                        raise

                output_pvcs_config.append({
                    "pvc_name": pvc_name,
                    "mount_path": pvc_info.get("mount_path", "/output"),
                    "created": True
                })

            secmate.output_pvcs = output_pvcs_config
            db.commit()

            # 2. 创建Deployment
            deployment_name = f"secmate-ng-{secmate.name}"
            deployment_manifest = self._build_deployment_manifest(
                secmate, deployment_name, secmate_id, output_pvcs_config, custom_env, secmate_env, image
            )
            k8s_client.create_deployment(project_id, deployment_manifest, user_token)
            secmate.deployment_name = deployment_name
            db.commit()

            # 3. 创建Service
            service_name = f"secmate-ng-{secmate.name}"
            service_manifest = self._build_service_manifest(service_name, secmate_id)
            k8s_client.create_service(project_id, service_manifest, user_token)
            secmate.service_name = service_name
            db.commit()

            # 4. 创建Ingress
            ingress_name = f"secmate-ng-{secmate.name}"
            ingress_manifest = self._build_ingress_manifest(ingress_name, secmate_id, service_name)
            k8s_client.create_ingress(project_id, ingress_manifest, user_token)
            
            host = f"{secmate_id}.{self.config.ingress.base_domain}"
            secmate.ingress_name = ingress_name
            secmate.access_url = f"https://{host}" if self.config.ingress.tls_enabled else f"http://{host}"

            # 5. 获取Pod信息
            time.sleep(2)
            pods = k8s_client.get_pods_by_deployment(
                project_id,
                f"app=secmate-ng,secmate-id={secmate_id}",
                user_token
            )
            if pods:
                secmate.pod_name = pods[0].get("name")

            secmate.status = SecmateNgStatus.RUNNING.value
            db.commit()

            return f"SecmateNg {secmate.name} 创建成功，访问地址: {secmate.access_url}"

        except Exception as e:
            secmate.status = SecmateNgStatus.ERROR.value
            db.commit()
            raise

    def _handle_delete_task(self, task: Task, db: Session) -> str:
        """处理删除任务"""
        params = task.params or {}
        secmate_id = params.get("secmate_id")
        delete_output_pvcs = params.get("delete_output_pvcs", False)
        user_token = params.get("user_token")
        project_id = task.project_id

        k8s_client = get_k8s_api_client()

        secmate = db.query(SecmateNg).filter(SecmateNg.id == secmate_id).first()
        if not secmate:
            raise ValueError(f"SecmateNg {secmate_id} 不存在")

        try:
            # 1. 删除Ingress
            if secmate.ingress_name:
                k8s_client.delete_ingress(project_id, secmate.ingress_name, user_token)

            # 2. 删除Service
            if secmate.service_name:
                k8s_client.delete_service(project_id, secmate.service_name, user_token)

            # 3. 删除Deployment
            if secmate.deployment_name:
                k8s_client.delete_deployment(project_id, secmate.deployment_name, user_token)

            # 4. 删除PVC（如果需要）
            if delete_output_pvcs:
                for pvc_info in secmate.output_pvcs or []:
                    pvc_name = pvc_info.get("pvc_name")
                    if pvc_name:
                        k8s_client.delete_pvc(project_id, pvc_name, user_token)

            # 5. 更新状态
            secmate.status = SecmateNgStatus.DELETED.value
            secmate.access_url = None
            secmate.pod_name = None
            secmate.deleted_at = datetime.utcnow()
            db.commit()

            return f"SecmateNg {secmate.name} 删除成功"

        except Exception as e:
            secmate.status = SecmateNgStatus.ERROR.value
            db.commit()
            raise

    def _handle_restart_task(self, task: Task, db: Session) -> str:
        """处理重建任务"""
        params = task.params or {}
        secmate_id = params.get("secmate_id")
        user_token = params.get("user_token")
        project_id = task.project_id

        k8s_client = get_k8s_api_client()

        secmate = db.query(SecmateNg).filter(SecmateNg.id == secmate_id).first()
        if not secmate:
            raise ValueError(f"SecmateNg {secmate_id} 不存在")

        if not secmate.deployment_name:
            raise ValueError("SecmateNg没有关联的Deployment")

        try:
            old_status = secmate.status
            secmate.status = SecmateNgStatus.PENDING.value
            db.commit()

            # 使用restart API
            k8s_client.restart_deployment(project_id, secmate.deployment_name, user_token)

            # 等待并获取新Pod
            time.sleep(5)
            pods = k8s_client.get_pods_by_deployment(
                project_id,
                f"app=secmate-ng,secmate-id={secmate_id}",
                user_token
            )
            if pods:
                secmate.pod_name = pods[0].get("name")

            secmate.status = SecmateNgStatus.RUNNING.value
            db.commit()

            return f"SecmateNg {secmate.name} 重建成功"

        except Exception as e:
            secmate.status = old_status if 'old_status' in locals() else SecmateNgStatus.ERROR.value
            db.commit()
            raise

    def _build_pvc_manifest(self, pvc_name: str, storage_size: str) -> dict:
        """构建PVC manifest"""
        return {
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {
                "name": pvc_name,
                "labels": {
                    "app": "secmate-ng",
                    "managed-by": "secmate-ng-manager"
                }
            },
            "spec": {
                "accessModes": [self.config.pvc.access_mode],
                "resources": {
                    "requests": {
                        "storage": storage_size
                    }
                },
                "storageClassName": self.config.pvc.storage_class
            }
        }

    def _build_deployment_manifest(self, secmate: SecmateNg, name: str, secmate_id: str,
                                   output_pvcs: list, custom_env: dict, secmate_env: dict,
                                   image: str = None) -> dict:
        """构建Deployment manifest"""
        config = self.config.secmate_ng

        volumes = []
        volume_mounts = []
        volume_index = 0

        # 源码PVC
        for pvc_info in secmate.source_pvcs or []:
            volume_name = f"source-volume-{volume_index}"
            volumes.append({
                "name": volume_name,
                "persistentVolumeClaim": {
                    "claimName": pvc_info["pvc_name"]
                }
            })
            volume_mounts.append({
                "name": volume_name,
                "mountPath": pvc_info["mount_path"]
            })
            volume_index += 1

        # 输出PVC
        for pvc_info in output_pvcs:
            volume_name = f"output-volume-{volume_index}"
            volumes.append({
                "name": volume_name,
                "persistentVolumeClaim": {
                    "claimName": pvc_info["pvc_name"]
                }
            })
            volume_mounts.append({
                "name": volume_name,
                "mountPath": pvc_info["mount_path"]
            })
            volume_index += 1

        # 构建环境变量（优先级：custom_env > secmate_env > default_secmate_env > common_env）
        env = []

        # 1. 添加通用环境变量（最低优先级）
        for key, value in config.common_env.items():
            env.append({"name": key, "value": str(value)})

        # 2. 添加默认 Secmate-NG 环境变量
        for key, value in config.default_secmate_env.items():
            if key not in [e["name"] for e in env]:  # 不覆盖 common_env
                env.append({"name": key, "value": str(value)})

        # 3. 添加用户自定义的 Secmate-NG 环境变量（更高优先级）
        for key, value in secmate_env.items():
            # 移除已存在的同名环境变量
            env = [e for e in env if e["name"] != key]
            env.append({"name": key, "value": str(value)})

        # 4. 添加 custom_env（最高优先级，包含 PROJECT_ID 等）
        for key, value in custom_env.items():
            # 移除已存在的同名环境变量
            env = [e for e in env if e["name"] != key]
            env.append({"name": key, "value": str(value)})

        container_image = image if image else config.image

        return {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": name,
                "labels": {
                    "app": "secmate-ng",
                    "secmate-id": secmate_id,
                    "managed-by": "secmate-ng-manager"
                }
            },
            "spec": {
                "replicas": 1,
                "selector": {
                    "matchLabels": {
                        "app": "secmate-ng",
                        "secmate-id": secmate_id
                    }
                },
                "template": {
                    "metadata": {
                        "labels": {
                            "app": "secmate-ng",
                            "secmate-id": secmate_id
                        }
                    },
                    "spec": {
                        "containers": [{
                            "name": "secmate-ng",
                            "image": container_image,
                            "imagePullPolicy": config.image_pull_policy,
                            "ports": [{
                                "containerPort": config.container_port,
                                "name": "http"
                            }],
                            "env": env,
                            "volumeMounts": volume_mounts,
                            "resources": config.resources
                        }],
                        "volumes": volumes
                    }
                }
            }
        }

    def _build_service_manifest(self, name: str, secmate_id: str) -> dict:
        """构建Service manifest"""
        config = self.config.secmate_ng
        return {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": name,
                "labels": {
                    "app": "secmate-ng",
                    "secmate-id": secmate_id,
                    "managed-by": "secmate-ng-manager"
                }
            },
            "spec": {
                "type": config.service_type,
                "selector": {
                    "app": "secmate-ng",
                    "secmate-id": secmate_id
                },
                "ports": [{
                    "port": config.service_port,
                    "targetPort": config.container_port,
                    "protocol": "TCP",
                    "name": "http"
                }]
            }
        }

    def _build_ingress_manifest(self, name: str, secmate_id: str, service_name: str) -> dict:
        """构建Ingress manifest"""
        config = self.config.ingress
        host = f"{secmate_id}.{config.base_domain}"

        ingress = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": {
                "name": name,
                "labels": {
                    "app": "secmate-ng",
                    "secmate-id": secmate_id,
                    "managed-by": "secmate-ng-manager"
                },
                "annotations": {
                    "nginx.ingress.kubernetes.io/proxy-body-size": "100m",
                    "nginx.ingress.kubernetes.io/proxy-read-timeout": "3600",
                    "nginx.ingress.kubernetes.io/proxy-send-timeout": "3600",
                    "nginx.ingress.kubernetes.io/backend-protocol": "HTTP"
                }
            },
            "spec": {
                "ingressClassName": config.ingress_class,
                "rules": [{
                    "host": host,
                    "http": {
                        "paths": [{
                            "path": "/",
                            "pathType": "Prefix",
                            "backend": {
                                "service": {
                                    "name": service_name,
                                    "port": {
                                        "number": self.config.secmate_ng.service_port
                                    }
                                }
                            }
                        }]
                    }
                }]
            }
        }

        if config.tls_enabled and config.tls_secret_name:
            ingress["spec"]["tls"] = [{
                "hosts": [host],
                "secretName": config.tls_secret_name
            }]

        return ingress

    def delete_task(self, task_id: str) -> bool:
        """删除任务"""
        db = get_db_session()
        try:
            task = db.query(Task).filter(Task.id == task_id).first()
            if not task:
                return False

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


_task_manager: Optional[TaskManager] = None


def get_task_manager() -> TaskManager:
    """获取任务管理器实例"""
    global _task_manager
    if _task_manager is None:
        _task_manager = TaskManager()
    return _task_manager
