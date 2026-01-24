"""
PVC管理任务函数
"""
import os
import re
import time
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from config import Config
from database import SessionLocal
from models import Project, ProjectTaskLog
from utils.errors import ProjectError, CodeServerError
from utils.task_logger import TaskLogger
from managers.kubernetes_manager import KubernetesManager

logger = logging.getLogger(__name__)

def create_project_pvc_task(project_id: str, storage_size: str = "5Gi"):
    """创建项目PVC并拷贝压缩包"""
    logger.info(f"开始创建项目PVC: project_id={project_id}")

    # 创建日志文件
    log_file_path = os.path.join(Config.TASK_LOG_DIR, f"{project_id}/pvc_create_{int(time.time())}.log")
    task_logger = TaskLogger(log_file_path)

    db = SessionLocal()
    project_task_log = None

    try:
        task_logger.info(f"开始创建项目PVC任务: {project_id}")
        task_logger.info(f"存储大小: {storage_size}")

        # 创建任务日志记录
        project_task_log = ProjectTaskLog(
            project_id=project_id,
            task_type="create_pvc",
            task_id=f"pvc_create_{project_id}_{int(time.time())}",
            status="running",
            log_path=log_file_path
        )
        db.add(project_task_log)
        db.commit()

        # 获取项目
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            error_msg = f"项目不存在: {project_id}"
            task_logger.error(error_msg)
            raise ProjectError(
                message="项目不存在",
                details={"project_id": project_id},
                status_code=404
            )

        # 检查项目是否有压缩包
        if not project.archive_path or not os.path.exists(project.archive_path):
            error_msg = f"项目压缩包不存在: {project.archive_path}"
            task_logger.error(error_msg)
            raise ProjectError(
                message="项目压缩包不存在，无法创建PVC",
                details={"project_id": project_id, "archive_path": project.archive_path},
                status_code=400
            )

        # 更新项目状态
        project.pvc_status = "creating"
        db.commit()

        # 初始化K8S管理器
        k8s = KubernetesManager(validate_connection=False)
        if not k8s.available:
            error_msg = "Kubernetes功能不可用"
            task_logger.error(error_msg)
            raise ProjectError(
                message="Kubernetes功能不可用",
                details={"project_id": project_id},
                status_code=503
            )

        # 步骤1: 创建PVC
        pvc_name = k8s.create_pvc(project_id, storage_size)
        project.pvc_name = pvc_name
        project.pvc_size = storage_size
        db.commit()

        # 等待PVC绑定
        task_logger.info(f"等待PVC绑定: {pvc_name}")
        for i in range(30):
            time.sleep(2)
            try:
                pvc = k8s.core_v1.read_namespaced_persistent_volume_claim(
                    name=pvc_name, namespace=k8s.namespace
                )
                if pvc.status.phase == "Bound":
                    task_logger.info(f"PVC已绑定: {pvc_name}")
                    project.pvc_status = "ready"
                    db.commit()
                    break
                elif pvc.status.phase == "Pending":
                    task_logger.info(f"PVC状态: Pending ({i+1}/30)")
                else:
                    task_logger.warning(f"PVC状态: {pvc.status.phase}")
            except:
                task_logger.warning(f"获取PVC状态失败 ({i+1}/30)")
                continue

        # 步骤2: 复制压缩包到PVC并解压
        task_logger.info(f"复制压缩包到PVC并解压: {pvc_name}")
        try:
            k8s.copy_archive_to_pvc(project_id, project.archive_path, pvc_name)
            project.file_synced = True
            db.commit()
            task_logger.info("压缩包复制并解压到PVC成功")
        except CodeServerError as e:
            error_msg = f"复制并解压文件到PVC失败: {e.message}"
            task_logger.error(error_msg)
            project.pvc_status = "error"
            db.commit()
            # 复制文件失败是严重错误，需要抛出异常
            raise ProjectError(
                message="复制并解压文件到PVC失败",
                details={
                    "project_id": project_id,
                    "error": e.message,
                    "details": e.details
                },
                status_code=e.status_code
            )

        # 更新任务日志
        if project_task_log:
            project_task_log.status = "completed"
            project_task_log.completed_at = datetime.now(timezone.utc)
            db.commit()

        result = {
            "success": True,
            "project_id": project_id,
            "pvc_name": pvc_name,
            "pvc_size": storage_size,
            "file_synced": project.file_synced,
            "status": "ready"
        }

        task_logger.info(f"项目PVC创建成功: {result}")
        return result

    except ProjectError:
        # 记录错误状态
        try:
            if 'project' in locals():
                project.pvc_status = "error"
                db.commit()

            if project_task_log:
                project_task_log.status = "failed"
                project_task_log.error_message = str(sys.exc_info()[1])
                project_task_log.completed_at = datetime.now(timezone.utc)
                db.commit()
        except:
            pass

        # 重新抛出异常
        raise

    except Exception as e:
        task_logger.error(f"创建项目PVC失败: {e}")

        # 更新状态为错误
        try:
            if 'project' in locals():
                project.pvc_status = "error"
                db.commit()

            if project_task_log:
                project_task_log.status = "failed"
                project_task_log.error_message = str(e)
                project_task_log.completed_at = datetime.now(timezone.utc)
                db.commit()
        except:
            pass

        # 包装为ProjectError
        raise ProjectError(
            message="创建项目PVC失败",
            details={
                "project_id": project_id,
                "error": str(e),
                "error_type": type(e).__name__
            },
            status_code=500
        )

    finally:
        db.close()
        task_logger.info("项目PVC创建任务结束")

def recreate_project_pvc_task(project_id: str, storage_size: str = None):
    """重建项目PVC的逻辑 - 直接清空并重新拷贝解压"""
    logger.info(f"开始重建项目PVC: project_id={project_id}")

    # 创建日志文件
    log_file_path = os.path.join(Config.TASK_LOG_DIR, f"{project_id}/pvc_recreate_{int(time.time())}.log")
    task_logger = TaskLogger(log_file_path)

    db = SessionLocal()
    project_task_log = None

    try:
        task_logger.info(f"开始重建项目PVC任务: {project_id}")
        task_logger.info(f"存储大小: {storage_size or '使用原大小'}")

        # 创建任务日志记录
        project_task_log = ProjectTaskLog(
            project_id=project_id,
            task_type="recreate_pvc",
            task_id=f"pvc_recreate_{project_id}_{int(time.time())}",
            status="running",
            log_path=log_file_path
        )
        db.add(project_task_log)
        db.commit()

        # 获取项目
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            error_msg = f"项目不存在: {project_id}"
            task_logger.error(error_msg)
            raise ProjectError(
                message="项目不存在",
                details={"project_id": project_id},
                status_code=404
            )

        # 检查项目是否还有压缩包
        if not project.archive_path or not os.path.exists(project.archive_path):
            error_msg = f"项目压缩包不存在，无法重建PVC: {project.archive_path}"
            task_logger.error(error_msg)
            raise ProjectError(
                message="项目压缩包不存在，无法重建PVC",
                details={"project_id": project_id, "archive_path": project.archive_path},
                status_code=400
            )

        # 更新项目状态
        project.pvc_status = "recreating"
        project.file_synced = False
        db.commit()

        # 初始化K8S管理器
        k8s = KubernetesManager(validate_connection=False)
        if not k8s.available:
            error_msg = "Kubernetes功能不可用"
            task_logger.error(error_msg)
            raise ProjectError(
                message="Kubernetes功能不可用",
                details={"project_id": project_id},
                status_code=503
            )

        # 步骤1: 清空PVC内容
        task_logger.info("步骤1: 清空PVC内容")
        pvc_name = project.pvc_name or k8s.generate_resource_name(project_id, "pvc")

        # 如果PVC不存在，先创建它
        pvc_exists = False
        try:
            k8s.core_v1.read_namespaced_persistent_volume_claim(
                name=pvc_name, namespace=k8s.namespace
            )
            pvc_exists = True
            task_logger.info(f"PVC已存在: {pvc_name}")
        except k8s.ApiException as e:
            if e.status == 404:
                task_logger.info(f"PVC不存在: {pvc_name}")
                pvc_exists = False
            else:
                raise

        if not pvc_exists:
            # 创建新的PVC
            target_storage_size = storage_size or project.pvc_size or Config.K8S_DEFAULT_STORAGE_SIZE
            task_logger.info(f"创建新的PVC: {pvc_name}, 大小: {target_storage_size}")
            try:
                pvc_name = k8s.create_pvc(project_id, target_storage_size)
                project.pvc_name = pvc_name
                project.pvc_size = target_storage_size
                db.commit()
            except Exception as e:
                error_msg = f"创建PVC失败: {str(e)}"
                task_logger.error(error_msg)
                raise ProjectError(
                    message="创建PVC失败",
                    details={"project_id": project_id, "error": str(e)},
                    status_code=500
                )
        else:
            # PVC已存在，清空内容
            task_logger.info(f"清空PVC内容: {pvc_name}")
            try:
                # 创建一个临时Pod来清空PVC内容
                cleanup_pod_name = f"cleanup-{project_id[:8]}"
                cleanup_pod_name = re.sub(r'[^a-z0-9-]', '-', cleanup_pod_name.lower())[:63]

                cleanup_pod = k8s.client.V1Pod(
                    metadata=k8s.client.V1ObjectMeta(
                        name=cleanup_pod_name,
                        namespace=k8s.namespace,
                        labels={
                            "app": "pvc-cleanup",
                            "project-id": project_id,
                            "managed-by": "source-manager"
                        }
                    ),
                    spec=k8s.client.V1PodSpec(
                        restart_policy="Never",
                        containers=[k8s.client.V1Container(
                            name="cleanup",
                            image="alpine:latest",
                            command=["sh", "-c", "rm -rf /workspace/* && echo 'PVC内容已清空'"],
                            volume_mounts=[k8s.client.V1VolumeMount(
                                name="workspace",
                                mount_path="/workspace"
                            )],
                            resources=k8s.client.V1ResourceRequirements(
                                requests={
                                    "cpu": "100m",
                                    "memory": "128Mi"
                                }
                            )
                        )],
                        volumes=[k8s.client.V1Volume(
                            name="workspace",
                            persistent_volume_claim=k8s.client.V1PersistentVolumeClaimVolumeSource(
                                claim_name=pvc_name
                            )
                        )]
                    )
                )

                k8s.core_v1.create_namespaced_pod(
                    namespace=k8s.namespace, body=cleanup_pod
                )
                task_logger.info(f"创建清空Pod: {cleanup_pod_name}")

                # 等待Pod完成
                for i in range(30):
                    time.sleep(2)
                    try:
                        pod_status = k8s.core_v1.read_namespaced_pod_status(
                            name=cleanup_pod_name, namespace=k8s.namespace
                        )
                        if pod_status.status.phase == "Succeeded":
                            task_logger.info(f"清空Pod完成: {cleanup_pod_name}")
                            break
                        elif pod_status.status.phase == "Failed":
                            task_logger.warning(f"清空Pod失败: {cleanup_pod_name}")
                            # 继续执行，即使清空失败
                            break
                    except:
                        task_logger.warning(f"获取清空Pod状态失败 ({i+1}/30)")
                        continue

                # 删除清空Pod
                try:
                    k8s.core_v1.delete_namespaced_pod(
                        name=cleanup_pod_name, namespace=k8s.namespace,
                        grace_period_seconds=0
                    )
                    task_logger.info(f"删除清空Pod: {cleanup_pod_name}")
                except:
                    pass

            except Exception as e:
                task_logger.warning(f"清空PVC内容失败: {str(e)}")
                # 继续执行，即使清空失败

        # 步骤2: 复制压缩包到PVC并解压
        task_logger.info(f"步骤2: 复制压缩包到PVC并解压: {pvc_name}")
        try:
            k8s.copy_archive_to_pvc(project_id, project.archive_path, pvc_name)
            project.file_synced = True
            project.pvc_status = "ready"
            db.commit()
            task_logger.info("压缩包复制并解压到PVC成功")
        except CodeServerError as e:
            error_msg = f"复制并解压文件到PVC失败: {e.message}"
            task_logger.error(error_msg)
            project.pvc_status = "error"
            db.commit()
            # 复制文件失败是严重错误，需要抛出异常
            raise ProjectError(
                message="复制并解压文件到PVC失败",
                details={
                    "project_id": project_id,
                    "error": e.message,
                    "details": e.details
                },
                status_code=e.status_code
            )

        # 更新任务日志
        if project_task_log:
            project_task_log.status = "completed"
            project_task_log.completed_at = datetime.now(timezone.utc)
            db.commit()

        result = {
            "success": True,
            "project_id": project_id,
            "pvc_name": pvc_name,
            "pvc_size": project.pvc_size,
            "file_synced": project.file_synced,
            "status": "ready",
            "message": "PVC重建成功，内容已清空并重新解压"
        }

        task_logger.info(f"项目PVC重建成功: {result}")
        return result

    except ProjectError:
        # 记录错误状态
        try:
            if 'project' in locals():
                project.pvc_status = "error"
                db.commit()

            if project_task_log:
                project_task_log.status = "failed"
                project_task_log.error_message = str(sys.exc_info()[1])
                project_task_log.completed_at = datetime.now(timezone.utc)
                db.commit()
        except:
            pass

        # 重新抛出异常
        raise

    except Exception as e:
        task_logger.error(f"重建项目PVC失败: {e}")

        # 更新状态为错误
        try:
            if 'project' in locals():
                project.pvc_status = "error"
                db.commit()

            if project_task_log:
                project_task_log.status = "failed"
                project_task_log.error_message = str(e)
                project_task_log.completed_at = datetime.now(timezone.utc)
                db.commit()
        except:
            pass

        # 包装为ProjectError
        raise ProjectError(
            message="重建项目PVC失败",
            details={
                "project_id": project_id,
                "error": str(e),
                "error_type": type(e).__name__
            },
            status_code=500
        )

    finally:
        db.close()
        task_logger.info("项目PVC重建任务结束")