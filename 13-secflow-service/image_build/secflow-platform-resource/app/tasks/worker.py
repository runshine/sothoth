"""Task worker for processing async resource task."""

import logging
import uuid
from typing import Optional, List

from sqlalchemy.orm import Session

from app.models import database
from app.models.database import (
    Resource, AsyncTaskLog, TaskStatus, TaskType, ResourceUploadStatus
)
from app.services.k8s import get_k8s_service

logger = logging.getLogger(__name__)


class ResourceTaskWorker:
    """资源任务处理器。"""

    @staticmethod
    async def process_upload_extract(
        task_id: str,
        db_session: Session,
        task: AsyncTaskLog,
        created_resources: List[dict],
        resource_uuid: str,
        project_id: str,
        project_ids: List[str],
        resource_name: str,
        resource_type: str,
        archive_url: str,
        pvc_size: int,
        original_file_name: str,
        original_file_size: int,
        original_file_md5: Optional[str],
        original_file_format: Optional[str]
    ) -> dict:
        """
        处理资源上传和解压任务。

        每次上传创建：
        1. PVC - 独立的存储卷
        2. Job - 下载并解压压缩包到PVC根目录

        Args:
            task_id: 任务ID
            db_session: 数据库会话
            task: 任务记录
            created_resources: 用于追踪创建的K8S资源
            resource_uuid: 资源UUID
            project_id: 项目ID
            resource_name: 资源名称
            resource_type: 资源类型
            archive_url: 压缩包URL
            pvc_size: PVC大小（Gi）
            original_file_name: 原始文件名
            original_file_size: 原始文件大小
            original_file_md5: 原始文件MD5
            original_file_format: 原始文件格式

        Returns:
            dict: 任务结果
        """
        from app.tasks.manager import get_task_manager
        task_manager = get_task_manager()
        k8s_service = get_k8s_service()

        try:
            await task_manager.append_task_log(task_id, f"Starting upload task for {resource_name}")
            await task_manager.update_task_progress(task_id, 5, "Initializing upload task")

            # 创建资源记录（先占位）
            resource = Resource(
                resource_uuid=resource_uuid,
                name=resource_name,
                resource_type=resource_type,
                original_file_name=original_file_name,
                original_file_size=original_file_size,
                original_file_md5=original_file_md5,
                original_file_format=original_file_format,
                upload_status=ResourceUploadStatus.UPLOADING,
                upload_message="Initializing upload",
                extract_path="/"
            )
            db_session.add(resource)
            db_session.commit()
            db_session.refresh(resource)

            # 更新任务关联的资源ID
            task.resource_id = resource.id
            db_session.commit()

            await task_manager.append_task_log(task_id, f"Resource record created: {resource.id}")
            await task_manager.update_task_progress(task_id, 10, "Creating PVC")

            # 生成唯一的PVC名称
            pvc_name = k8s_service.get_pvc_name(resource_uuid)
            project_namespace = k8s_service.get_project_namespace(project_id)

            # 步骤1: 创建PVC
            created_pvc = k8s_service.create_pvc(
                project_id=project_id,
                pvc_name=pvc_name,
                size=pvc_size  # 使用用户指定的PVC大小
            )

            if not created_pvc:
                raise Exception(f"Failed to create PVC: {pvc_name}")

            # 记录创建的PVC（用于失败时清理）
            created_resources.append({
                "type": "pvc",
                "name": pvc_name,
                "namespace": project_namespace
            })

            await task_manager.append_task_log(task_id, f"PVC created: {pvc_name}")
            await task_manager.update_task_progress(task_id, 20, "Waiting for PVC to be ready")

            # 等待PVC进入Bound状态
            pvc_bound = k8s_service.wait_for_pvc_bound(project_id, pvc_name, timeout=120)
            if not pvc_bound:
                raise Exception(f"PVC {pvc_name} did not become Bound within timeout")

            await task_manager.append_task_log(task_id, f"PVC is now Bound: {pvc_name}")
            await task_manager.update_task_progress(task_id, 30, "PVC ready, starting download job")

            await task_manager.append_task_log(
                task_id,
                f"Creating job with file format: {original_file_format or 'unknown'}"
            )

            # 步骤2: 创建下载和解压Job（解压到PVC根目录）
            job_name = k8s_service.create_upload_extract_job(
                project_id=project_id,
                pvc_name=pvc_name,
                upload_uuid=resource_uuid,
                archive_url=archive_url,
                file_format=original_file_format,  # 传递文件格式
                extract_path="/"  # 默认解压到根目录
            )

            if not job_name:
                raise Exception(f"Failed to create upload job")

            # 记录创建的Job（用于失败时清理）
            created_resources.append({
                "type": "job",
                "name": job_name,
                "namespace": project_namespace
            })

            await task_manager.append_task_log(task_id, f"Upload job created: {job_name}")
            await task_manager.update_task_progress(task_id, 50, "Download job running")

            # 步骤3: 等待Job完成
            success, message = await k8s_service.wait_for_job_completion(
                project_id=project_id,
                job_name=job_name,
                timeout=600  # 10分钟超时
            )

            if not success:
                raise Exception(f"Upload job failed: {message}")

            await task_manager.append_task_log(task_id, "Upload and extract completed successfully")
            await task_manager.update_task_progress(task_id, 90, "Verifying extraction")

            # 步骤4: 更新资源状态
            resource.pvc_name = pvc_name
            resource.pvc_namespace = project_namespace
            resource.upload_status = ResourceUploadStatus.COMPLETED
            resource.upload_message = "Upload and extract completed successfully"

            # 关联资源到所有项目
            if project_ids:
                from app.models.database import Project
                for pid in project_ids:
                    project = db_session.query(Project).filter(
                        Project.id == pid
                    ).first()
                    if project and project not in resource.projects:
                        resource.projects.append(project)

            db_session.commit()

            # 保存创建的K8S资源到任务记录
            task.created_k8s_resources = created_resources.copy()

            await task_manager.update_task_progress(task_id, 100, "Task completed")

            return {
                "task_id": task_id,
                "resource_id": resource.id,
                "resource_uuid": resource_uuid,
                "pvc_name": pvc_name,
                "pvc_namespace": project_namespace,
                "pvc_size": pvc_size,
                "extract_path": "/",
                "status": "completed"
            }

        except Exception as e:
            logger.error(f"Upload task {task_id} failed: {e}")

            # 更新资源状态为失败
            if 'resource' in dir() and resource:
                resource.upload_status = ResourceUploadStatus.FAILED
                resource.upload_message = str(e)
                db_session.commit()

            await task_manager.append_task_log(task_id, f"Error: {str(e)}")

            # 保存已创建的K8S资源（用于清理）
            task.created_k8s_resources = created_resources.copy()

            raise


    @staticmethod
    async def process_delete_resource(
        task_id: str,
        db_session: Session,
        task: AsyncTaskLog,
        resource_id: int,
        resource_uuid: str,
        resource_name: str,
        project_id: str,
        pvc_name: Optional[str],
        pvc_namespace: Optional[str],
        upload_file_uuid: Optional[str]
    ) -> dict:
        """
        处理资源删除任务（异步）。

        Args:
            task_id: 任务ID
            db_session: 数据库会话
            task: 任务记录
            resource_id: 资源ID
            resource_uuid: 资源UUID
            resource_name: 资源名称
            project_id: 项目ID
            pvc_name: PVC名称
            pvc_namespace: PVC命名空间
            upload_file_uuid: 上传文件的UUID（用于删除临时文件）

        Returns:
            dict: 任务结果
        """
        from app.tasks.manager import get_task_manager
        from app.main import get_config
        import os

        task_manager = get_task_manager()
        k8s_service = get_k8s_service()

        deleted_pvc = False
        deleted_file = False
        errors = []

        try:
            await task_manager.append_task_log(
                task_id, f"Starting delete task for resource {resource_name} (ID: {resource_id})"
            )
            await task_manager.update_task_progress(task_id, 10, "Initializing delete task")

            # 步骤1: 删除PVC（如果存在）
            if pvc_name and project_id:
                await task_manager.append_task_log(task_id, f"Deleting PVC: {pvc_name}")
                await task_manager.update_task_progress(task_id, 30, "Deleting PVC")

                try:
                    # 使用超时但不阻塞，在后台继续等待
                    import asyncio
                    pvc_deleted = await asyncio.to_thread(
                        k8s_service.delete_pvc,
                        project_id,
                        pvc_name,
                        timeout=300  # 5分钟超时
                    )

                    if pvc_deleted:
                        deleted_pvc = True
                        await task_manager.append_task_log(
                            task_id, f"PVC {pvc_name} deleted successfully"
                        )
                    else:
                        errors.append(f"PVC {pvc_name} deletion timeout or failed")
                        await task_manager.append_task_log(
                            task_id, f"Warning: PVC {pvc_name} deletion did not complete in time"
                        )

                except Exception as e:
                    errors.append(f"Failed to delete PVC: {str(e)}")
                    await task_manager.append_task_log(task_id, f"Error deleting PVC: {str(e)}")
                    logger.error(f"Error deleting PVC {pvc_name}: {e}")

            await task_manager.update_task_progress(task_id, 60, "PVC deletion processed")

            # 步骤2: 删除上传的临时文件
            if upload_file_uuid:
                await task_manager.append_task_log(
                    task_id, f"Deleting uploaded file: {upload_file_uuid}"
                )
                await task_manager.update_task_progress(task_id, 80, "Deleting temporary file")

                try:
                    config = get_config()
                    upload_dir = config.get("app", {}).get("upload_dir", "/tmp/uploads")
                    file_path = os.path.join(upload_dir, upload_file_uuid)

                    if os.path.exists(file_path):
                        os.remove(file_path)
                        deleted_file = True
                        await task_manager.append_task_log(
                            task_id, f"Temporary file deleted: {upload_file_uuid}"
                        )
                    else:
                        await task_manager.append_task_log(
                            task_id, f"Temporary file not found (may already deleted): {upload_file_uuid}"
                        )

                except Exception as e:
                    errors.append(f"Failed to delete temporary file: {str(e)}")
                    await task_manager.append_task_log(
                        task_id, f"Error deleting temporary file: {str(e)}"
                    )

            # 步骤3: 删除资源记录
            await task_manager.append_task_log(task_id, "Deleting resource record")
            await task_manager.update_task_progress(task_id, 90, "Cleaning up database")

            try:
                # 查找资源记录并删除
                resource = db_session.query(Resource).filter(
                    Resource.id == resource_id
                ).first()

                if resource:
                    db_session.delete(resource)
                    db_session.commit()
                    await task_manager.append_task_log(
                        task_id, f"Resource record {resource_id} deleted"
                    )
                else:
                    await task_manager.append_task_log(
                        task_id, f"Resource record {resource_id} not found (may already deleted)"
                    )

            except Exception as e:
                errors.append(f"Failed to delete resource record: {str(e)}")
                await task_manager.append_task_log(
                    task_id, f"Error deleting resource record: {str(e)}"
                )
                db_session.rollback()

            # 完成
            await task_manager.update_task_progress(task_id, 100, "Delete task completed")

            result = {
                "resource_id": resource_id,
                "resource_uuid": resource_uuid,
                "deleted_pvc": deleted_pvc,
                "deleted_file": deleted_file,
                "errors": errors if errors else None
            }

            if errors:
                await task_manager.append_task_log(
                    task_id, f"Delete task completed with warnings: {errors}"
                )
            else:
                await task_manager.append_task_log(task_id, "Delete task completed successfully")

            return result

        except Exception as e:
            logger.error(f"Delete task {task_id} failed: {e}")
            await task_manager.append_task_log(task_id, f"Fatal error: {str(e)}")
            raise


async def create_upload_extract_task(
    resource_uuid: str,
    project_id: str,
    project_ids: List[str],
    resource_name: str,
    resource_type: str,
    archive_url: str,
    original_file_name: str,
    original_file_size: int,
    original_file_md5: Optional[str] = None,
    original_file_format: Optional[str] = None,
    pvc_size: int = 10
) -> str:
    """
    创建并启动上传解压任务。

    Args:
        resource_uuid: 资源UUID
        project_id: 主项目ID
        project_ids: 所有关联的项目ID列表
        resource_name: 资源名称
        resource_type: 资源类型
        archive_url: 压缩包下载URL
        pvc_size: PVC大小（Gi）
        original_file_name: 原始文件名
        original_file_size: 原始文件大小
        original_file_md5: 原始文件MD5
        original_file_format: 原始文件格式

    Returns:
        str: 任务ID
    """
    from app.models.database import TaskType
    from app.tasks.manager import get_task_manager

    task_manager = get_task_manager()

    # 创建任务记录
    task = await task_manager.create_task(
        task_type=TaskType.UPLOAD_EXTRACT,
        project_id=project_id,
        input_params={
            "resource_uuid": resource_uuid,
            "project_ids": project_ids,
            "resource_name": resource_name,
            "resource_type": resource_type,
            "archive_url": archive_url,
            "pvc_size": pvc_size,
            "extract_path": "/",
            "original_file_name": original_file_name,
            "original_file_size": original_file_size,
            "original_file_md5": original_file_md5,
            "original_file_format": original_file_format
        }
    )

    # 启动任务
    await task_manager.start_task(
        task_id=task.task_id,
        coro=ResourceTaskWorker.process_upload_extract(
            task_id=task.task_id,
            db_session=database.SessionLocal(),
            task=task,
            created_resources=[],
            resource_uuid=resource_uuid,
            project_id=project_id,
            project_ids=project_ids,
            resource_name=resource_name,
            resource_type=resource_type,
            archive_url=archive_url,
            pvc_size=pvc_size,
            original_file_name=original_file_name,
            original_file_size=original_file_size,
            original_file_md5=original_file_md5,
            original_file_format=original_file_format
        )
    )

    return task.task_id


async def create_delete_resource_task(
    resource_id: int,
    resource_uuid: str,
    resource_name: str,
    project_id: str,
    pvc_name: Optional[str] = None,
    pvc_namespace: Optional[str] = None,
    upload_file_uuid: Optional[str] = None
) -> str:
    """
    创建并启动资源删除任务（异步）。

    Args:
        resource_id: 资源ID
        resource_uuid: 资源UUID
        resource_name: 资源名称
        project_id: 项目ID
        pvc_name: PVC名称（可选）
        pvc_namespace: PVC命名空间（可选）
        upload_file_uuid: 上传文件的UUID（可选）

    Returns:
        str: 任务ID
    """
    from app.models.database import TaskType
    from app.tasks.manager import get_task_manager

    task_manager = get_task_manager()

    # 创建任务记录
    task = await task_manager.create_task(
        task_type=TaskType.DELETE,
        project_id=project_id,
        input_params={
            "resource_id": resource_id,
            "resource_uuid": resource_uuid,
            "resource_name": resource_name,
            "pvc_name": pvc_name,
            "pvc_namespace": pvc_namespace,
            "upload_file_uuid": upload_file_uuid
        }
    )

    # 启动任务
    await task_manager.start_task(
        task_id=task.task_id,
        coro=ResourceTaskWorker.process_delete_resource(
            task_id=task.task_id,
            db_session=database.SessionLocal(),
            task=task,
            resource_id=resource_id,
            resource_uuid=resource_uuid,
            resource_name=resource_name,
            project_id=project_id,
            pvc_name=pvc_name,
            pvc_namespace=pvc_namespace,
            upload_file_uuid=upload_file_uuid
        )
    )

    return task.task_id