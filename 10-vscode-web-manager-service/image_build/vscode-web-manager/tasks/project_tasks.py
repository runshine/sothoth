"""
项目相关任务函数
"""
import os
import sys
import time
import shutil
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from config import Config
from database import SessionLocal
from models import Project, ProjectTaskLog, CodeServer, CodeWiki
from utils.file_utils import FileUtils
from utils.task_logger import TaskLogger
from utils.errors import ProjectError, CodeServerError
from managers.kubernetes_manager import KubernetesManager
from tasks.code_server_tasks import delete_code_server_task
from tasks.codewiki_tasks import delete_codewiki_task

logger = logging.getLogger(__name__)

def initialize_project_task(project_id: str, archive_path: str, storage_size: str = "5Gi", create_pvc: bool = True):
    """项目初始化任务：解压、扫描文件、创建PVC、拷贝文件"""
    logger.info(f"开始初始化项目: project_id={project_id}")

    # 创建日志文件
    log_file_path = os.path.join(Config.TASK_LOG_DIR, f"{project_id}/project_init_{int(time.time())}.log")
    task_logger = TaskLogger(log_file_path)

    db = SessionLocal()
    project_task_log = None

    try:
        # 记录任务开始
        task_logger.info(f"开始项目初始化任务: {project_id}")
        task_logger.info(f"存档文件: {archive_path}")
        task_logger.info(f"存储大小: {storage_size}")
        task_logger.info(f"创建PVC: {create_pvc}")

        # 创建任务日志记录
        project_task_log = ProjectTaskLog(
            project_id=project_id,
            task_type="init",
            task_id=f"init_{project_id}_{int(time.time())}",
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

        # 更新项目状态
        project.status = Config.PROJECT_STATUS_INITIALIZING
        project.init_log_path = log_file_path
        project.init_error = None
        db.commit()

        # 步骤1: 解压文件到本地目录（用于文件扫描）
        task_logger.info("步骤1: 解压文件到本地目录（用于文件扫描）")
        extract_dir = os.path.join(Config.EXTRACT_DIR, project_id)

        try:
            os.makedirs(extract_dir, exist_ok=True)
            task_logger.info(f"创建本地解压目录: {extract_dir}")
        except Exception as e:
            error_msg = f"创建本地解压目录失败: {str(e)}"
            task_logger.error(error_msg)
            raise ProjectError(
                message="创建本地解压目录失败",
                details={"project_id": project_id, "error": str(e)},
                status_code=500
            )

        # 检查存档文件是否存在
        if not os.path.exists(archive_path):
            error_msg = f"存档文件不存在: {archive_path}"
            task_logger.error(error_msg)
            raise ProjectError(
                message="存档文件不存在",
                details={"project_id": project_id, "archive_path": archive_path},
                status_code=404
            )

        # 解压文件到本地目录
        task_logger.info(f"开始解压文件到本地目录: {archive_path} -> {extract_dir}")
        if not FileUtils.extract_archive(archive_path, extract_dir):
            error_msg = "解压文件失败"
            task_logger.error(error_msg)
            raise ProjectError(
                message="解压文件失败",
                details={"project_id": project_id, "archive_path": archive_path},
                status_code=500
            )

        project.extract_path = extract_dir
        task_logger.info("文件解压到本地目录成功")

        # 跳过步骤2: 不扫描文件，不创建数据库记录
        task_logger.info("步骤2: 跳过文件扫描（不创建数据库记录）")

        # 步骤3: 创建PVC并拷贝文件
        if create_pvc:
            task_logger.info("步骤3: 创建PVC并拷贝压缩包")

            # 检查K8S是否可用
            try:
                from kubernetes import client
                k8s_available = True
            except ImportError:
                k8s_available = False

            if not k8s_available:
                error_msg = "Kubernetes功能不可用"
                task_logger.error(error_msg)
                raise ProjectError(
                    message="Kubernetes功能不可用",
                    details={"project_id": project_id},
                    status_code=503
                )

            # 初始化K8S管理器
            try:
                k8s = KubernetesManager(validate_connection=False)
                if not k8s.available:
                    error_msg = "Kubernetes客户端初始化失败"
                    task_logger.error(error_msg)
                    raise ProjectError(
                        message="Kubernetes客户端不可用",
                        details={"project_id": project_id},
                        status_code=503
                    )
            except Exception as e:
                error_msg = f"Kubernetes客户端初始化失败: {str(e)}"
                task_logger.error(error_msg)
                raise ProjectError(
                    message="Kubernetes客户端初始化失败",
                    details={"project_id": project_id, "error": str(e)},
                    status_code=500
                )

            # 更新项目状态
            project.pvc_status = "creating"
            db.commit()

            # 创建PVC
            task_logger.info(f"开始创建PVC，存储大小: {storage_size}")
            try:
                pvc_name = k8s.create_pvc(project_id, storage_size)
                project.pvc_name = pvc_name
                project.pvc_size = storage_size
                db.commit()
                task_logger.info(f"PVC创建成功: {pvc_name}")
            except CodeServerError as e:
                error_msg = f"创建PVC失败: {e.message}"
                task_logger.error(error_msg)
                project.pvc_status = "error"
                db.commit()
                raise ProjectError(
                    message="创建PVC失败",
                    details={
                        "project_id": project_id,
                        "error": e.message,
                        "details": e.details
                    },
                    status_code=e.status_code
                )

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

            # 复制压缩包到PVC并解压
            task_logger.info(f"复制压缩包到PVC并解压: {pvc_name}")
            try:
                # 使用新的方法：复制压缩包到PVC并在PVC中解压
                k8s.copy_archive_to_pvc(project_id, archive_path, pvc_name)
                project.file_synced = True
                db.commit()
                task_logger.info("压缩包复制并解压到PVC成功")
            except CodeServerError as e:
                error_msg = f"复制并解压文件到PVC失败: {e.message}"
                task_logger.error(error_msg)
                project.pvc_status = "error"
                db.commit()
                raise ProjectError(
                    message="复制并解压文件到PVC失败",
                    details={
                        "project_id": project_id,
                        "error": e.message,
                        "details": e.details
                    },
                    status_code=e.status_code
                )
        else:
            task_logger.info("跳过PVC创建，用户选择不创建PVC")

        # 更新项目状态为就绪
        project.status = Config.PROJECT_STATUS_READY
        project.initialized_at = datetime.now(timezone.utc)
        db.commit()

        # 更新任务日志
        if project_task_log:
            project_task_log.status = "completed"
            project_task_log.completed_at = datetime.now(timezone.utc)
            db.commit()

        result = {
            "success": True,
            "project_id": project_id,
            "status": Config.PROJECT_STATUS_READY,
            "file_count": project.file_count,
            "total_size": project.total_size,
            "pvc_name": project.pvc_name if create_pvc else None,
            "pvc_status": project.pvc_status if create_pvc else None,
            "file_synced": project.file_synced if create_pvc else None,
            "initialized_at": project.initialized_at.isoformat() if project.initialized_at else None,
            "message": "项目初始化成功"
        }

        task_logger.info(f"项目初始化成功: {result}")
        return result

    except ProjectError:
        # 记录错误状态
        try:
            if 'project' in locals():
                project.status = Config.PROJECT_STATUS_ERROR
                project.init_error = str(sys.exc_info()[1])
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
        # 记录未预期的错误
        error_msg = f"项目初始化过程中发生未预期的错误: {str(e)}"
        task_logger.error(error_msg)

        try:
            if 'project' in locals():
                project.status = Config.PROJECT_STATUS_ERROR
                project.init_error = str(e)
                db.commit()

            if project_task_log:
                project_task_log.status = "failed"
                project_task_log.error_message = str(e)
                project_task_log.completed_at = datetime.now(timezone.utc)
                db.commit()
        except:
            pass

        raise ProjectError(
            message="项目初始化失败",
            details={
                "project_id": project_id,
                "error": str(e),
                "error_type": type(e).__name__
            },
            status_code=500
        )

    finally:
        db.close()
        task_logger.info("项目初始化任务结束")

def delete_project_task(project_id: str, user_id: int):
    """删除项目任务：删除所有K8S资源和本地文件"""
    logger.info(f"开始删除项目: project_id={project_id}")

    # 创建日志文件
    log_file_path = os.path.join(Config.TASK_LOG_DIR, f"{project_id}/project_delete_{int(time.time())}.log")
    task_logger = TaskLogger(log_file_path)

    db = SessionLocal()
    project_task_log = None

    try:
        # 记录任务开始
        task_logger.info(f"开始项目删除任务: {project_id}")
        task_logger.info(f"用户ID: {user_id}")

        # 创建任务日志记录
        project_task_log = ProjectTaskLog(
            project_id=project_id,
            task_type="delete",
            task_id=f"delete_{project_id}_{int(time.time())}",
            status="running",
            log_path=log_file_path
        )
        db.add(project_task_log)
        db.commit()

        # 获取项目
        project = db.query(Project).filter(
            Project.id == project_id,
            Project.user_id == user_id
        ).first()

        if not project:
            error_msg = f"项目不存在或无权访问: {project_id}"
            task_logger.error(error_msg)
            raise ProjectError(
                message="项目不存在或无权访问",
                details={"project_id": project_id, "user_id": user_id},
                status_code=404
            )

        # 更新项目状态
        project.status = Config.PROJECT_STATUS_DELETING
        db.commit()

        # 步骤1: 删除Code-Server（如果存在）
        task_logger.info("步骤1: 检查并删除Code-Server")
        code_server = db.query(CodeServer).filter(CodeServer.project_id == project_id).first()

        if code_server:
            task_logger.info(f"发现Code-Server，状态: {code_server.status}")

            # 检查K8S是否可用
            try:
                from kubernetes import client
                k8s_available = True
            except ImportError:
                k8s_available = False

            if k8s_available:
                try:
                    # 使用专门的Code-Server删除任务
                    delete_code_server_task(project_id)
                    task_logger.info("Code-Server删除成功")
                except Exception as e:
                    task_logger.warning(f"删除Code-Server失败: {str(e)}")
            else:
                task_logger.warning("Kubernetes功能不可用，跳过Code-Server资源删除")

            # 删除数据库记录
            db.delete(code_server)
            db.commit()
            task_logger.info("Code-Server数据库记录删除成功")
        else:
            task_logger.info("未发现Code-Server")

        # 步骤1.5: 删除CodeWiki（如果存在）- 项目删除时强制删除
        task_logger.info("步骤1.5: 检查并删除CodeWiki")
        code_wiki = db.query(CodeWiki).filter(CodeWiki.project_id == project_id).first()

        if code_wiki:
            task_logger.info(f"发现CodeWiki，状态: {code_wiki.status}")

            # 检查K8S是否可用
            try:
                from kubernetes import client
                k8s_available = True
            except ImportError:
                k8s_available = False

            if k8s_available:
                try:
                    # 使用专门的CodeWiki删除任务
                    delete_codewiki_task(project_id)
                    task_logger.info("CodeWiki删除成功")
                except Exception as e:
                    task_logger.warning(f"删除CodeWiki失败: {str(e)}")
            else:
                task_logger.warning("Kubernetes功能不可用，跳过CodeWiki资源删除")

            # 删除数据库记录
            db.delete(code_wiki)
            db.commit()
            task_logger.info("CodeWiki数据库记录删除成功")
        else:
            task_logger.info("未发现CodeWiki")

        # 步骤2: 删除PVC（如果存在）
        task_logger.info("步骤2: 检查并删除PVC")
        if project.pvc_name:
            task_logger.info(f"发现PVC: {project.pvc_name}")

            try:
                from kubernetes import client
                k8s_available = True
            except ImportError:
                k8s_available = False

            if k8s_available:
                try:
                    k8s = KubernetesManager(validate_connection=False)
                    if k8s.available:
                        # 删除PVC
                        task_logger.info(f"删除PVC: {project.pvc_name}")
                        try:
                            k8s.delete_pvc(project_id)
                            task_logger.info("PVC删除成功")
                        except CodeServerError as e:
                            task_logger.warning(f"删除PVC失败: {e.message}")
                        except Exception as e:
                            task_logger.warning(f"删除PVC失败: {str(e)}")
                    else:
                        task_logger.warning("Kubernetes客户端不可用，跳过PVC删除")
                except Exception as e:
                    task_logger.warning(f"Kubernetes客户端初始化失败，跳过PVC删除: {str(e)}")
            else:
                task_logger.warning("Kubernetes功能不可用，跳过PVC删除")
        else:
            task_logger.info("未发现PVC")

        # 步骤3: 删除本地文件
        task_logger.info("步骤3: 删除本地文件")

        # 删除存档文件
        if project.archive_path and os.path.exists(project.archive_path):
            try:
                os.remove(project.archive_path)
                task_logger.info(f"删除存档文件: {project.archive_path}")
            except Exception as e:
                task_logger.warning(f"删除存档文件失败: {str(e)}")

        # 删除解压目录
        if project.extract_path and os.path.exists(project.extract_path):
            try:
                shutil.rmtree(project.extract_path)
                task_logger.info(f"删除解压目录: {project.extract_path}")
            except Exception as e:
                task_logger.warning(f"删除解压目录失败: {str(e)}")

        # 清理用户的临时下载文件
        user_download_dir = os.path.join(Config.DOWNLOAD_DIR, str(user_id))
        if os.path.exists(user_download_dir):
            try:
                # 删除与该项目相关的临时文件
                for filename in os.listdir(user_download_dir):
                    filepath = os.path.join(user_download_dir, filename)
                    try:
                        # 检查文件是否属于该项目（通过文件名包含项目ID判断）
                        if project_id in filename or os.path.getmtime(filepath) < time.time() - 86400:  # 24小时前
                            os.remove(filepath)
                            task_logger.info(f"删除临时文件: {filename}")
                    except:
                        pass
            except Exception as e:
                task_logger.warning(f"清理临时下载文件失败: {str(e)}")

        # 步骤4: 删除项目任务日志记录
        task_logger.info("步骤5: 删除项目任务日志记录")
        try:
            db.query(ProjectTaskLog).filter(ProjectTaskLog.project_id == project_id).delete()
            task_logger.info("项目任务日志记录删除成功")
        except Exception as e:
            task_logger.warning(f"删除项目任务日志记录失败: {str(e)}")


        # 步骤6: 删除项目记录
        task_logger.info("步骤6: 删除项目记录")
        db.delete(project)
        db.commit()
        task_logger.info("项目记录删除成功")

        result = {
            "success": True,
            "project_id": project_id,
            "message": "项目删除成功",
            "deleted_resources": {
                "code_server": code_server is not None,
                "code_wiki": code_wiki is not None,
                "pvc": project.pvc_name is not None,
                "archive_file": project.archive_path is not None,
                "extract_dir": project.extract_path is not None
            }
        }

        task_logger.info(f"项目删除成功: {result}")
        return result

    except ProjectError:
        # 记录错误状态
        try:
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
        # 记录未预期的错误
        error_msg = f"项目删除过程中发生未预期的错误: {str(e)}"
        task_logger.error(error_msg)

        try:
            if project_task_log:
                project_task_log.status = "failed"
                project_task_log.error_message = str(e)
                project_task_log.completed_at = datetime.now(timezone.utc)
                db.commit()
        except:
            pass

        raise ProjectError(
            message="项目删除失败",
            details={
                "project_id": project_id,
                "error": str(e),
                "error_type": type(e).__name__
            },
            status_code=500
        )

    finally:
        db.close()
        task_logger.info("项目删除任务结束")