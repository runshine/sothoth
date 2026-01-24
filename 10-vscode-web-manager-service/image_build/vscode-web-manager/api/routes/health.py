"""
健康检查API路由
"""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text, func

from config import Config
from database import get_db
from models import User, Project, CodeServer
from api.dependencies import K8SManagerDep, TaskManagerDep

router = APIRouter()

# @router.get("/health")
# async def health_check():
#     """基础健康检查"""
#     return {
#         "status": "healthy",
#         "service": Config.APP_NAME,
#         "version": Config.VERSION,
#         "timestamp": datetime.now(timezone.utc).isoformat()
#     }

@router.get("/health")
async def detailed_health_check(
    db: Session = Depends(get_db),
    k8s_manager = K8SManagerDep,
    task_manager = TaskManagerDep
):
    """详细健康检查"""
    checks = {}

    # 数据库检查
    try:
        db.execute(text("SELECT 1"))
        checks["database"] = "healthy"
    except Exception as e:
        checks["database"] = f"unhealthy: {str(e)}"

    # 存储检查
    import os
    for name, path in [
        ("uploads", Config.UPLOAD_DIR),
        ("archives", Config.ARCHIVE_DIR),
        ("projects", Config.EXTRACT_DIR),
        ("downloads", Config.DOWNLOAD_DIR),
        ("task_logs", Config.TASK_LOG_DIR)
    ]:
        try:
            if os.path.exists(path):
                checks[f"storage_{name}"] = "healthy"
            else:
                checks[f"storage_{name}"] = f"unhealthy: 目录不存在"
        except Exception as e:
            checks[f"storage_{name}"] = f"unhealthy: {str(e)}"

    # Kubernetes检查
    if k8s_manager and k8s_manager.available:
        try:
            k8s_manager.core_v1.list_namespaced_pod(
                namespace=k8s_manager.namespace, limit=1
            )
            checks["kubernetes"] = "healthy"
            checks["k8s_api_url"] = k8s_manager.api_url or "default"
            checks["k8s_namespace"] = k8s_manager.namespace
            checks["k8s_auth"] = "配置成功"
        except Exception as e:
            checks["kubernetes"] = f"unhealthy: {str(e)}"
    else:
        checks["kubernetes"] = "unhealthy: Kubernetes管理器不可用"

    # JWT库检查
    if Config.JWT_AVAILABLE:
        checks["jwt_library"] = "healthy"
    else:
        checks["jwt_library"] = "unhealthy: JWT库不可用"

    # 任务管理器检查
    if task_manager:
        try:
            if task_manager.is_healthy():
                checks["task_manager"] = "healthy"
            else:
                checks["task_manager"] = "unhealthy: 任务管理器线程池异常"
        except Exception as e:
            checks["task_manager"] = f"unhealthy: 检查失败: {str(e)}"
    else:
        checks["task_manager"] = "unhealthy: 任务管理器未初始化"

    # 统计信息
    try:
        user_count = db.query(User).count()
        project_count = db.query(Project).count()
        codeserver_count = db.query(CodeServer).count()

        # 项目状态统计
        project_status_stats = {}
        statuses = db.query(Project.status, func.count(Project.id)).group_by(Project.status).all()
        for status, count in statuses:
            project_status_stats[status] = count

        # 检查是否有错误状态的项目
        has_error_projects = project_status_stats.get(Config.PROJECT_STATUS_ERROR, 0) > 0
        stats_status = "healthy" if not has_error_projects else "unhealthy: 存在错误状态的项目"

        checks["stats"] = {
            "status": stats_status,
            "details": {
                "users": user_count,
                "projects": project_count,
                "code_servers": codeserver_count,
                "project_status": project_status_stats
            }
        }
    except Exception as e:
        checks["stats"] = f"unhealthy: 统计信息获取失败: {str(e)}"

    # 确定总体状态：如果所有检查都是healthy，则总体为healthy
    all_healthy = True
    error_messages = []

    for check_name, check_result in checks.items():
        if check_name.startswith("storage_") or check_name == "stats":
            # 存储和统计检查的特殊处理
            if isinstance(check_result, dict):
                if check_result.get("status", "").startswith("unhealthy"):
                    all_healthy = False
                    error_messages.append(f"{check_name}: {check_result['status']}")
            elif isinstance(check_result, str) and check_result.startswith("unhealthy"):
                all_healthy = False
                error_messages.append(f"{check_name}: {check_result}")
        elif isinstance(check_result, str) and check_result.startswith("unhealthy"):
            all_healthy = False
            error_messages.append(f"{check_name}: {check_result}")

    overall_status = "healthy" if all_healthy else "unhealthy"

    result = {
        "status": overall_status,
        "service": Config.APP_NAME,
        "version": Config.VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks
    }

    if not all_healthy:
        result["errors"] = error_messages
        result["message"] = f"发现 {len(error_messages)} 个问题"

    return result