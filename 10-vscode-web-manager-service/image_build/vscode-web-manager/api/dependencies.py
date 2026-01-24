"""
API依赖项
"""
from fastapi import Depends, HTTPException
from typing import Optional

from startup import get_k8s_manager, get_task_manager
from database import get_db
from utils.auth_utils import get_current_user

def get_k8s_manager_dep():
    """获取Kubernetes管理器依赖"""
    k8s_manager = get_k8s_manager()
    if not k8s_manager:
        return None
    return k8s_manager

def get_task_manager_dep():
    """获取任务管理器依赖"""
    task_manager = get_task_manager()
    if not task_manager:
        raise HTTPException(
            status_code=503,
            detail="任务管理器不可用"
        )
    return task_manager

# 创建依赖项
K8SManagerDep = Depends(get_k8s_manager_dep)
TaskManagerDep = Depends(get_task_manager_dep)
CurrentUserDep = Depends(get_current_user)
DBSessionDep = Depends(get_db)