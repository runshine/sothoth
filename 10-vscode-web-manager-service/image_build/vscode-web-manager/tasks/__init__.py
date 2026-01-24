"""
任务模块
"""
from tasks.project_tasks import initialize_project_task, delete_project_task
from tasks.pvc_tasks import create_project_pvc_task, recreate_project_pvc_task
from tasks.code_server_tasks import (
    create_code_server_task,
    start_code_server_task,
    stop_code_server_task,
    delete_code_server_task,
    restart_code_server_task,
    update_code_server_task
)

__all__ = [
    "initialize_project_task",
    "delete_project_task",
    "create_project_pvc_task",
    "recreate_project_pvc_task",
    "create_code_server_task",
    "start_code_server_task",
    "stop_code_server_task",
    "delete_code_server_task",
    "restart_code_server_task",
    "update_code_server_task"
]