"""
任务管理API路由
"""
from fastapi import APIRouter, Depends, HTTPException
from api.dependencies import TaskManagerDep, CurrentUserDep

router = APIRouter()

@router.get("/tasks/{task_id}")
async def get_task_status(task_id: str, task_manager = TaskManagerDep):
    """获取任务状态"""
    status_info = task_manager.get_status(task_id)

    # 如果任务失败，返回详细的错误信息
    if status_info["status"] == "failed":
        error_info = status_info.get("error", {})
        raise HTTPException(
            status_code=error_info.get("status_code", 500),
            detail={
                "message": error_info.get("message", "任务执行失败"),
                "details": error_info.get("details", {}),
                "task_id": task_id
            }
        )

    return {"task_id": task_id, **status_info}