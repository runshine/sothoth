# app/main.py
import os
import uuid
import asyncio
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Query
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRoute
from loguru import logger

from app import models, schemas, tasks, database, config, logs
from app.database import get_db, AsyncSession

# 配置日志
logger.add("logs/app_{time}.log", rotation="1 day", retention="7 days")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    # 启动时
    logger.info("Starting CodeWiki API Server...")

    # 初始化数据库
    await database.init_db()

    # 启动任务管理器
    await tasks.TaskManager.init()

    yield

    # 关闭时
    logger.info("Shutting down CodeWiki API Server...")
    await tasks.TaskManager.shutdown()


# 创建FastAPI应用
app = FastAPI(
    title="CodeWiki API Server",
    description="Web API server for CodeWiki documentation generation",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# API路由前缀配置
def use_route_names_as_operation_ids(app: FastAPI) -> None:
    """简化操作ID生成"""
    for route in app.routes:
        if isinstance(route, APIRoute):
            route.operation_id = route.name


# 创建带有前缀的路由器
from fastapi import APIRouter

# 创建主路由器
codewiki_router = APIRouter(tags=["codewiki"])

# API路由
@codewiki_router.get("/")
async def codewiki_root():
    """CodeWiki API 根路径"""
    return {
        "status": "running",
        "service": "CodeWiki API",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat(),
        "docs": "/codewiki/docs",
        "openapi": "/codewiki/openapi.json"
    }


@codewiki_router.get("/health")
async def health():
    """健康检查"""
    return {"status": "healthy"}


@codewiki_router.post("/tasks", response_model=schemas.TaskResponse)
async def create_task(
        task_request: schemas.TaskCreate,
        background_tasks: BackgroundTasks,
        db: AsyncSession = Depends(get_db)
):
    """创建新的文档生成任务"""
    try:
        # 生成任务ID
        task_id = str(uuid.uuid4())

        # 创建任务记录
        task = models.Task(
            id=task_id,
            status="pending",
            include_patterns=task_request.include,
            exclude_patterns=task_request.exclude,
            folder=task_request.folder or ".",
            config_overrides=task_request.config_overrides
        )

        # 保存到数据库
        db.add(task)
        await db.commit()
        await db.refresh(task)

        # 在后台启动任务
        background_tasks.add_task(
            tasks.execute_codewiki_task,
            task_id=task_id,
            include_patterns=task_request.include,
            exclude_patterns=task_request.exclude,
            folder=task_request.folder,
            config_overrides=task_request.config_overrides
        )

        logger.info(f"Task {task_id} created successfully")

        return schemas.TaskResponse(
            task_id=task_id,
            status="pending",
            message="Task created and queued for execution"
        )

    except Exception as e:
        logger.error(f"Failed to create task: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@codewiki_router.get("/tasks", response_model=List[schemas.Task])
async def list_tasks(
        skip: int = 0,
        limit: int = 100,
        db: AsyncSession = Depends(get_db)
):
    """获取任务列表"""
    try:
        tasks_list = await models.Task.get_all(db, skip=skip, limit=limit)
        return tasks_list
    except Exception as e:
        logger.error(f"Failed to list tasks: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@codewiki_router.get("/tasks/{task_id}", response_model=schemas.Task)
async def get_task(
        task_id: str,
        db: AsyncSession = Depends(get_db)
):
    """获取任务详情"""
    try:
        task = await models.Task.get(db, task_id)
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")
        return task
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get task {task_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@codewiki_router.delete("/tasks/{task_id}")
async def delete_task(
        task_id: str,
        db: AsyncSession = Depends(get_db)
):
    """删除任务"""
    try:
        # 先尝试停止任务
        await tasks.TaskManager.stop_task(task_id)

        # 从数据库删除
        success = await models.Task.delete(db, task_id)
        if not success:
            raise HTTPException(status_code=404, detail="Task not found")

        # 删除日志文件
        log_file = f"logs/{task_id}.log"
        if os.path.exists(log_file):
            os.remove(log_file)

        logger.info(f"Task {task_id} deleted successfully")

        return {"message": f"Task {task_id} deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete task {task_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@codewiki_router.post("/tasks/{task_id}/stop")
async def stop_task(
        task_id: str,
        db: AsyncSession = Depends(get_db)
):
    """停止运行中的任务"""
    try:
        success = await tasks.TaskManager.stop_task(task_id)
        if not success:
            raise HTTPException(status_code=404, detail="Task not found or not running")

        # 更新任务状态
        task = await models.Task.get(db, task_id)
        if task:
            task.status = "stopped"
            task.updated_at = datetime.utcnow()
            await db.commit()

        logger.info(f"Task {task_id} stopped successfully")

        return {"message": f"Task {task_id} stopped successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to stop task {task_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@codewiki_router.get("/tasks/{task_id}/logs")
async def get_task_logs(
        task_id: str,
        lines: int = 1000
):
    """获取任务日志"""
    try:
        log_file = f"logs/{task_id}.log"
        if not os.path.exists(log_file):
            raise HTTPException(status_code=404, detail="Log file not found")

        # 读取最后N行日志
        with open(log_file, 'r', encoding='utf-8') as f:
            all_lines = f.readlines()
            log_lines = all_lines[-lines:] if len(all_lines) > lines else all_lines

        return {
            "task_id": task_id,
            "total_lines": len(all_lines),
            "lines": len(log_lines),
            "logs": "".join(log_lines)
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get logs for task {task_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@codewiki_router.get("/config", response_model=schemas.ConfigResponse)
async def get_config():
    """获取当前配置"""
    try:
        current_config = await config.get_current_config()
        return schemas.ConfigResponse(
            config=current_config,
            message="Current configuration retrieved successfully"
        )
    except Exception as e:
        logger.error(f"Failed to get config: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@codewiki_router.post("/config", response_model=schemas.ConfigResponse)
async def update_config(
        config_update: schemas.ConfigUpdate,
        db: AsyncSession = Depends(get_db)
):
    """更新配置"""
    try:
        updated_config = await config.update_config(
            db,
            config_update.config
        )

        return schemas.ConfigResponse(
            config=updated_config,
            message="Configuration updated successfully"
        )

    except Exception as e:
        logger.error(f"Failed to update config: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@codewiki_router.get("/config/validate")
async def validate_config():
    """验证配置"""
    try:
        current_config = await config.get_current_config()

        # 这里可以添加配置验证逻辑
        # 例如检查API密钥是否有效

        return {
            "valid": True,
            "config": current_config,
            "message": "Configuration is valid"
        }

    except Exception as e:
        logger.error(f"Failed to validate config: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# 额外添加的路由，用于直接访问workspace中的文档
@codewiki_router.get("/workspace/{path:path}")
async def serve_workspace_file(path: str):
    """提供workspace中的文件访问"""
    workspace_dir = "/config/workspace"
    file_path = os.path.join(workspace_dir, path)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    if os.path.isdir(file_path):
        # 如果是目录，列出文件
        files = []
        for item in os.listdir(file_path):
            item_path = os.path.join(file_path, item)
            files.append({
                "name": item,
                "type": "directory" if os.path.isdir(item_path) else "file",
                "size": os.path.getsize(item_path) if os.path.isfile(item_path) else 0
            })

        return {
            "path": path,
            "type": "directory",
            "files": files
        }
    else:
        # 如果是文件，返回文件内容或下载
        # 根据文件类型决定返回方式
        if file_path.endswith(('.md', '.txt', '.json', '.html', '.css', '.js')):
            # 文本文件直接返回内容
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return {
                "path": path,
                "type": "file",
                "content": content
            }
        else:
            # 二进制文件返回下载
            return FileResponse(
                file_path,
                media_type="application/octet-stream",
                filename=os.path.basename(file_path)
            )


# 列出生成的文档
@codewiki_router.get("/docs")
async def list_generated_docs():
    """列出生成的文档"""
    workspace_dir = "/config/workspace"
    docs_dir = os.path.join(workspace_dir, "docs")

    if not os.path.exists(docs_dir):
        return {"message": "No documentation generated yet", "docs": []}

    docs = []
    for root, dirs, files in os.walk(docs_dir):
        for file in files:
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, workspace_dir)
            docs.append({
                "path": rel_path,
                "name": file,
                "size": os.path.getsize(file_path),
                "modified": os.path.getmtime(file_path)
            })

    return {
        "docs_dir": docs_dir,
        "count": len(docs),
        "docs": sorted(docs, key=lambda x: x["modified"], reverse=True)
    }


# ==================== 日志管理API ====================

@codewiki_router.get("/server/logs", response_model=schemas.ServerLogsResponse)
async def get_server_logs(
        lines: int = Query(1000, ge=1, le=10000, description="返回的行数"),
        search: Optional[str] = Query(None, description="搜索关键词"),
        level: Optional[str] = Query(None, description="日志级别过滤: ERROR, WARNING, INFO, DEBUG"),
        time_range: Optional[str] = Query(None, description="时间范围，如: 1d, 7d, 30d")
):
    """获取服务器运行日志"""
    try:
        logs_data = logs.log_manager.get_server_logs(
            lines=lines,
            search=search,
            level=level,
            time_range=time_range
        )
        return logs_data
    except Exception as e:
        logger.error(f"Failed to get server logs: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@codewiki_router.get("/server/logs/files", response_model=schemas.LogFilesResponse)
async def list_log_files():
    """列出所有日志文件"""
    try:
        log_files = logs.log_manager.get_log_files()
        return {
            "logs_dir": logs.log_manager.logs_dir,
            "total_files": len(log_files),
            "files": log_files
        }
    except Exception as e:
        logger.error(f"Failed to list log files: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@codewiki_router.get("/server/logs/file/{log_file}", response_model=schemas.LogContent)
async def get_log_file(
        log_file: str,
        lines: int = Query(1000, ge=1, le=10000, description="返回的行数"),
        search: Optional[str] = Query(None, description="搜索关键词"),
        level: Optional[str] = Query(None, description="日志级别过滤")
):
    """获取指定日志文件内容"""
    try:
        log_content = logs.log_manager.get_log_content(
            log_file=log_file,
            lines=lines,
            search=search,
            level=level
        )
        return log_content
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Log file not found: {log_file}")
    except Exception as e:
        logger.error(f"Failed to get log file {log_file}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@codewiki_router.get("/server/logs/stats", response_model=schemas.LogStats)
async def get_log_stats():
    """获取日志统计信息"""
    try:
        stats = logs.log_manager.get_log_stats()
        return stats
    except Exception as e:
        logger.error(f"Failed to get log stats: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@codewiki_router.delete("/server/logs/cleanup")
async def cleanup_old_logs(
        days: int = Query(30, ge=1, le=365, description="保留最近多少天的日志")
):
    """清理旧的日志文件"""
    try:
        result = logs.log_manager.delete_old_logs(days=days)
        return result
    except Exception as e:
        logger.error(f"Failed to cleanup old logs: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@codewiki_router.get("/server/logs/download/{log_file}")
async def download_log_file(log_file: str):
    """下载日志文件"""
    try:
        log_path = Path(logs.log_manager.logs_dir) / log_file

        if not log_path.exists():
            raise HTTPException(status_code=404, detail=f"Log file not found: {log_file}")

        return FileResponse(
            path=log_path,
            filename=log_file,
            media_type="text/plain"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to download log file {log_file}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@codewiki_router.get("/server/logs/search")
async def search_logs(
        query: str = Query(..., description="搜索关键词"),
        lines: int = Query(100, ge=1, le=1000, description="每个文件返回的行数"),
        file_pattern: Optional[str] = Query("*.log", description="文件模式匹配")
):
    """在所有日志文件中搜索"""
    try:
        results = []
        search_dir = Path(logs.log_manager.logs_dir)

        # 获取所有匹配的日志文件
        log_files = list(search_dir.glob(file_pattern))

        for log_file in log_files:
            try:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    file_lines = f.readlines()
                    matches = []

                    # 搜索匹配的行
                    for i, line in enumerate(file_lines):
                        if query.lower() in line.lower():
                            matches.append({
                                "line": i + 1,
                                "content": line.rstrip('\n'),
                                "level": logs.log_manager._extract_log_level(line)
                            })

                    # 只保留最近的匹配行
                    if matches:
                        recent_matches = matches[-lines:]
                        results.append({
                            "file": log_file.name,
                            "total_matches": len(matches),
                            "matches": recent_matches
                        })
            except Exception as e:
                logger.warning(f"Error searching file {log_file}: {e}")

        return {
            "query": query,
            "total_files_searched": len(log_files),
            "files_with_matches": len(results),
            "results": results
        }
    except Exception as e:
        logger.error(f"Failed to search logs: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# 将路由器挂载到应用，设置前缀为 /codewiki
app.include_router(codewiki_router, prefix="/codewiki")

# 根路径路由
@app.get("/")
async def root():
    """根路径"""
    return {
        "message": "Welcome to CodeWiki API Server",
        "version": "1.0.0",
        "codewiki_api": "/codewiki",
        "docs": "/docs",
        "openapi": "/openapi.json"
    }

@app.get("/health")
async def app_health():
    """应用级健康检查"""
    return {"status": "healthy", "service": "codewiki-api"}

@app.get("/docs", include_in_schema=False)
async def swagger_ui_redirect():
    """重定向到正确的Swagger UI"""
    return RedirectResponse(url="/codewiki/docs")

# 全局异常处理器 - 注册在FastAPI应用上
@app.exception_handler(Exception)
async def global_exception_handler(request, exc: Exception):
    """全局异常处理器"""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )

# 设置操作ID
use_route_names_as_operation_ids(app)