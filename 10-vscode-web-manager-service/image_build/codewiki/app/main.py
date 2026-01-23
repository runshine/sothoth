# app/main.py
import os
import uuid
import asyncio
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

# ... 现有的API路由保持不变 ...

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

# ... 其他路由保持不变 ...

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