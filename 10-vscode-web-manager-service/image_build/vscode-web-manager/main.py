#!/usr/bin/env python3
"""
app.py - 源码管理系统单文件版本
优化错误处理：将Code-Server相关API的错误信息返回给客户端
重构为模块化结构
"""

import os
import sys
import logging
import asyncio
import uvicorn
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from datetime import datetime, timezone

from config import Config
from startup import init_system
from api.router import api_router, register_error_handlers

# ============ 日志配置 ============
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============ FastAPI应用 ============
app = FastAPI(
    title=Config.APP_NAME,
    version=Config.VERSION,
    docs_url="/docs" if Config.DEBUG else None,
    redoc_url="/redoc" if Config.DEBUG else None
)

# 添加中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 导入并注册错误处理器
register_error_handlers(app)

# 注册API路由
app.include_router(api_router, prefix=Config.API_PREFIX)


# ============ 额外的错误处理器 ============
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """处理HTTP异常"""
    logger.error(f"HTTP异常: {exc.detail}, 状态码: {exc.status_code}")

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "message": exc.detail,
                "status_code": exc.status_code,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """处理通用异常"""
    logger.error(f"未处理的异常: {exc}", exc_info=True)

    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "message": "内部服务器错误",
                "details": {
                    "error_type": type(exc).__name__,
                    "error": str(exc)
                } if Config.DEBUG else None,
                "status_code": 500,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        }
    )


@app.get("/")
async def root():
    """根路径"""
    return {
        "message": f"欢迎使用 {Config.APP_NAME}",
        "version": Config.VERSION,
        "api_prefix": Config.API_PREFIX,
        "docs": "/docs" if Config.DEBUG else None,
        "project_status_definitions": {
            "pending": "等待中",
            "initializing": "初始化中",
            "ready": "就绪",
            "error": "错误",
            "deleting": "删除中"
        }
    }


# ============ 启动应用 ============
def main():
    """主启动函数"""
    init_system()

    print("\n=== 启动服务 ===")
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8080,
        reload=Config.DEBUG
    )


if __name__ == "__main__":
    main()