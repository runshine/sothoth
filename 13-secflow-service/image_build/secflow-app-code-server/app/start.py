#!/usr/bin/env python3
"""启动脚本 - 设置正确的 Python 路径"""

import os
import sys
from pathlib import Path

# 项目根目录 (app 的父目录)
PROJECT_ROOT = Path(__file__).parent.parent

# 设置环境变量 (供 uvicorn 子进程使用)
os.environ["PYTHONPATH"] = str(PROJECT_ROOT)

# 添加到 sys.path（供当前进程使用）
sys.path.insert(0, str(PROJECT_ROOT))

import uvicorn
from app.config import get_config

if __name__ == "__main__":
    config = get_config()
    uvicorn.run(
        "app.main:app",
        host=config.app.host,
        port=config.app.port,
        reload=config.app.debug,
    )
