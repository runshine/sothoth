"""
K8S资源管理服务启动脚本
"""

import uvicorn

from app.config import get_config

if __name__ == "__main__":
    config = get_config()

    print(f"启动K8S资源管理服务: {config.app.host}:{config.app.port}")

    uvicorn.run(
        "app.main:app",
        host=config.app.host,
        port=config.app.port,
        reload=config.app.debug,
        log_level=config.logging.level.lower(),
    )