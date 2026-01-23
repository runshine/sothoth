# app/config.py
from typing import Dict, Any, Optional
from app.database import AsyncSessionLocal
from app import models

# 默认配置
DEFAULT_CONFIG = {
    "api_key": "",
    "base_url": "https://api.anthropic.com",
    "main_model": "claude-sonnet-4",
    "cluster_model": "claude-sonnet-4",
    "fallback_model": "glm-4p5",
    "max_tokens": 32768,
    "max_token_per_module": 36369,
    "max_token_per_leaf_module": 16000,
    "max_depth": 2,
    "include": None,
    "exclude": None,
    "focus": None,
    "doc_type": "api",
    "instructions": None
}


async def get_current_config() -> Dict[str, Any]:
    """获取当前配置"""
    async with AsyncSessionLocal() as db:
        db_config = await models.Config.get_all(db)

    # 合并默认配置和数据库配置
    config = DEFAULT_CONFIG.copy()
    for key, value in db_config.items():
        if key in config:
            # 尝试转换类型
            if value is None:
                config[key] = None
            elif value.lower() == 'true':
                config[key] = True
            elif value.lower() == 'false':
                config[key] = False
            elif value.isdigit():
                config[key] = int(value)
            elif value.replace('.', '', 1).isdigit():
                config[key] = float(value)
            else:
                config[key] = value

    return config


async def update_config(db, config_updates: Dict[str, Any]) -> Dict[str, Any]:
    """更新配置"""
    for key, value in config_updates.items():
        if key in DEFAULT_CONFIG:
            await models.Config.set(db, key, value)

    # 获取更新后的完整配置
    return await get_current_config()


async def get_config_for_task(
        task_id: str,
        task_config_overrides: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """获取任务配置（合并全局配置和任务特定配置）"""
    # 获取全局配置
    global_config = await get_current_config()

    # 合并任务特定配置
    if task_config_overrides:
        global_config.update(task_config_overrides)

    return global_config