"""
评审研判配置管理
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field


class ReviewerConfig(BaseModel):
    model: Optional[str] = None
    thinking: Optional[str] = None
    tools: str = "read,bash"
    timeout_seconds: int = 3600
    max_retries: int = 3
    retry_interval_seconds: int = 30


class WorkerConfig(BaseModel):
    model: Optional[str] = None
    thinking: Optional[str] = None
    tools: str = "read,bash,edit,write"
    timeout_seconds: int = 3600
    max_retries: int = 3
    retry_interval_seconds: int = 30


class ReviewJudgeConfig(BaseModel):
    reviewer: ReviewerConfig = Field(default_factory=ReviewerConfig)
    worker: WorkerConfig = Field(default_factory=WorkerConfig)
    prompts_dir: str = "prompts/review_judge"
    log_level: str = "INFO"


_config: Optional[ReviewJudgeConfig] = None


def load_config(config_path: Optional[str] = None) -> ReviewJudgeConfig:
    global _config

    if config_path:
        path = Path(config_path)
        if path.is_file():
            data = json.loads(path.read_text(encoding="utf-8"))
            _config = ReviewJudgeConfig(**data)
            return _config

    # Default
    _config = ReviewJudgeConfig()
    return _config


def get_config() -> ReviewJudgeConfig:
    global _config
    if _config is None:
        _config = load_config()
    return _config