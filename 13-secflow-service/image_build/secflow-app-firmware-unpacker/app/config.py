"""Configuration loader for the AgentFlow-only firmware unpacker."""

from __future__ import annotations

import os
from typing import Optional

import yaml
from pydantic import BaseModel, Field


class AgentFlowConfig(BaseModel):
    """AgentFlow engine configuration."""

    enabled: bool = True
    profile: str = "production"
    runs_dir: str = "/data/files/.agentflow/runs"
    max_concurrent_runs: int = 2
    node_timeout_seconds: int = 1800
    use_worktree: bool = False
    graph_optimization_enabled: bool = False
    graph_optimizer: str = "codex"
    graph_optimization_rounds: int = 1
    evolution_archive_dir: str = ""
    cleanup_runs_retention_days: int = 7


class LoggingConfig(BaseModel):
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


class Config(BaseModel):
    agentflow: AgentFlowConfig = Field(default_factory=AgentFlowConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)


_config: Optional[Config] = None


def _candidate_paths(config_path: Optional[str]) -> list[str]:
    if config_path:
        return [config_path]
    return [
        os.environ.get("CONFIG_PATH", ""),
        os.environ.get("FIRMWARE_UNPACKER_CONFIG", ""),
        "config.yaml",
        os.path.join(os.path.dirname(__file__), "..", "config.yaml"),
        "/app/config.yaml",
    ]


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _apply_env_overrides(cfg: Config) -> Config:
    cfg.agentflow.enabled = True
    cfg.agentflow.profile = os.environ.get("AGENTFLOW_PROFILE", cfg.agentflow.profile)
    cfg.agentflow.runs_dir = os.environ.get("AGENTFLOW_RUNS_DIR", cfg.agentflow.runs_dir)
    cfg.agentflow.max_concurrent_runs = _env_int(
        "AGENTFLOW_MAX_CONCURRENT_RUNS",
        cfg.agentflow.max_concurrent_runs,
    )
    cfg.agentflow.node_timeout_seconds = _env_int(
        "AGENTFLOW_NODE_TIMEOUT_SECONDS",
        cfg.agentflow.node_timeout_seconds,
    )
    cfg.agentflow.use_worktree = _env_bool("AGENTFLOW_USE_WORKTREE", cfg.agentflow.use_worktree)
    cfg.agentflow.graph_optimization_enabled = _env_bool(
        "AGENTFLOW_GRAPH_OPTIMIZATION_ENABLED",
        cfg.agentflow.graph_optimization_enabled,
    )
    cfg.agentflow.graph_optimizer = os.environ.get(
        "AGENTFLOW_GRAPH_OPTIMIZER",
        cfg.agentflow.graph_optimizer,
    )
    cfg.agentflow.graph_optimization_rounds = _env_int(
        "AGENTFLOW_GRAPH_OPTIMIZATION_ROUNDS",
        cfg.agentflow.graph_optimization_rounds,
    )
    cfg.agentflow.evolution_archive_dir = os.environ.get(
        "AGENTFLOW_EVOLUTION_ARCHIVE_DIR",
        cfg.agentflow.evolution_archive_dir,
    )
    cfg.agentflow.cleanup_runs_retention_days = _env_int(
        "AGENTFLOW_CLEANUP_RUNS_RETENTION_DAYS",
        cfg.agentflow.cleanup_runs_retention_days,
    )
    cfg.logging.level = os.environ.get("LOG_LEVEL", cfg.logging.level)
    return cfg


def load_config(config_path: Optional[str] = None) -> Config:
    global _config
    if _config is not None:
        return _config

    for path in _candidate_paths(config_path):
        if not path or not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8") as file:
            data = yaml.safe_load(file) or {}
        _config = _apply_env_overrides(Config(**data))
        return _config

    _config = _apply_env_overrides(Config())
    return _config


def get_config() -> Config:
    global _config
    if _config is None:
        _config = load_config()
    return _config


def reload_config(config_path: Optional[str] = None) -> Config:
    global _config
    _config = None
    return load_config(config_path)
