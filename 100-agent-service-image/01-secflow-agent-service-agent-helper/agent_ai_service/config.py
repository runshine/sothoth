import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List


@dataclass
class Settings:
    timeout: int = int(os.getenv('TIMEOUT', 180))
    rest_port: int = int(os.getenv('REST_PORT', 20001))
    workdir: str = os.getenv('WORKDIR', '/app')
    state_dir: Path = Path(os.getenv('AGENT_HELPER_STATE_DIR', '/app/data'))
    allowed_commands_raw: str = os.getenv('ALLOWED_COMMANDS', '')
    blocked_commands: List[str] = field(default_factory=lambda: ['rm -rf /'])
    agent_default_backend: str = os.getenv('AGENT_DEFAULT_BACKEND', 'claude')
    agent_api_token: str = os.getenv('AGENT_API_TOKEN', '')
    backend_invoke_timeout_sec: int = int(os.getenv('AGENT_BACKEND_INVOKE_TIMEOUT_SEC', 300))
    backend_idle_timeout_sec: int = int(os.getenv('AGENT_BACKEND_IDLE_TIMEOUT_SEC', 1800))
    housekeeping_interval_sec: int = int(os.getenv('AGENT_HOUSEKEEPING_INTERVAL_SEC', 30))
    health_cache_ttl_sec: int = int(os.getenv('AGENT_HEALTH_CACHE_TTL_SEC', 3600))
    session_pty_quiet_window_ms: int = int(os.getenv('AGENT_SESSION_PTY_QUIET_WINDOW_MS', 450))
    session_pty_max_window_ms: int = int(os.getenv('AGENT_SESSION_PTY_MAX_WINDOW_MS', 10000))
    agent_trace_max_events: int = int(os.getenv('AGENT_TRACE_MAX_EVENTS', 200))
    agent_trace_max_bytes: int = int(os.getenv('AGENT_TRACE_MAX_BYTES', 131072))

    @property
    def allowed_commands(self) -> List[str]:
        return [item.strip() for item in self.allowed_commands_raw.split(',') if item.strip()]

settings = Settings()
settings.state_dir.mkdir(parents=True, exist_ok=True)
