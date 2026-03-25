from dataclasses import dataclass
import os


def _get_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class Settings:
    port: int = _get_int('PROCESS_MONITOR_PORT', 20004)
    interval_sec: int = _get_int('PROCESS_MONITOR_INTERVAL_SEC', 15)
    workdir: str = os.getenv('WORKDIR', '/app')
    state_dir: str = os.getenv('AGENT_HELPER_STATE_DIR', '/app/data')
    host_root: str = os.getenv('HOST_ROOT', '/host')
    proc_root: str = os.getenv('PROCESS_MONITOR_PROC_ROOT', '/host/proc')


settings = Settings()
