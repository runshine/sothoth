from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class BackendConfig:
    name: str
    command: str
    args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    cwd: Optional[str] = None
    description: str = ''


@dataclass
class BackendRuntimeState:
    pid: Optional[int] = None
    running: bool = False
    last_error: str = ''
    last_started_at: Optional[str] = None
