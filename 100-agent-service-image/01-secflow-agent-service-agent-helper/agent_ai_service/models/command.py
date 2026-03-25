from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class CommandRequest:
    command: str
    env: Optional[Dict[str, str]] = None
