from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class A2AMessage:
    role: str
    content: str


@dataclass
class A2ASession:
    session_id: str
    backend: str
    messages: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
