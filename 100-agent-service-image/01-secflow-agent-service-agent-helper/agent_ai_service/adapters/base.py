from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List

from agent_ai_service.models.agent_backend import BackendConfig


class BaseBackendAdapter(ABC):
    backend_type = 'generic'

    def __init__(self, config: BackendConfig):
        self.config = config

    @abstractmethod
    def check_installed(self) -> bool:
        raise NotImplementedError

    def capabilities(self) -> Dict[str, Any]:
        return {
            'type': self.backend_type,
            'supports_a2a': True,
            'supports_sessions': True,
        }

    def build_command(self, prompt: str, messages: List[Dict[str, Any]] | None = None) -> List[str]:
        args = list(self.config.args or [])
        if prompt:
            args.append(prompt)
        return [self.config.command, *args]
