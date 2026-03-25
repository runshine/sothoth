from agent_ai_service.adapters.base import BaseBackendAdapter
from agent_ai_service.services.bin_resolver import binary_installed


class ClaudeA2AAdapter(BaseBackendAdapter):
    backend_type = 'claude-a2a'

    def check_installed(self) -> bool:
        return binary_installed(self.config.command)
