from agent_ai_service.adapters.base import BaseBackendAdapter
from agent_ai_service.services.bin_resolver import binary_installed


class CodexAdapter(BaseBackendAdapter):
    backend_type = 'codex'

    def check_installed(self) -> bool:
        return binary_installed(self.config.command)
