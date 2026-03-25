import shutil

from agent_ai_service.adapters.base import BaseBackendAdapter


class ClaudeAdapter(BaseBackendAdapter):
    backend_type = 'claude'

    def check_installed(self) -> bool:
        return shutil.which(self.config.command) is not None
