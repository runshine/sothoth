import shutil

from agent_ai_service.adapters.base import BaseBackendAdapter


class ClaudeA2AAdapter(BaseBackendAdapter):
    backend_type = 'claude-a2a'

    def check_installed(self) -> bool:
        return shutil.which(self.config.command) is not None
