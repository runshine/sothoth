import shutil

from agent_ai_service.adapters.base import BaseBackendAdapter


class CodexAdapter(BaseBackendAdapter):
    backend_type = 'codex'

    def check_installed(self) -> bool:
        return shutil.which(self.config.command) is not None
