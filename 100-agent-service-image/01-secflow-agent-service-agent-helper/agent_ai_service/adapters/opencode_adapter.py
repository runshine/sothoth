import shutil

from agent_ai_service.adapters.base import BaseBackendAdapter


class OpencodeAdapter(BaseBackendAdapter):
    backend_type = 'opencode'

    def check_installed(self) -> bool:
        return shutil.which(self.config.command) is not None
