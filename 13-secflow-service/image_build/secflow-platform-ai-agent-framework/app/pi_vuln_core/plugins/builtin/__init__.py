"""内置插件包导出"""
from app.pi_vuln_core.plugins.builtin.env_setup import EnvSetupPlugin
from app.pi_vuln_core.plugins.builtin.workspace_init import WorkspaceInitPlugin
from app.pi_vuln_core.plugins.builtin.task_validator import TaskValidatorPlugin
from app.pi_vuln_core.plugins.builtin.result_archiver import ResultArchiverPlugin
from app.pi_vuln_core.plugins.builtin.next_task_generator import NextTaskGeneratorPlugin

__all__ = [
    "EnvSetupPlugin", "WorkspaceInitPlugin", "TaskValidatorPlugin",
    "ResultArchiverPlugin", "NextTaskGeneratorPlugin",
]
