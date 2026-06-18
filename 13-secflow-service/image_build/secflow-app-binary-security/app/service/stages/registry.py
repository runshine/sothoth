from __future__ import annotations

from dataclasses import dataclass

from app.service.stages.base import BinarySecurityStageHandler
from app.service.stages.binary_to_source import BinaryToSourceStageHandler
from app.service.stages.dataflow_vuln_scan import DataflowVulnScanStageHandler
from app.service.stages.entry_analysis import EntryAnalysisStageHandler
from app.service.stages.firmware_unpack import FirmwareUnpackStageHandler
from app.service.stages.knowledge_graph_entry_fetch import KnowledgeGraphEntryFetchStageHandler
from app.service.stages.system_analysis import SystemAnalysisStageHandler


@dataclass(frozen=True)
class _PassiveStageHandler(BinarySecurityStageHandler):
    pass


class BinarySecurityStageRegistry:
    def __init__(self) -> None:
        self._handlers = {
            "firmware_unpack": FirmwareUnpackStageHandler(),
            "system_analysis": SystemAnalysisStageHandler(),
            "binary_to_source": BinaryToSourceStageHandler(),
            "entry_analysis": EntryAnalysisStageHandler(),
            "knowledge_graph_entry_fetch": KnowledgeGraphEntryFetchStageHandler(),
            "dataflow_vuln_scan": DataflowVulnScanStageHandler(),
        }

    def get(self, stage_name: str | None) -> BinarySecurityStageHandler | None:
        normalized = str(stage_name or "").strip()
        if not normalized:
            return None
        return self._handlers.get(normalized)


_registry: BinarySecurityStageRegistry | None = None


def get_binary_security_stage_registry() -> BinarySecurityStageRegistry:
    global _registry
    if _registry is None:
        _registry = BinarySecurityStageRegistry()
    return _registry
