import unittest

from app.service.stages.binary_to_source import BinaryToSourceStageHandler
from app.service.stages.dataflow_vuln_scan import DataflowVulnScanStageHandler
from app.service.stages.entry_analysis import EntryAnalysisStageHandler
from app.service.stages.firmware_unpack import FirmwareUnpackStageHandler
from app.service.stages.knowledge_graph_entry_fetch import KnowledgeGraphEntryFetchStageHandler
from app.service.stages.registry import get_binary_security_stage_registry
from app.service.stages.system_analysis import SystemAnalysisStageHandler


class BinarySecurityStageRegistryTests(unittest.TestCase):
    def test_registry_returns_handler_for_each_known_stage(self):
        registry = get_binary_security_stage_registry()

        for stage_name in [
            "firmware_unpack",
            "system_analysis",
            "binary_to_source",
            "entry_analysis",
            "knowledge_graph_entry_fetch",
            "dataflow_vuln_scan",
        ]:
            with self.subTest(stage_name=stage_name):
                handler = registry.get(stage_name)
                self.assertIsNotNone(handler)
                self.assertEqual(stage_name, handler.stage_name)

    def test_registry_returns_system_analysis_specific_handler(self):
        registry = get_binary_security_stage_registry()

        handler = registry.get("system_analysis")

        self.assertIsInstance(handler, SystemAnalysisStageHandler)

    def test_registry_returns_specific_handlers_for_all_stage_types(self):
        registry = get_binary_security_stage_registry()

        self.assertIsInstance(registry.get("firmware_unpack"), FirmwareUnpackStageHandler)
        self.assertIsInstance(registry.get("system_analysis"), SystemAnalysisStageHandler)
        self.assertIsInstance(registry.get("binary_to_source"), BinaryToSourceStageHandler)
        self.assertIsInstance(registry.get("entry_analysis"), EntryAnalysisStageHandler)
        self.assertIsInstance(registry.get("knowledge_graph_entry_fetch"), KnowledgeGraphEntryFetchStageHandler)
        self.assertIsInstance(registry.get("dataflow_vuln_scan"), DataflowVulnScanStageHandler)

    def test_registry_returns_none_for_unknown_or_empty_stage(self):
        registry = get_binary_security_stage_registry()

        self.assertIsNone(registry.get(None))
        self.assertIsNone(registry.get(""))
        self.assertIsNone(registry.get("unknown_stage"))


if __name__ == "__main__":
    unittest.main()
