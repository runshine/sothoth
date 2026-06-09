"""Tests for Phase 2 output validation."""

import json
from pathlib import Path

from app.reporter import validate_phase2_outputs, summarize_result


class TestValidateOutputs:
    def test_all_valid(self, tmp_path):
        (tmp_path / "poc_result.json").write_text(json.dumps({"status": "reachable"}))
        (tmp_path / "patch_log.json").write_text(json.dumps({"patches": []}))
        (tmp_path / "branch_decisions.json").write_text(json.dumps({"branches": []}))
        (tmp_path / "poc_result.md").write_text("# test")

        checks = validate_phase2_outputs(tmp_path)
        assert checks["poc_result.json"]
        assert checks["patch_log.json"]
        assert checks["branch_decisions.json"]
        assert checks["poc_result.md"]

    def test_missing_files(self, tmp_path):
        checks = validate_phase2_outputs(tmp_path)
        assert not checks["poc_result.json"]
        assert not checks["poc_result.md"]

    def test_invalid_json(self, tmp_path):
        (tmp_path / "poc_result.json").write_text("not json")
        checks = validate_phase2_outputs(tmp_path)
        assert not checks["poc_result.json"]


class TestSummarizeResult:
    def test_summary(self, tmp_path):
        (tmp_path / "poc_result.json").write_text(json.dumps({
            "status": "reachable",
            "reach_vuln_point": True,
            "total_patches": 3,
            "total_branches": 5,
            "vuln_function": "foo",
            "entry_function": "main",
        }))
        s = summarize_result(tmp_path)
        assert "reachable" in s
        assert "YES" in s
        assert "3" in s
        assert "5" in s
