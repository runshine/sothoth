from __future__ import annotations

import json
from pathlib import Path

import pytest

from vuln_dispatch.models import UnrouteableError
from vuln_dispatch.parser import parse_report, parse_json_report, _extract_file_from_locator, _extract_function_from_json


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_valid_report():
    report = parse_report(FIXTURES / "valid_report.md")

    assert report.report_id == "result_001"
    assert report.fingerprint == "fp-abc-123"
    assert report.file == "libipsec.c"
    assert report.function == "IPSEC_AH_HandleOutputPktV4"
    assert report.source_path == str((FIXTURES / "valid_report.md").resolve())


def test_parse_missing_fingerprint():
    report = parse_report(FIXTURES / "missing_fingerprint.md")

    assert report.report_id == "result_002"
    assert report.fingerprint is None
    assert report.file == "crypto.c"
    assert report.function == "verify_packet"


def test_parse_missing_function():
    report = parse_report(FIXTURES / "missing_function.md")

    assert report.report_id == "result_003"
    assert report.fingerprint == "fp-no-func"
    assert report.file == "parser.c"
    assert report.function is None


def test_parse_missing_file():
    report = parse_report(FIXTURES / "missing_file.md")

    assert report.report_id == "result_004"
    assert report.fingerprint == "fp-no-file"
    assert report.file is None
    assert report.function == "parse_config"


def test_parse_missing_report_id():
    report = parse_report(FIXTURES / "missing_report_id.md")

    assert report.report_id == "missing_report_id"
    assert report.fingerprint == "fp-no-id"
    assert report.file == "fallback.c"
    assert report.function == "fallback_func"


def test_parse_blank_fingerprint(tmp_path):
    report_path = tmp_path / "blank_fingerprint.md"
    report_path.write_text(
        "**report_id**: result_blank_fp\n"
        "**fingerprint**: \n"
        "**subject.locator**: blank.c:10\n"
        "**subject.name**: blank_func\n"
    )

    report = parse_report(report_path)

    assert report.report_id == "result_blank_fp"
    assert report.fingerprint is None
    assert report.file == "blank.c"
    assert report.function == "blank_func"


def test_parse_blank_function(tmp_path):
    report_path = tmp_path / "blank_function.md"
    report_path.write_text(
        "**report_id**: result_blank_func\n"
        "**fingerprint**: fp-blank-func\n"
        "**subject.locator**: blank.c:10\n"
        "**subject.name**: \n"
    )

    report = parse_report(report_path)

    assert report.report_id == "result_blank_func"
    assert report.fingerprint == "fp-blank-func"
    assert report.file == "blank.c"
    assert report.function is None


def test_parse_blank_file(tmp_path):
    report_path = tmp_path / "blank_file.md"
    report_path.write_text(
        "**report_id**: result_blank_file\n"
        "**fingerprint**: fp-blank-file\n"
        "**subject.locator**:  :10\n"
        "**subject.name**: blank_file_func\n"
    )

    report = parse_report(report_path)

    assert report.report_id == "result_blank_file"
    assert report.fingerprint == "fp-blank-file"
    assert report.file is None
    assert report.function == "blank_file_func"


def test_parse_blank_report_id(tmp_path):
    report_path = tmp_path / "blank_report_id.md"
    report_path.write_text(
        "**report_id**: \n"
        "**fingerprint**: fp-blank-id\n"
        "**subject.locator**: blank.c:10\n"
        "**subject.name**: blank_id_func\n"
    )

    report = parse_report(report_path)

    assert report.report_id == "blank_report_id"
    assert report.fingerprint == "fp-blank-id"
    assert report.file == "blank.c"
    assert report.function == "blank_id_func"


def test_parse_unreadable_file():
    missing = FIXTURES / "does_not_exist.md"

    with pytest.raises(UnrouteableError) as excinfo:
        parse_report(missing)

    assert str(missing) in str(excinfo.value)
    assert excinfo.value.report_path == str(missing)


def test_parse_empty_file(tmp_path):
    empty = tmp_path / "empty.md"
    empty.write_text("")

    with pytest.raises(UnrouteableError) as excinfo:
        parse_report(empty)

    assert excinfo.value.report_path == str(empty)
    assert excinfo.value.reason == "empty file"


# ---------------------------------------------------------------------------
# JSON parser tests
# ---------------------------------------------------------------------------


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


class TestExtractFileFromLocator:
    def test_simple_file_line(self):
        assert _extract_file_from_locator("src/a.c:123") == "src/a.c"

    def test_file_func_line(self):
        assert _extract_file_from_locator("libipsec.c:MyFunc:100") == "libipsec.c"

    def test_file_func_range(self):
        assert _extract_file_from_locator("libipsec.c:Func:L123-L456") == "libipsec.c"

    def test_empty_locator(self):
        assert _extract_file_from_locator("") is None
        assert _extract_file_from_locator(None) is None

    def test_no_colon(self):
        assert _extract_file_from_locator("justfile.c") == "justfile.c"


class TestExtractFunctionFromJson:
    def test_source_function_name(self):
        case = {"metadata": {"source": {"function_name": "MyFunc"}}}
        assert _extract_function_from_json(case) == "MyFunc"

    def test_dvs_finding_artifact(self):
        case = {
            "metadata": {"source": {}},
            "artifacts": [{
                "name": "dvs-finding.json",
                "content": json.dumps({"function_name": "ArtifactFunc"}),
            }],
        }
        assert _extract_function_from_json(case) == "ArtifactFunc"

    def test_dvs_finding_dict_content(self):
        case = {
            "metadata": {"source": {}},
            "artifacts": [{
                "name": "dvs-finding.json",
                "content": {"function_name": "DictFunc"},
            }],
        }
        assert _extract_function_from_json(case) == "DictFunc"

    def test_fallback_subject_name(self):
        case = {
            "metadata": {"source": {}},
            "subject": {"name": "Report Title"},
        }
        assert _extract_function_from_json(case) == "Report Title"

    def test_all_empty(self):
        case = {}
        assert _extract_function_from_json(case) is None

    def test_source_takes_priority(self):
        case = {
            "metadata": {"source": {"function_name": "SourceFunc"}},
            "artifacts": [{
                "name": "dvs-finding.json",
                "content": json.dumps({"function_name": "ArtifactFunc"}),
            }],
            "subject": {"name": "Title"},
        }
        assert _extract_function_from_json(case) == "SourceFunc"


class TestParseJsonReport:
    def test_valid_with_function_name(self, tmp_path):
        case = {
            "finding_id": "DVS-test-001",
            "fingerprint": "abc123def",
            "subject": {"locator": "libipsec.c:MyFunc:100", "name": "Test Title"},
            "metadata": {"source": {"function_name": "MyFunc"}},
        }
        p = tmp_path / "test.json"
        _write_json(p, case)

        r = parse_json_report(p)
        assert r.report_id == "DVS-test-001"
        assert r.fingerprint == "abc123def"
        assert r.file == "libipsec.c"
        assert r.function == "MyFunc"
        assert r.source_path == str(p.resolve())

    def test_fallback_to_subject_name(self, tmp_path):
        case = {
            "finding_id": "DVS-test-002",
            "fingerprint": "def456",
            "subject": {"locator": "test.c:42", "name": "Fallback Func"},
            "metadata": {"source": {}},
        }
        p = tmp_path / "test2.json"
        _write_json(p, case)

        r = parse_json_report(p)
        assert r.report_id == "DVS-test-002"
        assert r.file == "test.c"
        assert r.function == "Fallback Func"

    def test_missing_fingerprint(self, tmp_path):
        case = {
            "finding_id": "DVS-no-fp",
            "subject": {"locator": "a.c:1"},
        }
        p = tmp_path / "no_fp.json"
        _write_json(p, case)

        r = parse_json_report(p)
        assert r.report_id == "DVS-no-fp"
        assert r.fingerprint is None

    def test_finding_id_fallback_to_report_id(self, tmp_path):
        case = {
            "report_id": "FALLBACK-ID",
            "subject": {"locator": "a.c:1"},
        }
        p = tmp_path / "no_fid.json"
        _write_json(p, case)

        r = parse_json_report(p)
        assert r.report_id == "FALLBACK-ID"

    def test_empty_json_raises(self, tmp_path):
        p = tmp_path / "empty.json"
        p.write_text("")
        with pytest.raises(UnrouteableError) as excinfo:
            parse_json_report(p)
        assert excinfo.value.reason == "empty file"

    def test_invalid_json_raises(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("not json")
        with pytest.raises(UnrouteableError) as excinfo:
            parse_json_report(p)
        assert "invalid JSON" in excinfo.value.reason

    def test_nonexistent_file_raises(self):
        with pytest.raises(UnrouteableError):
            parse_json_report("/nonexistent/path.json")
