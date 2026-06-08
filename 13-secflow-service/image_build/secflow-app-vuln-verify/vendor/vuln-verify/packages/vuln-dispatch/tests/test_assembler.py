from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from vuln_dispatch.assembler import assemble
from vuln_dispatch.models import (
    DedupRecord,
    ParsedReport,
    RouterOutput,
    UnrouteableRecord,
    VerifierGroup,
)


def make_output(base: Path) -> tuple[RouterOutput, Path, Path, Path]:
    reports_dir = base / "reports"
    reports_dir.mkdir()
    source_root = base / "src"
    binary_root = base / "bin"
    source_root.mkdir()
    binary_root.mkdir()
    threat = base / "threat.md"

    report1 = reports_dir / "result_001.md"
    report2 = reports_dir / "result_004.md"
    unrouteable = reports_dir / "bad.md"
    report1.write_text("report one", encoding="utf-8")
    report2.write_text("report four", encoding="utf-8")
    unrouteable.write_text("bad", encoding="utf-8")
    threat.write_text("threat model", encoding="utf-8")

    parsed1 = ParsedReport(
        report_id="result_001",
        fingerprint="fp1",
        file="libipsec.c",
        function="IPSEC_AH_HandleOutputPktV4",
        source_path=str(report1.resolve()),
    )
    parsed2 = ParsedReport(
        report_id="result_004",
        fingerprint="fp4",
        file="libipsec.c",
        function="IPSEC_AH_HandleOutputPktV4",
        source_path=str(report2.resolve()),
    )
    output = RouterOutput(
        groups=[
            VerifierGroup(
                group_id="group_001",
                file="libipsec.c",
                function="IPSEC_AH_HandleOutputPktV4",
                reports=[parsed1, parsed2],
            ),
            VerifierGroup(
                group_id="group_002",
                file="file_unknown",
                function="function_unknown",
                reports=[],
            ),
        ],
        deduplicated=[
            DedupRecord(
                fingerprint="fp1",
                kept_report_id="result_001",
                removed_report_ids=["result_003"],
            )
        ],
        unrouteable=[
            UnrouteableRecord(
                report_id="bad",
                reason="empty file",
                source_path=str(unrouteable.resolve()),
            )
        ],
    )
    return output, threat, source_root, binary_root


def test_directory_structure():
    with TemporaryDirectory() as tmp:
        base = Path(tmp)
        output, threat, source_root, binary_root = make_output(base)
        output_dir = base / "out"
        logfile = base / "routing_log.json"

        assemble(output, output_dir, logfile, threat, source_root, binary_root)

        assert (output_dir / "groups").is_dir()
        assert (output_dir / "unrouteable").is_dir()
        assert (output_dir / "groups" / "group_001").is_dir()
        assert (output_dir / "groups" / "group_001" / "reports").is_dir()
        assert (output_dir / "groups" / "group_002").is_dir()


def test_manifest_content():
    with TemporaryDirectory() as tmp:
        base = Path(tmp)
        output, threat, source_root, binary_root = make_output(base)
        output_dir = base / "out"
        logfile = base / "routing_log.json"

        assemble(output, output_dir, logfile, threat, source_root, binary_root)

        data = json.loads(
            (output_dir / "groups" / "group_001" / "manifest.json").read_text(
                encoding="utf-8"
            )
        )
        assert data["group_id"] == "group_001"
        assert data["file"] == "libipsec.c"
        assert data["file_path"] == str(source_root.resolve() / "libipsec.c")
        assert data["binary_root"] == str(binary_root.resolve())
        assert data["function"] == "IPSEC_AH_HandleOutputPktV4"
        assert data["report_ids"] == ["result_001", "result_004"]

        unknown_data = json.loads(
            (output_dir / "groups" / "group_002" / "manifest.json").read_text(
                encoding="utf-8"
            )
        )
        assert unknown_data["file"] == "file_unknown"
        assert "file_path" not in unknown_data


def test_threat_model_copied():
    with TemporaryDirectory() as tmp:
        base = Path(tmp)
        output, threat, source_root, binary_root = make_output(base)
        output_dir = base / "out"
        logfile = base / "routing_log.json"

        assemble(output, output_dir, logfile, threat, source_root, binary_root)

        assert (output_dir / "threat_model.md").read_text(encoding="utf-8") == "threat model"


def test_reports_copied():
    with TemporaryDirectory() as tmp:
        base = Path(tmp)
        output, threat, source_root, binary_root = make_output(base)
        output_dir = base / "out"
        logfile = base / "routing_log.json"

        assemble(output, output_dir, logfile, threat, source_root, binary_root)

        reports_out = output_dir / "groups" / "group_001" / "reports"
        assert (reports_out / "result_001_result_001.md").read_text(encoding="utf-8") == "report one"
        assert (reports_out / "result_004_result_004.md").read_text(encoding="utf-8") == "report four"
        assert (output_dir / "unrouteable" / "bad.md").read_text(encoding="utf-8") == "bad"


def test_reports_with_same_basename_are_prefixed_with_report_id():
    with TemporaryDirectory() as tmp:
        base = Path(tmp)
        reports_dir_1 = base / "reports_a"
        reports_dir_2 = base / "reports_b"
        source_root = base / "src"
        binary_root = base / "bin"
        reports_dir_1.mkdir()
        reports_dir_2.mkdir()
        source_root.mkdir()
        binary_root.mkdir()
        threat = base / "threat.md"

        report1 = reports_dir_1 / "result.md"
        report2 = reports_dir_2 / "result.md"
        report1.write_text("first report", encoding="utf-8")
        report2.write_text("second report", encoding="utf-8")
        threat.write_text("threat model", encoding="utf-8")

        parsed1 = ParsedReport(
            report_id="report_a",
            fingerprint="fp_a",
            file="libipsec.c",
            function="IPSEC_AH_HandleOutputPktV4",
            source_path=str(report1.resolve()),
        )
        parsed2 = ParsedReport(
            report_id="report_b",
            fingerprint="fp_b",
            file="libipsec.c",
            function="IPSEC_AH_HandleOutputPktV4",
            source_path=str(report2.resolve()),
        )
        output = RouterOutput(
            groups=[
                VerifierGroup(
                    group_id="group_001",
                    file="libipsec.c",
                    function="IPSEC_AH_HandleOutputPktV4",
                    reports=[parsed1, parsed2],
                )
            ],
            deduplicated=[],
            unrouteable=[],
        )
        output_dir = base / "out"
        logfile = base / "routing_log.json"

        assemble(output, output_dir, logfile, threat, source_root, binary_root)

        reports_out = output_dir / "groups" / "group_001" / "reports"
        assert (reports_out / "report_a_result.md").read_text(encoding="utf-8") == "first report"
        assert (reports_out / "report_b_result.md").read_text(encoding="utf-8") == "second report"


def test_routing_log_content():
    with TemporaryDirectory() as tmp:
        base = Path(tmp)
        output, threat, source_root, binary_root = make_output(base)
        output_dir = base / "out"
        logfile = base / "routing_log.json"

        assemble(output, output_dir, logfile, threat, source_root, binary_root)

        data = json.loads(logfile.read_text(encoding="utf-8"))
        assert data["groups"] == [
            {
                "group_id": "group_001",
                "file": "libipsec.c",
                "function": "IPSEC_AH_HandleOutputPktV4",
                "report_ids": ["result_001", "result_004"],
            },
            {
                "group_id": "group_002",
                "file": "file_unknown",
                "function": "function_unknown",
                "report_ids": [],
            },
        ]
        assert data["deduplicated"] == [
            {
                "fingerprint": "fp1",
                "kept_report_id": "result_001",
                "removed_report_ids": ["result_003"],
            }
        ]
        assert data["unrouteable"] == [
            {"report_id": "bad", "reason": "empty file"}
        ]
