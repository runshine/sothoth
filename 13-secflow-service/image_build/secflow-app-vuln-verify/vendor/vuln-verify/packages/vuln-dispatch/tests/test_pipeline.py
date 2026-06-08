from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from vuln_dispatch.models import DedupRecord, UnrouteableRecord
from vuln_dispatch.pipeline import run


def write_report(
    path: Path,
    report_id: str,
    fingerprint: str | None,
    file: str | None,
    function: str | None,
) -> None:
    lines = ["# Report", f"**report_id**: {report_id}"]
    if fingerprint is not None:
        lines.append(f"**fingerprint**: {fingerprint}")
    if file is not None:
        lines.append(f"**subject.locator**: {file}:10:2")
    if function is not None:
        lines.append(f"**subject.name**: {function}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_end_to_end():
    with TemporaryDirectory() as tmp:
        base = Path(tmp)
        reports_dir = base / "reports"
        source_root = base / "src"
        binary_root = base / "bin"
        threat = base / "threat.md"
        reports_dir.mkdir()
        source_root.mkdir()
        binary_root.mkdir()
        threat.write_text("threat", encoding="utf-8")

        write_report(reports_dir / "001.md", "result_001", "fp1", "a.c", "foo")
        write_report(reports_dir / "002.md", "result_002", "fp1", "a.c", "foo")
        write_report(reports_dir / "003.md", "result_003", "fp3", "b.c", "bar")
        write_report(reports_dir / "004.md", "result_004", None, "a.c", "foo")

        output = run(reports_dir, threat, source_root, binary_root)

        assert output.deduplicated == [
            DedupRecord(
                fingerprint="fp1",
                kept_report_id="result_001",
                removed_report_ids=["result_002"],
            )
        ]
        assert output.unrouteable == []
        assert [group.group_id for group in output.groups] == ["group_001", "group_002"]
        assert [(group.file, group.function) for group in output.groups] == [
            ("a.c", "foo"),
            ("b.c", "bar"),
        ]
        assert [report.report_id for report in output.groups[0].reports] == [
            "result_001",
            "result_004",
        ]
        assert [report.report_id for report in output.groups[1].reports] == ["result_003"]


def test_mixed_valid_and_unreadable():
    with TemporaryDirectory() as tmp:
        base = Path(tmp)
        reports_dir = base / "reports"
        source_root = base / "src"
        binary_root = base / "bin"
        threat = base / "threat.md"
        reports_dir.mkdir()
        source_root.mkdir()
        binary_root.mkdir()
        threat.write_text("threat", encoding="utf-8")

        write_report(reports_dir / "good.md", "good", "fp-good", "good.c", "good_func")
        (reports_dir / "bad.md").write_text("", encoding="utf-8")

        output = run(reports_dir, threat, source_root, binary_root)

        assert len(output.groups) == 1
        assert output.groups[0].reports[0].report_id == "good"
        assert output.unrouteable == [
            UnrouteableRecord(
                report_id="bad",
                reason="empty file",
                source_path=str((reports_dir / "bad.md").resolve()),
            )
        ]


def test_empty_reports_dir():
    with TemporaryDirectory() as tmp:
        base = Path(tmp)
        reports_dir = base / "reports"
        source_root = base / "src"
        binary_root = base / "bin"
        threat = base / "threat.md"
        reports_dir.mkdir()
        source_root.mkdir()
        binary_root.mkdir()
        threat.write_text("threat", encoding="utf-8")

        output = run(reports_dir, threat, source_root, binary_root)

        assert output.groups == []
        assert output.deduplicated == []
        assert output.unrouteable == []
