from __future__ import annotations

from vuln_dispatch.grouper import group
from vuln_dispatch.models import ParsedReport


def report(report_id: str, file: str | None, function: str | None) -> ParsedReport:
    return ParsedReport(
        report_id=report_id,
        fingerprint=f"fp-{report_id}",
        file=file,
        function=function,
        source_path=f"/tmp/{report_id}.md",
    )


def test_same_group():
    reports = [report("r1", "a.c", "func"), report("r2", "a.c", "func")]

    groups = group(reports)

    assert len(groups) == 1
    assert groups[0].group_id == "group_001"
    assert groups[0].file == "a.c"
    assert groups[0].function == "func"
    assert groups[0].reports == reports


def test_different_groups():
    reports = [
        report("r1", "a.c", "func"),
        report("r2", "b.c", "func"),
        report("r3", "a.c", "other"),
    ]

    groups = group(reports)

    assert [(g.file, g.function) for g in groups] == [
        ("a.c", "func"),
        ("b.c", "func"),
        ("a.c", "other"),
    ]


def test_null_file_reports_not_grouped_together():
    """Reports missing file each get their own group — no shared context."""
    groups = group([
        report("r1", None, "func"),
        report("r2", None, "func"),
    ])

    assert len(groups) == 2
    assert groups[0].file == "file_unknown"
    assert groups[1].file == "file_unknown"


def test_null_function_reports_not_grouped_together():
    """Reports missing function each get their own group."""
    groups = group([
        report("r1", "a.c", None),
        report("r2", "a.c", None),
    ])

    assert len(groups) == 2


def test_null_both_fields_each_own_group():
    """Completely unparseable reports each get their own group."""
    groups = group([
        report("r1", None, None),
        report("r2", None, None),
        report("r3", None, None),
    ])

    assert len(groups) == 3
    assert [g.group_id for g in groups] == ["group_001", "group_002", "group_003"]


def test_sequential_group_ids():
    reports = [
        report("r1", "a.c", "f1"),
        report("r2", "a.c", "f2"),
        report("r3", "b.c", "f1"),
        report("r4", None, None),
    ]

    groups = group(reports)

    assert [g.group_id for g in groups] == [
        "group_001",
        "group_002",
        "group_003",
        "group_004",
    ]


def test_order_preserved():
    reports = [
        report("r1", "a.c", "func"),
        report("r2", "b.c", "other"),
        report("r3", "a.c", "func"),
        report("r4", "a.c", "func"),
    ]

    groups = group(reports)

    assert [r.report_id for r in groups[0].reports] == ["r1", "r3", "r4"]
    assert [r.report_id for r in groups[1].reports] == ["r2"]
