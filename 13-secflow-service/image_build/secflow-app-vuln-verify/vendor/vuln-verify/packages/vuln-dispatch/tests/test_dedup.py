from __future__ import annotations

from vuln_dispatch.dedup import deduplicate
from vuln_dispatch.models import DedupRecord, ParsedReport


def report(report_id: str, fingerprint: str | None) -> ParsedReport:
    return ParsedReport(
        report_id=report_id,
        fingerprint=fingerprint,
        file="file.c",
        function="func",
        source_path=f"/tmp/{report_id}.md",
    )


def test_no_duplicates():
    reports = [report("r1", "fp1"), report("r2", "fp2"), report("r3", "fp3")]

    kept, records = deduplicate(reports)

    assert kept == reports
    assert records == []


def test_exact_duplicates_merged():
    reports = [report("r1", "fp1"), report("r2", "fp1"), report("r3", "fp1")]

    kept, records = deduplicate(reports)

    assert kept == [reports[0]]
    assert records == [
        DedupRecord(
            fingerprint="fp1",
            kept_report_id="r1",
            removed_report_ids=["r2", "r3"],
        )
    ]


def test_null_fingerprints_not_merged():
    reports = [report("r1", None), report("r2", None), report("r3", None)]

    kept, records = deduplicate(reports)

    assert kept == reports
    assert records == []


def test_blank_fingerprints_not_merged():
    reports = [report("r1", ""), report("r2", "")]

    kept, records = deduplicate(reports)

    assert kept == reports
    assert records == []


def test_mixed_scenario():
    reports = [
        report("r1", "fp1"),
        report("r2", None),
        report("r3", "fp2"),
        report("r4", "fp1"),
        report("r5", None),
        report("r6", "fp2"),
        report("r7", "fp3"),
    ]

    kept, records = deduplicate(reports)

    assert kept == [reports[0], reports[1], reports[2], reports[4], reports[6]]
    assert records == [
        DedupRecord(fingerprint="fp1", kept_report_id="r1", removed_report_ids=["r4"]),
        DedupRecord(fingerprint="fp2", kept_report_id="r3", removed_report_ids=["r6"]),
    ]
