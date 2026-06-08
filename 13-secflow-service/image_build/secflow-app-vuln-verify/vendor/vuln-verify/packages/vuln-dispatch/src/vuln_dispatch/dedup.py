from __future__ import annotations

from vuln_dispatch.log import logged
from vuln_dispatch.models import DedupRecord, ParsedReport


@logged
def deduplicate(reports: list[ParsedReport]) -> tuple[list[ParsedReport], list[DedupRecord]]:
    """Returns (deduplicated_reports, dedup_records)."""
    kept: list[ParsedReport] = []
    dedup_records: list[DedupRecord] = []
    fingerprint_to_kept: dict[str, ParsedReport] = {}
    fingerprint_to_removed: dict[str, list[str]] = {}

    for report in reports:
        if not report.fingerprint:
            kept.append(report)
            continue

        if report.fingerprint not in fingerprint_to_kept:
            fingerprint_to_kept[report.fingerprint] = report
            fingerprint_to_removed[report.fingerprint] = []
            kept.append(report)
        else:
            fingerprint_to_removed[report.fingerprint].append(report.report_id)

    for fp, kept_report in fingerprint_to_kept.items():
        removed = fingerprint_to_removed[fp]
        if removed:
            dedup_records.append(
                DedupRecord(
                    fingerprint=fp,
                    kept_report_id=kept_report.report_id,
                    removed_report_ids=removed,
                )
            )

    return kept, dedup_records
