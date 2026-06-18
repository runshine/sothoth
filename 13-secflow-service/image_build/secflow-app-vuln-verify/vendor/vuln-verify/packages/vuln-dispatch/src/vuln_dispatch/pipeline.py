from __future__ import annotations

from pathlib import Path

from vuln_dispatch.dedup import deduplicate
from vuln_dispatch.grouper import group
from vuln_dispatch.log import get_logger, logged
from vuln_dispatch.models import RouterOutput, UnrouteableError, UnrouteableRecord
from vuln_dispatch.parser import parse_report, parse_json_report

log = get_logger("vuln_dispatch.pipeline")


@logged
def run(
    reports_dir: str | Path,
    threat_model_path: str | Path | None = None,
    source_root: str | Path | None = None,
    binary_root: str | Path | None = None,
) -> RouterOutput:
    del threat_model_path, source_root, binary_root

    reports_path = Path(reports_dir)
    report_files = sorted(
        list(reports_path.glob("*.md")) + list(reports_path.glob("*.json"))
    )

    parsed_reports = []
    unrouteable = []

    for report_path in report_files:
        try:
            if report_path.suffix == '.json':
                parsed = parse_json_report(report_path)
            else:
                parsed = parse_report(report_path)
            parsed_reports.append(parsed)
        except UnrouteableError as exc:
            log.warning(
                "report_unrouteable",
                report_id=Path(exc.report_path).stem,
                reason=exc.reason,
            )
            unrouteable.append(
                UnrouteableRecord(
                    report_id=Path(exc.report_path).stem,
                    reason=exc.reason,
                    source_path=str(Path(exc.report_path).resolve()),
                )
            )

    deduplicated_reports, dedup_records = deduplicate(parsed_reports)
    groups = group(deduplicated_reports)

    return RouterOutput(
        groups=groups,
        deduplicated=dedup_records,
        unrouteable=unrouteable,
    )
