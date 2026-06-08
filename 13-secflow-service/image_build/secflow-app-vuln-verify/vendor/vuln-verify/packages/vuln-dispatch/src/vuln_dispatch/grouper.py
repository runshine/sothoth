from __future__ import annotations

from vuln_dispatch.log import get_logger
from vuln_dispatch.models import ParsedReport, VerifierGroup


log = get_logger("vuln_dispatch.grouper")


def group(reports: list[ParsedReport]) -> list[VerifierGroup]:
    """Groups by (file, function)."""
    groups: list[VerifierGroup] = []
    by_key: dict[tuple[str, str], VerifierGroup] = {}

    for report in reports:
        if report.file is None or report.function is None:
            file = report.file or "file_unknown"
            function = report.function or "function_unknown"
            group_id = f"group_{len(groups) + 1:03d}"
            vg = VerifierGroup(group_id=group_id, file=file, function=function, reports=[report])
            groups.append(vg)
            continue

        key = (report.file, report.function)
        if key not in by_key:
            group_id = f"group_{len(groups) + 1:03d}"
            vg = VerifierGroup(group_id=group_id, file=report.file, function=report.function)
            by_key[key] = vg
            groups.append(vg)

        by_key[key].reports.append(report)

    total_reports = sum(len(g.reports) for g in groups)
    log.info("group", group_count=len(groups), report_count=total_reports)
    return groups
