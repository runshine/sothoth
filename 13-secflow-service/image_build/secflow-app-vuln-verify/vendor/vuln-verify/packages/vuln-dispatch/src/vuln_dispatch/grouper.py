from __future__ import annotations

from vuln_dispatch.log import get_logger
from vuln_dispatch.models import ParsedReport, VerifierGroup


log = get_logger("vuln_dispatch.grouper")


def group(reports: list[ParsedReport]) -> list[VerifierGroup]:
    """KISS: no file/function routing; each report gets one verifier group."""
    groups: list[VerifierGroup] = []

    for report in reports:
        group_id = f"group_{len(groups) + 1:03d}"
        groups.append(
            VerifierGroup(
                group_id=group_id,
                file="report",
                function="report",
                reports=[report],
            )
        )

    total_reports = sum(len(g.reports) for g in groups)
    log.info("group", group_count=len(groups), report_count=total_reports, strategy="one_report_per_group")
    return groups
