from __future__ import annotations

from dataclasses import dataclass, field


class UnrouteableError(Exception):
    """Raised when a report file cannot be parsed (IO error, encoding, empty)."""

    def __init__(self, report_path: str, reason: str):
        self.report_path = report_path
        self.reason = reason
        super().__init__(f"Cannot route {report_path}: {reason}")


@dataclass
class ParsedReport:
    report_id: str
    fingerprint: str | None
    file: str | None
    function: str | None
    source_path: str


@dataclass
class VerifierGroup:
    group_id: str
    file: str
    function: str
    reports: list[ParsedReport] = field(default_factory=list)


@dataclass
class DedupRecord:
    fingerprint: str
    kept_report_id: str
    removed_report_ids: list[str]


@dataclass
class UnrouteableRecord:
    report_id: str
    reason: str
    source_path: str


@dataclass
class RouterOutput:
    groups: list[VerifierGroup] = field(default_factory=list)
    deduplicated: list[DedupRecord] = field(default_factory=list)
    unrouteable: list[UnrouteableRecord] = field(default_factory=list)

    def to_log_dict(self) -> dict:
        return {
            "group_count": len(self.groups),
            "dedup_removed": sum(len(r.removed_report_ids) for r in self.deduplicated),
            "unrouteable_count": len(self.unrouteable),
        }
