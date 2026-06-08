from __future__ import annotations

from pathlib import Path
import json
import shutil

from vuln_dispatch.log import logged
from vuln_dispatch.models import RouterOutput, VerifierGroup


def _write_manifest(
    manifest_path: Path, group: VerifierGroup, source_root: Path, binary_root: Path
) -> None:
    manifest = {
        "group_id": group.group_id,
        "file": group.file,
        "binary_root": str(binary_root.resolve()),
        "function": group.function,
        "report_ids": [report.report_id for report in group.reports],
    }
    if group.file != "file_unknown":
        manifest["file_path"] = str(source_root.resolve() / group.file)

    with manifest_path.open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")


def _routing_log(output_data: RouterOutput) -> dict:
    return {
        "groups": [
            {
                "group_id": group.group_id,
                "file": group.file,
                "function": group.function,
                "report_ids": [report.report_id for report in group.reports],
            }
            for group in output_data.groups
        ],
        "deduplicated": [
            {
                "fingerprint": item.fingerprint,
                "kept_report_id": item.kept_report_id,
                "removed_report_ids": item.removed_report_ids,
            }
            for item in output_data.deduplicated
        ],
        "unrouteable": [
            {"report_id": item.report_id, "reason": item.reason}
            for item in output_data.unrouteable
        ],
    }


@logged
def assemble(
    output_data: RouterOutput,
    output_dir: str | Path,
    logfile: str | Path,
    threat_model_path: str | Path,
    source_root: str | Path,
    binary_root: str | Path,
) -> dict:
    output_path = Path(output_dir)
    groups_path = output_path / "groups"
    unrouteable_path = output_path / "unrouteable"
    threat_path = Path(threat_model_path)
    source_root_path = Path(source_root)
    binary_root_path = Path(binary_root)

    groups_path.mkdir(parents=True, exist_ok=True)
    unrouteable_path.mkdir(parents=True, exist_ok=True)

    shutil.copy2(threat_path, output_path / "threat_model.md")

    for group in output_data.groups:
        group_path = groups_path / group.group_id
        reports_path = group_path / "reports"
        reports_path.mkdir(parents=True, exist_ok=True)

        manifest_path = group_path / "manifest.json"
        _write_manifest(manifest_path, group, source_root_path, binary_root_path)

        for report in group.reports:
            source = Path(report.source_path)
            destination = reports_path / f"{report.report_id}_{source.name}"
            shutil.copy2(source, destination)

    for item in output_data.unrouteable:
        source_path = item.source_path
        if source_path:
            source = Path(source_path)
            if source.exists():
                shutil.copy2(source, unrouteable_path / source.name)

    Path(logfile).parent.mkdir(parents=True, exist_ok=True)
    with Path(logfile).open("w", encoding="utf-8") as handle:
        json.dump(_routing_log(output_data), handle, indent=2)
        handle.write("\n")

    return {
        "group_count": len(output_data.groups),
        "report_count": sum(len(g.reports) for g in output_data.groups),
        "unrouteable_count": len(output_data.unrouteable),
    }
