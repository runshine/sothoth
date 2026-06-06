from __future__ import annotations

from sqlalchemy import text

from app.model import get_engine


STAGE_TABLES = [
    "secflow_binary_security_stage_item",
    "secflow_binary_security_stage_run",
    "secflow_binary_security_event",
    "secflow_binary_security_state_event",
    "secflow_binary_security_archive_job",
]

STAGE_RENAMES = {
    "dataflow_analysis": "dataflow_vuln_scan",
    "vuln_scan": "dataflow_vuln_scan",
}

SERVICE_RENAMES = {
    "dataflow_analyse": "dataflow_vuln_scan",
    "dataflow_vuln_scanner": "dataflow_vuln_scan",
}


def main() -> None:
    engine = get_engine()
    with engine.begin() as conn:
        for table_name in STAGE_TABLES:
            for legacy, canonical in STAGE_RENAMES.items():
                result = conn.execute(
                    text(f"UPDATE {table_name} SET stage_name = :canonical WHERE stage_name = :legacy"),
                    {"legacy": legacy, "canonical": canonical},
                )
                print(f"{table_name}.stage_name: {legacy} -> {canonical}, updated={result.rowcount}")

        for legacy, canonical in SERVICE_RENAMES.items():
            result = conn.execute(
                text(
                    "UPDATE secflow_binary_security_stage_item "
                    "SET downstream_service = :canonical "
                    "WHERE downstream_service = :legacy"
                ),
                {"legacy": legacy, "canonical": canonical},
            )
            print(
                "secflow_binary_security_stage_item.downstream_service: "
                f"{legacy} -> {canonical}, updated={result.rowcount}"
            )


if __name__ == "__main__":
    main()
