from __future__ import annotations

from sqlalchemy import bindparam, text

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


def _dedupe_stage_rows(conn, table_name: str, legacy: str) -> int:
    rows = conn.execute(
        text(
            f"SELECT id, task_id, item_key, parent_key, item_identity_key, created_at "
            f"FROM {table_name} WHERE stage_name = :legacy ORDER BY task_id, item_identity_key, created_at, id"
        ),
        {"legacy": legacy},
    ).mappings().all()
    if not rows:
        return 0
    keep_by_key: dict[tuple[str, str, str, str], str] = {}
    delete_ids: list[str] = []
    for row in rows:
        identity_key = str(row["item_identity_key"] or "").strip()
        if not identity_key:
            identity_key = "::".join(
                [
                    str(row["task_id"] or "").strip(),
                    str(row["item_key"] or "").strip(),
                    str(row["parent_key"] or "").strip(),
                ]
            )
        dedupe_key = (
            str(row["task_id"] or "").strip(),
            identity_key,
            str(row["item_key"] or "").strip(),
            str(row["parent_key"] or "").strip(),
        )
        if dedupe_key in keep_by_key:
            delete_ids.append(str(row["id"]))
            continue
        keep_by_key[dedupe_key] = str(row["id"])
    if delete_ids:
        delete_stmt = text(f"DELETE FROM {table_name} WHERE id IN :ids").bindparams(
            bindparam("ids", expanding=True)
        )
        result = conn.execute(delete_stmt, {"ids": delete_ids})
        return int(result.rowcount or 0)
    return 0


def main() -> None:
    engine = get_engine()
    with engine.begin() as conn:
        for table_name in STAGE_TABLES:
            for legacy, canonical in STAGE_RENAMES.items():
                deleted = _dedupe_stage_rows(conn, table_name, legacy)
                result = conn.execute(
                    text(f"UPDATE {table_name} SET stage_name = :canonical WHERE stage_name = :legacy"),
                    {"legacy": legacy, "canonical": canonical},
                )
                print(
                    f"{table_name}.stage_name: {legacy} -> {canonical}, "
                    f"deleted_duplicates={deleted}, updated={result.rowcount}"
                )

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
