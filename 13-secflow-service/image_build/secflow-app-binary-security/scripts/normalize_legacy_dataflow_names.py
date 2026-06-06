from __future__ import annotations

import sys
from pathlib import Path

from sqlalchemy import bindparam, text

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

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


def _dedupe_stage_item_rows(conn, table_name: str, legacy: str) -> int:
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


def _dedupe_stage_run_rows(conn, table_name: str, legacy: str) -> int:
    rows = conn.execute(
        text(
            f"SELECT id, task_id, sequence_no, created_at "
            f"FROM {table_name} WHERE stage_name = :legacy ORDER BY task_id, sequence_no, created_at, id"
        ),
        {"legacy": legacy},
    ).mappings().all()
    if not rows:
        return 0
    keep_by_task: dict[str, str] = {}
    delete_ids: list[str] = []
    for row in rows:
        task_id = str(row["task_id"] or "").strip()
        if task_id in keep_by_task:
            delete_ids.append(str(row["id"]))
            continue
        keep_by_task[task_id] = str(row["id"])
    if delete_ids:
        delete_stmt = text(f"DELETE FROM {table_name} WHERE id IN :ids").bindparams(
            bindparam("ids", expanding=True)
        )
        result = conn.execute(delete_stmt, {"ids": delete_ids})
        return int(result.rowcount or 0)
    return 0


def _delete_stage_item_collisions(conn) -> int:
    canonical_rows = conn.execute(
        text(
            "SELECT task_id, item_identity_key FROM secflow_binary_security_stage_item "
            "WHERE stage_name = :canonical"
        ),
        {"canonical": "dataflow_vuln_scan"},
    ).mappings().all()
    if not canonical_rows:
        return 0
    canonical_keys = {
        (str(row["task_id"] or "").strip(), str(row["item_identity_key"] or "").strip())
        for row in canonical_rows
    }
    legacy_rows = conn.execute(
        text(
            "SELECT id, task_id, item_identity_key FROM secflow_binary_security_stage_item "
            "WHERE stage_name IN :legacy"
        ).bindparams(bindparam("legacy", expanding=True)),
        {"legacy": list(STAGE_RENAMES.keys())},
    ).mappings().all()
    delete_ids = [
        str(row["id"])
        for row in legacy_rows
        if (str(row["task_id"] or "").strip(), str(row["item_identity_key"] or "").strip()) in canonical_keys
    ]
    if not delete_ids:
        return 0
    result = conn.execute(
        text("DELETE FROM secflow_binary_security_stage_item WHERE id IN :ids").bindparams(
            bindparam("ids", expanding=True)
        ),
        {"ids": delete_ids},
    )
    return int(result.rowcount or 0)


def main() -> None:
    engine = get_engine()
    with engine.begin() as conn:
        deleted_collisions = _delete_stage_item_collisions(conn)
        if deleted_collisions:
            print(f"secflow_binary_security_stage_item: deleted canonical collisions={deleted_collisions}")
        for table_name in STAGE_TABLES:
            for legacy, canonical in STAGE_RENAMES.items():
                if table_name == "secflow_binary_security_stage_item":
                    deleted = _dedupe_stage_item_rows(conn, table_name, legacy)
                elif table_name == "secflow_binary_security_stage_run":
                    deleted = _dedupe_stage_run_rows(conn, table_name, legacy)
                else:
                    deleted = 0
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
