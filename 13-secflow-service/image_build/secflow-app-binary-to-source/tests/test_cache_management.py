from __future__ import annotations

from pathlib import Path
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api import tasks as tasks_api
from app.exception import NotFoundError
from app.model import B2SAnalysisCache, Base
from app.schemas import B2SCacheBatchDeleteRequest, TokenUser
from app.service.cache_service import B2SCacheService


@pytest.fixture()
def db_session(tmp_path: Path):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    try:
        yield session, tmp_path
    finally:
        session.close()


def _make_cache_row(
    root: Path,
    *,
    cache_key: str,
    project_id: str,
    task_id: str,
    item_id: str,
    hit_count: int = 0,
    status: str = "ready",
    with_dir: bool = True,
) -> B2SAnalysisCache:
    cache_dir = root / cache_key
    output_dir = cache_dir / "output"
    if with_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        (cache_dir / "READY").write_text("ready", encoding="utf-8")
        (cache_dir / "manifest.json").write_text('{"sharing_mode":"shared"}', encoding="utf-8")
        (output_dir / "result.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    row = B2SAnalysisCache(
        id=f"id-{item_id}",
        cache_key=cache_key,
        file_sha256=cache_key.split("_")[0],
        file_size=1234,
        elf_basename=f"{item_id}.elf",
        analysis_signature=cache_key.split("_")[-1],
        status=status,
        source_project_id=project_id,
        source_task_id=task_id,
        source_item_id=item_id,
        canonical_output_dir=str(output_dir),
        canonical_input_path=f"/data/files/{project_id}/input/{item_id}.elf",
        generated_files_json='["result.c"]',
        metadata_json='{"source_metadata":{"sharing_mode":"shared"}}',
        hit_count=hit_count,
    )
    return row


def test_list_cache_entries_filters_and_summarizes(db_session, monkeypatch):
    session, tmp_path = db_session
    service = B2SCacheService()
    monkeypatch.setattr("app.service.cache_service.get_config", lambda: SimpleNamespace(cache=SimpleNamespace(enabled=True, root_dir=str(tmp_path), materialize_mode="copy")))
    row_a = _make_cache_row(tmp_path, cache_key=f"{'a' * 64}_fast", project_id="p1", task_id="t1", item_id="i1", hit_count=3)
    row_b = _make_cache_row(tmp_path, cache_key=f"{'b' * 64}_deep", project_id="p2", task_id="t2", item_id="i2", hit_count=0)
    session.add_all([row_a, row_b])
    session.commit()

    payload = service.list_cache_entries(session, project_id="p1", include_all_projects=True, mode="fast", has_hits="hit")

    assert payload["total"] == 1
    assert payload["items"][0]["cache_key"] == row_a.cache_key
    assert payload["summary"]["visible_entries"] == 1
    assert payload["summary"]["current_project_entries"] == 1
    assert payload["summary"]["fast_entries"] == 1
    assert payload["summary"]["deep_entries"] == 0
    assert payload["summary"]["total_hit_count"] == 3


def test_get_cache_entry_detail_returns_manifest_and_flags(db_session, monkeypatch):
    session, tmp_path = db_session
    service = B2SCacheService()
    monkeypatch.setattr("app.service.cache_service.get_config", lambda: SimpleNamespace(cache=SimpleNamespace(enabled=True, root_dir=str(tmp_path), materialize_mode="copy")))
    row = _make_cache_row(tmp_path, cache_key=f"{'c' * 64}_deep", project_id="p1", task_id="t1", item_id="i1", hit_count=1)
    session.add(row)
    session.commit()

    detail = service.get_cache_entry_detail(session, row.cache_key)

    assert detail is not None
    assert detail["manifest"]["sharing_mode"] == "shared"
    assert detail["cache_dir_exists"] is True
    assert detail["manifest_exists"] is True
    assert detail["output_dir_exists"] is True
    assert detail["generated_files"] == ["result.c"]


def test_delete_cache_entry_removes_directory_and_db_record(db_session, monkeypatch):
    session, tmp_path = db_session
    service = B2SCacheService()
    monkeypatch.setattr("app.service.cache_service.get_config", lambda: SimpleNamespace(cache=SimpleNamespace(enabled=True, root_dir=str(tmp_path), materialize_mode="copy")))
    row = _make_cache_row(tmp_path, cache_key=f"{'d' * 64}_fast", project_id="p1", task_id="t1", item_id="i1", hit_count=1)
    session.add(row)
    session.commit()

    result = service.delete_cache_entry(session, row.cache_key)

    assert result.deleted is True
    assert result.status == "deleted"
    assert not (tmp_path / row.cache_key).exists()
    assert session.query(B2SAnalysisCache).filter(B2SAnalysisCache.cache_key == row.cache_key).first() is None


def test_delete_cache_entry_cleans_orphan_record(db_session, monkeypatch):
    session, tmp_path = db_session
    service = B2SCacheService()
    monkeypatch.setattr("app.service.cache_service.get_config", lambda: SimpleNamespace(cache=SimpleNamespace(enabled=True, root_dir=str(tmp_path), materialize_mode="copy")))
    row = _make_cache_row(tmp_path, cache_key=f"{'e' * 64}_fast", project_id="p1", task_id="t1", item_id="i1", hit_count=0, with_dir=False)
    session.add(row)
    session.commit()

    result = service.delete_cache_entry(session, row.cache_key)

    assert result.deleted is True
    assert "孤儿" in (result.message or "")
    assert session.query(B2SAnalysisCache).filter(B2SAnalysisCache.cache_key == row.cache_key).first() is None


@pytest.mark.asyncio
async def test_cache_routes_support_list_detail_and_batch_delete(db_session, monkeypatch):
    session, tmp_path = db_session
    service = B2SCacheService()
    monkeypatch.setattr("app.service.cache_service.get_config", lambda: SimpleNamespace(cache=SimpleNamespace(enabled=True, root_dir=str(tmp_path), materialize_mode="copy")))
    monkeypatch.setattr(tasks_api, "get_cache_service", lambda: service)
    user = TokenUser(user_id="u1", username="tester", token_type="user")
    row_a = _make_cache_row(tmp_path, cache_key=f"{'f' * 64}_fast", project_id="p1", task_id="t1", item_id="i1", hit_count=1)
    row_b = _make_cache_row(tmp_path, cache_key=f"{'1' * 64}_deep", project_id="p2", task_id="t2", item_id="i2", hit_count=0)
    session.add_all([row_a, row_b])
    session.commit()

    listing = await tasks_api.list_b2s_cache(
        "p1",
        include_all_projects=False,
        _=user,
        db=session,
    )
    assert listing.total == 1
    assert listing.items[0].cache_key == row_a.cache_key

    detail = await tasks_api.get_b2s_cache_detail("p1", row_a.cache_key, _=user, db=session)
    assert detail.cache_key == row_a.cache_key

    batch = await tasks_api.batch_delete_b2s_cache_entries(
        "p1",
        payload=B2SCacheBatchDeleteRequest(cache_keys=[row_a.cache_key, "bad-key"]),
        _=user,
        db=session,
    )
    assert batch.deleted_count == 1
    assert batch.failed_count == 1
    assert any(item.status == "invalid_key" for item in batch.results)

    with pytest.raises(NotFoundError):
        await tasks_api.get_b2s_cache_detail("p1", row_a.cache_key, _=user, db=session)
