from __future__ import annotations

from types import SimpleNamespace

from app.models import database


def test_init_database_uses_mysql_advisory_lock(monkeypatch):
    events: list[tuple[str, object]] = []

    class FakeResult:
        def __init__(self, value):
            self._value = value

        def scalar(self):
            return self._value

    class FakeConnection:
        dialect = SimpleNamespace(name="mysql")

        def __enter__(self):
            events.append(("enter", None))
            return self

        def __exit__(self, exc_type, exc, tb):
            events.append(("exit", exc_type))

        def execute(self, stmt, params=None):
            sql = str(stmt)
            if "GET_LOCK" in sql:
                events.append(("get_lock", params["lock_name"]))
                return FakeResult(1)
            if "RELEASE_LOCK" in sql:
                events.append(("release_lock", params["lock_name"]))
                return FakeResult(1)
            events.append(("execute", sql))
            return FakeResult(None)

        def commit(self):
            events.append(("commit", None))

    class FakeEngine:
        dialect = SimpleNamespace(name="mysql")

        def connect(self):
            return FakeConnection()

    fake_engine = FakeEngine()
    monkeypatch.setattr(database, "get_engine", lambda: fake_engine)
    monkeypatch.setattr(database.Base.metadata, "create_all", lambda bind: events.append(("create_all", bind)))
    monkeypatch.setattr(database, "run_auto_migrations", lambda connection=None: events.append(("migrate", connection)))

    database.init_database()

    assert events[0] == ("enter", None)
    assert events[1][0] == "get_lock"
    assert events[2][0] == "create_all"
    assert events[3][0] == "migrate"
    assert events[4] == ("commit", None)
    assert events[5][0] == "release_lock"
