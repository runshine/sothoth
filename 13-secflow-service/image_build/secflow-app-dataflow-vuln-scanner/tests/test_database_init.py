from __future__ import annotations

from types import SimpleNamespace

from sqlalchemy.exc import OperationalError

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
    monkeypatch.setattr(database, "_mysql_core_tables_exist", lambda connection: False)
    monkeypatch.setattr(database.Base.metadata, "create_all", lambda bind: events.append(("create_all", bind)))
    monkeypatch.setattr(database, "run_auto_migrations", lambda connection=None: events.append(("migrate", connection)))

    database.init_database()

    assert events[0] == ("enter", None)
    assert events[1][0] == "get_lock"
    assert events[2][0] == "create_all"
    assert events[3][0] == "migrate"
    assert events[4] == ("commit", None)
    assert events[5][0] == "release_lock"


def test_init_database_skips_create_all_when_mysql_tables_exist(monkeypatch):
    events: list[str] = []

    class FakeResult:
        def __init__(self, value):
            self._value = value

        def scalar(self):
            return self._value

    class FakeConnection:
        dialect = SimpleNamespace(name="mysql")

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

        def execute(self, stmt, params=None):
            sql = str(stmt)
            if "GET_LOCK" in sql or "RELEASE_LOCK" in sql:
                return FakeResult(1)
            return FakeResult(None)

        def commit(self):
            events.append("commit")

    class FakeEngine:
        dialect = SimpleNamespace(name="mysql")

        def connect(self):
            return FakeConnection()

    fake_engine = FakeEngine()
    monkeypatch.setattr(database, "get_engine", lambda: fake_engine)
    monkeypatch.setattr(database, "_mysql_core_tables_exist", lambda connection: True)
    monkeypatch.setattr(database.Base.metadata, "create_all", lambda bind: events.append("create_all"))
    monkeypatch.setattr(database, "run_auto_migrations", lambda connection=None: events.append("migrate"))

    database.init_database()

    assert events == ["migrate", "commit"]


def test_mysql_core_tables_include_runtime_config_and_reservation():
    class FakeInspector:
        def get_table_names(self):
            return [
                database.WorkflowDefinition.__tablename__,
                database.WorkflowDefinitionVersion.__tablename__,
                database.TriggerTask.__tablename__,
                database.WorkflowExecution.__tablename__,
                database.RunIndex.__tablename__,
                database.SchedulerWorker.__tablename__,
                database.SchedulerWorkerSlotReservation.__tablename__,
                database.ServiceRuntimeConfig.__tablename__,
            ]

    class FakeConnection:
        pass

    original_inspect = database.inspect
    try:
        database.inspect = lambda connection: FakeInspector()
        assert database._mysql_core_tables_exist(FakeConnection()) is True
    finally:
        database.inspect = original_inspect


def test_init_database_retries_mysql_concurrent_ddl(monkeypatch):
    attempts: list[str] = []

    class FakeOrig(Exception):
        def __init__(self):
            self.args = (1684, "Table is being modified by concurrent DDL statement")

    def fake_init():
        attempts.append("call")
        if attempts.count("call") < 3:
            raise OperationalError("DESCRIBE test", None, FakeOrig())

    fake_engine = SimpleNamespace(dialect=SimpleNamespace(name="mysql"))
    monkeypatch.setattr(database, "get_engine", lambda: fake_engine)
    monkeypatch.setattr(database, "_init_database_with_mysql_lock", fake_init)
    monkeypatch.setattr(database.time, "sleep", lambda seconds: attempts.append(f"sleep:{seconds}"))

    database.init_database()

    assert attempts == ["call", "sleep:1.0", "call", "sleep:2.0", "call"]
