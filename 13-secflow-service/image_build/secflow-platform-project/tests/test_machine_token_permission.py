from types import SimpleNamespace

from app.api.projects import get_project_with_permission


class _FakeQuery:
    def __init__(self, project_obj):
        self._project_obj = project_obj

    def options(self, *args, **kwargs):
        return self

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self._project_obj


class _FakeDB:
    def __init__(self, project_obj):
        self._project_obj = project_obj

    def query(self, *args, **kwargs):
        return _FakeQuery(self._project_obj)


def test_get_project_with_permission_allows_global_machine_token():
    project = SimpleNamespace(id="p1", status="active")
    db = _FakeDB(project)
    current_user = {
        "token_type": "machine",
        "token_scope": "global",
        "project_id": None,
    }

    result = get_project_with_permission(db, "p1", current_user, require_manage=False)

    assert result is project
