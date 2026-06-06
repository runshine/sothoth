import asyncio
from datetime import datetime
from types import SimpleNamespace

import pytest
from pydantic import ValidationError as PydanticValidationError

from app.api import projects as projects_api
from app.exception import ValidationError
from app.model import Product, ProductVersion, Project
from app.schemas import ProductCreate, ProductVersionCreate, ProjectCreate


class _FakeQuery:
    def __init__(self, all_result=None, first_result=None):
        self._all_result = all_result if all_result is not None else []
        self._first_result = first_result

    def options(self, *args, **kwargs):
        return self

    def filter(self, *args, **kwargs):
        return self

    def group_by(self, *args, **kwargs):
        return self

    def all(self):
        return self._all_result

    def first(self):
        return self._first_result


class _TreeDB:
    def __init__(self, products, versions, project_counts):
        self._products = products
        self._versions = versions
        self._project_counts = project_counts

    def query(self, *args, **kwargs):
        del kwargs
        if len(args) == 1 and args[0] is Product:
            return _FakeQuery(all_result=self._products)
        if len(args) == 1 and args[0] is ProductVersion:
            return _FakeQuery(all_result=self._versions)
        if len(args) == 2:
            return _FakeQuery(all_result=self._project_counts)
        raise AssertionError(f"unexpected query args: {args}")


class _LeafCheckDB:
    def __init__(self, has_child):
        self._has_child = has_child

    def query(self, *args, **kwargs):
        del args, kwargs
        return _FakeQuery(first_result=object() if self._has_child else None)


class _DeleteVersionDB:
    def __init__(self, has_project):
        self._has_project = has_project
        self.committed = False

    def query(self, *args, **kwargs):
        del args, kwargs
        return _FakeQuery(first_result=object() if self._has_project else None)

    def commit(self):
        self.committed = True


class _DeleteProductDB:
    def __init__(self, has_child=False, has_version=False):
        self._has_child = has_child
        self._has_version = has_version
        self.committed = False

    def query(self, *args, **kwargs):
        del kwargs
        if args and args[0] is Product.id:
            return _FakeQuery(first_result=object() if self._has_child else None)
        if args and args[0] is ProductVersion.id:
            return _FakeQuery(first_result=object() if self._has_version else None)
        raise AssertionError(f"unexpected query args: {args}")

    def commit(self):
        self.committed = True


class _CreateEntityDB:
    def __init__(self, existing=None):
        self._existing = existing
        self.added = []
        self.committed = False
        self.refreshed = []

    def query(self, *args, **kwargs):
        del kwargs
        return _FakeQuery(first_result=self._existing)

    def add(self, obj):
        if isinstance(obj, Project) and self._version and obj.product_version_id == self._version.id:
            obj.product_version = self._version
        if getattr(obj, "created_at", None) is None:
            obj.created_at = datetime.utcnow()
        if getattr(obj, "updated_at", None) is None:
            obj.updated_at = datetime.utcnow()
        self.added.append(obj)

    def commit(self):
        self.committed = True

    def refresh(self, obj):
        self.refreshed.append(obj)


class _ProjectCreateDB:
    def __init__(self, existing_project=None, version=None):
        self._existing_project = existing_project
        self._version = version
        self.added = []
        self.committed = False
        self.refreshed = []

    def query(self, model, *args, **kwargs):
        del args, kwargs
        if model is Project:
            return _FakeQuery(first_result=self._existing_project)
        if model is ProductVersion:
            return _FakeQuery(first_result=self._version)
        if model is Product:
            return _FakeQuery(first_result=None)
        return _FakeQuery(first_result=None)

    def add(self, obj):
        if getattr(obj, "created_at", None) is None:
            obj.created_at = datetime.utcnow()
        if getattr(obj, "updated_at", None) is None:
            obj.updated_at = datetime.utcnow()
        self.added.append(obj)

    def commit(self):
        self.committed = True

    def refresh(self, obj):
        self.refreshed.append(obj)


def _make_product(product_id: str, name: str, code: str, parent=None):
    product = Product(
        id=product_id,
        name=name,
        code=code,
        parent_id=parent.id if parent else None,
        description=None,
        sort_order=0,
        status="active",
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    product.parent = parent
    product.children = []
    product.versions = []
    if parent:
        parent.children.append(product)
    return product


def _make_version(version_id: str, product: Product, version: str):
    item = ProductVersion(
        id=version_id,
        product_id=product.id,
        version=version,
        name=None,
        description=None,
        status="active",
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    item.product = product
    product.versions.append(item)
    return item


def test_build_product_tree_returns_nested_products_with_versions_and_counts():
    root = _make_product("p-root", "产品中心", "root")
    child = _make_product("p-child", "网关", "gateway", parent=root)
    version = _make_version("v1", child, "1.0.0")
    db = _TreeDB(
        products=[root, child],
        versions=[version],
        project_counts=[("v1", 3)],
    )

    tree = projects_api.build_product_tree(db)

    assert tree.total == 2
    assert len(tree.products) == 1
    assert tree.products[0].name == "产品中心"
    assert tree.products[0].project_count == 3
    assert len(tree.products[0].children) == 1
    assert tree.products[0].children[0].name == "网关"
    assert tree.products[0].children[0].is_leaf is True
    assert tree.products[0].children[0].versions[0].version == "1.0.0"
    assert tree.products[0].children[0].versions[0].project_count == 3


def test_validate_project_product_version_requires_value_when_creating_project():
    with pytest.raises(ValidationError) as exc_info:
        projects_api.validate_project_product_version(db=None, product_version_id=None, required=True)

    assert exc_info.value.message == "请选择产品版本"


def test_ensure_leaf_product_rejects_non_leaf_product():
    product = _make_product("p-parent", "平台产品", "platform")
    db = _LeafCheckDB(has_child=True)

    with pytest.raises(ValidationError) as exc_info:
        projects_api.ensure_leaf_product(db, product)

    assert exc_info.value.message == "只有叶子产品可以创建版本"


def test_delete_product_rejects_when_active_child_exists(monkeypatch):
    product = _make_product("p-parent", "平台产品", "platform")
    db = _DeleteProductDB(has_child=True, has_version=False)
    monkeypatch.setattr(projects_api, "ensure_project_admin_user", lambda db, current_user: 1)
    monkeypatch.setattr(projects_api, "get_active_product", lambda db, product_id: product)

    with pytest.raises(ValidationError) as exc_info:
        asyncio.run(projects_api.delete_product("p-parent", current_user={"id": "1"}, db=db))

    assert exc_info.value.message == "存在子产品，无法删除"
    assert db.committed is False


def test_delete_product_version_rejects_when_project_exists(monkeypatch):
    product = _make_product("p-leaf", "网关", "gateway")
    version = _make_version("v1", product, "1.0.0")
    db = _DeleteVersionDB(has_project=True)
    monkeypatch.setattr(projects_api, "ensure_project_admin_user", lambda db, current_user: 1)
    monkeypatch.setattr(projects_api, "get_active_product_version", lambda db, version_id: version)

    with pytest.raises(ValidationError) as exc_info:
        asyncio.run(projects_api.delete_product_version("v1", current_user={"id": "1"}, db=db))

    assert exc_info.value.message == "存在关联项目，无法删除产品版本"
    assert db.committed is False


def test_create_product_rejects_duplicate_code(monkeypatch):
    db = _CreateEntityDB(existing=object())
    monkeypatch.setattr(projects_api, "ensure_project_admin_user", lambda db, current_user: 1)

    with pytest.raises(ValidationError) as exc_info:
        asyncio.run(projects_api.create_product(
            ProductCreate(name="平台产品", code="platform", parent_id=None, description=None, sort_order=0),
            current_user={"id": "1", "username": "admin"},
            db=db,
        ))

    assert exc_info.value.message == "产品编码已存在: platform"


def test_create_product_version_requires_leaf_product(monkeypatch):
    product = _make_product("p-parent", "平台产品", "platform")
    db = _CreateEntityDB(existing=None)
    monkeypatch.setattr(projects_api, "ensure_project_admin_user", lambda db, current_user: 1)
    monkeypatch.setattr(projects_api, "get_active_product", lambda db, product_id: product)
    monkeypatch.setattr(projects_api, "ensure_leaf_product", lambda db, product: (_ for _ in ()).throw(ValidationError("只有叶子产品可以创建版本")))

    with pytest.raises(ValidationError) as exc_info:
        asyncio.run(projects_api.create_product_version(
            "p-parent",
            ProductVersionCreate(version="1.0.0", name=None, description=None),
            current_user={"id": "1"},
            db=db,
        ))

    assert exc_info.value.message == "只有叶子产品可以创建版本"


def test_create_project_requires_product_version(monkeypatch):
    db = _ProjectCreateDB(existing_project=None, version=None)
    monkeypatch.setattr(projects_api, "get_human_user_id", lambda current_user: 1)
    monkeypatch.setattr(projects_api, "get_k8s_client", lambda: SimpleNamespace(
        generate_namespace_name=lambda project_id: f"ns-{project_id}",
        create_namespace=lambda project_id: True,
        delete_namespace=lambda project_id, force=False: None,
        create_tls_secret=lambda project_id, authorization=None: (True, None),
    ))
    monkeypatch.setattr(projects_api, "validate_project_department_scope", lambda db, user_id, department_id: department_id)
    monkeypatch.setattr(projects_api, "get_auth_service", lambda: SimpleNamespace(ensure_project_token=lambda project_id, project_name: None))

    with pytest.raises(PydanticValidationError):
        ProjectCreate(name="demo", description=None, k8s_namespace=None, is_public=False, department_id=None, product_version_id="")


def test_create_project_success_persists_product_version(monkeypatch):
    product = _make_product("p-leaf", "网关", "gateway")
    version = _make_version("v1", product, "1.0.0")
    db = _ProjectCreateDB(existing_project=None, version=version)
    monkeypatch.setattr(projects_api, "get_human_user_id", lambda current_user: 1)
    monkeypatch.setattr(projects_api, "get_k8s_client", lambda: SimpleNamespace(
        generate_namespace_name=lambda project_id: f"ns-{project_id}",
        create_namespace=lambda project_id: True,
        delete_namespace=lambda project_id, force=False: None,
        create_tls_secret=lambda project_id, authorization=None: (True, None),
    ))
    monkeypatch.setattr(projects_api, "validate_project_department_scope", lambda db, user_id, department_id: department_id)
    monkeypatch.setattr(projects_api, "get_auth_service", lambda: SimpleNamespace(ensure_project_token=lambda project_id, project_name: None))
    monkeypatch.setattr(projects_api, "can_manage_project", lambda db, project, user_id: True)
    captured = {}
    monkeypatch.setattr(projects_api, "make_project_response", lambda project, roles, can_manage: captured.update({
        "project": project,
        "roles": roles,
        "can_manage": can_manage,
    }) or SimpleNamespace(product_version_id=project.product_version_id))

    result = asyncio.run(projects_api.create_project(
        ProjectCreate(name="demo", description="d", k8s_namespace=None, is_public=False, department_id=1, product_version_id="v1"),
        authorization="Bearer token",
        current_user={"id": "1", "username": "admin"},
        db=db,
    ))

    assert db.committed is True
    assert db.added[0].product_version_id == version.id
    assert captured["project"].product_version_id == version.id
    assert result.product_version_id == version.id
