"""
项目API路由模块
"""

import hashlib
import logging
import secrets
from datetime import datetime
from typing import Dict, List, Optional, Set

from fastapi import APIRouter, Depends, HTTPException, Header, Query, status
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from app.build_info import build_service_meta
from app.config import get_config
from app.exception import (
    DependencyUnavailableError,
    ForbiddenError,
    InternalError,
    NotFoundError,
    UnauthorizedError,
    ValidationError,
)
from app.model import (
    get_db,
    Department,
    DepartmentMember,
    Product,
    ProductVersion,
    Project,
    ProjectRoleBind,
    Role,
    secflow_user_user_role,
)
from app.schemas import (
    ProductCreate,
    ProductTreeNodeResponse,
    ProductTreeResponse,
    ProductUpdate,
    ProductVersionCreate,
    ProductVersionResponse,
    ProductVersionUpdate,
    ProjectCreate,
    ProjectUpdate,
    ProjectResponse,
    ProjectListResponse,
    ProjectAllListResponse,
    ProjectRoleBindCreate,
    ProjectRoleBindResponse,
    SuccessResponse,
    ProjectResourcesResponse,
    PodLogResponse,
)
from app.service.auth import AuthServiceError, get_auth_service, TokenInvalidError
from app.service.k8s import get_k8s_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/project", tags=["Projects"])

SUPER_ADMIN_ROLE_ID = 1
ORDINARY_ADMIN_ROLE_ID = 2
BOOTSTRAP_SUPER_ADMIN_USER_ID = 1
SUPER_ADMIN_ROLE_NAME = "super_admin"
ORDINARY_ADMIN_ROLE_NAME = "ordinary_admin"


# 健康检查
@router.get("/health")
async def health_check():
    """健康检查接口"""
    return {"status": "ok", "service": "secflow-project-service", **build_service_meta()}


# 就绪检查
@router.get("/ready")
async def ready_check():
    """就绪检查接口"""
    return {"status": "ready", **build_service_meta()}


def generate_project_id(name: str) -> str:
    """
    生成16位MD5项目ID

    Args:
        name: 项目名称

    Returns:
        16位MD5（小写）
    """
    # 使用项目名加时间戳增加随机性
    unique_str = f"{name}_{datetime.utcnow().timestamp()}"
    md5_hash = hashlib.md5(unique_str.encode()).hexdigest()
    return md5_hash[:16]


def normalize_product_code(value: str) -> str:
    return value.strip().lower().replace(" ", "-").replace("/", "-")


def verify_project_permission(
    project: Project,
    user_id: str,
    roles: List[str],
    require_owner: bool = False
) -> bool:
    """
    验证用户对项目的权限

    Args:
        project: 项目对象
        user_id: 用户ID
        roles: 用户角色列表
        require_owner: 是否需要所有者权限

    Returns:
        是否有权限
    """
    # 检查是否为项目所有者
    if project.owner_id == user_id:
        return True

    # 检查项目角色绑定
    for bind in project.role_binds:
        if bind.user_id == user_id:
            if require_owner:
                if bind.role == "owner":
                    return True
            else:
                return True

    return False


def is_machine_token_user(current_user: dict) -> bool:
    return current_user.get("token_type") == "machine"


def is_project_machine_token(current_user: dict, project_id: str) -> bool:
    return (
        is_machine_token_user(current_user)
        and current_user.get("token_scope") == "project"
        and current_user.get("project_id") == project_id
    )


def get_human_user_id(current_user: dict) -> int:
    if is_machine_token_user(current_user):
        raise ForbiddenError("项目级机机Token不允许执行当前用户操作")
    return int(current_user["id"])


def get_product_path(product: Optional[Product]) -> Optional[str]:
    if not product:
        return None
    names: List[str] = []
    current = product
    visited: Set[str] = set()
    while current and current.id not in visited:
        visited.add(current.id)
        names.append(current.name)
        current = current.parent
    return " / ".join(reversed(names))


def ensure_project_admin_user(db: Session, current_user: dict) -> int:
    user_id = get_human_user_id(current_user)
    if is_super_admin(db, user_id) or is_ordinary_admin(db, user_id):
        return user_id

    manageable_exists = db.query(Project.id).filter(Project.status == "active").all()
    for row in manageable_exists:
        project = db.query(Project).options(joinedload(Project.role_binds), joinedload(Project.department)).filter(
            Project.id == row.id,
            Project.status == "active"
        ).first()
        if project and can_manage_project(db, project, user_id):
            return user_id

    raise ForbiddenError("仅项目管理员可以维护产品目录")


def get_active_product(db: Session, product_id: str) -> Product:
    product = db.query(Product).options(joinedload(Product.children), joinedload(Product.versions)).filter(
        Product.id == product_id,
        Product.status == "active",
    ).first()
    if not product:
        raise NotFoundError("产品", product_id)
    return product


def get_active_product_version(db: Session, version_id: str) -> ProductVersion:
    version = db.query(ProductVersion).options(
        joinedload(ProductVersion.product).joinedload(Product.parent)
    ).filter(
        ProductVersion.id == version_id,
        ProductVersion.status == "active",
    ).first()
    if not version:
        raise NotFoundError("产品版本", version_id)
    return version


def ensure_leaf_product(db: Session, product: Product):
    active_children = db.query(Product.id).filter(
        Product.parent_id == product.id,
        Product.status == "active",
    ).first()
    if active_children:
        raise ValidationError("只有叶子产品可以创建版本")


def validate_product_parent(db: Session, parent_id: Optional[str], product_id: Optional[str] = None) -> Optional[Product]:
    if not parent_id:
        return None
    parent = get_active_product(db, parent_id)
    if product_id and parent.id == product_id:
        raise ValidationError("产品不能将自己设为父节点")
    current = parent.parent
    visited: Set[str] = {parent.id}
    while current:
        if current.id == product_id:
            raise ValidationError("不能将产品移动到自己的子节点下")
        if current.id in visited:
            break
        visited.add(current.id)
        current = current.parent
    return parent


def validate_project_product_version(db: Session, product_version_id: Optional[str], required: bool = False) -> Optional[ProductVersion]:
    if not product_version_id:
        if required:
            raise ValidationError("请选择产品版本")
        return None
    version = get_active_product_version(db, product_version_id)
    ensure_leaf_product(db, version.product)
    return version


def make_product_version_response(db: Session, version: ProductVersion) -> ProductVersionResponse:
    project_count = db.query(Project.id).filter(
        Project.product_version_id == version.id,
        Project.status == "active",
    ).count()
    return ProductVersionResponse(
        id=version.id,
        product_id=version.product_id,
        version=version.version,
        name=version.name,
        description=version.description,
        status=version.status,
        project_count=project_count,
        created_at=version.created_at,
        updated_at=version.updated_at,
    )


def build_product_tree(db: Session) -> ProductTreeResponse:
    products = db.query(Product).options(
        joinedload(Product.children),
        joinedload(Product.versions),
        joinedload(Product.parent),
    ).filter(Product.status == "active").all()
    versions = db.query(ProductVersion).options(joinedload(ProductVersion.product)).filter(
        ProductVersion.status == "active"
    ).all()

    versions_by_product: Dict[str, List[ProductVersion]] = {}
    for version in versions:
        versions_by_product.setdefault(version.product_id, []).append(version)
    for items in versions_by_product.values():
        items.sort(key=lambda item: (item.version, item.name or ""))

    products_by_id = {product.id: product for product in products}
    children_map: Dict[Optional[str], List[Product]] = {}
    for product in products:
        children_map.setdefault(product.parent_id, []).append(product)
    for children in children_map.values():
        children.sort(key=lambda item: (item.sort_order, item.name))

    project_counts = {
        row[0]: row[1]
        for row in db.query(Project.product_version_id, func.count(Project.id)).filter(
            Project.status == "active",
            Project.product_version_id.isnot(None),
        ).group_by(Project.product_version_id).all()
    }

    def build_node(product: Product) -> ProductTreeNodeResponse:
        child_nodes = [build_node(child) for child in children_map.get(product.id, [])]
        version_responses = [
            ProductVersionResponse(
                id=version.id,
                product_id=version.product_id,
                version=version.version,
                name=version.name,
                description=version.description,
                status=version.status,
                project_count=project_counts.get(version.id, 0),
                created_at=version.created_at,
                updated_at=version.updated_at,
            )
            for version in versions_by_product.get(product.id, [])
        ]
        project_count = sum(item.project_count for item in version_responses) + sum(child.project_count for child in child_nodes)
        return ProductTreeNodeResponse(
            id=product.id,
            name=product.name,
            code=product.code,
            parent_id=product.parent_id,
            description=product.description,
            sort_order=product.sort_order,
            status=product.status,
            is_leaf=len(child_nodes) == 0,
            project_count=project_count,
            created_at=product.created_at,
            updated_at=product.updated_at,
            children=child_nodes,
            versions=version_responses,
        )

    root_nodes = [build_node(product) for product in children_map.get(None, []) if product.id in products_by_id]
    return ProductTreeResponse(total=len(products), products=root_nodes)


def get_project_with_permission(
    db: Session,
    project_id: str,
    current_user: dict,
    require_manage: bool = False,
) -> Project:
    project = db.query(Project).options(joinedload(Project.role_binds), joinedload(Project.department)).filter(
        Project.id == project_id,
        Project.status == "active"
    ).first()

    if not project:
        raise NotFoundError("项目", project_id)

    # 机机Token（项目级或全局）均允许访问项目，供微服务间调用使用
    if is_machine_token_user(current_user):
        return project

    user_id = get_human_user_id(current_user)
    allowed = can_manage_project(db, project, user_id) if require_manage else can_view_project(db, project, user_id)
    if not allowed:
        if require_manage:
            raise ForbiddenError("只有归属部门管理员或其上级部门管理员可以执行此操作")
        raise ForbiddenError("无权访问此项目")

    return project


def get_user_department_ids(db: Session, user_id: int) -> List[int]:
    """获取用户所属部门。"""
    rows = db.query(DepartmentMember.department_id).filter(
        DepartmentMember.user_id == user_id
    ).all()
    return [row.department_id for row in rows]


def get_all_descendant_department_ids(db: Session, department_ids: List[int]) -> List[int]:
    """获取部门及其全部下级部门。"""
    all_ids = set(department_ids)
    pending = list(department_ids)

    while pending:
        child_rows = db.query(Department.id).filter(Department.parent_id.in_(pending)).all()
        child_ids = [row.id for row in child_rows if row.id not in all_ids]
        if not child_ids:
            break
        all_ids.update(child_ids)
        pending = child_ids

    return list(all_ids)


def get_primary_platform_role(db: Session, user_id: int) -> str:
    """直接从数据库解析平台角色。"""
    if user_id == BOOTSTRAP_SUPER_ADMIN_USER_ID:
        return SUPER_ADMIN_ROLE_NAME

    bound_roles = db.query(Role).join(
        secflow_user_user_role, Role.id == secflow_user_user_role.c.role_id
    ).filter(
        secflow_user_user_role.c.user_id == user_id
    ).all()

    for role in bound_roles:
        if role.id == SUPER_ADMIN_ROLE_ID or role.name == SUPER_ADMIN_ROLE_NAME:
            return SUPER_ADMIN_ROLE_NAME

    for role in bound_roles:
        if role.id == ORDINARY_ADMIN_ROLE_ID or role.name == ORDINARY_ADMIN_ROLE_NAME:
            return ORDINARY_ADMIN_ROLE_NAME

    return "ordinary_user"


def is_super_admin(db: Session, user_id: int) -> bool:
    return get_primary_platform_role(db, user_id) == SUPER_ADMIN_ROLE_NAME


def is_ordinary_admin(db: Session, user_id: int) -> bool:
    return get_primary_platform_role(db, user_id) == ORDINARY_ADMIN_ROLE_NAME


def get_visible_department_ids(db: Session, user_id: int) -> Set[int]:
    """用户可见的私有项目部门范围 = 自身部门及其全部下级部门。"""
    department_ids = get_user_department_ids(db, user_id)
    if not department_ids:
        return set()
    return set(get_all_descendant_department_ids(db, department_ids))


def get_manageable_department_ids(db: Session, user_id: int) -> Optional[Set[int]]:
    """可管理的项目部门范围。"""
    if is_super_admin(db, user_id):
        return None

    if not is_ordinary_admin(db, user_id):
        return set()

    department_ids = get_user_department_ids(db, user_id)
    if not department_ids:
        return set()

    return set(get_all_descendant_department_ids(db, department_ids))


def validate_project_department_scope(
    db: Session,
    user_id: int,
    department_id: Optional[int],
) -> Optional[int]:
    """校验当前用户是否可以将项目绑定到目标部门。"""
    if department_id is not None:
        department = db.query(Department).filter(Department.id == department_id).first()
        if not department:
            raise ValidationError(f"归属部门不存在: {department_id}")

    if is_super_admin(db, user_id):
        if department_id is not None:
            return department_id
        user_departments = get_user_department_ids(db, user_id)
        return user_departments[0] if user_departments else None

    user_departments = get_user_department_ids(db, user_id)
    default_department_id = user_departments[0] if user_departments else None
    target_department_id = department_id if department_id is not None else default_department_id

    if target_department_id is None:
        raise ValidationError("请先为当前用户绑定所属部门，再创建或维护项目")

    if is_ordinary_admin(db, user_id):
        manageable_department_ids = get_manageable_department_ids(db, user_id) or set()
        if target_department_id not in manageable_department_ids:
            raise ForbiddenError("只能维护所属部门及下级部门的项目")
        return target_department_id

    if target_department_id not in set(user_departments):
        raise ForbiddenError("普通用户只能创建或归属到自己所在部门的项目")

    return target_department_id


def can_view_project(db: Session, project: Project, user_id: int) -> bool:
    """按部门树和公开性校验项目可见性。"""
    if is_super_admin(db, user_id):
        return True

    if project.is_public:
        return True

    if project.department_id is not None:
        return project.department_id in get_visible_department_ids(db, user_id)

    return verify_project_permission(project, str(user_id), [], require_owner=False)


def can_manage_project(db: Session, project: Project, user_id: int) -> bool:
    """仅当前部门管理员及其上级部门管理员可编辑/删除。"""
    if is_super_admin(db, user_id):
        return True

    manageable_department_ids = get_manageable_department_ids(db, user_id)
    if project.department_id is not None:
        return manageable_department_ids is not None and project.department_id in manageable_department_ids

    return verify_project_permission(project, str(user_id), [], require_owner=True)


async def get_current_user(
    authorization: Optional[str] = Header(None),
    project_id: Optional[str] = None
) -> dict:
    """
    获取当前用户（认证）

    Args:
        authorization: Authorization header

    Returns:
        用户信息
    """
    if not authorization:
        raise UnauthorizedError("缺少Authorization头")

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise UnauthorizedError("Authorization格式错误，应为: Bearer <token>")

    token = parts[1]

    try:
        auth_service = get_auth_service()
        user = await auth_service.validate_token_async(token, project_id=project_id)
        return user
    except TokenInvalidError:
        raise UnauthorizedError("Token无效或已过期")
    except AuthServiceError as exc:
        raise DependencyUnavailableError("认证服务暂时不可用", details={"reason": str(exc)})


async def get_current_user_sync(
    authorization: Optional[str] = Header(None),
    project_id: Optional[str] = None
) -> dict:
    """
    获取当前用户（同步版本，用于非async函数）
    """
    if not authorization:
        raise UnauthorizedError("缺少Authorization头")

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise UnauthorizedError("Authorization格式错误，应为: Bearer <token>")

    token = parts[1]

    try:
        auth_service = get_auth_service()
        user = auth_service.validate_token(token, project_id=project_id)
        return user
    except TokenInvalidError:
        raise UnauthorizedError("Token无效或已过期")
    except AuthServiceError as exc:
        raise DependencyUnavailableError("认证服务暂时不可用", details={"reason": str(exc)})


def make_project_response(
    project: Project,
    roles: List[ProjectRoleBindResponse],
    can_manage: bool = False,
) -> ProjectResponse:
    """构建项目响应"""
    product_version = getattr(project, "product_version", None)
    product = product_version.product if product_version else None
    return ProjectResponse(
        id=project.id,
        name=project.name,
        description=project.description,
        owner_id=project.owner_id,
        owner_name=project.owner_name,
        k8s_namespace=project.k8s_namespace,
        status=project.status,
        is_public=project.is_public if project.is_public is not None else False,
        department_id=project.department_id,
        department_name=project.department.name if getattr(project, "department", None) else None,
        product_id=product.id if product else None,
        product_name=product.name if product else None,
        product_path=get_product_path(product),
        product_version_id=product_version.id if product_version else None,
        product_version_name=product_version.name if product_version else None,
        product_version=product_version.version if product_version else None,
        can_manage=can_manage,
        created_at=project.created_at,
        updated_at=project.updated_at,
        roles=roles
    )


@router.get("/products/tree", response_model=ProductTreeResponse)
async def get_product_tree(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    get_human_user_id(current_user)
    return build_product_tree(db)


@router.post("/products", response_model=ProductTreeNodeResponse, status_code=status.HTTP_201_CREATED)
async def create_product(
    payload: ProductCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    ensure_project_admin_user(db, current_user)
    code = normalize_product_code(payload.code)
    existing = db.query(Product).filter(Product.code == code, Product.status == "active").first()
    if existing:
        raise ValidationError(f"产品编码已存在: {payload.code}")
    parent = validate_product_parent(db, payload.parent_id)
    product = Product(
        id=generate_project_id(f"product_{payload.name}_{payload.code}"),
        name=payload.name.strip(),
        code=code,
        parent_id=parent.id if parent else None,
        description=payload.description,
        sort_order=payload.sort_order,
        status="active",
    )
    db.add(product)
    db.commit()
    db.refresh(product)
    tree = build_product_tree(db)
    return next(node for node in _flatten_product_tree(tree.products) if node.id == product.id)


def _flatten_product_tree(nodes: List[ProductTreeNodeResponse]) -> List[ProductTreeNodeResponse]:
    result: List[ProductTreeNodeResponse] = []
    for node in nodes:
        result.append(node)
        result.extend(_flatten_product_tree(node.children))
    return result


@router.put("/products/{product_id}", response_model=ProductTreeNodeResponse)
async def update_product(
    product_id: str,
    payload: ProductUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    ensure_project_admin_user(db, current_user)
    product = get_active_product(db, product_id)
    if payload.code is not None:
        code = normalize_product_code(payload.code)
        existing = db.query(Product).filter(
            Product.code == code,
            Product.id != product_id,
            Product.status == "active",
        ).first()
        if existing:
            raise ValidationError(f"产品编码已存在: {payload.code}")
        product.code = code
    if payload.name is not None:
        product.name = payload.name.strip()
    if payload.description is not None:
        product.description = payload.description
    if payload.sort_order is not None:
        product.sort_order = payload.sort_order
    if payload.parent_id is not None:
        parent = validate_product_parent(db, payload.parent_id or None, product_id=product_id)
        product.parent_id = parent.id if parent else None
    db.commit()
    tree = build_product_tree(db)
    return next(node for node in _flatten_product_tree(tree.products) if node.id == product_id)


@router.delete("/products/{product_id}", response_model=SuccessResponse)
async def delete_product(
    product_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    ensure_project_admin_user(db, current_user)
    product = get_active_product(db, product_id)
    active_child = db.query(Product.id).filter(Product.parent_id == product_id, Product.status == "active").first()
    if active_child:
        raise ValidationError("存在子产品，无法删除")
    active_version = db.query(ProductVersion.id).filter(ProductVersion.product_id == product_id, ProductVersion.status == "active").first()
    if active_version:
        raise ValidationError("存在产品版本，无法删除")
    product.status = "deleted"
    db.commit()
    return SuccessResponse(message=f"产品 {product.name} 已删除")


@router.post("/products/{product_id}/versions", response_model=ProductVersionResponse, status_code=status.HTTP_201_CREATED)
async def create_product_version(
    product_id: str,
    payload: ProductVersionCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    ensure_project_admin_user(db, current_user)
    product = get_active_product(db, product_id)
    ensure_leaf_product(db, product)
    existing = db.query(ProductVersion).filter(
        ProductVersion.product_id == product_id,
        ProductVersion.version == payload.version.strip(),
        ProductVersion.status == "active",
    ).first()
    if existing:
        raise ValidationError(f"产品版本已存在: {payload.version}")
    version = ProductVersion(
        id=generate_project_id(f"product_version_{product_id}_{payload.version}"),
        product_id=product_id,
        version=payload.version.strip(),
        name=(payload.name or "").strip() or None,
        description=payload.description,
        status="active",
    )
    db.add(version)
    db.commit()
    db.refresh(version)
    return make_product_version_response(db, version)


@router.put("/products/versions/{version_id}", response_model=ProductVersionResponse)
async def update_product_version(
    version_id: str,
    payload: ProductVersionUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    ensure_project_admin_user(db, current_user)
    version = get_active_product_version(db, version_id)
    if payload.version is not None:
        existing = db.query(ProductVersion).filter(
            ProductVersion.product_id == version.product_id,
            ProductVersion.version == payload.version.strip(),
            ProductVersion.id != version_id,
            ProductVersion.status == "active",
        ).first()
        if existing:
            raise ValidationError(f"产品版本已存在: {payload.version}")
        version.version = payload.version.strip()
    if payload.name is not None:
        version.name = payload.name.strip() or None
    if payload.description is not None:
        version.description = payload.description
    db.commit()
    db.refresh(version)
    return make_product_version_response(db, version)


@router.delete("/products/versions/{version_id}", response_model=SuccessResponse)
async def delete_product_version(
    version_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    ensure_project_admin_user(db, current_user)
    version = get_active_product_version(db, version_id)
    project_exists = db.query(Project.id).filter(
        Project.product_version_id == version_id,
        Project.status == "active",
    ).first()
    if project_exists:
        raise ValidationError("存在关联项目，无法删除产品版本")
    version.status = "deleted"
    db.commit()
    return SuccessResponse(message=f"产品版本 {version.version} 已删除")


# ============ 项目接口 ============

@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    project_data: ProjectCreate,
    authorization: Optional[str] = Header(None),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    创建项目

    - 项目名称必填
    - 自动生成16位MD5项目ID
    - 自动创建K8S Namespace
    - 自动将创建者设为项目所有者
    - 项目权限以归属部门为主，公开项目对所有人可见
    """
    user_id = get_human_user_id(current_user)

    # 检查项目名是否重复
    existing = db.query(Project).filter(
        Project.name == project_data.name,
        Project.status == "active"
    ).first()
    if existing:
        raise ValidationError(f"项目名称已存在: {project_data.name}")

    # 生成项目ID
    project_id = generate_project_id(project_data.name)
    product_version = validate_project_product_version(db, project_data.product_version_id, required=True)

    # 生成K8S Namespace名称
    k8s_client = get_k8s_client()
    k8s_namespace = k8s_client.generate_namespace_name(project_id)
    department_id = validate_project_department_scope(db, user_id, project_data.department_id)

    # 创建项目
    project = Project(
        id=project_id,
        name=project_data.name,
        description=project_data.description,
        owner_id=str(user_id),
        owner_name=current_user.get("username"),
        k8s_namespace=k8s_namespace,
        status="active",
        is_public=project_data.is_public,
        department_id=department_id,
        product_version_id=product_version.id,
    )
    db.add(project)

    # 创建者角色绑定
    role_bind = ProjectRoleBind(
        id=generate_project_id(f"{project_id}_{user_id}"),
        project_id=project_id,
        user_id=str(user_id),
        role="owner",
    )
    db.add(role_bind)

    # 创建K8S Namespace（不依赖项目已提交）
    if not k8s_client.create_namespace(project_id):
        logger.warning(f"创建K8S Namespace失败: {project_id}")
        # 回滚数据库事务
        db.rollback()
        raise HTTPException(status_code=500, detail="创建K8S Namespace失败")

    # 先提交项目数据，再创建依赖project_id校验的TLS Secret
    db.commit()
    db.refresh(project)
    db.refresh(role_bind)

    # 创建TLS Secret（platform-k8s 会校验 project_id 对应项目存在）
    tls_success, tls_error = k8s_client.create_tls_secret(project_id, authorization=authorization)
    if not tls_success:
        logger.error(f"创建TLS Secret失败: {project_id}, 错误: {tls_error}")
        # 删除已创建的Namespace
        k8s_client.delete_namespace(project_id, force=True)
        # 补偿删除已提交的项目与角色绑定，避免脏数据
        try:
            db.query(ProjectRoleBind).filter(ProjectRoleBind.project_id == project_id).delete(synchronize_session=False)
            db.query(Project).filter(Project.id == project_id).delete(synchronize_session=False)
            db.commit()
        except Exception as cleanup_error:
            db.rollback()
            logger.error(f"创建TLS Secret失败后的数据库补偿清理失败: {project_id}, 错误: {cleanup_error}")
        raise HTTPException(status_code=500, detail=f"创建TLS Secret失败: {tls_error}")

    try:
        get_auth_service().ensure_project_token(project_id=project_id, project_name=project.name)
    except Exception as exc:
        logger.error(f"自动创建项目级机机Token失败: {project_id}, 错误: {exc}")
        k8s_client.delete_namespace(project_id, force=True)
        try:
            db.query(ProjectRoleBind).filter(ProjectRoleBind.project_id == project_id).delete(synchronize_session=False)
            db.query(Project).filter(Project.id == project_id).delete(synchronize_session=False)
            db.commit()
        except Exception as cleanup_error:
            db.rollback()
            logger.error(f"项目级机机Token创建失败后的数据库补偿清理失败: {project_id}, 错误: {cleanup_error}")
        raise HTTPException(status_code=500, detail="创建项目级SDK Token失败")

    return make_project_response(project, [ProjectRoleBindResponse(
        user_id=role_bind.user_id,
        role=role_bind.role,
        created_at=role_bind.created_at
    )], can_manage=can_manage_project(db, project, user_id))


@router.get("", response_model=ProjectListResponse)
async def list_projects(
    product_id: Optional[str] = Query(None, description="按产品筛选"),
    product_version_id: Optional[str] = Query(None, description="按产品版本筛选"),
    unassigned_product_version: Optional[bool] = Query(None, description="筛选未绑定产品版本的项目"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    查询项目列表

    - 返回用户有权访问的所有项目
    - 公开项目：所有登录用户可见
    - 私有项目：仅归属部门及其上级部门可见
    """
    user_id = int(current_user["id"])

    query = db.query(Project).options(
        joinedload(Project.role_binds),
        joinedload(Project.department),
        joinedload(Project.product_version).joinedload(ProductVersion.product).joinedload(Product.parent),
    ).filter(Project.status == "active")
    if product_version_id:
        query = query.filter(Project.product_version_id == product_version_id)
    if unassigned_product_version is True:
        query = query.filter(Project.product_version_id.is_(None))
    if product_id:
        query = query.join(Project.product_version, isouter=True).filter(ProductVersion.product_id == product_id)
    projects = query.all()

    result = []
    for project in projects:
        if not can_view_project(db, project, user_id):
            continue
        roles = [ProjectRoleBindResponse(
            user_id=bind.user_id,
            role=bind.role,
            created_at=bind.created_at
        ) for bind in project.role_binds]
        result.append(make_project_response(project, roles, can_manage=can_manage_project(db, project, user_id)))

    return ProjectListResponse(total=len(result), projects=result)


@router.get("/list", response_model=ProjectAllListResponse)
async def list_all_projects(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    查询所有项目列表

    - 返回所有项目（不考虑用户角色），只需登录即可访问
    """
    # 查询所有项目
    user_id = int(current_user["id"])

    projects = db.query(Project).options(
        joinedload(Project.role_binds),
        joinedload(Project.department),
        joinedload(Project.product_version).joinedload(ProductVersion.product).joinedload(Product.parent),
    ).filter(
        Project.status == "active"
    ).all()

    result = []
    for project in projects:
        roles = [ProjectRoleBindResponse(
            user_id=bind.user_id,
            role=bind.role,
            created_at=bind.created_at
        ) for bind in project.role_binds]
        result.append(make_project_response(project, roles, can_manage=can_manage_project(db, project, user_id)))

    return ProjectAllListResponse(data=result)


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    查询单个项目

    - 需要对项目有访问权限
    """
    project = get_project_with_permission(db, project_id, current_user, require_manage=False)

    roles = [ProjectRoleBindResponse(
        user_id=bind.user_id,
        role=bind.role,
        created_at=bind.created_at
    ) for bind in project.role_binds]

    can_manage = is_machine_token_user(current_user) or is_project_machine_token(current_user, project_id)
    if not can_manage and not is_machine_token_user(current_user):
        can_manage = can_manage_project(db, project, int(current_user["id"]))

    return make_project_response(project, roles, can_manage=can_manage)


@router.post("/{project_id}/tls-secret/rebuild", response_model=SuccessResponse)
async def rebuild_project_tls_secret(
    project_id: str,
    authorization: Optional[str] = Header(None),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    重建项目 Ingress TLS Secret

    - 仅归属部门管理员或其上级部门管理员可操作
    - 行为与创建项目时的 TLS Secret 同步一致
    """
    get_project_with_permission(db, project_id, current_user, require_manage=True)

    k8s_client = get_k8s_client()
    tls_success, tls_error = k8s_client.create_tls_secret(project_id, authorization=authorization)
    if not tls_success:
        logger.error(f"重建TLS Secret失败: {project_id}, 错误: {tls_error}")
        raise HTTPException(status_code=500, detail=f"重建TLS Secret失败: {tls_error}")

    return SuccessResponse(message=f"项目 {project_id} Ingress TLS 重建成功")


@router.put("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: str,
    project_data: ProjectUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    修改项目

    - 仅归属部门管理员或其上级部门管理员可修改
    """
    project = get_project_with_permission(db, project_id, current_user, require_manage=True)
    user_id = None if is_machine_token_user(current_user) else int(current_user["id"])

    # 更新字段
    if project_data.name is not None:
        # 检查名称重复
        existing = db.query(Project).filter(
            Project.name == project_data.name,
            Project.id != project_id,
            Project.status == "active"
        ).first()
        if existing:
            raise ValidationError(f"项目名称已存在: {project_data.name}")
        project.name = project_data.name

    if project_data.description is not None:
        project.description = project_data.description

    if project_data.k8s_namespace is not None:
        project.k8s_namespace = project_data.k8s_namespace

    if project_data.is_public is not None:
        project.is_public = project_data.is_public

    if project_data.department_id is not None:
        if user_id is None:
            raise ForbiddenError("项目级机机Token不允许修改项目归属部门")
        project.department_id = validate_project_department_scope(db, user_id, project_data.department_id)

    if project_data.product_version_id is not None:
        version = validate_project_product_version(db, project_data.product_version_id, required=False)
        project.product_version_id = version.id if version else None

    db.commit()
    db.refresh(project)

    roles_list = [ProjectRoleBindResponse(
        user_id=bind.user_id,
        role=bind.role,
        created_at=bind.created_at
    ) for bind in project.role_binds]

    return make_project_response(project, roles_list, can_manage=True)


@router.delete("/{project_id}", response_model=SuccessResponse)
async def delete_project(
    project_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    删除项目

    - 仅归属部门管理员或其上级部门管理员可删除
    - 同时删除K8S Namespace及所有资源
    """
    project = get_project_with_permission(db, project_id, current_user, require_manage=True)

    # 软删除项目
    project.status = "deleted"
    db.commit()

    # 删除K8S Namespace
    k8s_client = get_k8s_client()
    k8s_client.delete_namespace(project_id, force=True)

    return SuccessResponse(message=f"项目 {project_id} 已删除")

# ============ 项目角色管理 ============

@router.post("/{project_id}/role", response_model=ProjectRoleBindResponse)
async def bind_role(
    project_id: str,
    role_data: ProjectRoleBindCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    为项目绑定用户角色

    - 需要项目管理权限
    """
    project = get_project_with_permission(db, project_id, current_user, require_manage=True)

    # 检查是否已存在绑定
    existing = db.query(ProjectRoleBind).filter(
        ProjectRoleBind.project_id == project_id,
        ProjectRoleBind.user_id == role_data.user_id
    ).first()

    if existing:
        # 更新现有绑定
        existing.role = role_data.role
        db.commit()
        return ProjectRoleBindResponse(
            user_id=existing.user_id,
            role=existing.role,
            created_at=existing.created_at
        )

    # 创建新绑定
    role_bind = ProjectRoleBind(
        id=generate_project_id(f"{project_id}_{role_data.user_id}"),
        project_id=project_id,
        user_id=role_data.user_id,
        role=role_data.role,
    )
    db.add(role_bind)
    db.commit()

    return ProjectRoleBindResponse(
        user_id=role_bind.user_id,
        role=role_bind.role,
        created_at=role_bind.created_at
    )


@router.delete("/{project_id}/role", response_model=SuccessResponse)
async def unbind_role(
    project_id: str,
    user_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    解除项目用户角色绑定

    - 需要项目管理权限
    - 不能解除所有者自己的角色
    """
    project = get_project_with_permission(db, project_id, current_user, require_manage=True)

    # 不能解除所有者
    if user_id == project.owner_id:
        raise ValidationError("不能解除项目所有者的角色")

    # 查找并删除绑定
    role_bind = db.query(ProjectRoleBind).filter(
        ProjectRoleBind.project_id == project_id,
        ProjectRoleBind.user_id == user_id
    ).first()

    if role_bind:
        db.delete(role_bind)
        db.commit()

    return SuccessResponse(message=f"已解除用户 {user_id} 的角色绑定")

# ============ K8S Namespace相关接口 ============

@router.get("/{project_id}/namespace")
async def get_project_namespace(
    project_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    获取项目关联的K8S Namespace状态
    """
    project = get_project_with_permission(db, project_id, current_user, require_manage=False)

    k8s_client = get_k8s_client()
    status = k8s_client.get_namespace_status(project_id)

    if not status:
        raise NotFoundError("Namespace", f"secflow_{project_id}")

    return {
        "namespace": status,
        "k8s_namespace": project.k8s_namespace
    }


@router.get("/{project_id}/resources", response_model=ProjectResourcesResponse)
async def get_project_resources(
    project_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    获取项目关联的K8S Namespace下的所有资源

    包括：Pod、Service、ConfigMap、Secret、Deployment、StatefulSet、PVC、Ingress等
    """
    project = get_project_with_permission(db, project_id, current_user, require_manage=False)

    k8s_client = get_k8s_client()

    # 获取Namespace下资源列表
    resources = k8s_client.list_namespace_resources(project_id)

    return ProjectResourcesResponse(
        namespace=project.k8s_namespace or k8s_client.generate_namespace_name(project_id),
        pods=resources.get("pods", []),
        services=resources.get("services", []),
        configmaps=resources.get("configmaps", []),
        secrets=resources.get("secrets", []),
        deployments=resources.get("deployments", []),
        statefulsets=resources.get("statefulsets", []),
        pvcs=resources.get("pvcs", []),
        ingresses=resources.get("ingresses", []),
    )


@router.get("/{project_id}/pods/{pod_name}/logs", response_model=PodLogResponse)
async def get_pod_logs(
    project_id: str,
    pod_name: str,
    tail_lines: int = Query(100, description="返回日志行数", ge=1, le=10000),
    container: Optional[str] = Query(None, description="容器名称（多容器Pod时需要）"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    获取指定Pod的日志

    - 通过K8S API获取与项目关联的K8S Namespace下，指定名称的Pod的运行日志
    - 支持设置返回行数tail_lines，默认100行
    - 多容器Pod可通过container参数指定容器
    """
    project = get_project_with_permission(db, project_id, current_user, require_manage=False)

    k8s_client = get_k8s_client()
    k8s_namespace = project.k8s_namespace or k8s_client.generate_namespace_name(project_id)

    # 获取日志
    logs = k8s_client.get_pod_logs(project_id, pod_name, container=container, tail_lines=tail_lines)

    if logs is None:
        raise NotFoundError("Pod日志", f"{pod_name} in namespace {k8s_namespace}")

    return PodLogResponse(
        pod_name=pod_name,
        namespace=k8s_namespace,
        logs=logs,
        container=container
    )


@router.delete("/{project_id}/pods/{pod_name}", response_model=SuccessResponse)
async def delete_pod(
    project_id: str,
    pod_name: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    删除指定Pod

    - 删除项目关联Namespace下的指定Pod
    """
    project = get_project_with_permission(db, project_id, current_user, require_manage=True)

    k8s_client = get_k8s_client()

    # 删除Pod
    if not k8s_client.delete_pod(project_id, pod_name):
        raise HTTPException(status_code=500, detail=f"删除Pod {pod_name} 失败")

    return SuccessResponse(message=f"Pod {pod_name} 已删除")


@router.delete("/{project_id}/pvcs/{pvc_name}", response_model=SuccessResponse)
async def delete_pvc(
    project_id: str,
    pvc_name: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    删除指定PVC

    - 删除前会检查PVC是否被任何Pod使用
    - 如PVC正在被使用，将返回409错误
    """
    project = get_project_with_permission(db, project_id, current_user, require_manage=True)

    k8s_client = get_k8s_client()

    # 删除PVC（检查是否被使用）
    success, error_msg = k8s_client.delete_pvc(project_id, pvc_name)

    if not success:
        from fastapi import HTTPException
        raise HTTPException(status_code=409, detail=error_msg)

    return SuccessResponse(message=f"PVC {pvc_name} 已删除")
