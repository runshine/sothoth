"""组织管理相关API"""

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_super_admin, get_current_user_management_user
from app.model import Department, DepartmentMember, Project, ProjectDepartment, User
from app.rbac import (
    can_access_user_management,
    get_primary_platform_role,
    is_ordinary_admin,
    is_super_admin,
)
from app.schema import (
    DepartmentCreate, DepartmentUpdate, DepartmentResponse,
    DepartmentMemberCreate, DepartmentMemberUpdate, DepartmentMemberResponse,
    ProjectCreate, ProjectUpdate, ProjectResponse, ProjectDetailResponse,
    Message, UserPermissionInfo,
    UserDepartmentProjectListResponse, UserDepartmentProjectResponse
)
from app.service.project import get_project_service, ProjectServiceError

router = APIRouter(prefix="/org", tags=["organization"])

logger = logging.getLogger(__name__)


def log_access_denied(user: User, resource_type: str, resource_id: int, reason: str):
    """记录访问被拒绝的日志"""
    logger.warning(
        f"访问被拒绝 - 用户: {user.username}(ID:{user.id}), "
        f"资源类型: {resource_type}, 资源ID: {resource_id}, "
        f"原因: {reason}"
    )


def is_admin(user: User) -> bool:
    """检查用户是否为管理员"""
    return is_super_admin(user)


def get_user_department_ids(db: Session, user_id: int) -> List[int]:
    """获取用户所属的所有部门ID"""
    memberships = db.query(DepartmentMember.department_id).filter(
        DepartmentMember.user_id == user_id
    ).all()
    return [m.department_id for m in memberships]


def get_all_descendant_ids(db: Session, department_ids: List[int]) -> List[int]:
    """获取所有下级部门ID（递归）"""
    all_descendants = set(department_ids)
    
    def find_children(parent_ids: List[int]):
        children = db.query(Department.id).filter(
            Department.parent_id.in_(parent_ids)
        ).all()
        child_ids = [c.id for c in children]
        if child_ids:
            new_ids = [cid for cid in child_ids if cid not in all_descendants]
            if new_ids:
                all_descendants.update(new_ids)
                find_children(new_ids)
    
    find_children(department_ids)
    return list(all_descendants)


def get_accessible_department_ids(db: Session, user: User) -> List[int]:
    """获取用户可访问的所有部门ID。"""
    if is_super_admin(user):
        return None

    if not is_ordinary_admin(user):
        return []

    user_dept_ids = get_user_department_ids(db, user.id)
    if not user_dept_ids:
        return []

    return get_all_descendant_ids(db, user_dept_ids)


def get_manageable_department_ids(db: Session, user: User) -> List[int]:
    """获取用户可管理的部门ID。普通管理员仅能管理所属部门及下级部门。"""
    if is_super_admin(user):
        return None

    if not is_ordinary_admin(user):
        return []

    user_dept_ids = get_user_department_ids(db, user.id)
    if not user_dept_ids:
        return []

    return get_all_descendant_ids(db, user_dept_ids)


def get_department_structure_manageable_ids(db: Session, user: User) -> List[int]:
    """仅超级管理员可以管理部门结构。"""
    if is_super_admin(user):
        return None
    return []


def can_move_member_between_departments(
    db: Session,
    current_user: User,
    target_member: DepartmentMember,
    new_department_id: int,
) -> tuple[bool, str]:
    """普通管理员仅能移动其部门树内的普通成员。"""
    if is_super_admin(current_user):
        return True, ""

    manageable_ids = get_manageable_department_ids(db, current_user) or []
    if target_member.department_id not in manageable_ids:
        return False, "无权调整该用户的所属部门"

    if new_department_id not in manageable_ids:
        return False, "目标部门不在可管理范围内"

    if target_member.role != "member":
        return False, "普通管理员只能调整普通成员的所属部门"

    return True, ""


def get_project_department_ids(db: Session, project_id: int) -> List[int]:
    """获取项目绑定的部门ID列表。"""
    rows = db.query(ProjectDepartment.department_id).filter(
        ProjectDepartment.project_id == project_id
    ).all()
    return [row.department_id for row in rows]


def get_project_departments(db: Session, project_id: int) -> List[Department]:
    """获取项目绑定的部门列表。"""
    return db.query(Department).join(ProjectDepartment).filter(
        ProjectDepartment.project_id == project_id
    ).all()


def is_department_scope_allowed(allowed_department_ids: Optional[List[int]], target_department_ids: List[int]) -> bool:
    """检查目标部门是否全部在允许范围内。"""
    if allowed_department_ids is None:
        return True

    if not target_department_ids:
        return False

    allowed_id_set = set(allowed_department_ids)
    return all(department_id in allowed_id_set for department_id in target_department_ids)


def can_manage_org_project(
    db: Session,
    current_user: User,
    project: Project,
) -> tuple[bool, str]:
    """普通管理员仅能管理绑定在自己部门树内的项目。"""
    if is_super_admin(current_user):
        return True, ""

    if not is_ordinary_admin(current_user):
        return False, "您没有权限管理项目"

    manageable_ids = get_manageable_department_ids(db, current_user) or []
    project_department_ids = get_project_department_ids(db, project.id)

    if not project_department_ids:
        return False, "普通管理员只能管理已绑定所属部门或下级部门的项目"

    if not is_department_scope_allowed(manageable_ids, project_department_ids):
        return False, "无权管理上级部门或其他部门的项目"

    return True, ""


def validate_project_assignment_scope(
    db: Session,
    current_user: User,
    department_ids: List[int],
    is_public: bool,
) -> tuple[bool, str]:
    """校验项目绑定部门是否在当前用户可管理范围内。"""
    if is_super_admin(current_user):
        return True, ""

    if not is_ordinary_admin(current_user):
        return False, "您没有权限管理项目"

    if is_public:
        return False, "普通管理员只能创建或维护绑定所属部门及下级部门的私有项目"

    if not department_ids:
        return False, "普通管理员必须为项目绑定所属部门或下级部门"

    manageable_ids = get_manageable_department_ids(db, current_user) or []
    if not is_department_scope_allowed(manageable_ids, department_ids):
        return False, "只能选择所属部门及下级部门"

    return True, ""


def build_project_detail_response(db: Session, project: Project) -> ProjectDetailResponse:
    """构建包含部门信息的项目响应。"""
    from app.schema import DepartmentResponse

    departments = get_project_departments(db, project.id)
    return ProjectDetailResponse(
        id=project.id,
        name=project.name,
        description=project.description,
        is_public=project.is_public,
        created_at=project.created_at,
        updated_at=project.updated_at,
        departments=[DepartmentResponse.from_orm(dept) for dept in departments]
    )


def check_circular_reference(db: Session, department_id: int, new_parent_id: int) -> bool:
    """检查是否存在循环引用"""
    visited = set()
    current_id = new_parent_id
    
    while current_id is not None:
        if current_id == department_id:
            return True
        if current_id in visited:
            return True
        visited.add(current_id)
        
        parent_dept = db.query(Department).filter(Department.id == current_id).first()
        if not parent_dept:
            break
        current_id = parent_dept.parent_id
    
    return False


# ============ 部门管理 ============

@router.get("/user-permissions", response_model=UserPermissionInfo)
def get_user_permissions(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_management_user)
):
    """获取当前用户的权限信息"""
    is_user_admin = is_admin(current_user)
    user_dept_ids = get_user_department_ids(db, current_user.id)
    manageable_dept_ids = get_manageable_department_ids(db, current_user)
    dept_structure_ids = get_department_structure_manageable_ids(db, current_user)
    role_names = current_user.get_all_role_names()

    return UserPermissionInfo(
        user_id=current_user.id,
        is_admin=is_user_admin,
        platform_role=get_primary_platform_role(current_user),
        department_ids=user_dept_ids,
        manageable_department_ids=manageable_dept_ids if manageable_dept_ids is not None else [],
        department_structure_manageable_ids=dept_structure_ids if dept_structure_ids is not None else [],
        role_names=role_names,
        can_access_user_management=can_access_user_management(current_user),
        can_manage_users=is_super_admin(current_user),
        can_manage_roles=is_super_admin(current_user),
        can_manage_departments=is_super_admin(current_user),
        can_manage_department_members=is_super_admin(current_user) or is_ordinary_admin(current_user),
        can_manage_org_projects=is_super_admin(current_user) or is_ordinary_admin(current_user),
    )


def get_user_department_info(db: Session, user_id: int) -> tuple[Optional[int], Optional[str]]:
    """
    获取用户的主要部门信息

    Returns:
        (部门ID, 部门名称)
    """
    member = db.query(DepartmentMember).filter(
        DepartmentMember.user_id == user_id
    ).first()

    if not member:
        return None, None

    department = db.query(Department).filter(Department.id == member.department_id).first()
    if not department:
        return None, None

    return department.id, department.name


@router.get("/user-department-projects", response_model=UserDepartmentProjectListResponse)
def get_user_department_projects(
    authorization: str = Header(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_management_user)
):
    """
    获取用户可见的项目列表

    - 公开项目：所有人可见
    - 非公开项目：仅项目归属部门在当前用户可访问部门范围内时可见
    - 返回这些项目的信息，包括归属部门信息
    """
    if authorization is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="缺少认证信息"
        )

    accessible_dept_ids = get_accessible_department_ids(db, current_user)

    try:
        # 调用project服务获取所有项目
        project_service = get_project_service()
        projects_data = project_service.get_all_projects(authorization.replace("Bearer ", ""))
    except ProjectServiceError as e:
        logger.error(f"获取项目列表失败: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"无法获取项目列表: {str(e)}"
        )

    # 筛选项目
    result_projects = []
    for proj in projects_data:
        is_public = proj.get("is_public", False)
        owner_id_str = proj.get("owner_id")
        project_department_id = proj.get("department_id")
        project_department_name = proj.get("department_name")
        can_manage = bool(proj.get("can_manage", False))

        owner_dept_id = None
        owner_dept_name = None
        if owner_id_str:
            try:
                owner_id = int(owner_id_str)
                owner_dept_id, owner_dept_name = get_user_department_info(db, owner_id)
            except (ValueError, TypeError):
                pass

        # 公开项目：所有人可见
        if is_public:
            roles = proj.get("roles", [])
            result_projects.append(UserDepartmentProjectResponse(
                id=proj.get("id"),
                name=proj.get("name"),
                description=proj.get("description"),
                owner_id=owner_id_str or "",
                owner_name=proj.get("owner_name"),
                k8s_namespace=proj.get("k8s_namespace"),
                status=proj.get("status"),
                is_public=is_public,
                department_id=project_department_id,
                department_name=project_department_name,
                can_manage=can_manage,
                created_at=proj.get("created_at"),
                updated_at=proj.get("updated_at"),
                roles=roles,
                owner_department_id=owner_dept_id,
                owner_department_name=owner_dept_name
            ))
        else:
            # 非公开项目：仅项目归属部门在当前用户可访问部门范围内时可见
            effective_department_id = project_department_id or owner_dept_id
            effective_department_name = project_department_name or owner_dept_name

            if effective_department_id is None:
                continue
            if accessible_dept_ids is None or effective_department_id in accessible_dept_ids:
                roles = proj.get("roles", [])
                result_projects.append(UserDepartmentProjectResponse(
                    id=proj.get("id"),
                    name=proj.get("name"),
                    description=proj.get("description"),
                    owner_id=owner_id_str or "",
                    owner_name=proj.get("owner_name"),
                    k8s_namespace=proj.get("k8s_namespace"),
                    status=proj.get("status"),
                    is_public=is_public,
                    department_id=effective_department_id,
                    department_name=effective_department_name,
                    can_manage=can_manage,
                    created_at=proj.get("created_at"),
                    updated_at=proj.get("updated_at"),
                    roles=roles,
                    owner_department_id=owner_dept_id,
                    owner_department_name=owner_dept_name
                ))

    return UserDepartmentProjectListResponse(
        total=len(result_projects),
        projects=result_projects
    )


@router.post("/departments", response_model=DepartmentResponse, status_code=status.HTTP_201_CREATED)
def create_department(
    department: DepartmentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """创建部门。仅超级管理员可用。"""
    # 验证父部门是否存在
    if department.parent_id is not None and department.parent_id != 0:
        parent_dept = db.query(Department).filter(Department.id == department.parent_id).first()
        if not parent_dept:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="父部门不存在"
            )
        
    else:
        department.parent_id = None
    
    # 创建部门
    db_department = Department(
        name=department.name,
        description=department.description,
        parent_id=department.parent_id if department.parent_id != 0 else None
    )
    db.add(db_department)
    db.commit()
    db.refresh(db_department)
    
    logger.info(f"创建部门: 用户{current_user.username}创建了部门{db_department.name}(ID: {db_department.id})")
    
    return db_department


@router.get("/departments", response_model=List[DepartmentResponse])
def get_departments(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_management_user)
):
    """获取部门列表（仅返回用户可访问的部门）"""
    accessible_ids = get_accessible_department_ids(db, current_user)
    
    if accessible_ids is None:
        departments = db.query(Department).all()
    else:
        departments = db.query(Department).filter(Department.id.in_(accessible_ids)).all()
    
    return departments


@router.get("/departments/{department_id}", response_model=DepartmentResponse)
def get_department(
    department_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_management_user)
):
    """获取部门详情"""
    accessible_ids = get_accessible_department_ids(db, current_user)
    
    if accessible_ids is not None and department_id not in accessible_ids:
        log_access_denied(current_user, "部门", department_id, "用户无权访问该部门（非所属部门或下级部门）")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="您没有权限访问该部门"
        )
    
    department = db.query(Department).filter(Department.id == department_id).first()
    if not department:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="部门不存在"
        )
    return department


@router.put("/departments/{department_id}", response_model=DepartmentResponse)
def update_department(
    department_id: int,
    department: DepartmentUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """更新部门信息。仅超级管理员可用。"""
    # 验证部门是否存在
    db_department = db.query(Department).filter(Department.id == department_id).first()
    if not db_department:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="部门不存在"
        )
    
    # 检查用户是否有权限管理该部门
    # 验证父部门是否存在
    if department.parent_id is not None:
        # 不能将自己设置为父部门
        if department.parent_id == department_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="不能将自己设置为父部门"
            )
        
        if department.parent_id != 0:
            parent_dept = db.query(Department).filter(Department.id == department.parent_id).first()
            if not parent_dept:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="父部门不存在"
                )
            
            # 检查循环引用
            if check_circular_reference(db, department_id, department.parent_id):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="不能设置循环引用的父部门，这会形成闭环关系"
                )
    
    # 更新部门信息
    if department.name is not None:
        db_department.name = department.name
    if department.description is not None:
        db_department.description = department.description
    if department.parent_id is not None:
        db_department.parent_id = department.parent_id if department.parent_id != 0 else None
    
    db.commit()
    db.refresh(db_department)
    return db_department


@router.delete("/departments/{department_id}", response_model=Message)
def delete_department(
    department_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """删除部门。仅超级管理员可用。"""
    # 验证部门是否存在
    db_department = db.query(Department).filter(Department.id == department_id).first()
    if not db_department:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="部门不存在"
        )
    
    # 检查是否有子部门
    if db_department.children:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="该部门下有子部门，无法删除"
        )
    
    # 删除部门成员
    db.query(DepartmentMember).filter(DepartmentMember.department_id == department_id).delete()
    
    # 删除部门与项目的关联
    db.query(ProjectDepartment).filter(ProjectDepartment.department_id == department_id).delete()
    
    # 删除部门
    db.delete(db_department)
    db.commit()
    
    return Message(message="部门删除成功")


# ============ 部门成员管理 ============

@router.post("/department-members", response_model=DepartmentMemberResponse, status_code=status.HTTP_201_CREATED)
def add_department_member(
    member: DepartmentMemberCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """添加部门成员。仅超级管理员可用。"""
    # 验证部门是否存在
    department = db.query(Department).filter(Department.id == member.department_id).first()
    if not department:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="部门不存在"
        )
    
    # 验证用户是否存在
    user = db.query(User).filter(User.id == member.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )
    
    # 验证用户是否已经是部门成员
    existing_member = db.query(DepartmentMember).filter(
        DepartmentMember.user_id == member.user_id,
        DepartmentMember.department_id == member.department_id
    ).first()
    if existing_member:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="用户已经是该部门的成员"
        )
    
    # 验证是否已经有组长
    if member.role == "leader":
        existing_leader = db.query(DepartmentMember).filter(
            DepartmentMember.department_id == member.department_id,
            DepartmentMember.role == "leader"
        ).first()
        if existing_leader:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="该部门已经有组长"
            )
    
    # 添加成员
    db_member = DepartmentMember(
        user_id=member.user_id,
        department_id=member.department_id,
        role=member.role
    )
    db.add(db_member)
    db.commit()
    db.refresh(db_member)
    
    logger.info(f"添加部门成员: 用户{current_user.username}将用户{user.username}添加到部门{department.name}，角色: {member.role}")
    
    # 构建响应
    response = DepartmentMemberResponse(
        id=db_member.id,
        user_id=db_member.user_id,
        username=user.username,
        department_id=db_member.department_id,
        department_name=department.name,
        role=db_member.role,
        created_at=db_member.created_at,
        updated_at=db_member.updated_at
    )
    return response


@router.get("/departments/{department_id}/members", response_model=List[DepartmentMemberResponse])
def get_department_members(
    department_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_management_user)
):
    """获取部门成员列表"""
    accessible_ids = get_accessible_department_ids(db, current_user)
    
    if accessible_ids is not None and department_id not in accessible_ids:
        log_access_denied(current_user, "部门成员", department_id, "用户无权访问该部门成员列表")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="您没有权限访问该部门"
        )
    
    # 验证部门是否存在
    department = db.query(Department).filter(Department.id == department_id).first()
    if not department:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="部门不存在"
        )
    
    # 获取部门成员
    members = db.query(DepartmentMember).filter(DepartmentMember.department_id == department_id).all()
    
    # 构建响应
    response = []
    for member in members:
        user = db.query(User).filter(User.id == member.user_id).first()
        if user:
            response.append(DepartmentMemberResponse(
                id=member.id,
                user_id=member.user_id,
                username=user.username,
                department_id=member.department_id,
                department_name=department.name,
                role=member.role,
                created_at=member.created_at,
                updated_at=member.updated_at
            ))
    
    return response


@router.put("/department-members/{member_id}", response_model=DepartmentMemberResponse)
def update_department_member(
    member_id: int,
    member_update: DepartmentMemberUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_management_user)
):
    """更新部门成员。普通管理员仅能在自己部门树内移动普通成员。"""
    # 验证成员是否存在
    db_member = db.query(DepartmentMember).filter(DepartmentMember.id == member_id).first()
    if not db_member:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="部门成员不存在"
        )
    
    if member_update.role is None and member_update.department_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="未提供需要更新的字段"
        )

    old_role = db_member.role

    if member_update.role is not None:
        if not is_super_admin(current_user):
            log_access_denied(current_user, "部门成员角色", db_member.department_id, "普通管理员无权编辑部门成员角色")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="只有超级管理员可以编辑部门成员角色"
            )
        if member_update.role == "leader":
            existing_leader = db.query(DepartmentMember).filter(
                DepartmentMember.department_id == db_member.department_id,
                DepartmentMember.role == "leader"
            ).first()
            if existing_leader and existing_leader.id != member_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="该部门已经有组长"
                )

    if member_update.department_id is not None:
        target_department = db.query(Department).filter(
            Department.id == member_update.department_id
        ).first()
        if not target_department:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="目标部门不存在"
            )

        allowed, error_msg = can_move_member_between_departments(
            db, current_user, db_member, member_update.department_id
        )
        if not allowed:
            log_access_denied(current_user, "部门成员归属", db_member.department_id, error_msg)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=error_msg
            )

        db_member.department_id = member_update.department_id

    if member_update.role is not None:
        db_member.role = member_update.role
    
    db.commit()
    db.refresh(db_member)
    
    # 构建响应
    user = db.query(User).filter(User.id == db_member.user_id).first()
    department = db.query(Department).filter(Department.id == db_member.department_id).first()
    
    logger.info(f"更新部门成员角色: 用户{current_user.username}将部门{department.name}的成员{user.username}角色从{old_role}改为{db_member.role}")
    
    response = DepartmentMemberResponse(
        id=db_member.id,
        user_id=db_member.user_id,
        username=user.username if user else "",
        department_id=db_member.department_id,
        department_name=department.name if department else "",
        role=db_member.role,
        created_at=db_member.created_at,
        updated_at=db_member.updated_at
    )
    return response


@router.delete("/department-members/{member_id}", response_model=Message)
def remove_department_member(
    member_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """移除部门成员。仅超级管理员可用。"""
    # 验证成员是否存在
    db_member = db.query(DepartmentMember).filter(DepartmentMember.id == member_id).first()
    if not db_member:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="部门成员不存在"
        )
    
    # 不允许移除自己
    if db_member.user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="不能移除自己作为部门成员"
        )
    
    # 获取信息用于日志
    user = db.query(User).filter(User.id == db_member.user_id).first()
    department = db.query(Department).filter(Department.id == db_member.department_id).first()
    
    # 删除成员
    db.delete(db_member)
    db.commit()
    
    logger.info(f"移除部门成员: 用户{current_user.username}将用户{user.username if user else '未知'}从部门{department.name if department else '未知'}移除")
    
    return Message(message="成员移除成功")


# ============ 项目管理 ============

@router.post("/projects", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
def create_project(
    project: ProjectCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_management_user)
):
    """创建项目"""
    department_ids = list(dict.fromkeys(project.department_ids or []))

    allowed, error_msg = validate_project_assignment_scope(
        db,
        current_user,
        department_ids,
        project.is_public,
    )
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=error_msg
        )

    for department_id in department_ids:
        department = db.query(Department).filter(Department.id == department_id).first()
        if not department:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"部门不存在: {department_id}"
            )

    # 创建项目
    db_project = Project(
        name=project.name,
        description=project.description,
        is_public=project.is_public
    )
    db.add(db_project)
    db.commit()
    db.refresh(db_project)

    # 绑定部门（如果是私有项目）
    if not project.is_public and department_ids:
        for department_id in department_ids:
            # 创建项目-部门关联
            project_department = ProjectDepartment(
                project_id=db_project.id,
                department_id=department_id
            )
            db.add(project_department)

    db.commit()
    return build_project_detail_response(db, db_project)


@router.get("/projects/by-name/{project_name}", response_model=ProjectDetailResponse)
def get_project_by_name(
    project_name: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_management_user)
):
    """通过项目名称获取项目详情"""
    # 验证项目是否存在
    project = db.query(Project).filter(Project.name == project_name).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="项目不存在"
        )

    allowed, error_msg = can_manage_org_project(db, current_user, project)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=error_msg
        )

    return build_project_detail_response(db, project)


@router.get("/projects", response_model=List[ProjectDetailResponse])
def get_projects(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_management_user)
):
    """获取项目列表"""
    projects = db.query(Project).all()
    
    result = []
    for project in projects:
        allowed, _ = can_manage_org_project(db, current_user, project)
        if allowed:
            result.append(build_project_detail_response(db, project))
    
    return result


@router.get("/projects/{project_id}", response_model=ProjectDetailResponse)
def get_project(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_management_user)
):
    """获取项目详情"""
    # 验证项目是否存在
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="项目不存在"
        )
    
    allowed, error_msg = can_manage_org_project(db, current_user, project)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=error_msg
        )

    return build_project_detail_response(db, project)


@router.put("/projects/{project_id}", response_model=ProjectResponse)
def update_project(
    project_id: int,
    project_update: ProjectUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_management_user)
):
    """更新项目信息"""
    # 验证项目是否存在
    db_project = db.query(Project).filter(Project.id == project_id).first()
    if not db_project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="项目不存在"
        )

    allowed, error_msg = can_manage_org_project(db, current_user, db_project)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=error_msg
        )

    if is_ordinary_admin(current_user) and project_update.is_public:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="普通管理员不能将项目设置为公开项目"
        )
    
    # 更新项目信息
    if project_update.name is not None:
        db_project.name = project_update.name
    if project_update.description is not None:
        db_project.description = project_update.description
    if project_update.is_public is not None:
        db_project.is_public = project_update.is_public
    
    db.commit()
    db.refresh(db_project)
    return db_project


@router.delete("/projects/{project_id}", response_model=Message)
def delete_project(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_management_user)
):
    """删除项目"""
    # 验证项目是否存在
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="项目不存在"
        )

    allowed, error_msg = can_manage_org_project(db, current_user, project)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=error_msg
        )
    
    # 删除项目-部门关联
    db.query(ProjectDepartment).filter(ProjectDepartment.project_id == project_id).delete()
    
    # 删除项目
    db.delete(project)
    db.commit()
    
    return Message(message="项目删除成功")
