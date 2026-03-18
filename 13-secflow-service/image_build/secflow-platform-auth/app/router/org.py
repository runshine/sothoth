"""组织管理相关API"""

import logging
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user
from app.model import User, Department, DepartmentMember, Project, ProjectDepartment
from app.schema import (
    DepartmentCreate, DepartmentUpdate, DepartmentResponse,
    DepartmentMemberCreate, DepartmentMemberUpdate, DepartmentMemberResponse,
    ProjectCreate, ProjectUpdate, ProjectResponse, ProjectDetailResponse,
    ProjectDepartmentBindRequest, Message, UserPermissionInfo
)

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
    role_names = user.get_all_role_names()
    return "admin" in role_names or "管理员" in role_names


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
    """获取用户可访问的所有部门ID（用户所属部门及其下级部门）- 用于查看权限"""
    if is_admin(user):
        return None
    
    user_dept_ids = get_user_department_ids(db, user.id)
    if not user_dept_ids:
        return []
    
    return get_all_descendant_ids(db, user_dept_ids)


def get_manageable_department_ids(db: Session, user: User) -> List[int]:
    """获取用户可管理的部门ID（用户作为组长或副组长的部门及其下级部门）- 用于部门成员管理权限"""
    if is_admin(user):
        return None
    
    leader_memberships = db.query(DepartmentMember.department_id).filter(
        DepartmentMember.user_id == user.id,
        DepartmentMember.role.in_(["leader", "vice_leader"])
    ).all()
    leader_dept_ids = [m.department_id for m in leader_memberships]
    
    if not leader_dept_ids:
        return []
    
    return get_all_descendant_ids(db, leader_dept_ids)


def get_department_structure_manageable_ids(db: Session, user: User) -> List[int]:
    """获取用户可管理部门结构的部门ID（仅组长）- 用于部门结构管理权限"""
    if is_admin(user):
        return None
    
    leader_memberships = db.query(DepartmentMember.department_id).filter(
        DepartmentMember.user_id == user.id,
        DepartmentMember.role == "leader"
    ).all()
    leader_dept_ids = [m.department_id for m in leader_memberships]
    
    if not leader_dept_ids:
        return []
    
    return get_all_descendant_ids(db, leader_dept_ids)


def is_department_leader(db: Session, user: User, department_id: int) -> bool:
    """检查用户是否为指定部门的组长或副组长，或上级部门的组长"""
    if is_admin(user):
        return True
    
    # 检查用户是否是目标部门的组长或副组长
    member = db.query(DepartmentMember).filter(
        DepartmentMember.user_id == user.id,
        DepartmentMember.department_id == department_id,
        DepartmentMember.role.in_(["leader", "vice_leader"])
    ).first()
    if member:
        return True
    
    # 检查用户是否是上级部门的组长
    manageable_ids = get_manageable_department_ids(db, user)
    if manageable_ids is not None and department_id in manageable_ids:
        return True
    
    return False


def get_user_role_in_department(db: Session, user: User, department_id: int) -> str | None:
    """获取用户在指定部门的角色（包括上级部门组长的情况）"""
    # 首先检查用户是否是目标部门的直接成员
    member = db.query(DepartmentMember).filter(
        DepartmentMember.user_id == user.id,
        DepartmentMember.department_id == department_id
    ).first()
    if member:
        return member.role
    
    # 检查用户是否是上级部门的组长
    # 获取用户作为组长的所有部门
    leader_memberships = db.query(DepartmentMember.department_id).filter(
        DepartmentMember.user_id == user.id,
        DepartmentMember.role == "leader"
    ).all()
    leader_dept_ids = [m.department_id for m in leader_memberships]
    
    if leader_dept_ids:
        # 获取这些部门的所有下级部门
        descendant_ids = get_all_descendant_ids(db, leader_dept_ids)
        if department_id in descendant_ids:
            return "leader"  # 上级部门组长视为组长权限
    
    return None


def can_manage_member(db: Session, current_user: User, target_member: DepartmentMember) -> tuple[bool, str]:
    """检查用户是否可以管理目标成员"""
    if is_admin(current_user):
        return True, ""
    
    current_user_role = get_user_role_in_department(db, current_user, target_member.department_id)
    if not current_user_role:
        return False, "您不是该部门的成员"
    
    role_hierarchy = {"leader": 3, "vice_leader": 2, "member": 1}
    current_level = role_hierarchy.get(current_user_role, 0)
    target_level = role_hierarchy.get(target_member.role, 0)
    
    if current_level <= target_level:
        role_names = {"leader": "组长", "vice_leader": "副组长", "member": "成员"}
        target_role_name = role_names.get(target_member.role, "该成员")
        return False, f"您无权管理{target_role_name}"
    
    return True, ""


def can_edit_role(db: Session, current_user: User, department_id: int) -> bool:
    """检查用户是否可以编辑角色（管理员或组长，包括上级部门组长）"""
    if is_admin(current_user):
        return True
    
    # 检查用户是否是目标部门的直接组长
    member = db.query(DepartmentMember).filter(
        DepartmentMember.user_id == current_user.id,
        DepartmentMember.department_id == department_id,
        DepartmentMember.role == "leader"
    ).first()
    if member:
        return True
    
    # 检查用户是否是上级部门的组长
    leader_memberships = db.query(DepartmentMember.department_id).filter(
        DepartmentMember.user_id == current_user.id,
        DepartmentMember.role == "leader"
    ).all()
    leader_dept_ids = [m.department_id for m in leader_memberships]
    
    if leader_dept_ids:
        # 获取这些部门的所有下级部门
        descendant_ids = get_all_descendant_ids(db, leader_dept_ids)
        if department_id in descendant_ids:
            return True
    
    return False


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
    current_user: User = Depends(get_current_user)
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
        department_ids=user_dept_ids,
        manageable_department_ids=manageable_dept_ids if manageable_dept_ids is not None else [],
        department_structure_manageable_ids=dept_structure_ids if dept_structure_ids is not None else [],
        role_names=role_names
    )


@router.post("/departments", response_model=DepartmentResponse, status_code=status.HTTP_201_CREATED)
def create_department(
    department: DepartmentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """创建部门（管理员或组长可用）"""
    # 验证父部门是否存在
    if department.parent_id is not None and department.parent_id != 0:
        parent_dept = db.query(Department).filter(Department.id == department.parent_id).first()
        if not parent_dept:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="父部门不存在"
            )
        
        # 检查用户是否有权限在父部门下创建子部门
        manageable_ids = get_department_structure_manageable_ids(db, current_user)
        if manageable_ids is not None and department.parent_id not in manageable_ids:
            log_access_denied(current_user, "部门", department.parent_id, "用户无权在该部门下创建子部门")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="您没有权限在该部门下创建子部门"
            )
    else:
        # 创建顶级部门需要管理员权限
        if not is_admin(current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="只有管理员可以创建顶级部门"
            )
    
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
    current_user: User = Depends(get_current_user)
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
    current_user: User = Depends(get_current_user)
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
    current_user: User = Depends(get_current_user)
):
    """更新部门信息（管理员或组长可用）"""
    # 验证部门是否存在
    db_department = db.query(Department).filter(Department.id == department_id).first()
    if not db_department:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="部门不存在"
        )
    
    # 检查用户是否有权限管理该部门
    manageable_ids = get_department_structure_manageable_ids(db, current_user)
    if manageable_ids is not None and department_id not in manageable_ids:
        log_access_denied(current_user, "部门", department_id, "用户无权更新该部门信息")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="您没有权限更新该部门信息"
        )
    
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
    current_user: User = Depends(get_current_user)
):
    """删除部门（管理员或组长可用）"""
    # 验证部门是否存在
    db_department = db.query(Department).filter(Department.id == department_id).first()
    if not db_department:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="部门不存在"
        )
    
    # 检查用户是否有权限管理该部门
    manageable_ids = get_department_structure_manageable_ids(db, current_user)
    if manageable_ids is not None and department_id not in manageable_ids:
        log_access_denied(current_user, "部门", department_id, "用户无权删除该部门")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="您没有权限删除该部门"
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
    current_user: User = Depends(get_current_user)
):
    """添加部门成员（管理员或部门组长/副组长可用）"""
    # 验证部门是否存在
    department = db.query(Department).filter(Department.id == member.department_id).first()
    if not department:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="部门不存在"
        )
    
    # 验证权限：管理员或部门组长/副组长
    if not is_department_leader(db, current_user, member.department_id):
        log_access_denied(current_user, "部门成员", member.department_id, "用户无权添加该部门成员")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="只有管理员或部门组长/副组长可以添加部门成员"
        )
    
    # 副组长只能添加普通成员
    user_role = get_user_role_in_department(db, current_user, member.department_id)
    if user_role == "vice_leader" and member.role in ["leader", "vice_leader"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="副组长只能添加普通成员"
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
    current_user: User = Depends(get_current_user)
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
    current_user: User = Depends(get_current_user)
):
    """更新部门成员角色（仅管理员或组长可用，副组长无权编辑角色）"""
    # 验证成员是否存在
    db_member = db.query(DepartmentMember).filter(DepartmentMember.id == member_id).first()
    if not db_member:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="部门成员不存在"
        )
    
    # 验证权限：仅管理员或组长可以编辑角色（副组长无权）
    if not can_edit_role(db, current_user, db_member.department_id):
        log_access_denied(current_user, "部门成员角色", db_member.department_id, "副组长无权编辑角色")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="只有管理员或组长可以编辑成员角色，副组长无权执行此操作"
        )
    
    # 验证是否已经有组长
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
    
    old_role = db_member.role
    # 更新角色
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
    current_user: User = Depends(get_current_user)
):
    """移除部门成员（管理员或部门组长/副组长可用，副组长只能移除普通成员）"""
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
    
    # 验证权限：检查是否可以管理该成员
    can_manage, error_msg = can_manage_member(db, current_user, db_member)
    if not can_manage:
        log_access_denied(current_user, "部门成员", db_member.department_id, error_msg)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=error_msg
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
    current_user: User = Depends(get_current_user)
):
    """创建项目"""
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
    if not project.is_public and project.department_ids:
        for department_id in project.department_ids:
            # 验证部门是否存在
            department = db.query(Department).filter(Department.id == department_id).first()
            if not department:
                continue
            
            # 验证用户是否为部门组长
            leader = db.query(DepartmentMember).filter(
                DepartmentMember.user_id == current_user.id,
                DepartmentMember.department_id == department_id,
                DepartmentMember.role == "leader"
            ).first()
            if not leader:
                continue
            
            # 创建项目-部门关联
            project_department = ProjectDepartment(
                project_id=db_project.id,
                department_id=department_id
            )
            db.add(project_department)
    
    db.commit()
    return db_project


@router.get("/projects", response_model=List[ProjectDetailResponse])
def get_projects(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """获取项目列表"""
    from app.schema import DepartmentResponse
    
    # 获取公开项目
    public_projects = db.query(Project).filter(Project.is_public == True).all()
    
    # 获取用户所在部门的私有项目
    user_departments = db.query(DepartmentMember.department_id).filter(
        DepartmentMember.user_id == current_user.id
    ).all()
    department_ids = [dept.department_id for dept in user_departments]
    
    private_projects = db.query(Project).join(ProjectDepartment).filter(
        Project.is_public == False,
        ProjectDepartment.department_id.in_(department_ids)
    ).all()
    
    # 合并项目列表
    projects = list(set(public_projects + private_projects))
    
    # 为每个项目加载部门信息
    result = []
    for project in projects:
        departments = db.query(Department).join(ProjectDepartment).filter(
            ProjectDepartment.project_id == project.id
        ).all()
        
        result.append(ProjectDetailResponse(
            id=project.id,
            name=project.name,
            description=project.description,
            is_public=project.is_public,
            created_at=project.created_at,
            updated_at=project.updated_at,
            departments=[DepartmentResponse.from_orm(dept) for dept in departments]
        ))
    
    return result


@router.get("/projects/{project_id}", response_model=ProjectDetailResponse)
def get_project(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """获取项目详情"""
    # 验证项目是否存在
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="项目不存在"
        )
    
    # 验证用户是否有权限访问
    if not project.is_public:
        # 检查用户是否属于绑定部门
        user_departments = db.query(DepartmentMember.department_id).filter(
            DepartmentMember.user_id == current_user.id
        ).all()
        department_ids = [dept.department_id for dept in user_departments]
        
        project_departments = db.query(ProjectDepartment.department_id).filter(
            ProjectDepartment.project_id == project_id
        ).all()
        project_dept_ids = [dept.department_id for dept in project_departments]
        
        has_access = any(dept_id in department_ids for dept_id in project_dept_ids)
        if not has_access:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="无权访问该项目"
            )
    
    # 获取项目绑定的部门
    departments = db.query(Department).join(ProjectDepartment).filter(
        ProjectDepartment.project_id == project_id
    ).all()
    
    # 构建响应
    response = ProjectDetailResponse(
        id=project.id,
        name=project.name,
        description=project.description,
        is_public=project.is_public,
        created_at=project.created_at,
        updated_at=project.updated_at,
        departments=[DepartmentResponse.from_orm(dept) for dept in departments]
    )
    return response


@router.put("/projects/{project_id}", response_model=ProjectResponse)
def update_project(
    project_id: int,
    project_update: ProjectUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """更新项目信息"""
    # 验证项目是否存在
    db_project = db.query(Project).filter(Project.id == project_id).first()
    if not db_project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="项目不存在"
        )
    
    # 验证用户是否有权限更新
    if not db_project.is_public:
        # 检查用户是否属于绑定部门的组长
        user_departments = db.query(DepartmentMember).filter(
            DepartmentMember.user_id == current_user.id,
            DepartmentMember.role == "leader"
        ).all()
        user_dept_ids = [dept.department_id for dept in user_departments]
        
        project_departments = db.query(ProjectDepartment.department_id).filter(
            ProjectDepartment.project_id == project_id
        ).all()
        project_dept_ids = [dept.department_id for dept in project_departments]
        
        has_access = any(dept_id in user_dept_ids for dept_id in project_dept_ids)
        if not has_access:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="无权更新该项目"
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


@router.post("/projects/{project_id}/bind-departments", response_model=Message)
def bind_project_departments(
    project_id: int,
    bind_request: ProjectDepartmentBindRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """绑定项目到部门"""
    # 验证项目是否存在
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="项目不存在"
        )
    
    # 验证项目是否为私有项目
    if project.is_public:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="公开项目不需要绑定部门"
        )
    
    # 验证用户是否有权限绑定
    user_departments = db.query(DepartmentMember).filter(
        DepartmentMember.user_id == current_user.id,
        DepartmentMember.role == "leader"
    ).all()
    user_dept_ids = [dept.department_id for dept in user_departments]
    
    # 验证要绑定的部门是否存在且用户是组长
    valid_departments = []
    for dept_id in bind_request.department_ids:
        department = db.query(Department).filter(Department.id == dept_id).first()
        if department and dept_id in user_dept_ids:
            valid_departments.append(dept_id)
    
    # 删除原有绑定
    db.query(ProjectDepartment).filter(ProjectDepartment.project_id == project_id).delete()
    
    # 创建新绑定
    for dept_id in valid_departments:
        project_department = ProjectDepartment(
            project_id=project_id,
            department_id=dept_id
        )
        db.add(project_department)
    
    db.commit()
    return Message(message="项目部门绑定成功")


@router.delete("/projects/{project_id}", response_model=Message)
def delete_project(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """删除项目"""
    # 验证项目是否存在
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="项目不存在"
        )
    
    # 验证用户是否有权限删除
    if not project.is_public:
        # 检查用户是否属于绑定部门的组长
        user_departments = db.query(DepartmentMember).filter(
            DepartmentMember.user_id == current_user.id,
            DepartmentMember.role == "leader"
        ).all()
        user_dept_ids = [dept.department_id for dept in user_departments]
        
        project_departments = db.query(ProjectDepartment.department_id).filter(
            ProjectDepartment.project_id == project_id
        ).all()
        project_dept_ids = [dept.department_id for dept in project_departments]
        
        has_access = any(dept_id in user_dept_ids for dept_id in project_dept_ids)
        if not has_access:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="无权删除该项目"
            )
    
    # 删除项目-部门关联
    db.query(ProjectDepartment).filter(ProjectDepartment.project_id == project_id).delete()
    
    # 删除项目
    db.delete(project)
    db.commit()
    
    return Message(message="项目删除成功")
