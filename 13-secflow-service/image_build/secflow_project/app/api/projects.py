"""
项目API路由模块
"""

import hashlib
import logging
import secrets
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Header, Query, status
from sqlalchemy.orm import Session, joinedload

from app.config import get_config
from app.exception import (
    ForbiddenError,
    NotFoundError,
    UnauthorizedError,
    ValidationError,
)
from app.model import get_db, Project, ProjectRoleBind
from app.schemas import (
    ProjectCreate,
    ProjectUpdate,
    ProjectResponse,
    ProjectListResponse,
    ProjectRoleBindCreate,
    ProjectRoleBindResponse,
    SuccessResponse,
    ProjectResourcesResponse,
    PodLogResponse,
)
from app.service.auth import get_auth_service, TokenInvalidError
from app.service.k8s import get_k8s_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/project", tags=["Projects"])


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


async def get_current_user(
    authorization: Optional[str] = Header(None)
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
        user = await auth_service.validate_token_async(token)
        return user
    except TokenInvalidError:
        raise UnauthorizedError("Token无效或已过期")


async def get_current_user_sync(
    authorization: Optional[str] = Header(None)
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
        user = auth_service.validate_token(token)
        return user
    except TokenInvalidError:
        raise UnauthorizedError("Token无效或已过期")


def make_project_response(project: Project, roles: List[ProjectRoleBindResponse]) -> ProjectResponse:
    """构建项目响应"""
    return ProjectResponse(
        id=project.id,
        name=project.name,
        description=project.description,
        owner_id=project.owner_id,
        owner_name=project.owner_name,
        k8s_namespace=project.k8s_namespace,
        status=project.status,
        created_at=project.created_at,
        updated_at=project.updated_at,
        roles=roles
    )


# ============ 项目接口 ============

@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    project_data: ProjectCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    创建项目

    - 项目名称必填
    - 自动生成16位MD5项目ID
    - 自动创建K8S Namespace
    - 自动将创建者设为项目所有者
    """
    # 检查项目名是否重复
    existing = db.query(Project).filter(
        Project.name == project_data.name,
        Project.status == "active"
    ).first()
    if existing:
        raise ValidationError(f"项目名称已存在: {project_data.name}")

    # 生成项目ID
    project_id = generate_project_id(project_data.name)

    # 生成K8S Namespace名称
    k8s_client = get_k8s_client()
    k8s_namespace = k8s_client.generate_namespace_name(project_id)

    # 创建项目
    project = Project(
        id=project_id,
        name=project_data.name,
        description=project_data.description,
        owner_id=str(current_user["id"]),
        owner_name=current_user.get("username"),
        k8s_namespace=k8s_namespace,
        status="active",
    )
    db.add(project)

    # 创建者角色绑定
    role_bind = ProjectRoleBind(
        id=generate_project_id(f"{project_id}_{current_user['id']}"),
        project_id=project_id,
        user_id=str(current_user["id"]),
        role="owner",
    )
    db.add(role_bind)

    # 创建K8S Namespace
    if not k8s_client.create_namespace(project_id):
        logger.warning(f"创建K8S Namespace失败: {project_id}")
        # 回滚数据库事务
        db.rollback()
        raise HTTPException(status_code=500, detail="创建K8S Namespace失败")

    # 创建TLS Secret
    tls_success, tls_error = k8s_client.create_tls_secret(project_id)
    if not tls_success:
        logger.error(f"创建TLS Secret失败: {project_id}, 错误: {tls_error}")
        # 回滚数据库事务
        db.rollback()
        # 删除已创建的Namespace
        k8s_client.delete_namespace(project_id, force=True)
        raise HTTPException(status_code=500, detail=f"创建TLS Secret失败: {tls_error}")

    db.commit()

    return make_project_response(project, [ProjectRoleBindResponse(
        user_id=role_bind.user_id,
        role=role_bind.role,
        created_at=role_bind.created_at
    )])


@router.get("", response_model=ProjectListResponse)
async def list_projects(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    查询项目列表

    - 返回用户有权访问的所有项目（作为所有者或成员）
    """
    user_id = str(current_user["id"])

    # 查询用户参与的项目
    project_ids = [bind.project_id for bind in db.query(ProjectRoleBind).filter(
        ProjectRoleBind.user_id == user_id
    ).all()]

    if not project_ids:
        return ProjectListResponse(total=0, projects=[])

    projects = db.query(Project).options(joinedload(Project.role_binds)).filter(
        Project.id.in_(project_ids),
        Project.status == "active"
    ).all()

    result = []
    for project in projects:
        roles = [ProjectRoleBindResponse(
            user_id=bind.user_id,
            role=bind.role,
            created_at=bind.created_at
        ) for bind in project.role_binds]
        result.append(make_project_response(project, roles))

    return ProjectListResponse(total=len(result), projects=result)


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
    user_id = str(current_user["id"])

    project = db.query(Project).options(joinedload(Project.role_binds)).filter(
        Project.id == project_id,
        Project.status == "active"
    ).first()

    if not project:
        raise NotFoundError("项目", project_id)

    # 检查权限
    if not verify_project_permission(project, user_id, current_user.get("role", [])):
        raise ForbiddenError("无权访问此项目")

    roles = [ProjectRoleBindResponse(
        user_id=bind.user_id,
        role=bind.role,
        created_at=bind.created_at
    ) for bind in project.role_binds]

    return make_project_response(project, roles)


@router.put("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: str,
    project_data: ProjectUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    修改项目

    - 需要项目所有者权限
    """
    user_id = str(current_user["id"])
    roles = current_user.get("role", [])

    project = db.query(Project).filter(
        Project.id == project_id,
        Project.status == "active"
    ).first()

    if not project:
        raise NotFoundError("项目", project_id)

    # 检查权限（需要owner）
    if not verify_project_permission(project, user_id, roles, require_owner=True):
        raise ForbiddenError("只有项目所有者可以修改项目")

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

    db.commit()

    roles_list = [ProjectRoleBindResponse(
        user_id=bind.user_id,
        role=bind.role,
        created_at=bind.created_at
    ) for bind in project.role_binds]

    return make_project_response(project, roles_list)


@router.delete("/{project_id}", response_model=SuccessResponse)
async def delete_project(
    project_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    删除项目

    - 需要项目所有者权限
    - 同时删除K8S Namespace及所有资源
    """
    user_id = str(current_user["id"])
    roles = current_user.get("role", [])

    project = db.query(Project).filter(
        Project.id == project_id,
        Project.status == "active"
    ).first()

    if not project:
        raise NotFoundError("项目", project_id)

    # 检查权限（需要owner）
    if not verify_project_permission(project, user_id, roles, require_owner=True):
        raise ForbiddenError("只有项目所有者可以删除项目")

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

    - 需要项目所有者权限
    """
    user_id = str(current_user["id"])
    roles = current_user.get("role", [])

    project = db.query(Project).filter(
        Project.id == project_id,
        Project.status == "active"
    ).first()

    if not project:
        raise NotFoundError("项目", project_id)

    # 检查权限
    if not verify_project_permission(project, user_id, roles, require_owner=True):
        raise ForbiddenError("只有项目所有者可以绑定角色")

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

    - 需要项目所有者权限
    - 不能解除所有者自己的角色
    """
    current_user_id = str(current_user["id"])
    roles = current_user.get("role", [])

    project = db.query(Project).filter(
        Project.id == project_id,
        Project.status == "active"
    ).first()

    if not project:
        raise NotFoundError("项目", project_id)

    # 检查权限
    if not verify_project_permission(project, current_user_id, roles, require_owner=True):
        raise ForbiddenError("只有项目所有者可以解除角色绑定")

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
    user_id = str(current_user["id"])

    project = db.query(Project).filter(
        Project.id == project_id,
        Project.status == "active"
    ).first()

    if not project:
        raise NotFoundError("项目", project_id)

    # 检查权限
    if not verify_project_permission(project, user_id, current_user.get("role", [])):
        raise ForbiddenError("无权访问此项目")

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
    user_id = str(current_user["id"])

    project = db.query(Project).filter(
        Project.id == project_id,
        Project.status == "active"
    ).first()

    if not project:
        raise NotFoundError("项目", project_id)

    # 检查权限
    if not verify_project_permission(project, user_id, current_user.get("role", [])):
        raise ForbiddenError("无权访问此项目")

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
    user_id = str(current_user["id"])

    project = db.query(Project).filter(
        Project.id == project_id,
        Project.status == "active"
    ).first()

    if not project:
        raise NotFoundError("项目", project_id)

    # 检查权限
    if not verify_project_permission(project, user_id, current_user.get("role", [])):
        raise ForbiddenError("无权访问此项目")

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
    user_id = str(current_user["id"])

    project = db.query(Project).filter(
        Project.id == project_id,
        Project.status == "active"
    ).first()

    if not project:
        raise NotFoundError("项目", project_id)

    # 检查权限
    if not verify_project_permission(project, user_id, current_user.get("role", [])):
        raise ForbiddenError("无权访问此项目")

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
    user_id = str(current_user["id"])

    project = db.query(Project).filter(
        Project.id == project_id,
        Project.status == "active"
    ).first()

    if not project:
        raise NotFoundError("项目", project_id)

    # 检查权限
    if not verify_project_permission(project, user_id, current_user.get("role", [])):
        raise ForbiddenError("无权访问此项目")

    k8s_client = get_k8s_client()

    # 删除PVC（检查是否被使用）
    success, error_msg = k8s_client.delete_pvc(project_id, pvc_name)

    if not success:
        from fastapi import HTTPException
        raise HTTPException(status_code=409, detail=error_msg)

    return SuccessResponse(message=f"PVC {pvc_name} 已删除")