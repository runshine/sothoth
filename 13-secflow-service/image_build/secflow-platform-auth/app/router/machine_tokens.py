"""机机Token管理路由"""

import secrets
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from app.config import config
from app.database import get_db
from app.dependencies import get_current_super_admin, get_current_user
from app.schema import (
    MachineTokenCreate, MachineTokenResponse, MachineTokenUpdate,
    MachineTokenDetailResponse, Message, ProjectMachineTokenEnsureRequest,
    ProjectMachineTokenResponse
)
from app.model import MachineToken, User
from app.service.project import ProjectServiceError, get_project_service

router = APIRouter(tags=["机机Token管理"], prefix="/machine-tokens")


def _build_project_machine_code(project_id: str) -> str:
    return f"project-sdk:{project_id}"


def _refresh_token_if_expired(db: Session, token: MachineToken) -> bool:
    now = datetime.utcnow()
    token_expired = token.expires_at and token.expires_at < now
    if token_expired and token.is_active:
        token.is_active = False
        token.updated_at = now
        db.commit()
    return bool(token_expired)


def _mask_expired_token(token: MachineToken) -> MachineTokenDetailResponse:
    return MachineTokenDetailResponse(
        id=token.id,
        machine_code=token.machine_code,
        description=token.description,
        token_scope=token.token_scope or "global",
        project_id=token.project_id,
        is_active=token.is_active,
        created_at=token.created_at,
        expires_at=token.expires_at,
        token=""
    )


def _get_internal_service_token() -> str:
    return (
        config.get("service_auth", {}).get("machine_token")
        or config.get("service_auth", {}).get("service_machine_token")
        or ""
    )


def _require_internal_service_token(authorization: Optional[str]) -> None:
    if not authorization:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="缺少Authorization头")

    try:
        scheme, token = authorization.split()
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization格式错误")

    if scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization格式错误")

    shared_token = _get_internal_service_token()
    if not shared_token or not secrets.compare_digest(token, shared_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="无权调用内部项目Token接口")


def _assert_project_manage_permission(project_id: str, authorization: Optional[str]) -> dict:
    if not authorization:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="缺少Authorization头")

    try:
        token = authorization.split()[1]
    except (IndexError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization格式错误")

    project_service = get_project_service()
    try:
        project = project_service.get_project(token, project_id)
    except ProjectServiceError as exc:
        message = str(exc)
        if "资源不存在" in message:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="项目不存在")
        if "无权限" in message or "Token无效" in message:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="无权访问当前项目")
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"校验项目权限失败: {message}")

    if not project.get("can_manage"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="仅项目管理员可查看或刷新项目级Token")

    return project


def _ensure_project_machine_token(
    db: Session,
    project_id: str,
    project_name: Optional[str] = None,
    description: Optional[str] = None,
    expires_at: Optional[datetime] = None,
    regenerate: bool = False,
) -> MachineToken:
    machine_code = _build_project_machine_code(project_id)
    token = db.query(MachineToken).filter(MachineToken.machine_code == machine_code).first()

    default_description = description or f"项目 {project_name or project_id} 的 SDK 访问凭证"
    now = datetime.utcnow()

    if token:
        token.description = default_description
        token.token_scope = "project"
        token.project_id = project_id
        if expires_at is not None:
            token.expires_at = expires_at
        if regenerate or not token.is_active:
            token.token = secrets.token_urlsafe(64)
            token.is_active = True
        token.updated_at = now
        db.commit()
        db.refresh(token)
        return token

    token = MachineToken(
        token=secrets.token_urlsafe(64),
        machine_code=machine_code,
        description=default_description,
        token_scope="project",
        project_id=project_id,
        expires_at=expires_at,
        is_active=True,
    )
    db.add(token)
    db.commit()
    db.refresh(token)
    return token


@router.get("", response_model=List[MachineTokenResponse])
def list_machine_tokens(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """
    获取机机Token列表

    返回所有机机Token的基本信息
    """
    tokens = db.query(MachineToken).all()
    
    # 检查每个Token的过期状态
    now = datetime.utcnow()
    for token in tokens:
        if token.expires_at and token.expires_at < now and token.is_active:
            token.is_active = False
            token.updated_at = now
    
    # 如果有更新，提交到数据库
    db.commit()
    
    return tokens


@router.get("/{token_id}", response_model=MachineTokenDetailResponse)
def get_machine_token(
    token_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """
    获取机机Token详情

    返回指定机机Token的详细信息
    - 如果Token已过期，token字段将被隐藏
    """
    token = db.query(MachineToken).filter(MachineToken.id == token_id).first()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token不存在"
        )
    
    token_expired = _refresh_token_if_expired(db, token)
    if token_expired:
        return _mask_expired_token(token)
    
    return token


@router.post("", response_model=MachineTokenDetailResponse, status_code=status.HTTP_201_CREATED)
def create_machine_token(
    token_data: MachineTokenCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """
    创建机机Token

    为指定的机器码创建新的机机Token
    """
    # 检查机器码是否已存在
    existing = db.query(MachineToken).filter(
        MachineToken.machine_code == token_data.machine_code
    ).first()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"机器码 '{token_data.machine_code}' 已存在"
        )

    import secrets

    # 生成随机token
    token_value = secrets.token_urlsafe(64)

    # 创建新的机机Token
    db_token = MachineToken(
        token=token_value,
        machine_code=token_data.machine_code,
        description=token_data.description,
        token_scope=token_data.token_scope or "global",
        project_id=token_data.project_id,
        expires_at=token_data.expires_at
    )

    db.add(db_token)
    db.commit()
    db.refresh(db_token)

    return db_token


@router.get("/projects/{project_id}", response_model=ProjectMachineTokenResponse)
def get_project_machine_token(
    project_id: str,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    获取项目级机机Token详情。

    仅具备项目管理权限的用户可查看。
    """
    _assert_project_manage_permission(project_id, authorization)

    machine_code = _build_project_machine_code(project_id)
    token = db.query(MachineToken).filter(MachineToken.machine_code == machine_code).first()
    if not token or token.token_scope != "project" or token.project_id != project_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="项目级Token不存在")

    token_expired = _refresh_token_if_expired(db, token)
    if token_expired:
        masked = _mask_expired_token(token)
        return ProjectMachineTokenResponse(
            id=masked.id,
            machine_code=masked.machine_code,
            description=masked.description,
            token_scope="project",
            project_id=project_id,
            is_active=masked.is_active,
            created_at=masked.created_at,
            expires_at=masked.expires_at,
            token=masked.token,
        )

    return token


@router.post("/projects/{project_id}/refresh", response_model=ProjectMachineTokenResponse)
def refresh_project_machine_token(
    project_id: str,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    手动刷新项目级机机Token。
    """
    project = _assert_project_manage_permission(project_id, authorization)
    token = _ensure_project_machine_token(
        db=db,
        project_id=project_id,
        project_name=project.get("name"),
        regenerate=True,
    )
    return token


@router.post("/projects/ensure", response_model=ProjectMachineTokenResponse, status_code=status.HTTP_201_CREATED)
def ensure_project_machine_token(
    request: ProjectMachineTokenEnsureRequest,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    """
    由项目微服务内部调用，自动创建项目级机机Token。
    """
    _require_internal_service_token(authorization)
    token = _ensure_project_machine_token(
        db=db,
        project_id=request.project_id,
        project_name=request.project_name,
        description=request.description,
        expires_at=request.expires_at,
        regenerate=False,
    )
    return token


@router.put("/{token_id}", response_model=MachineTokenDetailResponse)
def update_machine_token(
    token_id: int,
    token_data: MachineTokenUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """
    更新机机Token

    更新指定机机Token的描述和过期时间
    """
    token = db.query(MachineToken).filter(MachineToken.id == token_id).first()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token不存在"
        )

    # 更新描述
    if token_data.description is not None:
        token.description = token_data.description

    # 更新过期时间
    if token_data.expires_at is not None:
        token.expires_at = token_data.expires_at

    # 如果是空字符串表示设置为永不过期
    if token_data.expires_at == "":
        token.expires_at = None

    token.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(token)

    return token


@router.delete("/{token_id}", response_model=Message)
def delete_machine_token(
    token_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """
    删除机机Token

    永久删除指定的机机Token
    """
    token = db.query(MachineToken).filter(MachineToken.id == token_id).first()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token不存在"
        )

    db.delete(token)
    db.commit()

    return {"message": "Token已删除"}


@router.post("/{token_id}/enable", response_model=Message)
def enable_machine_token(
    token_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """
    启用机机Token

    将指定的机机Token设置为启用状态
    """
    token = db.query(MachineToken).filter(MachineToken.id == token_id).first()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token不存在"
        )

    token.is_active = True
    token.updated_at = datetime.utcnow()
    db.commit()

    return {"message": "Token已启用"}


@router.post("/{token_id}/disable", response_model=Message)
def disable_machine_token(
    token_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """
    禁用机机Token

    将指定的机机Token设置为禁用状态，禁用后Token将失效
    """
    token = db.query(MachineToken).filter(MachineToken.id == token_id).first()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token不存在"
        )

    token.is_active = False
    token.updated_at = datetime.utcnow()
    db.commit()

    return {"message": "Token已禁用"}


@router.post("/{token_id}/regenerate", response_model=MachineTokenDetailResponse)
def regenerate_machine_token(
    token_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_super_admin)
):
    """
    重新生成机机Token

    为指定的机器重新生成Token值，旧Token将失效
    """
    token = db.query(MachineToken).filter(MachineToken.id == token_id).first()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token不存在"
        )

    # 生成新的token值
    token.token = secrets.token_urlsafe(64)
    token.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(token)

    return token
