"""机机Token管理路由"""

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_machine_client
from app.schema import (
    MachineTokenCreate, MachineTokenResponse, MachineTokenUpdate,
    MachineTokenDetailResponse, Message
)
from app.model import MachineToken

router = APIRouter(tags=["机机Token管理"], prefix="/machine-tokens")


@router.get("", response_model=List[MachineTokenResponse])
def list_machine_tokens(
    db: Session = Depends(get_db)
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
            # 如果Token已过期且状态仍为激活，更新状态为禁用
            token.is_active = False
            token.updated_at = now
    
    # 如果有更新，提交到数据库
    db.commit()
    
    return tokens


@router.get("/{token_id}", response_model=MachineTokenDetailResponse)
def get_machine_token(
    token_id: int,
    db: Session = Depends(get_db)
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
    
    # 检查Token是否过期
    now = datetime.utcnow()
    token_expired = token.expires_at and token.expires_at < now
    
    if token_expired and token.is_active:
        # 如果Token已过期且状态仍为激活，更新状态为禁用
        token.is_active = False
        token.updated_at = now
        db.commit()
    
    # 如果Token已过期，创建一个不包含token字段的响应对象
    if token_expired:
        response_data = {
            "id": token.id,
            "machine_code": token.machine_code,
            "description": token.description,
            "is_active": token.is_active,
            "created_at": token.created_at,
            "expires_at": token.expires_at,
            "token": ""  # 设置为空字符串
        }
        return MachineTokenDetailResponse(**response_data)
    
    return token


@router.post("", response_model=MachineTokenDetailResponse, status_code=status.HTTP_201_CREATED)
def create_machine_token(
    token_data: MachineTokenCreate,
    db: Session = Depends(get_db)
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
        expires_at=token_data.expires_at
    )

    db.add(db_token)
    db.commit()
    db.refresh(db_token)

    return db_token


@router.put("/{token_id}", response_model=MachineTokenDetailResponse)
def update_machine_token(
    token_id: int,
    token_data: MachineTokenUpdate,
    db: Session = Depends(get_db)
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
    db: Session = Depends(get_db)
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
    db: Session = Depends(get_db)
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
    db: Session = Depends(get_db)
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
    db: Session = Depends(get_db)
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

    import secrets

    # 生成新的token值
    token.token = secrets.token_urlsafe(64)
    token.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(token)

    return token
