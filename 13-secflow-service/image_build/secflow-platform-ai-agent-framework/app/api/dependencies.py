from __future__ import annotations

import uuid
from typing import Optional, Tuple

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from app.config import get_config
from app.models.database import get_db
from app.services.auth import get_auth_service


def generate_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:20]}"


async def get_current_subject(authorization: Optional[str] = Header(default=None)) -> Tuple[dict, str]:
    auth = get_auth_service()
    return await auth.validate_human_authorization(authorization)


async def get_machine_subject(authorization: Optional[str] = Header(default=None)) -> Tuple[dict, str]:
    auth = get_auth_service()
    return await auth.validate_machine_authorization(authorization)


__all__ = ["generate_id", "get_db", "get_current_subject", "get_machine_subject"]
