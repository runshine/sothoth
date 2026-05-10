from __future__ import annotations

from dataclasses import dataclass

from fastapi import Header


@dataclass(frozen=True)
class Subject:
    username: str
    tenant_id: str | None = None


def get_current_subject(
    x_secflow_user: str | None = Header(default=None),
    x_secflow_tenant: str | None = Header(default=None),
) -> Subject:
    return Subject(username=x_secflow_user or "anonymous", tenant_id=x_secflow_tenant)

