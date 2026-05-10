from __future__ import annotations

from fastapi import APIRouter, Query

from app.schemas import ValidateInputRequest, ValidateInputResponse, WorkspaceSummaryResponse, WorkspaceTreeResponse
from app.services.workspace_service import get_workspace_service

router = APIRouter()


@router.get("/workspaces", response_model=list[WorkspaceSummaryResponse])
def list_workspaces() -> list[WorkspaceSummaryResponse]:
    return get_workspace_service().list_workspace_summaries()


@router.get("/workspaces/{workspace_id}", response_model=WorkspaceSummaryResponse)
def get_workspace(workspace_id: str) -> WorkspaceSummaryResponse:
    return get_workspace_service().get_workspace_summary(workspace_id)


@router.get("/workspaces/{workspace_id}/tree", response_model=WorkspaceTreeResponse)
def browse_workspace_tree(
    workspace_id: str,
    path: str = Query(default=""),
    depth: int = Query(default=1, ge=1, le=4),
    directories_only: bool = Query(default=False),
) -> WorkspaceTreeResponse:
    return get_workspace_service().browse_tree(workspace_id, path=path, depth=depth, directories_only=directories_only)


@router.post("/inputs/validate", response_model=ValidateInputResponse)
def validate_input(payload: ValidateInputRequest) -> ValidateInputResponse:
    return get_workspace_service().validate_input(payload.workspace_id, payload.input_ref)

