"""
Workflow template API routes
"""
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, generate_id
from app.models import get_db, WorkflowTemplate
from app.schemas import (
    WorkflowTemplateCreate,
    WorkflowTemplateUpdate,
    WorkflowTemplateResponse,
    WorkflowTemplateListResponse,
    SuccessResponse,
)
from app.exception import NotFoundError, ForbiddenError, ValidationError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/workflow-templates", tags=["Workflow Templates"])


def check_workflow_permission(template: WorkflowTemplate, user_id: str, user_roles: List[str]) -> bool:
    """Check if user has permission to access workflow template"""
    if template.scope == "global":
        return True
    if template.created_by == user_id:
        return True
    return False


@router.post("", response_model=WorkflowTemplateResponse, status_code=status.HTTP_201_CREATED)
async def create_workflow_template(
    template_data: WorkflowTemplateCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create workflow template

    - Supports drag-and-drop workflow orchestration
    - Nodes can be app templates or job templates
    - Edges define connections and PVC sharing between nodes
    """
    user_id = str(current_user.get("id", ""))

    # Validate permission for global templates
    if template_data.scope == "global":
        user_roles = current_user.get("role", [])
        if "admin" not in user_roles:
            raise ForbiddenError("Only admins can create global templates")

    # Validate project_id for project scope
    if template_data.scope == "project" and not template_data.project_id:
        raise ValidationError("project_id is required for project-scoped templates")

    # Generate template ID
    template_id = generate_id(template_data.name)

    # Create workflow template
    template = WorkflowTemplate(
        id=template_id,
        name=template_data.name,
        description=template_data.description,
        scope=template_data.scope.value,
        project_id=template_data.project_id,
        nodes=[node.model_dump() for node in template_data.nodes],
        edges=[edge.model_dump() for edge in template_data.edges],
        created_by=user_id,
    )

    db.add(template)
    db.commit()
    db.refresh(template)

    logger.info(f"Created workflow template {template_id} by user {user_id}")
    return template


@router.get("", response_model=WorkflowTemplateListResponse)
async def list_workflow_templates(
    scope: Optional[str] = Query(None, description="Filter by scope: global/project"),
    project_id: Optional[str] = Query(None, description="Filter by project ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List workflow templates"""
    user_id = str(current_user.get("id", ""))

    query = db.query(WorkflowTemplate)

    if scope:
        query = query.filter(WorkflowTemplate.scope == scope)

    if project_id:
        query = query.filter(
            (WorkflowTemplate.project_id == project_id) | (WorkflowTemplate.scope == "global")
        )
    else:
        query = query.filter(
            (WorkflowTemplate.scope == "global") | (WorkflowTemplate.created_by == user_id)
        )

    templates = query.all()

    return WorkflowTemplateListResponse(total=len(templates), items=templates)


@router.get("/{template_id}", response_model=WorkflowTemplateResponse)
async def get_workflow_template(
    template_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get workflow template details"""
    template = db.query(WorkflowTemplate).filter(WorkflowTemplate.id == template_id).first()

    if not template:
        raise NotFoundError("Workflow template", template_id)

    user_id = str(current_user.get("id", ""))
    user_roles = current_user.get("role", [])
    if not check_workflow_permission(template, user_id, user_roles):
        raise ForbiddenError("No permission to access this template")

    return template


@router.put("/{template_id}", response_model=WorkflowTemplateResponse)
async def update_workflow_template(
    template_id: str,
    template_data: WorkflowTemplateUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update workflow template"""
    template = db.query(WorkflowTemplate).filter(WorkflowTemplate.id == template_id).first()

    if not template:
        raise NotFoundError("Workflow template", template_id)

    user_id = str(current_user.get("id", ""))
    user_roles = current_user.get("role", [])

    if template.created_by != user_id and "admin" not in user_roles:
        raise ForbiddenError("Only template creator or admin can update")

    # Update fields
    if template_data.name is not None:
        template.name = template_data.name
    if template_data.description is not None:
        template.description = template_data.description
    if template_data.nodes is not None:
        template.nodes = [node.model_dump() for node in template_data.nodes]
    if template_data.edges is not None:
        template.edges = [edge.model_dump() for edge in template_data.edges]

    db.commit()
    db.refresh(template)

    logger.info(f"Updated workflow template {template_id} by user {user_id}")
    return template


@router.delete("/{template_id}", response_model=SuccessResponse)
async def delete_workflow_template(
    template_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete workflow template"""
    template = db.query(WorkflowTemplate).filter(WorkflowTemplate.id == template_id).first()

    if not template:
        raise NotFoundError("Workflow template", template_id)

    user_id = str(current_user.get("id", ""))
    user_roles = current_user.get("role", [])

    if template.created_by != user_id and "admin" not in user_roles:
        raise ForbiddenError("Only template creator or admin can delete")

    db.delete(template)
    db.commit()

    logger.info(f"Deleted workflow template {template_id} by user {user_id}")
    return SuccessResponse(message=f"Workflow template {template_id} deleted successfully")
