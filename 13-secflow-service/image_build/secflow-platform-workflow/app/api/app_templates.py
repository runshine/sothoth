"""
Application template API routes
"""
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, generate_id
from app.models import get_db, AppTemplate, TemplateTagBinding
from app.schemas import (
    AppTemplateCreate,
    AppTemplateUpdate,
    AppTemplateResponse,
    AppTemplateListResponse,
    SuccessResponse,
)
from app.exception import NotFoundError, ForbiddenError, ValidationError
from app.services.template_tags import filter_template_ids_by_tag_keys, get_template_tags, sync_template_tags

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/app-templates", tags=["App Templates"])


def _attach_app_template_tags(db: Session, templates: List[AppTemplate]) -> List[AppTemplate]:
    tag_map = get_template_tags(db, template_type="app", template_ids=[template.id for template in templates])
    for template in templates:
        template.tags = tag_map.get(template.id, [])
    return templates


def check_template_permission(
    template: AppTemplate,
    user_id: str,
    user_roles: List[str],
    project_id: Optional[str] = None,
) -> bool:
    """Check if user has permission to access template"""
    # Global templates are accessible to all
    if template.scope == "global":
        return True
    # Project templates require project access
    if template.created_by == user_id:
        return True
    if project_id and template.project_id == project_id:
        return True
    return False


@router.post("", response_model=AppTemplateResponse, status_code=status.HTTP_201_CREATED)
async def create_app_template(
    template_data: AppTemplateCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create application template

    - Supports multi-container configuration
    - Supports global templates (visible to all projects) and project-level templates
    - Health check configuration for first container
    - Supports defining Service ports (ClusterIP only)
    """
    user_id = str(current_user.get("id", ""))

    # Validate permission for global templates
    if template_data.scope == "global":
        # Check if user has admin role
        user_roles = current_user.get("role", [])
        if "admin" not in user_roles:
            raise ForbiddenError("Only admins can create global templates")

    # Validate project_id for project scope
    if template_data.scope == "project" and not template_data.project_id:
        raise ValidationError("project_id is required for project-scoped templates")

    # Generate template ID
    template_id = generate_id(template_data.name)

    # Convert containers to JSON-serializable format
    containers_json = []
    for container in template_data.containers:
        container_dict = {
            "name": container.name,
            "image": container.image,
            "command": container.command,
            "args": container.args,
            "env_vars": [{"name": e.name, "value": e.value} for e in container.env_vars],
            "volume_mounts": [vm.model_dump() for vm in container.volume_mounts],
            "input_env_vars": [iev.model_dump() for iev in container.input_env_vars],
            "input_volume_mounts": [ivm.model_dump() for ivm in container.input_volume_mounts],
            "privileged": container.privileged,
            "image_pull_policy": container.image_pull_policy.value if container.image_pull_policy else "IfNotPresent",
            "resources": container.resources.model_dump() if container.resources else None,
            "liveness_probe": container.liveness_probe.model_dump() if container.liveness_probe else None,
            "readiness_probe": container.readiness_probe.model_dump() if container.readiness_probe else None,
        }
        containers_json.append(container_dict)

    # Create template
    template = AppTemplate(
        id=template_id,
        name=template_data.name,
        description=template_data.description,
        scope=template_data.scope.value if template_data.scope else "project",
        project_id=template_data.project_id,
        containers=containers_json,
        replicas=template_data.replicas,
        created_by=user_id,
    )

    db.add(template)
    db.flush()
    sync_template_tags(db, template_type="app", template_id=template_id, tags=template_data.tags, created_by=user_id)
    db.commit()
    db.refresh(template)
    _attach_app_template_tags(db, [template])

    logger.info(f"Created app template {template_id} by user {user_id}")
    return template


@router.get("", response_model=AppTemplateListResponse)
async def list_app_templates(
    scope: Optional[str] = Query(None, description="Filter by scope: global/project"),
    project_id: Optional[str] = Query(None, description="Filter by project ID"),
    tag_keys: Optional[str] = Query(None, description="Comma separated tag keys"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List application templates

    - Returns global templates and templates for user's projects
    - Can filter by scope and project_id
    """
    user_id = str(current_user.get("id", ""))

    query = db.query(AppTemplate)

    # Filter by scope if provided
    if scope:
        query = query.filter(AppTemplate.scope == scope)

    # Filter by project_id if provided
    if project_id:
        query = query.filter(
            (AppTemplate.project_id == project_id) | (AppTemplate.scope == "global")
        )
    else:
        # Return global templates and user's templates
        query = query.filter(
            (AppTemplate.scope == "global") | (AppTemplate.created_by == user_id)
        )

    if tag_keys:
        matched_ids = filter_template_ids_by_tag_keys(
            db,
            template_type="app",
            tag_keys=[item.strip() for item in tag_keys.split(",") if item.strip()],
        )
        if matched_ids is not None:
            if not matched_ids:
                return AppTemplateListResponse(total=0, items=[])
            query = query.filter(AppTemplate.id.in_(matched_ids))

    templates = query.all()
    _attach_app_template_tags(db, templates)

    return AppTemplateListResponse(total=len(templates), items=templates)


@router.get("/{template_id}", response_model=AppTemplateResponse)
async def get_app_template(
    template_id: str,
    project_id: Optional[str] = Query(None, description="Project ID for project-scoped template access"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get application template details
    """
    template = db.query(AppTemplate).filter(AppTemplate.id == template_id).first()

    if not template:
        raise NotFoundError("Application template", template_id)

    # Check permission
    user_id = str(current_user.get("id", ""))
    user_roles = current_user.get("role", [])
    if not check_template_permission(template, user_id, user_roles, project_id):
        raise ForbiddenError("No permission to access this template")

    _attach_app_template_tags(db, [template])
    return template


@router.put("/{template_id}", response_model=AppTemplateResponse)
async def update_app_template(
    template_id: str,
    template_data: AppTemplateUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update application template

    - Only template creator or admin can update
    - Supports updating multi-container configuration
    """
    template = db.query(AppTemplate).filter(AppTemplate.id == template_id).first()

    if not template:
        raise NotFoundError("Application template", template_id)

    # Check permission
    user_id = str(current_user.get("id", ""))
    user_roles = current_user.get("role", [])

    if template.created_by != user_id and "admin" not in user_roles:
        raise ForbiddenError("Only template creator or admin can update")

    # Update fields
    logger.info(f"Update request: template_id={template_id}, replicas={template_data.replicas}")
    if template_data.name is not None:
        template.name = template_data.name
    if template_data.description is not None:
        template.description = template_data.description
    if template_data.containers is not None:
        # Convert containers to JSON-serializable format
        containers_json = []
        for container in template_data.containers:
            container_dict = {
                "name": container.name,
                "image": container.image,
                "command": container.command,
                "args": container.args,
                "env_vars": [{"name": e.name, "value": e.value} for e in container.env_vars],
                "volume_mounts": [vm.model_dump() for vm in container.volume_mounts],
                "input_env_vars": [iev.model_dump() for iev in container.input_env_vars],
                "input_volume_mounts": [ivm.model_dump() for ivm in container.input_volume_mounts],
                "privileged": container.privileged,
                "image_pull_policy": container.image_pull_policy.value if container.image_pull_policy else "IfNotPresent",
                "resources": container.resources.model_dump() if container.resources else None,
                "liveness_probe": container.liveness_probe.model_dump() if container.liveness_probe else None,
            "readiness_probe": container.readiness_probe.model_dump() if container.readiness_probe else None,
            }
            containers_json.append(container_dict)
        template.containers = containers_json
    if template_data.replicas is not None:
        template.replicas = template_data.replicas

    sync_template_tags(db, template_type="app", template_id=template.id, tags=template_data.tags, created_by=user_id)

    db.commit()
    db.refresh(template)
    _attach_app_template_tags(db, [template])

    logger.info(f"Updated app template {template_id} by user {user_id}")
    return template


@router.delete("/{template_id}", response_model=SuccessResponse)
async def delete_app_template(
    template_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Delete application template

    - Only template creator or admin can delete
    """
    template = db.query(AppTemplate).filter(AppTemplate.id == template_id).first()

    if not template:
        raise NotFoundError("Application template", template_id)

    # Check permission
    user_id = str(current_user.get("id", ""))
    user_roles = current_user.get("role", [])

    if template.created_by != user_id and "admin" not in user_roles:
        raise ForbiddenError("Only template creator or admin can delete")

    db.query(TemplateTagBinding).filter(
        TemplateTagBinding.template_type == "app",
        TemplateTagBinding.template_id == template.id,
    ).delete(synchronize_session=False)
    db.delete(template)
    db.commit()

    logger.info(f"Deleted app template {template_id} by user {user_id}")
    return SuccessResponse(message=f"Application template {template_id} deleted successfully")
