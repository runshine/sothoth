"""
Job template API routes
"""
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, generate_id
from app.models import get_db, JobTemplate
from app.schemas import (
    JobTemplateCreate,
    JobTemplateUpdate,
    JobTemplateResponse,
    JobTemplateListResponse,
    SuccessResponse,
)
from app.exception import NotFoundError, ForbiddenError, ValidationError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/job-templates", tags=["Job Templates"])


def check_job_template_permission(template: JobTemplate, user_id: str, user_roles: List[str]) -> bool:
    """Check if user has permission to access job template"""
    if template.scope == "global":
        return True
    if template.created_by == user_id:
        return True
    return False


@router.post("", response_model=JobTemplateResponse, status_code=status.HTTP_201_CREATED)
async def create_job_template(
    template_data: JobTemplateCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create job template

    - Supports global templates (visible to all projects) and project-level templates
    - One-time execution Job template
    - Supports multi-container configuration
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
    template = JobTemplate(
        id=template_id,
        name=template_data.name,
        description=template_data.description,
        scope=template_data.scope.value if template_data.scope else "project",
        project_id=template_data.project_id,
        containers=containers_json,
        ttl_seconds_after_finished=template_data.ttl_seconds_after_finished,
        backoff_limit=template_data.backoff_limit,
        created_by=user_id,
    )

    db.add(template)
    db.commit()
    db.refresh(template)

    logger.info(f"Created job template {template_id} by user {user_id}")
    return template


@router.get("", response_model=JobTemplateListResponse)
async def list_job_templates(
    scope: Optional[str] = Query(None, description="Filter by scope: global/project"),
    project_id: Optional[str] = Query(None, description="Filter by project ID"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List job templates

    - Returns global templates and templates for user's projects
    """
    user_id = str(current_user.get("id", ""))

    query = db.query(JobTemplate)

    if scope:
        query = query.filter(JobTemplate.scope == scope)

    if project_id:
        query = query.filter(
            (JobTemplate.project_id == project_id) | (JobTemplate.scope == "global")
        )
    else:
        query = query.filter(
            (JobTemplate.scope == "global") | (JobTemplate.created_by == user_id)
        )

    templates = query.all()

    return JobTemplateListResponse(total=len(templates), items=templates)


@router.get("/{template_id}", response_model=JobTemplateResponse)
async def get_job_template(
    template_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get job template details"""
    template = db.query(JobTemplate).filter(JobTemplate.id == template_id).first()

    if not template:
        raise NotFoundError("Job template", template_id)

    user_id = str(current_user.get("id", ""))
    user_roles = current_user.get("role", [])
    if not check_job_template_permission(template, user_id, user_roles):
        raise ForbiddenError("No permission to access this template")

    return template


@router.put("/{template_id}", response_model=JobTemplateResponse)
async def update_job_template(
    template_id: str,
    template_data: JobTemplateUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update job template"""
    template = db.query(JobTemplate).filter(JobTemplate.id == template_id).first()

    if not template:
        raise NotFoundError("Job template", template_id)

    user_id = str(current_user.get("id", ""))
    user_roles = current_user.get("role", [])

    if template.created_by != user_id and "admin" not in user_roles:
        raise ForbiddenError("Only template creator or admin can update")

    # Update fields
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
    if template_data.ttl_seconds_after_finished is not None:
        template.ttl_seconds_after_finished = template_data.ttl_seconds_after_finished
    if template_data.backoff_limit is not None:
        template.backoff_limit = template_data.backoff_limit

    db.commit()
    db.refresh(template)

    logger.info(f"Updated job template {template_id} by user {user_id}")
    return template


@router.delete("/{template_id}", response_model=SuccessResponse)
async def delete_job_template(
    template_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete job template"""
    template = db.query(JobTemplate).filter(JobTemplate.id == template_id).first()

    if not template:
        raise NotFoundError("Job template", template_id)

    user_id = str(current_user.get("id", ""))
    user_roles = current_user.get("role", [])

    if template.created_by != user_id and "admin" not in user_roles:
        raise ForbiddenError("Only template creator or admin can delete")

    db.delete(template)
    db.commit()

    logger.info(f"Deleted job template {template_id} by user {user_id}")
    return SuccessResponse(message=f"Job template {template_id} deleted successfully")
