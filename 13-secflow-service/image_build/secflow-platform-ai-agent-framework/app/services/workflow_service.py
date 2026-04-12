from __future__ import annotations

import uuid
from typing import Iterable, List

from fastapi import HTTPException, status
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.models.database import WorkflowDefinition, WorkflowDefinitionVersion
from app.pi_vuln_core.config.models import FrameworkConfig
from app.schemas import (
    WorkflowDefinitionCreate,
    WorkflowDefinitionResponse,
    WorkflowDefinitionUpdate,
    WorkflowDefinitionVersionResponse,
)


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:20]}"


def _principal_id(principal: dict) -> str:
    return principal.get("user_id") or principal.get("subject") or principal.get("client_id") or "system"


def _project_ids(principal: dict) -> set[str]:
    return set(principal.get("project_ids") or [])


class WorkflowService:
    def ready_check(self) -> None:
        return None

    def validate_definition_payload(self, definition_json: dict) -> FrameworkConfig:
        try:
            return FrameworkConfig.model_validate(definition_json)
        except (ValidationError, ValueError) as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    def _definition_response(self, definition: WorkflowDefinition, validated: FrameworkConfig | None = None) -> WorkflowDefinitionResponse:
        config = validated or self.validate_definition_payload(definition.definition_json)
        payload = {
            "id": definition.id,
            "name": definition.name,
            "description": definition.description,
            "project_id": definition.project_id,
            "root_workflow_id": config.root_workflow_id,
            "trigger_type": definition.trigger_type,
            "trigger_enabled": definition.trigger_enabled,
            "is_active": definition.is_active,
            "enabled": definition.enabled,
            "max_concurrency": definition.max_concurrency,
            "priority_default": definition.priority_default,
            "workspace_base_dir": definition.workspace_base_dir,
            "execution_timeout_seconds": definition.execution_timeout_seconds,
            "entry_input_task_type": config.resolve_entry_input_task_type(),
            "final_output_task_type": config.resolve_final_output_task_type(),
            "created_by": definition.created_by,
            "updated_by": definition.updated_by,
            "created_at": definition.created_at,
            "updated_at": definition.updated_at,
        }
        return WorkflowDefinitionResponse.model_validate(payload)

    def _ensure_project_access(self, principal: dict, project_id: str) -> None:
        project_ids = _project_ids(principal)
        if project_ids and project_id not in project_ids:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="project access denied")

    def _get_definition_or_404(self, db: Session, definition_id: str) -> WorkflowDefinition:
        definition = db.get(WorkflowDefinition, definition_id)
        if definition is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="workflow definition not found")
        return definition

    def _create_version_snapshot(self, db: Session, definition: WorkflowDefinition, created_by: str) -> WorkflowDefinitionVersion:
        current_max = (
            db.query(WorkflowDefinitionVersion)
            .filter(WorkflowDefinitionVersion.workflow_definition_id == definition.id)
            .order_by(WorkflowDefinitionVersion.version_no.desc())
            .first()
        )
        version = WorkflowDefinitionVersion(
            id=_new_id("wdv"),
            workflow_definition_id=definition.id,
            version_no=1 if current_max is None else current_max.version_no + 1,
            definition_json=definition.definition_json,
            created_by=created_by,
        )
        db.add(version)
        return version

    def create_definition(self, db: Session, payload: WorkflowDefinitionCreate, principal: dict) -> WorkflowDefinitionResponse:
        self._ensure_project_access(principal, payload.project_id)
        validated = self.validate_definition_payload(payload.definition_json)
        actor = _principal_id(principal)
        definition = WorkflowDefinition(
            id=_new_id("wfd"),
            name=payload.name,
            description=payload.description,
            project_id=payload.project_id,
            definition_json=payload.definition_json,
            root_workflow_id=validated.root_workflow_id,
            trigger_type=payload.trigger_type,
            trigger_enabled=payload.trigger_enabled,
            is_active=payload.is_active,
            enabled=payload.enabled,
            max_concurrency=payload.max_concurrency,
            priority_default=payload.priority_default,
            workspace_base_dir=payload.workspace_base_dir,
            execution_timeout_seconds=payload.execution_timeout_seconds,
            created_by=actor,
            updated_by=actor,
        )
        db.add(definition)
        self._create_version_snapshot(db, definition, actor)
        db.commit()
        db.refresh(definition)
        return self._definition_response(definition, validated)

    def list_definitions(self, db: Session, principal: dict) -> List[WorkflowDefinitionResponse]:
        project_ids = _project_ids(principal)
        query = db.query(WorkflowDefinition).order_by(WorkflowDefinition.created_at.desc())
        if project_ids:
            query = query.filter(WorkflowDefinition.project_id.in_(project_ids))
        return [self._definition_response(item) for item in query.all()]

    def get_definition(self, db: Session, definition_id: str, principal: dict) -> WorkflowDefinitionResponse:
        definition = self._get_definition_or_404(db, definition_id)
        self._ensure_project_access(principal, definition.project_id)
        return self._definition_response(definition)

    def update_definition(
        self,
        db: Session,
        definition_id: str,
        payload: WorkflowDefinitionUpdate,
        principal: dict,
    ) -> WorkflowDefinitionResponse:
        definition = self._get_definition_or_404(db, definition_id)
        self._ensure_project_access(principal, definition.project_id)
        actor = _principal_id(principal)
        updates = payload.model_dump(exclude_unset=True)
        if "definition_json" in updates:
            validated = self.validate_definition_payload(updates["definition_json"])
            definition.definition_json = updates["definition_json"]
            definition.root_workflow_id = validated.root_workflow_id
        for field in [
            "name",
            "description",
            "trigger_type",
            "trigger_enabled",
            "is_active",
            "enabled",
            "max_concurrency",
            "priority_default",
            "workspace_base_dir",
            "execution_timeout_seconds",
        ]:
            if field in updates:
                setattr(definition, field, updates[field])
        definition.updated_by = actor
        self._create_version_snapshot(db, definition, actor)
        db.add(definition)
        db.commit()
        db.refresh(definition)
        return self._definition_response(definition)

    def delete_definition(self, db: Session, definition_id: str, principal: dict) -> None:
        definition = self._get_definition_or_404(db, definition_id)
        self._ensure_project_access(principal, definition.project_id)
        db.query(WorkflowDefinitionVersion).filter(
            WorkflowDefinitionVersion.workflow_definition_id == definition.id
        ).delete(synchronize_session=False)
        db.delete(definition)
        db.commit()

    def list_definition_versions(self, db: Session, definition_id: str, principal: dict) -> List[WorkflowDefinitionVersionResponse]:
        definition = self._get_definition_or_404(db, definition_id)
        self._ensure_project_access(principal, definition.project_id)
        versions = (
            db.query(WorkflowDefinitionVersion)
            .filter(WorkflowDefinitionVersion.workflow_definition_id == definition_id)
            .order_by(WorkflowDefinitionVersion.version_no.desc())
            .all()
        )
        return [WorkflowDefinitionVersionResponse.model_validate(item, from_attributes=True) for item in versions]

    def get_definition_version(
        self,
        db: Session,
        definition_id: str,
        version_no: int,
        principal: dict,
    ) -> WorkflowDefinitionVersionResponse:
        definition = self._get_definition_or_404(db, definition_id)
        self._ensure_project_access(principal, definition.project_id)
        version = (
            db.query(WorkflowDefinitionVersion)
            .filter(
                WorkflowDefinitionVersion.workflow_definition_id == definition_id,
                WorkflowDefinitionVersion.version_no == version_no,
            )
            .first()
        )
        if version is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="workflow definition version not found")
        return WorkflowDefinitionVersionResponse.model_validate(version, from_attributes=True)

    def set_definition_active(self, db: Session, definition_id: str, principal: dict, active: bool) -> WorkflowDefinitionResponse:
        definition = self._get_definition_or_404(db, definition_id)
        self._ensure_project_access(principal, definition.project_id)
        definition.is_active = active
        definition.updated_by = _principal_id(principal)
        db.add(definition)
        db.commit()
        db.refresh(definition)
        return self._definition_response(definition)


_workflow_service: WorkflowService | None = None


def get_workflow_service() -> WorkflowService:
    global _workflow_service
    if _workflow_service is None:
        _workflow_service = WorkflowService()
    return _workflow_service
