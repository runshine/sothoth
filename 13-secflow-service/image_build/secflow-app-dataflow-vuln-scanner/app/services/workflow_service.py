from __future__ import annotations

import uuid
from typing import List, Optional

from fastapi import HTTPException, status
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.config import get_config
from app.models.database import WorkflowDefinition, WorkflowDefinitionVersion
from app.pi_vuln_core.config.models import FrameworkConfig
from app.schemas import (
    ProfileConfigPayload,
    ScanProfileCreateRequest,
    ScanProfileResponse,
    ScanProfileUpdateRequest,
    ScanProfileVersionResponse,
)
from app.services.profile_templates import get_profile_template_service


SUPPORTED_TEMPLATE_KINDS = {"vuln_scan_default", "full_pipeline"}


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

    def _ensure_project_access(self, principal: dict, project_id: str) -> None:
        project_ids = _project_ids(principal)
        if project_ids and project_id not in project_ids:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="project access denied")

    def _get_definition_or_404(self, db: Session, definition_id: str) -> WorkflowDefinition:
        definition = db.get(WorkflowDefinition, definition_id)
        if definition is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="workflow definition not found")
        return definition

    def _get_version_or_404(self, db: Session, definition_id: str, version_no: int) -> WorkflowDefinitionVersion:
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
        return version

    def _infer_template_kind(self, compiled_config: dict) -> str:
        entry = ((compiled_config.get("execution") or {}).get("entry_workflow") or "").strip()
        if entry == "full_vuln_pipeline":
            return "full_pipeline"
        return "vuln_scan_default"

    def _extract_config_payload(self, compiled_config: dict) -> dict:
        agents = compiled_config.get("agents") or []
        worker = next((item for item in agents if item.get("id") == "pi-worker"), {})
        advisor = next((item for item in agents if item.get("id") == "pi-advisor"), {})
        worker_runtime = worker.get("runtime_config") or {}
        advisor_runtime = advisor.get("runtime_config") or {}
        review_profile = "balanced"
        for workflow in ((compiled_config.get("workflows") or {}).get("atomic") or []):
            engine = workflow.get("engine") or {}
            if engine.get("review_profile"):
                review_profile = str(engine.get("review_profile") or "balanced")
                break
        return ProfileConfigPayload(
            model=str(worker_runtime.get("model") or advisor_runtime.get("model") or "legacy/model"),
            review_profile=review_profile,
            max_review_cycles=int(((compiled_config.get("global") or {}).get("max_review_cycles") or 6)),
            worker_timeout=int(worker_runtime.get("timeout_seconds") or 3600),
            advisor_timeout=int(advisor_runtime.get("timeout_seconds") or 3600),
            timeout_max_retries=int(worker_runtime.get("timeout_max_retries") if worker_runtime.get("timeout_max_retries") is not None else advisor_runtime.get("timeout_max_retries") if advisor_runtime.get("timeout_max_retries") is not None else 3),
            timeout_retry_interval_seconds=int(worker_runtime.get("timeout_retry_interval_seconds") if worker_runtime.get("timeout_retry_interval_seconds") is not None else advisor_runtime.get("timeout_retry_interval_seconds") if advisor_runtime.get("timeout_retry_interval_seconds") is not None else 30),
            result_review_concurrency=int(((compiled_config.get("global") or {}).get("parallel_result_review_limit") or 3)),
            runtime_overrides={},
        ).model_dump(mode="json")

    def _latest_version(self, db: Session, definition_id: str) -> Optional[WorkflowDefinitionVersion]:
        return (
            db.query(WorkflowDefinitionVersion)
            .filter(WorkflowDefinitionVersion.workflow_definition_id == definition_id)
            .order_by(WorkflowDefinitionVersion.version_no.desc())
            .first()
        )

    def _latest_definition_config_version(
        self,
        db: Session,
        definition: WorkflowDefinition,
    ) -> Optional[WorkflowDefinitionVersion]:
        target_payload = definition.config_payload_json or self._extract_config_payload(definition.definition_json)
        target_config = definition.definition_json or {}
        items = (
            db.query(WorkflowDefinitionVersion)
            .filter(WorkflowDefinitionVersion.workflow_definition_id == definition.id)
            .order_by(WorkflowDefinitionVersion.version_no.desc())
            .all()
        )
        for item in items:
            item_config = item.compiled_config_json or item.definition_json or {}
            if (item.config_payload_json or {}) == target_payload and item_config == target_config:
                return item
        return items[0] if items else None

    def _ensure_single_default(self, db: Session, definition: WorkflowDefinition) -> None:
        if not definition.is_default:
            existing_default = (
                db.query(WorkflowDefinition)
                .filter(
                    WorkflowDefinition.project_id == definition.project_id,
                    WorkflowDefinition.id != definition.id,
                    WorkflowDefinition.is_default.is_(True),
                )
                .first()
            )
            if existing_default is None:
                definition.is_default = True
            return
        db.query(WorkflowDefinition).filter(
            WorkflowDefinition.project_id == definition.project_id,
            WorkflowDefinition.id != definition.id,
        ).update({WorkflowDefinition.is_default: False}, synchronize_session=False)

    def _create_version_snapshot(
        self,
        db: Session,
        *,
        definition: WorkflowDefinition,
        created_by: str,
        config_payload: dict,
        compiled_config: dict,
    ) -> WorkflowDefinitionVersion:
        current_max = self._latest_version(db, definition.id)
        version = WorkflowDefinitionVersion(
            id=_new_id("wdv"),
            workflow_definition_id=definition.id,
            version_no=1 if current_max is None else current_max.version_no + 1,
            config_payload_json=config_payload,
            compiled_config_json=compiled_config,
            definition_json=compiled_config,
            created_by=created_by,
        )
        db.add(version)
        return version

    def _profile_response(self, db: Session, definition: WorkflowDefinition) -> ScanProfileResponse:
        version = self._latest_definition_config_version(db, definition)
        version_no = version.version_no if version is not None else 0
        config_payload = definition.config_payload_json or self._extract_config_payload(definition.definition_json)
        compiled_config = definition.definition_json or {}
        return ScanProfileResponse(
            profile_id=definition.id,
            project_id=definition.project_id,
            name=definition.name,
            description=definition.description,
            template_kind=definition.template_kind or self._infer_template_kind(compiled_config),
            config_payload=config_payload,
            compiled_config=compiled_config,
            is_default=bool(definition.is_default),
            enabled=bool(definition.enabled),
            default_priority=definition.priority_default,
            max_retry_count=definition.max_retry_count,
            execution_timeout_seconds=definition.execution_timeout_seconds,
            created_by=definition.created_by,
            updated_by=definition.updated_by,
            version=version_no,
            created_at=definition.created_at,
            updated_at=definition.updated_at,
        )

    def _create_bootstrap_profile(self, db: Session, *, project_id: str, actor: str) -> WorkflowDefinition:
        config = get_config()
        template_kind = config.service.default_profile_template_kind or "vuln_scan_default"
        normalized_payload, compiled_config = get_profile_template_service().compile_profile(
            template_kind=template_kind,
            config_payload=None,
        )
        validated = self.validate_definition_payload(compiled_config)
        definition = WorkflowDefinition(
            id=_new_id("wfd"),
            name="默认数据流漏洞挖掘模板",
            description="系统自动创建的默认扫描 Profile",
            project_id=project_id,
            template_kind=template_kind,
            config_payload_json=normalized_payload,
            definition_json=compiled_config,
            root_workflow_id=validated.root_workflow_id,
            trigger_type="manual",
            trigger_enabled=False,
            is_active=True,
            is_default=True,
            enabled=True,
            priority_default=100,
            max_retry_count=config.service.trigger_retry_limit,
            workspace_base_dir=None,
            execution_timeout_seconds=config.service.default_execution_timeout_seconds,
            created_by=actor,
            updated_by=actor,
        )
        db.add(definition)
        self._ensure_single_default(db, definition)
        self._create_version_snapshot(
            db,
            definition=definition,
            created_by=actor,
            config_payload=normalized_payload,
            compiled_config=compiled_config,
        )
        db.commit()
        db.refresh(definition)
        return definition

    def create_profile(self, db: Session, payload: ScanProfileCreateRequest, principal: dict) -> ScanProfileResponse:
        self._ensure_project_access(principal, payload.project_id)
        actor = _principal_id(principal)
        normalized_payload, compiled_config = get_profile_template_service().compile_profile(
            template_kind=payload.template_kind,
            config_payload=payload.config_payload.model_dump(mode="json"),
        )
        validated = self.validate_definition_payload(compiled_config)
        definition = WorkflowDefinition(
            id=_new_id("wfd"),
            name=payload.name,
            description=payload.description,
            project_id=payload.project_id,
            template_kind=payload.template_kind,
            config_payload_json=normalized_payload,
            definition_json=compiled_config,
            root_workflow_id=validated.root_workflow_id,
            trigger_type="manual",
            trigger_enabled=False,
            is_active=True,
            is_default=payload.is_default,
            enabled=payload.enabled,
            priority_default=payload.default_priority,
            max_retry_count=payload.max_retry_count,
            workspace_base_dir=None,
            execution_timeout_seconds=payload.execution_timeout_seconds,
            created_by=actor,
            updated_by=actor,
        )
        db.add(definition)
        self._ensure_single_default(db, definition)
        self._create_version_snapshot(
            db,
            definition=definition,
            created_by=actor,
            config_payload=normalized_payload,
            compiled_config=compiled_config,
        )
        db.commit()
        db.refresh(definition)
        return self._profile_response(db, definition)

    def list_profiles(self, db: Session, principal: dict, project_id: str | None = None) -> List[ScanProfileResponse]:
        project_ids = _project_ids(principal)
        query = db.query(WorkflowDefinition).order_by(WorkflowDefinition.updated_at.desc())
        if project_id:
            self._ensure_project_access(principal, project_id)
            query = query.filter(WorkflowDefinition.project_id == project_id)
        elif project_ids:
            query = query.filter(WorkflowDefinition.project_id.in_(project_ids))
        return [self._profile_response(db, item) for item in query.all()]

    def get_profile(self, db: Session, profile_id: str, principal: dict) -> ScanProfileResponse:
        definition = self._get_definition_or_404(db, profile_id)
        self._ensure_project_access(principal, definition.project_id)
        return self._profile_response(db, definition)

    def update_profile(self, db: Session, profile_id: str, payload: ScanProfileUpdateRequest, principal: dict) -> ScanProfileResponse:
        definition = self._get_definition_or_404(db, profile_id)
        self._ensure_project_access(principal, definition.project_id)
        actor = _principal_id(principal)
        updates = payload.model_dump(exclude_unset=True)

        template_kind = updates.get("template_kind", definition.template_kind or self._infer_template_kind(definition.definition_json))
        config_payload = updates.get("config_payload") or definition.config_payload_json or self._extract_config_payload(definition.definition_json)
        normalized_payload, compiled_config = get_profile_template_service().compile_profile(
            template_kind=template_kind,
            config_payload=config_payload,
        )
        validated = self.validate_definition_payload(compiled_config)

        if "name" in updates:
            definition.name = updates["name"]
        if "description" in updates:
            definition.description = updates["description"]
        if "enabled" in updates:
            definition.enabled = updates["enabled"]
        if "is_default" in updates:
            definition.is_default = updates["is_default"]
        if "default_priority" in updates:
            definition.priority_default = updates["default_priority"]
        if "max_retry_count" in updates:
            definition.max_retry_count = updates["max_retry_count"]
        if "execution_timeout_seconds" in updates:
            definition.execution_timeout_seconds = updates["execution_timeout_seconds"]

        definition.template_kind = template_kind
        definition.config_payload_json = normalized_payload
        definition.definition_json = compiled_config
        definition.root_workflow_id = validated.root_workflow_id
        definition.updated_by = actor
        self._ensure_single_default(db, definition)
        self._create_version_snapshot(
            db,
            definition=definition,
            created_by=actor,
            config_payload=normalized_payload,
            compiled_config=compiled_config,
        )
        db.add(definition)
        db.commit()
        db.refresh(definition)
        return self._profile_response(db, definition)

    def list_profile_versions(self, db: Session, profile_id: str, principal: dict) -> List[ScanProfileVersionResponse]:
        definition = self._get_definition_or_404(db, profile_id)
        self._ensure_project_access(principal, definition.project_id)
        items = (
            db.query(WorkflowDefinitionVersion)
            .filter(WorkflowDefinitionVersion.workflow_definition_id == profile_id)
            .order_by(WorkflowDefinitionVersion.version_no.desc())
            .all()
        )
        return [
            ScanProfileVersionResponse(
                version_id=item.id,
                profile_id=item.workflow_definition_id,
                version=item.version_no,
                config_payload=item.config_payload_json or {},
                compiled_config=item.compiled_config_json or item.definition_json or {},
                created_by=item.created_by,
                created_at=item.created_at,
            )
            for item in items
        ]

    def set_profile_enabled(self, db: Session, profile_id: str, principal: dict, enabled: bool) -> ScanProfileResponse:
        definition = self._get_definition_or_404(db, profile_id)
        self._ensure_project_access(principal, definition.project_id)
        definition.enabled = enabled
        definition.updated_by = _principal_id(principal)
        db.add(definition)
        db.commit()
        db.refresh(definition)
        return self._profile_response(db, definition)

    def set_profile_default(self, db: Session, profile_id: str, principal: dict) -> ScanProfileResponse:
        definition = self._get_definition_or_404(db, profile_id)
        self._ensure_project_access(principal, definition.project_id)
        definition.is_default = True
        definition.updated_by = _principal_id(principal)
        self._ensure_single_default(db, definition)
        db.add(definition)
        db.commit()
        db.refresh(definition)
        return self._profile_response(db, definition)

    def get_default_profile_model(self, db: Session, project_id: str, principal: dict) -> WorkflowDefinition:
        self._ensure_project_access(principal, project_id)
        item = (
            db.query(WorkflowDefinition)
            .filter(
                WorkflowDefinition.project_id == project_id,
                WorkflowDefinition.enabled.is_(True),
            )
            .order_by(WorkflowDefinition.is_default.desc(), WorkflowDefinition.updated_at.desc())
            .first()
        )
        if item is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no scan profile configured for project")
        return item

    def get_or_create_default_profile_model(self, db: Session, project_id: str, principal: dict) -> WorkflowDefinition:
        try:
            return self.get_default_profile_model(db, project_id, principal)
        except HTTPException as exc:
            if exc.status_code != status.HTTP_404_NOT_FOUND or exc.detail != "no scan profile configured for project":
                raise
        actor = _principal_id(principal)
        return self._create_bootstrap_profile(db, project_id=project_id, actor=actor)

    def get_profile_version_model(self, db: Session, profile_id: str, version_no: int | None = None) -> WorkflowDefinitionVersion:
        if version_no is None:
            definition = self._get_definition_or_404(db, profile_id)
            version = self._latest_definition_config_version(db, definition)
            if version is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="profile version not found")
            return version
        return self._get_version_or_404(db, profile_id, version_no)

    def build_task_bound_version(
        self,
        db: Session,
        *,
        definition: WorkflowDefinition,
        principal: dict,
        runtime_overrides: dict | None = None,
        config_payload_overrides: dict | None = None,
    ) -> WorkflowDefinitionVersion:
        actor = _principal_id(principal)
        try:
            latest = self.get_profile_version_model(db, definition.id)
        except HTTPException as exc:
            if exc.status_code != status.HTTP_404_NOT_FOUND:
                raise
            latest = None
        if latest is not None and not runtime_overrides and not config_payload_overrides:
            return latest
        base_payload = definition.config_payload_json or self._extract_config_payload(definition.definition_json)
        merged_payload = dict(base_payload)
        if config_payload_overrides:
            for key, value in config_payload_overrides.items():
                if value is not None:
                    merged_payload[key] = value
        normalized_payload, compiled_config = get_profile_template_service().compile_profile(
            template_kind=definition.template_kind or self._infer_template_kind(definition.definition_json),
            config_payload=merged_payload,
            runtime_overrides=runtime_overrides,
        )
        self.validate_definition_payload(compiled_config)
        version = self._create_version_snapshot(
            db,
            definition=definition,
            created_by=actor,
            config_payload=normalized_payload,
            compiled_config=compiled_config,
        )
        db.flush()
        return version

    def get_effective_project_config(self, db: Session, project_id: str, principal: dict) -> dict:
        profile = self.get_default_profile_model(db, project_id, principal)
        version = self.get_profile_version_model(db, profile.id)
        return {
            "project_id": project_id,
            "default_profile_id": profile.id,
            "effective_config": {
                "profile": self._profile_response(db, profile).model_dump(mode="json"),
                "profile_version": {
                    "version_id": version.id,
                    "version": version.version_no,
                    "config_payload": version.config_payload_json or {},
                    "compiled_config": version.compiled_config_json or version.definition_json or {},
                },
            },
        }

_workflow_service: WorkflowService | None = None


def get_workflow_service() -> WorkflowService:
    global _workflow_service
    if _workflow_service is None:
        _workflow_service = WorkflowService()
    return _workflow_service
