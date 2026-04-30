"""Per-project analysis config CRUD service."""

from __future__ import annotations

from typing import Any, Dict

from sqlalchemy.orm import Session

from app.model import SystemAnalysisProjectConfig
from app.schemas import AnalysisServiceConfigRequest, AnalysisServiceConfigResponse, StagesConfigSchema


_DEFAULT_CONFIG: Dict[str, Any] = {
    "analyse_targets": ["all"],
    "binary_arch": ["all"],
    "parallel_modules": 1,
    "parallel_sub_workers": 1,
    "agent_max_retries": 100,
    "agent_retry_delay": 30,
    "pi_max_retries": -1,
    "pi_retry_delay": 10,
    "stages": {
        "classify": {"min_rounds": 2, "max_rounds": 5, "pass_mode": "majority"},
        "refine": {"min_rounds": 2, "max_rounds": 3, "pass_mode": "majority"},
        "analyse": {"min_rounds": 2, "max_rounds": 5, "pass_mode": "majority"},
        "final_check": {"min_rounds": 1, "max_rounds": 1, "pass_mode": "all"},
    },
    "workers": {"default_tools": ["read", "bash", "edit", "write"], "system_prompt_dir": "./prompts/workers", "default_thinking_level": "off", "agents": [], "stage_models": {}},
    "judges": {"default_tools": ["read", "bash", "edit", "write"], "system_prompt_dir": "./prompts/judges", "default_thinking_level": "off", "agents": [], "stage_models": {}},
    "output_dir": "/data/output",
    "archive_dir": "/data/output",
    "result_dir": "/data/output",
    "start_stage": 1,
    "resume_workspace": "",
}


class ConfigService:
    def get_config(self, db: Session, project_id: str) -> AnalysisServiceConfigResponse:
        row = db.query(SystemAnalysisProjectConfig).filter_by(project_id=project_id).first()
        if row and row.config_json:
            data = {**_DEFAULT_CONFIG, **row.config_json, "project_id": project_id}
            resp = AnalysisServiceConfigResponse.model_validate(data)
            resp.updated_at = row.updated_at
            return resp
        return AnalysisServiceConfigResponse.model_validate({**_DEFAULT_CONFIG, "project_id": project_id})

    def save_config(self, db: Session, payload: AnalysisServiceConfigRequest) -> AnalysisServiceConfigResponse:
        config_data = payload.model_dump(exclude={"project_id"})
        row = db.query(SystemAnalysisProjectConfig).filter_by(project_id=payload.project_id).first()
        if row:
            row.config_json = config_data
        else:
            row = SystemAnalysisProjectConfig(project_id=payload.project_id, config_json=config_data)
            db.add(row)
        db.commit()
        db.refresh(row)
        resp = AnalysisServiceConfigResponse.model_validate({**config_data, "project_id": payload.project_id})
        resp.updated_at = row.updated_at
        return resp


_config_service: ConfigService | None = None


def get_config_service() -> ConfigService:
    global _config_service
    if _config_service is None:
        _config_service = ConfigService()
    return _config_service
