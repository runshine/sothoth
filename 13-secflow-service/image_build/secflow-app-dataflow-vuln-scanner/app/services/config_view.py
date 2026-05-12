from __future__ import annotations

from typing import Any

from app.artifacts.io import sanitize_name
from app.config import get_config
from app.services.profile_templates import get_profile_template_service

REDACTED_KEYS = {"password", "token", "secret", "api_key", "authorization"}


def _should_redact(key: str | None) -> bool:
    if not key:
        return False
    lowered = key.lower()
    return any(marker in lowered for marker in REDACTED_KEYS)


def _redact(value: Any, key: str | None = None) -> Any:
    if isinstance(value, dict):
        return {
            item_key: ("***" if _should_redact(item_key) else _redact(item_value, item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [_redact(item, key) for item in value]
    if _should_redact(key) and value not in (None, ""):
        return "***"
    return value


def build_sanitized_service_config() -> dict[str, Any]:
    config = get_config()
    payload = config.model_dump(mode="json")
    agent_storage = _build_agent_storage_view()
    return {
        "service_name": config.registry.service_name,
        "api_prefix": config.service.public_api_prefix,
        "agent_storage": agent_storage,
        "config": _redact(payload),
    }


def _build_agent_storage_view() -> dict[str, Any]:
    config = get_config()
    template_kind = str(config.service.default_profile_template_kind or "vuln_scan_default").strip() or "vuln_scan_default"
    try:
        _, compiled = get_profile_template_service().compile_profile(
            template_kind=template_kind,
            config_payload=None,
            runtime_overrides=None,
        )
        agents = compiled.get("agents") or []
    except Exception:
        agents = []

    project_files_dir = str(config.fileserver_service.project_files_dirname or "files").strip().strip("/")
    subproject = sanitize_name(str(config.fileserver_service.dataflow_subproject_name or "DATAFLOW_VULN_SCANNER"))
    base_template = f"/{project_files_dir}" + "/{project_id}/" + f"{subproject}/agent-state/shared"
    items: list[dict[str, Any]] = []
    for agent in agents:
        if not isinstance(agent, dict):
            continue
        agent_id = str(agent.get("id") or "").strip()
        if not agent_id:
            continue
        agent_key = sanitize_name(agent_id)
        root_template = f"{base_template}/{agent_key}"
        items.append(
            {
                "agent_id": agent_id,
                "root_dir_template": root_template,
                "skills_dir_template": f"{root_template}/skills",
                "memory_dir_template": f"{root_template}/memory",
                "source": "shared_default",
            }
        )

    return {
        "mode": "project_scoped_shared_pvc",
        "project_id_placeholder": "{project_id}",
        "shared_root_template": base_template,
        "agents": items,
    }
