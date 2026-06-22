from __future__ import annotations

from typing import Any, Optional

from app.config import get_config
from app.service.downstream_base import JsonHttpClient


class KnowledgeGraphAuditClient(JsonHttpClient):
    def __init__(self) -> None:
        cfg = get_config().services.knowledge_graph_audit
        super().__init__(base_url=cfg.base_url.rstrip("/"), timeout=int(cfg.timeout_seconds or 60))
        self._cfg = cfg

    async def get_sources(
        self,
        *,
        upload_id: str | None = None,
        db_name: str | None = None,
        status_filter: str | None = None,
        include_excluded: bool | None = None,
        kind: str | None = None,
        module: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "status": str(status_filter or self._cfg.default_status_filter or "identified").strip() or "identified",
            "include_excluded": "true" if bool(self._cfg.default_include_excluded if include_excluded is None else include_excluded) else "false",
        }
        if kind:
            params["kind"] = str(kind).strip()
        if module is not None:
            params["module"] = str(module)
        if upload_id:
            path = self._cfg.upload_sources_path_template.format(upload_id=str(upload_id).strip())
        else:
            path = self._cfg.project_sources_path_template.format(db_name=str(db_name or "").strip())
        return await self.get(path, params=params)


_client: Optional[KnowledgeGraphAuditClient] = None


def get_knowledge_graph_audit_client() -> KnowledgeGraphAuditClient:
    global _client
    if _client is None:
        _client = KnowledgeGraphAuditClient()
    return _client
