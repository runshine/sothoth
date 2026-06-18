from __future__ import annotations

from typing import Any, Optional
from urllib.parse import urlsplit

from app.config import get_config
from app.exception import ValidationError
from app.service.downstream_base import JsonHttpClient


class KnowledgeGraphEntriesClient(JsonHttpClient):
    def __init__(self) -> None:
        cfg = get_config().services.knowledge_graph_entries
        super().__init__(base_url=cfg.base_url.rstrip("/"), timeout=int(cfg.timeout_seconds or 60))
        self._default_entries_path = str(cfg.entries_path or "/api/v1/sources/entries").strip() or "/api/v1/sources/entries"

    def _validate_override_url(self, url: str) -> tuple[str, str]:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValidationError(f"knowledge_graph_entries_url 非法: {url!r}")
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return base_url, path

    async def list_entries(
        self,
        *,
        override_url: str | None = None,
    ) -> dict[str, Any]:
        if not override_url:
            return await self.get(self._default_entries_path)
        base_url, path = self._validate_override_url(str(override_url).strip())
        client = JsonHttpClient(base_url=base_url, timeout=self.timeout)
        return await client.get(path)


_client: Optional[KnowledgeGraphEntriesClient] = None


def get_knowledge_graph_entries_client() -> KnowledgeGraphEntriesClient:
    global _client
    if _client is None:
        _client = KnowledgeGraphEntriesClient()
    return _client
