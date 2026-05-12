from __future__ import annotations

import os
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.services.provider_client import ProviderClientError, get_provider_client


@dataclass(frozen=True)
class ResolvedProviderRuntime:
    provider_keys: list[str]
    provider_snapshots: list[dict[str, Any]]
    merged_env: dict[str, str]
    merged_files: list[dict[str, Any]]
    effective_model: str | None


@dataclass(frozen=True)
class ProviderRuntimeMaterialization:
    provider_root: Path
    home_dir: Path
    xdg_config_home: Path
    xdg_data_home: Path
    xdg_cache_home: Path
    xdg_state_home: Path
    mapped_env_keys: list[str]
    mapped_file_paths: list[str]
    rewritten_file_paths: dict[str, str]


class ProviderRuntimeService:
    def normalize_provider_keys(self, provider_keys: list[str] | None) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for item in provider_keys or []:
            value = str(item or "").strip()
            if not value or value in seen:
                continue
            seen.add(value)
            normalized.append(value)
        return normalized

    def list_provider_summaries(self) -> dict[str, Any]:
        payload = get_provider_client().list_providers()
        items = payload.get("items") if isinstance(payload.get("items"), list) else []
        return {
            "total": int(payload.get("total") or len(items)),
            "default_provider_key": payload.get("default_provider_key"),
            "items": [self._build_summary(item) for item in items if isinstance(item, dict)],
        }

    def get_provider_summary(self, provider_key: str) -> dict[str, Any]:
        return self._build_summary(get_provider_client().get_provider_detail(provider_key))

    def resolve_runtime(
        self,
        provider_keys: list[str] | None,
        *,
        explicit_task_model: str | None = None,
        fallback_model: str | None = None,
    ) -> ResolvedProviderRuntime:
        normalized_keys = self.normalize_provider_keys(provider_keys)
        provider_snapshots: list[dict[str, Any]] = []
        merged_env: dict[str, str] = {}
        merged_files_by_path: "OrderedDict[str, dict[str, Any]]" = OrderedDict()
        last_provider_model: str | None = None

        for provider_key in normalized_keys:
            detail = get_provider_client().get_provider_detail(provider_key)
            if detail.get("enabled") is False:
                raise ProviderClientError(f"provider disabled: {provider_key}")
            provider_snapshots.append(self._build_summary(detail))

            model = str(detail.get("model") or "").strip()
            if model:
                last_provider_model = model

            env_bindings = detail.get("env_bindings") if isinstance(detail.get("env_bindings"), dict) else {}
            for env_key, value in env_bindings.items():
                normalized_env_key = str(env_key or "").strip()
                if not normalized_env_key:
                    continue
                merged_env[normalized_env_key] = "" if value is None else str(value)

            for item in self._normalize_file_bindings(detail.get("file_bindings")):
                file_path = str(item.get("path") or "").strip()
                if not file_path:
                    continue
                if file_path in merged_files_by_path:
                    del merged_files_by_path[file_path]
                merged_files_by_path[file_path] = item

        return ResolvedProviderRuntime(
            provider_keys=normalized_keys,
            provider_snapshots=provider_snapshots,
            merged_env=merged_env,
            merged_files=list(merged_files_by_path.values()),
            effective_model=explicit_task_model or last_provider_model or fallback_model or None,
        )

    def materialize_runtime(
        self,
        attempt_runtime_root: Path,
        resolved: ResolvedProviderRuntime | None,
    ) -> ProviderRuntimeMaterialization:
        runtime = resolved or ResolvedProviderRuntime([], [], {}, [], None)
        provider_root = attempt_runtime_root / "provider"
        home_dir = provider_root / "home"
        xdg_config_home = provider_root / "xdg-config"
        xdg_data_home = provider_root / "xdg-data"
        xdg_cache_home = provider_root / "xdg-cache"
        xdg_state_home = provider_root / "xdg-state"
        for path in (home_dir, xdg_config_home, xdg_data_home, xdg_cache_home, xdg_state_home):
            path.mkdir(parents=True, exist_ok=True)

        rewritten_file_paths: dict[str, str] = {}
        for item in runtime.merged_files:
            raw_path = str(item.get("path") or "").strip()
            content = item.get("content")
            target_path = self._rewrite_file_path(
                raw_path,
                home_dir=home_dir,
                xdg_config_home=xdg_config_home,
                xdg_data_home=xdg_data_home,
            )
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_text(str(content or ""), encoding="utf-8")
            rewritten_file_paths[raw_path] = target_path.as_posix()

        return ProviderRuntimeMaterialization(
            provider_root=provider_root,
            home_dir=home_dir,
            xdg_config_home=xdg_config_home,
            xdg_data_home=xdg_data_home,
            xdg_cache_home=xdg_cache_home,
            xdg_state_home=xdg_state_home,
            mapped_env_keys=sorted(runtime.merged_env.keys()),
            mapped_file_paths=sorted(rewritten_file_paths.keys()),
            rewritten_file_paths=rewritten_file_paths,
        )

    def build_process_env(
        self,
        resolved: ResolvedProviderRuntime | None,
        materialized: ProviderRuntimeMaterialization,
    ) -> dict[str, str]:
        runtime = resolved or ResolvedProviderRuntime([], [], {}, [], None)
        env = dict(os.environ)
        env.update(runtime.merged_env)
        env["HOME"] = str(materialized.home_dir)
        env["XDG_CONFIG_HOME"] = str(materialized.xdg_config_home)
        env["XDG_DATA_HOME"] = str(materialized.xdg_data_home)
        env["XDG_CACHE_HOME"] = str(materialized.xdg_cache_home)
        env["XDG_STATE_HOME"] = str(materialized.xdg_state_home)
        return env

    @staticmethod
    def _build_summary(detail: dict[str, Any]) -> dict[str, Any]:
        env_bindings = detail.get("env_bindings") if isinstance(detail.get("env_bindings"), dict) else {}
        file_bindings = ProviderRuntimeService._normalize_file_bindings(detail.get("file_bindings"))
        return {
            "provider_key": str(detail.get("provider_key") or "").strip(),
            "display_name": str(detail.get("display_name") or "").strip(),
            "provider_type": str(detail.get("provider_type") or "").strip(),
            "enabled": bool(detail.get("enabled", True)),
            "is_default": bool(detail.get("is_default", False)),
            "api_base": str(detail.get("api_base") or "").strip(),
            "model": str(detail.get("model") or "").strip(),
            "updated_at": detail.get("updated_at"),
            "mapped_env_keys": sorted(str(key).strip() for key in env_bindings.keys() if str(key).strip()),
            "mapped_file_paths": sorted(
                str(item.get("path") or "").strip()
                for item in file_bindings
                if str(item.get("path") or "").strip()
            ),
        }

    @staticmethod
    def _normalize_file_bindings(raw_bindings: Any) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        if not isinstance(raw_bindings, list):
            return normalized
        for item in raw_bindings:
            if not isinstance(item, dict):
                continue
            if item.get("enabled") is False:
                continue
            name = str(item.get("name") or "").strip()
            path = str(item.get("path") or "").strip()
            if not path:
                continue
            content = item.get("content")
            if content is None:
                continue
            normalized.append(
                {
                    "name": name or Path(path).name,
                    "path": path,
                    "content": str(content),
                    "format": str(item.get("format") or "other").strip() or "other",
                    "enabled": True,
                }
            )
        return normalized

    @staticmethod
    def _rewrite_file_path(
        raw_path: str,
        *,
        home_dir: Path,
        xdg_config_home: Path,
        xdg_data_home: Path,
    ) -> Path:
        normalized = str(raw_path or "").strip()
        if normalized.startswith("/root/.codex/"):
            return home_dir / ".codex" / normalized[len("/root/.codex/") :]
        if normalized.startswith("/root/.config/opencode/"):
            return xdg_config_home / "opencode" / normalized[len("/root/.config/opencode/") :]
        if normalized.startswith("/root/.local/share/opencode/"):
            return xdg_data_home / "opencode" / normalized[len("/root/.local/share/opencode/") :]
        raise ProviderClientError(f"unsupported provider file binding path: {raw_path}")


_provider_runtime_service: ProviderRuntimeService | None = None


def get_provider_runtime_service() -> ProviderRuntimeService:
    global _provider_runtime_service
    if _provider_runtime_service is None:
        _provider_runtime_service = ProviderRuntimeService()
    return _provider_runtime_service
