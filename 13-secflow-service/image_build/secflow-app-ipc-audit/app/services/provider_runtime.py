from __future__ import annotations

import json
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
    effective_model: str | None = None
    executor_model: str | None = None


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
        executor_mode: str | None = None,
        explicit_task_model: str | None = None,
        fallback_model: str | None = None,
    ) -> ResolvedProviderRuntime:
        normalized_keys = self.normalize_provider_keys(provider_keys)
        provider_snapshots: list[dict[str, Any]] = []
        merged_env: dict[str, str] = {}
        merged_files_by_path: "OrderedDict[str, dict[str, Any]]" = OrderedDict()
        last_provider_model: str | None = None
        effective_provider_fields: dict[str, str] = {}

        for provider_key in normalized_keys:
            detail = get_provider_client().get_provider_detail(provider_key)
            if detail.get("enabled") is False:
                raise ProviderClientError(f"provider disabled: {provider_key}")
            provider_snapshots.append(self._build_summary(detail))
            effective_provider_fields.update(self._extract_provider_runtime_fields(detail))

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

        effective_model = explicit_task_model or last_provider_model or fallback_model or None
        if effective_model:
            effective_provider_fields["model"] = effective_model
        self._normalize_executor_files(
            merged_files_by_path,
            executor_mode=executor_mode,
            provider_fields=effective_provider_fields,
            effective_model=effective_model,
        )
        has_opencode_config = "/root/.config/opencode/opencode.json" in merged_files_by_path
        executor_model = self._build_executor_model(
            executor_mode=executor_mode,
            provider_fields=effective_provider_fields,
            effective_model=effective_model,
            has_executor_config=has_opencode_config,
        )
        self._apply_generated_env_bindings(merged_env, effective_provider_fields)
        self._apply_executor_generated_files(
            merged_files_by_path,
            executor_mode=executor_mode,
            provider_fields=effective_provider_fields,
        )

        return ResolvedProviderRuntime(
            provider_keys=normalized_keys,
            provider_snapshots=provider_snapshots,
            merged_env=merged_env,
            merged_files=list(merged_files_by_path.values()),
            effective_model=effective_model,
            executor_model=executor_model,
        )

    def materialize_runtime(
        self,
        attempt_runtime_root: Path,
        resolved: ResolvedProviderRuntime | None,
    ) -> ProviderRuntimeMaterialization:
        runtime = resolved or ResolvedProviderRuntime([], [], {}, [], None, None)
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
        runtime = resolved or ResolvedProviderRuntime([], [], {}, [], None, None)
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

    @staticmethod
    def _normalize_provider_type(value: Any) -> str:
        return str(value or "").strip().lower().replace("_", "-")

    @classmethod
    def _default_api_key_env_key(cls, provider_type: str) -> str:
        normalized = cls._normalize_provider_type(provider_type)
        if normalized == "anthropic":
            return "ANTHROPIC_API_KEY"
        return "OPENAI_API_KEY"

    @classmethod
    def _default_api_base_env_key(cls, provider_type: str) -> str:
        normalized = cls._normalize_provider_type(provider_type)
        if normalized == "anthropic":
            return "ANTHROPIC_BASE_URL"
        return "OPENAI_BASE_URL"

    @classmethod
    def _extract_provider_runtime_fields(cls, detail: dict[str, Any]) -> dict[str, str]:
        provider_type = cls._normalize_provider_type(detail.get("provider_type"))
        env_bindings = detail.get("env_bindings") if isinstance(detail.get("env_bindings"), dict) else {}
        api_key = str(detail.get("api_key") or "").strip()
        if not api_key:
            api_key = str(env_bindings.get(cls._default_api_key_env_key(provider_type)) or "").strip()
        api_base = str(detail.get("api_base") or "").strip()
        if not api_base:
            api_base = str(env_bindings.get(cls._default_api_base_env_key(provider_type)) or "").strip()
        return {
            "provider_key": str(detail.get("provider_key") or "").strip(),
            "display_name": str(detail.get("display_name") or "").strip(),
            "provider_type": provider_type,
            "api_base": api_base,
            "api_key": api_key,
            "model": str(detail.get("model") or "").strip(),
        }

    @classmethod
    def _apply_generated_env_bindings(
        cls,
        merged_env: dict[str, str],
        provider_fields: dict[str, str],
    ) -> None:
        provider_type = cls._normalize_provider_type(provider_fields.get("provider_type"))
        api_key = str(provider_fields.get("api_key") or "").strip()
        api_base = str(provider_fields.get("api_base") or "").strip()
        if api_key:
            merged_env.setdefault(cls._default_api_key_env_key(provider_type), api_key)
        if api_base:
            merged_env.setdefault(cls._default_api_base_env_key(provider_type), api_base)

    @classmethod
    def _normalize_executor_files(
        cls,
        merged_files_by_path: "OrderedDict[str, dict[str, Any]]",
        *,
        executor_mode: str | None,
        provider_fields: dict[str, str],
        effective_model: str | None,
    ) -> None:
        normalized_mode = str(executor_mode or "").strip().lower()
        if not cls._has_provider_source_fields(provider_fields):
            return
        if normalized_mode == "codex_cli":
            file_path = "/root/.codex/config.toml"
            item = merged_files_by_path.get(file_path)
            if item is not None and not cls._is_codex_config_usable(item.get("content"), expected_model=effective_model):
                del merged_files_by_path[file_path]
            return
        if normalized_mode == "opencode_cli":
            file_path = "/root/.config/opencode/opencode.json"
            item = merged_files_by_path.get(file_path)
            expected_executor_model = cls._build_executor_model(
                executor_mode="opencode_cli",
                provider_fields=provider_fields,
                effective_model=effective_model,
                has_executor_config=False,
            )
            if item is not None and not cls._is_opencode_config_usable(
                item.get("content"),
                expected_executor_model=expected_executor_model,
            ):
                del merged_files_by_path[file_path]

    @classmethod
    def _apply_executor_generated_files(
        cls,
        merged_files_by_path: "OrderedDict[str, dict[str, Any]]",
        *,
        executor_mode: str | None,
        provider_fields: dict[str, str],
    ) -> None:
        normalized_mode = str(executor_mode or "").strip().lower()
        if normalized_mode == "codex_cli":
            for item in cls._build_codex_generated_files(provider_fields):
                cls._add_generated_file_if_missing(merged_files_by_path, item)
            return
        if normalized_mode == "opencode_cli":
            for item in cls._build_opencode_generated_files(provider_fields):
                cls._add_generated_file_if_missing(merged_files_by_path, item)

    @staticmethod
    def _add_generated_file_if_missing(
        merged_files_by_path: "OrderedDict[str, dict[str, Any]]",
        item: dict[str, Any],
    ) -> None:
        file_path = str(item.get("path") or "").strip()
        if not file_path or file_path in merged_files_by_path:
            return
        merged_files_by_path[file_path] = item

    @staticmethod
    def _sanitize_provider_alias(raw_value: str | None) -> str:
        value = "".join(
            char if char.isalnum() or char == "_" else "_"
            for char in str(raw_value or "").strip()
        ).strip("_")
        return value or "ipc_audit_provider"

    @staticmethod
    def _json_string(value: str) -> str:
        return json.dumps(str(value), ensure_ascii=False)

    @staticmethod
    def _extract_codex_config_model(content: Any) -> str | None:
        for raw_line in str(content or "").splitlines():
            stripped = raw_line.strip()
            if not stripped.startswith("model ="):
                continue
            _, _, value = stripped.partition("=")
            normalized = value.strip().strip('"').strip("'")
            return normalized or None
        return None

    @classmethod
    def _is_codex_config_usable(cls, content: Any, *, expected_model: str | None) -> bool:
        text = str(content or "")
        if not text.strip():
            return False
        if 'wire_api = "chat"' in text or "wire_api = 'chat'" in text:
            return False
        if expected_model:
            configured_model = cls._extract_codex_config_model(text)
            if configured_model and configured_model != expected_model:
                return False
        return True

    @staticmethod
    def _is_opencode_config_usable(content: Any, *, expected_executor_model: str | None) -> bool:
        try:
            payload = json.loads(str(content or ""))
        except json.JSONDecodeError:
            return False
        if not isinstance(payload, dict):
            return False
        providers = payload.get("provider")
        if not isinstance(providers, dict) or not providers:
            return False
        model = str(payload.get("model") or "").strip()
        if expected_executor_model and model and model != expected_executor_model:
            return False
        return True

    @classmethod
    def _preferred_provider_alias(cls, provider_fields: dict[str, str]) -> str:
        model = str(provider_fields.get("model") or "").strip()
        if "/" in model:
            model_prefix = model.split("/", 1)[0].strip()
            if model_prefix:
                return cls._sanitize_provider_alias(model_prefix)
        return cls._sanitize_provider_alias(
            provider_fields.get("provider_key") or provider_fields.get("provider_type") or "ipc_audit_provider"
        )

    @classmethod
    def _default_provider_alias(cls, provider_fields: dict[str, str]) -> str:
        return cls._sanitize_provider_alias(
            provider_fields.get("provider_key") or provider_fields.get("provider_type") or "ipc_audit_provider"
        )

    @classmethod
    def _opencode_provider_alias(cls, provider_fields: dict[str, str]) -> str:
        provider_type = cls._normalize_provider_type(provider_fields.get("provider_type"))
        if provider_type in {"openai", "anthropic"}:
            model = str(provider_fields.get("model") or "").strip()
            if "/" in model:
                model_prefix = model.split("/", 1)[0].strip()
                if model_prefix:
                    return cls._sanitize_provider_alias(model_prefix)
            return cls._sanitize_provider_alias(provider_type)
        return cls._default_provider_alias(provider_fields)

    @classmethod
    def _opencode_model_id(cls, provider_fields: dict[str, str]) -> str:
        model = str(provider_fields.get("model") or "").strip()
        provider_type = cls._normalize_provider_type(provider_fields.get("provider_type"))
        if provider_type in {"openai", "anthropic"} and "/" in model:
            return model.split("/", 1)[1].strip()
        return model

    @classmethod
    def _has_provider_source_fields(cls, provider_fields: dict[str, str]) -> bool:
        for key in ("provider_key", "provider_type", "display_name", "api_base", "api_key"):
            if str(provider_fields.get(key) or "").strip():
                return True
        return False

    @classmethod
    def _build_executor_model(
        cls,
        *,
        executor_mode: str | None,
        provider_fields: dict[str, str],
        effective_model: str | None,
        has_executor_config: bool,
    ) -> str | None:
        model = str(effective_model or provider_fields.get("model") or "").strip()
        if not model:
            return None
        if str(executor_mode or "").strip().lower() != "opencode_cli":
            return model
        if has_executor_config or not cls._has_provider_source_fields(provider_fields):
            return model
        provider_fields_for_model = dict(provider_fields)
        provider_fields_for_model["model"] = model
        provider_alias = cls._opencode_provider_alias(provider_fields_for_model)
        model_id = cls._opencode_model_id(provider_fields_for_model)
        if not provider_alias or not model_id:
            return model
        candidate = f"{provider_alias}/{model_id}"
        return candidate or model

    @classmethod
    def _build_codex_generated_files(cls, provider_fields: dict[str, str]) -> list[dict[str, Any]]:
        provider_type = cls._normalize_provider_type(provider_fields.get("provider_type"))
        provider_alias = cls._preferred_provider_alias(provider_fields)
        provider_name = (
            str(provider_fields.get("display_name") or "").strip()
            or str(provider_fields.get("provider_key") or "").strip()
            or str(provider_fields.get("provider_type") or "").strip()
            or provider_alias
        )
        model = str(provider_fields.get("model") or "").strip()
        api_base = str(provider_fields.get("api_base") or "").strip()
        api_key = str(provider_fields.get("api_key") or "").strip()
        api_key_env = cls._default_api_key_env_key(provider_type)
        items: list[dict[str, Any]] = []

        if api_key:
            items.append(
                {
                    "name": "generated-auth.json",
                    "path": "/root/.codex/auth.json",
                    "content": json.dumps({api_key_env: api_key}, ensure_ascii=False, indent=2) + "\n",
                    "format": "json",
                    "enabled": True,
                }
            )

        config_lines: list[str] = []
        if model:
            config_lines.append(f"model = {cls._json_string(model)}")
        config_lines.append(f"model_provider = {cls._json_string(provider_alias)}")
        config_lines.append("")
        config_lines.append(f"[model_providers.{provider_alias}]")
        config_lines.append(f"name = {cls._json_string(provider_name)}")
        if api_base:
            config_lines.append(f"base_url = {cls._json_string(api_base)}")
        config_lines.append(f"env_key = {cls._json_string(api_key_env)}")
        if provider_type != "anthropic":
            config_lines.append('wire_api = "responses"')
        items.append(
            {
                "name": "generated-config.toml",
                "path": "/root/.codex/config.toml",
                "content": "\n".join(config_lines).strip() + "\n",
                "format": "toml",
                "enabled": True,
            }
        )
        return items

    @classmethod
    def _build_opencode_generated_files(cls, provider_fields: dict[str, str]) -> list[dict[str, Any]]:
        provider_type = cls._normalize_provider_type(provider_fields.get("provider_type"))
        if not cls._has_provider_source_fields(provider_fields):
            return []
        provider_alias = cls._opencode_provider_alias(provider_fields)
        model = str(provider_fields.get("model") or "").strip()
        api_base = str(provider_fields.get("api_base") or "").strip()
        api_key = str(provider_fields.get("api_key") or "").strip()
        model_id = cls._opencode_model_id(provider_fields)

        provider_config: dict[str, Any] = {
            "name": "anthropic" if provider_type == "anthropic" else provider_alias,
        }
        if provider_type == "openai":
            provider_config["npm"] = "@ai-sdk/openai"
            provider_config["name"] = "openai"
        elif provider_type == "anthropic":
            provider_config["name"] = "anthropic"
        else:
            provider_config["npm"] = "@ai-sdk/openai-compatible"

        options: dict[str, Any] = {}
        if api_base:
            options["baseURL"] = api_base
        if api_key:
            options["apiKey"] = api_key
        if options:
            provider_config["options"] = options
        if model_id:
            provider_config["models"] = {
                model_id: {
                    "id": model_id,
                    "name": model_id,
                }
            }

        payload: dict[str, Any] = {
            "$schema": "https://opencode.ai/config.json",
            "provider": {
                provider_alias: provider_config,
            },
        }
        if model_id:
            payload["model"] = f"{provider_alias}/{model_id}"

        return [
            {
                "name": "generated-opencode.json",
                "path": "/root/.config/opencode/opencode.json",
                "content": json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                "format": "json",
                "enabled": True,
            }
        ]


_provider_runtime_service: ProviderRuntimeService | None = None


def get_provider_runtime_service() -> ProviderRuntimeService:
    global _provider_runtime_service
    if _provider_runtime_service is None:
        _provider_runtime_service = ProviderRuntimeService()
    return _provider_runtime_service
