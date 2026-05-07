#!/usr/bin/env python3

import json
import os
import shutil
import sys
from pathlib import Path

import json5


DEFAULT_PASSWORD = "Huawei12#$"


def ensure_dict(parent, key):
    value = parent.get(key)
    if isinstance(value, dict):
        return value
    value = {}
    parent[key] = value
    return value


def parse_allowed_origins(raw_value):
    if raw_value is None:
        return None
    origins = []
    for chunk in raw_value.replace(";", ",").replace("\n", ",").split(","):
        value = chunk.strip()
        if value:
            origins.append(value)
    return list(dict.fromkeys(origins))


def copy_seed_tree(source_dir, target_dir):
    if not source_dir.exists():
        return
    target_dir.mkdir(parents=True, exist_ok=True)
    for item in source_dir.iterdir():
        destination = target_dir / item.name
        if destination.exists():
            continue
        if item.is_dir():
            shutil.copytree(item, destination)
        else:
            shutil.copy2(item, destination)


def load_config(config_path):
    if not config_path.exists():
        return {}
    try:
        with config_path.open("r", encoding="utf-8") as handle:
            content = handle.read().strip()
        if not content:
            return {}
        data = json5.loads(content)
        if isinstance(data, dict):
            return data
        raise ValueError("root config is not an object")
    except Exception as exc:
        raise RuntimeError(f"failed to parse {config_path}: {exc}") from exc


def save_config(config_path, config):
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with config_path.open("w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2, ensure_ascii=True)
        handle.write("\n")


def main():
    seed_dir = Path(os.getenv("OPENCLAW_SEED_DIR", "/app/openclaw-seed"))
    state_seed_dir = seed_dir / "state"
    workspace_seed_dir = seed_dir / "workspace"

    state_dir = Path(os.getenv("OPENCLAW_STATE_DIR", "/app/data/openclaw"))
    config_path = Path(os.getenv("OPENCLAW_CONFIG_PATH", str(state_dir / "openclaw.json")))
    workspace_dir = Path(os.getenv("OPENCLAW_WORKSPACE_DIR", "/host"))
    gateway_port = int(os.getenv("OPENCLAW_GATEWAY_PORT", "20005"))
    password = os.getenv("OPENCLAW_GATEWAY_PASSWORD", "").strip() or DEFAULT_PASSWORD
    allowed_origins = parse_allowed_origins(os.getenv("OPENCLAW_CONTROL_UI_ALLOWED_ORIGINS"))

    state_dir.mkdir(parents=True, exist_ok=True)
    copy_seed_tree(state_seed_dir, state_dir)

    if not config_path.exists():
        seed_config = state_seed_dir / "openclaw.json"
        if seed_config.exists():
            shutil.copy2(seed_config, config_path)

    if str(workspace_dir) != "/host":
        if not workspace_dir.exists():
            copy_seed_tree(workspace_seed_dir, workspace_dir)
        workspace_dir.mkdir(parents=True, exist_ok=True)

    config = load_config(config_path)

    gateway = ensure_dict(config, "gateway")
    gateway["mode"] = "local"
    gateway["bind"] = "lan"
    gateway["port"] = gateway_port

    auth = ensure_dict(gateway, "auth")
    auth["mode"] = "password"
    auth["password"] = password
    auth.pop("token", None)

    control_ui = ensure_dict(gateway, "controlUi")
    control_ui["enabled"] = True
    if allowed_origins:
        control_ui["allowedOrigins"] = allowed_origins
        control_ui["dangerouslyAllowHostHeaderOriginFallback"] = False
    elif isinstance(control_ui.get("allowedOrigins"), list) and any(str(item).strip() for item in control_ui["allowedOrigins"]):
        control_ui["allowedOrigins"] = [str(item).strip() for item in control_ui["allowedOrigins"] if str(item).strip()]
        control_ui.setdefault("dangerouslyAllowHostHeaderOriginFallback", False)
    else:
        control_ui["dangerouslyAllowHostHeaderOriginFallback"] = True

    agents = ensure_dict(config, "agents")
    defaults = ensure_dict(agents, "defaults")
    defaults["workspace"] = str(workspace_dir)

    save_config(config_path, config)

    print(f"OpenClaw state dir: {state_dir}")
    print(f"OpenClaw config path: {config_path}")
    print(f"OpenClaw workspace dir: {workspace_dir}")
    print(f"OpenClaw gateway port: {gateway_port}")
    print("OpenClaw auth mode: password")
    print("OpenClaw bind mode: lan")
    if allowed_origins:
        print(f"OpenClaw allowed origins count: {len(allowed_origins)}")
    elif isinstance(control_ui.get('allowedOrigins'), list) and control_ui["allowedOrigins"]:
        print(f"OpenClaw preserved allowed origins count: {len(control_ui['allowedOrigins'])}")
    else:
        print("OpenClaw control UI origin policy: host-header fallback")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"OpenClaw bootstrap failed: {exc}", file=sys.stderr)
        sys.exit(1)
