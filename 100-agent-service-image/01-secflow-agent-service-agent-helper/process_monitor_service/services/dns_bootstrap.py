from __future__ import annotations

import ipaddress
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from process_monitor_service.config import settings


def _parse_dns_servers(raw_value: str) -> tuple[list[str], list[str]]:
    valid: list[str] = []
    invalid: list[str] = []
    seen: set[str] = set()
    for token in re.split(r"[,\s;]+", str(raw_value or "").strip()):
        item = token.strip()
        if not item:
            continue
        try:
            parsed = ipaddress.ip_address(item)
            normalized = str(parsed)
        except ValueError:
            invalid.append(item)
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        valid.append(normalized)
    return valid, invalid


def _extract_nameservers(lines: list[str]) -> list[str]:
    servers: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            servers.append(parts[1])
    return servers


def _read_resolv_conf(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        return []
    return text.splitlines()


def _write_resolv_conf_atomic(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(lines).rstrip("\n") + "\n"
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=str(path.parent),
        prefix=".resolv.conf.",
        delete=False,
    ) as tmp_file:
        tmp_file.write(content)
        tmp_name = tmp_file.name
    os.replace(tmp_name, path)


def bootstrap_dns() -> dict[str, Any]:
    resolv_path = Path(settings.resolv_conf_path or "/etc/resolv.conf")
    configured_dns = str(settings.dns_server or "").strip()
    before_lines = _read_resolv_conf(resolv_path)
    before_servers = _extract_nameservers(before_lines)
    valid_servers, invalid_servers = _parse_dns_servers(configured_dns)

    result: dict[str, Any] = {
        "configured_dns_server": configured_dns,
        "dns_servers_before": before_servers,
        "dns_servers_after": before_servers,
        "dns_override_applied": False,
        "resolv_conf_path": str(resolv_path),
        "invalid_dns_entries": invalid_servers,
    }

    if not configured_dns:
        result["reason"] = "dns_server_not_configured"
        return result
    if not valid_servers:
        result["reason"] = "dns_server_has_no_valid_ip"
        return result

    preserved_lines = []
    for line in before_lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and stripped.split()[0] == "nameserver":
            continue
        preserved_lines.append(line)
    next_lines = [f"nameserver {server}" for server in valid_servers] + preserved_lines
    try:
        _write_resolv_conf_atomic(resolv_path, next_lines)
    except Exception as exc:
        result["reason"] = "dns_override_failed"
        result["error"] = str(exc)
        return result

    after_lines = _read_resolv_conf(resolv_path)
    result["dns_servers_after"] = _extract_nameservers(after_lines)
    result["dns_override_applied"] = True
    result["reason"] = "dns_override_applied"
    return result
