from __future__ import annotations

import os


def _env_value(name: str, default: str) -> str:
    value = str(os.environ.get(name) or "").strip()
    return value or default


def build_poc_qemu_instance_name(task_id: str) -> str:
    raw = str(task_id or "").replace("ipc-audit-task-", "")
    safe = "".join(ch if ch.isalnum() or ch == "-" else "-" for ch in raw).strip("-")
    return f"ipc-audit-{(safe or 'task')[:20]}"


def build_in_container_qemu_runtime(instance_name: str) -> dict[str, str]:
    hdc_bin = _env_value("HDC_BIN", "/workspace/openharmony_6_1/vendor/edu/docker/src/hdc")
    helper_bin = _env_value("OHEMU_HELPER_BIN", "/usr/local/bin/ipc-audit-qemu")
    workspace_root = _env_value("OHEMU_WORKSPACE_ROOT", "/workspace/openharmony_6_1")
    qcow2_root = _env_value(
        "OHEMU_QCOW2_PREPARED_ROOT",
        f"{workspace_root}/vendor/edu/docker/volumes/qcow2_cache",
    )
    runtime_root = _env_value("OHEMU_RUNTIME_ROOT", "/var/lib/secflow-ipc-audit/ohemu")
    arch = _env_value("OHEMU_ARCH", "arm64")
    network_mode = _env_value("OHEMU_NETWORK_MODE", "bridge")
    hdc_bind = _env_value("OHEMU_HDC_BIND", "127.0.0.1")
    hdc_port = _env_value("OHEMU_HDC_BASE_PORT", "55555")
    boot_dir = _env_value("OHEMU_BOOT_DIR", f"{qcow2_root}/{arch}/boot")
    ohemu_src = _env_value("OHEMU_SRC_DIR", f"{workspace_root}/vendor/edu/docker/src")
    return {
        "instance_name": instance_name,
        "hdc_bin": hdc_bin,
        "helper_bin": helper_bin,
        "workspace_root": workspace_root,
        "qcow2_root": qcow2_root,
        "runtime_root": runtime_root,
        "overlay_root": f"{runtime_root}/runtime/instances/{instance_name}",
        "arch": arch,
        "network_mode": network_mode,
        "hdc_bind": hdc_bind,
        "hdc_port": hdc_port,
        "boot_dir": boot_dir,
        "ohemu_src": ohemu_src,
    }


def build_in_container_qemu_prompt(instance_name: str) -> str:
    runtime = build_in_container_qemu_runtime(instance_name)
    helper_bin = runtime["helper_bin"]
    hdc_bin = runtime["hdc_bin"]
    hdc_bind = runtime["hdc_bind"]
    return "\n".join(
        [
            "Container PoC runtime rules:",
            "- You are already inside the secflow-app-ipc-audit container.",
            "- Do not start an additional service/OHEMU Docker container. Do not call ohemu-container.sh, docker run, docker exec, or docker compose.",
            f"- Use the in-container QEMU helper: {helper_bin}",
            f"- The helper sources OpenHarmony QEMU scripts from: {runtime['ohemu_src']}",
            f"- OpenHarmony workspace root: {runtime['workspace_root']}",
            f"- Prepared qcow2 root: {runtime['qcow2_root']}",
            f"- Default boot dir: {runtime['boot_dir']}",
            f"- QEMU runtime/state root: {runtime['runtime_root']}",
            f"- Per-task overlay disk root: {runtime['overlay_root']}",
            f"- Default QEMU arch/network: {runtime['arch']}/{runtime['network_mode']}",
            f"- Default HDC endpoint in this container: {hdc_bind}:{runtime['hdc_port']}",
            f"- HDC binary: {hdc_bin}",
            f"- Preferred instance name for this task: {runtime['instance_name']}",
            "",
            "Use these commands when runtime testing is needed:",
            f"  {helper_bin} list",
            f"  {helper_bin} ensure {runtime['instance_name']}",
            f"  {hdc_bin} tconn {hdc_bind}:<HDC_PORT_FROM_HELPER_LIST>",
            f"  {hdc_bin} list targets",
            "",
            "Network rules:",
            f"- In bridge mode, the guest normally receives a 192.168.111.x address and {helper_bin} starts socat to forward {hdc_bind}:<HDC_PORT> to <GUEST_IP>:55555.",
            "- Prefer the HDC endpoint printed by the helper or recorded in the runtime/state/*.env file; do not guess the IP/port.",
            "- The helper waits for the helper-reported HDC endpoint to become Connected before returning, unless OHEMU_WAIT_FOR_HDC_READY=0 is explicitly set.",
            "- If bridge setup is unavailable, usermode may show a 20.20.20.x guest IP and QEMU hostfwd may listen before hdcd is ready; still use the helper-reported HDC endpoint and wait for Connected.",
            "",
            "Disk safety rules:",
            f"- QEMU must run only with per-task overlay qcow2 files under {runtime['overlay_root']}.",
            f"- The prepared base qcow2 files under {runtime['qcow2_root']}/{runtime['arch']}/base are backing files only; do not write to them.",
            "- Do not run QEMU directly on OpenHarmony out/*/images/*.img, prepared base qcow2 files, or any shared qcow2 cache file.",
            "- If overlay creation fails or no per-task overlay exists, classify runtime verification as BLOCKED_ENV instead of running on the shared images.",
            "",
            "Read the HDC port from the helper output or from the state file under the runtime/state directory; do not assume guest-side port 5555 is the host-connect port.",
            "If the helper, qemu binary, mounted workspace, prepared qcow2 cache, boot images, or hdc binary is missing, classify runtime verification as BLOCKED_ENV and record the exact failing command and output.",
        ]
    )
