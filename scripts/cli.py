#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import re
from dataclasses import dataclass
from pathlib import Path

from selection import SelectionOption, resolve_named_targets
from workspace import (
    SCRIPTS_DIR,
    SECFLOW_DIR,
    get_k8s_groups,
    resolve_k8s_group_keys,
)

DEFAULT_NAMESPACE = os.environ.get("NAMESPACE", "secflow-ns")
DEFAULT_IMAGE_REGISTRY_PREFIX = os.environ.get("IMAGE_REGISTRY_PREFIX", "")
DEFAULT_BASE_DOMAIN = os.environ.get("BASE_DOMAIN", "")
DEFAULT_FLANNEL_NETWORK_CIDR = os.environ.get("FLANNEL_NETWORK_CIDR", "10.42.0.0/16")
DEFAULT_FLANNEL_NETWORK_BASE = os.environ.get("FLANNEL_NETWORK_BASE", "10.42.0.0")
DEFAULT_NFS_SERVER = os.environ.get("NFS_SERVER", "172.31.30.81")
DEFAULT_NFS_PATH = os.environ.get("NFS_PATH", "/nvme/share_k8s")
DEFAULT_METALLB_SHARED_POOL_RANGE = os.environ.get(
    "METALLB_SHARED_POOL_RANGE", "172.31.30.100-172.31.30.110"
)
DEFAULT_METALLB_STATIC_POOL_RANGE = os.environ.get(
    "METALLB_STATIC_POOL_RANGE", "172.31.30.111-172.31.30.120"
)
DEFAULT_METALLB_SHARED_LB_IP = os.environ.get("METALLB_SHARED_LB_IP", "172.31.30.100")
DEFAULT_INGRESS_NGINX_LB_IP = os.environ.get("INGRESS_NGINX_LB_IP", "172.31.30.101")
DEFAULT_SETUP_TLS_SECRETS = os.environ.get("SETUP_TLS_SECRETS", "1")
IMAGES_ENV = SECFLOW_DIR / "images.env"
DEPLOY_PRESETS = {
    "blue": {
        "namespace": "secflow-ns",
        "image_registry_prefix": "172.31.30.52:5000",
        "base_domain": "ai.icsl.huawei.com",
        "flannel_network_cidr": "10.42.0.0/16",
        "flannel_network_base": "10.42.0.0",
        "nfs_server": "172.31.30.81",
        "nfs_path": "/nvme/share_k8s",
        "metallb_shared_pool_range": "172.31.30.100-172.31.30.110",
        "metallb_static_pool_range": "172.31.30.111-172.31.30.120",
        "metallb_shared_lb_ip": "172.31.30.100",
        "ingress_nginx_lb_ip": "172.31.30.101",
        "setup_tls_secrets": "1",
    },
    "green": {
        "namespace": "secflow-ns",
        "image_registry_prefix": "10.43.208.68/hub-proxy",
        "base_domain": "ai.icsl.huawei.com",
        "flannel_network_cidr": "10.244.0.0/16",
        "flannel_network_base": "10.244.0.0",
        "nfs_server": "30.250.0.4",
        "nfs_path": "/k8s",
        "metallb_shared_pool_range": "30.250.0.200-30.250.0.210",
        "metallb_static_pool_range": "30.250.0.211-30.250.0.220",
        "metallb_shared_lb_ip": "30.250.0.200",
        "ingress_nginx_lb_ip": "30.250.0.201",
        "setup_tls_secrets": "0",
    },
}


@dataclass(frozen=True)
class Component:
    name: str
    files: tuple[str, ...]
    description: str
    wait_deployments: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()


COMPONENTS: tuple[Component, ...] = (
    Component(
        name="bootstrap",
        files=(
            "00-secflow-00-00-namespace.yaml",
            "00-secflow-00-01-mysql-init-job.yaml",
            "00-secflow-113-00-shared-runtime-resources.yaml",
        ),
        description="Creating namespace and shared runtime resources",
        aliases=("base",),
    ),
    Component(
        name="frontend",
        files=(
            "00-secflow-01-00-platform-frontend-configmap.yaml",
            "00-secflow-01-00-platform-frontend-deployment.yaml",
            "00-secflow-01-00-platform-frontend-service.yaml",
        ),
        description="Deploying secflow frontend",
        wait_deployments=("secflow-platform-frontend",),
    ),
    Component(
        name="menu",
        files=(
            "00-secflow-02-00-platform-menu-configmap.yaml",
            "00-secflow-02-01-platform-menu-deployment.yaml",
            "00-secflow-02-02-platform-menu-service.yaml",
        ),
        description="Deploying secflow menu",
        wait_deployments=("secflow-platform-menu",),
    ),
    Component(
        name="auth",
        files=(
            "00-secflow-03-00-platform-auth-configmap.yaml",
            "00-secflow-03-01-platform-auth-deployment.yaml",
            "00-secflow-03-02-platform-auth-service.yaml",
        ),
        description="Deploying secflow auth",
        wait_deployments=("secflow-platform-auth",),
    ),
    Component(
        name="project",
        files=(
            "00-secflow-04-00-platform-project-configmap.yaml",
            "00-secflow-04-01-platform-project-serviceaccount.yaml",
            "00-secflow-04-02-platform-project-deployment.yaml",
            "00-secflow-04-03-platform-project-service.yaml",
        ),
        description="Deploying secflow project",
        wait_deployments=("secflow-platform-project",),
    ),
    Component(
        name="resource",
        files=(
            "00-secflow-05-00-platform-resource-configmap.yaml",
            "00-secflow-05-01-platform-resource-pvc.yaml",
            "00-secflow-05-02-platform-resource-serviceaccount.yaml",
            "00-secflow-05-03-platform-resource-deployment.yaml",
            "00-secflow-05-04-platform-resource-service.yaml",
        ),
        description="Deploying secflow resource",
        wait_deployments=("secflow-platform-resource",),
    ),
    Component(
        name="static-binary",
        files=(
            "00-secflow-06-00-platform-static-binary-pvc.yaml",
            "00-secflow-06-01-platform-static-binary-configmap.yaml",
            "00-secflow-06-02-platform-static-binary-deployment.yaml",
            "00-secflow-06-02-platform-static-binary-service.yaml",
        ),
        description="Deploying secflow static-binary",
        wait_deployments=("secflow-platform-static-binary",),
        aliases=("static",),
    ),
    Component(
        name="deploy-script",
        files=(
            "00-secflow-07-00-platform-deploy-script-pvc.yaml",
            "00-secflow-07-01-platform-deploy-script-configmap.yaml",
            "00-secflow-07-02-platform-deploy-script-deployment.yaml",
            "00-secflow-07-03-platform-deploy-script-service.yaml",
        ),
        description="Deploying secflow deploy-script",
        wait_deployments=("secflow-platform-deploy-script",),
        aliases=("deploy",),
    ),
    Component(
        name="agent",
        files=(
            "00-secflow-08-00-platform-agent-pvc.yaml",
            "00-secflow-08-01-platform-agent-configmap.yaml",
            "00-secflow-08-02-platform-agent-deployment.yaml",
            "00-secflow-08-03-platform-agent-service.yaml",
        ),
        description="Deploying secflow agent",
        wait_deployments=("secflow-platform-agent",),
    ),
    Component(
        name="k8s",
        files=(
            "00-secflow-09-00-platform-k8s-serviceaccount.yaml",
            "00-secflow-09-01-platform-k8s-configmap.yaml",
            "00-secflow-09-02-platform-k8s-deployment.yaml",
            "00-secflow-09-03-platform-k8s-service.yaml",
        ),
        description="Deploying secflow k8s service",
        wait_deployments=("secflow-platform-k8s",),
    ),
    Component(
        name="workflow",
        files=(
            "00-secflow-10-01-platform-workflow-configmap.yaml",
            "00-secflow-10-02-platform-workflow-deployment.yaml",
            "00-secflow-10-03-platform-workflow-service.yaml",
        ),
        description="Deploying secflow workflow",
        wait_deployments=("secflow-platform-workflow",),
    ),
    Component(
        name="vuln",
        files=(
            "00-secflow-11-00-platform-vuln-configmap.yaml",
            "00-secflow-11-02-platform-vuln-deployment.yaml",
            "00-secflow-11-03-platform-vuln-service.yaml",
            "00-secflow-11-04-platform-vuln-hpa.yaml",
        ),
        description="Deploying secflow vuln service",
        wait_deployments=("secflow-platform-vuln",),
    ),
    Component(
        name="fileserver",
        files=(
            "00-secflow-12-01-platform-fileserver-configmap.yaml",
            "00-secflow-12-02-platform-fileserver-deployment.yaml",
            "00-secflow-12-03-platform-fileserver-service.yaml",
        ),
        description="Deploying secflow fileserver",
        wait_deployments=("secflow-platform-fileserver",),
    ),
    Component(
        name="workflow-status",
        files=(
            "00-secflow-13-01-platform-workflow-status-configmap.yaml",
            "00-secflow-13-02-platform-workflow-status-deployment.yaml",
            "00-secflow-13-03-platform-workflow-status-service.yaml",
        ),
        description="Deploying secflow workflow-status",
        wait_deployments=("secflow-platform-workflow-status",),
    ),
    Component(
        name="configcenter",
        files=(
            "00-secflow-14-00-platform-configcenter-configmap.yaml",
            "00-secflow-14-01-platform-configcenter-deployment.yaml",
            "00-secflow-14-02-platform-configcenter-service.yaml",
        ),
        description="Deploying secflow configcenter",
        wait_deployments=("secflow-platform-configcenter",),
        aliases=("config",),
    ),
    Component(
        name="system-analysis",
        files=(
            "00-secflow-15-00-platform-system-analysis-configmap.yaml",
            "00-secflow-15-01-platform-system-analysis-deployment.yaml",
            "00-secflow-15-02-platform-system-analysis-service.yaml",
        ),
        description="Deploying secflow system-analysis",
        wait_deployments=("secflow-platform-system-analysis",),
    ),
    Component(
        name="code-server",
        files=(
            "00-secflow-100-00-app-code-server-configmap.yaml",
            "00-secflow-100-01-app-code-server-serviceaccount.yaml",
            "00-secflow-100-02-app-code-server-deployment.yaml",
            "00-secflow-100-03-app-code-server-service.yaml",
        ),
        description="Deploying secflow code-server",
        wait_deployments=("secflow-app-code-server",),
    ),
    Component(
        name="binary-to-source",
        files=(
            "00-secflow-102-00-app-binary-to-source-configmap.yaml",
            "00-secflow-102-01-app-binary-to-source-pvc.yaml",
            "00-secflow-102-02-app-binary-to-source-serviceaccount.yaml",
            "00-secflow-102-03-app-binary-to-source-manager-deployment.yaml",
            "00-secflow-102-04-app-binary-to-source-worker-deployment.yaml",
            "00-secflow-102-05-app-binary-to-source-manager-service.yaml",
            "00-secflow-102-06-app-binary-to-source-pi-re-agent-service.yaml",
            "00-secflow-102-07-app-binary-to-source-pi-re-agent-deployment.yaml",
        ),
        description="Deploying secflow binary-to-source",
        wait_deployments=(
            "secflow-app-binary-to-source-manager",
            "secflow-app-binary-to-source-worker",
            "secflow-pi-re-agent",
        ),
        aliases=("b2s",),
    ),
    Component(
        name="firmware-unpacker",
        files=(
            "00-secflow-103-00-app-firmware-unpacker-configmap.yaml",
            "00-secflow-103-01-app-firmware-unpacker-serviceaccount.yaml",
            "00-secflow-103-02-app-firmware-unpacker-deployment.yaml",
            "00-secflow-103-03-app-firmware-unpacker-service.yaml",
            "00-secflow-103-04-app-firmware-unpacker-pdb.yaml",
        ),
        description="Deploying secflow firmware-unpacker",
        wait_deployments=(
            "secflow-app-firmware-unpacker-api",
            "secflow-app-firmware-unpacker-dispatcher",
            "secflow-app-firmware-unpacker-cleanup",
        ),
        aliases=("fw",),
    ),
    Component(
        name="entry-analyse",
        files=(
            "00-secflow-104-00-app-entry-analyse-configmap.yaml",
            "00-secflow-104-01-app-entry-analyse-deployment.yaml",
            "00-secflow-104-02-app-entry-analyse-service.yaml",
            "00-secflow-104-03-app-entry-analyse-worker-deployment.yaml",
            "00-secflow-104-04-app-entry-analyse-scheduler-deployment.yaml",
            "00-secflow-104-05-app-entry-analyse-worker-adaptive-deployment.yaml",
        ),
        description="Deploying secflow entry-analyse",
        wait_deployments=(
            "secflow-app-entry-analyse",
            "secflow-app-entry-analyse-worker",
            "secflow-app-entry-analyse-scheduler",
            "secflow-app-entry-analyse-worker-adaptive",
        ),
        aliases=("entry",),
    ),
    Component(
        name="dataflow-analyse",
        files=(
            "00-secflow-105-00-app-dataflow-analyse-configmap.yaml",
            "00-secflow-105-01-app-dataflow-analyse-deployment.yaml",
            "00-secflow-105-02-app-dataflow-analyse-service.yaml",
            "00-secflow-105-03-app-dataflow-analyse-worker-deployment.yaml",
            "00-secflow-105-04-app-dataflow-analyse-hpa.yaml",
            "00-secflow-105-05-app-dataflow-analyse-worker-hpa.yaml",
        ),
        description="Deploying secflow dataflow-analyse",
        wait_deployments=(
            "secflow-app-dataflow-analyse",
            "secflow-app-dataflow-analyse-worker",
        ),
        aliases=("dataflow",),
    ),
    Component(
        name="system-analyse",
        files=(
            "00-secflow-106-00-app-system-analyse-configmap.yaml",
            "00-secflow-106-01-app-system-analyse-deployment.yaml",
            "00-secflow-106-02-app-system-analyse-service.yaml",
            "00-secflow-106-03-app-system-analyse-worker-deployment.yaml",
            "00-secflow-106-04-app-system-analyse-runner-deployment.yaml",
            "00-secflow-106-05-app-system-analyse-runner-hpa.yaml",
        ),
        description="Deploying secflow system-analyse",
        wait_deployments=(
            "secflow-app-system-analyse",
            "secflow-app-system-analyse-worker",
            "secflow-app-system-analyse-runner",
        ),
        aliases=("system",),
    ),
    Component(
        name="dataflow-vuln-scanner",
        files=(
            "00-secflow-107-00-app-dataflow-vuln-scanner-configmap.yaml",
            "00-secflow-107-01-app-dataflow-vuln-scanner-deployment.yaml",
            "00-secflow-107-02-app-dataflow-vuln-scanner-service.yaml",
        ),
        description="Deploying secflow dataflow-vuln-scanner",
        wait_deployments=(
            "secflow-app-dataflow-vuln-scanner-api",
            "secflow-app-dataflow-vuln-scanner-manager",
            "secflow-app-dataflow-vuln-scanner-worker",
        ),
        aliases=("scanner",),
    ),
    Component(
        name="binary-security",
        files=(
            "00-secflow-108-00-app-binary-security-configmap.yaml",
            "00-secflow-108-00b-app-binary-security-rbac.yaml",
            "00-secflow-108-01-app-binary-security-deployment.yaml",
            "00-secflow-108-01b-app-binary-security-worker-deployment.yaml",
            "00-secflow-108-01c-app-binary-security-reducer-deployment.yaml",
            "00-secflow-108-02-app-binary-security-service.yaml",
            "00-secflow-108-02b-app-binary-security-reducer-service.yaml",
        ),
        description="Deploying secflow binary-security",
        wait_deployments=(
            "secflow-app-binary-security",
            "secflow-app-binary-security-worker",
            "secflow-app-binary-security-reducer",
        ),
    ),
    Component(
        name="ipc-audit",
        files=(
            "00-secflow-109-00-app-ipc-audit-configmap.yaml",
            "00-secflow-109-00a-app-ipc-audit-pvc.yaml",
            "00-secflow-109-01-app-ipc-audit-deployment.yaml",
            "00-secflow-109-02-app-ipc-audit-service.yaml",
        ),
        description="Deploying secflow ipc-audit",
        wait_deployments=("secflow-app-ipc-audit",),
        aliases=("ipc",),
    ),
    Component(
        name="binary-evolution-center",
        files=(
            "00-secflow-110-00-app-binary-evolution-center-configmap.yaml",
            "00-secflow-110-02-app-binary-evolution-center-serviceaccount.yaml",
            "00-secflow-110-03-app-binary-evolution-center-manager-deployment.yaml",
            "00-secflow-110-04-app-binary-evolution-center-worker-deployment.yaml",
            "00-secflow-110-05-app-binary-evolution-center-service.yaml",
        ),
        description="Deploying secflow binary-evolution-center",
        wait_deployments=(
            "secflow-app-binary-evolution-center-manager",
            "secflow-app-binary-evolution-center-worker",
        ),
        aliases=("evolution",),
    ),
    Component(
        name="kernel-scan",
        files=(
            "00-secflow-111-00-app-kernel-scan-configmap.yaml",
            "00-secflow-111-00a-app-kernel-scan-secret.yaml",
            "00-secflow-111-01-app-kernel-scan-pvc.yaml",
            "00-secflow-111-02-app-kernel-scan-deployment.yaml",
            "00-secflow-111-03-app-kernel-scan-service.yaml",
        ),
        description="Deploying secflow kernel-scan",
        wait_deployments=("secflow-app-kernel-scan",),
        aliases=("kernel",),
    ),
    Component(
        name="ai-agent-framework",
        files=("00-secflow-112-00-platform-ai-agent-framework.yaml",),
        description="Deploying secflow ai-agent-framework",
        wait_deployments=("secflow-platform-ai-agent-framework",),
        aliases=("ai",),
    ),
    Component(
        name="ingress",
        files=("00-secflow-00-02-platform-ingress.yaml",),
        description="Creating ingress",
    ),
)

COMPONENT_INDEX = {component.name: component for component in COMPONENTS}
for component in COMPONENTS:
    for alias in component.aliases:
        COMPONENT_INDEX[alias] = component

BATCH_TARGETS = (
    "pull",
    "commit",
    "push",
    "build",
    "push_image",
    "push_image_remote",
)


def run(cmd: list[str], *, env: dict[str, str] | None = None, check: bool = True) -> None:
    subprocess.run(cmd, check=check, env=env)


def run_shell(command: str, *, cwd: Path, env: dict[str, str] | None = None, check: bool = True) -> None:
    subprocess.run(
        command,
        shell=True,
        executable="/bin/bash",
        cwd=cwd,
        env=env,
        check=check,
    )


def parse_shared_args(args: argparse.Namespace) -> dict[str, str]:
    preset_name = getattr(args, "preset", None)
    preset = DEPLOY_PRESETS.get(preset_name, {})
    namespace = args.namespace or preset.get("namespace", DEFAULT_NAMESPACE)
    image_registry_prefix = args.image_registry_prefix or preset.get(
        "image_registry_prefix", DEFAULT_IMAGE_REGISTRY_PREFIX
    )
    base_domain = args.base_domain or preset.get("base_domain", DEFAULT_BASE_DOMAIN)
    return {
        "NAMESPACE": namespace,
        "IMAGE_REGISTRY_PREFIX": image_registry_prefix,
        "BASE_DOMAIN": base_domain,
        "SERVICE_ACCOUNT_NAME": args.service_account_name or f"{namespace}-server",
        "CLUSTER_ROLE_NAME": args.cluster_role_name or f"{namespace}-role",
        "CLUSTER_ROLE_BINDING_NAME": args.cluster_role_binding_name or f"{namespace}-binding",
        "FLANNEL_NETWORK_CIDR": preset.get("flannel_network_cidr", DEFAULT_FLANNEL_NETWORK_CIDR),
        "FLANNEL_NETWORK_BASE": preset.get("flannel_network_base", DEFAULT_FLANNEL_NETWORK_BASE),
        "NFS_SERVER": preset.get("nfs_server", DEFAULT_NFS_SERVER),
        "NFS_PATH": preset.get("nfs_path", DEFAULT_NFS_PATH),
        "METALLB_SHARED_POOL_RANGE": preset.get(
            "metallb_shared_pool_range", DEFAULT_METALLB_SHARED_POOL_RANGE
        ),
        "METALLB_STATIC_POOL_RANGE": preset.get(
            "metallb_static_pool_range", DEFAULT_METALLB_STATIC_POOL_RANGE
        ),
        "METALLB_SHARED_LB_IP": preset.get("metallb_shared_lb_ip", DEFAULT_METALLB_SHARED_LB_IP),
        "INGRESS_NGINX_LB_IP": preset.get("ingress_nginx_lb_ip", DEFAULT_INGRESS_NGINX_LB_IP),
        "SETUP_TLS_SECRETS": preset.get("setup_tls_secrets", DEFAULT_SETUP_TLS_SECRETS),
    }


def resolve_component_names(names: list[str]) -> list[Component]:
    options = [
        SelectionOption(
            value=component.name,
            display_name=component.name,
            description=component.description,
            aliases=component.aliases,
        )
        for component in COMPONENTS
    ]
    resolved_names = resolve_named_targets(
        names,
        options=options,
        item_label="components",
        example="0 or 1,4,7 or frontend,resource,kernel-scan",
        unknown_label="component",
        no_selection_message="No components selected",
    )
    return [COMPONENT_INDEX[name] for name in resolved_names]


def prompt_for_preset() -> str:
    presets = list(DEPLOY_PRESETS)
    print("Select deploy preset:")
    for index, preset_name in enumerate(presets, start=1):
        preset = DEPLOY_PRESETS[preset_name]
        print(
            f"{index:>2}. {preset_name:<5} "
            f"registry={preset['image_registry_prefix']} domain={preset['base_domain']}"
        )
    response = input("Preset: ").strip().lower()
    if not response:
        raise SystemExit("No deploy preset selected")

    if response.isdigit():
        position = int(response)
        if position < 1 or position > len(presets):
            raise SystemExit(f"Selection out of range: {response}")
        return presets[position - 1]

    if response not in DEPLOY_PRESETS:
        available = ", ".join(presets)
        raise SystemExit(f"Unknown deploy preset: {response}\nAvailable: {available}")
    return response


def print_header(
    title: str,
    config: dict[str, str],
    group_names: list[str],
    components: list[Component] | None = None,
) -> None:
    print("==========================================")
    print(title)
    print("Groups: " + " ".join(group_names))
    if "secflow" in group_names:
        print(f"Namespace: {config['NAMESPACE']}")
        print(f"Secflow Dir: {SECFLOW_DIR}")
        print(f"Image Prefix: {config['IMAGE_REGISTRY_PREFIX'] or '<default>'}")
        print(f"Base Domain: {config['BASE_DOMAIN'] or '<default>'}")
    if {"pre-init", "external"} & set(group_names):
        print(f"Flannel Network: {config['FLANNEL_NETWORK_CIDR']}")
        print(f"NFS: {config['NFS_SERVER']}:{config['NFS_PATH']}")
        print(f"MetalLB Shared Pool: {config['METALLB_SHARED_POOL_RANGE']}")
        print(f"MetalLB Static Pool: {config['METALLB_STATIC_POOL_RANGE']}")
        print(f"MetalLB Shared IP: {config['METALLB_SHARED_LB_IP']}")
        print(f"Ingress LB IP: {config['INGRESS_NGINX_LB_IP']}")
        print(f"Setup TLS Secrets: {config['SETUP_TLS_SECRETS']}")
    if components is not None:
        print("Components: " + " ".join(component.name for component in components))
    print("==========================================")


def load_images_env_defaults() -> dict[str, str]:
    if not IMAGES_ENV.exists():
        return {}

    defaults: dict[str, str] = {}
    pattern = re.compile(r'^export\s+([A-Za-z_][A-Za-z0-9_]*)="\$\{\1:-([^}]*)\}"\s*$')
    for line in IMAGES_ENV.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = pattern.match(stripped)
        if match:
            defaults[match.group(1)] = match.group(2)
    return defaults


def image_prefix_mode(prefix: str) -> str:
    return "ghcr-hub-proxy" if prefix.endswith("/hub-proxy") else "prefix-all"


def rewrite_image_reference(image: str, prefix: str) -> str:
    cleaned = image.strip().strip('"').strip("'")
    if not cleaned or cleaned.startswith("${"):
        return image

    green_direct_prefix = prefix.removesuffix("/hub-proxy")
    if cleaned.startswith(f"{prefix.rstrip('/')}/") or cleaned.startswith(f"{green_direct_prefix.rstrip('/')}/"):
        return image

    mode = image_prefix_mode(prefix)
    if mode == "ghcr-hub-proxy":
        if cleaned.startswith("ghcr.io/"):
            rewritten = f"{prefix.removesuffix('/hub-proxy')}/{cleaned}"
        else:
            rewritten = f"{prefix}/{cleaned}"
    else:
        rewritten = f"{prefix.rstrip('/')}/{cleaned}"
    return image.replace(cleaned, rewritten, 1)


def render_blue_default_overrides(manifest_path: Path, text: str, env: dict[str, str]) -> str:
    replacements_by_manifest = {
        "00-network-kube-flannel-00-init.yaml": (
            (f'"Network": "{DEFAULT_FLANNEL_NETWORK_CIDR}"', "FLANNEL_NETWORK_CIDR", DEFAULT_FLANNEL_NETWORK_CIDR),
        ),
        "00-network-kube-flannel-02-frr-configmap.yaml": (
            (f"FLANNEL_IP={DEFAULT_FLANNEL_NETWORK_BASE}", "FLANNEL_NETWORK_BASE", DEFAULT_FLANNEL_NETWORK_BASE),
            (f"RR_FLANNEL_IP={DEFAULT_FLANNEL_NETWORK_BASE}", "FLANNEL_NETWORK_BASE", DEFAULT_FLANNEL_NETWORK_BASE),
            (f'FLANNEL_IP="{DEFAULT_FLANNEL_NETWORK_BASE}"', "FLANNEL_NETWORK_BASE", DEFAULT_FLANNEL_NETWORK_BASE),
            (f'RR_FLANNEL_IP="{DEFAULT_FLANNEL_NETWORK_BASE}"', "FLANNEL_NETWORK_BASE", DEFAULT_FLANNEL_NETWORK_BASE),
            (DEFAULT_FLANNEL_NETWORK_CIDR, "FLANNEL_NETWORK_CIDR", DEFAULT_FLANNEL_NETWORK_CIDR),
        ),
        "01-storageclass-01-nfs-client-provisioner.yaml": (
            (DEFAULT_NFS_SERVER, "NFS_SERVER", DEFAULT_NFS_SERVER),
            (DEFAULT_NFS_PATH, "NFS_PATH", DEFAULT_NFS_PATH),
        ),
        "02-metallb-01-ip-address-pool.yaml": (
            (DEFAULT_METALLB_SHARED_POOL_RANGE, "METALLB_SHARED_POOL_RANGE", DEFAULT_METALLB_SHARED_POOL_RANGE),
            (DEFAULT_METALLB_STATIC_POOL_RANGE, "METALLB_STATIC_POOL_RANGE", DEFAULT_METALLB_STATIC_POOL_RANGE),
        ),
        "03-nginx-ingress-00-install.yaml": (
            (f'"{DEFAULT_INGRESS_NGINX_LB_IP}"', "INGRESS_NGINX_LB_IP", DEFAULT_INGRESS_NGINX_LB_IP),
        ),
        "00-kube-00-coredns-metallb.yaml": (
            (f'"{DEFAULT_METALLB_SHARED_LB_IP}"', "METALLB_SHARED_LB_IP", DEFAULT_METALLB_SHARED_LB_IP),
        ),
        "01-mysql-01-mysql-metallb-for-debug.yaml": (
            (f'"{DEFAULT_METALLB_SHARED_LB_IP}"', "METALLB_SHARED_LB_IP", DEFAULT_METALLB_SHARED_LB_IP),
        ),
        "02-vpn-access-00-openvpn-metallb.yaml": (
            (f'"{DEFAULT_METALLB_SHARED_LB_IP}"', "METALLB_SHARED_LB_IP", DEFAULT_METALLB_SHARED_LB_IP),
        ),
        "06-nacos-01-register-metallb-for-debug.yaml": (
            (f'"{DEFAULT_METALLB_SHARED_LB_IP}"', "METALLB_SHARED_LB_IP", DEFAULT_METALLB_SHARED_LB_IP),
        ),
        "09-redis-00-metallb-for-debug.yaml": (
            (f'"{DEFAULT_METALLB_SHARED_LB_IP}"', "METALLB_SHARED_LB_IP", DEFAULT_METALLB_SHARED_LB_IP),
        ),
    }
    for original, env_key, default_value in replacements_by_manifest.get(manifest_path.name, ()):
        value = env.get(env_key, default_value)
        if value != default_value:
            text = text.replace(original, original.replace(default_value, value))
    return text


def render_manifest_text(manifest_path: Path, env: dict[str, str], image_registry_prefix: str) -> str:
    text = manifest_path.read_text()
    text = re.sub(
        r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}",
        lambda match: env.get(match.group(1), match.group(0)),
        text,
    )
    text = render_blue_default_overrides(manifest_path, text, env)
    if image_registry_prefix:
        text = re.sub(
            r'(^\s*[A-Za-z0-9_-]*image:\s*["\']?)([^"\s\'#]+)(["\']?)',
            lambda match: (
                match.group(1)
                + rewrite_image_reference(match.group(2), image_registry_prefix)
                + match.group(3)
            ),
            text,
            flags=re.MULTILINE,
        )
    return text


def kubectl_apply_manifest(manifest_path: Path, env: dict[str, str], image_registry_prefix: str) -> None:
    rendered_text = render_manifest_text(manifest_path, env, image_registry_prefix)
    subprocess.run(
        ["kubectl", "apply", "-f", "-"],
        input=rendered_text,
        text=True,
        check=True,
        env=env,
    )


def kubectl_apply(component: Component, env: dict[str, str], image_registry_prefix: str) -> None:
    for file_name in component.files:
        manifest_path = SECFLOW_DIR / file_name
        kubectl_apply_manifest(manifest_path, env, image_registry_prefix)


def kubectl_delete(component: Component) -> None:
    for file_name in component.files:
        manifest_path = SECFLOW_DIR / file_name
        run(
            ["kubectl", "delete", "-f", str(manifest_path), "--ignore-not-found"],
            check=False,
        )


def apply_managed_group(group_key: str, env: dict[str, str]) -> None:
    group = get_k8s_groups([group_key])[0]
    image_registry_prefix = env.get("IMAGE_REGISTRY_PREFIX", "") if group.key == "secflow" else ""
    if group.pre_deploy_shell:
        run_shell(group.pre_deploy_shell, cwd=group.directory, env=env)
    for manifest_path in group.manifest_paths():
        kubectl_apply_manifest(manifest_path, env, image_registry_prefix)
    if group.post_deploy_shell:
        run_shell(group.post_deploy_shell, cwd=group.directory, env=env)


def delete_managed_group(group_key: str, env: dict[str, str]) -> None:
    group = get_k8s_groups([group_key])[0]
    if group.pre_clean_shell:
        run_shell(group.pre_clean_shell, cwd=group.directory, env=env, check=False)
    for manifest_path in reversed(group.manifest_paths()):
        run(
            ["kubectl", "delete", "-f", str(manifest_path), "--ignore-not-found"],
            env=env,
            check=False,
        )
    if group.post_clean_shell:
        run_shell(group.post_clean_shell, cwd=group.directory, env=env, check=False)


def wait_component(namespace: str, component: Component, *, delete: bool = False) -> None:
    for deployment in component.wait_deployments:
        if delete:
            run(
                [
                    "kubectl",
                    "wait",
                    "--for=delete",
                    f"deployment/{deployment}",
                    "-n",
                    namespace,
                    "--timeout=120s",
                ],
                check=False,
            )
            continue
        run(
            [
                "kubectl",
                "rollout",
                "status",
                f"deployment/{deployment}",
                "-n",
                namespace,
                "--timeout=300s",
            ],
            check=False,
        )


def show_cluster_status(namespace: str) -> None:
    run(["kubectl", "get", "deployments", "-n", namespace], check=False)
    run(["kubectl", "get", "pods", "-n", namespace], check=False)
    run(["kubectl", "get", "services", "-n", namespace], check=False)
    run(["kubectl", "get", "ingress", "-n", namespace], check=False)


def build_command_env(config: dict[str, str]) -> dict[str, str]:
    env = os.environ.copy()
    env.update(config)
    for key, value in load_images_env_defaults().items():
        env.setdefault(key, value)
    return env


def command_deploy(args: argparse.Namespace) -> int:
    group_keys = resolve_k8s_group_keys(args.group)
    if args.components and "secflow" not in group_keys:
        raise SystemExit("Components can only be selected when the secflow group is included")
    preset_groups = {"pre-init", "external", "secflow"}
    if preset_groups & set(group_keys) and args.preset is None:
        args.preset = prompt_for_preset()
    config = parse_shared_args(args)
    components = resolve_component_names(args.components) if "secflow" in group_keys else []
    env = build_command_env(config)
    try:
        print_header(
            "Deploying managed Kubernetes groups",
            config,
            group_keys,
            components if "secflow" in group_keys else None,
        )

        step = 0
        total_steps = len([group for group in group_keys if group != "secflow"]) + len(components)
        if "secflow" in group_keys and not args.skip_wait:
            total_steps += 1
        if "secflow" in group_keys:
            total_steps += 2

        for group_key in group_keys:
            if group_key == "secflow":
                continue
            step += 1
            print()
            print(f"[{step}/{total_steps}] Deploying group {group_key}...")
            apply_managed_group(group_key, env)

        for component in components:
            step += 1
            print()
            print(f"[{step}/{total_steps}] {component.description}...")
            kubectl_apply(component, env, config["IMAGE_REGISTRY_PREFIX"])

        if "secflow" in group_keys and not args.skip_wait:
            step += 1
            print()
            print(f"[{step}/{total_steps}] Waiting for selected deployments to be ready...")
            for component in components:
                wait_component(config["NAMESPACE"], component)

        if "secflow" in group_keys:
            print()
            print(f"[{step + 1}/{total_steps}] Checking deployment status...")
            show_cluster_status(config["NAMESPACE"])

            print()
            print(f"[{step + 2}/{total_steps}] Deployment completed!")
        else:
            print()
            print("Deployment completed!")
        return 0
    except subprocess.CalledProcessError as exc:
        print(f"Command failed with exit code {exc.returncode}", file=sys.stderr)
        return exc.returncode


def command_clean(args: argparse.Namespace) -> int:
    group_keys = resolve_k8s_group_keys(args.group)
    if args.components and "secflow" not in group_keys:
        raise SystemExit("Components can only be selected when the secflow group is included")
    config = parse_shared_args(args)
    components = list(reversed(resolve_component_names(args.components))) if "secflow" in group_keys else []
    env = build_command_env(config)
    try:
        print_header(
            "Cleaning managed Kubernetes groups",
            config,
            group_keys,
            components if "secflow" in group_keys else None,
        )
        step = 0
        total_steps = len([group for group in group_keys if group != "secflow"]) + len(components)
        if "secflow" in group_keys and not args.skip_wait:
            total_steps += 1
        if "secflow" in group_keys:
            total_steps += 2

        for group_key in reversed(group_keys):
            if group_key == "secflow":
                continue
            step += 1
            print()
            print(f"[{step}/{total_steps}] Removing group {group_key}...")
            delete_managed_group(group_key, env)

        for component in components:
            step += 1
            print()
            print(f"[{step}/{total_steps}] Removing {component.name}...")
            kubectl_delete(component)

        if "secflow" in group_keys and not args.skip_wait:
            step += 1
            print()
            print(f"[{step}/{total_steps}] Waiting for selected deployments to terminate...")
            for component in components:
                wait_component(config["NAMESPACE"], component, delete=True)

        if "secflow" in group_keys:
            print()
            print(f"[{step + 1}/{total_steps}] Checking remaining resources...")
            show_cluster_status(config["NAMESPACE"])

            print()
            print(f"[{step + 2}/{total_steps}] Cleanup completed!")

            if args.delete_namespace:
                print()
                print(f"Deleting namespace {config['NAMESPACE']}...")
                run(["kubectl", "delete", "namespace", config["NAMESPACE"]], check=False)
        else:
            print()
            print("Cleanup completed!")
        return 0
    except subprocess.CalledProcessError as exc:
        print(f"Command failed with exit code {exc.returncode}", file=sys.stderr)
        return exc.returncode


def forward_to_script(script_name: str, args: list[str]) -> int:
    script = SCRIPTS_DIR / script_name
    env = os.environ.copy()
    command = [sys.executable, str(script), *args]
    return subprocess.run(command, env=env).returncode


def command_batch(args: argparse.Namespace) -> int:
    forward_args = []
    for group in args.group:
        forward_args.extend(["--group", group])
    for repo in args.repo:
        forward_args.extend(["--repo", repo])
    if args.jobs is not None:
        forward_args.extend(["--jobs", str(args.jobs)])
    for match in args.match:
        forward_args.extend(["--match", match])
    if args.dry_run:
        forward_args.append("--dry-run")
    if args.plain:
        forward_args.append("--plain")
    forward_args.extend(args.make_args)
    return forward_to_script("batch.py", forward_args)


def forward_batch_target(args: argparse.Namespace, make_target: str) -> int:
    forward_args = []
    for group in args.group:
        forward_args.extend(["--group", group])
    for repo in args.targets:
        forward_args.extend(["--repo", repo])
    if args.jobs is not None:
        forward_args.extend(["--jobs", str(args.jobs)])
    if args.dry_run:
        forward_args.append("--dry-run")
    if args.plain:
        forward_args.append("--plain")
    forward_args.append(make_target)
    return forward_to_script("batch.py", forward_args)


def command_hot(args: argparse.Namespace) -> int:
    forward_args = []
    for group in args.group:
        forward_args.extend(["--group", group])
    if args.skip_if_image_unchanged:
        forward_args.append("--skip-if-image-unchanged")
    if args.namespace:
        forward_args.extend(["--namespace", args.namespace])
    if args.jobs is not None:
        forward_args.extend(["--jobs", str(args.jobs)])
    if args.timeout is not None:
        forward_args.extend(["--timeout", str(args.timeout)])
    forward_args.extend(args.deployments)
    return forward_to_script("hot.py", forward_args)


def command_status(args: argparse.Namespace) -> int:
    namespace = args.namespace or DEFAULT_NAMESPACE
    show_cluster_status(namespace)
    return 0


def add_batch_passthrough_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument("--group", action="append", default=[], help="managed image group name; repeatable")
    command.add_argument("--jobs", type=int)
    command.add_argument("--dry-run", action="store_true")
    command.add_argument("--plain", action="store_true")
    command.add_argument("targets", nargs="*")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Unified managed scripts entrypoint.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_shared_k8s_arguments(command: argparse.ArgumentParser) -> None:
        command.add_argument("--group", action="append", default=[], help="managed group name; repeatable")
        command.add_argument("--namespace")
        command.add_argument("--image-registry-prefix")
        command.add_argument("--base-domain")
        command.add_argument("--service-account-name")
        command.add_argument("--cluster-role-name")
        command.add_argument("--cluster-role-binding-name")

    deploy = subparsers.add_parser(
        "deploy",
        help="Apply managed Kubernetes groups",
    )
    add_shared_k8s_arguments(deploy)
    deploy.add_argument("--preset", choices=sorted(DEPLOY_PRESETS))
    deploy.add_argument("--skip-wait", action="store_true")
    deploy.add_argument("components", nargs="*")
    deploy.set_defaults(func=command_deploy)

    clean = subparsers.add_parser("clean", help="Delete managed Kubernetes groups")
    add_shared_k8s_arguments(clean)
    clean.add_argument("--skip-wait", action="store_true")
    clean.add_argument("--delete-namespace", action="store_true")
    clean.add_argument("components", nargs="*")
    clean.set_defaults(func=command_clean)

    hot = subparsers.add_parser("hot", help="Restart managed Kubernetes deployments")
    hot.add_argument("--group", action="append", default=[], help="managed group name; repeatable")
    hot.add_argument("--namespace", default=DEFAULT_NAMESPACE)
    hot.add_argument("--jobs", type=int)
    hot.add_argument("--timeout", type=int)
    hot.add_argument("--skip-if-image-unchanged", action="store_true")
    hot.add_argument("deployments", nargs="*")
    hot.set_defaults(func=command_hot)

    batch = subparsers.add_parser("batch", help="Forward to batch.py for managed image groups")
    batch.add_argument("--group", action="append", default=[], help="managed image group name; repeatable")
    batch.add_argument("--repo", action="append", default=[])
    batch.add_argument("--jobs", type=int)
    batch.add_argument("--match", action="append", default=[])
    batch.add_argument("--dry-run", action="store_true")
    batch.add_argument("--plain", action="store_true")
    batch.add_argument("make_args", nargs=argparse.REMAINDER)
    batch.set_defaults(func=command_batch)

    for target in BATCH_TARGETS:
        command = subparsers.add_parser(target, help=f"Run make {target} across selected managed image repos")
        add_batch_passthrough_arguments(command)
        command.set_defaults(func=lambda args, target=target: forward_batch_target(args, target))

    status = subparsers.add_parser("status", help="Show cluster resources")
    status.add_argument("--namespace", default=DEFAULT_NAMESPACE)
    status.set_defaults(func=command_status)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
