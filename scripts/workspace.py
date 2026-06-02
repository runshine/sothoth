from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from selection import SelectionOption, resolve_named_targets


ROOT_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = ROOT_DIR / "scripts"
SECFLOW_DIR = ROOT_DIR / "13-secflow-service"
SECFLOW_IMAGE_BUILD_DIR = SECFLOW_DIR / "image_build"
AGENT_IMAGE_DIR = ROOT_DIR / "100-agent-service-image"


@dataclass(frozen=True)
class K8sGroup:
    key: str
    directory: Path
    display_name: str
    description: str
    aliases: tuple[str, ...] = ()
    exclude_files: tuple[str, ...] = ()
    pre_deploy_shell: str | None = None
    post_deploy_shell: str | None = None
    pre_clean_shell: str | None = None
    post_clean_shell: str | None = None

    def manifest_paths(self) -> list[Path]:
        excluded = set(self.exclude_files)
        return sorted(
            path
            for path in self.directory.glob("*.yaml")
            if path.is_file() and path.name not in excluded
        )


@dataclass(frozen=True)
class BatchGroup:
    key: str
    root: Path
    display_name: str
    description: str
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class BatchRepo:
    group: BatchGroup
    name: str
    path: Path
    display_name: str
    aliases: tuple[str, ...] = ()


K8S_GROUPS: tuple[K8sGroup, ...] = (
    K8sGroup(
        key="pre-init",
        directory=ROOT_DIR / "00-pre-init",
        display_name="pre-init",
        description="Cluster bootstrap resources",
        aliases=("00", "bootstrap"),
    ),
    K8sGroup(
        key="mysql",
        directory=ROOT_DIR / "01-mysql-service",
        display_name="mysql",
        description="MySQL and CloudBeaver",
        aliases=("01",),
    ),
    K8sGroup(
        key="vpn",
        directory=ROOT_DIR / "02-vpn-access-service",
        display_name="vpn",
        description="OpenVPN access stack",
        aliases=("02", "openvpn"),
    ),
    K8sGroup(
        key="elk",
        directory=ROOT_DIR / "03-elk-service",
        display_name="elk",
        description="Elastic stack",
        aliases=("03",),
    ),
    K8sGroup(
        key="nacos",
        directory=ROOT_DIR / "06-nacos-registry-service",
        display_name="nacos",
        description="Nacos registry",
        aliases=("06",),
    ),
    K8sGroup(
        key="redis",
        directory=ROOT_DIR / "09-redis-service",
        display_name="redis",
        description="Redis service",
        aliases=("09",),
    ),
    K8sGroup(
        key="new-api",
        directory=ROOT_DIR / "11-new-api-service",
        display_name="new-api",
        description="New API service area",
        aliases=("11", "api"),
    ),
    K8sGroup(
        key="harbor",
        directory=ROOT_DIR / "12-harbor-service",
        display_name="harbor",
        description="Harbor registry",
        aliases=("12",),
        post_deploy_shell="./setup-ingress-tls.sh && helm install -n harbor-ns harbor ./harbor",
        pre_clean_shell="helm uninstall harbor -n harbor-ns",
    ),
    K8sGroup(
        key="secflow",
        directory=SECFLOW_DIR,
        display_name="secflow",
        description="SecFlow platform services",
        aliases=("13",),
    ),
    K8sGroup(
        key="external",
        directory=ROOT_DIR / "99-external-service",
        display_name="external",
        description="Ingress and external exposure resources",
        aliases=("99",),
        exclude_files=("14-sothoth-00-ingress.yaml",),
        pre_deploy_shell='if [[ "${SETUP_TLS_SECRETS:-1}" == "1" ]]; then source ../00-pre-init/setup-k8s-tls-secrets.sh && main; fi',
    ),
)

K8S_GROUP_INDEX = {group.key: group for group in K8S_GROUPS}
for group in K8S_GROUPS:
    for alias in group.aliases:
        K8S_GROUP_INDEX[alias] = group


BATCH_GROUPS: tuple[BatchGroup, ...] = (
    BatchGroup(
        key="secflow",
        root=SECFLOW_IMAGE_BUILD_DIR,
        display_name="secflow",
        description="SecFlow image build repositories",
        aliases=("13",),
    ),
    BatchGroup(
        key="agent",
        root=AGENT_IMAGE_DIR,
        display_name="agent",
        description="Agent image build repositories",
        aliases=("100",),
    ),
)

BATCH_GROUP_INDEX = {group.key: group for group in BATCH_GROUPS}
for group in BATCH_GROUPS:
    for alias in group.aliases:
        BATCH_GROUP_INDEX[alias] = group


def resolve_k8s_group_keys(targets: Iterable[str], *, default: tuple[str, ...] = ("secflow",)) -> list[str]:
    return _resolve_group_keys(
        targets,
        groups=K8S_GROUPS,
        default=default,
        item_label="groups",
        example="0 or 1,4 or secflow,redis,external",
        unknown_label="group",
        no_selection_message="No groups selected",
    )


def resolve_batch_group_keys(targets: Iterable[str], *, default: tuple[str, ...] = ("secflow",)) -> list[str]:
    return _resolve_group_keys(
        targets,
        groups=BATCH_GROUPS,
        default=default,
        item_label="build groups",
        example="0 or 1,2 or secflow,agent",
        unknown_label="build group",
        no_selection_message="No build groups selected",
    )


def _resolve_group_keys(
    targets: Iterable[str],
    *,
    groups: Iterable[K8sGroup | BatchGroup],
    default: tuple[str, ...],
    item_label: str,
    example: str,
    unknown_label: str,
    no_selection_message: str,
) -> list[str]:
    selected_targets = list(targets) or list(default)
    options = [
        SelectionOption(
            value=group.key,
            display_name=group.display_name,
            description=group.description,
            aliases=group.aliases,
        )
        for group in groups
    ]
    return resolve_named_targets(
        selected_targets,
        options=options,
        item_label=item_label,
        example=example,
        unknown_label=unknown_label,
        no_selection_message=no_selection_message,
    )


def get_k8s_groups(keys: Iterable[str]) -> list[K8sGroup]:
    return [K8S_GROUP_INDEX[key] for key in keys]


def get_batch_groups(keys: Iterable[str]) -> list[BatchGroup]:
    return [BATCH_GROUP_INDEX[key] for key in keys]


def discover_k8s_deployments(group_keys: Iterable[str]) -> list[str]:
    deployments: list[str] = []
    for group in get_k8s_groups(group_keys):
        for path in group.manifest_paths():
            lines = path.read_text().splitlines()
            for index, line in enumerate(lines):
                if line.strip() != "kind: Deployment":
                    continue
                for offset in range(index + 1, min(index + 20, len(lines))):
                    match = re.match(r"^\s*name:\s*([^\s#]+)", lines[offset])
                    if match:
                        deployments.append(match.group(1))
                        break

    seen: set[str] = set()
    resolved: list[str] = []
    for deployment in deployments:
        if deployment in seen:
            continue
        seen.add(deployment)
        resolved.append(deployment)
    return resolved


def discover_batch_repos(group_keys: Iterable[str]) -> list[BatchRepo]:
    repos: list[BatchRepo] = []
    for group in get_batch_groups(group_keys):
        if not group.root.is_dir():
            continue
        for path in sorted(group.root.iterdir()):
            if not path.is_dir() or path.name.startswith("."):
                continue
            if not (path / "Dockerfile").exists():
                continue
            display_name, aliases = build_repo_labels(group.key, path.name)
            repos.append(
                BatchRepo(
                    group=group,
                    name=path.name,
                    path=path,
                    display_name=display_name,
                    aliases=aliases,
                )
            )
    return repos


def build_repo_labels(group_key: str, repo_name: str) -> tuple[str, tuple[str, ...]]:
    aliases = {repo_name}
    if group_key == "secflow":
        trimmed = repo_name.removeprefix("secflow-")
        aliases.add(trimmed)
        return trimmed, tuple(sorted(aliases))

    cleaned = re.sub(r"^\d+-", "", repo_name)
    cleaned = cleaned.removeprefix("secflow-agent-service-")
    aliases.add(cleaned)
    return cleaned, tuple(sorted(aliases))
