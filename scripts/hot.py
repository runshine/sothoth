#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import suppress
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path
from threading import Lock

from selection import SelectionOption, resolve_named_targets

ROOT_DIR = Path(__file__).resolve().parent.parent
SECFLOW_DIR = ROOT_DIR / "13-secflow-service"
DEFAULT_NAMESPACE = os.environ.get("NAMESPACE", "secflow-ns")
DEFAULT_TIMEOUT_SECONDS = 300
PROGRESS_REFRESH_SECONDS = 0.2
REGISTRY_REQUEST_TIMEOUT_SECONDS = 10
MANIFEST_ACCEPT_HEADERS = ",".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)


def discover_deployments() -> list[str]:
    deployments: list[str] = []
    for path in sorted(SECFLOW_DIR.glob("*.yaml")):
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


@dataclass
class DeploymentResult:
    deployment: str
    success: bool
    duration_seconds: float
    details: str
    skipped: bool = False


@dataclass
class DeploymentProgress:
    deployment: str
    phase: str = "queued"
    message: str = "Waiting to start"
    started_at: float | None = None
    updated_at: float = 0.0
    success: bool | None = None


class ProgressTracker:
    SPINNER_FRAMES = "|/-\\"
    PHASE_LABELS = {
        "queued": "QUEUED",
        "checking": "CHECK",
        "restarting": "RESTART",
        "watching": "ROLLOUT",
        "skipped": "SKIP",
        "success": "OK",
        "failed": "FAIL",
    }

    def __init__(self, deployments: list[str]) -> None:
        now = time.monotonic()
        self._lock = Lock()
        self._tick = 0
        self._interactive = sys.stdout.isatty()
        self._cursor_hidden = False
        self._last_rendered_lines = 0
        self._order = deployments
        self._entries = {
            deployment: DeploymentProgress(deployment=deployment, updated_at=now)
            for deployment in deployments
        }

    def update(
        self,
        deployment: str,
        *,
        phase: str | None = None,
        message: str | None = None,
        success: bool | None = None,
    ) -> None:
        with self._lock:
            entry = self._entries[deployment]
            now = time.monotonic()
            if entry.started_at is None and phase != "queued":
                entry.started_at = now
            if phase is not None:
                entry.phase = phase
            if message is not None:
                entry.message = message
            if success is not None:
                entry.success = success
            entry.updated_at = now

    def render(self, completed: int, total: int, ok: int, failed: int, elapsed_seconds: float) -> None:
        with self._lock:
            snapshot = [self._entries[name] for name in self._order]
            self._tick += 1
            tick = self._tick

        if self._interactive:
            self._render_interactive(snapshot, completed, total, ok, failed, elapsed_seconds, tick)
            return

        sys.stdout.write(
            format_progress(
                completed=completed,
                total=total,
                ok=ok,
                failed=failed,
                elapsed_seconds=elapsed_seconds,
            )
        )
        sys.stdout.flush()

    def finish_render(self) -> None:
        if not self._interactive:
            sys.stdout.write("\n")
            sys.stdout.flush()
            return

        if self._cursor_hidden:
            sys.stdout.write("\x1b[?25h")
            sys.stdout.flush()
            self._cursor_hidden = False

    def _render_interactive(
        self,
        snapshot: list[DeploymentProgress],
        completed: int,
        total: int,
        ok: int,
        failed: int,
        elapsed_seconds: float,
        tick: int,
    ) -> None:
        spinner = self.SPINNER_FRAMES[tick % len(self.SPINNER_FRAMES)]
        width = shutil.get_terminal_size((140, 24)).columns
        name_width = max(len(item.deployment) for item in snapshot) if snapshot else 10
        phase_width = 8
        elapsed_width = 7
        prefix_width = 2 + name_width + 2 + phase_width + 2 + elapsed_width + 2
        message_width = max(20, width - prefix_width)

        lines = [
            format_progress(
                completed=completed,
                total=total,
                ok=ok,
                failed=failed,
                elapsed_seconds=elapsed_seconds,
            ).lstrip("\r"),
            "",
        ]

        for entry in snapshot:
            indicator = self._indicator(entry, spinner)
            phase_label = self.PHASE_LABELS[entry.phase]
            phase_elapsed = 0.0
            if entry.started_at is not None:
                phase_elapsed = time.monotonic() - entry.started_at
            message = self._truncate(entry.message, message_width)
            lines.append(
                f"{indicator} {entry.deployment:<{name_width}}  "
                f"{phase_label:<{phase_width}}  {phase_elapsed:>{elapsed_width}.1f}s  {message}"
            )

        cursor_up = ""
        if self._last_rendered_lines > 1:
            cursor_up = f"\x1b[{self._last_rendered_lines - 1}F"

        output = "\x1b[?25l" + cursor_up + "\x1b[2J" + "\n".join(lines)
        sys.stdout.write(output)
        sys.stdout.flush()
        self._cursor_hidden = True
        self._last_rendered_lines = len(lines)

    def _indicator(self, entry: DeploymentProgress, spinner: str) -> str:
        if entry.success is True:
            return self._color("OK", "32")
        if entry.success is False:
            return self._color("!!", "31")
        if entry.phase == "queued":
            return self._color("..", "90")
        return self._color(spinner, "36")

    def _color(self, text: str, code: str) -> str:
        if not self._interactive:
            return text
        return f"\x1b[{code}m{text}\x1b[0m"

    @staticmethod
    def _truncate(text: str, width: int) -> str:
        if len(text) <= width:
            return text
        if width <= 3:
            return text[:width]
        return text[: width - 3] + "..."


def parse_args() -> argparse.Namespace:
    available_deployments = discover_deployments()
    parser = argparse.ArgumentParser(
        description=(
            "Restart one or all Kubernetes deployments in parallel and watch rollout status."
        )
    )
    parser.add_argument(
        "deployments",
        nargs="*",
        help="Specific deployments to restart. If omitted, choose all or specific services interactively.",
    )
    parser.add_argument(
        "-n",
        "--namespace",
        default=DEFAULT_NAMESPACE,
        help=f"Kubernetes namespace. Default: {DEFAULT_NAMESPACE}",
    )
    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=0,
        help="Maximum concurrent restarts. Default: restart all targets in parallel.",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=(
            "Timeout in seconds for each `kubectl rollout status` command. "
            f"Default: {DEFAULT_TIMEOUT_SECONDS}"
        ),
    )
    parser.add_argument(
        "--skip-if-image-unchanged",
        action="store_true",
        help=(
            "Before restarting a deployment, compare each running container image digest "
            "with the latest digest in the registry. If all digests are unchanged, skip "
            "the rollout for that deployment."
        ),
    )
    args = parser.parse_args()
    if not available_deployments:
        parser.error(f"no deployments discovered from {SECFLOW_DIR}")
    if args.jobs == 0:
        args.jobs = len(available_deployments)
    args.available_deployments = available_deployments
    return args


def ensure_kubectl() -> None:
    if shutil.which("kubectl") is None:
        print("kubectl not found in PATH", file=sys.stderr)
        sys.exit(1)


def resolve_deployments(targets: list[str], available_deployments: list[str]) -> list[str]:
    options = [
        SelectionOption(
            value=deployment,
            display_name=deployment.removeprefix("secflow-"),
            description=deployment,
            aliases=(deployment,),
        )
        for deployment in available_deployments
    ]
    return resolve_named_targets(
        targets,
        options=options,
        item_label="deployments",
        example="0 or 1,4 or platform-auth,app-kernel-scan",
        unknown_label="deployment",
        no_selection_message="No deployments selected",
    )


def run_kubectl(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["kubectl", *args],
        capture_output=True,
        text=True,
        check=True,
    )


def run_kubectl_json(args: list[str]) -> dict:
    result = run_kubectl([*args, "-o", "json"])
    return json.loads(result.stdout)


def collect_output(*parts: str | None) -> str:
    return "\n".join(part.strip() for part in parts if part and part.strip())


def normalize_image_id(image_id: str | None) -> str | None:
    if not image_id:
        return None
    match = re.search(r"sha256:[0-9a-fA-F]{64}", image_id)
    if match:
        return match.group(0).lower()
    return None


def parse_image_reference(image: str) -> tuple[str, str, str]:
    original = image.strip()
    if not original:
        raise ValueError("image reference is empty")

    name_part, at, digest = original.rpartition("@")
    if at:
        reference = digest
        name = name_part
    else:
        name = original
        last_segment = name.rsplit("/", 1)[-1]
        if ":" in last_segment:
            name, _, reference = name.rpartition(":")
        else:
            reference = "latest"

    first_segment = name.split("/", 1)[0]
    if "." in first_segment or ":" in first_segment or first_segment == "localhost":
        registry = first_segment
        repository = name.split("/", 1)[1] if "/" in name else ""
    else:
        registry = "registry-1.docker.io"
        repository = name

    if not repository:
        raise ValueError(f"invalid image reference: {image}")

    if registry == "registry-1.docker.io" and "/" not in repository:
        repository = f"library/{repository}"

    return registry, repository, reference


def registry_manifest_url(registry: str, repository: str, reference: str) -> str:
    scheme = "https" if registry == "registry-1.docker.io" else "http"
    return f"{scheme}://{registry}/v2/{repository}/manifests/{reference}"


def load_docker_auths() -> dict[str, str]:
    config_path = os.path.expanduser("~/.docker/config.json")
    if not os.path.exists(config_path):
        return {}

    with suppress(OSError, json.JSONDecodeError):
        with open(config_path, "r", encoding="utf-8") as handle:
            config = json.load(handle)
        auths = config.get("auths", {})
        result: dict[str, str] = {}
        for host, entry in auths.items():
            auth = entry.get("auth")
            if not auth:
                continue
            normalized = host.removeprefix("https://").removeprefix("http://").rstrip("/")
            result[normalized] = auth
        return result

    return {}


DOCKER_AUTHS = load_docker_auths()


def docker_auth_for_registry(registry: str) -> str | None:
    aliases = (
        registry,
        f"https://{registry}",
        f"http://{registry}",
    )
    if registry == "registry-1.docker.io":
        aliases += (
            "docker.io",
            "https://docker.io",
            "https://index.docker.io/v1/",
            "index.docker.io/v1",
        )

    for alias in aliases:
        normalized = alias.removeprefix("https://").removeprefix("http://").rstrip("/")
        auth = DOCKER_AUTHS.get(normalized)
        if auth:
            return auth
    return None


def build_registry_request(
    url: str,
    *,
    token: str | None = None,
    basic_auth: str | None = None,
) -> urllib.request.Request:
    request = urllib.request.Request(url)
    request.add_header("Accept", MANIFEST_ACCEPT_HEADERS)
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    elif basic_auth:
        request.add_header("Authorization", f"Basic {basic_auth}")
    return request


def parse_www_authenticate(header: str) -> tuple[str, dict[str, str]]:
    scheme, _, rest = header.partition(" ")
    values: dict[str, str] = {}
    for key, value in re.findall(r'([A-Za-z]+)="([^"]*)"', rest):
        values[key] = value
    return scheme, values


def fetch_registry_token(auth_header: str, basic_auth: str | None) -> str | None:
    scheme, params = parse_www_authenticate(auth_header)
    if scheme.lower() != "bearer":
        return None

    realm = params.get("realm")
    if not realm:
        return None

    query = {}
    if "service" in params:
        query["service"] = params["service"]
    if "scope" in params:
        query["scope"] = params["scope"]
    token_url = f"{realm}?{urllib.parse.urlencode(query)}" if query else realm

    request = urllib.request.Request(token_url)
    if basic_auth:
        request.add_header("Authorization", f"Basic {basic_auth}")

    with urllib.request.urlopen(request, timeout=REGISTRY_REQUEST_TIMEOUT_SECONDS) as response:
        payload = json.loads(response.read().decode("utf-8"))
    return payload.get("token") or payload.get("access_token")


def get_remote_manifest_digest(image: str) -> str:
    registry, repository, reference = parse_image_reference(image)
    manifest_url = registry_manifest_url(registry, repository, reference)
    basic_auth = docker_auth_for_registry(registry)

    request = build_registry_request(manifest_url, basic_auth=basic_auth)
    try:
        with urllib.request.urlopen(request, timeout=REGISTRY_REQUEST_TIMEOUT_SECONDS) as response:
            digest = response.headers.get("Docker-Content-Digest")
            if not digest:
                raise RuntimeError(f"registry did not return digest for {image}")
            return digest.lower()
    except urllib.error.HTTPError as exc:
        if exc.code != 401:
            detail = exc.read().decode("utf-8", errors="ignore")
            raise RuntimeError(
                f"failed to fetch registry digest for {image}: HTTP {exc.code} {detail}".strip()
            ) from exc

        auth_header = exc.headers.get("WWW-Authenticate")
        if not auth_header:
            raise RuntimeError(f"registry authentication challenge missing for {image}") from exc

        token = fetch_registry_token(auth_header, basic_auth)
        if not token:
            raise RuntimeError(f"unable to obtain registry token for {image}")

        retry_request = build_registry_request(manifest_url, token=token, basic_auth=basic_auth)
        with urllib.request.urlopen(retry_request, timeout=REGISTRY_REQUEST_TIMEOUT_SECONDS) as response:
            digest = response.headers.get("Docker-Content-Digest")
            if not digest:
                raise RuntimeError(f"registry did not return digest for {image}")
            return digest.lower()
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, ssl.SSLError):
            raise RuntimeError(
                f"failed to fetch registry digest for {image}: SSL error while requesting {manifest_url}: {reason}"
            ) from exc
        raise RuntimeError(
            f"failed to fetch registry digest for {image}: unable to reach {manifest_url}: {reason}"
        ) from exc


def selector_to_label_query(selector: dict) -> str:
    match_labels = selector.get("matchLabels") or {}
    if not match_labels:
        raise RuntimeError("deployment selector.matchLabels is empty; cannot locate pods")
    return ",".join(f"{key}={value}" for key, value in sorted(match_labels.items()))


def deployment_image_status(deployment: str, namespace: str) -> tuple[dict[str, str], dict[str, set[str]]]:
    deployment_json = run_kubectl_json(["get", "deployment", deployment, "-n", namespace])
    pod_selector = selector_to_label_query(deployment_json["spec"]["selector"])
    pod_list = run_kubectl_json(["get", "pods", "-n", namespace, "-l", pod_selector])

    containers = deployment_json["spec"]["template"]["spec"].get("containers", [])
    desired_images = {container["name"]: container["image"] for container in containers}
    current_digests: dict[str, set[str]] = {name: set() for name in desired_images}

    for pod in pod_list.get("items", []):
        statuses = pod.get("status", {}).get("containerStatuses", [])
        for status in statuses:
            name = status.get("name")
            if name not in current_digests:
                continue
            digest = normalize_image_id(status.get("imageID"))
            if digest:
                current_digests[name].add(digest)

    return desired_images, current_digests


def evaluate_skip_reason(deployment: str, namespace: str) -> str | None:
    desired_images, current_digests = deployment_image_status(deployment, namespace)
    if not desired_images:
        return None

    comparison_lines: list[str] = []
    for container_name, image in desired_images.items():
        running = current_digests.get(container_name) or set()
        if not running:
            return None

        remote_digest = get_remote_manifest_digest(image)
        if any(digest != remote_digest for digest in running):
            return None

        comparison_lines.append(
            f"{container_name}: unchanged at {remote_digest}"
        )

    joined = "; ".join(comparison_lines)
    return f"Skipped because image digests are unchanged ({joined})"


def stream_rollout_status(
    deployment: str,
    namespace: str,
    timeout_seconds: int,
    tracker: ProgressTracker,
) -> list[str]:
    args = [
        "kubectl",
        "rollout",
        "status",
        f"deployment/{deployment}",
        "-n",
        namespace,
        f"--timeout={timeout_seconds}s",
    ]
    lines: list[str] = []
    process = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    try:
        assert process.stdout is not None
        for raw_line in process.stdout:
            line = raw_line.strip()
            if not line:
                continue
            lines.append(line)
            tracker.update(deployment, phase="watching", message=line)
    finally:
        with suppress(Exception):
            if process.stdout is not None:
                process.stdout.close()

    return_code = process.wait()
    if return_code != 0:
        raise subprocess.CalledProcessError(
            return_code,
            args,
            output="\n".join(lines),
        )

    return lines


def restart_and_watch(
    deployment: str,
    namespace: str,
    timeout_seconds: int,
    tracker: ProgressTracker,
    skip_if_image_unchanged: bool,
) -> DeploymentResult:
    start_time = time.monotonic()
    restart_output = ""

    try:
        if skip_if_image_unchanged:
            tracker.update(
                deployment,
                phase="checking",
                message="Comparing running image digests with registry",
            )
            skip_reason = evaluate_skip_reason(deployment, namespace)
            if skip_reason:
                tracker.update(
                    deployment,
                    phase="skipped",
                    message="Image digests unchanged",
                    success=True,
                )
                return DeploymentResult(
                    deployment=deployment,
                    success=True,
                    duration_seconds=time.monotonic() - start_time,
                    details=skip_reason,
                    skipped=True,
                )

        tracker.update(
            deployment,
            phase="restarting",
            message="Sending rollout restart request",
        )
        restart = run_kubectl(
            ["rollout", "restart", f"deployment/{deployment}", "-n", namespace]
        )
        restart_output = collect_output(restart.stdout, restart.stderr)
        tracker.update(
            deployment,
            phase="watching",
            message=restart_output.splitlines()[-1] if restart_output else "Restart requested",
        )
        status_lines = stream_rollout_status(deployment, namespace, timeout_seconds, tracker)
    except subprocess.CalledProcessError as exc:
        details = collect_output(restart_output, exc.stdout, exc.stderr) or str(exc)
        tracker.update(
            deployment,
            phase="failed",
            message=(details.splitlines()[-1] if details else "Rollout failed"),
            success=False,
        )
        return DeploymentResult(
            deployment=deployment,
            success=False,
            duration_seconds=time.monotonic() - start_time,
            details=details,
        )

    details = collect_output(restart_output, "\n".join(status_lines))
    tracker.update(
        deployment,
        phase="success",
        message=(status_lines[-1] if status_lines else "Rollout completed"),
        success=True,
    )
    return DeploymentResult(
        deployment=deployment,
        success=True,
        duration_seconds=time.monotonic() - start_time,
        details=details,
    )


def format_progress(completed: int, total: int, ok: int, failed: int, elapsed_seconds: float) -> str:
    bar_width = 32
    ratio = completed / total if total else 1
    filled = int(bar_width * ratio)
    bar = "#" * filled + "-" * (bar_width - filled)
    running = total - completed
    return (
        f"\r[{bar}] {completed}/{total} done "
        f"| ok={ok} failed={failed} running={running} "
        f"| elapsed={elapsed_seconds:.1f}s"
    )


def print_summary(results: list[DeploymentResult]) -> None:
    print("\n")
    print("Summary:")
    for result in sorted(results, key=lambda item: item.deployment):
        if result.skipped:
            status = "SKIP"
        else:
            status = "OK" if result.success else "FAIL"
        print(f"  [{status}] {result.deployment} ({result.duration_seconds:.1f}s)")
        if result.details:
            for line in result.details.splitlines():
                print(f"    {line}")


def main() -> int:
    args = parse_args()
    ensure_kubectl()

    if args.jobs < 1:
        print("--jobs must be at least 1", file=sys.stderr)
        return 1
    if args.timeout < 1:
        print("--timeout must be at least 1 second", file=sys.stderr)
        return 1

    deployments = resolve_deployments(args.deployments, args.available_deployments)
    max_workers = min(args.jobs, len(deployments))

    print(
        f"Restarting {len(deployments)} deployment(s) in namespace "
        f"{args.namespace} with concurrency={max_workers}"
    )
    print("Targets:", ", ".join(deployments))
    if args.skip_if_image_unchanged:
        print("Mode: skip rollout when registry digest matches running image digest")
    if sys.stdout.isatty():
        print()

    results: list[DeploymentResult] = []
    start_time = time.monotonic()
    tracker = ProgressTracker(deployments)

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            pending = {
                executor.submit(
                    restart_and_watch,
                    deployment,
                    args.namespace,
                    args.timeout,
                    tracker,
                    args.skip_if_image_unchanged,
                )
                for deployment in deployments
            }

            while pending:
                done, pending = wait(
                    pending,
                    timeout=PROGRESS_REFRESH_SECONDS,
                    return_when=FIRST_COMPLETED,
                )

                for future in done:
                    results.append(future.result())

                ok_count = sum(1 for result in results if result.success)
                failed_count = len(results) - ok_count
                tracker.render(
                    completed=len(results),
                    total=len(deployments),
                    ok=ok_count,
                    failed=failed_count,
                    elapsed_seconds=time.monotonic() - start_time,
                )
    finally:
        tracker.finish_render()

    print_summary(results)

    failures = [result for result in results if not result.success]
    if failures:
        print("\nFailed deployments:", ", ".join(result.deployment for result in failures), file=sys.stderr)
        return 1

    print("\nAll deployments rolled out successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
