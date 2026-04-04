from pathlib import Path


FORBIDDEN_PATTERNS = (
    "import kubernetes",
    "from kubernetes",
    "CoreV1Api(",
    "AppsV1Api(",
    "NetworkingV1Api(",
    "load_kube_config(",
    "load_incluster_config(",
)


def test_code_server_does_not_use_k8s_sdk_directly():
    """
    code-server 微服务必须通过 platform-k8s 微服务间接操作 K8S，
    禁止直接引入 kubernetes SDK。
    """
    root = Path(__file__).resolve().parents[1] / "app"
    offenders = []
    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_PATTERNS:
            if pattern in text:
                offenders.append(f"{path.relative_to(root.parent)}: {pattern}")

    assert not offenders, "发现 code-server 直接调用 K8S SDK:\n" + "\n".join(offenders)
