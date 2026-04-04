import unittest

from app.services.k8s import KubernetesService


class DeploymentManifestConversionTests(unittest.TestCase):
    def setUp(self):
        self.service = KubernetesService.__new__(KubernetesService)

    def test_dict_to_v1_deployment_keeps_configmap_volume_and_init_containers(self):
        manifest = {
            "metadata": {
                "name": "code-server-ne-test-3b6700",
                "namespace": "secflow-44f9029d00650a10",
                "labels": {"app": "code-server", "code-server-id": "3b67002c63735a03"},
            },
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": "code-server", "code-server-id": "3b67002c63735a03"}},
                "template": {
                    "metadata": {"labels": {"app": "code-server", "code-server-id": "3b67002c63735a03"}},
                    "spec": {
                        "initContainers": [
                            {
                                "name": "llm-file-init",
                                "image": "ghcr.io/skiyer/deepsight:latest",
                                "command": ["sh", "-c", "mkdir -p /root/.codex"],
                            }
                        ],
                        "containers": [
                            {
                                "name": "code-server",
                                "image": "ghcr.io/skiyer/deepsight:latest",
                                "volumeMounts": [
                                    {"name": "source-volume-0", "mountPath": "/config/workspace"},
                                    {"name": "llm-provider-files", "mountPath": "/root/.codex/auth.json", "subPath": "file-1", "readOnly": True},
                                ],
                            }
                        ],
                        "volumes": [
                            {"name": "source-volume-0", "persistentVolumeClaim": {"claimName": "secflow-pvc-10178337-bed"}},
                            {"name": "llm-provider-files", "configMap": {"name": "code-server-llm-3b67002c63735a03"}},
                        ],
                    },
                },
            },
        }

        dep = self.service._dict_to_v1_deployment(manifest)

        self.assertEqual(dep.spec.template.spec.init_containers[0].name, "llm-file-init")
        self.assertEqual(dep.spec.template.spec.init_containers[0].command, ["sh", "-c", "mkdir -p /root/.codex"])
        volumes = {v.name: v for v in dep.spec.template.spec.volumes}
        self.assertIn("llm-provider-files", volumes)
        self.assertEqual(volumes["llm-provider-files"].config_map.name, "code-server-llm-3b67002c63735a03")


if __name__ == "__main__":
    unittest.main()
