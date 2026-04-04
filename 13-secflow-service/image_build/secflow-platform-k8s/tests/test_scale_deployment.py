import types
import unittest

from app.services.k8s import KubernetesService


class _FakeAppsV1:
    def __init__(self):
        self.last_call = None

    def patch_namespaced_deployment_scale(self, name, namespace, body):
        self.last_call = {
            "name": name,
            "namespace": namespace,
            "body": body,
        }
        return types.SimpleNamespace(spec=types.SimpleNamespace(replicas=body["spec"]["replicas"]))


class ScaleDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.service = KubernetesService.__new__(KubernetesService)
        self.service._apps_v1 = _FakeAppsV1()

    def test_scale_deployment_uses_patch_scale_spec_replicas(self):
        result = self.service.scale_deployment("secflow-p1", "code-server-ne40e-572410", 0)

        self.assertEqual(result["name"], "code-server-ne40e-572410")
        self.assertEqual(result["replicas"], 0)
        self.assertIsNotNone(self.service._apps_v1.last_call)
        self.assertEqual(self.service._apps_v1.last_call["body"]["spec"]["replicas"], 0)


if __name__ == "__main__":
    unittest.main()
