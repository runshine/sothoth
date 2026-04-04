import unittest

from app.services.k8s import KubernetesService


class SimpleIngressTlsTests(unittest.TestCase):
    def setUp(self):
        self.service = KubernetesService.__new__(KubernetesService)
        self.captured = {}

        def _fake_create_ingress(namespace, manifest):
            self.captured["namespace"] = namespace
            self.captured["manifest"] = manifest
            return manifest

        self.service.create_ingress = _fake_create_ingress

    def test_create_simple_ingress_adds_tls_block_when_enabled(self):
        self.service.create_simple_ingress(
            namespace="secflow-p1",
            name="ing-test",
            service_name="svc-test",
            service_port=8443,
            host="h.example.local",
            ingress_type="nginx",
            path="/",
            path_type="Prefix",
            tls_enabled=True,
            tls_secret_name="wildcard-code-server.sothothv2.com-tls",
        )

        manifest = self.captured["manifest"]
        self.assertEqual(manifest["spec"]["rules"][0]["host"], "h.example.local")
        self.assertEqual(manifest["spec"]["tls"][0]["hosts"], ["h.example.local"])
        self.assertEqual(manifest["spec"]["tls"][0]["secret_name"], "wildcard-code-server.sothothv2.com-tls")


if __name__ == "__main__":
    unittest.main()
