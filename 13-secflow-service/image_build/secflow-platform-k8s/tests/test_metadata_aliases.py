import unittest

from app.services.k8s import KubernetesService


class MetadataAliasesTests(unittest.TestCase):
    def setUp(self):
        self.service = KubernetesService.__new__(KubernetesService)

    def test_configmap_metadata_accepts_legacy_label_annotation_aliases(self):
        manifest = {
            "metadata": {
                "name": "demo-cm",
                "namespace": "secflow-ns",
                "label": {"app": "demo"},
                "annotation": {"owner": "qa"},
            },
            "data": {"k": "v"},
        }
        cm = self.service._dict_to_v1_configmap(manifest)
        self.assertEqual(cm.metadata.labels, {"app": "demo"})
        self.assertEqual(cm.metadata.annotations, {"owner": "qa"})

    def test_secret_metadata_prefers_standard_fields(self):
        manifest = {
            "metadata": {
                "name": "demo-secret",
                "namespace": "secflow-ns",
                "labels": {"app": "std"},
                "label": {"app": "legacy"},
                "annotations": {"owner": "std"},
                "annotation": {"owner": "legacy"},
            },
            "data": {"token": "xxx"},
        }
        secret = self.service._dict_to_v1_secret(manifest)
        self.assertEqual(secret.metadata.labels, {"app": "std"})
        self.assertEqual(secret.metadata.annotations, {"owner": "std"})


if __name__ == "__main__":
    unittest.main()
