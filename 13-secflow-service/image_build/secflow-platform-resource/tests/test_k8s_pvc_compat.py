import unittest

from app.services.k8s import KubernetesService


class FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload
        self.text = str(payload)

    def json(self):
        return self._payload


class K8sPvcCompatTests(unittest.TestCase):
    def setUp(self):
        self.service = KubernetesService.__new__(KubernetesService)
        self.service.storage_class_name = "nfs-client"
        self.service.get_project_namespace = lambda project_id: f"secflow-{project_id}"

    def test_list_pvcs_handles_manual_pvc_with_nullable_fields(self):
        def fake_request(method, path, project_id=None, **kwargs):
            self.assertEqual(method, "GET")
            self.assertEqual(path, "/pvcs")
            return FakeResponse(
                200,
                {
                    "items": [
                        {
                            "name": "manual-pvc",
                            "namespace": "secflow-p1",
                            "status": "Bound",
                            "storage_class": None,
                            "capacity": {"storage": "5Gi"},
                        },
                        {
                            "name": "no-capacity-pvc",
                            "namespace": "secflow-p1",
                            "status": "Pending",
                            "storage_class": "",
                            "capacity": {},
                        },
                    ]
                },
            )

        self.service._request = fake_request
        result = self.service.list_pvcs("p1")

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["storage_class"], "n/a")
        self.assertEqual(result[0]["capacity"], "5Gi")
        self.assertEqual(result[1]["storage_class"], "n/a")
        self.assertEqual(result[1]["capacity"], "0Gi")

    def test_get_pvc_status_handles_string_capacity_and_empty_storage_class(self):
        def fake_request(method, path, project_id=None, **kwargs):
            self.assertEqual(method, "GET")
            self.assertEqual(path, "/pvcs/manual-pvc")
            return FakeResponse(
                200,
                {
                    "name": "manual-pvc",
                    "namespace": "secflow-p1",
                    "status": "Bound",
                    "storage_class": None,
                    "capacity": "8Gi",
                },
            )

        self.service._request = fake_request
        status = self.service.get_pvc_status("p1", "manual-pvc")

        self.assertIsNotNone(status)
        self.assertEqual(status["name"], "manual-pvc")
        self.assertEqual(status["storage_class"], "n/a")
        self.assertEqual(status["capacity"], "8Gi")


if __name__ == "__main__":
    unittest.main()
