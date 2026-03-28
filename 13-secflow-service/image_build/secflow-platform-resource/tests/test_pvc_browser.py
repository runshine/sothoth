import unittest
from unittest import mock

from fastapi import HTTPException

from app.services.pvc_browser import PvcBrowserService, _normalize_browser_path, _validate_target_name


class FakeK8sService:
    def __init__(self, pod=None):
        self.pod = pod
        self.deleted = []
        self.created = []
        self.waited = []

    def get_pod(self, project_id, pod_name):
        return self.pod

    def delete_pod(self, project_id, pod_name):
        self.deleted.append((project_id, pod_name))
        self.pod = None
        return True

    def create_pod(self, project_id, manifest):
        self.created.append((project_id, manifest))
        self.pod = {
            "status": "Running",
            "label": manifest["metadata"]["labels"],
        }
        return self.pod

    def wait_for_pod_running(self, project_id, pod_name, timeout=60):
        self.waited.append((project_id, pod_name, timeout))
        return True


class NormalizeBrowserPathTests(unittest.TestCase):
    def test_normalize_browser_path_keeps_root(self):
        self.assertEqual(_normalize_browser_path("/"), "/")
        self.assertEqual(_normalize_browser_path(""), "/")
        self.assertEqual(_normalize_browser_path("reports/2026"), "/reports/2026")

    def test_normalize_browser_path_rejects_escape(self):
        with self.assertRaises(HTTPException):
            _normalize_browser_path("../etc/passwd")

    def test_validate_target_name_rejects_invalid(self):
        with self.assertRaises(HTTPException):
            _validate_target_name("../bad")

        self.assertEqual(_validate_target_name("report.txt"), "report.txt")


class EnsureBrowserPodTests(unittest.TestCase):
    def setUp(self):
        self.service = PvcBrowserService.__new__(PvcBrowserService)
        self.service.image = "python:3.12-alpine"
        self.service.image_pull_policy = "IfNotPresent"
        self.service.mount_path = "/mnt/pvc"
        self.service.pod_name = "secflow-resource-browser"
        self.service.container_name = "browser"
        self.service.ready_timeout = 60
        self.service.exec_timeout = 30

    def test_ensure_browser_pod_reuses_matching_running_pod(self):
        fake_k8s = FakeK8sService(
            pod={
                "status": "Running",
                "label": {"secflow-pvc-name": "target-pvc"},
            }
        )
        with mock.patch("app.services.pvc_browser.get_k8s_service", return_value=fake_k8s):
            pod_name = self.service.ensure_browser_pod("proj-1", "target-pvc")

        self.assertEqual(pod_name, "secflow-resource-browser")
        self.assertEqual(fake_k8s.deleted, [])
        self.assertEqual(fake_k8s.created, [])

    def test_ensure_browser_pod_recreates_when_pvc_changes(self):
        fake_k8s = FakeK8sService(
            pod={
                "status": "Running",
                "label": {"secflow-pvc-name": "old-pvc"},
            }
        )
        with mock.patch("app.services.pvc_browser.get_k8s_service", return_value=fake_k8s):
            pod_name = self.service.ensure_browser_pod("proj-1", "new-pvc")

        self.assertEqual(pod_name, "secflow-resource-browser")
        self.assertEqual(fake_k8s.deleted, [("proj-1", "secflow-resource-browser")])
        self.assertEqual(len(fake_k8s.created), 1)
        manifest = fake_k8s.created[0][1]
        self.assertEqual(
            manifest["spec"]["volumes"][0]["persistentVolumeClaim"]["claimName"],
            "new-pvc",
        )


if __name__ == "__main__":
    unittest.main()
