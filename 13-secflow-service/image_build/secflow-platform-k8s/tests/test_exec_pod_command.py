import json
import unittest
from unittest import mock

from app.services.k8s import KubernetesService


class FakeExecResponse:
    def __init__(self, stdout="", stderr="", error_payload=None):
        self.stdout = stdout
        self.stderr = stderr
        self.error_payload = error_payload
        self._open = True

    def write_stdin(self, data):
        self.stdin = data

    def close_stdin(self):
        self.stdin_closed = True

    def is_open(self):
        return self._open

    def update(self, timeout=1):
        self._open = False

    def peek_stdout(self):
        return bool(self.stdout)

    def read_stdout(self):
        data, self.stdout = self.stdout, ""
        return data

    def peek_stderr(self):
        return bool(self.stderr)

    def read_stderr(self):
        data, self.stderr = self.stderr, ""
        return data

    def peek_channel(self, channel):
        return bool(self.error_payload)

    def read_channel(self, channel):
        data, self.error_payload = self.error_payload, ""
        return data

    def close(self):
        self.closed = True


class ExecPodCommandTests(unittest.TestCase):
    def create_service(self):
        service = KubernetesService.__new__(KubernetesService)
        service._handle_api_exception = lambda e, resource, action: (_ for _ in ()).throw(e)
        service._core_v1 = mock.Mock()
        service._core_v1.connect_get_namespaced_pod_exec = mock.Mock()
        return service

    def test_exec_pod_command_returns_stdout_and_success_exit(self):
        response = FakeExecResponse(
            stdout="hello\n",
            error_payload=json.dumps({"status": "Success"}),
        )
        service = self.create_service()
        with mock.patch("app.services.k8s.stream", return_value=response):
            result = service.exec_pod_command("ns", "pod-1", ["echo", "hello"])

        self.assertEqual(result["stdout"], "hello\n")
        self.assertEqual(result["stderr"], "")
        self.assertEqual(result["exit_code"], 0)

    def test_exec_pod_command_parses_non_zero_exit_code(self):
        response = FakeExecResponse(
            stderr="failure\n",
            error_payload=json.dumps(
                {
                    "status": "Failure",
                    "message": "command terminated",
                    "details": {"causes": [{"reason": "ExitCode", "message": "7"}]},
                }
            ),
        )
        service = self.create_service()
        with mock.patch("app.services.k8s.stream", return_value=response):
            result = service.exec_pod_command("ns", "pod-1", ["sh", "-lc", "exit 7"])

        self.assertEqual(result["exit_code"], 7)
        self.assertIn("failure", result["stderr"])
        self.assertIn("command terminated", result["stderr"])


if __name__ == "__main__":
    unittest.main()
