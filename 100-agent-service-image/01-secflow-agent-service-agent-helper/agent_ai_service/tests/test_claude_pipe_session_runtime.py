import unittest
from unittest.mock import Mock, patch
import json
import io

from agent_ai_service.services.claude_pipe_session_runtime import ClaudePipeSessionRuntime
from agent_ai_service.models.agent_backend import BackendConfig


class ClaudePipeSessionRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.session_store = Mock()
        self.runtime = ClaudePipeSessionRuntime(self.session_store)
        self.config = BackendConfig(
            name="claude",
            backend_type="claude",
            command="claude",
            args=[],
            env={},
            cwd="/host",
        )

    def test_create_or_get_vendor_session_sets_vendor_fields(self):
        session = {"session_id": "s-1", "backend": "claude"}
        self.session_store.patch.return_value = {
            **session,
            "vendor_session_id": "v-1",
            "vendor_session_kind": "claude",
        }

        result = self.runtime.create_or_get_vendor_session(session, self.config)

        self.assertEqual(result["vendor_session_kind"], "claude")
        self.session_store.patch.assert_called_once()
        _, payload = self.session_store.patch.call_args[0]
        self.assertEqual(payload["vendor_session_kind"], "claude")
        self.assertEqual(payload["vendor_resume_mode"], "resume_then_session_id")
        self.assertEqual(payload["backend_pid"], None)

    @patch("agent_ai_service.services.claude_pipe_session_runtime.subprocess.run")
    def test_invoke_once_resume_then_fallback(self, run_mock):
        session = {
            "session_id": "s-1",
            "backend": "claude",
            "vendor_session_id": "v-1",
            "vendor_session_initialized": True,
        }
        self.session_store.patch.side_effect = lambda sid, payload: {**session, **payload}
        run_mock.side_effect = [
            Mock(returncode=0, stdout=json.dumps({
                "type": "result",
                "subtype": "error_during_execution",
                "is_error": True,
                "errors": ["No conversation found with session ID: v-1"],
            }), stderr=""),
            Mock(returncode=0, stdout="ok response", stderr=""),
        ]

        result = self.runtime.invoke_once(session, self.config, "hello")

        self.assertEqual(run_mock.call_count, 2)
        first_cmd = run_mock.call_args_list[0].args[0]
        second_cmd = run_mock.call_args_list[1].args[0]
        self.assertIn("--resume", first_cmd)
        self.assertIn("--session-id", second_cmd)
        self.assertEqual(result["output"], "ok response")
        self.assertTrue(result["raw"]["used_fallback"])
        self.assertTrue(result["success"])

    @patch("agent_ai_service.services.claude_pipe_session_runtime.subprocess.run")
    def test_invoke_once_first_turn_uses_session_id(self, run_mock):
        session = {
            "session_id": "s-2",
            "backend": "claude",
        }
        self.session_store.patch.side_effect = lambda sid, payload: {**session, **payload}
        run_mock.return_value = Mock(returncode=0, stdout="first response", stderr="")

        result = self.runtime.invoke_once(session, self.config, "hello")

        cmd = run_mock.call_args.args[0]
        self.assertIn("--session-id", cmd)
        self.assertNotIn("--resume", cmd)
        self.assertTrue(result["success"])

    def test_extract_text_from_stream_json(self):
        payload = {
            "type": "content_block_delta",
            "delta": {"text": "hello"},
            "message": {"content": [{"type": "text", "text": " world"}]},
        }

        fragments = self.runtime._extract_text_from_stream_json(payload)
        merged = "".join(fragments)
        self.assertIn("hello", merged)
        self.assertIn("world", merged)

    @patch("agent_ai_service.services.claude_pipe_session_runtime.subprocess.Popen")
    def test_invoke_stream_includes_verbose_flag(self, popen_mock):
        session = {
            "session_id": "s-3",
            "backend": "claude",
            "vendor_session_id": "v-3",
            "vendor_session_initialized": False,
        }
        self.session_store.patch.side_effect = lambda sid, payload: {**session, **payload}
        process = Mock()
        process.stdout = io.StringIO('{"type":"result","is_error":false}\n')
        process.stderr = io.StringIO("")
        process.wait.return_value = 0
        process.poll.return_value = 0
        popen_mock.return_value = process

        events = list(self.runtime.invoke_stream(session, self.config, "hello stream"))

        cmd = popen_mock.call_args.args[0]
        self.assertIn("--verbose", cmd)
        self.assertIn("--output-format", cmd)
        self.assertIn("stream-json", cmd)
        self.assertTrue(any(event.get("type") == "done" for event in events))


if __name__ == "__main__":
    unittest.main()
