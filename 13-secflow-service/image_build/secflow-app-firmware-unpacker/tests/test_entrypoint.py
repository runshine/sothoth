import unittest
from unittest.mock import patch

from app import entrypoint


class EntrypointModeTests(unittest.TestCase):
    def test_api_mode_selected_when_api_role_present(self):
        with patch("app.entrypoint.get_runtime_roles", return_value={"api", "dispatcher"}):
            self.assertEqual("api", entrypoint.resolve_runtime_mode())

    def test_background_mode_selected_for_non_api_roles(self):
        with patch("app.entrypoint.get_runtime_roles", return_value={"dispatcher", "worker"}):
            self.assertEqual("background", entrypoint.resolve_runtime_mode())
