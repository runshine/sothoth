import os
import tempfile
import unittest
from pathlib import Path

import yaml

from app.config import reload_config
from app.start import build_uvicorn_argv


class StartScriptTests(unittest.TestCase):
    def test_build_uvicorn_argv_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = root / "config.yaml"
            config_path.write_text(
                yaml.safe_dump(
                    {
                        "app": {
                            "host": "127.0.0.1",
                            "port": 18080,
                        }
                    }
                ),
                encoding="utf-8",
            )
            reload_config(str(config_path))
            old_keep_alive = os.environ.pop("UVICORN_TIMEOUT_KEEP_ALIVE", None)
            try:
                argv = build_uvicorn_argv()
            finally:
                if old_keep_alive is not None:
                    os.environ["UVICORN_TIMEOUT_KEEP_ALIVE"] = old_keep_alive

        self.assertIn("app.main:app", argv)
        self.assertEqual("10", argv[argv.index("--timeout-keep-alive") + 1])

    def test_build_uvicorn_argv_uses_asgi_entrypoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = root / "config.yaml"
            config_path.write_text(
                yaml.safe_dump(
                    {
                        "app": {
                            "host": "127.0.0.1",
                            "port": 18080,
                        }
                    }
                ),
                encoding="utf-8",
            )
            reload_config(str(config_path))
            old_env = {key: os.environ.get(key) for key in (
                "UVICORN_TIMEOUT_KEEP_ALIVE",
                "UVICORN_BACKLOG",
            )}
            os.environ["UVICORN_TIMEOUT_KEEP_ALIVE"] = "22"
            os.environ["UVICORN_BACKLOG"] = "4096"
            try:
                argv = build_uvicorn_argv()
            finally:
                for key, value in old_env.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value

        self.assertIn("app.main:app", argv)
        self.assertNotIn("app.wsgi:app", argv)
        self.assertEqual("127.0.0.1", argv[argv.index("--host") + 1])
        self.assertEqual("18080", argv[argv.index("--port") + 1])
        self.assertEqual("22", argv[argv.index("--timeout-keep-alive") + 1])
        self.assertEqual("4096", argv[argv.index("--backlog") + 1])
